#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mdns_alerts.py - 告警 Webhook（零第三方依赖）

触发源
------
* 健康状态翻转：目标 up -> down / down -> up（首次探测只记基线，不刷屏）；
* 名称冲突：外来应答与本地发布同名异值时登记。

设计
----
* 有界队列 + 独立 daemon 发送线程，绝不阻塞 mDNS 主循环；
* 冷却去重（同一 key 在 cooldown 秒内只发一次），队列满时丢弃并计数；
* 平台自动按 URL 推断：钉钉 / 飞书 / Slack / 企业微信 / 通用 JSON；
* sender 可注入（自测用 fake sender，完全离线），失败有界重试 1 次；
* 不保存任何 token 明文到日志，state() 中 URL 只回显尾段掩码。

配置见 config.example.toml 的 [server].alert_* 段，支持热重载。
"""

from __future__ import annotations

import json
import queue
import threading
import time
import urllib.request

LOG = __import__("logging").getLogger("mdns.alerts")

PLATFORMS = ("dingtalk", "feishu", "slack", "wecom", "generic")


def infer_platform(url: str) -> str:
    """按 webhook URL 推断平台；无法识别则走通用 JSON。"""
    u = (url or "").lower()
    if "oapi.dingtalk.com" in u:
        return "dingtalk"
    if "open.feishu.cn" in u or "open.larksuite.com" in u:
        return "feishu"
    if "hooks.slack.com" in u:
        return "slack"
    if "qyapi.weixin.qq.com" in u:
        return "wecom"
    return "generic"


def _plain_text(event: dict) -> str:
    return (f"[{event.get('level', 'warning').upper()}] {event.get('title', '')}\n"
            f"{event.get('detail', '')}\n"
            f"时间: {event.get('time', '')}  来源: mDNS Responder")


def _markdown_text(event: dict) -> str:
    return (f"### {event.get('title', '')}\n\n"
            f"{event.get('detail', '')}\n\n"
            f"> 级别: {event.get('level', 'warning')}  "
            f"时间: {event.get('time', '')}  \n"
            f"> 来源: mDNS Responder")


def build_payload(platform: str, event: dict) -> bytes:
    """按平台构造 webhook 请求体（JSON bytes）。"""
    title = event.get("title", "mDNS 告警")
    if platform == "dingtalk":
        body = {"msgtype": "markdown",
                "markdown": {"title": title, "text": _markdown_text(event)}}
    elif platform == "feishu":
        body = {"msg_type": "text", "content": {"text": _plain_text(event)}}
    elif platform == "slack":
        body = {"text": _plain_text(event)}
    elif platform == "wecom":
        body = {"msgtype": "markdown",
                "markdown": {"content": _markdown_text(event)}}
    else:
        body = {"source": "mdns-responder", **event}
    return json.dumps(body, ensure_ascii=False).encode("utf-8")


def http_sender(url: str, body: bytes, timeout: float) -> None:
    """默认发送器：标准库 urllib，POST JSON；非 2xx 抛异常。"""
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json; charset=utf-8",
                 "User-Agent": "mDNSStudio-Alert/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        resp.read(2048)


class AlertManager:
    """告警编排器：去重 -> 入队 -> 异步投递。"""

    def __init__(self, webhooks: list | None = None, cooldown: float = 300.0,
                 timeout: float = 5.0, on_health: bool = True,
                 on_conflict: bool = True, enabled: bool = True,
                 sender=None):
        self.enabled = bool(enabled)
        self.cooldown = max(0.0, float(cooldown))
        self.timeout = max(0.5, float(timeout))
        self.on_health = bool(on_health)
        self.on_conflict = bool(on_conflict)
        # 锁与状态先就位：configure() 会在构造期被调用并用到 _lock
        self._webhooks: list[dict] = []
        self._lock = threading.Lock()
        self._cooldowns: dict[str, float] = {}
        self._last_health: dict[str, str] = {}
        self.configure(webhooks or [])
        self._sender = sender or http_sender
        self._queue: queue.Queue = queue.Queue(maxsize=200)
        self.stats = {"events": 0, "sent": 0, "failed": 0, "dropped": 0,
                      "last_error": "", "last_sent_at": 0.0}
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop,
                                        name="mdns-alert", daemon=True)
        self._thread.start()

    # -- 配置（热重载）-------------------------------------------------
    def configure(self, webhooks: list, enabled: bool | None = None,
                  cooldown: float | None = None, timeout: float | None = None,
                  on_health: bool | None = None,
                  on_conflict: bool | None = None) -> None:
        normalized = []
        for item in webhooks or []:
            if isinstance(item, dict):
                url = str(item.get("url", "")).strip()
                platform = str(item.get("platform", "")).strip().lower()
            else:
                url, platform = str(item).strip(), ""
            if not url or not url.lower().startswith(("http://", "https://")):
                continue
            if platform not in PLATFORMS:
                platform = infer_platform(url)
            normalized.append({"url": url, "platform": platform})
        with self._lock:
            self._webhooks = normalized
            if enabled is not None:
                self.enabled = bool(enabled)
            if cooldown is not None:
                self.cooldown = max(0.0, float(cooldown))
            if timeout is not None:
                self.timeout = max(0.5, float(timeout))
            if on_health is not None:
                self.on_health = bool(on_health)
            if on_conflict is not None:
                self.on_conflict = bool(on_conflict)

    # -- 事件入口 -------------------------------------------------------
    def emit(self, kind: str, key: str, title: str, detail: str,
             level: str = "warning") -> bool:
        """登记一个告警事件；冷却内重复或队列满返回 False。"""
        if not self.enabled:
            return False
        dedup = f"{kind}:{key}"
        now = time.time()
        with self._lock:
            last = self._cooldowns.get(dedup, 0.0)
            if now - last < self.cooldown:
                self.stats["dropped"] += 1
                return False
            self._cooldowns[dedup] = now
            # 冷却表本身也有界，避免长期运行无限增长
            if len(self._cooldowns) > 1000:
                for k in list(self._cooldowns)[:500]:
                    self._cooldowns.pop(k, None)
            self.stats["events"] += 1
            hooks = list(self._webhooks)
            event = {
                "kind": kind, "key": key, "title": title, "detail": detail,
                "level": level, "ts": now,
                "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
            }
        if not hooks:
            return True                     # 事件已登记，但没有 webhook 可发
        for hook in hooks:
            try:
                self._queue.put_nowait((hook, event))
            except queue.Full:
                with self._lock:
                    self.stats["dropped"] += 1
        return True

    def check_health(self, items: list[dict]) -> int:
        """比对健康状态快照，状态翻转时触发告警；返回触发条数。"""
        if not self.on_health or not self.enabled:
            # 未开启也要维护基线，避免开启瞬间把历史状态当成新事件
            self._remember_health(items)
            return 0
        fired = 0
        for item in items or []:
            key = item.get("key", "")
            cur = item.get("status", "unknown")
            if not key or cur == "unknown":
                continue
            with self._lock:
                prev = self._last_health.get(key)
                self._last_health[key] = cur
            if prev is None or prev == cur:
                continue
            label = item.get("label", key)
            target = item.get("target", "")
            if cur == "down":
                title = f"服务离线：{label}"
                detail = f"目标 {target} 探测失败（连续 {item.get('failures', 1)} 次），已由「在线」转为「离线」。"
                level = "critical"
            else:
                title = f"服务恢复：{label}"
                detail = f"目标 {target} 已恢复在线，延迟 {item.get('latency_ms')} ms。"
                level = "info"
            if self.emit("health", f"{key}:{cur}", title, detail, level):
                fired += 1
        return fired

    def _remember_health(self, items: list[dict]) -> None:
        with self._lock:
            for item in items or []:
                if item.get("key") and item.get("status") != "unknown":
                    self._last_health[item["key"]] = item["status"]

    def emit_conflict(self, name: str, theirs: str, source: str) -> bool:
        if not self.on_conflict or not self.enabled:
            return False
        return self.emit(
            "conflict", name.lower(),
            f"检测到名称冲突：{name}",
            f"局域网内 {source} 宣称了与本地发布不同的取值「{theirs}」。"
            f"按 RFC 6762，同名冲突可能导致客户端解析到错误目标，请尽快确认。",
            level="critical")

    # -- 发送线程 -------------------------------------------------------
    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                hook, event = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue
            body = build_payload(hook["platform"], event)
            ok = False
            for attempt in range(2):            # 有界重试：最多 2 次
                try:
                    self._sender(hook["url"], body, self.timeout)
                    ok = True
                    break
                except Exception as exc:  # noqa: BLE001 - 第三方端点不可信
                    if attempt == 0:
                        self._stop.wait(1.0)
                        continue
                    with self._lock:
                        self.stats["last_error"] = f"{type(exc).__name__}: {exc}"[:200]
                    LOG.warning("告警发送失败 [%s]: %s",
                                hook["platform"], self.stats["last_error"])
            with self._lock:
                if ok:
                    self.stats["sent"] += 1
                    self.stats["last_sent_at"] = time.time()
                else:
                    self.stats["failed"] += 1

    def state(self) -> dict:
        with self._lock:
            hooks = [{"platform": h["platform"],
                      "url_mask": "…" + h["url"][-10:]} for h in self._webhooks]
            stats = dict(self.stats)
            health = dict(self._last_health)
        return {
            "enabled": self.enabled,
            "webhooks": len(hooks), "hooks": hooks,
            "cooldown": self.cooldown, "timeout": self.timeout,
            "on_health": self.on_health, "on_conflict": self.on_conflict,
            "queued": self._queue.qsize(),
            "stats": stats, "health_tracked": len(health),
        }

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        try:
            self._thread.join(timeout)
        except RuntimeError:
            pass
