#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mdns_insights.py - mDNS 可观测增强层（零第三方依赖）

在 responder 之上提供四类「网络洞察」能力，全部运行于同进程内、
无外部依赖、可独立单测：

1. HealthMonitor   周期 TCP 探测已登记的 host(80) / service(ip:port)，
                   产出 up/down/unknown 状态灯与延迟；
2. QueryAudit      有界环形查询审计日志（谁在查什么、命中与否）；
3. ConflictState   名称冲突登记：外来应答中出现与本地发布
                   同名同类型但不同值的 RR 即视为冲突（RFC 6762 防御观测）；
4. BrowseState     局域网服务浏览：摄取外来 DNS-SD 应答，按 TTL 过期，
                   形成「局域网服务地图」。

冲突 / 浏览共用一条摄取管道：responder 收到任何 QR=1 的外来报文
（含 avahi、Chrome、其他 mDNS 实现与自身回环）都会喂给 ingest，
本地记录经 local_values 索引自然标记为 ours、不产生假冲突。
"""

from __future__ import annotations

import re
import socket
import threading
import time
from collections import deque
from typing import Callable, Iterable

LOG = __import__("logging").getLogger("mdns.insights")

# 常见 mDNS 服务类型：浏览查询时顺带枚举，提高「首次就有地图」的概率
WELL_KNOWN_TYPES: tuple[str, ...] = (
    "_http._tcp.local", "_https._tcp.local", "_ssh._tcp.local",
    "_ftp._tcp.local", "_print._tcp.local", "_ipp._tcp.local",
    "_smb._tcp.local", "_nfs._tcp.local",
)


def tcp_probe(ip: str, port: int, timeout: float = 2.0) -> tuple[bool, int]:
    """TCP 连通性探测。返回 (是否可达, 耗时毫秒)。连接成功立即关闭。"""
    started = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True, int((time.monotonic() - started) * 1000)
    except (OSError, ValueError):
        return False, int((time.monotonic() - started) * 1000)


# ---------------------------------------------------------------------------
# 查询审计
# ---------------------------------------------------------------------------
class QueryAudit:
    """有界环形审计日志：记录每个查询包（来源、question 列表、命中）。"""

    def __init__(self, maxlen: int = 500):
        self.maxlen = max(10, int(maxlen))
        self._items: deque[dict] = deque(maxlen=self.maxlen)
        self._lock = threading.Lock()
        self.total = 0

    def record(self, client: str, client_port: int,
               questions: list, hit: bool, unicast: bool = False) -> None:
        now = time.time()
        item = {
            "ts": now,
            "time": time.strftime("%H:%M:%S", time.localtime(now)),
            "client": f"{client}:{client_port}",
            "names": [q.name for q in questions],
            "qtypes": [getattr(q, "qtype_name", "") for q in questions],
            "hit": bool(hit),
            "unicast": bool(unicast),
        }
        with self._lock:
            self._items.append(item)
            self.total += 1

    def recent(self, limit: int = 100) -> list[dict]:
        with self._lock:
            items = list(self._items)
        return items[-max(1, limit):][::-1]      # 最新在前

    def json(self, limit: int = 100) -> dict:
        with self._lock:
            total, size = self.total, len(self._items)
        return {"items": self.recent(limit), "total": total, "buffer": size}


# ---------------------------------------------------------------------------
# 名称冲突
# ---------------------------------------------------------------------------
class ConflictState:
    """登记「本地发布同名但值不同」的外来 RR。

    ingest() 只在调用方确认 (rtype, name) 存在于本地发布、且 value 与本地
    所有取值都不相同时才调用——自身回环应答（值相同）天然被排除。
    300 秒内无再次出现的冲突会被 purge() 清掉。
    """

    def __init__(self, maxlen: int = 200, max_age: float = 300.0):
        self.maxlen = max(1, int(maxlen))
        self.max_age = float(max_age)
        self._items: dict[tuple, dict] = {}
        self._order: deque[tuple] = deque()
        self._lock = threading.Lock()

    def ingest(self, rtype_name: str, name: str, value: str,
               source: str, now: float | None = None) -> None:
        now = now or time.time()
        key = (rtype_name, name.lower())
        with self._lock:
            item = self._items.get(key)
            if item is None:
                if len(self._items) >= self.maxlen:
                    oldest = self._order.popleft()
                    self._items.pop(oldest, None)
                item = {
                    "rtype": rtype_name, "name": name, "theirs": [],
                    "source": source, "first_seen": now, "last_seen": now,
                    "count": 0,
                }
                self._items[key] = item
                self._order.append(key)
            if value not in item["theirs"] and len(item["theirs"]) < 8:
                item["theirs"].append(value)
            item["source"] = source
            item["last_seen"] = now
            item["count"] += 1

    def purge(self, now: float | None = None) -> None:
        now = now or time.time()
        with self._lock:
            stale = [k for k, v in self._items.items()
                     if now - v["last_seen"] > self.max_age]
            for k in stale:
                self._items.pop(k, None)
                try:
                    self._order.remove(k)
                except ValueError:
                    pass

    def json(self) -> dict:
        with self._lock:
            items = []
            for v in self._items.values():
                items.append({
                    "rtype": v["rtype"], "name": v["name"],
                    "theirs": list(v["theirs"]), "source": v["source"],
                    "first_seen": v["first_seen"], "last_seen": v["last_seen"],
                    "count": v["count"],
                    "stale": (time.time() - v["last_seen"]) > self.max_age,
                })
        items.sort(key=lambda x: -x["last_seen"])
        return {"count": len(items), "items": items}


# ---------------------------------------------------------------------------
# 局域网服务浏览
# ---------------------------------------------------------------------------
_SRV_VALUE_RE = re.compile(r"port=(\d+)\s+target=(.+)\.?")


def parse_srv_value(value: str) -> tuple[int | None, str]:
    """把 'port=8080  target=nas.local.' 解回 (port, host)。"""
    m = _SRV_VALUE_RE.search(value or "")
    if not m:
        return None, ""
    return int(m.group(1)), m.group(2).rstrip(".")


class BrowseState:
    """摄取外来 DNS-SD 应答，聚合成服务实例地图。

    ingest() 参数：
        rtype_name  记录类型名（PTR/SRV/TXT/A/AAAA/...）
        name        RR 名称（已小写）
        value       人类可读值（与 _record_value 同风格）
        ttl         记录 TTL（用于过期）
        source      应答来源 ip:port
        is_ours     是否本地自身记录（回环/重复宣告）
    """

    def __init__(self, maxlen: int = 400, grace: float = 60.0):
        self.maxlen = max(10, int(maxlen))
        self.grace = float(grace)               # 过期宽限（TTL + grace）
        self._svcs: dict[str, dict] = {}        # fqdn(小写) -> 实例信息
        self._lock = threading.Lock()
        self.last_scan = 0.0

    def ingest(self, rtype_name: str, name: str, value: str,
               ttl: int, source: str, is_ours: bool,
               now: float | None = None) -> None:
        now = now or time.time()
        rtype = rtype_name.upper()
        name_l = (name or "").lower()          # 统一小写键，避免大小写拆成多实例
        with self._lock:
            if rtype == "PTR":
                # 服务类型枚举：_http._tcp.local -> 实例 fqdn
                if name_l.startswith("_") and not name_l.startswith("_services"):
                    m = re.match(r"^_.*\._(tcp|udp)\.local$", name_l)
                    if m:
                        inst = (value or "").rstrip(".").lower()
                        if inst:
                            self._ensure(inst, now, source, is_ours, ttl)
                            self._svcs[inst]["type"] = name_l
                # 实例枚举：_http._tcp.local -> Office Web._http._tcp.local
                elif name_l.startswith("_"):
                    inst = (value or "").rstrip(".").lower()
                    if inst and "." in inst:
                        self._ensure(inst, now, source, is_ours, ttl)

            elif rtype == "SRV":
                port, host = parse_srv_value(value)
                info = self._ensure(name_l, now, source, is_ours, ttl)
                if port is not None:
                    info["port"] = port
                if host:
                    info["host"] = host

            elif rtype == "TXT":
                info = self._ensure(name_l, now, source, is_ours, ttl)
                info["txt"] = value

            elif rtype in ("A", "AAAA"):
                # host 名 -> ip 回填到实例的 host_ip
                target = name_l
                for info in self._svcs.values():
                    if info.get("host", "").lower() == target:
                        info["host_ip"] = value
                        break

            if len(self._svcs) > self.maxlen:     # 硬上界保护
                oldest = sorted(self._svcs.items(),
                                key=lambda kv: kv[1]["last_seen"])
                for key, _ in oldest[: len(self._svcs) - self.maxlen]:
                    self._svcs.pop(key, None)

    def _ensure(self, fqdn: str, now: float, source: str,
                is_ours: bool, ttl: int) -> dict:
        info = self._svcs.get(fqdn)
        if info is None:
            parts = fqdn.split(".", 1)
            info = {
                "fqdn": fqdn,
                "instance": parts[0] if parts else fqdn,
                "type": parts[1] if len(parts) > 1 else "",
                "port": None, "host": "", "txt": "",
                "source": source, "first_seen": now,
                "last_seen": now, "ttl": ttl, "ours": is_ours,
            }
            self._svcs[fqdn] = info
        else:
            info["last_seen"] = now
            info["ttl"] = max(info.get("ttl") or 0, ttl)
            if is_ours:
                info["ours"] = True
            if source:
                info["source"] = source
        return info

    def purge(self, now: float | None = None) -> int:
        """按 TTL 过期清理，返回被清除数量。"""
        now = now or time.time()
        with self._lock:
            stale = [k for k, v in self._svcs.items()
                     if now - v["last_seen"] > (v.get("ttl") or 120) + self.grace]
            for k in stale:
                self._svcs.pop(k, None)
            return len(stale)

    def json(self) -> dict:
        with self._lock:
            items = list(self._svcs.values())
        for it in items:
            it["instance"] = it.get("instance") or it["fqdn"].split(".", 1)[0]
        items.sort(key=lambda x: x.get("type", ""))
        return {
            "count": len(items),
            "items": items,
            "last_scan": self.last_scan,
        }


# ---------------------------------------------------------------------------
# 健康监控
# ---------------------------------------------------------------------------
class HealthMonitor:
    """后台线程：周期 TCP 探测 responder.health_targets() 的全部目标。

    * health_interval <= 0 时暂停探测（每 5s 重新检查一次配置）；
    * 结果存于 dict，线程安全；API 侧读快照；
    * 新增目标首次探测前状态为 unknown。
    """

    def __init__(self, responder, target_getter: Callable[[], list],
                 get_interval: Callable[[], int],
                 get_timeout: Callable[[], float],
                 start: bool = True):
        self._responder = responder
        self._targets = target_getter
        self._interval = get_interval
        self._timeout = get_timeout
        self._results: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._loop, name="mdns-health", daemon=True)
        if start:
            self._thread.start()

    def start(self) -> None:
        """（重新）启动探测线程。已运行则忽略。"""
        if self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop,
                                        name="mdns-health", daemon=True)
        self._thread.start()

    # -- 探测循环 --------------------------------------------------------
    def _loop(self) -> None:
        first_cycle = True
        while not self._stop.is_set():
            interval = self._interval()
            if interval <= 0:
                self._stop.wait(5)
                first_cycle = True
                continue
            if not first_cycle:
                self._stop.wait(interval)
                if self._stop.is_set():
                    break
            first_cycle = False
            timeout = self._timeout()
            for key, kind, label, ip, port in self._targets():
                if self._stop.is_set():
                    break
                up, elapsed_ms = tcp_probe(ip, port, timeout)
                with self._lock:
                    prev = self._results.get(key) or {}
                    self._results[key] = {
                        "key": key, "kind": kind, "label": label,
                        "target": f"{ip}:{port}", "ip": ip, "port": port,
                        "status": "up" if up else "down",
                        "latency_ms": elapsed_ms,
                        "checked_at": time.time(),
                        "failures": 0 if up else prev.get("failures", 0) + 1,
                        "up_since": (prev.get("up_since")
                                     if up and prev else time.time()),
                    }
            # 配置热重载可能删掉目标：清理陈旧结果
            with self._lock:
                live = {t[0] for t in self._targets()}
                for stale in list(self._results):
                    if stale not in live:
                        self._results.pop(stale, None)

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        try:
            self._thread.join(timeout)
        except RuntimeError:
            pass

    def is_alive(self) -> bool:
        return self._thread.is_alive()

    def items(self) -> list[dict]:
        targets = self._targets()
        with self._lock:
            results = dict(self._results)
        out: list[dict] = []
        for key, kind, label, ip, port in targets:
            res = results.get(key)
            if res is None:
                out.append({
                    "key": key, "kind": kind, "label": label,
                    "target": f"{ip}:{port}", "ip": ip, "port": port,
                    "status": "unknown", "latency_ms": None,
                    "checked_at": None, "failures": 0, "up_since": None,
                })
            else:
                out.append(res)
        return out
