#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
admin_server.py - mdns_responder 的 Web 管理 API（零第三方依赖）

由 mdns_responder.py 在进程内拉起，共享同一份状态、日志与配置：
    GET  /                       管理页面 admin.html
    GET  /api/status             运行状态与统计
    GET  /api/config             当前配置（结构化 + TOML 原文）
    POST /api/config             保存配置（校验 -> 备份 -> 原子替换 -> 触发热重载）
    GET  /api/records            将发布的 DNS 记录
    GET  /api/logs?limit=200     最近日志
    GET  /api/logs/stream        SSE 实时日志流
    POST /api/probe              发起一次 mDNS 查询并返回解析结果
    POST /api/reload             手动触发配置重载
    GET  /api/interfaces         可用网卡 / 接口选项
    GET  /api/health            健康探测结果（目标状态灯）
    GET  /api/queries           查询审计日志（有界环形，可 limit）
    GET  /api/browse            局域网服务地图（外来 DNS-SD 摄取）
    GET  /api/conflicts         名称冲突登记（本地同名异值）
    GET  /api/metrics           Prometheus 文本指标
    GET  /api/auth              管理员密码状态（是否已设置）
    GET  /api/config/history    配置版本快照列表
    GET  /api/alerts            告警编排器状态与统计
    POST /api/auth/password     设置 / 修改管理员密码
    POST /api/auth/verify       校验管理员密码
    POST /api/config/rollback   一键回滚到指定历史版本
    GET  /go/<domain>/<path>     网关：反代到该域名登记的目标；目标不可达/未找到时
                                返回友好页（非报错栈）
    未知路径 / 目标不可达       友好 404 / 503 页（与控制台同设计语言）

安全：默认仅监听 127.0.0.1；配置 management_token 后所有 API 需带
      X-Admin-Token 请求头（或 ?token= 查询参数）。
      **所有写操作**（改配置 / 回滚 / 改密）额外需要 X-Admin-Password，
      密码以 PBKDF2 加盐摘要存于 gitignored 的 auth.toml，绝不落明文。
      网关页与控制台首页同为公开。
"""

from __future__ import annotations

import http.client
import json
import logging
import logging.handlers
import os
import queue
import threading
import time
import tomllib
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

from mdns_responder import _slug

LOG = logging.getLogger("mdns.admin")

# ---------------------------------------------------------------------------
# 环形日志缓冲 + SSE 订阅
# ---------------------------------------------------------------------------
class RingLogHandler(logging.Handler):
    def __init__(self, capacity: int = 600):
        super().__init__(level=logging.DEBUG)
        self.capacity = capacity
        self.buffer: deque[dict] = deque(maxlen=capacity)
        self.subscribers: set[queue.Queue] = set()
        # 注意：不要覆盖 logging.Handler 自身的 self.lock（框架在 handle() 中已持有它），
        # 否则 emit 内再次加锁会与框架的可重入锁语义冲突，导致自死锁。
        self._buf_lock = threading.Lock()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            item = {
                "ts": record.created,
                "time": time.strftime("%H:%M:%S", time.localtime(record.created)),
                "level": record.levelname,
                "name": record.name,
                "msg": record.getMessage(),
            }
        except Exception:
            return
        with self._buf_lock:
            self.buffer.append(item)
            for sub in list(self.subscribers):
                try:
                    sub.put_nowait(item)
                except queue.Full:
                    pass

    def history(self, limit: int = 200) -> list[dict]:
        with self._buf_lock:
            return list(self.buffer)[-max(1, min(limit, self.capacity)):]

    def subscribe(self) -> queue.Queue:
        sub: queue.Queue = queue.Queue(maxsize=300)
        with self._buf_lock:
            self.subscribers.add(sub)
        return sub

    def unsubscribe(self, sub: queue.Queue) -> None:
        with self._buf_lock:
            self.subscribers.discard(sub)


# ---------------------------------------------------------------------------
# 有界文件日志：循环写 + 自动删除最老 + 可选按 mtime 过期
# ---------------------------------------------------------------------------
class BoundedRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """在 RotatingFileHandler 的数量上限之外，再按 mtime 删除过期归档。

    backupCount 保证文件数不超过 backupCount+1，是磁盘占用的硬上界；
    retention_days 提供额外的时间维度清理。两者叠加即「自动过期 + 循环写」。
    """

    def __init__(self, *args, retention_days: int = 0, **kwargs):
        super().__init__(*args, **kwargs)
        self.retention_days = max(0, int(retention_days))

    def doRollover(self) -> None:
        super().doRollover()
        if self.retention_days <= 0:
            return
        cutoff = time.time() - self.retention_days * 86400
        directory = os.path.dirname(self.baseFilename) or "."
        prefix = os.path.basename(self.baseFilename) + "."
        try:
            names = os.listdir(directory)
        except OSError:
            return
        for name in names:
            if not name.startswith(prefix) or not name[len(prefix):].isdigit():
                continue
            path = os.path.join(directory, name)
            try:
                if os.path.getmtime(path) < cutoff:
                    os.remove(path)
            except OSError:
                pass


def build_file_handler(log_cfg, root_dir: str | None = None) -> logging.Handler | None:
    """按配置构造有界轮转文件 handler；log_file 为空时返回 None。"""
    path = str(getattr(log_cfg, "log_file", "") or "").strip()
    if not path:
        return None
    max_bytes = int(getattr(log_cfg, "log_max_bytes", 10 * 1024 * 1024))
    backups = int(getattr(log_cfg, "log_backup_count", 5))
    retention = int(getattr(log_cfg, "log_retention_days", 0))
    if not os.path.isabs(path):
        root = root_dir or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(root, path)
    path = os.path.abspath(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    handler = BoundedRotatingFileHandler(
        path, maxBytes=max_bytes, backupCount=backups,
        encoding="utf-8", delay=False, retention_days=retention,
    )
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)-7s %(name)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    return handler


def log_disk_cap(log_cfg) -> int:
    """日志目录的理论最大磁盘占用（字节）；禁用文件日志时为 0。"""
    if not str(getattr(log_cfg, "log_file", "") or "").strip():
        return 0
    return (int(getattr(log_cfg, "log_max_bytes", 10 * 1024 * 1024))
            * (int(getattr(log_cfg, "log_backup_count", 5)) + 1))


_FILE_HANDLER: logging.Handler | None = None


def install_logging(log_cfg=None) -> RingLogHandler:
    """装配 root logger：控制台(可关) + 有界轮转文件 + 内存环形缓冲。幂等。"""
    global _FILE_HANDLER
    root = logging.getLogger()
    ring: RingLogHandler | None = None
    for handler in root.handlers:
        if isinstance(handler, RingLogHandler):
            ring = handler
            break
    if ring is None:
        ring = RingLogHandler()
        root.addHandler(ring)

    if log_cfg is None:
        return ring

    if not bool(getattr(log_cfg, "log_console", True)):
        for handler in list(root.handlers):
            if (isinstance(handler, logging.StreamHandler)
                    and not isinstance(handler, logging.FileHandler)
                    and not isinstance(handler, RingLogHandler)):
                root.removeHandler(handler)

    if _FILE_HANDLER is None:
        try:
            file_handler = build_file_handler(log_cfg)
        except OSError as exc:
            LOG.warning("文件日志初始化失败，仅保留控制台/SSE 日志: %s", exc)
        else:
            if file_handler is not None:
                root.addHandler(file_handler)
                _FILE_HANDLER = file_handler
    return ring


# ---------------------------------------------------------------------------
# TOML 序列化（仅覆盖本服务的固定结构）
# ---------------------------------------------------------------------------
def _toml_str(value: object) -> str:
    text = str(value)
    for src, dst in (("\\", "\\\\"), ('"', '\\"'), ("\n", "\\n"),
                     ("\r", "\\r"), ("\t", "\\t")):
        text = text.replace(src, dst)
    return '"' + text + '"'


def _toml_key(key: object) -> str:
    text = str(key)
    return text if text.replace("_", "").replace("-", "").isalnum() else _toml_str(text)


SERVER_FIELDS = (
    ("interface", str), ("group", str), ("port", int), ("ttl", int),
    ("announce_interval", int), ("announce_count", int), ("reverse_ptr", bool),
    ("management", bool), ("management_host", str),
    ("management_port", int), ("management_token", str),
    # HTTP 网关（Host 头反代 + 管理台收编）
    ("gateway", bool), ("gateway_port", int),
    ("gateway_admin_host", str), ("gateway_timeout", float),
    ("log_file", str), ("log_max_bytes", int), ("log_backup_count", int),
    ("log_retention_days", int), ("log_console", bool),
    # 可观测增强（health / audit / browse / conflict）
    ("health", bool), ("health_interval", int), ("health_timeout", float),
    ("audit", bool), ("audit_limit", int),
    ("browse", bool), ("browse_scan_interval", int), ("browse_limit", int),
    ("conflict_detect", bool),
    # 告警 Webhook / 配置版本历史（mdns_alerts.py / mdns_history.py）
    ("alert", bool), ("alert_cooldown", int), ("alert_on_health", bool),
    ("alert_on_conflict", bool), ("alert_timeout", float),
    ("alert_webhooks", list), ("history_limit", int),
)


def _normalize_gateway_field(key: str, value):
    """管理台表单的空值不该变成 0，否则开启网关时必然校验失败。

    仅作用于「表单保存」链路（dump_toml）；手工编辑 TOML 走 raw 分支，
    仍由 ServerConfig.validate() 严格校验，不会被这里悄悄改写。
    """
    if key == "gateway_port":
        try:
            n = int(value)
        except (TypeError, ValueError):
            return 80
        return n if 1 <= n <= 65535 else 80
    if key == "gateway_admin_host":
        return str(value or "").strip() or "mdns.local"
    if key == "gateway_timeout":
        try:
            f = float(value)
        except (TypeError, ValueError):
            return 5.0
        return f if f > 0 else 5.0
    return value


def dump_toml(config: dict) -> str:
    """把结构化配置序列化为 TOML；server 中未提交的键由调用方先合并进 config。"""
    lines = [
        "# mDNS Responder 配置 —— 由管理控制台生成",
        "# 原文件已备份为 config.toml.bak",
        "",
        "[server]",
    ]
    server = config.get("server", {}) or {}
    for key, cast in SERVER_FIELDS:
        if key not in server or server[key] is None:
            continue
        value = _normalize_gateway_field(key, server[key])
        if cast is bool:
            lines.append(f"{key} = {'true' if value else 'false'}")
        elif cast is int:
            lines.append(f"{key} = {int(value)}")
        elif cast is float:
            lines.append(f"{key} = {float(value)}")
        elif cast is list:
            items = [str(v) for v in (value or []) if str(v).strip()]
            lines.append(f"{key} = {json.dumps(items, ensure_ascii=False)}")
        else:
            lines.append(f"{key} = {_toml_str(value)}")

    for host in config.get("hosts", []) or []:
        lines += ["", "[[hosts]]",
                  f"name = {_toml_str(host.get('name', ''))}",
                  f"ip = {_toml_str(host.get('ip', ''))}"]

    for svc in config.get("services", []) or []:
        lines += ["", "[[services]]",
                  f"type = {_toml_str(svc.get('type', ''))}",
                  f"instance = {_toml_str(svc.get('instance', ''))}"]
        if svc.get("host"):
            lines.append(f"host = {_toml_str(svc['host'])}")
        lines += [f"ip = {_toml_str(svc.get('ip', ''))}",
                  f"port = {int(svc.get('port', 0))}"]
        txt = svc.get("txt") or {}
        if txt:
            pairs = ", ".join(f"{_toml_key(k)} = {_toml_str(v)}" for k, v in txt.items())
            lines.append(f"txt = {{ {pairs} }}")
        # 网关反代开关：始终显式落盘，保证 TOML 与界面开关一一对应。
        # 缺省仍为 true（兼容未写 proxy 的旧配置），只是不再省略。
        lines.append("proxy = " + ("false" if svc.get("proxy") is False else "true"))
    return "\n".join(lines) + "\n"


def merge_server(raw_text: str, submitted: dict) -> dict:
    """保留原 server 段中表单未提交的键（如 management_token），避免保存后丢失。"""
    try:
        existing = tomllib.loads(raw_text).get("server", {}) or {}
    except (tomllib.TOMLDecodeError, AttributeError):
        existing = {}
    merged = dict(existing)
    merged.update(submitted or {})
    return merged


# ---------------------------------------------------------------------------
# 友好返回页：域名已登记但目标不可达 / 域名未找到
# 设计语言与控制台一致（玻璃拟态 + 极光背景 + 细线 SVG），不暴露任何报错栈。
# ---------------------------------------------------------------------------
FRIENDLY_CODES = {"notfound": 404, "unreachable": 503}


def build_friendly_page(kind: str, domain: str = "", target: str = "",
                        detail: str = "") -> str:
    """返回一个自包含、双主题的友好 HTML 页面（无外部依赖）。"""
    if kind == "unreachable":
        code = 503
        eyebrow = "SERVICE UNREACHABLE"
        title = "这个地址暂时连不上"
        desc = ("我们找到了这个域名，但它背后那台服务没有回应。"
                "可能是服务刚停、网络抖动，或它换了端口。")
        icon = _ICON_OFFLINE
    else:
        code = 404
        eyebrow = "NOT FOUND"
        title = "这里没有可访问的服务"
        desc = ("这个域名没有在 mDNS 控制台里登记，所以不知道该去哪里找它。"
                "请确认域名拼写，或回到控制台补一条映射。")
        icon = _ICON_GHOST

    target_row = (f'<div class="kv"><span>目标地址</span><b class="mono">{_esc(target)}</b></div>'
                 if target else "")
    domain_row = (f'<div class="kv"><span>请求域名</span><b class="mono">{_esc(domain)}</b></div>'
                 if domain else "")
    hint = (f'<div class="hint">{_esc(detail)}</div>' if detail else "")

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>{code} · {title}</title>
<style>
:root{{--bg:#f2f4f9;--shell:rgba(255,255,255,.66);--core:#ffffff;
--ink:#101828;--ink-2:#5b6679;--ink-3:#98a2b3;--line:rgba(16,24,40,.10);
--accent:#4f46e5;--accent-2:#0891b2;--accent-soft:rgba(79,70,229,.10);
--aurora-1:rgba(99,102,241,.16);--aurora-2:rgba(6,182,212,.12);--grid:rgba(16,24,40,.03)}}
@media (prefers-color-scheme: dark){{:root{{--bg:#06080e;--shell:rgba(255,255,255,.05);
--core:rgba(17,22,34,.9);--ink:#eef2ff;--ink-2:#98a3b8;--ink-3:#5d6a82;--line:rgba(255,255,255,.10);
--accent:#818cf8;--accent-2:#22d3ee;--accent-soft:rgba(129,140,248,.14);
--aurora-1:rgba(99,102,241,.24);--aurora-2:rgba(34,211,238,.14);--grid:rgba(255,255,255,.022)}}}}
*,*::before,*::after{{box-sizing:border-box}}
html,body{{margin:0;height:100%}}
body{{background:var(--bg);color:var(--ink);
font-family:"Plus Jakarta Sans","Segoe UI",-apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif;
display:grid;place-items:center;min-height:100%;padding:28px;overflow:hidden}}
.aurora{{position:fixed;inset:0;z-index:0;pointer-events:none;overflow:hidden}}
.aurora::before,.aurora::after{{content:"";position:absolute;border-radius:50%;filter:blur(90px)}}
.aurora::before{{width:680px;height:680px;top:-300px;left:-140px;background:var(--aurora-1)}}
.aurora::after{{width:600px;height:600px;bottom:-320px;right:-120px;background:var(--aurora-2)}}
.grid{{position:fixed;inset:0;z-index:0;pointer-events:none;opacity:.5;
background-image:linear-gradient(var(--grid) 1px,transparent 1px),linear-gradient(90deg,var(--grid) 1px,transparent 1px);
background-size:56px 56px;-webkit-mask-image:radial-gradient(ellipse at 50% 40%,#000 8%,transparent 75%);
mask-image:radial-gradient(ellipse at 50% 40%,#000 8%,transparent 75%)}}
.card{{position:relative;z-index:2;width:min(520px,100%);border-radius:30px;border:1px solid var(--line);
background:var(--shell);backdrop-filter:blur(26px) saturate(150%);-webkit-backdrop-filter:blur(26px) saturate(150%);
box-shadow:0 32px 90px -46px rgba(16,24,40,.4);padding:38px 34px 30px;text-align:center}}
.ico{{width:84px;height:84px;margin:0 auto 18px;display:grid;place-items:center;border-radius:24px;color:#fff;
background:linear-gradient(140deg,var(--accent),var(--accent-2));
box-shadow:0 12px 30px -10px var(--accent),inset 0 1px 0 rgba(255,255,255,.35)}}
.badge{{display:inline-flex;align-items:center;gap:8px;padding:7px 15px;border-radius:99px;border:1px solid var(--line);
background:var(--core);font-size:10px;letter-spacing:.22em;text-transform:uppercase;font-weight:700;color:var(--ink-3);margin-bottom:16px}}
.badge b{{font-size:13px;color:var(--accent);letter-spacing:0}}
h1{{font-size:23px;letter-spacing:-.03em;margin:0 0 10px;font-weight:700}}
p{{margin:0 auto 18px;max-width:40ch;color:var(--ink-2);font-size:14px;line-height:1.6}}
.meta{{background:var(--core);border:1px solid var(--line);border-radius:16px;padding:10px 16px;margin:0 0 16px;text-align:left}}
.kv{{display:flex;justify-content:space-between;gap:14px;font-size:12.5px;padding:4px 0}}
.kv span{{color:var(--ink-3)}}.kv b{{color:var(--ink);font-weight:600}}
.hint{{font-size:12px;color:var(--ink-3);background:var(--accent-soft);border:1px solid var(--accent-soft);
border-radius:12px;padding:9px 13px;margin:0 0 18px;text-align:left}}
.act{{display:inline-flex;align-items:center;gap:9px;padding:11px 22px;border-radius:99px;font-size:13px;font-weight:700;
color:#fff;text-decoration:none;background:linear-gradient(135deg,var(--accent),var(--accent-2));
box-shadow:0 12px 28px -14px var(--accent),inset 0 1px 0 rgba(255,255,255,.28);transition:transform .5s cubic-bezier(.32,.72,0,1)}}
.act:hover{{transform:translateY(-1px)}}
.foot{{margin-top:16px;font-size:11px;color:var(--ink-3)}}
</style></head>
<body>
<div class="aurora"></div><div class="grid"></div>
<div class="card">
  <div class="ico">{icon}</div>
  <div class="badge"><span>HTTP</span><b>{code}</b><span>{eyebrow}</span></div>
  <h1>{title}</h1>
  <p>{desc}</p>
  <div class="meta">{domain_row}{target_row}</div>
  {hint}
  <a class="act" href="/">返回控制台</a>
  <div class="foot">mDNS Studio · 组播域名管理</div>
</div>
</body></html>"""


_ICON_OFFLINE = ('<svg width="40" height="40" viewBox="0 0 24 24" fill="none" '
                 'stroke="currentColor" stroke-width="1.6" stroke-linecap="round" '
                 'stroke-linejoin="round"><path d="M2 8.5a15 15 0 0 1 20 0"/>'
                 '<path d="M5 12a10 10 0 0 1 14 0"/>'
                 '<path d="M8.5 15.5a5 5 0 0 1 7 0"/>'
                 '<circle cx="12" cy="19" r="1.1" fill="currentColor" stroke="none"/>'
                 '<line x1="3" y1="3" x2="21" y2="21"/></svg>')

_ICON_GHOST = ('<svg width="40" height="40" viewBox="0 0 24 24" fill="none" '
               'stroke="currentColor" stroke-width="1.6" stroke-linecap="round" '
               'stroke-linejoin="round"><path d="M5 20v-9a7 7 0 0 1 14 0v9l-2.3-1.7L14.4 20l-2.4-1.7L9.6 20 '
               '8 18.3z"/><circle cx="9.2" cy="10.5" r="1" fill="currentColor" stroke="none"/>'
               '<circle cx="14.8" cy="10.5" r="1" fill="currentColor" stroke="none"/></svg>')


def _esc(value: str) -> str:
    return (str(value).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _short_exc(exc: Exception) -> str:
    """把连接异常翻译成一句人话，避免把底层异常类暴露给用户。"""
    text = str(exc).strip() or type(exc).__name__
    lowered = text.lower()
    if "refused" in lowered:
        return "目标拒绝了连接（服务可能没在监听这个端口）。"
    if "timed out" in lowered:
        return "连接超时，目标迟迟没有回应（网络不通或服务卡住）。"
    if "name or service not known" in lowered or "getaddrinfo" in lowered:
        return "目标地址本身无法解析。"
    if "network is unreachable" in lowered:
        return "网络不可达，本机到目标之间没有路由。"
    return f"连接失败：{text}"


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
class AdminHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler_cls, responder, log_handler, token,
                 gateway_admin_host: str = "", gateway_timeout: float = 6.0,
                 gateway_enabled: bool = False):
        super().__init__(address, handler_cls)
        self.responder = responder
        self.log_handler = log_handler
        self.token = token or ""
        # 网关相关（仅网关服务器 gateway_enabled=True 时生效；管理台服务器恒为 False）
        self.gateway_admin_host = gateway_admin_host or ""
        self.gateway_timeout = float(gateway_timeout or 6.0)
        self.gateway_enabled = gateway_enabled
        self.running = threading.Event()
        self.running.set()


class AdminHandler(BaseHTTPRequestHandler):
    server_version = "mDNSStudio/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        LOG.debug("%s - %s", self.address_string(), fmt % args)

    # -- helpers ------------------------------------------------------------
    def _cors(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers",
                         "Content-Type, X-Admin-Token, X-Admin-Password")

    def _json(self, obj: object, code: int = 200) -> None:
        body = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _authorized(self) -> bool:
        if not self.server.token:
            return True
        supplied = self.headers.get("X-Admin-Token", "")
        if not supplied:
            supplied = parse_qs(urlparse(self.path).query).get("token", [""])[0]
        return supplied == self.server.token

    def _text(self, body: str, code: int = 200,
              content_type: str = "text/plain; version=0.0.4; charset=utf-8") -> None:
        """纯文本响应（Prometheus 指标等）。"""
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self._cors()
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _admin_password(self) -> str:
        supplied = self.headers.get("X-Admin-Password", "")
        if not supplied:
            supplied = parse_qs(urlparse(self.path).query).get(
                "admin_password", [""])[0]
        return supplied or ""

    def _require_admin(self) -> bool:
        """写操作前置校验：未初始化密码 -> 409；密码错误/缺失 -> 403。

        返回 True 表示通过；False 表示响应已发出，调用方应立即 return。
        """
        responder = self.server.responder
        if not responder.auth.enabled:
            self._json({"error": "尚未设置管理员密码，请先在「安全设置」中初始化",
                        "code": "setup_required"}, 409)
            return False
        if not responder.verify_admin_password(self._admin_password()):
            self._json({"error": "管理员密码错误或缺失", "code": "auth_failed"}, 403)
            return False
        return True

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0) or 0)
        if not length:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError(f"请求体不是合法 JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError("请求体必须是 JSON 对象")
        return data

    def _page(self) -> None:
        # 前端位于项目根 web/ 目录，本模块位于 src/
        _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(_ROOT, "web", "admin.html")
        try:
            with open(path, "rb") as fh:
                body = fh.read()
        except OSError:
            body = b"<h1>admin.html not found</h1>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._cors()
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    # -- routes -------------------------------------------------------------
    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self._cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    # 网关：把 /go/<domain>/path 反代到该域名登记的目标；失败则给友好页而非报错栈
    def _lookup_target(self, domain: str, only_proxied: bool = True):
        """解析域名对应的反代目标 (ip, port)。

        only_proxied=True（默认）：仅返回「开启网关反代」的服务 / 域名映射目标，
        用于真正转发请求；proxy=false 的服务会被跳过（返回 None）。
        only_proxied=False：返回任何已登记匹配（无论是否开启反代），用于判断
        该域名是否「已登记」——网关据此把已登记但未开反代的服务导向友好页，
        而非误当成控制台。
        """
        cfg = self.server.responder.cfg
        name = domain.rstrip(".").lower()
        # 1) 服务发布优先：host 即 SRV target，目标为服务自身的 ip:port（显式端口）
        for s in cfg.services:
            host = (s.host or f"{_slug(s.instance)}.local").rstrip(".").lower()
            if host == name:
                if only_proxied and getattr(s, "proxy", True) is False:
                    return None
                return (s.ip, s.port)
        # 2) 纯域名映射（hosts）默认走 80（hosts 无独立反代开关，始终可反代）
        for h in cfg.hosts:
            if h.name.rstrip(".").lower() == name:
                return (h.ip, 80)
        return None

    def _gateway(self, parsed) -> None:
        rest = parsed.path[len("/go/"):]
        if "/" in rest:
            domain, sub = rest.split("/", 1)
            sub = "/" + sub
        else:
            domain, sub = rest, "/"
        domain = unquote(domain).strip()
        if not domain:
            return self._friendly("notfound", detail="网关路径缺少域名，例如 /go/nas.local/")
        target = self._lookup_target(domain)
        if not target:
            if self._lookup_target(domain, only_proxied=False):
                return self._friendly(
                    "notfound", domain=domain,
                    detail="该服务已登记但未开启网关反代（在「服务发布」中打开「网关反代」开关）")
            return self._friendly(
                "notfound", domain=domain,
                detail="该域名未在 mDNS 控制台登记，无法路由")
        ip, port = target
        query = parsed.query
        try:
            conn = http.client.HTTPConnection(ip, port, timeout=6)
            conn.request(
                "GET", sub + (("?" + query) if query else ""),
                headers={"Host": domain, "User-Agent": "mDNSStudio-Gateway/1.0",
                         "Accept": "*/*"})
            resp = conn.getresponse()
        except Exception as exc:  # noqa: BLE001 - 目标不可达统一走友好页
            return self._friendly(
                "unreachable", domain=domain, target=f"{ip}:{port}",
                detail=_short_exc(exc))
        try:
            body = resp.read()
            self.send_response(resp.status)
            for key, val in resp.getheaders():
                low = key.lower()
                if low in ("transfer-encoding", "connection", "keep-alive",
                           "content-length"):
                    continue
                self.send_header(key, val)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass
        finally:
            conn.close()

    def _friendly(self, kind: str, domain: str = "", target: str = "",
                  detail: str = "") -> None:
        html = build_friendly_page(kind, domain, target, detail)
        body = html.encode("utf-8")
        self.send_response(FRIENDLY_CODES.get(kind, 404))
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    # -- 网关（按 Host 头反代）-------------------------------------------------
    def _is_admin_request(self) -> bool:
        """是否为「管理台请求」。

        管理台服务器（gateway_enabled=False）永远返回 True：所有请求都交给
        管理台逻辑处理。网关服务器（gateway_enabled=True）才按 Host 头分流：
          1) Host == gateway_admin_host          -> 管理台（含所有路径）
          2) Host 命中已注册服务 / 域名映射        -> 反代（即使是根路径 /）
          3) 其余（盒子 IP / localhost / 未知）     -> 管理台（保留前缀 /api /admin 与根路径）
        这样 http://<服务名>/ 直达后端，而 http://<盒子IP>/ 与 http://<管理台域名>/
        都进控制台，互不冲突。
        """
        if not getattr(self.server, "gateway_enabled", False):
            return True
        host = (self.headers.get("Host", "").split(":")[0] or "").strip().lower()
        admin_host = (self.server.gateway_admin_host or "").strip().lower()
        if admin_host and host == admin_host:
            return True
        # 已登记的服务 / 域名映射（无论是否开启反代）都不交给控制台
        if self._lookup_target(host, only_proxied=False):
            return False
        path = urlparse(self.path).path
        if path.startswith("/api/") or path.startswith("/admin") or path == "/":
            return True
        return False

    def _gateway_by_host(self, method: str) -> None:
        """按 Host 头把请求反代到该域名登记的目标（services 显式端口 / hosts 默认 80）。

        这是「域名直达」的关键：浏览器访问 http://ratio-guard.local 走 80，
        网关读 Host 头找到目标 IP:端口并转发，等价于公司「防火墙 / 反代把域名映射到端口」。
        """
        host = (self.headers.get("Host", "").split(":")[0] or "").strip().lower()
        target = self._lookup_target(host)
        if not target:
            if self._lookup_target(host, only_proxied=False):
                return self._friendly(
                    "notfound", domain=host,
                    detail="该服务已登记但未开启网关反代（在「服务发布」中打开「网关反代」开关）")
            return self._friendly(
                "notfound", domain=host,
                detail="该域名未在 mDNS 控制台登记，无法路由（可在「服务发布」或「域名映射」中补一条）")
        ip, port = target
        # 自环保护：目标指向网关自身（同端口的回环地址）时直接报错，避免无限转发
        if port == self.server.server_address[1] and ip in ("127.0.0.1", "0.0.0.0", "::1"):
            return self._friendly(
                "unreachable", domain=host, target=f"{ip}:{port}",
                detail="目标指向网关自身，请改用管理台域名（gateway_admin_host）访问控制台")
        parsed = urlparse(self.path)
        timeout = getattr(self.server, "gateway_timeout", 6.0)
        try:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
            fwd: dict[str, str] = {}
            for key, val in self.headers.items():
                low = key.lower()
                if low in ("connection", "keep-alive", "proxy-connection",
                           "transfer-encoding", "content-length", "host"):
                    continue
                fwd[key] = val
            # 保留 Host 头，便于后端按虚拟主机路由
            fwd["Host"] = host
            body = None
            if method in ("POST", "PUT", "PATCH", "DELETE"):
                length = int(self.headers.get("Content-Length", 0) or 0)
                if length > 0:
                    body = self.rfile.read(length)
            conn.request(method, parsed.path + (("?" + parsed.query) if parsed.query else ""),
                         body=body, headers=fwd)
            resp = conn.getresponse()
            payload = resp.read()
        except Exception as exc:  # noqa: BLE001 - 目标不可达统一走友好页
            return self._friendly(
                "unreachable", domain=host, target=f"{ip}:{port}",
                detail=_short_exc(exc))
        try:
            self.send_response(resp.status)
            for key, val in resp.getheaders():
                low = key.lower()
                if low in ("transfer-encoding", "connection", "keep-alive",
                           "content-length", "server", "date"):
                    continue
                self.send_header(key, val)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass
        finally:
            conn.close()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path in ("/", "/index.html"):
            return self._page()
        if path.startswith("/go/"):
            return self._gateway(parsed)
        if not self._authorized():
            return self._json({"error": "unauthorized", "hint": "需要 X-Admin-Token"}, 401)

        responder = self.server.responder
        try:
            if path == "/api/status":
                return self._json(responder.status())
            if path == "/api/config":
                return self._json(responder.config_json())
            if path == "/api/records":
                return self._json({"items": responder.records_json()})
            if path == "/api/logs":
                limit = int(parse_qs(urlparse(self.path).query).get("limit", ["200"])[0])
                return self._json({"items": self.server.log_handler.history(limit)})
            if path == "/api/logs/stream":
                return self._stream_logs()
            if path == "/api/interfaces":
                return self._json({"items": responder.interfaces()})
            if path == "/api/health":
                return self._json(responder.insights_health())
            if path == "/api/queries":
                limit = int(parse_qs(urlparse(self.path).query).get("limit", ["100"])[0])
                return self._json(responder.insights_queries(limit))
            if path == "/api/browse":
                return self._json(responder.insights_browse())
            if path == "/api/conflicts":
                return self._json(responder.insights_conflicts())
            if path == "/api/metrics":
                return self._text(responder.metrics_text())
            if path == "/api/auth":
                return self._json(responder.auth_state())
            if path == "/api/config/history":
                return self._json(responder.config_history())
            if path == "/api/alerts":
                return self._json(responder.alerts_state())
            # 未知路径：给友好 404 页，而不是让人头大的报错栈
            return self._friendly("notfound", domain=path,
                                 detail="管理控制台没有这个地址")
        except Exception as exc:  # noqa: BLE001 - API 边界统一转 JSON 错误
            LOG.exception("GET %s 失败", path)
            return self._json({"error": str(exc)}, 500)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if not self._authorized():
            return self._json({"error": "unauthorized"}, 401)
        responder = self.server.responder
        try:
            payload = self._body()

            # -- 管理员密码（首次设置无需旧密码；之后需带 X-Admin-Password）--
            if path == "/api/auth/password":
                try:
                    result = responder.set_admin_password(
                        self._admin_password(), payload.get("new_password", ""))
                except PermissionError as exc:
                    return self._json({"error": str(exc), "code": "auth_failed"}, 403)
                except ValueError as exc:
                    return self._json({"error": str(exc), "code": "invalid_password"}, 400)
                return self._json({"ok": True, **result})
            if path == "/api/auth/verify":
                ok = responder.verify_admin_password(self._admin_password())
                return self._json({"ok": ok, "code": None if ok else "auth_failed"},
                                  200 if ok else 403)

            # -- 所有变更类操作统一要求管理员密码 --
            if path == "/api/config":
                if not self._require_admin():
                    return None
                return self._json(responder.save_config(payload))
            if path == "/api/config/rollback":
                if not self._require_admin():
                    return None
                return self._json(responder.rollback_config(str(payload.get("id", ""))))

            if path == "/api/reload":
                responder.request_reload()
                return self._json({"ok": True, "message": "已触发配置重载"})
            if path == "/api/probe":
                return self._json(responder.probe_once(payload.get("name", ""),
                                                       payload.get("type", "ANY")))
            return self._json({"error": "not found", "path": path}, 404)
        except ValueError as exc:
            return self._json({"error": str(exc)}, 400)
        except FileNotFoundError as exc:
            return self._json({"error": str(exc)}, 404)
        except Exception as exc:  # noqa: BLE001
            LOG.exception("POST %s 失败", path)
            return self._json({"error": str(exc)}, 500)

    def _stream_logs(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-transform")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self._cors()
        self.end_headers()
        sub = self.server.log_handler.subscribe()
        try:
            self.wfile.write(b": connected\n\n")
            self.wfile.flush()
            while self.server.running.is_set():
                try:
                    item = sub.get(timeout=10)
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                    continue
                payload = json.dumps(item, ensure_ascii=False).encode("utf-8")
                self.wfile.write(b"data: " + payload + b"\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError, ValueError):
            pass
        finally:
            self.server.log_handler.unsubscribe(sub)


# ---------------------------------------------------------------------------
# 生命周期
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# 网关：在独立端口（默认 80）按 Host 头反代 + 收编管理台
# ---------------------------------------------------------------------------
class GatewayHandler(AdminHandler):
    """网关端口处理器：Host 头命中服务 -> 反代；命中管理台域名 / 盒子 IP -> 控制台。

    复用 AdminHandler 的全部管理 API 与友好页，仅把「根 / 未知路径」的默认行为
    从「404」改为「按 Host 反代」。原 /go/<domain>/ 路径反代仍保留。
    """

    def _dispatch_admin(self) -> None:
        # 管理台只用了 GET / POST；HEAD 退化为只读流程
        if self.command == "POST":
            return super().do_POST()
        return super().do_GET()

    def do_GET(self) -> None:
        if self._is_admin_request():
            return self._dispatch_admin()
        parsed = urlparse(self.path)
        if parsed.path.startswith("/go/"):
            return self._gateway(parsed)
        return self._gateway_by_host("GET")

    def do_POST(self) -> None:
        if self._is_admin_request():
            return self._dispatch_admin()
        return self._gateway_by_host("POST")

    def do_HEAD(self) -> None:
        if self._is_admin_request():
            return self._dispatch_admin()
        return self._gateway_by_host("HEAD")

    def do_PUT(self) -> None:
        if self._is_admin_request():
            return self._dispatch_admin()
        return self._gateway_by_host("PUT")

    def do_DELETE(self) -> None:
        if self._is_admin_request():
            return self._dispatch_admin()
        return self._gateway_by_host("DELETE")

    def do_PATCH(self) -> None:
        if self._is_admin_request():
            return self._dispatch_admin()
        return self._gateway_by_host("PATCH")


class HTTPGatewayServer(AdminHTTPServer):
    """网关服务器：在网关端口上启用 Host 路由（gateway_enabled=True）。"""


def start_gateway(responder, log_handler: RingLogHandler | None = None):
    """在独立线程启动 HTTP 网关（默认 80）：按 Host 头反代 + 收编管理台。

    端口冲突（如本机已有 Web 服务占用 80）时仅告警，不影响 mDNS 主服务。
    """
    server_cfg = responder.cfg.server
    if not getattr(server_cfg, "gateway", False):
        return None
    handler = log_handler or install_logging()
    try:
        httpd = HTTPGatewayServer(
            ("0.0.0.0", server_cfg.gateway_port),
            GatewayHandler, responder, handler, server_cfg.management_token,
            gateway_admin_host=server_cfg.gateway_admin_host,
            gateway_timeout=server_cfg.gateway_timeout,
            gateway_enabled=True,
        )
    except OSError as exc:
        LOG.warning("HTTP 网关启动失败（不影响 mDNS 服务）: %s", exc)
        return None
    thread = threading.Thread(target=httpd.serve_forever, name="mdns-gateway", daemon=True)
    thread.start()
    admin_hint = server_cfg.gateway_admin_host or "(本机 IP 或 /admin)"
    LOG.info("HTTP 网关已启动: http://0.0.0.0:%d/  (管理台域名=%s)",
             server_cfg.gateway_port, admin_hint)
    return httpd


def start_admin(responder, log_handler: RingLogHandler | None = None):
    """在独立线程启动管理 HTTP 服务；端口冲突时仅告警，不影响 mDNS 主服务。"""
    server_cfg = responder.cfg.server
    if not getattr(server_cfg, "management", False):
        return None
    handler = log_handler or install_logging()
    try:
        httpd = AdminHTTPServer(
            (server_cfg.management_host, server_cfg.management_port),
            AdminHandler, responder, handler, server_cfg.management_token,
        )
    except OSError as exc:
        LOG.warning("管理界面启动失败（不影响 mDNS 服务）: %s", exc)
        return None
    thread = threading.Thread(target=httpd.serve_forever, name="mdns-admin", daemon=True)
    thread.start()
    host = server_cfg.management_host
    LOG.info("管理界面已启动: http://%s:%d/", host, server_cfg.management_port)
    return httpd


def stop_admin(httpd) -> None:
    if httpd is None:
        return
    httpd.running.clear()
    try:
        httpd.shutdown()
        httpd.server_close()
    except OSError:
        pass
