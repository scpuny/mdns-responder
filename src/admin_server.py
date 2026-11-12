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
    GET  /go/<domain>/<path>     网关：反代到该域名登记的目标；目标不可达/未找到时
                                返回友好页（非报错栈）
    未知路径 / 目标不可达       友好 404 / 503 页（与控制台同设计语言）

安全：默认仅监听 127.0.0.1；配置 management_token 后所有 API 需带
      X-Admin-Token 请求头（或 ?token= 查询参数）。网关页与控制台首页同为公开。
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
    ("log_file", str), ("log_max_bytes", int), ("log_backup_count", int),
    ("log_retention_days", int), ("log_console", bool),
    # 可观测增强（health / audit / browse / conflict）
    ("health", bool), ("health_interval", int), ("health_timeout", float),
    ("audit", bool), ("audit_limit", int),
    ("browse", bool), ("browse_scan_interval", int), ("browse_limit", int),
    ("conflict_detect", bool),
)


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
        value = server[key]
        if cast is bool:
            lines.append(f"{key} = {'true' if value else 'false'}")
        elif cast is int:
            lines.append(f"{key} = {int(value)}")
        elif cast is float:
            lines.append(f"{key} = {float(value)}")
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

    def __init__(self, address, handler_cls, responder, log_handler, token):
        super().__init__(address, handler_cls)
        self.responder = responder
        self.log_handler = log_handler
        self.token = token or ""
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
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Admin-Token")

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
    def _lookup_target(self, domain: str):
        """同名既是 host（隐式 80）又是服务 host（显式端口）时，服务端口优先。

        服务发布带显式 ip:port，是比 host 的默认 80 更具体的声明，故先解析服务；
        仅当域名只是纯 host 映射时才回退到 80。避免「配了 8080 却访问到 80」。
        """
        cfg = self.server.responder.cfg
        name = domain.rstrip(".").lower()
        # 1) 服务发布优先：host 即 SRV target，目标为服务自身的 ip:port（显式端口）
        for s in cfg.services:
            host = (s.host or f"{_slug(s.instance)}.local").rstrip(".").lower()
            if host == name:
                return (s.ip, s.port)
        # 2) 纯域名映射（hosts）默认走 80
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
            if path == "/api/config":
                return self._json(responder.save_config(payload))
            if path == "/api/reload":
                responder.request_reload()
                return self._json({"ok": True, "message": "已触发配置重载"})
            if path == "/api/probe":
                return self._json(responder.probe_once(payload.get("name", ""),
                                                       payload.get("type", "ANY")))
            return self._json({"error": "not found", "path": path}, 404)
        except ValueError as exc:
            return self._json({"error": str(exc)}, 400)
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
