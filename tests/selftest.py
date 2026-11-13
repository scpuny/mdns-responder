#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
selftest.py - mdns_responder 离线单元测试 + 真实组播端到端测试

    python3 tests/selftest.py                    # 全部
    python3 tests/selftest.py --offline          # 仅离线报文测试（不碰网络）
    python3 tests/selftest.py --standard-port    # 追加 5353 共存验证
"""

from __future__ import annotations

import argparse
import contextlib
import io
import logging
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time

# 代码位于 ../src，配置位于项目根 ../
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)

import mdns_probe  # noqa: E402
from mdns_responder import (  # noqa: E402
    CLASS_IN, QU_BIT, TYPE_A, TYPE_ANY, TYPE_PTR, TYPE_SRV, TYPE_TXT,
    Question, build_query, build_records, build_response, decode_name,
    encode_name, load_config, parse_query,
)

PASSED = 0
FAILED = 0


def check(cond: bool, label: str) -> None:
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  PASS  {label}")
    else:
        FAILED += 1
        print(f"  FAIL  {label}")


# ---------------------------------------------------------------------------
# 离线测试
# ---------------------------------------------------------------------------
def offline() -> None:
    print("\n[1] 域名编解码")
    for name in ("nas.local", "Office Web._http._tcp.local",
                 r"a\.b.local", "设备.local"):
        wire = encode_name(name)
        decoded, end = decode_name(wire, 0)
        check(decoded.replace("\\", "") == name.replace("\\", "")
              and end == len(wire), f"往返 {name!r}")

    # 压缩指针：offset 12 处放 name，随后用 0xC00C 指向它
    base = struct.pack("!6H", 0, 0, 0, 0, 0, 0) + encode_name("ptr-target.local")
    compressed = base + b"\xc0\x0c"
    decoded, end = decode_name(compressed, len(base))
    check(decoded == "ptr-target.local" and end == len(base) + 2,
          "压缩指针 0xC00C 解码")

    print("\n[2] 查询报文解析")
    query = build_query([("nas.local", TYPE_A),
                         ("Office Web._http._tcp.local", TYPE_SRV)], unicast=True)
    msg = parse_query(query, ("127.0.0.1", 5353))
    check(msg is not None and len(msg.questions) == 2, "多 question 解析")
    check(msg is not None and all(q.wants_unicast for q in msg.questions), "QU 位识别")
    check(msg is not None and msg.questions[0].name == "nas.local", "域名大小写/尾点归一化")

    print("\n[3] 应答构造")
    cfg = load_config(os.path.join(ROOT, "config.toml"))
    records, by_key = build_records(cfg)

    def answer_for(name, qtype):
        q = build_query([(name, qtype)])
        m = parse_query(q, ("127.0.0.1", 5353))
        return build_response(records, by_key, m.questions, m.known_answers, 0)

    pkt = answer_for("nas.local", TYPE_A)
    _flags, lines = mdns_probe.parse_response(pkt or b"")
    check(pkt is not None and any("172.15.103.30" in ln for ln in lines),
          "A 查询 -> 正确的 A 记录")

    pkt = answer_for("_http._tcp.local", TYPE_PTR)
    _flags, lines = mdns_probe.parse_response(pkt or b"")
    joined = "\n".join(lines)
    check("PTR" in joined and "SRV" in joined and "TXT" in joined and "8080" in joined,
          "PTR 查询 -> PTR + SRV/TXT/A 附加记录齐备")

    pkt = answer_for("Office Web._http._tcp.local", TYPE_ANY)
    _flags, lines = mdns_probe.parse_response(pkt or b"")
    joined = "\n".join(lines)
    check("SRV" in joined and "TXT" in joined and "172.15.103.30" in joined,
          "ANY 查询实例名 -> SRV + TXT + A")

    pkt = answer_for("Office Web._http._tcp.local", TYPE_SRV)
    _flags, lines = mdns_probe.parse_response(pkt or b"")
    check("port=8080" in "\n".join(lines), "SRV 查询 -> 端口 8080")

    pkt = answer_for("_services._dns-sd._udp.local", TYPE_PTR)
    _flags, lines = mdns_probe.parse_response(pkt or b"")
    check(sum("PTR" in ln for ln in lines) >= 2, "服务类型枚举 -> 2 条以上 PTR")

    pkt = answer_for("30.103.15.172.in-addr.arpa", TYPE_PTR)
    _flags, lines = mdns_probe.parse_response(pkt or b"")
    check("nas.local" in "\n".join(lines), "IPv4 反查 PTR -> 域名")

    check(answer_for("not-exist.local", TYPE_A) is None, "未配置的域名不应产生应答")
    check(answer_for("nas.local", TYPE_TXT) is None, "类型不匹配不应产生应答")

    print("\n[4] Known-Answer 抑制")
    # 构造带 answer 段的查询：客户端宣称已知 nas.local A 172.15.103.30
    question_section = build_query([("nas.local", TYPE_A)])[12:]
    known_rr = (encode_name("nas.local")
                + struct.pack("!HHIH", TYPE_A, CLASS_IN, 120, 4)
                + socket.inet_aton("172.15.103.30"))
    packet = struct.pack("!6H", 0, 0, 1, 1, 0, 0) + question_section + known_rr
    msg = parse_query(packet, ("127.0.0.1", 5353))
    check(msg is not None and len(msg.known_answers) == 1, "解析客户端 known-answer")
    suppressed = build_response(records, by_key, msg.questions, msg.known_answers, 0)
    check(suppressed is None, "已知答案被抑制，不重复应答")

    # known-answer 中使用压缩指针指向 question 里的域名
    ptr_rr = b"\xc0\x0c" + struct.pack("!HHIH", TYPE_A, CLASS_IN, 120, 4) \
        + socket.inet_aton("172.15.103.30")
    packet2 = struct.pack("!6H", 0, 0, 1, 1, 0, 0) + question_section + ptr_rr
    msg2 = parse_query(packet2, ("127.0.0.1", 5353))
    check(msg2 is not None and ("nas.local", TYPE_A,
                               socket.inet_aton("172.15.103.30")) in msg2.known_answers,
          "known-answer 中压缩指针域名可规范化")

    print("\n[5] QU / 单播应答 ID 回显")
    quni = [Question("nas.local", TYPE_A, CLASS_IN | QU_BIT)]
    pkt = build_response(records, by_key, quni, set(), 0x1234)
    check(pkt is not None and struct.unpack("!H", pkt[:2])[0] == 0x1234,
          "单播应答回显 query ID")


# ---------------------------------------------------------------------------
# 真实组播端到端测试
# ---------------------------------------------------------------------------
TEST_CONFIG = """\
[server]
interface = "0.0.0.0"
group = "224.0.0.251"
port = {port}
ttl = 120
announce_interval = 0
announce_count = 0
management = false

[[hosts]]
name = "nas.local"
ip = "172.15.103.30"

[[hosts]]
name = "camera.local"
ip = "172.15.103.31"

[[services]]
type = "_http._tcp.local"
instance = "Office Web"
host = "nas.local"
ip = "172.15.103.30"
port = 8080
txt = {{ path = "/" }}
"""


def run_probe(names, qtype, port, multicast=False, timeout=2.0) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        try:
            mdns_probe.probe([(n, qtype) for n in names], "224.0.0.251", port,
                             timeout, False, multicast)
        except SystemExit:
            pass
    return buf.getvalue()


def e2e() -> None:
    print("\n[6] 真实组播端到端（临时端口 15353，不干扰系统 mDNS）")
    port = 15353
    tmpdir = tempfile.mkdtemp(prefix="mdns-selftest-")
    cfg_path = os.path.join(tmpdir, "config.toml")
    with open(cfg_path, "w", encoding="utf-8") as fh:
        fh.write(TEST_CONFIG.format(port=port))

    proc = subprocess.Popen(
        [sys.executable, os.path.join(SRC, "mdns_responder.py"), "-c", cfg_path],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    output = ""
    try:
        time.sleep(0.9)
        check(proc.poll() is None, "responder 进程成功启动并持有组播 socket")

        out = run_probe(["nas.local"], TYPE_A, port, timeout=1.8)
        print("      " + out.strip().replace("\n", "\n      "))
        check("172.15.103.30" in out, "单播应答路径：A 查询返回配置 IP")

        out = run_probe(["Office Web._http._tcp.local"], TYPE_ANY, port,
                        multicast=True, timeout=1.8)
        print("      " + out.strip().replace("\n", "\n      "))
        check("port=8080" in out and "172.15.103.30" in out,
              "组播应答路径：ANY 查询返回 SRV 端口 + 附加 A 记录")

        out = run_probe(["_services._dns-sd._udp.local"], TYPE_PTR, port,
                        timeout=1.8)
        check("_http._tcp.local" in out, "服务类型枚举查询")

        # 热重载：只改 camera.local 的 IP，等待 mtime 检测
        with open(cfg_path, "r", encoding="utf-8") as fh:
            changed = fh.read().replace('ip = "172.15.103.31"',
                                        'ip = "172.15.103.99"')
        # 保证 mtime_ns 变化
        os.utime(cfg_path, ns=(time.time_ns() - 5_000_000_000,
                               time.time_ns()))
        with open(cfg_path, "w", encoding="utf-8") as fh:
            fh.write(changed)
        time.sleep(1.4)
        out = run_probe(["camera.local"], TYPE_A, port, timeout=1.8)
        check("172.15.103.99" in out, "配置热重载：改 IP 后无需重启即生效")
    finally:
        proc.terminate()
        try:
            output = proc.communicate(timeout=5)[0] or ""
        except subprocess.TimeoutExpired:
            proc.kill()
            output = proc.communicate()[0] or ""
        print("      --- responder 日志（尾部） ---")
        for line in output.strip().splitlines()[-12:]:
            print("      " + line)
    check("goodbye" in output, "SIGTERM 时发送 goodbye（TTL=0）")


COEXIST_CONFIG = """\
[server]
interface = "0.0.0.0"
group = "224.0.0.251"
port = 5353
ttl = 120
announce_interval = 0
announce_count = 0
reverse_ptr = false
management = false

[[hosts]]
name = "wb-mdns-coexist-test.local"
ip = "127.0.0.1"
"""


def verify_standard_port() -> None:
    """验证可与系统已占用 5353 的 avahi/Chrome/systemd-resolved 共存（不发送任何报文）。"""
    print("\n[7] 标准端口 5353 共存（仅验证绑定与加组，不主动发包）")
    tmpdir = tempfile.mkdtemp(prefix="mdns-coexist-")
    cfg_path = os.path.join(tmpdir, "config.toml")
    with open(cfg_path, "w", encoding="utf-8") as fh:
        fh.write(COEXIST_CONFIG)
    proc = subprocess.Popen(
        [sys.executable, os.path.join(SRC, "mdns_responder.py"), "-c", cfg_path],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    time.sleep(1.0)
    alive = proc.poll() is None
    proc.terminate()
    try:
        out = proc.communicate(timeout=5)[0] or ""
    except subprocess.TimeoutExpired:
        proc.kill()
        out = proc.communicate()[0] or ""
    for line in out.strip().splitlines()[-8:]:
        print("      " + line)
    check(alive and "监听 224.0.0.251:5353" in out and "启动失败" not in out,
          "SO_REUSEPORT 与系统既有 5353 socket 共存")


ADMIN_CONFIG = """\
[server]
interface = "0.0.0.0"
group = "224.0.0.251"
port = {port}
ttl = 120
announce_interval = 0
announce_count = 0
reverse_ptr = false
management = true
management_host = "127.0.0.1"
management_port = {admin_port}
management_token = "{token}"

[[hosts]]
name = "nas.local"
ip = "172.15.103.30"

[[services]]
type = "_http._tcp.local"
instance = "Office Web"
host = "nas.local"
ip = "172.15.103.30"
port = 8080
txt = {{ path = "/" }}
"""
ADMIN_TOKEN = "selftest-token-9527"
ADMIN_PASSWORD = "selftest-admin-pw-2026"
ADMIN_PASSWORD_NEW = "selftest-admin-pw-2027"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def verify_admin_api() -> None:
    """管理控制台真实 HTTP 端到端：页面 / REST / SSE / 鉴权 / 配置写回热重载。"""
    import json
    import urllib.error
    import urllib.request

    print("\n[8] 管理控制台 HTTP API（真实进程）")
    port, admin_port = _free_port(), _free_port()
    tmpdir = tempfile.mkdtemp(prefix="mdns-admin-")
    cfg_path = os.path.join(tmpdir, "config.toml")
    with open(cfg_path, "w", encoding="utf-8") as fh:
        fh.write(ADMIN_CONFIG.format(port=port, admin_port=admin_port, token=ADMIN_TOKEN))
    base = f"http://127.0.0.1:{admin_port}"
    # 本地管理接口必须直连：开发机常设 http_proxy 且未配 no_proxy，
    # 否则 urllib 会把 127.0.0.1 的请求发给代理，拿回 HTML 错误页导致 JSON 解析失败。
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def req(path, method="GET", body=None, auth=True, want_json=True, pw=None):
        headers = {"Content-Type": "application/json"}
        if auth:
            headers["X-Admin-Token"] = ADMIN_TOKEN
        if pw:
            headers["X-Admin-Password"] = pw
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(base + path, data=data, headers=headers, method=method)
        try:
            with opener.open(request, timeout=6) as resp:
                raw = resp.read().decode("utf-8", "replace")
                return resp.status, (json.loads(raw) if want_json else raw)
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace")
            return exc.code, (json.loads(raw) if want_json and raw else raw)
        except Exception as exc:  # noqa: BLE001
            return 0, {"error": str(exc)}

    env = os.environ.copy()
    env["MDNS_AUTH_FILE"] = os.path.join(tmpdir, "auth.toml")
    env["MDNS_HISTORY_DIR"] = os.path.join(tmpdir, "config_history")
    proc = subprocess.Popen(
        [sys.executable, os.path.join(SRC, "mdns_responder.py"), "-c", cfg_path],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env,
    )
    out = ""
    try:
        time.sleep(1.0)
        check(proc.poll() is None, "带管理界面的 responder 启动成功")

        code, page = req("/", want_json=False)
        check(code == 200 and "mDNS Studio" in page and 'id="view"' in page,
              "GET / 返回单文件管理页面")

        code, st = req("/api/status")
        check(code == 200 and st.get("running") is True and st.get("records", 0) > 0,
              "GET /api/status 返回运行状态与记录数")
        check(isinstance(st.get("stats"), dict) and st.get("management", {}).get("enabled"),
              "状态包含统计与管理接口信息")

        code, cfg = req("/api/config")
        check(code == 200 and "[server]" in cfg.get("raw", "")
              and len(cfg.get("config", {}).get("hosts", [])) == 1,
              "GET /api/config 返回 TOML 原文与结构化配置")

        code, rec = req("/api/records")
        check(code == 200 and any(r["type"] == "A" for r in rec.get("items", [])),
              "GET /api/records 返回 A / SRV / TXT 等记录")

        code, ifaces = req("/api/interfaces")
        check(code == 200 and "0.0.0.0" in ifaces.get("items", []),
              "GET /api/interfaces 返回网卡选项")

        # 可观测增强 API：健康 / 审计 / 浏览 / 冲突（默认开启，含 items/结构）
        code, hlth = req("/api/health")
        check(code == 200 and hlth.get("enabled") is True
              and isinstance(hlth.get("items"), list),
              "GET /api/health 返回健康目标结构")
        check(any(t.get("key", "").startswith("host:nas.local")
                  for t in hlth.get("items", [])),
              "健康目标包含已登记 host")
        code, qry = req("/api/queries?limit=20")
        check(code == 200 and qry.get("enabled") is True
              and isinstance(qry.get("items"), list),
              "GET /api/queries 返回查询审计结构")
        code, brw = req("/api/browse")
        check(code == 200 and brw.get("enabled") is True
              and "count" in brw and "items" in brw,
              "GET /api/browse 返回局域网地图结构")
        code, cfl = req("/api/conflicts")
        check(code == 200 and cfl.get("enabled") is True
              and cfl.get("count", 0) >= 0,
              "GET /api/conflicts 返回冲突登记结构")

        code, logs = req("/api/logs?limit=20")
        check(code == 200 and len(logs.get("items", [])) > 0,
              "GET /api/logs 返回环形缓冲日志")

        code, result = req("/api/probe", "POST", {"name": "nas.local", "type": "A"})
        check(code == 200 and any("172.15.103.30" in r.get("value", "")
                                  for r in result.get("records", [])),
              "POST /api/probe 发起真实查询并解析应答")

        # SSE：直接读一小段 HTTP 响应，确认事件流已建立
        try:
            with socket.create_connection(("127.0.0.1", admin_port), timeout=3) as s:
                s.settimeout(1.5)
                s.sendall(("GET /api/logs/stream?token=" + ADMIN_TOKEN +
                           " HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\n\r\n"
                           ).encode())
                head = b""
                try:
                    while b"connected" not in head and len(head) < 16384:
                        chunk = s.recv(4096)
                        if not chunk:
                            break
                        head += chunk
                except socket.timeout:
                    pass
            check(b"text/event-stream" in head and b"connected" in head,
                  "GET /api/logs/stream 建立 SSE 事件流")
        except OSError as exc:
            check(False, f"SSE 事件流失败: {exc}")

        code, denied = req("/api/status", auth=False)
        check(code == 401 and "unauthorized" in str(denied), "未带 token 的 API 返回 401")

        # ---- Prometheus 指标 / 管理员密码 / 告警 / 版本历史 ----
        code, metrics = req("/api/metrics", want_json=False)
        check(code == 200 and "mdns_responder_up 1" in metrics
              and "# TYPE mdns_responder_up gauge" in metrics,
              "GET /api/metrics 返回 Prometheus 文本指标")
        code, authst = req("/api/auth")
        check(code == 200 and authst.get("enabled") is False,
              "GET /api/auth 返回管理员密码未初始化状态")
        code, al = req("/api/alerts")
        check(code == 200 and "stats" in al and al.get("webhooks") == 0,
              "GET /api/alerts 返回告警编排器状态")
        code, hist0 = req("/api/config/history")
        check(code == 200 and "items" in hist0,
              "GET /api/config/history 返回版本列表")
        code, blocked = req("/api/config", "POST", {"raw": cfg["raw"]})
        check(code == 409 and blocked.get("code") == "setup_required",
              "未设置管理员密码时写操作被拒绝（409）")
        code, setup = req("/api/auth/password", "POST",
                          {"new_password": ADMIN_PASSWORD})
        check(code == 200 and setup.get("ok") and setup.get("enabled"),
              "首次设置管理员密码成功")
        code, verify = req("/api/auth/verify", "POST", {}, pw=ADMIN_PASSWORD)
        check(code == 200 and verify.get("ok") is True, "正确管理员密码校验通过")
        code, verify_bad = req("/api/auth/verify", "POST", {}, pw="wrong-pw")
        check(code == 403, "错误管理员密码校验返回 403")
        code, weak = req("/api/auth/password", "POST",
                         {"new_password": "123"}, pw=ADMIN_PASSWORD)
        check(code == 400 and weak.get("code") == "invalid_password",
              "过短新密码被拒绝")
        code, wrongpw = req("/api/config", "POST", {"raw": cfg["raw"]},
                            pw="wrong-pw")
        check(code == 403 and wrongpw.get("code") == "auth_failed",
              "密码错误时写操作被拒绝（403）")

        # 结构化保存 -> 备份 -> 热重载生效（需管理员密码）
        new_cfg = cfg["config"]
        new_cfg["hosts"].append({"name": "printer.local", "ip": "172.15.103.77"})
        code, saved = req("/api/config", "POST", {"config": new_cfg},
                          pw=ADMIN_PASSWORD)
        check(code == 200 and saved.get("ok") is True, "POST /api/config 结构化保存成功")
        check(os.path.isfile(cfg_path + ".bak"), "保存前生成 config.toml.bak 备份")
        time.sleep(1.2)
        code, rec2 = req("/api/records")
        check(any(r["name"] == "printer.local" and "172.15.103.77" in r["value"]
                  for r in rec2.get("items", [])),
              "保存后热重载生效，新域名已发布")

        code, bad = req("/api/config", "POST", {
            "raw": '[server]\nport = 5353\n\n[[hosts]]\nname = "x.local"\nip = "not-an-ip"\n'
        }, pw=ADMIN_PASSWORD)
        check(code == 400, "非法配置被拒绝（HTTP 400）")
        code, rec3 = req("/api/records")
        check(any(r["name"] == "printer.local" for r in rec3.get("items", [])),
              "校验失败时原配置未被破坏")

        code, reload_result = req("/api/reload", "POST", {})
        check(code == 200 and reload_result.get("ok") is True, "POST /api/reload 手动重载")

        # ---- 配置版本历史 + 一键回滚 ----
        code, hist1 = req("/api/config/history")
        check(hist1["count"] >= 1, "保存配置自动生成版本快照")
        code, cfg_now = req("/api/config")
        cfg2 = cfg_now["config"]
        cfg2["hosts"] = [h for h in cfg2["hosts"]
                         if h["name"] != "printer.local"]
        code, saved2 = req("/api/config", "POST", {"config": cfg2},
                           pw=ADMIN_PASSWORD)
        check(code == 200 and saved2.get("ok"), "第二次保存成功（移除域名）")
        time.sleep(1.2)
        code, rec_mid = req("/api/records")
        check(not any(r["name"] == "printer.local" for r in rec_mid["items"]),
              "第二次保存后域名已移除")
        code, hist2 = req("/api/config/history")
        target = hist2["items"][0]["id"]
        code, rb = req("/api/config/rollback", "POST", {"id": target},
                       pw=ADMIN_PASSWORD)
        check(code == 200 and rb.get("ok")
              and rb.get("rolled_back_to") == target,
              "POST /api/config/rollback 一键回滚成功")
        time.sleep(1.2)
        code, rec_back = req("/api/records")
        check(any(r["name"] == "printer.local" for r in rec_back["items"]),
              "回滚后配置恢复（printer.local 重新发布）")
        code, badid = req("/api/config/rollback", "POST",
                          {"id": "../../etc/passwd"}, pw=ADMIN_PASSWORD)
        check(code == 400, "非法版本 ID 被拒绝（防路径穿越）")

        # ---- 修改管理员密码 ----
        code, chp = req("/api/auth/password", "POST",
                        {"new_password": ADMIN_PASSWORD_NEW}, pw=ADMIN_PASSWORD)
        check(code == 200 and chp.get("ok"), "修改管理员密码成功")
        code, old_bad = req("/api/auth/verify", "POST", {}, pw=ADMIN_PASSWORD)
        check(code == 403, "旧密码立即失效")
        code, new_ok = req("/api/auth/verify", "POST", {}, pw=ADMIN_PASSWORD_NEW)
        check(code == 200 and new_ok.get("ok"), "新密码生效")
    finally:
        proc.terminate()
        try:
            out = proc.communicate(timeout=5)[0] or ""
        except subprocess.TimeoutExpired:
            proc.kill()
            out = proc.communicate()[0] or ""
        for line in out.strip().splitlines()[-6:]:
            print("      " + line)
    check("管理界面已启动" in out and "goodbye" in out,
          "管理线程随主服务一起启停")


def log_rotation() -> None:
    print("\n[9] 有界文件日志轮转（磁盘占用有确定上界）")
    from admin_server import build_file_handler, log_disk_cap

    max_bytes = 1024
    backups = 3
    tmpdir = tempfile.mkdtemp(prefix="mdns-logtest-")
    path = os.path.join(tmpdir, "mdns.log")

    class Cfg:
        log_file = path
        log_max_bytes = max_bytes
        log_backup_count = backups
        log_retention_days = 0
        log_console = True

    cfg = Cfg()
    check(log_disk_cap(cfg) == max_bytes * (backups + 1),
          "磁盘上界 = max_bytes × (backup_count + 1)")

    handler = build_file_handler(cfg)
    check(handler is not None, "按配置构造轮转文件 handler")
    logger = logging.getLogger("mdns.selftest.rotation")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    logger.addHandler(handler)
    for i in range(600):
        logger.info("轮转压力测试 %04d %s", i, "x" * 100)
    handler.flush()
    logger.removeHandler(handler)
    handler.close()

    files = sorted(f for f in os.listdir(tmpdir) if f.startswith("mdns.log"))
    total = sum(os.path.getsize(os.path.join(tmpdir, f)) for f in files)
    check(len(files) <= backups + 1,
          f"历史文件数受 backup_count 限制（实际 {len(files)} 个）")
    check(total <= max_bytes * (backups + 1) + 2048,
          f"日志总字节有上界（实际 {total}B）")
    check(any(f == "mdns.log.1" for f in files), "轮转生成 .1 归档文件")

    class Off:
        log_file = ""
        log_max_bytes = max_bytes
        log_backup_count = backups
        log_retention_days = 0
        log_console = True

    check(build_file_handler(Off()) is None and log_disk_cap(Off()) == 0,
          "log_file 为空时完全不写文件")

    class Expire(Cfg):
        log_retention_days = 1

    h3 = build_file_handler(Expire())
    check(getattr(h3, "retention_days", 0) == 1, "retention_days 传入轮转 handler")
    h3.close()

    # 管理页面保存配置时，日志字段必须随 server 段一起保留，否则会被覆盖丢失
    from admin_server import dump_toml, merge_server
    merged = merge_server("[server]\nlog_max_bytes = 2048\nlog_backup_count = 9\n",
                          {"port": 5353})
    saved = dump_toml({"server": merged, "hosts": [], "services": []})
    check("log_max_bytes = 2048" in saved and "log_backup_count = 9" in saved,
          "管理页面保存配置时保留 log_* 字段")


def friendly_page() -> None:
    """网关友好页：两种场景的文案、状态码、双主题，且不含任何报错栈。"""
    print("\n[11] 网关友好页（目标不可达 / 未找到）")
    from admin_server import build_friendly_page, FRIENDLY_CODES

    for kind, exp_code, exp_title in (
        ("notfound", 404, "这里没有可访问的服务"),
        ("unreachable", 503, "这个地址暂时连不上"),
    ):
        html = build_friendly_page(
            kind, domain="nas.local", target="172.15.103.30:8080",
            detail="目标拒绝了连接")
        check(FRIENDLY_CODES.get(kind) == exp_code, f"{kind} 状态码 = {exp_code}")
        check(exp_title in html, f"{kind} 含友好标题而非报错文案")
        check("@media (prefers-color-scheme: dark)" in html, f"{kind} 含双主题适配")
        check("<!DOCTYPE html>" in html and "</html>" in html, f"{kind} 是完整 HTML 文档")
        check("Traceback" not in html and "Error" not in html,
              f"{kind} 不暴露报错栈 / Error 字样")
        check("nas.local" in html and "172.15.103.30:8080" in html,
              f"{kind} 展示请求域名与目标地址")


def insights() -> None:
    """可观测增强离线测试：SRV 解析 / 查询审计 / 冲突判定 / 浏览聚合（纯逻辑）。"""
    print("\n[10] 可观测增强（健康 / 审计 / 冲突 / 浏览）")
    from mdns_insights import (
        BrowseState, ConflictState, QueryAudit, parse_srv_value, tcp_probe)

    # --- SRV 值解析
    check(parse_srv_value("port=8080  target=nas.local.") == (8080, "nas.local"),
          "SRV 值解析出 port + target")
    check(parse_srv_value("garbage") == (None, ""), "SRV 值解析容错非法输入")

    # --- 查询审计（环形 + 最新在前 + hit 字段 + maxlen 下限）
    q = Question("nas.local", TYPE_A, CLASS_IN)
    audit = QueryAudit(maxlen=5)
    check(audit.maxlen == 10, "审计 maxlen 有 10 条下限（过小无意义）")
    audit.record("10.0.0.1", 5353, [q], hit=True, unicast=False)
    check(audit.total == 1, "查询审计记录一条")
    check(audit.recent(10)[0]["client"].startswith("10.0.0.1"),
          "审计 recent 最新在前")
    for i in range(30):
        audit.record("10.0.0.2", 5353, [q], hit=(i % 2 == 0))
    aj = audit.json(50)
    check(len(aj["items"]) == 10, "审计环形上界 = 实际 maxlen（10，旧值被挤掉）")
    check(aj["total"] == 31, "审计 total 累计独立于环形")
    check(aj["buffer"] == 10 and all("hit" in it for it in aj["items"]),
          "审计项含 hit 字段且 buffer 反映当前容量")

    # --- 冲突判定（同名异值去重 + 计数 + 过期）
    conf = ConflictState()
    conf.ingest("A", "nas.local", "192.168.1.5", "172.16.5.9:5353", now=1000.0)
    conf.ingest("A", "nas.local", "192.168.1.5", "172.16.5.9:5353", now=1001.0)
    conf.ingest("A", "nas.local", "192.168.1.6", "172.16.5.9:5353", now=1002.0)
    cj = conf.json()
    check(cj["count"] == 1, "冲突按 (类型, 名) 去重为一条")
    check(cj["items"][0]["count"] == 3, "冲突累计出现次数")
    check(set(cj["items"][0]["theirs"]) == {"192.168.1.5", "192.168.1.6"},
          "冲突保留对方取值集合（去重）")
    conf2 = ConflictState(max_age=1.0)
    conf2.ingest("A", "x.local", "1.1.1.1", "2.2.2.2:5353", now=1000.0)
    conf2.purge(now=1002.0)
    check(conf2.json()["count"] == 0, "冲突按 max_age 过期清除")

    # --- 浏览聚合（PTR/SRV/TXT/A 摄取成实例地图 + TTL 过期 + 本机标记）
    bs = BrowseState()
    bs.ingest("PTR", "_http._tcp.local", "Office Web._http._tcp.local.",
              120, "172.16.5.9:5353", False, now=1000.0)
    bs.ingest("SRV", "office web._http._tcp.local",
              "port=8080  target=nas.local.", 120, "172.16.5.9:5353", False, now=1000.0)
    bs.ingest("TXT", "office web._http._tcp.local", "path=/  version=1.0",
              120, "172.16.5.9:5353", False, now=1000.0)
    bs.ingest("A", "nas.local", "172.15.103.30", 120, "172.16.5.9:5353", False, now=1000.0)
    bj = bs.json()
    check(bj["count"] == 1, "浏览聚合为单实例（跨 record 归并）")
    it = bj["items"][0]
    check(it["instance"] == "office web" and it["port"] == 8080,
          "浏览解析 instance（DNS 名小写）+ SRV 端口")
    check(it["host"] == "nas.local" and it["host_ip"] == "172.15.103.30",
          "浏览由 SRV target（去尾点）+ A 记录回填 host_ip")
    check(it["ours"] is False, "外部实例未标记本机")

    bs2 = BrowseState(grace=1.0)
    bs2.ingest("SRV", "a._http._tcp.local", "port=1  target=h.",
               60, "1.1.1.1:5353", False, now=1000.0)
    removed = bs2.purge(now=1000.0 + 60 + 1.0 + 1)
    check(removed == 1 and bs2.json()["count"] == 0,
          "浏览按 TTL+grace 过期清除")

    bs3 = BrowseState()
    bs3.ingest("SRV", "mine._http._tcp.local", "port=9  target=m.",
               120, "127.0.0.1:5353", True, now=1000.0)
    check(bs3.json()["items"][0]["ours"] is True, "浏览标记本机回显为 ours")

    # --- 健康探测（只校验返回契约，不依赖真实可达性）
    up, ms = tcp_probe("127.0.0.1", 1, timeout=0.1)
    check(isinstance(up, bool) and isinstance(ms, int) and ms >= 0,
          "tcp_probe 返回 (bool, 非负 ms)")


def platform_features() -> None:
    """管理密码 / 版本历史 / 告警 / Prometheus —— 纯逻辑离线测试。"""
    import json
    print("\n[12] 管理密码 / 版本历史 / 告警 / Prometheus（纯逻辑）")
    from mdns_security import AuthManager, validate_password
    from mdns_history import ConfigHistory
    from mdns_alerts import AlertManager, build_payload, infer_platform
    from mdns_responder import format_metrics
    from admin_server import dump_toml, merge_server

    tmp = tempfile.mkdtemp(prefix="mdns-platform-")

    # --- 管理员密码：加盐摘要 / 常量时间 / 改密 / 重启可加载 ---------------
    auth_path = os.path.join(tmp, "auth.toml")
    auth = AuthManager(path=auth_path)
    check(not auth.enabled, "初始未设置管理员密码")
    check(not auth.verify("whatever"), "未启用时任何密码都校验失败")
    try:
        validate_password("short")
        check(False, "过短密码应被拒绝")
    except ValueError:
        check(True, "过短密码被拒绝（至少 8 位）")
    auth.set_password("correct-horse-9527")
    check(auth.enabled, "首次设置密码后启用")
    check(auth.verify("correct-horse-9527"), "正确密码校验通过")
    check(not auth.verify("wrong"), "错误密码校验失败")
    with open(auth_path, "r", encoding="utf-8") as fh:
        raw = fh.read()
    check("correct-horse-9527" not in raw, "auth.toml 不含明文密码")
    check("pbkdf2_sha256" in raw and "salt" in raw, "auth.toml 含算法与随机盐")
    check(oct(os.stat(auth_path).st_mode & 0o777) == "0o600", "auth.toml 权限 0600")
    reopened = AuthManager(path=auth_path)
    check(reopened.enabled and reopened.verify("correct-horse-9527"),
          "重新加载 auth.toml 后密码仍有效")
    try:
        reopened.set_password("new-password-123", "wrong-old")
        check(False, "旧密码错误应被拒绝")
    except PermissionError:
        check(True, "改密时旧密码错误被拒绝")
    reopened.set_password("new-password-123", "correct-horse-9527")
    check(reopened.verify("new-password-123")
          and not reopened.verify("correct-horse-9527"), "改密后旧密码立即失效")

    # --- 配置版本历史：有界 / 读回 / 防穿越 --------------------------------
    hist = ConfigHistory(directory=os.path.join(tmp, "history"), limit=3)
    for i in range(5):
        hist.save(f"# version {i}\n[server]\nport = 5353\n", reason="before-save")
    items = hist.list()
    check(len(items) == 3, "历史快照有界保留（limit=3）")
    check(items[0]["reason"] == "before-save", "历史元数据含来源")
    check(hist.get(items[0]["id"]).startswith("# version"), "按 ID 可读回 TOML 原文")
    try:
        hist.get("../../etc/passwd")
        check(False, "非法 ID 应被拒绝")
    except ValueError:
        check(True, "非法版本 ID 被拒绝（防路径穿越）")
    try:
        hist.get("config-20000101T000000Z-abcdef-1234.json")
        check(False, "不存在的版本应报错")
    except FileNotFoundError:
        check(True, "不存在的版本返回 FileNotFoundError")

    # --- 告警：平台识别 / 载荷 / 状态翻转 / 冷却 / 失败计数 ----------------
    sent: list = []

    def fake_sender(url, body, timeout):
        sent.append((url, json.loads(body.decode("utf-8"))))

    alerts = AlertManager(
        webhooks=["https://oapi.dingtalk.com/robot/send?access_token=x",
                  "https://hooks.slack.com/services/xxx",
                  "https://example.com/hook"],
        cooldown=0, timeout=1, sender=fake_sender)
    check(infer_platform("https://open.feishu.cn/open-apis/bot/v2/hook/x") == "feishu",
          "飞书平台按 URL 识别")
    check(infer_platform("https://qyapi.weixin.qq.com/cgi-bin/webhook/send") == "wecom",
          "企业微信平台按 URL 识别")
    check(infer_platform("https://example.com/hook") == "generic",
          "未知 URL 走通用 JSON")
    ding = json.loads(build_payload(
        "dingtalk", {"title": "t", "detail": "d", "level": "critical",
                     "time": "now"}).decode("utf-8"))
    check(ding["msgtype"] == "markdown" and "t" in ding["markdown"]["text"],
          "钉钉 markdown 载荷正确")
    generic = json.loads(build_payload(
        "generic", {"kind": "health", "title": "t", "detail": "d",
                    "level": "info", "ts": 1}).decode("utf-8"))
    check(generic["source"] == "mdns-responder" and generic["kind"] == "health",
          "通用 JSON 载荷含来源与事件类型")
    base = {"key": "host:nas.local", "label": "nas.local",
            "target": "172.15.103.30:80", "status": "up",
            "latency_ms": 3, "failures": 0}
    check(alerts.check_health([base]) == 0, "首次探测只记基线，不告警")
    down = dict(base, status="down", failures=1)
    check(alerts.check_health([down]) == 1, "up -> down 触发一次告警")
    check(alerts.check_health([down]) == 0, "状态未变化不重复告警")
    deadline = time.time() + 3
    while len(sent) < 3 and time.time() < deadline:
        time.sleep(0.02)
    check(len(sent) == 3, "告警异步投递到 3 个 webhook")
    check(alerts.state()["stats"]["sent"] == 3, "告警 sent 统计正确")
    check(alerts.emit_conflict("nas.local", "192.168.1.9", "172.16.5.9:5353"),
          "名称冲突告警入队")
    cold = AlertManager(webhooks=[], cooldown=100, sender=fake_sender)
    check(cold.emit("health", "k", "t", "d") is True, "首次事件登记成功")
    check(cold.emit("health", "k", "t", "d") is False, "冷却窗口内重复事件被去重")

    def bad_sender(url, body, timeout):
        raise OSError("boom")

    failing = AlertManager(webhooks=["https://example.com/hook"],
                           cooldown=0, sender=bad_sender)
    failing.emit("test", "k2", "t", "d")
    deadline = time.time() + 4
    while failing.state()["stats"]["failed"] == 0 and time.time() < deadline:
        time.sleep(0.02)
    check(failing.state()["stats"]["failed"] == 1, "webhook 发送失败被计数")
    alerts.stop()
    cold.stop()
    failing.stop()

    # --- TOML 序列化：新字段（数组 / 浮点 / 布尔）--------------------------
    text = dump_toml({
        "server": {"port": 5353, "alert": True, "alert_timeout": 5.0,
                   "alert_webhooks": ["https://a", "https://b"]},
        "hosts": [], "services": []})
    check('alert_webhooks = ["https://a", "https://b"]' in text,
          "TOML 序列化支持 webhook 字符串数组")
    check("alert_timeout = 5.0" in text and "alert = true" in text,
          "TOML 序列化支持新增浮点 / 布尔字段")
    merged = merge_server(text, {"port": 5454})
    check(merged["alert_webhooks"] == ["https://a", "https://b"]
          and merged["port"] == 5454,
          "merge_server 保留表单未提交的新字段")

    # --- Prometheus 文本 ---------------------------------------------------
    status = {
        "running": True, "uptime": 123, "records": 13, "hosts": 2,
        "services": 2, "ttl": 120,
        "stats": {"queries": 10, "responses": 9, "bytes": 1000, "announces": 2},
        "insights": {"audit": {"total": 10}, "browse": {"instances": 5},
                     "conflicts": {"count": 1}},
        "security": {"admin_password_enabled": True},
        "history": {"count": 2, "limit": 30},
        "logging": {"max_disk_bytes": 1024},
        "config_saves": 3,
    }
    extra = {
        "health_items": [
            dict(base, kind="host"),
            {"key": "svc:0:x", "label": "bad", "target": "1.2.3.4:9",
             "kind": "service", "status": "down", "latency_ms": None},
        ],
        "alerts": {"enabled": True, "webhooks": 2, "queued": 0,
                   "stats": {"events": 3, "sent": 3, "failed": 0, "dropped": 0}},
    }
    metrics = format_metrics(status, extra)
    check("mdns_responder_up 1" in metrics
          and "# TYPE mdns_responder_up gauge" in metrics,
          "指标含 HELP / TYPE 与 up 值")
    check('mdns_responder_health_status{target="nas.local"' in metrics
          and "mdns_responder_health_down 1" in metrics,
          "指标含带标签的健康状态与聚合计数")
    check("mdns_responder_alert_sent_total 3" in metrics
          and "mdns_responder_config_saves_total 3" in metrics,
          "指标含告警与配置写入计数")
    check(metrics.endswith("\n"), "指标以换行结束")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--offline", action="store_true", help="仅运行离线报文测试")
    parser.add_argument("--standard-port", action="store_true",
                        help="额外验证标准 5353 端口与系统 mDNS 共存")
    args = parser.parse_args()
    offline()
    insights()
    platform_features()
    log_rotation()
    friendly_page()
    if not args.offline:
        e2e()
        verify_admin_api()
    if args.standard_port:
        verify_standard_port()
    print(f"\n===== {PASSED} passed, {FAILED} failed =====")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
