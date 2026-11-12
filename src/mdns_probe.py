#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mdns_probe.py - mDNS 查询探针 / 应答解析工具（零第三方依赖）

用于验证 mdns_responder.py 是否按配置正确应答，也可作为通用的局域网 mDNS 调试工具。

示例（在项目根目录执行）
----
    # 查 A 记录
    python3 src/mdns_probe.py --name nas.local --type A
    # 查服务实例（ANY 会一次拿到 SRV / TXT / A）
    python3 src/mdns_probe.py --name "Office Web._http._tcp.local" --type ANY
    # 枚举局域网内所有服务类型
    python3 src/mdns_probe.py --name _services._dns-sd._udp.local --type PTR
    # 与服务端口保持一致，接收组播应答（而非 legacy 单播应答）
    python3 src/mdns_probe.py --name nas.local --type A --port 5353 --multicast
    # 自定义组播端口（配合测试用配置）
    python3 src/mdns_probe.py --name nas.local --type A --port 15353 --group 224.0.0.251
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys
import time
from pathlib import Path
from typing import Iterable

# 与 mdns_responder.py 同处 src/，显式加入 sys.path 便于从任意目录调用
SRC_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SRC_DIR))

from mdns_responder import (  # noqa: E402
    CLASS_IN, FLAGS_RESPONSE_AA, MCAST_GROUP_DEFAULT, MCAST_PORT_DEFAULT,
    QU_BIT, TYPE_A, TYPE_AAAA, TYPE_ANY, TYPE_NAMES, TYPE_PTR, TYPE_SRV, TYPE_TXT,
    build_query, decode_name,
)

TYPE_BY_NAME = {v: k for k, v in TYPE_NAMES.items()}


def _rdata_text(data: bytes, rtype: int, offset: int, rdlen: int) -> str:
    end = offset + rdlen
    try:
        if rtype == TYPE_A and rdlen == 4:
            return socket.inet_ntoa(data[offset:end])
        if rtype == TYPE_AAAA and rdlen == 16:
            return socket.inet_ntop(socket.AF_INET6, data[offset:end])
        if rtype == TYPE_PTR:
            name, _ = decode_name(data, offset)
            return name + "."
        if rtype == TYPE_SRV and rdlen >= 7:
            prio, weight, port = struct.unpack("!HHH", data[offset:offset + 6])
            target, _ = decode_name(data, offset + 6)
            return f"prio={prio} weight={weight} port={port} target={target}."
        if rtype == TYPE_TXT:
            parts, i = [], offset
            while i < end:
                n = data[i]
                parts.append(data[i + 1:i + 1 + n].decode("utf-8", "replace"))
                i += 1 + n
            return repr(parts)
    except (ValueError, struct.error, IndexError):
        pass
    return f"<{rdlen} bytes hex={data[offset:end].hex()}>"


def parse_response(data: bytes) -> tuple[int, list[str]]:
    """返回 (flags, 人类可读记录行列表)；非应答报文返回 (flags, [])。"""
    if len(data) < 12:
        return 0, []
    msg_id, flags, _qd, ancount, _ns, arcount = struct.unpack("!6H", data[:12])
    if not (flags & 0x8000):
        return flags, []
    offset = 12
    lines: list[str] = []
    for section, count in (("ANSWER", ancount), ("ADDITIONAL", arcount)):
        for _ in range(count):
            name, offset = decode_name(data, offset)
            if offset + 10 > len(data):
                return flags, lines
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
            rdata_offset = offset + 10
            offset = rdata_offset + rdlen
            if offset > len(data):
                return flags, lines
            flush = " flush" if rclass & 0x8000 else ""
            lines.append(
                f"  [{section:<10}] {name}. {TYPE_NAMES.get(rtype, rtype):<5} "
                f"ttl={ttl:<5}{flush:<6} {_rdata_text(data, rtype, rdata_offset, rdlen)}"
            )
    return flags, lines


def probe(names: Iterable[tuple[str, int]], group: str, port: int,
          timeout: float, unicast: bool, multicast_reply: bool) -> int:
    query = build_query(names, unicast=unicast)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
    if multicast_reply:
        sock.bind(("", port))
        try:
            mreq = struct.pack("=4s4s", socket.inet_aton(group), socket.inet_aton("0.0.0.0"))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except OSError as exc:
            print(f"警告: 加入组播组失败: {exc}", file=sys.stderr)
    else:
        sock.bind(("", 0))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack("B", 255))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
    sock.settimeout(0.3)

    desc = ", ".join(f"{name}/{TYPE_NAMES.get(qt, qt)}" for name, qt in names)
    print(f"查询 -> {group}:{port}  [{desc}]  (QU={unicast}, 组播应答={multicast_reply})")
    try:
        sock.sendto(query, (group, port))
    except OSError as exc:
        print(f"发送失败: {exc}", file=sys.stderr)
        sock.close()
        return 2

    deadline = time.monotonic() + timeout
    seen: set[str] = set()
    packets = 0
    while time.monotonic() < deadline:
        try:
            data, addr = sock.recvfrom(9000)
        except socket.timeout:
            continue
        except OSError as exc:
            print(f"接收失败: {exc}", file=sys.stderr)
            break
        flags, lines = parse_response(data)
        if not lines:
            continue
        packets += 1
        print(f"应答 <- {addr[0]}:{addr[1]}  flags=0x{flags:04x}  {len(data)} bytes")
        for line in lines:
            if line not in seen:
                seen.add(line)
                print(line)
    sock.close()
    print(f"---- 共收到 {packets} 个应答包 / {len(seen)} 条不同记录 ----")
    return 0 if seen else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="mDNS 查询探针 / 应答解析工具")
    parser.add_argument("--name", action="append", required=True,
                        help="查询域名，可多次指定")
    parser.add_argument("--type", default="ANY",
                        choices=list(TYPE_BY_NAME.keys()),
                        help="查询类型（默认 ANY）")
    parser.add_argument("--group", default=MCAST_GROUP_DEFAULT, help="组播地址")
    parser.add_argument("--port", type=int, default=MCAST_PORT_DEFAULT, help="mDNS 端口")
    parser.add_argument("--timeout", type=float, default=2.0, help="等待应答秒数")
    parser.add_argument("--unicast", action="store_true",
                        help="设置 QU 位，要求服务端单播应答")
    parser.add_argument("--multicast", action="store_true",
                        help="以 --port 为源端口并加入组播组，接收组播应答")
    args = parser.parse_args(argv)
    qtype = TYPE_BY_NAME[args.type.upper() if args.type.upper() in TYPE_BY_NAME else args.type]
    return probe([(n, qtype) for n in args.name], args.group, args.port,
                 args.timeout, args.unicast, args.multicast)


if __name__ == "__main__":
    raise SystemExit(main())
