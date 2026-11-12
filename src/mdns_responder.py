#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mdns_responder.py - 可配置的 mDNS / DNS-SD 组播应答服务（零第三方依赖）

功能
----
* 通过 TOML 配置「域名 -> IP」「服务实例 -> IP + 端口」映射；
* 监听 224.0.0.251:5353 组播查询，按 RFC 6762 / 6763 返回
  A / AAAA / PTR / SRV / TXT 记录及附加记录（Additional）；
* 支持服务枚举（_services._dns-sd._udp.local）、QU 位单播应答、
  Known-Answer 抑制、legacy 单播查询（源端口 != 5353）；
* 启动时主动宣告（announce）、周期性刷新，退出时发送 goodbye（TTL=0）；
* 配置文件 mtime 变化自动热重载，SIGHUP 亦可触发；
* SO_REUSEADDR / SO_REUSEPORT，可与 avahi-daemon、Chrome mDNS 等共存；
* 支持指定单网卡或 "all"（枚举全部非回环 IPv4 接口）；
* 内置 Web 管理控制台（admin.html + admin_server.py），默认 http://127.0.0.1:8765/ 。
* 文件日志按大小循环轮转、自动删除最老归档，磁盘占用有确定上界（见 [server].log_*）。

用法（在项目根目录执行）
----
    python3 src/mdns_responder.py -c config.toml             # 启动（含管理界面）
    python3 src/mdns_responder.py -c config.toml --check     # 仅校验并打印将发布的记录
    python3 src/mdns_responder.py -c config.toml -v          # DEBUG 日志
    python3 src/mdns_responder.py -c config.toml --no-admin  # 不开启管理界面
    ./start.sh                                               # 推荐：统一启动入口

依赖：Python >= 3.11（tomllib），Linux / macOS / Windows 均可运行（多网卡枚举为 Linux 优化）。
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import select
import shutil
import signal
import socket
import struct
import sys
import time
import tomllib
from dataclasses import dataclass, field
from typing import Iterable

LOG = logging.getLogger("mdns")

# ---------------------------------------------------------------------------
# DNS / mDNS 常量
# ---------------------------------------------------------------------------
MCAST_GROUP_DEFAULT = "224.0.0.251"
MCAST_PORT_DEFAULT = 5353

TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_PTR = 12
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_SRV = 33
TYPE_ANY = 255

CLASS_IN = 1
CACHE_FLUSH_BIT = 0x8000
QU_BIT = 0x8000
FLAGS_RESPONSE_AA = 0x8400          # QR=1, AA=1
FLAGS_QUERY = 0x0000

SERVICES_DNSSD_NAME = "_services._dns-sd._udp.local"
MAX_DATAGRAM = 9000

TYPE_NAMES = {
    TYPE_A: "A", TYPE_NS: "NS", TYPE_CNAME: "CNAME", TYPE_PTR: "PTR",
    TYPE_TXT: "TXT", TYPE_AAAA: "AAAA", TYPE_SRV: "SRV", TYPE_ANY: "ANY",
}


class DnsError(ValueError):
    """DNS 报文解析/编码错误。"""


class ConfigError(ValueError):
    """配置错误。"""


# ---------------------------------------------------------------------------
# 域名编解码（含 DNS 压缩指针、label 转义）
# ---------------------------------------------------------------------------
def normalize_name(name: str, require_local: bool = False) -> str:
    """规范化域名：去首尾空白、去尾部根点、校验长度；保留原始大小写。"""
    if not isinstance(name, str) or not name.strip():
        raise ConfigError("域名不能为空")
    out = name.strip().rstrip(".")
    if not out:
        raise ConfigError(f"非法域名: {name!r}")
    if require_local and not out.lower().endswith(".local"):
        raise ConfigError(f"mDNS 域名应以 .local 结尾: {name!r}")
    for label in out.split("."):
        if not label:
            raise ConfigError(f"域名含空 label: {name!r}")
        if len(label.encode("utf-8")) > 63:
            raise ConfigError(f"域名 label 超过 63 字节: {name!r}")
    if len(encode_name(out)) > 255:
        raise ConfigError(f"域名总长超过 255 字节: {name!r}")
    return out


def encode_name(name: str) -> bytes:
    """把 'a.example.local' 编码为 DNS label 序列。支持 '\\.' 表示字面点。"""
    out = bytearray()
    label = bytearray()
    i = 0
    while i < len(name):
        ch = name[i]
        if ch == "\\" and i + 1 < len(name):
            label += name[i + 1].encode("utf-8")
            i += 2
            continue
        if ch == ".":
            if not label:
                raise DnsError(f"空 label: {name!r}")
            out.append(len(label))
            out += label
            label.clear()
            i += 1
            continue
        label += ch.encode("utf-8")
        i += 1
    if label:
        out.append(len(label))
        out += label
    out.append(0)
    return bytes(out)


def _escape_label(text: str) -> str:
    return text.replace("\\", "\\\\").replace(".", "\\.")


def decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """解码 DNS name，跟随压缩指针，返回 (name, 报文内下一个读取位置)。"""
    labels: list[str] = []
    jumped = False
    end_offset = offset
    seen: set[int] = set()
    while True:
        if offset >= len(data):
            raise DnsError("name 越界")
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                end_offset = offset
            break
        kind = length & 0xC0
        if kind == 0xC0:
            if offset + 1 >= len(data):
                raise DnsError("压缩指针被截断")
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if ptr in seen or ptr >= len(data):
                raise DnsError("压缩指针循环或越界")
            seen.add(ptr)
            if not jumped:
                end_offset = offset + 2
            offset = ptr
            jumped = True
            continue
        if kind:
            raise DnsError(f"非法 label 长度标志: 0x{length:02x}")
        if offset + 1 + length > len(data):
            raise DnsError("label 越界")
        raw = data[offset + 1: offset + 1 + length]
        labels.append(_escape_label(raw.decode("utf-8", "replace")))
        offset += 1 + length
        if not jumped:
            end_offset = offset
    return ".".join(labels), end_offset


def canonical_rdata(data: bytes, rtype: int, offset: int, rdlen: int) -> bytes:
    """把 RDATA 中可能被压缩的域名还原为无压缩编码，便于与本地记录做 known-answer 比较。"""
    try:
        if rtype in (TYPE_PTR, TYPE_NS, TYPE_CNAME):
            name, _ = decode_name(data, offset)
            return encode_name(name)
        if rtype == TYPE_SRV:
            if rdlen < 7:
                return data[offset:offset + rdlen]
            name, _ = decode_name(data, offset + 6)
            return data[offset:offset + 6] + encode_name(name)
    except DnsError:
        pass
    return data[offset:offset + rdlen]


# ---------------------------------------------------------------------------
# 报文模型
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Question:
    name: str                 # 已 lower()
    qtype: int
    qclass: int               # 含 QU 位

    @property
    def wants_unicast(self) -> bool:
        return bool(self.qclass & QU_BIT)

    @property
    def qtype_name(self) -> str:
        return TYPE_NAMES.get(self.qtype, str(self.qtype))


@dataclass
class QueryMessage:
    msg_id: int
    questions: list[Question]
    known_answers: set[tuple[str, int, bytes]]
    source: tuple[str, int]


def parse_query(data: bytes, source: tuple[str, int]) -> QueryMessage | None:
    """解析 mDNS 查询；非查询报文（QR=1）或损坏报文返回 None。"""
    if len(data) < 12:
        return None
    msg_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!6H", data[:12])
    if flags & 0x8000:                       # 这是应答，忽略（避免环路/风暴）
        return None

    offset = 12
    questions: list[Question] = []
    for _ in range(qdcount):
        name, offset = decode_name(data, offset)
        if offset + 4 > len(data):
            raise DnsError("question 被截断")
        qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
        offset += 4
        questions.append(Question(name.lower(), qtype, qclass))

    known: set[tuple[str, int, bytes]] = set()
    for _ in range(ancount):
        rr_name, offset = decode_name(data, offset)
        if offset + 10 > len(data):
            raise DnsError("answer RR 被截断")
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
        rdata_offset = offset + 10
        offset = rdata_offset + rdlen
        if offset > len(data):
            raise DnsError("answer RDATA 越界")
        known.add((rr_name.lower(), rtype,
                   canonical_rdata(data, rtype, rdata_offset, rdlen)))

    # authority / additional 段仅跳过（responder 不消费）
    for _ in range(nscount + arcount):
        _, offset = decode_name(data, offset)
        if offset + 10 > len(data):
            raise DnsError("RR 被截断")
        _rt, _rc, _ttl, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10 + rdlen
        if offset > len(data):
            raise DnsError("RR RDATA 越界")

    return QueryMessage(msg_id, questions, known, source)


@dataclass
class Record:
    key: str
    name: str
    rtype: int
    rdata: bytes
    ttl: int
    flush: bool = False
    extras: tuple[str, ...] = ()
    display: str = ""

    def wire(self, ttl: int | None = None) -> bytes:
        cls = CLASS_IN | (CACHE_FLUSH_BIT if self.flush else 0)
        real_ttl = self.ttl if ttl is None else ttl
        return (encode_name(self.name)
                + struct.pack("!HHIH", self.rtype, cls, real_ttl, len(self.rdata))
                + self.rdata)

    def known_key(self) -> tuple[str, int, bytes]:
        return (self.name.lower(), self.rtype, self.rdata)


# ---------------------------------------------------------------------------
# TOML 配置
# ---------------------------------------------------------------------------
@dataclass
class ServerConfig:
    interface: str = "0.0.0.0"
    group: str = MCAST_GROUP_DEFAULT
    port: int = MCAST_PORT_DEFAULT
    ttl: int = 120
    announce_interval: int = 60
    announce_count: int = 3
    reverse_ptr: bool = True          # 发布 in-addr.arpa 反查 PTR（RFC 6762 §6.4）
    # Web 管理控制台（admin.html + admin_server.py），默认仅本机可访问
    management: bool = True
    management_host: str = "127.0.0.1"
    management_port: int = 8765
    management_token: str = ""
    # 有界文件日志（相对项目根；循环写 + 自动删除最老 + 可选按天过期）
    log_file: str = "logs/mdns.log"
    log_max_bytes: int = 10 * 1024 * 1024
    log_backup_count: int = 5
    log_retention_days: int = 7
    log_console: bool = True
    # 可观测增强（mdns_insights.py）：健康探测 / 查询审计 / 局域网浏览 / 冲突检测
    health: bool = True              # 周期 TCP 探测已登记目标
    health_interval: int = 30        # 探测周期（秒）；0 = 关闭探测
    health_timeout: float = 2.0      # 单次探测超时（秒）
    audit: bool = True               # 查询审计环形日志
    audit_limit: int = 500           # 审计保留条数
    browse: bool = True              # 摄取外来 DNS-SD 应答，构建局域网服务地图
    browse_scan_interval: int = 45   # 主动枚举查询周期（秒）；0 = 只被动摄取
    browse_limit: int = 400          # 服务地图保留实例数
    conflict_detect: bool = True     # 本地同名异值外来 RR 登记为冲突

    def validate(self) -> None:
        if self.log_max_bytes < 1024:
            raise ConfigError("server.log_max_bytes 必须 >= 1024")
        if self.log_backup_count < 0:
            raise ConfigError("server.log_backup_count 必须 >= 0")
        if self.log_retention_days < 0:
            raise ConfigError("server.log_retention_days 必须 >= 0")
        if self.port < 1 or self.port > 65535:
            raise ConfigError("server.port 必须在 1..65535")
        if self.ttl < 1:
            raise ConfigError("server.ttl 必须 > 0")
        if self.announce_interval < 0:
            raise ConfigError("server.announce_interval 必须 >= 0")
        if self.announce_count < 0:
            raise ConfigError("server.announce_count 必须 >= 0")
        if not 1 <= self.management_port <= 65535:
            raise ConfigError("server.management_port 必须在 1..65535")
        if self.management_port == self.port:
            raise ConfigError("server.management_port 不能与 mDNS 端口相同")
        if not self.management_host.strip():
            raise ConfigError("server.management_host 不能为空")
        if (not self.management_token
                and self.management_host not in ("127.0.0.1", "localhost", "::1")):
            LOG.warning("管理接口监听在非回环地址且未设置 token，建议配置 management_token")
        if self.health_interval < 0:
            raise ConfigError("server.health_interval 必须 >= 0（0 = 关闭探测）")
        if self.health_timeout < 0.1 or self.health_timeout > 30:
            raise ConfigError("server.health_timeout 必须在 0.1..30 秒")
        if self.audit_limit < 10:
            raise ConfigError("server.audit_limit 必须 >= 10")
        if self.browse_scan_interval < 0:
            raise ConfigError("server.browse_scan_interval 必须 >= 0")
        if self.browse_limit < 10:
            raise ConfigError("server.browse_limit 必须 >= 10")
        try:
            socket.inet_aton(self.group)
        except OSError as exc:
            raise ConfigError(f"server.group 不是合法 IPv4 组播地址: {self.group!r}") from exc
        if not self.group.startswith("224.") and not self.group.startswith("239."):
            LOG.warning("server.group=%s 并非典型组播地址，请确认", self.group)
        if self.interface not in ("0.0.0.0", "all"):
            try:
                socket.inet_aton(self.interface)
            except OSError as exc:
                raise ConfigError(f"server.interface 必须是 IP 或 'all'/'0.0.0.0': {self.interface!r}") from exc


@dataclass
class HostEntry:
    name: str
    ip: str


@dataclass
class ServiceEntry:
    type: str
    instance: str
    ip: str
    port: int
    host: str | None = None
    txt: dict[str, str] = field(default_factory=dict)


@dataclass
class Config:
    server: ServerConfig
    hosts: list[HostEntry]
    services: list[ServiceEntry]
    path: str
    mtime_ns: int


def _as_str(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"{field_name} 必须是字符串，实际为 {type(value).__name__}")
    return value


def _as_int(value: object, field_name: str) -> int:
    if isinstance(value, bool):
        raise ConfigError(f"{field_name} 必须是整数")
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{field_name} 必须是整数，实际为 {value!r}") from exc


def _as_bool(value: object, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{field_name} 必须是 true / false")
    return value


def _validate_ip(value: object, field_name: str) -> str:
    text = _as_str(value, field_name)
    try:
        return str(ipaddress.ip_address(text))
    except ValueError as exc:
        raise ConfigError(f"{field_name} 不是合法 IP: {text!r}") from exc


def load_config(path: str) -> Config:
    if not os.path.isfile(path):
        raise ConfigError(f"配置文件不存在: {path}")
    try:
        with open(path, "rb") as fh:
            raw = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"TOML 解析失败: {exc}") from exc

    server_raw = raw.get("server", {}) or {}
    if not isinstance(server_raw, dict):
        raise ConfigError("server 必须是表")
    server = ServerConfig(
        interface=_as_str(server_raw.get("interface", "0.0.0.0"), "server.interface"),
        group=_as_str(server_raw.get("group", MCAST_GROUP_DEFAULT), "server.group"),
        port=_as_int(server_raw.get("port", MCAST_PORT_DEFAULT), "server.port"),
        ttl=_as_int(server_raw.get("ttl", 120), "server.ttl"),
        announce_interval=_as_int(server_raw.get("announce_interval", 60),
                                  "server.announce_interval"),
        announce_count=_as_int(server_raw.get("announce_count", 3),
                               "server.announce_count"),
        reverse_ptr=_as_bool(server_raw.get("reverse_ptr", True), "server.reverse_ptr"),
        management=_as_bool(server_raw.get("management", True), "server.management"),
        management_host=_as_str(server_raw.get("management_host", "127.0.0.1"),
                                "server.management_host"),
        management_port=_as_int(server_raw.get("management_port", 8765),
                                "server.management_port"),
        management_token=_as_str(server_raw.get("management_token", ""),
                                 "server.management_token"),
        log_file=_as_str(server_raw.get("log_file", "logs/mdns.log"),
                         "server.log_file"),
        log_max_bytes=_as_int(server_raw.get("log_max_bytes", 10 * 1024 * 1024),
                              "server.log_max_bytes"),
        log_backup_count=_as_int(server_raw.get("log_backup_count", 5),
                                 "server.log_backup_count"),
        log_retention_days=_as_int(server_raw.get("log_retention_days", 7),
                                   "server.log_retention_days"),
        log_console=_as_bool(server_raw.get("log_console", True),
                              "server.log_console"),
        health=_as_bool(server_raw.get("health", True), "server.health"),
        health_interval=_as_int(server_raw.get("health_interval", 30),
                                "server.health_interval"),
        health_timeout=float(server_raw.get("health_timeout", 2.0)),
        audit=_as_bool(server_raw.get("audit", True), "server.audit"),
        audit_limit=_as_int(server_raw.get("audit_limit", 500),
                            "server.audit_limit"),
        browse=_as_bool(server_raw.get("browse", True), "server.browse"),
        browse_scan_interval=_as_int(server_raw.get("browse_scan_interval", 45),
                                     "server.browse_scan_interval"),
        browse_limit=_as_int(server_raw.get("browse_limit", 400),
                             "server.browse_limit"),
        conflict_detect=_as_bool(server_raw.get("conflict_detect", True),
                                 "server.conflict_detect"),
    )
    server.validate()

    hosts: list[HostEntry] = []
    for idx, item in enumerate(raw.get("hosts", []) or []):
        if not isinstance(item, dict):
            raise ConfigError(f"hosts[{idx}] 必须是表")
        name = normalize_name(_as_str(item.get("name"), f"hosts[{idx}].name"), require_local=False)
        ip = _validate_ip(item.get("ip"), f"hosts[{idx}].ip")
        hosts.append(HostEntry(name, ip))

    services: list[ServiceEntry] = []
    for idx, item in enumerate(raw.get("services", []) or []):
        if not isinstance(item, dict):
            raise ConfigError(f"services[{idx}] 必须是表")

        raw_type = _as_str(item.get("type"), f"services[{idx}].type").strip()
        if not raw_type:
            raise ConfigError(f"services[{idx}].type 不能为空，形如 _http._tcp.local")
        svc_type = normalize_name(raw_type)
        if not svc_type.lower().endswith(("_tcp.local", "_udp.local")):
            raise ConfigError(f"services[{idx}].type={raw_type!r} 不是标准 _xxx._tcp/_udp.local 形式")
        raw_host = item.get("host")
        host = (normalize_name(_as_str(raw_host, f"services[{idx}].host"))
                if raw_host is not None else None)

        instance = _as_str(item.get("instance"), f"services[{idx}].instance").strip()
        if not instance or "." in instance:
            raise ConfigError(
                f"services[{idx}].instance 不能为空且不能含 '.'（实例名是单个 DNS label）")
        ip = _validate_ip(item.get("ip"), f"services[{idx}].ip")
        if "port" not in item:
            raise ConfigError(f"services[{idx}].port 缺失，必须是 1..65535 的整数")
        port = _as_int(item["port"], f"services[{idx}].port")
        if not 1 <= port <= 65535:
            raise ConfigError(f"services[{idx}].port 必须在 1..65535")
        txt_raw = item.get("txt", {}) or {}
        if not isinstance(txt_raw, dict):
            raise ConfigError(f"services[{idx}].txt 必须是表")
        txt = {str(k): ("1" if v is True else "0" if v is False else str(v))
               for k, v in txt_raw.items()}
        services.append(ServiceEntry(svc_type, instance, ip, port, host, txt))

    if not hosts and not services:
        raise ConfigError("配置中没有任何 hosts 或 services，服务不会发布任何记录")

    return Config(server, hosts, services, os.path.abspath(path), os.stat(path).st_mtime_ns)


def _slug(instance: str) -> str:
    """由实例名派生单 label 兜底主机名；仅用于未显式配置 host 的场景。

    实例名本身不允许裸 "."（load_config 已校验），因此这里只把空格等
    非法字符折成连字符，生成 <slug>.local 形式的单 label 主机名。
    """
    cleaned = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in instance.lower())
    return cleaned.strip("-") or "mdns-host"


def _txt_bytes(text: str) -> bytes:
    """TXT 单字符串上限 255 字节，截断时保证不切断 UTF-8 多字节字符。"""
    raw = text.encode("utf-8")[:255]
    while raw:
        try:
            raw.decode("utf-8")
            return raw
        except UnicodeDecodeError:
            raw = raw[:-1]
    return b""


def _address_rdata(ip: str) -> tuple[int, bytes]:
    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        return TYPE_A, socket.inet_aton(ip)
    return TYPE_AAAA, socket.inet_pton(socket.AF_INET6, ip)


def build_records(cfg: Config) -> tuple[list[Record], dict[str, Record]]:
    """由配置生成全部 DNS 记录与附加记录索引。"""
    ttl = cfg.server.ttl
    records: list[Record] = []
    by_key: dict[str, Record] = {}

    def add(rec: Record) -> None:
        if rec.key in by_key:
            existing = by_key[rec.key]
            if existing.rdata != rec.rdata:
                raise ConfigError(
                    f"记录冲突: {rec.name} ({TYPE_NAMES.get(rec.rtype, rec.rtype)}) "
                    f"被映射到两个不同值（{existing.display} / {rec.display}）"
                )
            return                              # 等价记录，复用（可能补充 extras）
        by_key[rec.key] = rec
        records.append(rec)

    def make_address(host_name: str, ip: str) -> str:
        rtype, rdata = _address_rdata(ip)
        key = f"{rtype}:{host_name.lower()}"
        add(Record(
            key=key, name=host_name, rtype=rtype, rdata=rdata, ttl=ttl, flush=True,
            display=f"{TYPE_NAMES[rtype]} {host_name}. -> {ip}",
        ))
        # RFC 6762 §6.4：地址 -> 名称反查。IPv6 的 ip6.arpa 需 nibble 展开，此处仅 IPv4
        if rtype == TYPE_A and cfg.server.reverse_ptr:
            rev_key = f"rev:{ip}"
            if rev_key not in by_key:            # 同一 IP 只发布一条反查 PTR
                rev_name = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
                add(Record(
                    key=rev_key, name=rev_name, rtype=TYPE_PTR,
                    rdata=encode_name(host_name), ttl=ttl, flush=True,
                    display=f"PTR  {rev_name}. -> {host_name}. (reverse)",
                ))
        return key

    for entry in cfg.hosts:
        make_address(entry.name, entry.ip)

    all_service_keys: list[str] = []
    service_types: list[str] = []

    for svc in cfg.services:
        # host 可显式指定为 SRV target / A 记录名；未配置时由实例名派生 <slug>.local 兜底。
        host_name = svc.host or f"{_slug(svc.instance)}.local"
        a_key = make_address(host_name, svc.ip)
        rtype, _ = _address_rdata(svc.ip)

        instance_fqdn = f"{svc.instance}.{svc.type}"
        txt_rdata = b"".join(
            bytes([len(blob)]) + blob
            for blob in sorted(_txt_bytes(f"{k}={v}") for k, v in svc.txt.items())
        ) or b"\x00"

        srv_rdata = struct.pack("!HHH", 0, 0, svc.port) + encode_name(host_name)
        srv_key = f"srv:{instance_fqdn.lower()}"
        txt_key = f"txt:{instance_fqdn.lower()}"
        ptr_key = f"ptr:{svc.type.lower()}:{instance_fqdn.lower()}"

        add(Record(
            key=srv_key, name=instance_fqdn, rtype=TYPE_SRV, rdata=srv_rdata,
            ttl=ttl, flush=True, extras=(a_key, txt_key),
            display=f"SRV  {instance_fqdn}. -> 0 0 {svc.port} {host_name}.",
        ))
        add(Record(
            key=txt_key, name=instance_fqdn, rtype=TYPE_TXT, rdata=txt_rdata,
            ttl=ttl, flush=True, extras=(srv_key, a_key),
            display=(f"TXT  {instance_fqdn}. -> "
                     f"{[s.decode('utf-8', 'replace') for s in _txt_strings(txt_rdata)]}"),
        ))
        add(Record(
            key=ptr_key, name=svc.type, rtype=TYPE_PTR,
            rdata=encode_name(instance_fqdn), ttl=ttl, flush=False,
            extras=(srv_key, txt_key, a_key),
            display=f"PTR  {svc.type}. -> {instance_fqdn}.",
        ))

        all_service_keys.extend((ptr_key, srv_key, txt_key, a_key))
        if svc.type.lower() not in [t.lower() for t in service_types]:
            service_types.append(svc.type)

    # 服务类型枚举：_services._dns-sd._udp.local -> 每个服务类型一条 PTR
    for svc_type in service_types:
        add(Record(
            key=f"dnssd:{svc_type.lower()}", name=SERVICES_DNSSD_NAME,
            rtype=TYPE_PTR, rdata=encode_name(svc_type), ttl=ttl, flush=False,
            extras=tuple(dict.fromkeys(all_service_keys)),
            display=f"PTR  {SERVICES_DNSSD_NAME}. -> {svc_type}.",
        ))

    # 补充 extras（同一 A 记录被多条服务引用时，首次 add 的 extras 已固定；此处统一收敛）
    return records, by_key


def _txt_strings(rdata: bytes) -> list[bytes]:
    out: list[bytes] = []
    i = 0
    while i < len(rdata):
        n = rdata[i]
        out.append(rdata[i + 1:i + 1 + n])
        i += 1 + n
    return out


def _record_value(rec: Record) -> str:
    """把 RDATA 转成人类可读文本（管理 API 用）。"""
    try:
        if rec.rtype == TYPE_A and len(rec.rdata) == 4:
            return socket.inet_ntoa(rec.rdata)
        if rec.rtype == TYPE_AAAA and len(rec.rdata) == 16:
            return socket.inet_ntop(socket.AF_INET6, rec.rdata)
        if rec.rtype == TYPE_PTR:
            return decode_name(rec.rdata, 0)[0] + "."
        if rec.rtype == TYPE_SRV and len(rec.rdata) >= 7:
            _prio, _weight, port = struct.unpack("!HHH", rec.rdata[:6])
            target, _ = decode_name(rec.rdata, 6)
            return f"port={port}  target={target}."
        if rec.rtype == TYPE_TXT:
            return "  ".join(s.decode("utf-8", "replace") for s in _txt_strings(rec.rdata))
    except (DnsError, struct.error, ValueError, OSError):
        pass
    return rec.rdata.hex()


# ---------------------------------------------------------------------------
# 应答构造
# ---------------------------------------------------------------------------
def build_response(
    records: list[Record],
    by_key: dict[str, Record],
    questions: list[Question],
    known: set[tuple[str, int, bytes]],
    msg_id: int,
) -> bytes | None:
    answers: list[Record] = []
    answer_keys: set[str] = set()
    extras: list[Record] = []
    extra_keys: set[str] = set()

    for q in questions:
        for rec in records:
            if q.qtype != TYPE_ANY and rec.rtype != q.qtype:
                continue
            if rec.name.lower() != q.name:
                continue
            if rec.key in answer_keys:
                continue
            answers.append(rec)
            answer_keys.add(rec.key)
            for extra_key in rec.extras:
                extra = by_key.get(extra_key)
                if extra is not None and extra.key not in extra_keys:
                    extras.append(extra)
                    extra_keys.add(extra.key)

    extras = [r for r in extras if r.key not in answer_keys]
    answers = [r for r in answers if r.known_key() not in known]
    extras = [r for r in extras if r.known_key() not in known]

    if not answers and extras:
        answers, extras = extras, []           # 避免 ANCOUNT=0 / ARCOUNT>0 的空应答
    if not answers and not extras:
        return None

    header = struct.pack("!6H", msg_id, FLAGS_RESPONSE_AA,
                         0, len(answers), 0, len(extras))
    body = b"".join(r.wire() for r in answers)
    additional = b"".join(r.wire() for r in extras)
    return header + body + additional


def build_announce(records: list[Record], ttl: int | None = None) -> bytes:
    body = b"".join(r.wire(ttl=ttl) for r in records)
    return struct.pack("!6H", 0, FLAGS_RESPONSE_AA, 0, len(records), 0, 0) + body


def build_query(names: Iterable[tuple[str, int]], unicast: bool = False) -> bytes:
    """构造查询报文（供探针 / 自检使用）。names 为 (name, qtype) 列表。"""
    items = list(names)
    qclass = CLASS_IN | (QU_BIT if unicast else 0)
    body = b"".join(encode_name(name) + struct.pack("!HH", qtype, qclass)
                    for name, qtype in items)
    return struct.pack("!6H", 0, FLAGS_QUERY, len(items), 0, 0, 0) + body


def parse_response_rrs(data: bytes, addr: tuple[str, int]) -> list[dict] | None:
    """解析任意 mDNS/DNS 应答报文，返回 [{section,name,type,rtype,ttl,flush,
    value,from}]；非应答或损坏返回 None。

    供 insights 层做「外来应答摄取」：既喂冲突检测，也喂局域网服务地图。
    """
    if len(data) < 12:
        return None
    _id, flags, _qd, ancount, _ns, arcount = struct.unpack("!6H", data[:12])
    if not flags & 0x8000:                       # 不是应答
        return None
    offset, out = 12, []
    for section, count in (("ANSWER", ancount), ("ADDITIONAL", arcount)):
        for _ in range(count):
            try:
                name, offset = decode_name(data, offset)
                rtype, rclass, ttl, rdlen = struct.unpack(
                    "!HHIH", data[offset:offset + 10])
                rdata_offset = offset + 10
                offset = rdata_offset + rdlen
                if offset > len(data):
                    break
                rec = Record("tmp", name, rtype, data[rdata_offset:offset],
                              ttl, bool(rclass & CACHE_FLUSH_BIT))
                out.append({
                    "section": section, "name": name,
                    "type": TYPE_NAMES.get(rtype, str(rtype)),
                    "rtype": rtype, "ttl": ttl,
                    "flush": bool(rclass & CACHE_FLUSH_BIT),
                    "value": _record_value(rec),
                    "from": f"{addr[0]}:{addr[1]}",
                })
            except (DnsError, struct.error, IndexError):
                break
    return out or None


# ---------------------------------------------------------------------------
# 组播 socket
# ---------------------------------------------------------------------------
def _local_ipv4_interfaces() -> list[str]:
    """枚举本机非回环 IPv4 地址（Linux 优先，其他平台尽力而为）。"""
    found: list[str] = []
    try:
        import fcntl
        SIOCGIFADDR = 0x8915
        for _, ifname in socket.if_nameindex():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                    raw = fcntl.ioctl(probe.fileno(), SIOCGIFADDR,
                                      struct.pack("256s", ifname.encode()[:15]))
                ip = socket.inet_ntoa(raw[20:24])
                if not ip.startswith("127.") and ip not in found:
                    found.append(ip)
            except OSError:
                continue
    except (ImportError, OSError):
        pass
    if not found:
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
                ip = info[4][0]
                if not ip.startswith("127.") and ip not in found:
                    found.append(ip)
        except OSError:
            pass
    return found or ["0.0.0.0"]


class MdnsSocket:
    def __init__(self, cfg: ServerConfig):
        self.cfg = cfg
        self.group = cfg.group
        self.port = cfg.port
        if cfg.interface == "all":
            self.interfaces = _local_ipv4_interfaces()
        elif cfg.interface == "0.0.0.0":
            self.interfaces = ["0.0.0.0"]
        else:
            self.interfaces = [cfg.interface]
        LOG.info("组播接口: %s", ", ".join(self.interfaces))

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError as exc:
                LOG.warning("SO_REUSEPORT 不可用，可能与已有 mDNS 服务冲突: %s", exc)
        self.sock.bind(("", cfg.port))
        self.sock.setblocking(False)

        group_bytes = socket.inet_aton(cfg.group)
        joined = 0
        for ifip in self.interfaces:
            try:
                mreq = struct.pack("=4s4s", group_bytes, socket.inet_aton(ifip))
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                joined += 1
            except OSError as exc:
                LOG.warning("加入组播组失败 (interface=%s): %s", ifip, exc)
        if joined == 0:
            raise OSError("未能加入任何组播组，请检查 server.interface 配置")
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack("B", 255))
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        LOG.info("监听 %s:%d（UDP, 组播）", cfg.group, cfg.port)

    def fileno(self) -> int:
        return self.sock.fileno()

    def recv(self) -> tuple[bytes, tuple[str, int]] | None:
        try:
            return self.sock.recvfrom(MAX_DATAGRAM)
        except (BlockingIOError, InterruptedError):
            return None
        except OSError as exc:
            LOG.warning("接收数据报错: %s", exc)
            return None

    def send(self, packet: bytes, unicast_addr: tuple[str, int] | None = None) -> None:
        if unicast_addr is not None:
            try:
                self.sock.sendto(packet, unicast_addr)
            except OSError as exc:
                LOG.warning("单播应答发送失败 -> %s: %s", unicast_addr, exc)
            return
        for ifip in self.interfaces:
            try:
                if ifip != "0.0.0.0":
                    self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                                         socket.inet_aton(ifip))
                self.sock.sendto(packet, (self.group, self.port))
            except OSError as exc:
                LOG.warning("组播发送失败 (interface=%s): %s", ifip, exc)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Responder 主体
# ---------------------------------------------------------------------------
class Responder:
    def __init__(self, config_path: str, verbose: bool = False,
                 disable_admin: bool = False):
        self.config_path = os.path.abspath(config_path)
        self.verbose = verbose
        self.cfg = load_config(self.config_path)
        # 尽早装配有界文件日志，确保启动日志（记录清单、告警）也受轮转保护
        from admin_server import install_logging
        install_logging(self.cfg.server)
        if disable_admin:
            self.cfg.server.management = False
        self.records, self.by_key = build_records(self.cfg)
        self.net = MdnsSocket(self.cfg.server)
        self.running = True
        self.reload_requested = False
        self.pending_bursts = self.cfg.server.announce_count
        self.next_burst_at = 0.0
        self.next_periodic_at: float | None = None
        self.started_at = time.time()
        self.stats = {"queries": 0, "responses": 0, "bytes": 0, "announces": 0}
        self.admin = None
        # 可观测增强：查询审计 / 局域网浏览 / 冲突检测（mdns_insights）
        from mdns_insights import BrowseState, ConflictState, HealthMonitor, QueryAudit
        srv = self.cfg.server
        self.query_audit = QueryAudit(srv.audit_limit) if srv.audit else None
        self.browse = BrowseState(srv.browse_limit) if srv.browse else None
        self.conflicts = ConflictState() if srv.conflict_detect else None
        self._local_values: dict[tuple[str, str], set[str]] = {}
        self._ingest_external = True
        self._next_browse_scan = 0.0
        self._refresh_local_values()
        self._refresh_browse_scan()
        # 自身源地址：外来应答回环识别（避免把自己的宣告当成「别人」的记录）
        self._own_ips = set(self.net.interfaces)
        if "0.0.0.0" in self._own_ips:
            self._own_ips = set(_local_ipv4_interfaces())
        self.health = (HealthMonitor(
            self,
            target_getter=self.health_targets,
            get_interval=lambda: self.cfg.server.health_interval,
            get_timeout=lambda: self.cfg.server.health_timeout,
            start=False)
            if srv.health else None)
        if self.health is not None and srv.health_interval > 0:
            self.health.start()
        self._reset_periodic()

    def _refresh_local_values(self) -> None:
        """构建 (类型名, 小写域名) -> 本地取值集合，用于外来应答的冲突判定。"""
        values: dict[tuple[str, str], set[str]] = {}
        for rec in self.records:
            if rec.rtype == TYPE_PTR and not rec.flush:
                continue                       # 服务类型枚举 PTR：多值正常，不算冲突
            key = (TYPE_NAMES.get(rec.rtype, str(rec.rtype)), rec.name.lower())
            values.setdefault(key, set()).add(_record_value(rec))
        self._local_values = values

    def _refresh_browse_scan(self) -> None:
        interval = self.cfg.server.browse_scan_interval
        self._next_browse_scan = (time.monotonic() + interval
                                  if (self.browse is not None and interval > 0) else 0.0)

    def health_targets(self) -> list[tuple]:
        """健康探测目标：(key, kind, label, ip, port)。host 默认探测 80。"""
        targets: list[tuple] = []
        for h in self.cfg.hosts:
            targets.append((f"host:{h.name.lower()}", "host", h.name, h.ip, 80))
        for i, s in enumerate(self.cfg.services):
            key = f"svc:{i}:{(s.host or (_slug(s.instance) + '.local')).lower()}"
            targets.append((key, "service", s.instance or f"#{i}", s.ip, s.port))
        return targets

    def _reset_periodic(self) -> None:
        interval = self.cfg.server.announce_interval
        self.next_periodic_at = time.monotonic() + interval if interval > 0 else None

    def _log_records(self) -> None:
        LOG.info("配置已加载: %s", self.config_path)
        LOG.info("将发布 %d 条记录 (ttl=%ds):", len(self.records), self.cfg.server.ttl)
        for rec in self.records:
            LOG.info("  %s", rec.display)

    # ------------------------------------------------------------------
    # 管理 API 数据接口（由 admin_server.py 在同一进程内调用）
    # ------------------------------------------------------------------
    def status(self) -> dict:
        from admin_server import log_disk_cap
        srv = self.cfg.server
        log_path = srv.log_file
        if log_path and not os.path.isabs(log_path):
            log_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))), log_path)
        return {
            "running": self.running,
            "pid": os.getpid(),
            "uptime": max(0, int(time.time() - self.started_at)),
            "group": srv.group,
            "port": srv.port,
            "interface": srv.interface,
            "interfaces": list(self.net.interfaces),
            "ttl": srv.ttl,
            "announce_interval": srv.announce_interval,
            "records": len(self.records),
            "hosts": len(self.cfg.hosts),
            "services": len(self.cfg.services),
            "reverse_ptr": srv.reverse_ptr,
            "management": {
                "enabled": srv.management,
                "url": f"http://{srv.management_host}:{srv.management_port}/",
                "auth_required": bool(srv.management_token),
            },
            "logging": {
                "enabled": bool(srv.log_file.strip()),
                "file": os.path.abspath(log_path) if log_path else "",
                "max_bytes": srv.log_max_bytes,
                "backup_count": srv.log_backup_count,
                "retention_days": srv.log_retention_days,
                "console": srv.log_console,
                "max_disk_bytes": log_disk_cap(srv),
            },
            "insights": {
                "health": {
                    "enabled": srv.health,
                    "interval": srv.health_interval,
                    "timeout_s": srv.health_timeout,
                    "targets": len(self.health_targets()),
                    "up": sum(1 for t in self.health.items()
                               if t["status"] == "up") if self.health else 0,
                },
                "audit": {
                    "enabled": srv.audit,
                    "buffer": srv.audit_limit,
                    "total": self.query_audit.total if self.query_audit else 0,
                },
                "browse": {
                    "enabled": srv.browse,
                    "scan_interval": srv.browse_scan_interval,
                    "instances": len(self.browse.json()["items"])
                    if self.browse else 0,
                },
                "conflicts": {
                    "enabled": srv.conflict_detect,
                    "count": self.conflicts.json()["count"]
                    if self.conflicts else 0,
                },
            },
            "stats": dict(self.stats),
            "config_path": self.config_path,
        }

    # ------------------------------------------------------------------
    # 可观测增强 API（admin_server 路由到这些方法）
    # ------------------------------------------------------------------
    def insights_health(self) -> dict:
        srv = self.cfg.server
        items = self.health.items() if self.health else []
        if not srv.health:
            return {"enabled": False, "interval": srv.health_interval,
                    "timeout_s": srv.health_timeout, "items": []}
        return {"enabled": True, "interval": srv.health_interval,
                "timeout_s": srv.health_timeout, "items": items}

    def insights_queries(self, limit: int = 100) -> dict:
        if self.query_audit is None:
            return {"enabled": False, "items": [], "total": 0, "buffer": 0}
        data = self.query_audit.json(limit)
        data["enabled"] = True
        return data

    def insights_browse(self) -> dict:
        srv = self.cfg.server
        if self.browse is None:
            return {"enabled": False, "scan_interval": srv.browse_scan_interval,
                    "items": [], "count": 0, "last_scan": 0.0}
        data = self.browse.json()
        data["enabled"] = True
        data["scan_interval"] = srv.browse_scan_interval
        return data

    def insights_conflicts(self) -> dict:
        srv = self.cfg.server
        if self.conflicts is None:
            return {"enabled": False, "count": 0, "items": []}
        data = self.conflicts.json()
        data["enabled"] = True
        return data

    def records_json(self) -> list[dict]:
        return [{
            "type": TYPE_NAMES.get(rec.rtype, str(rec.rtype)),
            "type_id": rec.rtype,
            "name": rec.name,
            "ttl": rec.ttl,
            "flush": rec.flush,
            "value": _record_value(rec),
            "extras": len(rec.extras),
        } for rec in self.records]

    def config_json(self) -> dict:
        with open(self.config_path, "r", encoding="utf-8") as fh:
            raw = fh.read()
        srv = self.cfg.server
        return {
            "raw": raw,
            "config": {
                "server": {
                    "interface": srv.interface, "group": srv.group, "port": srv.port,
                    "ttl": srv.ttl, "announce_interval": srv.announce_interval,
                    "announce_count": srv.announce_count, "reverse_ptr": srv.reverse_ptr,
                    "management": srv.management, "management_host": srv.management_host,
                    "management_port": srv.management_port,
                    "management_token": srv.management_token,
                    "log_file": srv.log_file, "log_max_bytes": srv.log_max_bytes,
                    "log_backup_count": srv.log_backup_count,
                    "log_retention_days": srv.log_retention_days,
                    "log_console": srv.log_console,
                    "health": srv.health, "health_interval": srv.health_interval,
                    "health_timeout": srv.health_timeout,
                    "audit": srv.audit, "audit_limit": srv.audit_limit,
                    "browse": srv.browse, "browse_scan_interval": srv.browse_scan_interval,
                    "browse_limit": srv.browse_limit,
                    "conflict_detect": srv.conflict_detect,
                },
                "hosts": [{"name": h.name, "ip": h.ip} for h in self.cfg.hosts],
                "services": [{
                    "type": s.type, "instance": s.instance, "host": s.host or "",
                    "ip": s.ip, "port": s.port, "txt": dict(s.txt),
                } for s in self.cfg.services],
            },
        }

    def save_config(self, payload: dict) -> dict:
        """校验 -> 备份 -> 原子替换 -> 标记热重载。任何校验失败都不改动原文件。"""
        from admin_server import dump_toml, merge_server

        if isinstance(payload.get("raw"), str):
            text = payload["raw"]
        elif isinstance(payload.get("config"), dict):
            with open(self.config_path, "r", encoding="utf-8") as fh:
                current_raw = fh.read()
            cfg = dict(payload["config"])
            cfg["server"] = merge_server(current_raw, cfg.get("server", {}))
            text = dump_toml(cfg)
        else:
            raise ConfigError("请求体需包含 raw 或 config")
        if not text.endswith("\n"):
            text += "\n"

        tmp_path = self.config_path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as fh:
            fh.write(text)
        try:
            new_cfg = load_config(tmp_path)
            new_records, _ = build_records(new_cfg)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
        try:
            shutil.copy2(self.config_path, self.config_path + ".bak")
        except OSError as exc:
            LOG.warning("配置备份失败（仍继续保存）: %s", exc)
        os.replace(tmp_path, self.config_path)
        self.reload_requested = True
        LOG.info("管理界面已保存配置，等待热重载（%d 条记录）", len(new_records))
        return {
            "ok": True,
            "message": "配置已保存并触发热重载",
            "records": len(new_records),
            "backup": self.config_path + ".bak",
            "restart_required": (
                new_cfg.server.interface != self.cfg.server.interface
                or new_cfg.server.group != self.cfg.server.group
                or new_cfg.server.port != self.cfg.server.port
            ),
        }

    def interfaces(self) -> list[str]:
        return list(dict.fromkeys(["0.0.0.0", "all"] + _local_ipv4_interfaces()))

    def request_reload(self) -> None:
        self.reload_requested = True

    QTYPE_BY_NAME = {
        "A": TYPE_A, "AAAA": TYPE_AAAA, "PTR": TYPE_PTR, "SRV": TYPE_SRV,
        "TXT": TYPE_TXT, "ANY": TYPE_ANY,
    }

    @staticmethod
    def _parse_probe_response(data: bytes, addr: tuple[str, int]) -> list[dict] | None:
        if len(data) < 12:
            return None
        _id, flags, _qd, ancount, _ns, arcount = struct.unpack("!6H", data[:12])
        if not flags & 0x8000:
            return None
        offset, out = 12, []
        for section, count in (("ANSWER", ancount), ("ADDITIONAL", arcount)):
            for _ in range(count):
                try:
                    name, offset = decode_name(data, offset)
                    rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
                    rdata_offset = offset + 10
                    offset = rdata_offset + rdlen
                    if offset > len(data):
                        break
                    rec = Record("tmp", name, rtype, data[rdata_offset:offset],
                                 ttl, bool(rclass & CACHE_FLUSH_BIT))
                    out.append({
                        "section": section, "name": name,
                        "type": TYPE_NAMES.get(rtype, str(rtype)),
                        "ttl": ttl, "flush": bool(rclass & CACHE_FLUSH_BIT),
                        "value": _record_value(rec),
                        "from": f"{addr[0]}:{addr[1]}",
                    })
                except (DnsError, struct.error, IndexError):
                    break
        return out or None

    def probe_once(self, name: str, qtype_name: str = "ANY") -> dict:
        """从管理界面发起一次真实 mDNS 查询并收集应答。"""
        qtype = self.QTYPE_BY_NAME.get(str(qtype_name).upper(), TYPE_ANY)
        name = normalize_name(name)
        query = build_query([(name, qtype)])
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack("B", 255))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        sock.settimeout(0.2)
        started = time.monotonic()
        packets, items = 0, []
        try:
            sock.sendto(query, (self.cfg.server.group, self.cfg.server.port))
            deadline = started + 1.5
            while time.monotonic() < deadline:
                try:
                    data, addr = sock.recvfrom(MAX_DATAGRAM)
                except socket.timeout:
                    continue
                except OSError:
                    break
                parsed = self._parse_probe_response(data, addr)
                if parsed:
                    packets += 1
                    items.extend(parsed)
        finally:
            sock.close()
        return {
            "name": name, "type": TYPE_NAMES.get(qtype, str(qtype)),
            "group": self.cfg.server.group, "port": self.cfg.server.port,
            "packets": packets, "records": items,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
        }

    def reload(self, force: bool = False) -> None:
        try:
            current_ns = os.stat(self.config_path).st_mtime_ns
        except OSError as exc:
            LOG.error("无法读取配置文件: %s", exc)
            return
        if not force and current_ns == self.cfg.mtime_ns:
            return
        try:
            new_cfg = load_config(self.config_path)
            new_records, new_by_key = build_records(new_cfg)
        except (ConfigError, OSError) as exc:
            LOG.error("配置重载失败，继续使用旧配置: %s", exc)
            self.cfg.mtime_ns = current_ns       # 避免重复报错刷屏
            return
        server_changed = (
            new_cfg.server.interface != self.cfg.server.interface
            or new_cfg.server.group != self.cfg.server.group
            or new_cfg.server.port != self.cfg.server.port
        )
        self.cfg, self.records, self.by_key = new_cfg, new_records, new_by_key
        self._log_records()
        self._refresh_local_values()
        self._refresh_browse_scan()
        self._sync_health_thread()
        if server_changed:
            LOG.warning("server.interface/group/port 变更需重启进程才能生效")
        self._reset_periodic()
        self.pending_bursts = max(1, self.cfg.server.announce_count)
        self.next_burst_at = 0.0
        self.reload_requested = False

    def _sync_health_thread(self) -> None:
        """按配置开关同步健康探测线程（启动/停止），避免重复线程。"""
        srv = self.cfg.server
        if srv.health and self.health is not None and not self.health.is_alive():
            self.health.start()
        elif not srv.health and self.health is not None and self.health.is_alive():
            self.health.stop()

    def _announce(self, goodbye: bool = False) -> None:
        packet = build_announce(self.records, ttl=0 if goodbye else None)
        if goodbye:
            LOG.info("发送 goodbye（TTL=0）")
        else:
            LOG.debug("发送主动宣告，%d 条记录 / %d 字节", len(self.records), len(packet))
        self.net.send(packet)
        if not goodbye:
            self.stats["announces"] += 1

    # ------------------------------------------------------------------
    # 可观测增强：审计 / 冲突 / 浏览（mdns_insights）
    # ------------------------------------------------------------------
    def _own_source(self, addr: tuple[str, int]) -> bool:
        """应答来自本机（自身宣告回环 / 本机其他 mDNS 实例）？"""
        return addr[0] in self._own_ips or addr[0] in ("127.0.0.1", "::1")

    def _ingest_incoming(self, data: bytes, addr: tuple[str, int]) -> None:
        """外来 mDNS 应答的单一摄取入口：冲突登记 + 服务地图。

        在 select 主循环中处理 QR=1 报文时调用（原直接丢弃）。
        """
        if not (self.browse is not None or self.conflicts is not None):
            return
        rr_list = parse_response_rrs(data, addr)
        if not rr_list:
            return
        ours = self._own_source(addr)
        for rr in rr_list:
            if self.conflicts is not None:
                local = self._local_values.get((rr["type"], rr["name"].lower()))
                if local is not None and rr["value"] not in local:
                    self.conflicts.ingest(rr["type"], rr["name"], rr["value"],
                                          rr["from"])
            if self.browse is not None:
                self.browse.ingest(rr["type"], rr["name"], rr["value"],
                                   rr["ttl"], rr["from"], ours)

    def _scan_browse(self) -> None:
        """周期主动枚举：发 _services + 本地服务类型 + 常见类型 PTR。

        各 mDNS 实现会据此应答自己发布的服务；应答在 select 循环中
        经 _ingest_incoming() 摄取进服务地图。
        """
        if self.browse is None or self.cfg.server.browse_scan_interval <= 0:
            return
        self.browse.last_scan = time.time()
        from mdns_insights import WELL_KNOWN_TYPES
        names = [SERVICES_DNSSD_NAME]
        names.extend(s.type for s in self.cfg.services)
        names.extend(WELL_KNOWN_TYPES)
        try:
            self.net.send(build_query(
                [(n, TYPE_PTR) for n in dict.fromkeys(names)]))
        except OSError as exc:
            LOG.warning("浏览枚举查询发送失败: %s", exc)

    def _handle(self, data: bytes, addr: tuple[str, int]) -> None:
        if len(data) < 12:
            return
        # QR 位（flags 高字节 & 0x80）先分流：外来应答走「摄取」，查询走「应答」
        if data[2] & 0x80:
            self._ingest_incoming(data, addr)
            return
        try:
            msg = parse_query(data, addr)
        except DnsError as exc:
            LOG.warning("丢弃损坏的查询报文 <- %s: %s", addr, exc)
            return
        if msg is None or not msg.questions:
            return
        self.stats["queries"] += 1
        LOG.debug("查询 <- %s:%d id=0x%04x %s", addr[0], addr[1], msg.msg_id,
                  ", ".join(f"{q.name}/{q.qtype_name}"
                            f"{'(QU)' if q.wants_unicast else ''}"
                            for q in msg.questions))

        legacy_unicast = addr[1] != self.cfg.server.port
        uni_q = [q for q in msg.questions if q.wants_unicast]
        multi_q = [q for q in msg.questions if not q.wants_unicast]
        if legacy_unicast:
            LOG.debug("检测到 legacy 单播查询（源端口 %d），全部单播应答", addr[1])
            uni_q, multi_q = msg.questions, []

        hit = False
        if multi_q:
            packet = build_response(self.records, self.by_key, multi_q,
                                    msg.known_answers, 0)
            if packet:
                self.net.send(packet)
                self.stats["responses"] += 1
                self.stats["bytes"] += len(packet)
                hit = True
                LOG.info("组播应答 -> %s:%d (%d 字节)",
                         self.cfg.server.group, self.cfg.server.port, len(packet))
        if uni_q:
            packet = build_response(self.records, self.by_key, uni_q,
                                    msg.known_answers, msg.msg_id)
            if packet:
                self.net.send(packet, unicast_addr=addr)
                self.stats["responses"] += 1
                self.stats["bytes"] += len(packet)
                hit = True
                LOG.info("单播应答 -> %s:%d (%d 字节)", addr[0], addr[1], len(packet))

        if self.query_audit is not None:
            self.query_audit.record(addr[0], addr[1], msg.questions, hit,
                                   unicast=bool(uni_q))

    def run(self) -> int:
        self._log_records()
        signal.signal(signal.SIGINT, self._on_signal)
        signal.signal(signal.SIGTERM, self._on_signal)
        if hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, self._on_hup)

        from admin_server import install_logging, start_admin, stop_admin
        log_handler = install_logging(self.cfg.server)
        self.admin = start_admin(self, log_handler=log_handler)
        self._sync_health_thread()
        LOG.info("mDNS responder 已启动 (pid=%d)", os.getpid())
        last_housekeeping = time.monotonic()
        while self.running:
            now = time.monotonic()
            if self.reload_requested:
                self.reload(force=True)

            if self.pending_bursts > 0 and now >= self.next_burst_at:
                self._announce()
                self.pending_bursts -= 1
                self.next_burst_at = now + 1.0
            if self.next_periodic_at is not None and now >= self.next_periodic_at:
                self._announce()
                self._reset_periodic()

            # 局域网浏览：周期发枚举查询 + 到期清理过期实例
            if (self.browse is not None and now >= self._next_browse_scan):
                self._scan_browse()
                self._refresh_browse_scan()
            if now - last_housekeeping >= 60:
                last_housekeeping = now
                if self.browse is not None:
                    self.browse.purge()
                if self.conflicts is not None:
                    self.conflicts.purge()

            deadlines = [0.5]
            if self.pending_bursts > 0:
                deadlines.append(max(0.0, self.next_burst_at - time.monotonic()))
            if self.next_periodic_at is not None:
                deadlines.append(max(0.0, self.next_periodic_at - time.monotonic()))
            timeout = min(deadlines)

            ready, _, _ = select.select([self.net], [], [], timeout)
            if ready:
                while True:
                    item = self.net.recv()
                    if item is None:
                        break
                    self._handle(*item)
            else:
                self.reload()                    # 空闲时检查配置文件 mtime

        try:
            self._announce(goodbye=True)
        finally:
            stop_admin(self.admin)
            self.net.close()
        if self.health is not None:
            self.health.stop()
        LOG.info("已停止")
        return 0

    def _on_signal(self, _signum, _frame) -> None:
        self.running = False

    def _on_hup(self, _signum, _frame) -> None:
        self.reload_requested = True


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    # 代码位于 src/，配置位于项目根目录
    _ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    default_config = os.path.join(_ROOT, "config.toml")
    parser = argparse.ArgumentParser(
        description="可配置的 mDNS / DNS-SD 组播应答服务（零第三方依赖）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-c", "--config", default=default_config,
                        help=f"TOML 配置文件路径（默认 {default_config}）")
    parser.add_argument("-v", "--verbose", action="store_true", help="输出 DEBUG 日志")
    parser.add_argument("--check", action="store_true",
                        help="仅校验配置并打印将发布的记录，不启动网络")
    parser.add_argument("--no-admin", action="store_true",
                        help="本次启动不开启 Web 管理界面")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )

    try:
        if args.check:
            cfg = load_config(args.config)
            records, _ = build_records(cfg)
            print(f"配置校验通过: {os.path.abspath(args.config)}")
            print(f"server: interface={cfg.server.interface} group={cfg.server.group} "
                  f"port={cfg.server.port} ttl={cfg.server.ttl} "
                  f"announce_interval={cfg.server.announce_interval} "
                  f"announce_count={cfg.server.announce_count} "
                  f"reverse_ptr={cfg.server.reverse_ptr}")
            print(f"管理界面: enabled={cfg.server.management} "
                  f"url=http://{cfg.server.management_host}:{cfg.server.management_port}/ "
                  f"auth={'token' if cfg.server.management_token else 'none'}")
            print(f"文件日志: {cfg.server.log_file or '(禁用)'} "
                  f"单文件={cfg.server.log_max_bytes}B 保留={cfg.server.log_backup_count}份 "
                  f"过期={cfg.server.log_retention_days}天 "
                  f"磁盘上界={cfg.server.log_max_bytes * (cfg.server.log_backup_count + 1)}B")
            print(f"记录共 {len(records)} 条:")
            for rec in records:
                print(f"  {rec.display}")
            return 0
        return Responder(args.config, args.verbose, args.no_admin).run()
    except (ConfigError, DnsError, OSError) as exc:
        LOG.error("启动失败: %s", exc)
        return 2
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
