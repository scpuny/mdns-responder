"""LanAsset — controlled active asset probing with a unified device pool.

Design constraints (from the LanAsset PRD):
  * disabled by default; no background scanning whatsoever
  * every scan is manually triggered, rate limited, bounded and cancellable
  * probe failures are isolated and never affect the mDNS responder
  * active results and passive mDNS discoveries merge into one device pool

Capabilities: ICMP reachability (raw socket + system ping fallback), ARP
(L2 MAC discovery with graceful degradation), offline OUI vendor lookup,
bounded TCP port probes, incremental device pool, cancellation and events.
Snapshots / CSV live in asset_db.py; WebSocket transport lives in asset_events.py.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import select
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Iterable

from asset_oui import DEFAULT_LOOKUP, OUILookup
from asset_events import (
    EV_DEVICE_ADD, EV_DEVICE_OFFLINE, EV_DEVICE_UPDATE,
    EV_PROBE_ERROR, EV_SCAN_DONE, EV_SCAN_START, EV_SCAN_STOP,
)

LOG = logging.getLogger("lan-asset")

STATE_IDLE = "idle"
STATE_RUNNING = "running"
STATE_DONE = "done"
STATE_STOPPED = "stopped"
STATE_FAILED = "failed"
MAX_EVENTS = 200

MODE_ARP = "arp"
MODE_ICMP = "icmp"
MODE_COMBO = "arp+icmp"
VALID_MODES = (MODE_ARP, MODE_ICMP, MODE_COMBO)

# 内置端口探针模板（PRD 3.3）。仅探测用户显式给出的端口，绝不全端口扫描。
PORT_TEMPLATES: dict[str, list[int]] = {
    "dev": [22, 80, 443, 3000],
    "industrial": [502, 1883, 8080],
}


@dataclass
class AssetConfig:
    """[asset] 配置。`enabled` 在任何地方都默认为 False。"""

    enabled: bool = False
    interval_ms: int = 200
    timeout_ms: int = 800
    max_concurrent: int = 16
    exclude_ips: list[str] = field(default_factory=list)
    # 探测策略
    mode: str = MODE_COMBO                       # arp / icmp / arp+icmp（默认组合）
    port_probe: bool = False                     # 端口探针默认关闭
    port_template: str = ""                      # dev / industrial / custom
    custom_ports: list[int] = field(default_factory=list)
    port_timeout_ms: int = 300                   # 单端口连接超时
    oui_extra_path: str = ""                     # 可选外部 OUI JSON
    retention_days: int = 7                      # 离线资产保留天数；0=永久保留

    def validate(self) -> None:
        if not 10 <= self.interval_ms <= 1000:
            raise ValueError("asset.interval_ms 必须在 10..1000 毫秒")
        if not 50 <= self.timeout_ms <= 5000:
            raise ValueError("asset.timeout_ms 必须在 50..5000 毫秒")
        if not 1 <= self.max_concurrent <= 256:
            raise ValueError("asset.max_concurrent 必须在 1..256")
        if self.mode not in VALID_MODES:
            raise ValueError(f"asset.mode 必须是 {', '.join(VALID_MODES)} 之一")
        if not 50 <= self.port_timeout_ms <= 5000:
            raise ValueError("asset.port_timeout_ms 必须在 50..5000 毫秒")
        if self.retention_days < 0:
            raise ValueError("asset.retention_days 必须 >= 0（0 表示永久保留）")
        for raw in self.exclude_ips:
            try:
                ipaddress.IPv4Address(str(raw).strip())
            except ValueError as exc:
                raise ValueError(f"asset.exclude_ips 含非法地址: {raw!r}") from exc
        for port in self.custom_ports:
            if not 1 <= int(port) <= 65535:
                raise ValueError(f"asset.custom_ports 含非法端口: {port!r}")

    def resolved_ports(self) -> list[int]:
        """按模板 / 自定义解析最终探测端口列表（去重、有序、有界）。"""
        if not self.port_probe:
            return []
        ports: list[int] = []
        if self.port_template in PORT_TEMPLATES:
            ports.extend(PORT_TEMPLATES[self.port_template])
        ports.extend(int(p) for p in self.custom_ports)
        seen: set[int] = set()
        result: list[int] = []
        for p in ports:
            if p not in seen and 1 <= p <= 65535 and len(result) < 64:
                seen.add(p)
                result.append(p)
        return result


def config_from_dict(data: dict[str, Any] | None) -> AssetConfig:
    raw = dict(data or {})

    def _ports(value: Any) -> list[int]:
        out: list[int] = []
        for item in (value or []):
            try:
                out.append(int(str(item).split(",")[0].strip()))
            except (TypeError, ValueError):
                continue
        return out

    cfg = AssetConfig(
        enabled=bool(raw.get("enabled", False)),
        interval_ms=int(raw.get("interval_ms", 200)),
        timeout_ms=int(raw.get("timeout_ms", 800)),
        max_concurrent=int(raw.get("max_concurrent", 16)),
        exclude_ips=[str(x) for x in (raw.get("exclude_ips") or [])],
        mode=str(raw.get("mode", MODE_COMBO) or MODE_COMBO).strip().lower(),
        port_probe=bool(raw.get("port_probe", False)),
        port_template=str(raw.get("port_template", "") or "").strip().lower(),
        custom_ports=_ports(raw.get("custom_ports")),
        port_timeout_ms=int(raw.get("port_timeout_ms", 300)),
        oui_extra_path=str(raw.get("oui_extra_path", "") or ""),
        retention_days=int(raw.get("retention_days", 7)),
    )
    cfg.validate()
    return cfg


def iter_targets(cidr: str, exclude_ips: Iterable[str] = ()) -> list[str]:
    """Enumerate scannable hosts. Rejects the whole Internet by design."""
    try:
        network = ipaddress.IPv4Network(str(cidr).strip(), strict=False)
    except ValueError as exc:
        raise ValueError(f"非法 CIDR: {cidr!r}") from exc
    if network.prefixlen == 0:
        raise ValueError("禁止 0.0.0.0/0 全网扫描")
    excluded = {str(x).strip() for x in exclude_ips}
    return [str(host) for host in network.hosts() if str(host) not in excluded]


def requires_confirmation(cidr: str, threshold: int = 24) -> bool:
    """CIDRs larger than the threshold need explicit UI confirmation."""
    try:
        network = ipaddress.IPv4Network(str(cidr).strip(), strict=False)
    except ValueError:
        return True
    return network.prefixlen < threshold


# ---------------------------------------------------------------------------
# ICMP reachability: raw socket first, system ping as a fallback
# ---------------------------------------------------------------------------

def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _icmp_echo_request(identifier: int, sequence: int) -> bytes:
    header = struct.pack("!BBHHH", 8, 0, 0, identifier, sequence)
    payload = struct.pack("!d", time.time())
    checksum = _checksum(header + payload)
    return struct.pack("!BBHHH", 8, 0, checksum, identifier, sequence) + payload


def _raw_icmp_probe(ip: str, timeout_ms: int) -> bool | None:
    """Return True/False if a raw socket worked, None if unavailable."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(max(timeout_ms, 50) / 1000.0)
        identifier = os.getpid() & 0xFFFF
        packet = _icmp_echo_request(identifier, 1)
        sock.sendto(packet, (ip, 0))
        deadline = time.monotonic() + timeout_ms / 1000.0
        while time.monotonic() < deadline:
            ready, _, _ = select.select([sock], [], [], max(0.0, deadline - time.monotonic()))
            if not ready:
                break
            data, _ = sock.recvfrom(2048)
            if len(data) < 28:
                continue
            rtype, _, _, rid, _ = struct.unpack("!BBHHH", data[20:28])
            if rtype == 0 and rid == identifier:
                return True
        return False
    except (OSError, PermissionError):
        return None
    finally:
        if sock is not None:
            sock.close()


def _ping_probe(ip: str, timeout_ms: int) -> bool:
    """Fallback using the system ping binary (no CAP_NET_RAW needed)."""
    seconds = max(1, int((timeout_ms + 999) // 1000))
    if sys.platform == "win32":
        command = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    elif sys.platform == "darwin":
        command = ["ping", "-c", "1", "-W", str(timeout_ms), ip]
    else:
        command = ["ping", "-c", "1", "-W", str(seconds), ip]
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=seconds + 1,
            check=False,
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def probe_host(ip: str, timeout_ms: int) -> tuple[bool, str]:
    """Probe one host. Returns (online, method) with method 'icmp' or 'ping'."""
    result = _raw_icmp_probe(ip, timeout_ms)
    if result is not None:
        return result, "icmp"
    return _ping_probe(ip, timeout_ms), "ping"


# ---------------------------------------------------------------------------
# ARP 探测（二层）。raw socket 不可用时从系统邻居表读取 MAC，再降级 ICMP。
# ---------------------------------------------------------------------------
_ARP_AVAILABLE: bool | None = None


def arp_available() -> bool:
    """探测本机是否具备 ARP raw socket 能力（Linux AF_PACKET）。结果缓存。"""
    global _ARP_AVAILABLE
    if _ARP_AVAILABLE is not None:
        return _ARP_AVAILABLE
    available = False
    if sys.platform.startswith("linux"):
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                 socket.htons(0x0806))
            sock.close()
            available = True
        except (OSError, PermissionError, AttributeError):
            available = False
    _ARP_AVAILABLE = available
    return available


def _arp_request_frame(target_ip: str, src_mac: bytes, src_ip: bytes) -> bytes:
    """构造 Ethernet(II) + ARP who-has 请求帧。"""
    broadcast = b"\xff" * 6
    ethertype = struct.pack("!H", 0x0806)
    # htype=1(ethernet), ptype=0x0800(IPv4), hlen=6, plen=4, op=1(request)
    arp = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
    arp += src_mac + src_ip + b"\x00" * 6 + socket.inet_aton(target_ip)
    return broadcast + src_mac + ethertype + arp


def _arp_reply_mac(data: bytes, target_ip: str) -> str | None:
    """从以太帧解析 ARP reply，匹配目标 IP 时返回发送方 MAC。"""
    if len(data) < 42 or struct.unpack("!H", data[12:14])[0] != 0x0806:
        return None
    arp = data[14:]
    if len(arp) < 28:
        return None
    op = struct.unpack("!H", arp[6:8])[0]
    if op != 2:  # 2 = reply
        return None
    sender_mac = arp[8:14]
    sender_ip = socket.inet_ntoa(arp[14:18])
    if sender_ip != target_ip:
        return None
    return ":".join(f"{b:02x}" for b in sender_mac)


def _interface_for_ip(target_ip: str) -> tuple[str, bytes, bytes] | None:
    """通过 UDP connect（不发实际数据）找出到达目标的网卡 IP 与 MAC。"""
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect((target_ip, 80))
        local_ip = probe.getsockname()[0]
        probe.close()
    except OSError:
        return None
    if not sys.platform.startswith("linux"):
        return None
    interfaces = _linux_interfaces()
    for name, mac, ip in interfaces:
        if ip == local_ip and mac and len(mac) == 6:
            return name, mac, socket.inet_aton(local_ip)
    return None


def _linux_interfaces() -> list[tuple[str, bytes, str]]:
    """枚举 Linux 网卡 (名称, MAC 6字节, IPv4)。零外部命令。"""
    result: list[tuple[str, bytes, str]] = []
    import fcntl  # Linux-only，运行在非 Linux 时不会被调用

    try:
        names = os.listdir("/sys/class/net")
    except OSError:
        return result
    for name in names:
        try:
            with open(f"/sys/class/net/{name}/address", "r", encoding="ascii") as fh:
                mac_raw = fh.read().strip()
            mac = bytes.fromhex(mac_raw.replace(":", "").replace("-", ""))
            if len(mac) != 6:
                continue
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ip = socket.inet_ntoa(fcntl.ioctl(
                sock.fileno(), 0x8915,  # SIOCGIFADDR
                struct.pack("256s", name[:15].encode()))[20:24])
            sock.close()
            result.append((name, mac, ip))
        except (OSError, ValueError):
            continue
    return result


def arp_probe(ip: str, timeout_ms: int) -> tuple[bool, str] | None:
    """真正的 ARP 探测（需 CAP_NET_RAW）。

    返回 (online, mac)；本机无 raw socket 权限时返回 None，由调用方降级。
    """
    if not arp_available():
        return None
    route = _interface_for_ip(ip)
    if route is None:
        return None
    ifname, src_mac, src_ip = route
    sock = None
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                             socket.htons(0x0806))
        sock.bind((ifname, 0))
        sock.settimeout(max(timeout_ms, 100) / 1000.0)
        frame = _arp_request_frame(ip, src_mac, src_ip)
        sock.send(frame)
        deadline = time.monotonic() + timeout_ms / 1000.0
        while time.monotonic() < deadline:
            ready, _, _ = select.select([sock], [], [],
                                        max(0.0, deadline - time.monotonic()))
            if not ready:
                break
            data, _ = sock.recvfrom(2048)
            mac = _arp_reply_mac(data, ip)
            if mac:
                return True, mac
        return False, ""
    except (OSError, PermissionError, ValueError):
        return None
    finally:
        if sock is not None:
            sock.close()


def arp_cache_lookup(ip: str) -> str:
    """从系统邻居表读取 MAC（无需 CAP_NET_RAW）。

    ping 触发内核 ARP 学习后这里通常能拿到同网段设备 MAC；跨网段为空。
    """
    try:
        if sys.platform.startswith("linux"):
            with open("/proc/net/arp", "r", encoding="utf-8", errors="replace") as fh:
                next(fh, None)
                for line in fh:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == ip and parts[3].upper() != "0X0":
                        return parts[3].lower().replace("-", ":")
        else:
            command = ["arp", "-an"] if sys.platform != "win32" else ["arp", "-a"]
            out = subprocess.run(command, capture_output=True, text=True, timeout=2,
                                 check=False).stdout
            for line in out.splitlines():
                if ip in line:
                    match = re.search(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", line)
                    if match:
                        return match.group(0).replace("-", ":").lower()
    except (OSError, subprocess.SubprocessError):
        pass
    return ""


def probe_ports(ip: str, ports: list[int], timeout_ms: int,
                max_concurrent: int = 8) -> list[dict[str, Any]]:
    """仅探测用户显式给出的 TCP 端口（connect_ex），限速并发。

    绝不做全端口扫描；结果按端口升序返回。
    """
    if not ports:
        return []
    timeout_s = max(50, timeout_ms) / 1000.0
    results: list[dict[str, Any]] = []

    def one(port: int) -> dict[str, Any]:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout_s)
            code = sock.connect_ex((ip, port))
            return {"port": int(port), "proto": "tcp", "open": code == 0}
        except OSError:
            return {"port": int(port), "proto": "tcp", "open": False}
        finally:
            if sock is not None:
                sock.close()

    workers = max(1, min(int(max_concurrent), len(ports)))
    with ThreadPoolExecutor(max_workers=workers,
                            thread_name_prefix="lan-asset-port") as pool:
        futures = [pool.submit(one, p) for p in ports]
        for fut in as_completed(futures):
            results.append(fut.result())
    return sorted(results, key=lambda x: x["port"])


def probe_host_full(ip: str, timeout_ms: int, *, mode: str = MODE_COMBO,
                    ports: list[int] | None = None, port_timeout_ms: int = 300,
                    max_concurrent: int = 8,
                    oui: OUILookup | None = None) -> dict[str, Any]:
    """统一探测入口：按 mode 做 ARP / ICMP，回填 MAC 与厂商，可选端口探针。"""
    oui = oui or DEFAULT_LOOKUP
    online = False
    method = ""
    mac = ""
    arp_unavailable = False

    if mode in (MODE_ARP, MODE_COMBO) and arp_available():
        result = arp_probe(ip, timeout_ms)
        if result is not None:
            online, mac = result
            method = "arp"
    elif mode in (MODE_ARP, MODE_COMBO):
        arp_unavailable = True

    if not online and mode in (MODE_ICMP, MODE_COMBO):
        online, method = probe_host(ip, timeout_ms)
        # ICMP 跨网段拿不到 MAC，但同网段 ping 后邻居表通常已学习
        if not mac:
            mac = arp_cache_lookup(ip)

    detected = probe_ports(ip, ports or [], port_timeout_ms, max_concurrent) \
        if online else []
    return {
        "online": online,
        "method": method,
        "mac": mac,
        "vendor": oui.lookup(mac) if mac else "Unknown",
        "ports": detected,
        "arp_unavailable": arp_unavailable,
    }


# ---------------------------------------------------------------------------
# Unified device pool
# ---------------------------------------------------------------------------

def _new_device(ip: str, now: float) -> dict[str, Any]:
    """统一设备结构（PRD 3.5 字段全集）。"""
    return {
        "id": ip,
        "ip": ip,
        "mac": "",
        "vendor": "Unknown",
        "online": True,
        "sources": [],
        "services": [],
        "detected_ports": [],
        "tags": [],
        "remark": "",
        "last_seen": now,
        "linked_mdns_record": None,
        "probe_method": "",
    }


class AssetStore:
    """线程安全统一设备池；mDNS 被动与主动探测按 IP 合并。"""

    def __init__(self, *, event_bus: Any = None,
                 oui: OUILookup | None = None) -> None:
        self._lock = threading.RLock()
        self._devices: dict[str, dict[str, Any]] = {}
        self._bus = event_bus
        self._oui = oui or DEFAULT_LOOKUP

    def _publish(self, event: str, device: dict[str, Any]) -> None:
        if self._bus is None:
            return
        try:
            self._bus.publish(event, ip=device["ip"], device=dict(device))
        except Exception:  # noqa: BLE001 - 事件失败绝不影响设备池
            LOG.debug("发布设备事件失败", exc_info=True)

    def update_scan(self, ip: str, online: bool, method: str = "ping", *,
                    mac: str = "", vendor: str = "",
                    detected_ports: list[dict[str, Any]] | None = None) -> None:
        now = time.time()
        source = "arp" if method == "arp" else "icmp"
        event = EV_DEVICE_ADD
        with self._lock:
            device = self._devices.get(ip)
            if device is None:
                device = _new_device(ip, now)
                device["online"] = online
                device["sources"] = [source]
                device["probe_method"] = method
                device["last_seen"] = now if online else 0.0
                self._devices[ip] = device
            else:
                event = EV_DEVICE_UPDATE
                if source not in device["sources"]:
                    device["sources"].append(source)
                was_online = device["online"]
                device["online"] = online
                device["probe_method"] = method
                if online and not was_online:
                    event = EV_DEVICE_UPDATE
                if not online and was_online:
                    event = EV_DEVICE_OFFLINE
                if online:
                    device["last_seen"] = now
            if mac and not device.get("mac"):
                device["mac"] = mac
            if mac or vendor:
                device["vendor"] = vendor or self._oui.lookup(mac)
            if detected_ports:
                device["detected_ports"] = detected_ports
        self._publish(event, device)

    def merge_mdns(self, items: Iterable[dict[str, Any]]) -> int:
        """合并被动 mDNS 数据；返回本次新增来源/服务的设备数（事件已内部发布）。"""
        changed: list[dict[str, Any]] = []
        now = time.time()
        with self._lock:
            for item in items or []:
                ip = str((item or {}).get("host_ip") or "").strip()
                if not ip:
                    continue
                device = self._devices.get(ip)
                is_new = device is None
                if device is None:
                    device = _new_device(ip, now)
                    self._devices[ip] = device
                device["online"] = True
                if "mdns" not in device["sources"]:
                    device["sources"].append("mdns")
                service = {
                    "name": item.get("instance") or item.get("fqdn") or "",
                    "type": item.get("type") or "",
                    "port": item.get("port"),
                    "host": item.get("host") or "",
                    "txt": item.get("txt") or "",
                }
                existing = device["services"]
                if not any(s.get("name") == service["name"] and s.get("type") == service["type"]
                           for s in existing):
                    existing.append(service)
                    is_new = True
                device["last_seen"] = max(device.get("last_seen") or 0.0,
                                          float(item.get("last_seen") or now))
                if is_new:
                    changed.append(dict(device, sources=list(device["sources"]),
                                        services=[dict(s) for s in device["services"]]))
        for device in changed:
            self._publish(EV_DEVICE_ADD, device)
        return len(changed)

    def set_meta(self, ip: str, *, tags: list[str] | None = None,
                 remark: str | None = None,
                 linked_mdns_record: str | None = None) -> dict[str, Any] | None:
        """更新用户自定义标签 / 备注 / 静态 mDNS 关联（PRD 3.5/3.9）。"""
        with self._lock:
            device = self._devices.get(ip)
            if device is None:
                return None
            if tags is not None:
                device["tags"] = list(dict.fromkeys(str(t).strip() for t in tags if str(t).strip()))
            if remark is not None:
                device["remark"] = str(remark)
            if linked_mdns_record is not None:
                device["linked_mdns_record"] = str(linked_mdns_record) or None
            snapshot = dict(device, sources=list(device["sources"]))
        self._publish(EV_DEVICE_UPDATE, snapshot)
        return snapshot

    def restore_meta(self, ip: str, *, tags: list[str], remark: str,
                     linked_mdns_record: str | None,
                     offline: bool = True) -> None:
        """启动时从数据库恢复设备元数据；仅创建占位行，不触发事件。"""
        with self._lock:
            device = self._devices.get(ip)
            if device is None:
                device = _new_device(ip, time.time())
                device["online"] = not offline
                device["sources"] = []
                device["last_seen"] = 0.0 if offline else time.time()
                self._devices[ip] = device
            device["tags"] = list(tags or [])
            device["remark"] = remark or ""
            device["linked_mdns_record"] = linked_mdns_record or None

    def remove(self, ip: str) -> bool:
        with self._lock:
            return self._devices.pop(ip, None) is not None

    def prune_offline(self, retention_days: int) -> int:
        """老化策略：清理离线超过 N 天的资产；0 表示永久保留。"""
        if retention_days <= 0:
            return 0
        cutoff = time.time() - retention_days * 86400
        removed: list[str] = []
        with self._lock:
            for ip, device in self._devices.items():
                if not device["online"] and device.get("last_seen", 0) and \
                        device["last_seen"] < cutoff:
                    removed.append(ip)
            for ip in removed:
                del self._devices[ip]
        return len(removed)

    def snapshot_items(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(d, sources=list(d["sources"]),
                         services=[dict(s) for s in d["services"]],
                         detected_ports=[dict(p) for p in d.get("detected_ports", [])],
                         tags=list(d["tags"]))
                    for d in self._devices.values()]

    def devices(self, *, online: bool | None = None,
                source: str | None = None, cidr: str | None = None,
                tag: str | None = None) -> list[dict[str, Any]]:
        network = ipaddress.IPv4Network(cidr, strict=False) if cidr else None
        with self._lock:
            result = [dict(d, sources=list(d["sources"]),
                           services=[dict(s) for s in d["services"]],
                           detected_ports=[dict(p) for p in d.get("detected_ports", [])],
                           tags=list(d["tags"]))
                      for d in self._devices.values()]
        if online is not None:
            result = [d for d in result if bool(d["online"]) == online]
        if source:
            result = [d for d in result if source in d["sources"]]
        if tag:
            result = [d for d in result if tag in d["tags"]]
        if network is not None:
            result = [d for d in result
                      if ipaddress.IPv4Address(d["ip"]) in network]
        result.sort(key=lambda d: ipaddress.IPv4Address(d["ip"]))
        return result

    def count(self) -> int:
        with self._lock:
            return len(self._devices)


# ---------------------------------------------------------------------------
# Scan lifecycle
# ---------------------------------------------------------------------------

class ScanManager:
    """Owns at most one scan thread. Cancellation is immediate and safe."""

    def __init__(self, store: AssetStore, config: AssetConfig,
                 event_bus: Any = None) -> None:
        self._store = store
        self._config = config
        self._bus = event_bus
        self._oui = OUILookup(config.oui_extra_path) if config.oui_extra_path else DEFAULT_LOOKUP
        self._lock = threading.RLock()
        self._cancel = threading.Event()
        self._thread: threading.Thread | None = None
        self._state = STATE_IDLE
        self._stats: dict[str, Any] = {}
        self._events: deque[dict[str, Any]] = deque(maxlen=MAX_EVENTS)
        self._event_seq = 0
        self._ports: list[int] = config.resolved_ports()
        self._mode: str = config.mode

    def configure(self, config: AssetConfig) -> None:
        with self._lock:
            self._config = config
            self._ports = config.resolved_ports()
            self._mode = config.mode
            if config.oui_extra_path:
                self._oui = OUILookup(config.oui_extra_path)
            if not config.enabled and self._state == STATE_RUNNING:
                self._cancel.set()

    def _publish(self, event: str, **data: Any) -> None:
        if self._bus is None:
            return
        try:
            self._bus.publish(event, **data)
        except Exception:  # noqa: BLE001
            LOG.debug("发布扫描事件失败", exc_info=True)

    def _log(self, kind: str, message: str) -> None:
        with self._lock:
            self._event_seq += 1
            self._events.append({
                "id": self._event_seq,
                "time": time.time(),
                "kind": kind,
                "message": message,
            })
        LOG.info("LanAsset: %s", message)
        # 内部控制事件映射到 WS 对外事件名
        mapping = {
            "scan.start": EV_SCAN_START, "scan.done": EV_SCAN_DONE,
            "scan.stop": EV_SCAN_STOP, "scan.error": EV_SCAN_DONE,
            "probe.error": EV_PROBE_ERROR,
        }
        if kind in mapping:
            self._publish(mapping[kind], message=message,
                          status=self.status() if kind.startswith("scan.") else {})

    def start(self, cidr: str, *, confirm_large: bool = False,
              interval_ms: int | None = None, timeout_ms: int | None = None,
              max_concurrent: int | None = None,
              exclude_ips: list[str] | None = None,
              mode: str | None = None, port_probe: bool | None = None,
              port_template: str | None = None,
              custom_ports: list[int] | None = None) -> dict[str, Any]:
        with self._lock:
            if not self._config.enabled:
                raise RuntimeError("资产扫描模块未启用")
            if self._state == STATE_RUNNING:
                raise RuntimeError("已有扫描任务正在运行")
            cidr = str(cidr or "").strip()
            if not cidr:
                raise ValueError("请提供扫描网段 CIDR")
            if requires_confirmation(cidr) and not confirm_large:
                raise ValueError("该网段较大，请确认后重试（confirm_large=true）")
            excluded = exclude_ips if exclude_ips is not None else self._config.exclude_ips
            targets = iter_targets(cidr, excluded)
            if not targets:
                raise ValueError("过滤后没有可扫描的地址")
            interval = self._config.interval_ms if interval_ms is None else int(interval_ms)
            timeout = self._config.timeout_ms if timeout_ms is None else int(timeout_ms)
            concurrency = self._config.max_concurrent if max_concurrent is None else int(max_concurrent)
            if not 10 <= interval <= 1000 or not 50 <= timeout <= 5000 or not 1 <= concurrency <= 256:
                raise ValueError("扫描参数超出允许范围")
            chosen_mode = (mode or self._config.mode).strip().lower()
            if chosen_mode not in VALID_MODES:
                raise ValueError(f"探测模式必须是 {', '.join(VALID_MODES)} 之一")
            # 本次扫描的端口列表（请求级覆盖优先于配置）
            if port_probe is not None:
                enabled_ports = bool(port_probe)
            else:
                enabled_ports = self._config.port_probe
            template = (port_template if port_template is not None
                        else self._config.port_template)
            custom = custom_ports if custom_ports is not None else self._config.custom_ports
            if enabled_ports:
                ports: list[int] = []
                if template in PORT_TEMPLATES:
                    ports.extend(PORT_TEMPLATES[template])
                ports.extend(int(p) for p in (custom or []))
                ports = list(dict.fromkeys(p for p in ports if 1 <= p <= 65535))[:64]
            else:
                ports = []
            self._cancel.clear()
            self._state = STATE_RUNNING
            self._mode = chosen_mode
            self._ports = ports
            self._stats = {
                "cidr": cidr,
                "mode": chosen_mode,
                "port_probe": enabled_ports,
                "port_count": len(ports),
                "total": len(targets),
                "scanned": 0,
                "online": 0,
                "offline": 0,
                "started_at": time.time(),
                "finished_at": None,
            }
            self._thread = threading.Thread(
                target=self._run,
                args=(targets, interval, timeout, concurrency, chosen_mode, ports),
                name="lan-asset-scan",
                daemon=True,
            )
            self._thread.start()
        self._log("scan.start", f"开始扫描 {cidr}，共 {len(targets)} 个地址（模式 {chosen_mode}）")
        return self.status()

    def stop(self) -> dict[str, Any]:
        with self._lock:
            if self._state != STATE_RUNNING:
                return self.status()
            self._cancel.set()
            thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2.0)
        with self._lock:
            if self._state == STATE_RUNNING:
                self._state = STATE_STOPPED
                self._stats["finished_at"] = time.time()
        self._log("scan.stop", "扫描已停止")
        return self.status()

    def _run(self, targets: list[str], interval_ms: int,
             timeout_ms: int, concurrency: int,
             mode: str = MODE_COMBO, ports: list[int] | None = None) -> None:
        throttle_lock = threading.Lock()
        last_dispatch = [0.0]
        interval_s = interval_ms / 1000.0
        reported_arp_warning = [False]

        def worker(ip: str) -> tuple[str, dict[str, Any]] | None:
            if self._cancel.is_set():
                return None
            with throttle_lock:
                wait = interval_s - (time.monotonic() - last_dispatch[0])
                if wait > 0:
                    self._cancel.wait(wait)
                last_dispatch[0] = time.monotonic()
            if self._cancel.is_set():
                return None
            try:
                detail = probe_host_full(
                    ip, timeout_ms, mode=mode, ports=ports,
                    port_timeout_ms=self._config.port_timeout_ms,
                    max_concurrent=min(concurrency, 8), oui=self._oui)
                return ip, detail
            except Exception as exc:  # noqa: BLE001 - probe isolation
                self._log("probe.error", f"探测 {ip} 失败: {exc}")
                return ip, {"online": False, "method": "", "mac": "",
                            "vendor": "Unknown", "ports": [],
                            "arp_unavailable": False}

        try:
            with ThreadPoolExecutor(max_workers=concurrency,
                                    thread_name_prefix="lan-asset-probe") as pool:
                futures = [pool.submit(worker, ip) for ip in targets]
                for future in as_completed(futures):
                    if self._cancel.is_set():
                        for item in futures:
                            item.cancel()
                        break
                    result = future.result()
                    if result is None:
                        continue
                    ip, detail = result
                    self._store.update_scan(
                        ip, detail["online"], detail["method"] or "ping",
                        mac=detail.get("mac", ""), vendor=detail.get("vendor", ""),
                        detected_ports=detail.get("ports", []))
                    if detail.get("arp_unavailable") and not reported_arp_warning[0]:
                        reported_arp_warning[0] = True
                        self._log("probe.warn",
                                  "ARP 不可用（缺少 CAP_NET_RAW / 管理员权限），已自动降级为 ICMP")
                    with self._lock:
                        self._stats["scanned"] += 1
                        key = "online" if detail["online"] else "offline"
                        self._stats[key] += 1
        except Exception as exc:  # noqa: BLE001 - never crash the responder
            self._log("scan.error", f"扫描异常: {exc}")
            with self._lock:
                self._state = STATE_FAILED
                self._stats["finished_at"] = time.time()
        else:
            with self._lock:
                if self._state == STATE_RUNNING:
                    self._state = STATE_DONE
                    self._stats["finished_at"] = time.time()
            stats = self._stats
            self._log("scan.done",
                      f"扫描完成：{stats.get('scanned', 0)}/{stats.get('total', 0)} "
                      f"在线 {stats.get('online', 0)}")

    def status(self) -> dict[str, Any]:
        with self._lock:
            stats = dict(self._stats)
            if self._state == STATE_RUNNING and stats.get("total"):
                remaining = max(0, stats["total"] - stats.get("scanned", 0))
                stats["eta_seconds"] = round(
                    remaining * (self._config.interval_ms / 1000.0)
                    / max(1, self._config.max_concurrent), 1)
            return {
                "enabled": self._config.enabled,
                "state": self._state,
                "stats": stats,
                "events": list(self._events)[-20:],
            }

    def close(self) -> None:
        """Called on responder shutdown; cancels any in-flight scan."""
        self.stop()
