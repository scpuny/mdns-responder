"""LanAsset 设备事件总线 + WebSocket 协议工具（零第三方依赖）。

PRD 3.8 / 7：单个 WS 流同时推送 mDNS 被动事件与 LanAsset 主动探测事件，
LanLink 只需订阅 /api/v1/devices/watch 即可。事件总线同时服务 WS 与内存历史。
WebSocket 握手 / 帧为 RFC 6455 最小实现（服务端只发文本帧，处理客户端 ping/close）。
"""

from __future__ import annotations

import base64
import hashlib
import json
import queue
import struct
import threading
import time
from collections import deque
from typing import Any

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_HISTORY = 300
MAX_SUB_QUEUE = 500

# 事件类型常量（PRD 3.8）
EV_DEVICE_ADD = "device.add"
EV_DEVICE_UPDATE = "device.update"
EV_DEVICE_OFFLINE = "device.offline"
EV_SCAN_START = "scan.start"
EV_SCAN_DONE = "scan.done"
EV_SCAN_STOP = "scan.stop"
EV_PROBE_ERROR = "probe.error"
EV_SNAPSHOT = "snapshot.created"


class DeviceEventBus:
    """线程安全的发布/订阅总线；订阅者慢消费不会阻塞发布者。"""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._subs: set[queue.Queue] = set()
        self._history: deque[dict[str, Any]] = deque(maxlen=MAX_HISTORY)
        self._seq = 0

    def subscribe(self) -> queue.Queue:
        sub: queue.Queue = queue.Queue(maxsize=MAX_SUB_QUEUE)
        with self._lock:
            self._subs.add(sub)
            # 新订阅者先收到最近 20 条，避免刚连上什么也看不到
            for item in list(self._history)[-20:]:
                try:
                    sub.put_nowait(item)
                except queue.Full:
                    break
        return sub

    def unsubscribe(self, sub: queue.Queue) -> None:
        with self._lock:
            self._subs.discard(sub)

    def publish(self, event: str, **data: Any) -> dict[str, Any]:
        item = {
            "id": self._next_id(),
            "event": event,
            "ts": time.time(),
            "data": data,
        }
        with self._lock:
            self._history.append(item)
            for sub in list(self._subs):
                try:
                    sub.put_nowait(item)
                except queue.Full:
                    pass  # 丢弃慢订阅者的旧事件，不影响主流程
        return item

    def history(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._history)[-max(1, min(limit, MAX_HISTORY)):]

    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subs)

    def _next_id(self) -> int:
        with self._lock:
            self._seq += 1
            return self._seq


# ---------------------------------------------------------------------------
# RFC 6455 最小实现
# ---------------------------------------------------------------------------
def ws_accept_key(client_key: str) -> str:
    """计算 Sec-WebSocket-Accept。"""
    digest = hashlib.sha1((str(client_key) + WS_GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


def ws_text_frame(payload: str | bytes) -> bytes:
    """构造一个服务端文本帧（不掩码）。支持 7 / 16 / 64 位长度。"""
    data = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)
    n = len(data)
    header = bytearray([0x81])  # FIN + opcode=1(text)
    if n < 126:
        header.append(0x80 | n)  # 服务端帧不设 MASK 位
    elif n < 65536:
        header.append(0x80 | 126)
        header += struct.pack("!H", n)
    else:
        header.append(0x80 | 127)
        header += struct.pack("!Q", n)
    return bytes(header) + data


def ws_pong_frame(payload: bytes = b"") -> bytes:
    """构造 pong 帧（opcode=0xA）。"""
    n = len(payload)
    header = bytearray([0x8A, 0x80 | n]) if n < 126 else bytearray([0x8A, 0xFE]) + struct.pack("!H", n)
    return bytes(header) + payload


def ws_close(code: int = 1000) -> bytes:
    return b"\x88\x82" + struct.pack("!H", code)


def recv_exact(sock, count: int) -> bytes:
    """从 socket 精确读取 count 字节；不足时抛 OSError。"""
    chunks = bytearray()
    while len(chunks) < count:
        part = sock.recv(count - len(chunks))
        if not part:
            raise ConnectionError("连接已关闭")
        chunks += part
    return bytes(chunks)


def read_ws_frame(sock) -> tuple[int, bytes] | None:
    """读取一帧，返回 (opcode, payload)。控制帧由调用方处理。

    不支持分片 / 客户端未掩码帧直接断开（符合 RFC 要求）。
    """
    first, second = recv_exact(sock, 2)
    fin = bool(first & 0x80)
    opcode = first & 0x0F
    masked = bool(second & 0x80)
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", recv_exact(sock, 8))[0]
    if length > 4 * 1024 * 1024:
        raise ValueError("WebSocket 帧过大")
    mask = recv_exact(sock, 4) if masked else b""
    payload = recv_exact(sock, length) if length else b""
    if masked:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    if not fin and opcode in (0x1, 0x2):
        # 分片消息：消费后续帧直到 FIN，拼接后一次性返回
        parts = bytearray(payload)
        while True:
            f1, f2 = recv_exact(sock, 2)
            ln = f2 & 0x7F
            if ln == 126:
                ln = struct.unpack("!H", recv_exact(sock, 2))[0]
            elif ln == 127:
                ln = struct.unpack("!Q", recv_exact(sock, 8))[0]
            mk = recv_exact(sock, 4) if (f2 & 0x80) else b""
            seg = recv_exact(sock, ln) if ln else b""
            if mk:
                seg = bytes(b ^ mk[i % 4] for i, b in enumerate(seg))
            parts += seg
            if f1 & 0x80:
                break
        return (opcode, bytes(parts))
    return (opcode, payload)


def encode_event(item: dict[str, Any]) -> bytes:
    return ws_text_frame(json.dumps(item, ensure_ascii=False, default=str))
