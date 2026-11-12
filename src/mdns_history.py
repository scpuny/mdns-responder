#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mdns_history.py - 配置版本历史与一键回滚（零第三方依赖）

* 每次保存 / 回滚前，把「当前生效的 config.toml 原文」存成一份快照；
* 快照落在 ``logs/config_history/``（可用 ``MDNS_HISTORY_DIR`` 覆盖），
  单份文件是一个 JSON：{ts, reason, text}，text 即当时的 TOML 原文；
* 有界保留（history_limit，默认 30 份），超出自动删最老的；
* 回滚 = 读出 text -> 走与在线保存完全相同的「校验 -> 备份 -> 原子替换 -> 热重载」链路，
  因此永远不会把一份非法配置写回磁盘。

文件名：config-<UTC 秒>-<微秒 hex>-<随机 hex>.json；ID 白名单正则防止路径穿越。
"""

from __future__ import annotations

import json
import os
import re
import threading
import time

HISTORY_ENV = "MDNS_HISTORY_DIR"
# config-<UTC 秒>-<微秒 hex6>-<随机 hex4>.json
# 微秒段保证同一秒内多次保存的字典序单调递增；随机段避免多进程碰撞。
ID_RE = re.compile(r"^config-\d{8}T\d{6}Z-[0-9a-f]{6}-[0-9a-f]{4,8}\.json$")

LOG = __import__("logging").getLogger("mdns.history")


def project_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def default_history_dir() -> str:
    return os.environ.get(HISTORY_ENV) or os.path.join(
        project_root(), "logs", "config_history")


class ConfigHistory:
    """有界的配置快照仓库（线程安全）。"""

    def __init__(self, directory: str | None = None, limit: int = 30):
        self.dir = os.path.abspath(directory or default_history_dir())
        self.limit = max(1, int(limit))
        self._lock = threading.Lock()
        os.makedirs(self.dir, exist_ok=True)

    # -- 写 -------------------------------------------------------------
    def save(self, text: str, reason: str = "manual") -> dict:
        """保存一份快照，返回元数据 dict。"""
        now = time.time()
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now))
        seq = f"{(time.time_ns() // 1000) % 0x1000000:06x}"
        name = f"config-{stamp}-{seq}-{os.urandom(2).hex()}.json"
        payload = {
            "ts": now,
            "reason": str(reason or "manual")[:64],
            "text": text if isinstance(text, str) else str(text),
        }
        with self._lock:
            os.makedirs(self.dir, exist_ok=True)
            tmp = os.path.join(self.dir, name + ".tmp")
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False)
            os.replace(tmp, os.path.join(self.dir, name))
            self._prune(keep=name)
            return self._entry(os.path.join(self.dir, name))

    def _prune(self, keep: str | None = None) -> int:
        """按 mtime 淘汰超出 limit 的最老快照；刚写入的 keep 不参与淘汰。

        不能只按文件名排序：同一秒内随机后缀的字典序与写入顺序无关，
        会误删刚刚写入的那份快照。
        """
        names = [n for n in os.listdir(self.dir)
                 if ID_RE.match(n) and n != keep]
        names.sort(key=lambda n: (os.path.getmtime(os.path.join(self.dir, n)), n))
        budget = max(0, self.limit - 1) if keep else self.limit
        removed = 0
        for name in names[:max(0, len(names) - budget)]:
            try:
                os.unlink(os.path.join(self.dir, name))
                removed += 1
            except OSError:
                pass
        return removed

    # -- 读 -------------------------------------------------------------
    @staticmethod
    def _read(path: str) -> dict:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def _entry(self, path: str) -> dict:
        st = os.stat(path)
        data = self._read(path)
        text = data.get("text", "") or ""
        return {
            "id": os.path.basename(path),
            "ts": float(data.get("ts", st.st_mtime)),
            "time": time.strftime("%Y-%m-%d %H:%M:%S",
                                  time.localtime(float(data.get("ts", st.st_mtime)))),
            "reason": str(data.get("reason", "")),
            "size": st.st_size,
            "records": text.count("[[hosts]]") + text.count("[[services]]"),
            "preview": text[:160].replace("\n", " ⏎ "),
        }

    def list(self, limit: int = 50) -> list[dict]:
        with self._lock:
            names = [n for n in os.listdir(self.dir) if ID_RE.match(n)]
            names.sort(key=lambda n: (os.path.getmtime(os.path.join(self.dir, n)), n),
                       reverse=True)          # 最新在前
            items = []
            for name in names[:max(1, int(limit))]:
                try:
                    items.append(self._entry(os.path.join(self.dir, name)))
                except (OSError, ValueError, json.JSONDecodeError):
                    continue
            return items

    def get(self, version_id: str) -> str:
        """按 ID 取出当时的 TOML 原文；严格校验 ID 防路径穿越。"""
        if not isinstance(version_id, str) or not ID_RE.match(version_id):
            raise ValueError("非法的版本 ID")
        path = os.path.join(self.dir, version_id)
        if not os.path.isfile(path):
            raise FileNotFoundError(f"版本不存在: {version_id}")
        text = self._read(path).get("text", "")
        if not isinstance(text, str):
            raise ValueError("版本文件内容损坏")
        return text

    def json(self, limit: int = 50) -> dict:
        items = self.list(limit)
        return {"enabled": True, "dir": self.dir, "limit": self.limit,
                "count": len(items), "items": items}
