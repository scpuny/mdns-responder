"""LanAsset SQLite 持久化（复用标准库 sqlite3，零第三方依赖）。

PRD 3.7 要求新增表且不单独建库——本仓库此前无数据库，故统一在本模块管理的
单一 sqlite 文件（默认 logs/assets.sqlite3）内建表，与 mDNS 其他状态同进程：

  asset_scan_config   扫描配置（网段 / 黑名单 / 策略 / 速率模板）持久化
  asset_device_meta   设备用户字段（标签 / 备注 / 静态 mDNS 关联）持久化
  asset_snapshot      快照头（名称 / 备注 / 时间 / 设备数）
  asset_snapshot_item 快照内资产明细

所有写操作用单连接 + RLock 串行化，WAL 模式保证读不阻塞写。快照 diff 在
Python 内完成（数据量小、逻辑清晰），CSV 用标准库 csv 导出。
"""

from __future__ import annotations

import csv
import io
import json
import os
import sqlite3
import threading
import time
from typing import Any, Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS asset_scan_config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS asset_device_meta (
    ip                TEXT PRIMARY KEY,
    tags              TEXT NOT NULL DEFAULT '[]',
    remark            TEXT NOT NULL DEFAULT '',
    linked_mdns_record TEXT,
    updated_at        REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS asset_snapshot (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    note         TEXT NOT NULL DEFAULT '',
    created_at   REAL NOT NULL,
    device_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS asset_snapshot_item (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id  INTEGER NOT NULL,
    ip           TEXT NOT NULL,
    mac          TEXT NOT NULL DEFAULT '',
    vendor       TEXT NOT NULL DEFAULT 'Unknown',
    online       INTEGER NOT NULL DEFAULT 0,
    sources      TEXT NOT NULL DEFAULT '[]',
    ports        TEXT NOT NULL DEFAULT '[]',
    services     TEXT NOT NULL DEFAULT '[]',
    tags         TEXT NOT NULL DEFAULT '[]',
    remark       TEXT NOT NULL DEFAULT '',
    last_seen    REAL NOT NULL DEFAULT 0,
    FOREIGN KEY(snapshot_id) REFERENCES asset_snapshot(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_snap_item_snap ON asset_snapshot_item(snapshot_id);
CREATE INDEX IF NOT EXISTS idx_snap_item_ip ON asset_snapshot_item(ip);
"""


def _dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def _loads(value: str | None, fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return fallback


class AssetDatabase:
    """线程安全的单文件 SQLite 存储。"""

    def __init__(self, path: str = "") -> None:
        default = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "logs", "assets.sqlite3")
        self.path = os.path.abspath(path or default)
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------
    # 扫描配置持久化
    # ------------------------------------------------------------------
    def save_scan_config(self, data: dict[str, Any]) -> None:
        with self._lock:
            for key, value in data.items():
                self._conn.execute(
                    "INSERT INTO asset_scan_config(key,value) VALUES(?,?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (str(key), _dumps(value)))
            self._conn.commit()

    def load_scan_config(self) -> dict[str, Any]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT key,value FROM asset_scan_config").fetchall()
        return {row["key"]: _loads(row["value"], None) for row in rows}

    # ------------------------------------------------------------------
    # 设备元数据（标签 / 备注 / 静态 mDNS 关联）
    # ------------------------------------------------------------------
    def upsert_device_meta(self, ip: str, *, tags: list[str] | None = None,
                           remark: str | None = None,
                           linked_mdns_record: str | None = None) -> None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM asset_device_meta WHERE ip=?", (ip,)).fetchone()
            current = {
                "tags": _loads(row["tags"], []) if row else [],
                "remark": row["remark"] if row else "",
                "linked_mdns_record": row["linked_mdns_record"] if row else None,
            }
            if tags is not None:
                current["tags"] = list(tags)
            if remark is not None:
                current["remark"] = str(remark)
            if linked_mdns_record is not None:
                current["linked_mdns_record"] = linked_mdns_record or None
            self._conn.execute(
                "INSERT INTO asset_device_meta(ip,tags,remark,linked_mdns_record,updated_at) "
                "VALUES(?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET "
                "tags=excluded.tags, remark=excluded.remark, "
                "linked_mdns_record=excluded.linked_mdns_record, updated_at=excluded.updated_at",
                (ip, _dumps(current["tags"]), current["remark"],
                 current["linked_mdns_record"], time.time()))
            self._conn.commit()

    def device_meta(self, ip: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM asset_device_meta WHERE ip=?", (ip,)).fetchone()
        if row is None:
            return None
        return {
            "ip": row["ip"],
            "tags": _loads(row["tags"], []),
            "remark": row["remark"],
            "linked_mdns_record": row["linked_mdns_record"],
            "updated_at": row["updated_at"],
        }

    def all_device_meta(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM asset_device_meta").fetchall()
        return {row["ip"]: {
            "tags": _loads(row["tags"], []),
            "remark": row["remark"],
            "linked_mdns_record": row["linked_mdns_record"],
        } for row in rows}

    # ------------------------------------------------------------------
    # 快照：保存 / 列表 / 读取 / 删除
    # ------------------------------------------------------------------
    def save_snapshot(self, name: str, note: str,
                      devices: Iterable[dict[str, Any]]) -> dict[str, Any]:
        items = list(devices or [])
        created = time.time()
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO asset_snapshot(name,note,created_at,device_count) "
                "VALUES(?,?,?,?)", (str(name or "")[:80], str(note or "")[:500],
                                    created, len(items)))
            sid = int(cur.lastrowid)
            for d in items:
                self._conn.execute(
                    "INSERT INTO asset_snapshot_item(snapshot_id,ip,mac,vendor,online,"
                    "sources,ports,services,tags,remark,last_seen) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (sid, str(d.get("ip", "")), str(d.get("mac", "")),
                     str(d.get("vendor", "Unknown")), 1 if d.get("online") else 0,
                     _dumps(d.get("sources", [])), _dumps(d.get("detected_ports", [])),
                     _dumps(d.get("services", [])), _dumps(d.get("tags", [])),
                     str(d.get("remark", "")), float(d.get("last_seen") or 0)))
            self._conn.commit()
        return {"id": sid, "name": str(name or ""), "note": str(note or ""),
                "created_at": created, "device_count": len(items)}

    def list_snapshots(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM asset_snapshot ORDER BY created_at DESC").fetchall()
        return [dict(row) for row in rows]

    def get_snapshot(self, sid: int) -> dict[str, Any] | None:
        with self._lock:
            head = self._conn.execute(
                "SELECT * FROM asset_snapshot WHERE id=?", (sid,)).fetchone()
            if head is None:
                return None
            rows = self._conn.execute(
                "SELECT * FROM asset_snapshot_item WHERE snapshot_id=? ORDER BY ip",
                (sid,)).fetchall()
        result = dict(head)
        result["items"] = [_item_dict(row) for row in rows]
        return result

    def delete_snapshot(self, sid: int) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM asset_snapshot WHERE id=?", (sid,))
            self._conn.execute("DELETE FROM asset_snapshot_item WHERE snapshot_id=?", (sid,))
            self._conn.commit()
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # 快照对比 / CSV 导出
    # ------------------------------------------------------------------
    def diff_snapshots(self, base_id: int, other_id: int) -> dict[str, Any]:
        """从 base 到 other 的差异：新增 / 消失 / 信息变更。"""
        base = self.get_snapshot(base_id)
        other = self.get_snapshot(other_id)
        if base is None or other is None:
            raise FileNotFoundError("快照不存在")
        bmap = {d["ip"]: d for d in base["items"]}
        omap = {d["ip"]: d for d in other["items"]}
        added = [omap[ip] for ip in omap if ip not in bmap]
        removed = [bmap[ip] for ip in bmap if ip not in omap]
        changed: list[dict[str, Any]] = []
        for ip in bmap:
            if ip not in omap:
                continue
            diffs: list[str] = []
            b, o = bmap[ip], omap[ip]
            if b.get("mac") != o.get("mac"):
                diffs.append("MAC 变更")
            if b.get("vendor") != o.get("vendor"):
                diffs.append("厂商变更")
            if _fingerprint(b.get("ports")) != _fingerprint(o.get("ports")):
                diffs.append("端口变化")
            if bool(b.get("online")) != bool(o.get("online")):
                diffs.append("在线状态变化")
            if b.get("tags") != o.get("tags"):
                diffs.append("标签变化")
            if b.get("remark") != o.get("remark"):
                diffs.append("备注变化")
            if diffs:
                changed.append({"ip": ip, "changes": diffs,
                                "before": b, "after": o})
        added.sort(key=lambda d: d["ip"])
        removed.sort(key=lambda d: d["ip"])
        changed.sort(key=lambda d: d["ip"])
        return {
            "base": {"id": base_id, "name": base["name"], "created_at": base["created_at"]},
            "other": {"id": other_id, "name": other["name"], "created_at": other["created_at"]},
            "added": added, "removed": removed, "changed": changed,
            "summary": {"added": len(added), "removed": len(removed),
                        "changed": len(changed)},
        }

    def export_csv(self, sid: int) -> str:
        """导出快照为 CSV：IP、MAC、厂商、端口、来源、备注（PRD 3.6）。"""
        snap = self.get_snapshot(sid)
        if snap is None:
            raise FileNotFoundError("快照不存在")
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["IP", "MAC", "厂商", "端口", "来源", "在线", "备注"])
        for d in snap["items"]:
            ports = ",".join(
                f"{p['port']}/{p.get('proto', 'tcp')}"
                for p in d.get("ports", []) if p.get("open"))
            writer.writerow([
                d["ip"], d.get("mac", ""), d.get("vendor", "Unknown"), ports,
                "|".join(d.get("sources", [])), "是" if d.get("online") else "否",
                d.get("remark", ""),
            ])
        return buf.getvalue()


def _fingerprint(ports: Any) -> list[tuple[int, str, bool]]:
    return sorted((int(p.get("port", 0)), str(p.get("proto", "tcp")),
                   bool(p.get("open")))
                  for p in (ports or []) if isinstance(p, dict))


def _item_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "ip": row["ip"],
        "mac": row["mac"],
        "vendor": row["vendor"],
        "online": bool(row["online"]),
        "sources": _loads(row["sources"], []),
        "ports": _loads(row["ports"], []),
        "detected_ports": _loads(row["ports"], []),
        "services": _loads(row["services"], []),
        "tags": _loads(row["tags"], []),
        "remark": row["remark"],
        "last_seen": row["last_seen"],
    }
