"""离线精简 OUI 厂商库（零依赖，可单独更新）。

设计取舍（对应 PRD 3.10 / 非功能需求 4）：
  * 只内置常见前缀（含工控 / 网络设备厂商），不全量加载百万级 OUI，内存占用可控；
  * 匹配不到返回 "Unknown"，绝不联网查询；
  * 支持通过外部 JSON 文件叠加自定义条目（键为 6 位大写十六进制前缀）。
"""

from __future__ import annotations

import json
import os
import re
from typing import Any

# 常见 OUI 前缀 -> 厂商名。仅收录高频 / 工控 / 网络设备相关条目。
_BUILTIN: dict[str, str] = {
    "000C29": "VMware",
    "00155D": "Microsoft",
    "001B21": "Intel",
    "0026B9": "Microsoft",
    "005056": "VMware",
    "080027": "VirtualBox",
    "0C29C8": "Microsoft",
    "18FE34": "Espressif",
    "24A160": "Huawei",
    "286EF1": "Cisco",
    "3C6EF5": "Dell",
    "3C52FF": "Apple",
    "485D60": "Huawei",
    "525400": "QEMU",
    "6C2B59": "ZTE",
    "782C8D": "Samsung",
    "84A4F4": "Apple",
    "8C1F64": "Huawei",
    "A4C138": "Tuya",
    "B827EB": "Raspberry Pi",
    "B8AC6F": "Cisco",
    "C81F66": "Huawei",
    "D48C9A": "Cisco",
    "D8CB8A": "Dell",
    "E4F0F7": "Ubiquiti",
    "EC17E8": "Huawei",
    "F0B479": "Cisco",
    "FC3DC1": "Huawei",
    "000D3A": "Microsoft Azure",
    "0017E0": "Huawei",
    "0022FD": "Zebra Technologies",
    "003067": "Cisco",
    "00A0C9": "Intel",
    "00C09F": "Dell",
    "00D861": "HP",
    "00E06F": "Siemens",
    "00E0EC": "Bosch",
    "00A045": "Schneider Electric",
    "000BAB": "Cisco Linksys",
    "001122": "Bosch",
    "001EC9": "Siemens",
    "0024E8": "ABB",
    "002655": "Siemens",
    "0050C2": "MikroTik",
    "00A059": "MikroTik",
    "00E0A6": "3Com",
    "0CC47A": "Dell",
    "18A905": "Siemens",
    "20F8D7": "Huawei",
    "28C7CE": "TP-Link",
    "30F421": "MikroTik",
    "4C77D2": "Ubiquiti",
    "54A050": "ASUS",
    "64D9ED": "Siemens",
    "74C63D": "TP-Link",
    "80D3F0": "Synology",
    "90A2D2": "Schneider Electric",
    "A088B4": "Raspberry Pi",
    "AC22F3": "Huawei",
    "B4FB84": "Siemens",
    "C029F8": "Synology",
    "C4E9F2": "Ubiquiti",
    "D017C2": "Siemens",
    "DCDA60": "TP-Link",
    "E0D5BE": "Siemens",
    "ECFA7B": "Huawei",
    "F0D1F2": "MikroTik",
    "F4F26D": "Apple",
    "F8D1F1": "TP-Link",
    "FCFBBC": "Lamco / ABB",
    "001D7D": "Siemens",
    "000488": "Hirschmann",
    "000BB6": "Phoenix Contact",
    "001379": "WAGO",
    "0022F7": "Beckhoff",
    "00E02D": "Modicon / Schneider",
    "080020": "OMRON",
    "0875F5": "SICK",
    "3CD92B": "Rockwell Automation",
    "6CB8CB": "B&R Automation",
    "A4D5F2": "Bosch Rexroth",
    "D8D38C": "Panasonic",
    "E8DF50": "Keyence",
    "000FE8": "Juniper",
    "001AA9": "Arista",
    "001B0C": "Cisco",
    "00A0DE": "Extreme Networks",
    "C4EAE9": "Fortinet",
    "002099": "Check Point",
    "000F20": "Netgear",
    "0846AB": "Netgear",
    "204E7E": "Netgear",
    "20E52F": "Synology",
    "5054AA": "Synology",
    "001EC0": "Seagate",
    "001B44": "Western Digital",
    "001EE9": "Canon",
    "002716": "Epson",
    "3C7A0B": "HP",
    "3CD9D0": "Lexmark",
    "000102": "Xerox",
    "00E025": "Zebra",
    "0026C1": "Zebra",
    "64488B": "Intel",
    "A0D3C1": "Intel",
    "3CE1A1": "Intel",
    "8C16A5": "Realtek",
    "00E070": "Realtek",
    "52FD4F": "Realtek",
    "D85D62": "MediaTek",
    "C88508": "MediaTek",
    "A4CF12": "Samsung",
    "F8A026": "LG",
    "001CBF": "Sony",
    "1078D2": "Nintendo",
    "40B4CD": "Samsung",
    "7CD55D": "Amazon",
    "F0D2F1": "Amazon",
    "0A1A2B": "Locally Administered",
}


class OUILookup:
    """线程安全的只读 OUI 查询器；外部叠加文件可选。"""

    def __init__(self, extra_path: str = "") -> None:
        self._table: dict[str, str] = dict(_BUILTIN)
        self.path = str(extra_path or "").strip()
        if self.path and os.path.isfile(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                if isinstance(data, dict):
                    for key, value in data.items():
                        prefix = _normalize_prefix(str(key))
                        if prefix and isinstance(value, str):
                            self._table[prefix] = value.strip() or "Unknown"
            except (OSError, ValueError):
                pass  # 外部库损坏时静默忽略，内置库仍可用

    @property
    def size(self) -> int:
        return len(self._table)

    def lookup(self, mac: str) -> str:
        prefix = _normalize_prefix(mac)
        if not prefix:
            return "Unknown"
        return self._table.get(prefix, "Unknown")


def _normalize_prefix(value: str) -> str:
    digits = re.sub(r"[^0-9A-Fa-f]", "", str(value or ""))[:6].upper()
    return digits if len(digits) == 6 else ""


def lookup_vendor(mac: str, table: dict[str, str] | None = None) -> str:
    """便捷函数：给定 MAC 返回厂商名。"""
    source = table if table is not None else _BUILTIN
    prefix = _normalize_prefix(mac)
    if not prefix:
        return "Unknown"
    return source.get(prefix, "Unknown")


# 模块级默认实例：全球共享只读，避免重复加载
DEFAULT_LOOKUP = OUILookup()
