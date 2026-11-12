#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mdns_security.py - 管理员密码（零第三方依赖）

设计要点
--------
* 只存「加盐 PBKDF2-HMAC-SHA256」摘要，绝不存明文；校验用 hmac.compare_digest 常量时间比较。
* 状态文件 auth.toml 默认位于项目根，**必须加入 .gitignore**；可用环境变量
  ``MDNS_AUTH_FILE`` 覆盖路径（Docker / 自测 / 多实例场景）。
* 首次未设置密码时，任何写操作都被服务端拒绝（setup_required），
  控制台会引导「首次设置管理员密码」；设置后修改配置 / 回滚 / 改密都要校验。
* 文件权限 0600，原子替换写入，避免半截文件。

auth.toml 是标准 TOML，可用 tomllib 直接读；内容形如：

    version = 1
    algorithm = "pbkdf2_sha256"
    iterations = 200000
    salt = "<hex>"
    hash = "<hex>"
    updated_at = "2026-11-12T15:30:00+00:00"
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
import tomllib

AUTH_ENV = "MDNS_AUTH_FILE"
AUTH_FILENAME = "auth.toml"
ALGORITHM = "pbkdf2_sha256"
ITERATIONS = 200_000
MIN_LENGTH = 8
MAX_LENGTH = 256

LOG = __import__("logging").getLogger("mdns.security")


def project_root() -> str:
    """项目根目录（本文件位于 <root>/src/）。"""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def default_auth_path() -> str:
    return os.environ.get(AUTH_ENV) or os.path.join(project_root(), AUTH_FILENAME)


def validate_password(password: object) -> str:
    """校验新密码强度；不满足抛 ValueError。"""
    if not isinstance(password, str):
        raise ValueError("管理员密码必须是字符串")
    if len(password) < MIN_LENGTH:
        raise ValueError(f"管理员密码至少 {MIN_LENGTH} 位")
    if len(password) > MAX_LENGTH:
        raise ValueError(f"管理员密码最多 {MAX_LENGTH} 位")
    return password


def _toml_str(value: str) -> str:
    return json.dumps(str(value), ensure_ascii=False)


class AuthManager:
    """管理员密码状态机。线程安全；路径可由环境变量覆盖以便测试。"""

    def __init__(self, path: str | None = None):
        self.path = os.path.abspath(path or default_auth_path())
        self._lock = threading.Lock()
        self._state: dict | None = None
        self._load()

    # -- 持久化 ---------------------------------------------------------
    def _load(self) -> None:
        try:
            with open(self.path, "rb") as fh:
                raw = tomllib.load(fh)
        except (OSError, tomllib.TOMLDecodeError, ValueError):
            self._state = None
            return
        required = ("algorithm", "iterations", "salt", "hash")
        if not isinstance(raw, dict) or any(k not in raw for k in required):
            self._state = None
            return
        if raw.get("algorithm") != ALGORITHM:
            LOG.warning("auth.toml 算法不受支持（%r），忽略", raw.get("algorithm"))
            self._state = None
            return
        try:
            bytes.fromhex(str(raw["salt"]))
            int(raw["iterations"])
        except (ValueError, TypeError):
            self._state = None
            return
        self._state = raw

    def _write(self, state: dict) -> None:
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        lines = [
            "# 由 mDNS Studio 自动生成，请勿手工编辑；明文密码不会落盘。",
            "# 此文件已在 .gitignore 中排除，不要提交到版本库。",
            "version = 1",
            f"algorithm = {_toml_str(ALGORITHM)}",
            f"iterations = {ITERATIONS}",
            f"salt = {_toml_str(state['salt'])}",
            f"hash = {_toml_str(state['hash'])}",
            f"updated_at = {_toml_str(state['updated_at'])}",
            "",
        ]
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:  # 某些文件系统不支持 chmod，不阻断功能
            pass

    # -- 查询 -----------------------------------------------------------
    @property
    def enabled(self) -> bool:
        return self._state is not None

    def state(self) -> dict:
        st = self._state or {}
        return {
            "enabled": self.enabled,
            "algorithm": ALGORITHM if self.enabled else "",
            "iterations": ITERATIONS if self.enabled else 0,
            "updated_at": st.get("updated_at", ""),
            "path": self.path,
        }

    def verify(self, password: object) -> bool:
        """常量时间校验；未启用 / 非字符串一律 False。"""
        st = self._state
        if st is None or not isinstance(password, str) or not password:
            return False
        try:
            calc = hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"),
                bytes.fromhex(str(st["salt"])), int(st["iterations"]))
        except (ValueError, TypeError, KeyError):
            return False
        return hmac.compare_digest(calc.hex(), str(st["hash"]))

    # -- 写入 -----------------------------------------------------------
    def set_password(self, new_password: object,
                     old_password: object | None = None) -> dict:
        """设置 / 修改管理员密码。

        已启用时必须提供正确的 old_password；未启用时为「首次设置」，old 可空。
        """
        with self._lock:
            if self._state is not None and not self.verify(old_password):
                raise PermissionError("原管理员密码不正确")
            password = validate_password(new_password)
            salt = os.urandom(16)
            digest = hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"), salt, ITERATIONS)
            state = {
                "salt": salt.hex(),
                "hash": digest.hex(),
                "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            self._write(state)
            self._state = {
                "algorithm": ALGORITHM, "iterations": ITERATIONS, **state,
            }
            LOG.info("管理员密码已%s", "修改" if old_password else "初始化")
            return self.state()

    def reset(self) -> None:
        """仅供测试：删除状态文件并清空内存态。"""
        with self._lock:
            self._state = None
            try:
                os.unlink(self.path)
            except OSError:
                pass
