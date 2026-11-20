#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mdns_tls.py - HTTPS 与自签 CA 证书管理（零第三方 pip 依赖）

设计要点
--------
* 运行期 TLS 由 Python 标准库 ``ssl`` 提供（服务端 socket 包装、证书链加载、
  协议版本控制、可选双向认证）。不引入 cryptography / pyOpenSSL。
* 证书**签发**需要 X.509 工具，调用系统 ``openssl`` CLI（Linux/macOS/容器基础镜像
  普遍自带）。openssl 不可用时给出明确错误，不影响 mDNS 主服务。
* 默认关闭：``[tls] enabled = false``，现有 HTTP 部署行为完全不变。
* 证书文件权限 0600（私钥）；CA 证书公开可下载，供客户端信任 / 指纹固定。
* 自签 CA 与服务器证书分开：CA 只负责签发，服务器证书带 SAN（域名 + IP），
  避免浏览器 "net::ERR_CERT_COMMON_NAME_INVALID"。
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import ssl
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone

LOG = logging.getLogger("mdns.tls")

VERSIONS = {
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}
DEFAULT_CA_DAYS = 730
DEFAULT_CERT_DAYS = 365
DEFAULT_CA_CN = "mDNS Studio Local CA"
DEFAULT_CERT_CN = "mDNS Studio"


@dataclass
class TLSConfig:
    enabled: bool = False
    cert_file: str = "certs/server.crt"
    key_file: str = "certs/server.key"
    ca_file: str = "certs/ca.crt"
    ca_key_file: str = "certs/ca.key"
    min_version: str = "TLSv1.2"
    client_auth: str = "none"           # none | optional | require
    redirect_http: bool = False         # 预留：HTTP -> HTTPS 跳转（网关层实现）
    publish_service: bool = True        # 发布 _https._tcp.local（TXT 带 CA 指纹）
    service_instance: str = DEFAULT_CERT_CN
    service_host: str = ""              # 空 = 复用 gateway_admin_host
    ca_days: int = DEFAULT_CA_DAYS
    cert_days: int = DEFAULT_CERT_DAYS

    def validate(self) -> None:
        if self.min_version not in VERSIONS:
            raise ValueError(f"tls.min_version 必须是 TLSv1.2 或 TLSv1.3，实际为 {self.min_version!r}")
        if self.client_auth not in ("none", "optional", "require"):
            raise ValueError("tls.client_auth 必须是 none / optional / require")
        for name in ("cert_file", "key_file", "ca_file", "ca_key_file",
                     "service_instance", "service_host"):
            if not isinstance(getattr(self, name), str):
                raise ValueError(f"tls.{name} 必须是字符串")
        if self.ca_days < 1 or self.cert_days < 1:
            raise ValueError("tls.ca_days / tls.cert_days 必须 > 0")
        if self.cert_days > self.ca_days:
            raise ValueError("tls.cert_days 不能大于 tls.ca_days（服务器证书不得超出 CA 有效期）")


def openssl_available() -> bool:
    return shutil.which("openssl") is not None


def resolve_path(path: str, base_dir: str) -> str:
    """相对路径按配置文件目录解析，绝对路径原样返回。"""
    if not path:
        return ""
    return path if os.path.isabs(path) else os.path.normpath(os.path.join(base_dir, path))


def _run(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if check and proc.returncode != 0:
        raise RuntimeError(f"openssl 执行失败（{args[1] if len(args) > 1 else 'openssl'}）: "
                           f"{(proc.stderr or proc.stdout).strip()[:500]}")
    return proc


def _ensure_parent(path: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)


def generate_ca(cert_path: str, key_path: str, *, cn: str = DEFAULT_CA_CN,
                days: int = DEFAULT_CA_DAYS) -> dict:
    """生成自签 CA 证书与私钥。返回证书信息。"""
    if not openssl_available():
        raise RuntimeError("未找到 openssl，无法签发证书；请安装 openssl 或导入已有 PEM 证书")
    _ensure_parent(cert_path)
    _ensure_parent(key_path)
    common_name = cn.strip() or DEFAULT_CA_CN
    _run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256",
        "-nodes", "-days", str(int(days)),
        "-keyout", key_path, "-out", cert_path,
        "-subj", f"/C=CN/O=mDNS Studio/CN={common_name}",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        "-addext", "subjectKeyIdentifier=hash",
    ])
    os.chmod(key_path, 0o600)
    os.chmod(cert_path, 0o644)
    LOG.info("已生成自签 CA: %s (CN=%s, %d 天)", cert_path, common_name, days)
    return cert_info(cert_path)


def generate_server_cert(cert_path: str, key_path: str,
                         ca_cert_path: str, ca_key_path: str,
                         *, common_name: str = DEFAULT_CERT_CN,
                         names: list[str] | None = None,
                         days: int = DEFAULT_CERT_DAYS) -> dict:
    """由 CA 签发服务器证书（含 SAN），供 HTTPS 管理台使用。"""
    if not openssl_available():
        raise RuntimeError("未找到 openssl，无法签发证书")
    for p in (ca_cert_path, ca_key_path):
        if not os.path.isfile(p):
            raise FileNotFoundError(f"CA 文件不存在: {p}")
    _ensure_parent(cert_path)
    _ensure_parent(key_path)

    san_entries: list[str] = []
    for raw in names or []:
        item = str(raw).strip()
        if not item:
            continue
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", item):
            san_entries.append(f"IP:{item}")
        elif ":" in item:                       # IPv6
            san_entries.append(f"IP:{item}")
        else:
            san_entries.append(f"DNS:{item}")
    if not any(x.startswith("DNS:localhost") for x in san_entries):
        san_entries.insert(0, "DNS:localhost")
    if not any(x == "IP:127.0.0.1" for x in san_entries):
        san_entries.insert(1, "IP:127.0.0.1")
    cn = (common_name or DEFAULT_CERT_CN).strip()

    with tempfile.NamedTemporaryFile("w", suffix=".ext", delete=False, encoding="utf-8") as fh:
        ext_path = fh.name
        fh.write("basicConstraints=critical,CA:FALSE\n")
        fh.write("extendedKeyUsage=serverAuth\n")
        fh.write("keyUsage=critical,digitalSignature,keyEncipherment\n")
        fh.write("subjectAltName=" + ",".join(san_entries) + "\n")
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".cnf", delete=False, encoding="utf-8") as fh:
            req_cfg = fh.name
            fh.write("[req]\ndistinguished_name=dn\nprompt=no\n[dn]\n")
            fh.write(f"CN={cn}\n")
        try:
            _run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-sha256",
                  "-nodes", "-keyout", key_path, "-out",
                  ext_path + ".csr", "-config", req_cfg])
            _run(["openssl", "x509", "-req", "-in", ext_path + ".csr",
                  "-CA", ca_cert_path, "-CAkey", ca_key_path, "-CAcreateserial",
                  "-out", cert_path, "-days", str(int(days)), "-sha256",
                  "-extfile", ext_path])
        finally:
            _safe_unlink(req_cfg)
    finally:
        _safe_unlink(ext_path)
        _safe_unlink(ext_path + ".csr")
        _safe_unlink(ca_cert_path + ".srl")

    os.chmod(key_path, 0o600)
    os.chmod(cert_path, 0o644)
    LOG.info("已签发服务器证书: %s (CN=%s, SAN=%s)", cert_path, cn, ",".join(san_entries))
    return cert_info(cert_path)


def _safe_unlink(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def cert_fingerprint(path: str) -> str:
    """返回证书 SHA-256 指纹（小写 hex，无冒号）；标准库无证书解析，借 openssl。"""
    if not os.path.isfile(path):
        return ""
    if not openssl_available():
        return ""
    proc = _run(["openssl", "x509", "-in", path, "-noout", "-fingerprint", "-sha256"],
                check=False)
    if proc.returncode != 0:
        return ""
    m = re.search(r"=([0-9A-Fa-f:]+)", proc.stdout)
    return m.group(1).replace(":", "").lower() if m else ""


def cert_info(path: str) -> dict:
    """读取证书摘要信息；文件缺失或 openssl 不可用时返回可用=false。"""
    result: dict = {"path": path, "available": False, "fingerprint": ""}
    if not path or not os.path.isfile(path):
        return result
    if not openssl_available():
        result["error"] = "openssl 不可用，无法读取证书信息"
        return result
    proc = _run([
        "openssl", "x509", "-in", path, "-noout",
        "-subject", "-issuer", "-dates", "-fingerprint", "-sha256",
        "-ext", "subjectAltName",
    ], check=False)
    if proc.returncode != 0:
        result["error"] = (proc.stderr or proc.stdout).strip()[:300]
        return result
    text = proc.stdout
    result["available"] = True
    result["subject"] = _pem_field(text, "subject=")
    result["issuer"] = _pem_field(text, "issuer=")
    result["not_before"] = _pem_field(text, "notBefore=")
    result["not_after"] = _pem_field(text, "notAfter=")
    result["fingerprint"] = cert_fingerprint(path)
    san = ""
    m = re.search(r"Subject Alternative Name:\s*\n\s*([^\n]+)", text)
    if m:
        san = m.group(1).strip()
    result["san"] = san
    result["expired"] = _is_expired(result["not_after"])
    return result


def _pem_field(text: str, prefix: str) -> str:
    for line in text.splitlines():
        if line.startswith(prefix):
            return line[len(prefix):].strip()
    return ""


def _is_expired(not_after: str) -> bool:
    if not not_after:
        return False
    try:
        dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        return dt.replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc)
    except ValueError:
        return False


def make_ssl_context(cfg: TLSConfig, base_dir: str,
                     *, client_auth_override: str | None = None) -> ssl.SSLContext:
    """按配置构造 TLS 服务端上下文。证书缺失 / 格式错误时抛异常，由调用方降级。"""
    cert = resolve_path(cfg.cert_file, base_dir)
    key = resolve_path(cfg.key_file, base_dir)
    if not cert or not key or not os.path.isfile(cert) or not os.path.isfile(key):
        raise FileNotFoundError(f"TLS 证书或私钥不存在: {cert} / {key}")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = VERSIONS.get(cfg.min_version, ssl.TLSVersion.TLSv1_2)
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    mode = client_auth_override or cfg.client_auth
    if mode in ("optional", "require"):
        ca = resolve_path(cfg.ca_file, base_dir)
        if not ca or not os.path.isfile(ca):
            raise FileNotFoundError(f"双向认证需要 CA 证书: {ca}")
        ctx.load_verify_locations(cafile=ca)
        ctx.verify_mode = (ssl.CERT_OPTIONAL if mode == "optional"
                           else ssl.CERT_REQUIRED)
    return ctx


def tls_status(cfg: TLSConfig, base_dir: str) -> dict:
    """供 GET /api/tls/status 使用；不暴露私钥内容。"""
    ca = resolve_path(cfg.ca_file, base_dir)
    cert = resolve_path(cfg.cert_file, base_dir)
    key = resolve_path(cfg.key_file, base_dir)
    ca_key = resolve_path(cfg.ca_key_file, base_dir)
    return {
        "enabled": cfg.enabled,
        "openssl": openssl_available(),
        "configured": {
            "cert_file": cfg.cert_file, "key_file": cfg.key_file,
            "ca_file": cfg.ca_file, "min_version": cfg.min_version,
            "client_auth": cfg.client_auth,
            "publish_service": cfg.publish_service,
        },
        "files": {
            "cert": os.path.isfile(cert), "key": os.path.isfile(key),
            "ca": os.path.isfile(ca), "ca_key": os.path.isfile(ca_key),
        },
        "certificate": cert_info(cert),
        "ca": cert_info(ca),
        "ready": cfg.enabled and os.path.isfile(cert) and os.path.isfile(key),
    }
