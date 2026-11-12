#!/usr/bin/env bash
# =============================================================================
# mDNS Responder 一键安装脚本（零第三方依赖，仅需 Python >= 3.11）
#
# 用法（远程，需能访问 GitHub）：
#   curl -fsSL https://raw.githubusercontent.com/scpuny/mdns-responder/main/install.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/scpuny/mdns-responder/main/install.sh | bash -s -- <选项...>
#
# 用法（本地源码目录，离线 / 不可访问 GitHub）：
#   ./install.sh                 安装当前目录
#   ./install.sh -d ./build      安装到指定前缀
#   ./install.sh --systemd      额外生成并安装 systemd 单元（需 root）
#
# 选项：
#   -d, --prefix DIR   安装目录，默认 /opt/mdns-responder；无写权限时回退 $HOME/.local/share/mdns-responder
#   -s, --systemd     生成并（root 时）安装 systemd 服务，开机自启
#   -u, --user USER   创建 systemd 运行用户，默认 mdns
#   -p, --port PORT   覆盖组播端口写入 config.toml（默认 5353）
#   -m, --mgmt-port N 覆盖管理台端口（默认 8765）
#   -h, --help        显示帮助
#
# 环境变量：
#   MDNS_INSTALL_PREFIX   同 -d
#   MDNS_GITHUB_REPO      远程源码 tarball 基址，默认
#                         https://github.com/scpuny/mdns-responder
#   MDNS_REF              远程分支 / tag，默认 main
#   MDNS_DOWNLOAD_TOOL    auto|curl|wget，默认 auto（有 curl 用 curl）
#
# 行为说明：
#   - 非 root 安装到 $HOME 下前缀，不碰 /opt 与 /etc；systemd 步骤仅在 root 时执行。
#   - 已存在 config.toml 绝不覆盖（保留用户已保存的在线配置），只补缺失。
#   - 安装完成打印：管理台地址、启动命令、systemd 命令（若启用）。
# =============================================================================
set -euo pipefail

# ------------------------------------------------------------------ 默认值 --
PREFIX="${MDNS_INSTALL_PREFIX:-/opt/mdns-responder}"
INSTALL_SYSTEMD=0
RUN_USER="mdns"
OVERRIDE_PORT=""
OVERRIDE_MGMT_PORT=""
# 若从 GitHub raw 管道执行，则默认下载远程源码；若已是本地 clone（含 src/），则本地安装
LOCAL_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() { sed -n '2,40p' "$0"; }

while [ $# -gt 0 ]; do
  case "$1" in
    -d|--prefix)      PREFIX="$2"; shift 2 ;;
    -s|--systemd)     INSTALL_SYSTEMD=1; shift ;;
    -u|--user)        RUN_USER="$2"; shift 2 ;;
    -p|--port)        OVERRIDE_PORT="$2"; shift 2 ;;
    -m|--mgmt-port)   OVERRIDE_MGMT_PORT="$2"; shift 2 ;;
    -h|--help)        usage; exit 0 ;;
    --) shift; break ;;
    *) echo "[install] 未知参数: $1" >&2; usage; exit 2 ;;
  esac
done

# 无写权限时回退到用户前缀
if [ ! -w "$(dirname "$PREFIX")" ] && [ "$(id -u)" != "0" ]; then
  echo "[install] $PREFIX 无写权限，回退到 \$HOME/.local/share/mdns-responder"
  PREFIX="$HOME/.local/share/mdns-responder"
fi

log(){ echo "[install] $*"; }
die(){ echo "[install] 错误: $*" >&2; exit 1; }

# ------------------------------------------------------- Python 版本检查 ----
PY="$(command -v python3 || true)"
[ -n "$PY" ] || die "未找到 python3；请先安装 Python >= 3.11"
if ! "$PY" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)'; then
  echo "[install] 警告: 当前 Python $($PY -V 2>&1) < 3.11，本服务需要 tomllib（3.11+）。仍继续，运行可能失败。"
fi

# ------------------------------------------------------- 获取源码目录 ------
SRC=""
if [ -f "$LOCAL_SRC/src/mdns_responder.py" ]; then
  SRC="$LOCAL_SRC"
  log "使用本地源码: $SRC"
else
  # 远程下载
  REPO="${MDNS_GITHUB_REPO:-https://github.com/scpuny/mdns-responder}"
  REF="${MDNS_REF:-main}"
  URL="$REPO/archive/refs/$REF.tar.gz"
  case "$REF" in main|master) URL="$REPO/archive/refs/$REF.tar.gz" ;;
                *) URL="$REPO/archive/refs/tags/$REF.tar.gz" ;; esac
  log "下载源码: $URL"
  DLTMP="$(mktemp -d)"
  trap 'rm -rf "$DLTMP"' EXIT
  if [ "${MDNS_DOWNLOAD_TOOL:-auto}" != "wget" ] && command -v curl >/dev/null 2>&1; then
    curl -fsSL "$URL" -o "$DLTMP/src.tgz" || die "下载失败：$URL（检查网络 / 仓库是否存在）"
  else
    wget -qO "$DLTMP/src.tgz" "$URL" || die "下载失败：$URL（检查网络 / 仓库是否存在）"
  fi
  tar -xzf "$DLTMP/src.tgz" -C "$DLTMP"
  SRC="$(find "$DLTMP" -maxdepth 1 -mindepth 1 -type d -print -quit)"
  [ -n "$SRC" ] && [ -f "$SRC/src/mdns_responder.py" ] || die "下载的源码缺少 src/mdns_responder.py"
fi

# ------------------------------------------------------- 安装到前缀 --------
# 只拷贝「精选文件集」，绝不带入 __pycache__ / logs 运行态 / 用户 config.toml / *.bak。
# 用 Python 内容级复制（不保留时间戳/属主），规避受限环境 cp -a 的 timestamp 权限问题。
KEEP_DIRS="src web tests deploy"
KEEP_FILES="start.sh install.sh config.example.toml README.md .gitignore"
mkdir -p "$PREFIX"
log "安装到: $PREFIX"
[ -f "$PREFIX/config.toml" ] && log "检测到已有 $PREFIX/config.toml，保留不覆盖" || true
rm -rf "$PREFIX/src" "$PREFIX/web" "$PREFIX/tests" "$PREFIX/deploy" "$PREFIX/start.sh" \
       "$PREFIX/install.sh" "$PREFIX/config.example.toml" "$PREFIX/README.md" "$PREFIX/.gitignore"
"$PY" - "$SRC" "$PREFIX" "$KEEP_DIRS" "$KEEP_FILES" <<'PYCOPY'
import os, sys, shutil
src, dst = sys.argv[1], sys.argv[2]
keep_dirs = sys.argv[3].split()
keep_files = sys.argv[4].split()

def copy_file(rel):
    spath, dpath = os.path.join(src, rel), os.path.join(dst, rel)
    os.makedirs(os.path.dirname(dpath) or dst, exist_ok=True)
    with open(spath, 'rb') as fs, open(dpath, 'wb') as fd:
        fd.write(fs.read())
    if rel in ('start.sh', 'install.sh'):
        os.chmod(dpath, 0o755)

for f in keep_files:
    if os.path.isfile(os.path.join(src, f)):
        copy_file(f)
for d in keep_dirs:
    base = os.path.join(src, d)
    if not os.path.isdir(base):
        continue
    for root, dirs, files in os.walk(base):
        dirs[:] = [x for x in dirs if x not in ('__pycache__',)]   # 跳过字节码
        for name in files:
            if name.endswith(('.pyc', '.pyo')):
                continue
            rel = os.path.relpath(os.path.join(root, name), src)
            copy_file(rel)
PYCOPY
mkdir -p "$PREFIX/logs"
[ -f "$PREFIX/logs/.gitkeep" ] || : > "$PREFIX/logs/.gitkeep"
[ -f "$PREFIX/config.toml" ] || cp "$PREFIX/config.example.toml" "$PREFIX/config.toml"
log "config.toml 就位（首次由模板生成 / 已保留）"

# 按需覆盖端口
apply_overrides() {
  local cfg="$1"; [ -f "$cfg" ] || return 0
  if [ -n "$OVERRIDE_PORT" ]; then
    sed -i.bak -E "s/^port[[:space:]]*=[[:space:]]*.*/port = $OVERRIDE_PORT/" "$cfg" && rm -f "$cfg.bak"
    log "覆盖组播端口 port=$OVERRIDE_PORT"
  fi
  if [ -n "$OVERRIDE_MGMT_PORT" ]; then
    sed -i.bak -E "s/^management_port[[:space:]]*=[[:space:]]*.*/management_port = $OVERRIDE_MGMT_PORT/" "$cfg" && rm -f "$cfg.bak"
    log "覆盖管理台端口 management_port=$OVERRIDE_MGMT_PORT"
  fi
}
apply_overrides "$PREFIX/config.toml"

# ------------------------------------------------------- systemd（可选）----
SYSTEMD_UNIT=""
if [ "$INSTALL_SYSTEMD" -eq 1 ]; then
  if [ "$(id -u)" != "0" ]; then
    log "跳过 systemd（非 root）；如需系统服务请 root 重跑并加 --systemd，或手动安装 deploy/mdns-responder.service"
  else
    # 创建运行用户（幂等）
    if ! id "$RUN_USER" >/dev/null 2>&1; then
      useradd --system --home-dir "$PREFIX" --shell /usr/sbin/nologin "$RUN_USER" 2>/dev/null \
        || useradd -r -d "$PREFIX" -s /sbin/nologin "$RUN_USER" 2>/dev/null || true
      log "创建系统用户 $RUN_USER"
    fi
    chown -R "$RUN_USER:$RUN_USER" "$PREFIX" 2>/dev/null || true
    # 生成 systemd 单元（指向当前前缀）
    SYSTEMD_UNIT="/etc/systemd/system/mdns-responder.service"
    sed -e "s|/opt/mdns-responder|$PREFIX|g" -e "s|^User=.*|User=$RUN_USER|" \
        -e "s|^Group=.*|Group=$RUN_USER|" "$SRC/deploy/mdns-responder.service" > "$SYSTEMD_UNIT"
    systemctl daemon-reload
    systemctl enable mdns-responder.service
    log "systemd 单元已安装并设为开机自启: $SYSTEMD_UNIT"
  fi
fi

# ------------------------------------------------------- 完成提示 ----------
echo
log "================================================================"
log "  mDNS Responder 安装完成"
log "================================================================"
log "  安装目录 : $PREFIX"
log "  管理页面 : http://127.0.0.1:8765/   （可改 [server].management* ）"
log "  启动命令 : cd $PREFIX && ./start.sh --bg"
log "  校验配置 : cd $PREFIX && ./start.sh --check"
log "  跑自测   : cd $PREFIX && ./start.sh --test"
if [ -n "$SYSTEMD_UNIT" ]; then
  log "  系统服务 : systemctl start|stop|status mdns-responder"
  log "             热重载配置: systemctl reload mdns-responder"
fi
log "  说明：修改 $PREFIX/config.toml 会自动热重载（log_* 段除外，改后需重启）"
log "================================================================"
