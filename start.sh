#!/usr/bin/env bash
# =============================================================================
# mDNS Responder 统一启动入口（零第三方依赖，仅需 Python >= 3.11）
#
# 目录结构（项目根 = 本脚本所在目录）：
#   config.toml            实际运行配置（管理页面可在线修改并热重载）
#   config.example.toml    配置模板，首次运行且缺 config.toml 时自动复制
#   start.sh               本脚本
#   src/                   Python 源码：mdns_responder / admin_server / mdns_probe
#   web/admin.html         管理控制台前端（单文件，零外部依赖）
#   tests/selftest.py      离线报文 + 真实组播端到端自测
#   deploy/                systemd unit
#   logs/                  运行日志、PID 文件
#
# 用法：
#   ./start.sh                     前台启动（Ctrl+C 退出，自动发 goodbye）
#   ./start.sh --bg                后台启动；文件日志由 Python 内部有界轮转（logs/mdns.log + .1/.2...）
#   ./start.sh --status            查看后台实例状态
#   ./start.sh --stop              停止后台实例（SIGTERM，优雅退出）
#   ./start.sh --check             仅校验配置并打印将发布的 DNS 记录
#   ./start.sh --test              运行完整自测（含 5353 共存验证）
#   ./start.sh -c other.toml       指定配置文件
#   ./start.sh -v / --no-admin    透传 responder 参数
#
# 管理页面：http://127.0.0.1:8765/  （由 [server].management* 配置）
# 配置热重载：改 config.toml 后自动生效，或 kill -HUP $(cat logs/mdns.pid)
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-python3}"
CONFIG="${CONFIG:-$ROOT/config.toml}"
PIDFILE="$ROOT/logs/mdns.pid"
LOGFILE="$ROOT/logs/mdns.log"
ENTRY="$ROOT/src/mdns_responder.py"

if ! "$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
    echo "[start] 需要 Python >= 3.11（tomllib），当前：$($PYTHON -V 2>&1)" >&2
    exit 2
fi

mkdir -p "$ROOT/logs"

if [ ! -f "$CONFIG" ] && [ -f "$ROOT/config.example.toml" ]; then
    cp "$ROOT/config.example.toml" "$CONFIG"
    echo "[start] 已由模板生成 $CONFIG"
fi

ACTION="run"
ARGS=()
while [ $# -gt 0 ]; do
    case "$1" in
        -c|--config)  CONFIG="$2"; ARGS+=(-c "$2"); shift 2 ;;
        --check)      ACTION="check"; shift ;;
        --bg)         ACTION="bg"; shift ;;
        --stop)       ACTION="stop"; shift ;;
        --status)     ACTION="status"; shift ;;
        --test)       ACTION="test"; shift ;;
        -v|--verbose) ARGS+=(-v); shift ;;
        --no-admin)   ARGS+=(--no-admin); shift ;;
        -h|--help)
            echo "用法: ./start.sh [--bg|--stop|--status|--check|--test] [-c config.toml] [-v] [--no-admin]"
            echo "详见本文件头部注释。"
            exit 0 ;;
        *)            ARGS+=("$1"); shift ;;
    esac
done

case "$ACTION" in
    check)
        exec "$PYTHON" "$ENTRY" -c "$CONFIG" --check "${ARGS[@]}"
        ;;
    test)
        exec "$PYTHON" "$ROOT/tests/selftest.py" --standard-port
        ;;
    status)
        if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
            echo "[start] 运行中 PID=$(cat "$PIDFILE")"
        else
            echo "[start] 未运行"
            exit 1
        fi
        ;;
    stop)
        if [ ! -f "$PIDFILE" ]; then
            echo "[start] 未运行（无 PID 文件）"
            exit 0
        fi
        PID="$(cat "$PIDFILE")"
        if kill -0 "$PID" 2>/dev/null; then
            kill -TERM "$PID"
            for _ in 1 2 3 4 5 6 7 8 9 10; do
                kill -0 "$PID" 2>/dev/null || break
                sleep 0.3
            done
            echo "[start] 已停止 PID=$PID"
        else
            echo "[start] 进程 PID=$PID 已不在运行"
        fi
        mv -f "$PIDFILE" "$ROOT/logs/mdns.pid.stopped" 2>/dev/null || true
        ;;
    bg)
        if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
            echo "[start] 已在运行 PID=$(cat "$PIDFILE")"
            exit 1
        fi
        # 文件日志由 Python 内部有界轮转（logs/mdns.log + .1/.2...）。
        # 此处不能用 >> 重定向到同一文件，否则会双写并绕过轮转，导致磁盘无限增长。
        nohup "$PYTHON" "$ENTRY" -c "$CONFIG" "${ARGS[@]}" >/dev/null 2>&1 &
        echo $! > "$PIDFILE"
        echo "[start] 已后台启动 PID=$(cat "$PIDFILE")"
        echo "[start] 管理页面 http://127.0.0.1:8765/"
        echo "[start] 日志 $LOGFILE"
        ;;
    run)
        exec "$PYTHON" "$ENTRY" -c "$CONFIG" "${ARGS[@]}"
        ;;
esac
