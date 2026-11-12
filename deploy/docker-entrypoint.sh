#!/usr/bin/env bash
# 容器入口：首次启动由模板生成 /data/config.toml，之后一律保留用户在线保存的配置。
set -euo pipefail

mkdir -p /data /app/logs

if [ ! -f /data/config.toml ]; then
  cp /app/config.example.toml /data/config.toml
  echo "[entrypoint] 已由模板生成 /data/config.toml"
fi
if [ ! -f /app/config.toml ]; then
  cp /data/config.toml /app/config.toml
fi

exec "$@"
