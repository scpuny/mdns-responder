# syntax=docker/dockerfile:1
# mDNS Responder —— 零第三方依赖，仅 Python 标准库
#
# 重要：mDNS 依赖二层组播（224.0.0.251:5353），容器必须使用 host 网络，
#       bridge 网络收不到组播，也发不出正确的源地址。见 docker-compose.yml。
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    MDNS_AUTH_FILE=/data/auth.toml \
    MDNS_HISTORY_DIR=/data/config_history \
    TZ=Asia/Shanghai

WORKDIR /app

COPY src/ ./src/
COPY web/ ./web/
COPY tests/ ./tests/
COPY deploy/ ./deploy/
COPY start.sh install.sh config.example.toml README.md LICENSE ./

RUN chmod +x start.sh install.sh deploy/docker-entrypoint.sh \
 && mkdir -p /data /app/logs \
 && cp config.example.toml /app/config.toml

# 5353/udp = mDNS 组播；8765/tcp = Web 管理台（默认仅监听 127.0.0.1）
EXPOSE 5353/udp 8765/tcp

# 管理台状态接口即健康探针；需要 token 时也可改用 ?token= 或关闭鉴权
HEALTHCHECK --interval=30s --timeout=5s --start-period=8s --retries=3 \
  CMD ["python3", "-c", "import sys,urllib.request; r=urllib.request.urlopen('http://127.0.0.1:8765/api/status',timeout=3); sys.exit(0 if r.status==200 else 1)"]

ENTRYPOINT ["/app/deploy/docker-entrypoint.sh"]
CMD ["python3", "/app/src/mdns_responder.py", "-c", "/data/config.toml"]
