# mDNS Responder

> 零第三方依赖、可配置的多播 DNS / DNS-SD 应答服务，附带玻璃拟态 Web 管理控制台。
>
> `mDNS Responder` 在局域网内以组播方式应答 mDNS / DNS-SD 查询（A / AAAA / PTR / SRV / TXT），
> 让 `nas.local`、`Office Web._http._tcp.local` 这类名字在网段内可被解析与发现，
> 并提供一个可在线编辑配置、实时观测局域网服务状态的 Web 控制台。

- **零依赖**：仅用 Python 3.11+ 标准库（`socket` / `struct` / `tomllib` / `http.server` / `collections`），手写 DNS 报文编解码，无需 pip、无需构建。
- **即装即用**：`curl | bash` 一行安装、一行升级，或 clone 后 `./start.sh` 直接跑，也可用 Docker Compose 部署。
- **热重载**：改 `config.toml` 自动生效（mtime 监听 + `SIGHUP`），无需重启。
- **可观测**：健康探测状态灯、查询审计、局域网服务地图、名称冲突登记、Prometheus 指标五合一。
- **可运维**：管理员密码保护写操作、配置版本历史一键回滚、健康翻转 / 冲突告警 Webhook。

---

## 目录

- [特性](#特性)
- [快速开始](#快速开始)
- [安装](#安装)
- [升级](#升级)
- [配置](#配置)
- [Web 管理控制台](#web-管理控制台)
- [可观测增强](#可观测增强)
- [管理员密码](#管理员密码)
- [配置版本历史与回滚](#配置版本历史与回滚)
- [告警 Webhook](#告警-webhook)
- [Prometheus 指标](#prometheus-指标)
- [管理 API 一览](#管理-api-一览)
- [网关 /go/（友好页）](#网关-go友好页)
- [systemd 部署](#systemd-部署)
- [Docker 部署](#docker-部署)
- [测试](#测试)
- [安全](#安全)
- [已知边界](#已知边界)
- [目录结构](#目录结构)
- [License](#license)

---

## 特性

| 能力 | 说明 |
|---|---|
| **域名 → IP**（`[[hosts]]`） | 发布 `A`（IPv4）/ `AAAA`（IPv6）记录；可选 `in-addr.arpa` 反查 PTR |
| **服务发现**（`[[services]]`） | 每条自动生成 `PTR + SRV + TXT + A`；应答时把 SRV/TXT/A 作为附加记录一次往返返回 |
| **服务枚举** | 自动发布 `_services._dns-sd._udp.local` 指向各服务类型，客户端可枚举整网服务 |
| **QU / legacy 单播** | 支持 RFC 6762 单播应答位（QU）与 legacy 单播回退 |
| **已知应答抑制** | 客户端带上 known-answer 时不再重复回发，降低组播负载 |
| **启动 / 周期宣告** | 启动连发 `announce_count` 次刷新缓存，之后按 `announce_interval` 周期宣告 |
| **goodbye** | 停止时发 TTL=0 记录，客户端即时失效 |
| **热重载** | 改配置自动 reload；`kill -HUP <pid>` 手动触发 |
| **5353 共存** | `SO_REUSEADDR + SO_REUSEPORT`，与系统 avahi / Chrome / systemd-resolved 共存 |
| **Web 控制台** | 在线改配置并即时生效、看记录 / 日志 / 探针，双主题玻璃拟态单文件 |
| **可观测** | 健康状态灯 / 查询审计 / 局域网地图 / 名称冲突 / Prometheus 指标 |
| **写操作保护** | 管理员密码（PBKDF2 加盐）保护配置保存、回滚、改密；只在当前标签页会话内缓存 |
| **配置版本历史** | 每次保存 / 回滚前自动快照，可查看并一键回滚；有界保留、防路径穿越 |
| **告警通知** | 健康状态翻转 / 名称冲突推送钉钉 / 飞书 / Slack / 企业微信 / 通用 Webhook |

---

## 快速开始

### 方式 A：一行安装（远程，需能访问 GitHub）

```bash
curl -fsSL https://raw.githubusercontent.com/scpuny/mdns-responder/main/install.sh | bash
```

安装到 `/opt/mdns-responder`（无 root 写权限时自动回退 `$HOME/.local/share/mdns-responder`），
打印管理台地址与启动命令。加 `--systemd` 可顺带装系统服务（需 root）：

```bash
curl -fsSL https://raw.githubusercontent.com/scpuny/mdns-responder/main/install.sh | bash -s -- --systemd
```

### 方式 B：clone 本地跑（离线 / 二次开发）

```bash
git clone https://github.com/scpuny/mdns-responder.git
cd mdns-responder
./start.sh --check     # 校验配置，打印将发布的 DNS 记录（不联网）
./start.sh             # 前台启动（Ctrl+C 优雅退出并 goodbye）
# 或
./start.sh --bg        # 后台启动，写 PID 到 logs/mdns.pid
```

启动后浏览器打开 **`http://127.0.0.1:8765/`** 管理控制台。

> 首次运行缺 `config.toml` 时会自动从 `config.example.toml` 复制一份模板。
> 首次在控制台保存配置前，会要求先设置管理员密码（见[管理员密码](#管理员密码)）。

### 方式 C：Docker Compose

```bash
docker compose up -d --build
# 管理台：http://127.0.0.1:8765/  配置和历史落在 ./data，日志落在 ./logs
```

详见 [Docker 部署](#docker-部署)。**必须使用 host 网络**，否则二层组播收不到。

---

## 安装

`install.sh` 选项：

| 选项 | 说明 | 默认 |
|---|---|---|
| `-d, --prefix DIR` | 安装目录 | `/opt/mdns-responder`（非 root 回退 `$HOME/.local/share/mdns-responder`） |
| `-s, --systemd` | 生成并安装 systemd 单元、开机自启（需 root） | 关 |
| `-u, --user USER` | systemd 运行用户 | `mdns` |
| `-p, --port PORT` | 覆盖组播端口写入 config.toml | `5353` |
| `-m, --mgmt-port N` | 覆盖管理台端口 | `8765` |
| `--upgrade` | 就地升级已有安装（保留配置 / 密码 / 日志） | 关 |

环境变量：`MDNS_INSTALL_PREFIX` / `MDNS_GITHUB_REPO` / `MDNS_REF` / `MDNS_DOWNLOAD_TOOL`（auto|curl|wget）。

已存在的 `config.toml` **绝不会被覆盖**（保留你在控制台保存的配置），只补缺失文件。

---

## 升级

`install.sh --upgrade` 用于把已安装实例升级到新版本，**现场先备份、配置不丢失**：

```bash
# 远程
curl -fsSL https://raw.githubusercontent.com/scpuny/mdns-responder/main/install.sh | bash -s -- --upgrade
# 或本地 clone 后
./install.sh --upgrade -d /opt/mdns-responder
```

流程：

1. 校验目标前缀下确实存在已安装实例（否则报错退出，避免误建新目录）；
2. 现场备份到 `.upgrade-backup-<UTC时间戳>/`：`config.toml`、`auth.toml`、`logs/`；
3. 覆盖程序文件（`src/`、`web/`、`tests/`、`deploy/`、`start.sh`、`Dockerfile` 等），**不覆盖** `config.toml`；
4. 可选重新安装 systemd 单元；
5. 自动重启 systemd 服务或后台实例（若检测到正在运行）；
6. 打印升级结果与备份位置。

`auth.toml`（管理员密码摘要）与 `logs/` 完整保留，升级后无需重设密码。升级备份目录已被 `.gitignore` / `.dockerignore` 排除。

---

## 配置

所有配置集中在 `config.toml`（模板 `config.example.toml`）。结构：

```toml
[server]          # 组播 / 管理台 / 日志 / 可观测 / 告警 / 历史参数
[[hosts]]         # 域名 → IP 纯映射
[[services]]      # DNS-SD 服务（自动 PTR+SRV+TXT+A）
```

### `[server]` 关键项

| 键 | 默认 | 说明 |
|---|---|---|
| `interface` | `"0.0.0.0"` | `0.0.0.0`（内核默认路由）/ 指定网卡 IP / `"all"`（全部非回环 IPv4） |
| `group` / `port` | `224.0.0.251` / `5353` | 组播地址与端口（标准值） |
| `ttl` | `120` | 记录 TTL（秒） |
| `announce_interval` | `60` | 周期主动宣告间隔（0=关，仍做启动宣告） |
| `announce_count` | `3` | 启动连发次数 |
| `reverse_ptr` | `true` | 是否发布 IPv4 反查 PTR |
| `management` | `true` | 是否启动 Web 控制台 |
| `management_host` / `management_port` | `127.0.0.1` / `8765` | 控制台监听地址（默认仅回环，安全） |
| `management_token` | `""` | 留空 = 不鉴权；填值后所有 API 需带 `X-Admin-Token` 头 |
| `log_file` / `log_max_bytes` / `log_backup_count` / `log_retention_days` / `log_console` | 见模板 | 有界轮转日志，磁盘硬上界 = `log_max_bytes × (log_backup_count+1)` |
| `health` / `health_interval` / `health_timeout` | 见「可观测」 | 健康探测 |
| `audit` / `audit_limit` | 见「可观测」 | 查询审计 |
| `browse` / `browse_scan_interval` / `browse_limit` | 见「可观测」 | 局域网服务地图 |
| `conflict_detect` | `true` | 名称冲突登记 |
| `alert` / `alert_on_health` / `alert_on_conflict` | `true` | 告警总开关与事件开关 |
| `alert_webhooks` | `[]` | Webhook URL 数组，平台按域名自动识别 |
| `alert_cooldown` | `300` | 同一事件冷却秒数，0 = 不去重 |
| `alert_timeout` | `5.0` | 单次 webhook 超时（0.5..30 秒） |
| `history_limit` | `30` | 配置版本快照有界保留份数 |

> 除 `log_*` 段（改了需重启）外，所有键都支持热重载。

### `[[hosts]]` 示例

```toml
[[hosts]]
name = "nas.local"
ip   = "172.15.103.30"        # 写 IPv6 地址则生成 AAAA 记录
```

### `[[services]]` 示例

```toml
[[services]]
type     = "_http._tcp.local"      # 标准服务类型 _xxx._tcp.local / _xxx._udp.local
instance = "Office Web"            # 实例名（不能含 '.'，可用空格 / 中文）
host     = "nas.local"            # 可省略；省略时由实例名自动派生 <slug>.local
ip       = "172.15.103.30"        # 服务实际所在 IP
port     = 8080                    # 服务实际端口
txt      = { path = "/", version = "1.0" }
```

每条 service 自动发布：`PTR <type>. → <instance>.<type>.`、`SRV <instance>.<type>. → 0 0 <port> <host>.`、
`TXT`、`A/AAAA <host>. → <ip>`，且应答 PTR/SRV/TXT 查询时会把附加记录一并带上（一次往返拿全）。

> **多级 `.local`**：`.local` 是 mDNS 保留域。多级 `.local` 在 Linux 客户端依赖逐台改 nss-mdns，
> 且 mDNS 只在同网段有效、跨网段/代理脆弱。团队级场景建议改用内网 DNS（dnsmasq / CoreDNS / 企业 DNS），
> 并优先 `.internal` 或自有子域，而非 `.local`。

---

## Web 管理控制台

启动后访问 `http://127.0.0.1:8765/`（单文件 `web/admin.html`，零外部依赖，双击也能用演示模式预览）。

**9 个标签页：**

| 标签 | 功能 |
|---|---|
| 服务概览 | Bento 概览 + SVG 组播拓扑 + 运维接口与安全卡（指标 / 密码 / 历史 / 告警状态） |
| 配置管理 | 可视化编辑 / TOML 源码双模式；安全设置、配置版本历史、告警通知三块扩展配置；保存前校验 → 备份 → 原子替换 → 热重载 |
| DNS 记录 | 已发布记录全表，可按类型筛选 |
| 实时日志 | SSE 实时日志流 |
| 查询探针 | 向组播地址发起一次真实查询并解析应答 |
| 健康监控 | 周期 TCP 探测已登记目标，红绿状态灯 |
| 局域网地图 | 摄取局域网其它 mDNS/DNS-SD 服务实例 |
| 查询审计 | 谁查了什么、命中与否（有界环形缓冲） |
| 名称冲突 | 本地同名异值的外来记录（RFC 6762 防御观测） |

远程访问控制台时，顶栏「链路图标」可设置远端管理地址（存 localStorage）。
设置 `management_token` 后，所有 API 需带 `X-Admin-Token` 头（或 `?token=` 查询参数）。
管理员密码通过 `X-Admin-Password` 头传递，仅在当前标签页 `sessionStorage` 缓存，关闭标签页即失效。

---

## 可观测增强

纯可观测层（`src/mdns_insights.py`），零网络副作用，默认全开、热重载即时生效。

| 模块 | 开关 | 说明 |
|---|---|---|
| **健康监控** | `health` | 独立守护线程周期 TCP 探测已登记目标（host→80，service→ip:port），管理台出红绿状态灯；`/api/health` |
| **查询审计** | `audit` | 有界环形缓冲记录「谁查了什么 / 命中与否 / QU 位」；`/api/queries?limit=` |
| **局域网服务浏览** | `browse` | 被动摄取外来 DNS-SD 应答 + 周期主动枚举，按 (type,instance) 聚合出「网络地图」；`/api/browse` |
| **名称冲突** | `conflict_detect` | 登记本地同名异值的外来记录（RFC 6762 §4 防御观测，LRU + 时效）；`/api/conflicts` |
| **Prometheus** | 常开 | `/api/metrics` 输出文本格式 0.0.4，可被 Prometheus 直接抓取；详见下文 |

`/api/status` 的 `insights` 段汇总四项开关与计数，`security` / `history` / `alerts` 段汇总运维状态。

---

## 管理员密码

**所有变更类操作（保存配置、回滚版本、修改密码）都要求管理员密码**，防止控制台被误操作或越权改写。

- 密码以 **PBKDF2-HMAC-SHA256**（20 万次迭代 + 16 字节随机盐）摘要保存在项目根目录 `auth.toml`，
  **绝不明文落盘**，文件权限 `0600`，已被 `.gitignore` 排除；`hmac.compare_digest` 常量时间校验。
- 路径可用环境变量 `MDNS_AUTH_FILE` 覆盖（Docker 中指向 `/data/auth.toml`）。
- 密码长度 8..256 位，可在控制台「配置管理 → 安全设置」随时修改（需输入旧密码）。
- **首次使用**：未设置密码时，任何写操作返回 `409 {"code":"setup_required"}`；
  密码缺失 / 错误返回 `403 {"code":"auth_failed"}`。控制台会自动弹出密码框引导初始化与校验。

命令行示例：

```bash
# 首次设置（无需旧密码）
curl -s -X POST http://127.0.0.1:8765/api/auth/password \
  -H 'Content-Type: application/json' \
  -d '{"new_password":"your-strong-password"}'

# 校验
curl -s -X POST http://127.0.0.1:8765/api/auth/verify \
  -H 'X-Admin-Password: your-strong-password'

# 修改（旧密码放请求头，新密码放 body）
curl -s -X POST http://127.0.0.1:8765/api/auth/password \
  -H 'X-Admin-Password: your-old-password' \
  -H 'Content-Type: application/json' \
  -d '{"new_password":"your-new-strong-password"}'

# 保存配置（带 X-Admin-Password）
curl -s -X POST http://127.0.0.1:8765/api/config \
  -H 'X-Admin-Password: your-strong-password' \
  -H 'Content-Type: application/json' \
  -d '{"raw":"..."}'
```

> **忘记密码怎么办**：删除 `auth.toml` 并重启进程即可回到「未初始化」状态，之后重新设置。
> 该操作需要能登录到服务器文件系统，属于有意的恢复通道。

---

## 配置版本历史与回滚

每次**保存配置**或**执行回滚**之前，服务会先把「当前生效版本」的 TOML 原文快照下来，
因此任何一次变更都可以一键回到上一版本。

- 快照落在 `logs/config_history/`（可用 `MDNS_HISTORY_DIR` 覆盖；Docker 中指向 `/data/config_history`）。
- 单份快照是 JSON：`{ts, reason, text}`，文件名 `config-<UTC秒>-<微秒hex>-<随机hex>.json`。
- 有界保留 `history_limit`（默认 30）份，超出按修改时间淘汰最老的。
- 版本 ID 走白名单正则，非法 ID 直接 `400`，**防路径穿越**。
- 回滚读回原文后走与在线保存**完全相同**的「校验 → 备份 → 原子替换 → 热重载」链路，
  永远不会把一份非法配置写回磁盘。

```bash
# 查看版本列表
curl -s http://127.0.0.1:8765/api/config/history

# 一键回滚
curl -s -X POST http://127.0.0.1:8765/api/config/rollback \
  -H 'X-Admin-Password: your-strong-password' \
  -H 'Content-Type: application/json' \
  -d '{"id":"config-20261112T085245Z-a1b2c3-4d5e.json"}'
```

控制台「配置管理 → 配置版本历史」提供可视化列表与回滚按钮；概览页显示当前保留版本数。

---

## 告警 Webhook

`mdns_alerts.py` 把「健康状态翻转」和「名称冲突」编排成告警，推送到常见群机器人。

| 平台 | 识别依据 | 载荷 |
|---|---|---|
| 钉钉 | `oapi.dingtalk.com` | `msgtype: markdown` |
| 飞书 / Lark | `open.feishu.cn` / `open.larksuite.com` | `msg_type: interactive` card |
| Slack | `hooks.slack.com` | `attachments` |
| 企业微信 | `qyapi.weixin.qq.com` | `msgtype: markdown` |
| 其它 | 任意 URL | 通用 JSON `{title, level, detail, ts, source}` |

配置（写入 `config.toml` 的 `alert_webhooks` 即可热重载）：

```toml
alert = true
alert_on_health = true
alert_on_conflict = true
alert_cooldown = 300
alert_timeout = 5.0
alert_webhooks = [
  "https://oapi.dingtalk.com/robot/send?access_token=xxx",
  "https://hooks.slack.com/services/T000/B000/XXXX",
]
```

行为要点：

- **只在状态真正翻转时触发**（`up → down` / `down → up`），首次观测不告警，避免启动时刷屏。
- 同一事件在 `alert_cooldown` 秒内去重；队列 `maxsize=200` 有界，满了丢弃最旧而非阻塞主循环。
- 独立 daemon 发送线程 + 失败最多重试 2 次，网络抖动不会拖慢 mDNS 应答。
- 未配置 webhook 时事件仍会被登记统计（`GET /api/alerts` 可查），只是不向外投递。
- `GET /api/status` 的 `alerts` 段与 `/api/metrics` 均暴露 `events / sent / failed / dropped / queue` 计数。

---

## Prometheus 指标

`GET /api/metrics` 返回 Prometheus 文本格式 `0.0.4`，无需额外 exporter：

```bash
curl -s http://127.0.0.1:8765/api/metrics
```

`scrape_configs` 示例：

```yaml
- job_name: mdns-responder
  static_configs:
    - targets: ['127.0.0.1:8765']
```

主要指标：

| 指标 | 类型 | 含义 |
|---|---|---|
| `mdns_responder_up` / `uptime_seconds` | gauge | 主循环运行中 / 运行时长 |
| `mdns_responder_records` / `hosts` / `services` / `ttl_seconds` | gauge | 当前发布状态 |
| `mdns_responder_queries_total` / `responses_total` / `response_bytes_total` / `announces_total` | counter | 累计流量 |
| `mdns_responder_health_targets` / `health_{up,down,unknown}` | gauge | 健康目标聚合 |
| `mdns_responder_health_status{target,address,kind}` | gauge | 单目标 1=up / 0=down |
| `mdns_responder_health_latency_ms{target}` | gauge | 探测延迟 |
| `mdns_responder_queries_audited_total` / `browse_instances` / `conflicts` | gauge/counter | 可观测计数 |
| `mdns_responder_config_saves_total` / `config_history_versions` | counter/gauge | 配置写入次数 / 快照数 |
| `mdns_responder_admin_password_enabled` | gauge | 是否已设管理员密码 |
| `mdns_responder_alerts_enabled` / `alert_webhooks` | gauge | 告警配置 |
| `mdns_responder_alert_{events,sent,failed,dropped}_total` / `alert_queue_depth` | counter/gauge | 告警投递统计 |
| `mdns_responder_log_max_disk_bytes` | gauge | 日志磁盘占用硬上界 |

---

## 管理 API 一览

设置 `management_token` 后所有请求需带 `X-Admin-Token`（或 `?token=`）；变更类操作另需 `X-Admin-Password`。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/status` | 总状态（含 `insights` / `security` / `history` / `alerts` / `config_saves`） |
| GET | `/api/config` | 当前配置（JSON 视图） |
| GET | `/api/records` | 已发布 DNS 记录 |
| GET | `/api/logs` / `/api/logs/stream` | 最近日志 / SSE 实时流 |
| GET | `/api/interfaces` | 可选网卡 |
| GET | `/api/health` / `/api/queries` / `/api/browse` / `/api/conflicts` | 可观测四件套 |
| GET | `/api/metrics` | Prometheus 文本指标 |
| GET | `/api/auth` | 管理员密码状态（是否启用 / 算法 / 更新时间） |
| GET | `/api/config/history` | 配置版本列表 |
| GET | `/api/alerts` | 告警编排器状态与统计 |
| POST | `/api/auth/password` | 首次设置 / 修改管理员密码（body `new_password`） |
| POST | `/api/auth/verify` | 校验管理员密码 |
| POST | `/api/config` | 保存配置（**需密码**，body `{raw}` 或 `{config}`） |
| POST | `/api/config/rollback` | 一键回滚（**需密码**，body `{id}`） |
| POST | `/api/reload` | 手动触发热重载 |
| POST | `/api/probe` | 发起一次真实 mDNS 查询（body `{name,type}`） |
| GET | `/go/<域名>/` | 网关友好页 / 反代入口（见下） |

---

### 网关 `/go/<域名>/`

控制台每行「打开」链接指向 `http://<管理台>/go/<域名>/`：网关把该域名解析到登记目标并反代。
**服务显式端口优先**——若域名同时是某 service 的 host，路由到该 service 的 `ip:port`；
纯 host 才回退 80。目标不可达 / 域名未登记时返回友好 404/503 页（非报错栈），绝不暴露堆栈。

> 架构边界：mDNS 模型下客户端解析 `.local` 后**直连目标 IP**，不经过本服务。
> `/go/` 只是管理台提供的辅助入口，不是全局流量前置网关（那是 nginx 的角色）。

### HTTP 网关（域名直达 80，可选）

`[server].gateway = true` 时，本服务额外在 `gateway_port`（默认 80）监听一个 **Host 头反代网关**：
浏览器访问 `http://<域名>`（不带端口）即被转发到该域名登记的目标 `ip:port`，等价于公司「防火墙 / 反代把域名映射到端口」。
复用 `[[services]]` / `[[hosts]]` 作为路由规则，**加一条服务即自动可无端口访问，无需另装 nginx**。

- `gateway_admin_host`（默认 `mdns.local`）：访问该域名（或盒子 IP、`/admin`）即进管理台控制台，不与服务反代冲突。
- **每服务独立开关 `proxy`**：`[[services]]` 里可写 `proxy = false`——该服务仍正常广播 DNS-SD 发现，
  但**不再经网关反代**（适合远程 / 非 HTTP 设备，如打印机）。访问其域名直达会返回友好页「未开启网关反代」。
  缺省 `proxy = true`（即开启反代，兼容未写该字段的旧配置）。管理台保存时会**显式写出** `proxy = true` 或
  `proxy = false`，保证配置文件与界面开关一一对应，便于核对。
- **开 / 关即时生效**：全局 `gateway` 开关、网关端口 / 管理台域名 / 超时均支持热重载——在管理台改完保存即可，
  不必 `docker restart`。底层会在重载时按配置自动启停网关 socket（关闭后 80 端口随即释放）。
  （注意：mDNS 主端口 `port`、网卡 `interface/group`、以及 `log_*` 段仍属进程级参数，需重启才生效。）

---

## systemd 部署

仓库提供 `deploy/mdns-responder.service`。`install.sh --systemd` 会自动生成并指向实际安装前缀；
手动部署：

```bash
sudo cp deploy/mdns-responder.service /etc/systemd/system/
# 按实际前缀改 [Service] 的 WorkingDirectory / ExecStart / config 路径
sudo systemctl daemon-reload && sudo systemctl enable --now mdns-responder
sudo systemctl reload mdns-responder      # 热重载配置（SIGHUP）
```

- 运行用户 `mdns`（install 时自动创建系统用户），`WorkingDirectory=/opt/mdns-responder`。
- `ExecReload=/bin/kill -HUP $MAINPID` 支持 `systemctl reload`。
- 文件日志由 Python 内部有界轮转，unit **不再** `StandardOutput=append:`（避免双写绕过轮转）；
  控制台输出默认进 journald（自带轮转）。
- `auth.toml` 随安装前缀保留，升级不会丢失。

---

## Docker 部署

仓库提供 `Dockerfile`、`docker-compose.yml`、`.dockerignore` 与 `deploy/docker-entrypoint.sh`。

```bash
docker compose up -d --build
docker compose logs -f
docker compose down
```

要点：

- 基于 `python:3.11-slim`，**零 pip 安装**；镜像内 `HEALTHCHECK` 请求 `/api/status`。
- **`network_mode: host` 是硬性要求**：mDNS 依赖二层组播 `224.0.0.251:5353`，
  Docker bridge 网络无法转发组播，容器将收不到任何查询。
- 卷 `./data:/data` 持久化 `config.toml`、`auth.toml`、`config_history/`；
  卷 `./logs:/app/logs` 持久化有界轮转日志。
- entrypoint 首次启动从模板生成 `/data/config.toml`，**后续绝不覆盖**；
  环境变量 `MDNS_AUTH_FILE=/data/auth.toml`、`MDNS_HISTORY_DIR=/data/config_history` 已预置。
- host 网络下管理台仍只监听宿主机回环 `127.0.0.1:8765`，局域网不可直接访问（保持安全默认）。
- 如需健康检查端口暴露给编排系统，注意 host 网络模式下 `EXPOSE` 不生效。

单跑（不用 compose）：

```bash
docker build -t mdns-responder:local .
docker run -d --name mdns --network host \
  -v "$PWD/data:/data" -v "$PWD/logs:/app/logs" \
  mdns-responder:local
```

---

## 测试

```bash
./start.sh --test          # = python3 tests/selftest.py --standard-port
```

覆盖：离线报文编解码单测（压缩指针 / QU 位 / known-answer 抑制 / SRV 解析 / 审计环形 / 冲突判定 / 浏览聚合）、
真实组播端到端（收发自证、QU/legacy 单播、热重载改 IP 生效、goodbye、5353 共存）、
管理 API（REST / SSE / 401 鉴权 / 结构化保存→备份→热重载 / 非法配置 400 且不破坏原配置）、
可观测四路由、Prometheus 文本指标、管理员密码全生命周期（初始化 / 校验 / 改密 / 写操作 409/403）、
配置版本快照与一键回滚、告警编排纯逻辑、网关友好页四分支、日志轮转上界。
当前全量 **146 passed / 0 failed**（其中离线 97 条）。

单独跑：

```bash
python3 tests/selftest.py --offline      # 仅离线逻辑，不碰组播
python3 tests/selftest.py --standard-port
```

CI：push / PR 到 `main` 时 GitHub Actions 执行 `py_compile`（全部 Python 模块）、`bash -n`、
前端内联 JS `node --check`、Compose YAML 解析，再跑 `bash start.sh --test` 全量自测。

---

## 安全

- **默认仅回环**：控制台默认监听 `127.0.0.1:8765`，局域网不可达。
- **双层鉴权**：`management_token` 保护读接口（401）；`X-Admin-Password` 保护写接口（409/403）。
- **密码不明文**：PBKDF2-HMAC-SHA256 加盐摘要存 `auth.toml`（0600，不入库），常量时间校验；
  前端仅用 `sessionStorage` 在当前标签页缓存，关闭即失效。
- **写前快照**：每次配置变更自动留档，非法配置在写入前被拒绝，可一键回滚。
- **不写系统区**：非 root 安装落 `$HOME`，不碰 `/etc`；systemd 步骤显式需 root。
- **网关不泄栈**：`/go/` 目标不可达返回友好页，异常信息被翻译成一句人话。
- **日志 / 队列 / 历史全部有界**：磁盘占用与内存队列都有硬上界，长期运行不会撑爆。
- **构建隔离**：`.dockerignore` 排除本机 `config.toml` / `auth.toml` / 日志 / 缓存，不进镜像。

---

## 已知边界

- 仅加入 IPv4 组播 `224.0.0.251`，未监听 `ff02::fb`（IPv6-only 客户端无法发现）。
- 名称冲突只做**防御观测登记**（RFC 6762 §4），不做 RFC 6762 的 probing / 强制改名——需保证 `.local` 命名在网内唯一。
- mDNS 只在同网段有效；跨网段 / VPN / 代理环境脆弱，团队级建议内网 DNS。
- 管理员密码是「控制台写操作保护」，不是传输层加密；远程访问管理台请置于 HTTPS 反向代理之后。

---

## 目录结构

```
mdns-responder/
  config.example.toml   配置模板（入库）
  config.toml           实际运行配置（不入库，含本机 IP / token）
  auth.toml             管理员密码摘要（不入库，0600）
  start.sh              统一启动入口（前台 / 后台 / 校验 / 自测 / 启停）
  install.sh            一键安装 / 升级脚本（curl | bash，--upgrade）
  Dockerfile            python:3.11-slim 零依赖镜像
  docker-compose.yml    host 网络 + 数据卷部署
  .dockerignore         排除本机敏感配置 / 日志 / 缓存
  src/
    mdns_responder.py   核心：组播 socket + DNS 编解码 + 应答 + 热重载 + 运维装配
    mdns_insights.py    可观测层：健康探测 / 查询审计 / 服务浏览 / 名称冲突
    mdns_security.py    管理员密码（PBKDF2 加盐哈希）
    mdns_history.py     配置版本快照 / 列表 / 读回 / 有界淘汰
    mdns_alerts.py      告警 Webhook 编排（平台识别 / 冷却 / 重试）
    admin_server.py     Web 管理 API（ThreadingHTTPServer）+ 友好页 + 网关
    mdns_probe.py       查询探针（调试 / 验证）
  web/admin.html        管理控制台前端（单文件，零外部依赖）
  tests/selftest.py     离线 + 组播端到端 + 管理 API + 新功能自测
  deploy/
    mdns-responder.service   systemd 单元
    docker-entrypoint.sh    容器首次启动生成配置
  .github/workflows/ci.yml   GitHub Actions CI
  logs/                 运行日志 / PID / config_history（gitignore）
```

---

## License

MIT，见 [LICENSE](LICENSE)。
