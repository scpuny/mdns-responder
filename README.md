# mDNS Responder

> 零第三方依赖、可配置的多播 DNS / DNS-SD 应答服务，附带玻璃拟态 Web 管理控制台。
>
> `mDNS Responder` 在局域网内以组播方式应答 mDNS / DNS-SD 查询（A / AAAA / PTR / SRV / TXT），
> 让 `nas.local`、`Office Web._http._tcp.local` 这类名字在网段内可被解析与发现，
> 并提供一个可在线编辑配置、实时观测局域网服务状态的 Web 控制台。

- **零依赖**：仅用 Python 3.11+ 标准库（`socket` / `struct` / `tomllib` / `http.server` / `collections`），手写 DNS 报文编解码，无需 pip、无需构建。
- **即装即用**：`curl | bash` 一行安装，或 clone 后 `./start.sh` 直接跑。
- **热重载**：改 `config.toml` 自动生效（mtime 监听 + `SIGHUP`），无需重启。
- **可观测**：健康探测状态灯、查询审计、局域网服务地图、名称冲突登记四合一。

---

## 目录

- [特性](#特性)
- [快速开始](#快速开始)
- [安装](#安装)
- [配置](#配置)
- [Web 管理控制台](#web-管理控制台)
- [可观测增强](#可观测增强)
- [网关 /go/（友好页）](#网关-go友好页)
- [systemd 部署](#systemd-部署)
- [测试](#测试)
- [安全](#安全)
- [已知边界](#已知边界)
- [目录结构](#目录结构)

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
| **可观测** | 健康状态灯 / 查询审计 / 局域网地图 / 名称冲突（详见下文） |

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

环境变量：`MDNS_INSTALL_PREFIX` / `MDNS_GITHUB_REPO` / `MDNS_REF` / `MDNS_DOWNLOAD_TOOL`（auto|curl|wget）。

已存在的 `config.toml` **绝不会被覆盖**（保留你在控制台保存的配置），只补缺失文件。

---

## 配置

所有配置集中在 `config.toml`（模板 `config.example.toml`）。结构：

```toml
[server]          # 组播 / 管理台 / 日志 / 可观测参数（详见 config.example.toml 注释）
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
| 服务概览 | Bento 概览 + SVG 组播拓扑 |
| 配置管理 | 可视化编辑 / TOML 源码双模式；保存前校验 → 备份 `config.toml.bak` → 原子替换 → 热重载 |
| DNS 记录 | 已发布记录全表，可按类型筛选 |
| 实时日志 | SSE 实时日志流 |
| 查询探针 | 向组播地址发起一次真实查询并解析应答 |
| 健康监控 | 周期 TCP 探测已登记目标，红绿状态灯 |
| 局域网地图 | 摄取局域网其它 mDNS/DNS-SD 服务实例 |
| 查询审计 | 谁查了什么、命中与否（有界环形缓冲） |
| 名称冲突 | 本地同名异值的外来记录（RFC 6762 防御观测） |

远程访问控制台时，顶栏「链路图标」可设置远端管理地址（存 localStorage）。
设置 `management_token` 后，所有 API 需带 `X-Admin-Token` 头（或 `?token=` 查询参数）。

### 网关 `/go/<域名>/`

控制台每行「打开」链接指向 `http://<管理台>/go/<域名>/`：网关把该域名解析到登记目标并反代。
**服务显式端口优先**——若域名同时是某 service 的 host，路由到该 service 的 `ip:port`；
纯 host 才回退 80。目标不可达 / 域名未登记时返回友好 404/503 页（非报错栈），绝不暴露堆栈。

---

## 可观测增强

纯可观测层（`src/mdns_insights.py`），零网络副作用，默认全开、热重载即时生效。

| 模块 | 开关 | 说明 |
|---|---|---|
| **健康监控** | `health` | 独立守护线程周期 TCP 探测已登记目标（host→80，service→ip:port），管理台出红绿状态灯；`/api/health` |
| **查询审计** | `audit` | 有界环形缓冲记录「谁查了什么 / 命中与否 / QU 位」；`/api/queries?limit=` |
| **局域网服务浏览** | `browse` | 被动摄取外来 DNS-SD 应答 + 周期主动枚举，按 (type,instance) 聚合出「网络地图」；`/api/browse` |
| **名称冲突** | `conflict_detect` | 登记本地同名异值的外来记录（RFC 6762 §4 防御观测，LRU + 时效）；`/api/conflicts` |

`/api/status` 的 `insights` 段汇总四项开关与计数。

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

---

## 测试

```bash
./start.sh --test          # = python3 tests/selftest.py --standard-port
```

覆盖：离线报文编解码单测（压缩指针 / QU 位 / known-answer 抑制 / SRV 解析 / 审计环形 / 冲突判定 / 浏览聚合）、
真实组播端到端（收发自证、QU/legacy 单播、热重载改 IP 生效、goodbye、5353 共存）、
管理 API（REST / SSE / 401 鉴权 / 结构化保存→备份→热重载 / 非法配置 400 且不破坏原配置）、
可观测四路由、网关友好页四分支、日志轮转上界。当前全量 **89 passed / 0 failed**。

单独跑：

```bash
python3 tests/selftest.py --offline      # 仅离线报文，不碰组播
python3 tests/selftest.py --standard-port
```

---

## 安全

- **默认仅回环**：控制台默认监听 `127.0.0.1:8765`，局域网不可达。
- **可选鉴权**：设 `management_token` 后所有 API 需 `X-Admin-Token` 头，否则 401。
- **不写系统区**：非 root 安装落 `$HOME`，不碰 `/etc`；systemd 步骤显式需 root。
- **网关不泄栈**：`/go/` 目标不可达返回友好页，异常信息被翻译成一句人话。
- **日志有界**：磁盘占用有硬上界，长期运行不会撑爆硬盘。

---

## 已知边界

- 仅加入 IPv4 组播 `224.0.0.251`，未监听 `ff02::fb`（IPv6-only 客户端无法发现）。
- 名称冲突只做**防御观测登记**（RFC 6762 §4），不做 RFC 6762 的 probing / 强制改名——需保证 `.local` 命名在网内唯一。
- mDNS 只在同网段有效；跨网段 / VPN / 代理环境脆弱，团队级建议内网 DNS。
- 与 Hermes-EAM（Spring Boot）集成：可作独立 sidecar，或引入 JmDNS。

---

## 目录结构

```
mdns-responder/
  config.example.toml   配置模板（入库）
  config.toml           实际运行配置（不入库，含本机 IP / token）
  start.sh              统一启动入口（前台 / 后台 / 校验 / 自测 / 启停）
  install.sh            一键安装脚本（curl | bash）
  src/
    mdns_responder.py   核心：组播 socket + DNS 编解码 + 应答 + 热重载 + 可观测装配
    mdns_insights.py    可观测层：健康探测 / 查询审计 / 服务浏览 / 名称冲突
    admin_server.py     Web 管理 API（ThreadingHTTPServer）+ 友好页 + 网关
    mdns_probe.py       查询探针（调试 / 验证）
  web/admin.html        管理控制台前端（单文件，零外部依赖）
  tests/selftest.py     离线 + 组播端到端 + 管理 API 自测
  deploy/mdns-responder.service   systemd 单元
  logs/                 运行日志 / PID（gitignore）
```

---

## License

MIT（可按需替换）。
