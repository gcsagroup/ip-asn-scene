# IP ASN Scene Service

> 语言 / Language: 简体中文 | [繁體中文](README.zh-Hant.md) | [English](README.en.md)

输入 IP 或 ASN，返回 ASN、公司信息、匹配网段、路由状态、应用场景、判断依据和可选的 IP 所在地。

当前项目是 Go 服务，README 是项目主要说明入口。仓库保存源码、规则、脚本、配置模板、文档和一份 Git LFS 管理的初始化离线库；运行缓存、本机配置和编译产物不进入 Git。

## 当前发布状态

截至 2026-08-24，项目已清理为发布用结构：

- 源码、规则、脚本、配置模板、文档和初始化离线库保留在仓库。
- `data/raw` 和需要随仓库分发的 `data/generated` 文件使用 Git LFS 管理。
- `config.yaml` 是本机正式配置，可能包含授权地址、后台 token、证书路径或 AI key，默认不提交。
- 本机生成内容不提交，包括 `.DS_Store`、`.gocache/`、`.gomodcache/`、`bin/`、`dist/`、`logs/`、`screenlog.*`、`data/cache/`、`data/evaluation/`、`data/generated/firewall/`、`data/generated/bgp-index.bin`、`data/processed/download-cache/`、`data/processed/download-state.json`、`data/processed/bgp-refresh-state.json`。
- 后台更新只更新当前机器的离线数据；是否把更新后的 `data/raw`、`data/generated/services.json`、`data/generated/bgp-observations-full.jsonl.gz`、`data/processed/manifest.json` 发布到 GitHub，需要单独确认。

## 功能

- 支持 IP 查询和 ASN 查询
- 支持 IPv4 和 IPv6
- 使用离线库完成高并发查询
- 支持自动更新离线数据库
- 支持 Team Cymru、RIPEstat、RDAP、WHOIS 做当前校验和补充
- 支持 RIPE RIS AS Path 多点观察和地理一致性分析
- 支持历史 BGP 样本辅助判断
- 支持 RouteViews / RIPE RIS 全量 RIB 后台离线构建，多 collector 交叉验证
- 支持本机配置管理后台
- 支持本地规则表维护公共 DNS、STUN、爬虫、邮件、监控、风险网段等服务 IP
- 支持 IP2Proxy 增强 `VPN`、`PROXY`、`TOR`
- 支持 ip2region 返回 IP 所在地
- 支持 IP 质量 / 纯净度评分，输出风险等级、扣分原因和建议动作
- 支持 OpenAI、Anthropic、Gemini 和 OpenAI 兼容服务，只处理低置信度结果
- 支持 YAML 配置文件
- 支持 HTTPS
- 支持 Linux / Windows 安装为系统服务
- 支持编译为单文件可执行程序

## 配套产品推荐

[GCSA SentraX](https://sentrax.gcsa.org/zh) 是 GCSA 的实时威胁情报与风险分析产品，用于把域名、IP、哈希、代码仓库、MCP 服务、钱包地址和 IoC 等线索关联起来，输出带证据链的风险判断。

IPASN 更适合做高并发、本地离线优先的 IP / ASN / 场景 / 质量判断；SentraX 更适合做跨线索情报研判、风险画像和证据链分析。需要把 IP 风险结果继续关联到域名、仓库、软件包行为、MCP 权限、钱包活动或 IoC 时，推荐把 IPASN 作为本地基础识别层，把 SentraX 作为上层情报分析和研判入口。

## 快速运行

首次克隆后先拉取 Git LFS 数据并生成本机配置：

```bash
git lfs install
git lfs pull
cp config.yaml.example config.yaml
```

下载离线库并退出：

```bash
go run ./cmd/ipasn -config config.yaml -download-only
```

启动服务：

```bash
go run ./cmd/ipasn -config config.yaml
```

首次启动时先更新离线库：

```bash
go run ./cmd/ipasn -config config.yaml -update-on-start
```

生成防火墙 CIDR 列表：

```bash
go run ./cmd/ipasn -config config.yaml -generate-firewall-lists
go run ./cmd/ipasn -config generate_firewall.yaml -generate-firewall-lists
```

默认会读取 ip2region IPv4/IPv6 全载库，结合 ASN、服务规则和本地离线索引，合并相邻/重叠网段后输出到 `data/generated/firewall`。该目录是可重新生成的发布产物，默认不提交。

所在地查询已在 `config.yaml` 里启用，需要默认显示时把 `include_default` 改成 `true`。

接口按需显示所在地时使用 `include_location=1`。

IP 质量 / 纯净度评分默认按需输出。接口使用 `include_quality=1`，或调用单独的 `/api/quality`；需要默认输出时在 `quality.include_default` 里开启。

打开页面：

```text
http://localhost:18080
```

配置管理后台：

```text
http://localhost:18080/admin
```

## 文档入口

| 文档 | 内容 |
| --- | --- |
| [部署文档](docs/deploy.md) | Linux / Windows / macOS 部署、服务安装、HTTPS、离线库初始化。 |
| [API 文档](docs/api.md) | 查询接口、后台接口、返回字段、更新接口和状态字段。 |
| [配置文件说明](docs/configuration.md) | `config.yaml` 字段、AI、在线增强、BGP、ip2region、动态规则、数据源。 |
| [项目目录和文件说明](docs/project-structure.md) | 源码目录、规则目录、数据目录、缓存目录、构建产物说明。 |
| [配置模板](config.yaml.example) | 部署时复制为 `config.yaml` 后填写本机配置和授权地址。 |

## 接口

完整说明见 [API 文档](docs/api.md)。

```text
GET  /api/lookup?query=8.8.8.8
GET  /api/lookup?query=8.8.8.8&include_location=1
GET  /api/lookup?query=8.8.8.8&include_quality=1
GET  /api/lookup?query=8.8.8.8&include_performance=1
GET  /api/lookup?query=8.8.8.8&online_enrichment=wait
GET  /api/lookup?query=AS15169
GET  /api/quality?query=8.8.8.8
GET  /api/health
GET  /api/db/status
POST /api/db/update
GET  /admin
GET  /api/admin/config
PUT  /api/admin/config
POST /api/admin/ai/models
GET  /api/admin/status
POST /api/admin/update
```

`include_location=1` 会返回 IP 所在地，包含国家、省/州、城市、运营商、国家码和所在地库自带的 ASN。页面里勾选“所在地”也是同样效果。

`include_quality=1` 会返回 `ip_quality`，包含 0-100 评分、A-F 等级、风险等级、建议动作、风险原因、正向信号和分维度评分。页面里勾选“IP 质量”也是同样效果；也可以直接调用 `/api/quality?query=IP`。

`include_performance=1` 会返回 `performance`，包含总耗时、本地离线查询、在线增强、所在地、质量评分、AI 和第三方在线源耗时。页面里勾选“性能”也是同样效果；第三方明细可用 `include_third_party_timing=0/1` 控制。

`online_enrichment` 支持 `fast`、`wait`、`off`：`fast` 快速返回并后台刷新，`wait` 等联网增强完成或超时后返回，`off` 只使用离线库。

## 数据来源

- CAIDA Prefix2AS：IP 到 ASN 的主离线库
- CAIDA 历史 Prefix2AS：历史 BGP 样本
- RIR delegated extended：ASN、国家、注册局和分配状态
- PeeringDB：ASN 网络画像、公开互联点和机房 presence
- IANA RDAP Bootstrap：RDAP 路由入口
- Team Cymru：当前路由校验
- RIPEstat：当前宣告校验
- RIPE RIS：AS Path 多点观察
- RouteViews / RIPE RIS 全量 RIB：后台下载公开 MRT，生成本地多观察点 BGP 摘要
- RPKI VRP：ROA 授权校验，支持 Routinator / rpki-client / FORT 导出的离线 CSV
- IRR route/route6：IRR 路由对象校验
- RouteViews / RIPE RIS 摘要：多观察点 BGP 离线一致性分析
- RDAP / WHOIS：注册主体、网络名和描述
- `rules/services.json`：手工维护的离线服务规则
- `data/generated/services.json`：自动生成的动态服务规则
- IP2Proxy：VPN、代理、Tor 增强判断
- geofeed：RFC 8805 实际所在地增强，查询时优先于 ip2region
- ip2region：IP 所在地和库内 ASN / ISP 补充
- `data/generated/firewall`：按国家/地区、公司和场景生成的防火墙 CIDR 列表
- OpenAI / Anthropic / Gemini：低置信度结果辅助判断；OpenAI 兼容服务可通过自定义 Base URL 接入

查询结果中的 `egress` 会结合 RIPE RIS AS Path 主上游、PeeringDB IXP / Facility、IP 所在地和注册信息，给出机房/出口推断。它会优先按 IP 当前宣告地和所在地匹配机房/IXP；匹配不上时不输出外地机房，只保留主上游 `TRANSIT` 证据。家庭宽带、移动网络、教育/政府/组织机构，以及公共 DNS/CDN 等 Anycast 服务，会避免把主上游 PeeringDB 机房误当成用户、基站、校园或办公出口。低置信度场景会结合主规则、RDAP / WHOIS、AI 和机房/出口信息做加权投票修正；高置信度命中会保留主规则，只把增强信息作为参考证据。

查询结果中的 `routing_security` 会结合 RPKI、IRR 和 BGP 多观察点摘要判断路由可靠性；`data_quality` 会给出综合质量评分；`warnings` 会提示 RPKI Invalid、IRR 冲突、MOAS 等风险。

## 缓存和速度

默认查询不实时解析全量 BGP，也不实时下载公网路由表。全量 BGP 只在后台更新阶段下载 MRT RIB，生成 `data/generated/bgp-observations-full.jsonl.gz` 摘要，并编译 `data/generated/bgp-index.bin` 紧凑查询索引；查询接口优先读取本地紧凑索引。

IP 查询优先返回本地离线库和缓存结果。缓存未命中时，会先给 Team Cymru、RIPEstat、RIPE RIS、RDAP、WHOIS 一个短前台等待窗口，默认最多 1500ms。

如果在线增强在窗口内完成，首次查询就会显示地理不一致和 AS Path。超过窗口后先返回离线结果，后台继续刷新并写入本地缓存，默认保存 7 天；需要调试单个 IP 时，可以把 `enrichment.async_on_miss` 设为 `false`，让接口同步等待完整增强结果。

AS Path 多点观察也会随联网增强一起缓存，避免重复访问 RIPEstat。

反向 DNS 也会做内存缓存，默认保存 7 天，用来减少重复查询等待。

本地缓存目录统一放在 `data/cache`。

## 场景类型

| 标识 | 类型 | 说明 |
| --- | --- | --- |
| `CDN` | 内容分发 | CDN 节点或边缘加速 IP，通常属于机房、云厂商或专门的内容分发网络。 |
| `DNS` | 域名解析 | 公共 DNS、权威 DNS、递归 DNS 等域名解析服务 IP。 |
| `EDU` | 教育机构 | 学校、大学、科研教育网络使用的 IP。 |
| `GTW` | 企业专线 | 企业固定出口、专线出口、中大型公司办公网络出口 IP。 |
| `GOV` | 政府机构 | 政府部门、公共机构、政务网络使用的 IP。 |
| `DYN` | 家庭宽带 | 家庭住宅宽带、动态拨号、普通民用网络出口 IP。 |
| `IDC` | 数据中心 | 机房、云服务商、VPS、服务器托管、云主机网络 IP。 |
| `MOB` | 移动网络 | 2G / 3G / 4G / 5G 基站出口、移动运营商 NAT 出口 IP。 |
| `ORG` | 组织机构 | 非营利组织、协会、基金会、公共组织使用的 IP。 |
| `NET` | 基础设施 | 网络基础设施 IP，例如路由器、交换设备、传输设备、运营商骨干设施。 |
| `BOGON` | 保留 IP | 私有地址、保留地址、未分配地址、特殊用途地址等公网不可正常路由的 IP。 |
| `UNROUTED` | 已分配未宣告 | 已被注册局分配，但当前 BGP 数据里没有看到有效公网宣告。 |
| `STUN` | NAT 穿透 | STUN / TURN / WebRTC 连通性探测服务 IP。 |
| `VPN` | VPN 服务 | VPN 出口节点、商业 VPN、企业 VPN 或匿名网络出口。 |
| `PROXY` | 代理服务 | HTTP、SOCKS、透明代理、住宅代理、数据中心代理等出口 IP。 |
| `TOR` | Tor 网络 | Tor 出口节点或相关匿名网络出口。 |
| `BOT` | 自动化访问 | 搜索引擎爬虫、自动化抓取、平台机器人等 IP。 |
| `MAIL` | 邮件服务 | SMTP、邮件网关、邮件投递、云邮件服务使用的 IP。 |
| `MON` | 监控服务 | 可用性监控、拨测、探针、网站监控平台使用的 IP。 |
| `IOT` | 物联网 | 摄像头、网关、IoT 平台、设备云服务或物联网接入网络 IP。 |
| `BLOCKLIST` | 风险网段 | 命中公开黑名单、DROP 列表、恶意或高风险网络的 IP。 |

`scene` 表示技术场景，不直接等同于防火墙处置动作。Apple iCloud Private Relay、Google Fi VPN 这类运营商或系统级消费者隐私服务仍会归入 `PROXY` / `VPN`，但查询结果会额外返回 `service_policy`，标记为正常用户流量、低风险、默认不建议直接拦截。

## 规则维护

手工规则放在：

```text
rules/services.json
rules/asn_scenes.yaml
```

示例：

```json
{
  "id": "stun-example",
  "name": "Example STUN",
  "scene": "STUN",
  "scene_name": "NAT 穿透",
  "confidence": 0.99,
  "prefixes": ["203.0.113.10/32"],
  "rdns_contains": ["stun.example.com"]
}
```

`rules/asn_scenes.yaml` 用于维护 ASN 级场景种子，适合全球 `GOV`、`EDU`、`MOB` 和弱 `DYN` 规则。明确 IP/CIDR 服务规则优先级高于 ASN 规则，避免公共 DNS、CDN、Tor 等高确定性命中被运营商 ASN 覆盖。

动态规则会写入：

```text
data/generated/services.json
```

自动来源覆盖：

- `BOT`：Google Common Crawlers、Bingbot
- `TOR`：Tor 出口节点
- `MAIL`：常见邮件服务 SPF 记录
- `MON`：UptimeRobot 监控 IP
- `BLOCKLIST`：Spamhaus DROP、FireHOL level1
- `CDN`：Cloudflare、Fastly、AWS CloudFront 官方 IP 段
- `IDC`：AWS、Google Cloud、Azure、Oracle Cloud 官方 IP 段
- `ORG`：GitHub 官方 Meta IP 段
- `PROXY`：Apple iCloud Private Relay 官方出口 IP 段
- `VPN`：Google Fi VPN、Mullvad、NordVPN、az0/vpn_ip 公开出口/中继列表
- `PROXY`：可选 FireHOL anonymous 匿名代理聚合列表
- `VPN` / `PROXY` / `TOR`：IP2Proxy 离线库

其中 FireHOL level1 默认启用，覆盖 DShield、Feodo、fullbogons、Spamhaus DROP 等第三方风险源；az0/vpn_ip 默认启用，用于补充公开 VPN 服务 IP；FireHOL anonymous 体积较大，默认留空，按需启用。Apple iCloud Private Relay 和 Google Fi VPN 会带有消费者隐私服务策略元数据；Mullvad、NordVPN、IP2Proxy 等仍按 VPN / PROXY / TOR 风险来源处理，是否拦截应结合业务策略决定。

阿里云、腾讯云、华为云、火山引擎、网宿等需要账号或 API 鉴权的来源，当前保留为后续 provider 插件接入；没有凭证时先通过 ASN 场景规则、RDAP/WHOIS、BGP 和商业库增强辅助判断。`IOT` 可以通过固定 IP、网段或反向 DNS 关键词维护。

## 配置

正式配置写在 `config.yaml`，模板是 `config.yaml.example`。

详细说明见 [配置文件说明](docs/configuration.md)。

`config.yaml` 可能包含商业授权下载地址、后台 token、证书路径等本机信息，默认不会提交。仓库提交了一份初始化离线库，`data/raw` 和部分 `data/generated` 文件通过 Git LFS 管理；克隆源码后先执行 `git lfs pull`，即可直接使用随仓库带的离线数据。

后台更新只更新本机 `data` 文件，不会自动提交到 GitHub。运行缓存、评估输出、构建产物和本机可执行文件不会提交，包括 `.DS_Store`、`.gocache/`、`.gomodcache/`、`bin/`、`data/cache/`、`data/evaluation/`、`data/generated/firewall/`、`data/generated/bgp-index.bin`、`data/processed/download-cache/`、`data/processed/download-state.json`、`data/processed/bgp-refresh-state.json`、`dist/`、`logs/`、`screenlog.*`、本机 `ipasn` 可执行文件和 zip 归档。

## 编译和服务安装

编译本机 macOS、Linux 和 Windows 单文件：

```bash
./scripts/build-release.sh
```

推送到 `main` 后，GitHub Actions 会自动运行测试、创建 `vYYYY.MM.DD-短SHA` tag，并发布 Linux、Windows、macOS 的单文件可执行程序。Release 资产包含 `SHA256SUMS.txt` 校验和。

安装为 Linux / Windows 服务：

```bash
./ipasn -config config.yaml -install-service
```

启用 HTTPS：

```yaml
tls:
  enabled: true
  cert_file: "certs/server.crt"
  key_file: "certs/server.key"
```

## 验证

```bash
go test ./... -count=1
go test -race ./...
./scripts/build-release.sh
git lfs fsck
git diff --check
```

## 许可证

本项目使用 [MIT License](LICENSE) 发布。
