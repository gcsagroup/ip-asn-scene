# 项目目录和文件说明

以下说明以 `IPASN/` 为项目根目录。

## 根目录

```text
README.md
config.yaml
config.yaml.example
go.mod
go.sum
ipasn
```

- `README.md`：项目入口说明，放快速运行、接口、数据来源和常用命令。
- `config.yaml`：本机正式配置文件，包含端口、数据源、SSL、AI、IP库等配置。本文件可能包含授权地址，已放入忽略规则。
- `config.yaml.example`：配置模板，用于部署时复制和修改。
- `go.mod` / `go.sum`：Go 依赖清单。
- `ipasn`：本机 macOS 测试用可执行文件，由打包脚本生成。

## cmd

```text
cmd/ipasn/
```

- `main.go`：程序入口，负责读取配置、启动 Web 服务、安装系统服务、启用 SSL。
- `main_test.go`：启动参数和服务安装参数测试。
- `signals_unix.go` / `signals_windows.go`：不同系统下的退出信号处理。

## internal

```text
internal/ai
internal/classify
internal/config
internal/enrich
internal/geo
internal/httpapi
internal/lookup
internal/store
internal/update
```

- `internal/ai`：低置信度结果的 AI 辅助判断，支持 OpenAI 和 Ollama。
- `internal/classify`：应用场景分类规则和规则匹配。
- `internal/config`：配置文件、环境变量、默认值读取。
- `internal/enrich`：Team Cymru、RIPEstat、RDAP、WHOIS 等联网增强查询和缓存。
- `internal/geo`：ip2region 所在地查询。
- `internal/httpapi`：网页和接口处理。
- `internal/lookup`：IP / ASN 查询主流程。
- `internal/store`：离线数据库索引、ASN、网段、历史路由、RPKI、IRR、BGP 多观察点数据结构。
- `internal/update`：离线数据库下载、更新、解析、全量 BGP RIB 汇总和动态规则生成。

每个目录里的 `*_test.go` 是对应模块的测试。

## data

```text
data/raw
data/raw/bgp
data/raw/history
data/generated
data/processed
data/cache
```

- `data/raw`：原始离线数据库，例如 CAIDA、RIR、PeeringDB、IANA RDAP、ip2region、RPKI VRP、IRR route dump、BGP 观察摘要。
- `data/raw/bgp`：全量 BGP 模式下载的 RouteViews / RIPE RIS MRT RIB 原始文件。
- `data/raw/history`：历史 BGP 样本。
- `data/generated`：自动生成的服务规则和 BGP 汇总索引，例如 `services.json`、`bgp-observations-full.jsonl.gz`。
- `data/processed`：解析后生成的索引状态和清单。
- `data/cache`：运行时缓存，当前主要是 `data/cache/enrich`。

`data/cache` 可以删除，服务会重新生成。`data/raw` 体积较大，生产部署时建议保留，避免每次重新下载。

## rules

```text
rules/services.json
rules/asn_scenes.yaml
```

人工维护的离线规则表，适合放公共 DNS、STUN、固定服务 IP、已知业务网段等规则。

- `services.json`：IP / CIDR / RDNS 级服务规则，适合高确定性规则，例如公共 DNS、STUN、官方 CDN/云前缀、Tor、邮件服务。
- `asn_scenes.yaml`：ASN 级场景种子表，适合维护全球 `GOV`、`EDU`、`MOB` 和弱 `DYN` 规则。ASN 规则低于明确服务规则，避免覆盖 DNS/CDN/TOR 等高确定性命中。

## docs

```text
docs/deploy.md
docs/api.md
docs/configuration.md
docs/project-structure.md
```

- `deploy.md`：Linux / Windows 部署、服务安装、HTTPS、常用命令。
- `api.md`：HTTP API 参数、响应字段、在线增强模式、机房/出口、路由安全和数据质量字段说明。
- `configuration.md`：配置文件字段说明。
- `project-structure.md`：项目目录和文件说明。

## scripts

```text
scripts/build-release.sh
scripts/evaluate_ip_coverage.py
```

- `build-release.sh`：编译脚本，会生成本机 macOS 可执行文件，以及 Linux / Windows 单文件。
- `evaluate_ip_coverage.py`：覆盖评估脚本，会生成 IPv4 / IPv6 样本、API 原始结果和 Markdown 评估报告。

## dist

```text
dist/ipasn-darwin-arm64
dist/ipasn-linux-amd64
dist/ipasn-windows-amd64.exe
```

跨平台编译产物。可以删除后重新运行 `scripts/build-release.sh` 生成。

## 可删除目录和文件

这些属于运行或构建产物，可以按需删除：

```text
data/cache
dist
ipasn
```

这些文件不应该保留在项目里：

```text
.DS_Store
page-check.png
ipasn.zip
cache/
```
