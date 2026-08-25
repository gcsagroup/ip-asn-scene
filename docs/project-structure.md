# 项目目录和文件说明

> 语言 / Language: 简体中文 | [繁體中文](project-structure.zh-Hant.md) | [English](project-structure.en.md) | [返回 README](../README.md)

以下说明以 `IPASN/` 为项目根目录。

## 根目录

```text
README.md
README.zh-Hant.md
README.en.md
.github/workflows/release.yml
.gitattributes
.gitignore
config.yaml.example
generate_firewall.yaml
go.mod
go.sum
```

- `README.md`：简体中文项目入口说明，放快速运行、接口、数据来源和常用命令。
- `README.zh-Hant.md`：繁体中文项目入口说明。
- `README.en.md`：英文项目入口说明。
- `.github/workflows/release.yml`：GitHub Actions 自动发布配置，推送到 `main` 后测试、打 tag、上传多平台单文件可执行程序。
- `.gitattributes`：Git LFS 跟踪规则，当前用于 `data/raw/**` 和 `data/generated/**`。
- `.gitignore`：本机配置、缓存、构建产物和运行日志的忽略规则。
- `config.yaml.example`：配置模板，用于部署时复制和修改。
- `generate_firewall.yaml`：只生成国家、公司、IDC/CDN 等防火墙 CIDR 列表的专用配置。
- `go.mod` / `go.sum`：Go 依赖清单。

以下是常见本机文件，不应提交：

```text
config.yaml
ipasn
bin/
dist/
logs/
```

- `config.yaml`：本机正式配置文件，包含端口、数据源、SSL、AI、IP库等配置，可能包含授权地址或 token。
- `ipasn` / `bin/` / `dist/`：本机和跨平台构建产物，可由 `scripts/build-release.sh` 或 `go build` 重新生成。
- `logs/`：运行日志。

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

- `internal/ai`：低置信度结果的 AI 辅助判断，支持 OpenAI、Anthropic、Gemini 和 OpenAI 兼容服务。
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
- `data/raw/bgp`：全量 BGP 模式下载的 RouteViews / RIPE RIS MRT RIB 原始文件，体积大，默认不提交。
- `data/raw/history`：历史 BGP 样本。
- `data/generated`：自动生成数据。当前可随仓库分发的文件主要是 `services.json` 和 `bgp-observations-full.jsonl.gz`；`bgp-index.bin` 和 `firewall/` 是本机可重建产物，默认不提交。
- `data/processed`：解析状态和清单。`manifest.json` 用于记录当前离线库版本；`download-state.json`、`download-cache/`、`bgp-refresh-state.json` 是本机更新状态缓存，默认不提交。
- `data/cache`：运行时缓存，当前主要是 `data/cache/enrich`，可删除，会自动重建。

仓库提交了一份初始化离线库：`data/raw`、部分 `data/generated`、`data/processed/manifest.json`。其中 `data/raw` 和 `data/generated` 通过 Git LFS 管理，克隆后需要 `git lfs pull` 才能拿到真实数据文件。后台更新只更新本机数据文件，不会自动提交到 GitHub；要发布新的离线库版本时，需要单独检查并提交对应 LFS 文件和 `manifest.json`。

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
docs/deploy.zh-Hant.md
docs/deploy.en.md
docs/api.md
docs/api.zh-Hant.md
docs/api.en.md
docs/configuration.md
docs/configuration.zh-Hant.md
docs/configuration.en.md
docs/project-structure.md
docs/project-structure.zh-Hant.md
docs/project-structure.en.md
```

- `*.md`：简体中文文档。
- `*.zh-Hant.md`：繁体中文文档。
- `*.en.md`：英文文档。
- `deploy.*.md`：Linux / Windows 部署、服务安装、HTTPS、常用命令。
- `api.*.md`：HTTP API 参数、响应字段、在线增强模式、机房/出口、路由安全和数据质量字段说明。
- `configuration.*.md`：配置文件字段说明。
- `project-structure.*.md`：项目目录和文件说明。

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
.gocache
.gomodcache
bin
data/cache
data/evaluation
data/generated/bgp-index.bin
data/generated/firewall
data/processed/bgp-refresh-state.json
data/processed/download-cache
data/processed/download-state.json
data/raw/bgp
dist
ipasn
logs
```

这些文件不应该保留在项目里：

```text
.DS_Store
page-check.png
ipasn.zip
cache/
screenlog.*
```
