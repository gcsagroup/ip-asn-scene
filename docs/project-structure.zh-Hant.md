# 項目目錄和文件說明

> 語言 / Language: [简体中文](project-structure.md) | 繁體中文 | [English](project-structure.en.md) | [返回 README](../README.zh-Hant.md)


以下說明以 `IPASN/` 爲項目根目錄。

## 根目錄

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

- `README.md`：簡體中文項目入口說明，放快速運行、接口、數據來源和常用命令。
- `README.zh-Hant.md`：繁體中文項目入口說明。
- `README.en.md`：英文項目入口說明。
- `.github/workflows/release.yml`：GitHub Actions 自動發佈配置，推送到 `main` 後測試、打 tag、上傳多平臺單文件可執行程序。
- `.gitattributes`：Git LFS 跟蹤規則，當前用於 `data/raw/**` 和 `data/generated/**`。
- `.gitignore`：本機配置、緩存、構建產物和運行日誌的忽略規則。
- `config.yaml.example`：配置模板，用於部署時複製和修改。
- `generate_firewall.yaml`：只生成國家、公司、IDC/CDN 等防火牆 CIDR 列表的專用配置。
- `go.mod` / `go.sum`：Go 依賴清單。

以下是常見本機文件，不應提交：

```text
config.yaml
ipasn
bin/
dist/
logs/
```

- `config.yaml`：本機正式配置文件，包含端口、數據源、SSL、AI、IP庫等配置，可能包含授權地址或 token。
- `ipasn` / `bin/` / `dist/`：本機和跨平臺構建產物，可由 `scripts/build-release.sh` 或 `go build` 重新生成。
- `logs/`：運行日誌。

## cmd

```text
cmd/ipasn/
```

- `main.go`：程序入口，負責讀取配置、啓動 Web 服務、安裝系統服務、啓用 SSL。
- `main_test.go`：啓動參數和服務安裝參數測試。
- `signals_unix.go` / `signals_windows.go`：不同系統下的退出信號處理。

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

- `internal/ai`：低置信度結果的 AI 輔助判斷，支持 OpenAI、Anthropic、Gemini 和 OpenAI 兼容服務。
- `internal/classify`：應用場景分類規則和規則匹配。
- `internal/config`：配置文件、環境變量、默認值讀取。
- `internal/enrich`：Team Cymru、RIPEstat、RDAP、WHOIS 等聯網增強查詢和緩存。
- `internal/geo`：ip2region 所在地查詢。
- `internal/httpapi`：網頁和接口處理。
- `internal/lookup`：IP / ASN 查詢主流程。
- `internal/store`：離線數據庫索引、ASN、網段、歷史路由、RPKI、IRR、BGP 多觀察點數據結構。
- `internal/update`：離線數據庫下載、更新、解析、全量 BGP RIB 彙總和動態規則生成。

每個目錄裏的 `*_test.go` 是對應模塊的測試。

## data

```text
data/raw
data/raw/bgp
data/raw/history
data/generated
data/processed
data/cache
```

- `data/raw`：原始離線數據庫，例如 CAIDA、RIR、PeeringDB、IANA RDAP、ip2region、RPKI VRP、IRR route dump、BGP 觀察摘要。
- `data/raw/bgp`：全量 BGP 模式下載的 RouteViews / RIPE RIS MRT RIB 原始文件，體積大，默認不提交。
- `data/raw/history`：歷史 BGP 樣本。
- `data/generated`：自動生成數據。當前可隨倉庫分發的文件主要是 `services.json` 和 `bgp-observations-full.jsonl.gz`；`bgp-index.bin` 和 `firewall/` 是本機可重建產物，默認不提交。
- `data/processed`：解析狀態和清單。`manifest.json` 用於記錄當前離線庫版本；`download-state.json`、`download-cache/`、`bgp-refresh-state.json` 是本機更新狀態緩存，默認不提交。
- `data/cache`：運行時緩存，當前主要是 `data/cache/enrich`，可刪除，會自動重建。

倉庫提交了一份初始化離線庫：`data/raw`、部分 `data/generated`、`data/processed/manifest.json`。其中 `data/raw` 和 `data/generated` 通過 Git LFS 管理，克隆後需要 `git lfs pull` 才能拿到真實數據文件。後臺更新只更新本機數據文件，不會自動提交到 GitHub；要發佈新的離線庫版本時，需要單獨檢查並提交對應 LFS 文件和 `manifest.json`。

## rules

```text
rules/services.json
rules/asn_scenes.yaml
```

人工維護的離線規則表，適合放公共 DNS、STUN、固定服務 IP、已知業務網段等規則。

- `services.json`：IP / CIDR / RDNS 級服務規則，適合高確定性規則，例如公共 DNS、STUN、官方 CDN/雲前綴、Tor、郵件服務。
- `asn_scenes.yaml`：ASN 級場景種子表，適合維護全球 `GOV`、`EDU`、`MOB` 和弱 `DYN` 規則。ASN 規則低於明確服務規則，避免覆蓋 DNS/CDN/TOR 等高確定性命中。

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

- `*.md`：簡體中文文檔。
- `*.zh-Hant.md`：繁體中文文檔。
- `*.en.md`：英文文檔。
- `deploy.*.md`：Linux / Windows 部署、服務安裝、HTTPS、常用命令。
- `api.*.md`：HTTP API 參數、響應字段、在線增強模式、機房/出口、路由安全和數據質量字段說明。
- `configuration.*.md`：配置文件字段說明。
- `project-structure.*.md`：項目目錄和文件說明。

## scripts

```text
scripts/build-release.sh
scripts/evaluate_ip_coverage.py
```

- `build-release.sh`：編譯腳本，會生成本機 macOS 可執行文件，以及 Linux / Windows 單文件。
- `evaluate_ip_coverage.py`：覆蓋評估腳本，會生成 IPv4 / IPv6 樣本、API 原始結果和 Markdown 評估報告。

## dist

```text
dist/ipasn-darwin-arm64
dist/ipasn-linux-amd64
dist/ipasn-windows-amd64.exe
```

跨平臺編譯產物。可以刪除後重新運行 `scripts/build-release.sh` 生成。

## 可刪除目錄和文件

這些屬於運行或構建產物，可以按需刪除：

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

這些文件不應該保留在項目裏：

```text
.DS_Store
page-check.png
ipasn.zip
cache/
screenlog.*
```
