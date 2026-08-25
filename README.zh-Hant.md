# IP ASN Scene Service

> 語言 / Language: [简体中文](README.md) | 繁體中文 | [English](README.en.md)


輸入 IP 或 ASN，返回 ASN、公司信息、匹配網段、路由狀態、應用場景、判斷依據和可選的 IP 所在地。

當前項目是 Go 服務，README 是項目主要說明入口。倉庫保存源碼、規則、腳本、配置模板、文檔和一份 Git LFS 管理的初始化離線庫；運行緩存、本機配置和編譯產物不進入 Git。

## 當前發佈狀態

截至 2026-08-24，項目已清理爲發佈用結構：

- 源碼、規則、腳本、配置模板、文檔和初始化離線庫保留在倉庫。
- `data/raw` 和需要隨倉庫分發的 `data/generated` 文件使用 Git LFS 管理。
- `config.yaml` 是本機正式配置，可能包含授權地址、後臺 token、證書路徑或 AI key，默認不提交。
- 本機生成內容不提交，包括 `.DS_Store`、`.gocache/`、`.gomodcache/`、`bin/`、`dist/`、`logs/`、`screenlog.*`、`data/cache/`、`data/evaluation/`、`data/generated/firewall/`、`data/generated/bgp-index.bin`、`data/processed/download-cache/`、`data/processed/download-state.json`、`data/processed/bgp-refresh-state.json`。
- 後臺更新只更新當前機器的離線數據；是否把更新後的 `data/raw`、`data/generated/services.json`、`data/generated/bgp-observations-full.jsonl.gz`、`data/processed/manifest.json` 發佈到 GitHub，需要單獨確認。

## 功能

- 支持 IP 查詢和 ASN 查詢
- 支持 IPv4 和 IPv6
- 使用離線庫完成高併發查詢
- 支持自動更新離線數據庫
- 支持 Team Cymru、RIPEstat、RDAP、WHOIS 做當前校驗和補充
- 支持 RIPE RIS AS Path 多點觀察和地理一致性分析
- 支持歷史 BGP 樣本輔助判斷
- 支持 RouteViews / RIPE RIS 全量 RIB 後臺離線構建，多 collector 交叉驗證
- 支持本機配置管理後臺
- 支持本地規則表維護公共 DNS、STUN、爬蟲、郵件、監控、風險網段等服務 IP
- 支持 IP2Proxy 增強 `VPN`、`PROXY`、`TOR`
- 支持 ip2region 返回 IP 所在地
- 支持 IP 質量 / 純淨度評分，輸出風險等級、扣分原因和建議動作
- 支持 OpenAI、Anthropic、Gemini 和 OpenAI 兼容服務，只處理低置信度結果
- 支持 YAML 配置文件
- 支持 HTTPS
- 支持 Linux / Windows 安裝爲系統服務
- 支持編譯爲單文件可執行程序

## 配套產品推薦

[GCSA SentraX](https://sentrax.gcsa.org/zh) 是 GCSA 的即時威脅情報與風險分析產品，用於把域名、IP、哈希、代碼倉庫、MCP 服務、錢包地址和 IoC 等線索關聯起來，輸出帶證據鏈的風險判斷。

IPASN 更適合做高併發、本地離線優先的 IP / ASN / 場景 / 質量判斷；SentraX 更適合做跨線索情報研判、風險畫像和證據鏈分析。需要把 IP 風險結果繼續關聯到域名、倉庫、軟件包行爲、MCP 權限、錢包活動或 IoC 時，推薦把 IPASN 作爲本地基礎識別層，把 SentraX 作爲上層情報分析和研判入口。

## 快速運行

首次克隆後先拉取 Git LFS 數據並生成本機配置：

```bash
git lfs install
git lfs pull
cp config.yaml.example config.yaml
```

下載離線庫並退出：

```bash
go run ./cmd/ipasn -config config.yaml -download-only
```

啓動服務：

```bash
go run ./cmd/ipasn -config config.yaml
```

首次啓動時先更新離線庫：

```bash
go run ./cmd/ipasn -config config.yaml -update-on-start
```

生成防火牆 CIDR 列表：

```bash
go run ./cmd/ipasn -config config.yaml -generate-firewall-lists
go run ./cmd/ipasn -config generate_firewall.yaml -generate-firewall-lists
```

默認會讀取 ip2region IPv4/IPv6 全載庫，結合 ASN、服務規則和本地離線索引，合併相鄰/重疊網段後輸出到 `data/generated/firewall`。該目錄是可重新生成的發佈產物，默認不提交。

所在地查詢已在 `config.yaml` 裏啓用，需要默認顯示時把 `include_default` 改成 `true`。

接口按需顯示所在地時使用 `include_location=1`。

IP 質量 / 純淨度評分默認按需輸出。接口使用 `include_quality=1`，或調用單獨的 `/api/quality`；需要默認輸出時在 `quality.include_default` 裏開啓。

打開頁面：

```text
http://localhost:18080
```

配置管理後臺：

```text
http://localhost:18080/admin
```

## 文檔入口

| 文檔 | 內容 |
| --- | --- |
| [部署文檔](docs/deploy.zh-Hant.md) | Linux / Windows / macOS 部署、服務安裝、HTTPS、離線庫初始化。 |
| [API 文檔](docs/api.zh-Hant.md) | 查詢接口、後臺接口、返回字段、更新接口和狀態字段。 |
| [配置文件說明](docs/configuration.zh-Hant.md) | `config.yaml` 字段、AI、在線增強、BGP、ip2region、動態規則、數據源。 |
| [項目目錄和文件說明](docs/project-structure.zh-Hant.md) | 源碼目錄、規則目錄、數據目錄、緩存目錄、構建產物說明。 |
| [配置模板](config.yaml.example) | 部署時複製爲 `config.yaml` 後填寫本機配置和授權地址。 |

## 接口

完整說明見 [API 文檔](docs/api.zh-Hant.md)。

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

`include_location=1` 會返回 IP 所在地，包含國家、省/州、城市、運營商、國家碼和所在地庫自帶的 ASN。頁面裏勾選“所在地”也是同樣效果。

`include_quality=1` 會返回 `ip_quality`，包含 0-100 評分、A-F 等級、風險等級、建議動作、風險原因、正向信號和分維度評分。頁面裏勾選“IP 質量”也是同樣效果；也可以直接調用 `/api/quality?query=IP`。

`include_performance=1` 會返回 `performance`，包含總耗時、本地離線查詢、在線增強、所在地、質量評分、AI 和第三方在線源耗時。頁面裏勾選“性能”也是同樣效果；第三方明細可用 `include_third_party_timing=0/1` 控制。

`online_enrichment` 支持 `fast`、`wait`、`off`：`fast` 快速返回並後臺刷新，`wait` 等聯網增強完成或超時後返回，`off` 只使用離線庫。

## 數據來源

- CAIDA Prefix2AS：IP 到 ASN 的主離線庫
- CAIDA 歷史 Prefix2AS：歷史 BGP 樣本
- RIR delegated extended：ASN、國家、註冊局和分配狀態
- PeeringDB：ASN 網絡畫像、公開互聯點和機房 presence
- IANA RDAP Bootstrap：RDAP 路由入口
- Team Cymru：當前路由校驗
- RIPEstat：當前宣告校驗
- RIPE RIS：AS Path 多點觀察
- RouteViews / RIPE RIS 全量 RIB：後臺下載公開 MRT，生成本地多觀察點 BGP 摘要
- RPKI VRP：ROA 授權校驗，支持 Routinator / rpki-client / FORT 導出的離線 CSV
- IRR route/route6：IRR 路由對象校驗
- RouteViews / RIPE RIS 摘要：多觀察點 BGP 離線一致性分析
- RDAP / WHOIS：註冊主體、網絡名和描述
- `rules/services.json`：手工維護的離線服務規則
- `data/generated/services.json`：自動生成的動態服務規則
- IP2Proxy：VPN、代理、Tor 增強判斷
- geofeed：RFC 8805 實際所在地增強，查詢時優先於 ip2region
- ip2region：IP 所在地和庫內 ASN / ISP 補充
- `data/generated/firewall`：按國家/地區、公司和場景生成的防火牆 CIDR 列表
- OpenAI / Anthropic / Gemini：低置信度結果輔助判斷；OpenAI 兼容服務可通過自定義 Base URL 接入

查詢結果中的 `egress` 會結合 RIPE RIS AS Path 主上游、PeeringDB IXP / Facility、IP 所在地和註冊信息，給出機房/出口推斷。它會優先按 IP 當前宣告地和所在地匹配機房/IXP；匹配不上時不輸出外地機房，只保留主上游 `TRANSIT` 證據。家庭寬帶、移動網絡、教育/政府/組織機構，以及公共 DNS/CDN 等 Anycast 服務，會避免把主上游 PeeringDB 機房誤當成用戶、基站、校園或辦公出口。低置信度場景會結合主規則、RDAP / WHOIS、AI 和機房/出口信息做加權投票修正；高置信度命中會保留主規則，只把增強信息作爲參考證據。

查詢結果中的 `routing_security` 會結合 RPKI、IRR 和 BGP 多觀察點摘要判斷路由可靠性；`data_quality` 會給出綜合質量評分；`warnings` 會提示 RPKI Invalid、IRR 衝突、MOAS 等風險。

## 緩存和速度

默認查詢不實時解析全量 BGP，也不實時下載公網路由表。全量 BGP 只在後臺更新階段下載 MRT RIB，生成 `data/generated/bgp-observations-full.jsonl.gz` 摘要，並編譯 `data/generated/bgp-index.bin` 緊湊查詢索引；查詢接口優先讀取本地緊湊索引。

IP 查詢優先返回本地離線庫和緩存結果。緩存未命中時，會先給 Team Cymru、RIPEstat、RIPE RIS、RDAP、WHOIS 一個短前臺等待窗口，默認最多 1500ms。

如果在線增強在窗口內完成，首次查詢就會顯示地理不一致和 AS Path。超過窗口後先返回離線結果，後臺繼續刷新並寫入本地緩存，默認保存 7 天；需要調試單個 IP 時，可以把 `enrichment.async_on_miss` 設爲 `false`，讓接口同步等待完整增強結果。

AS Path 多點觀察也會隨聯網增強一起緩存，避免重複訪問 RIPEstat。

反向 DNS 也會做內存緩存，默認保存 7 天，用來減少重複查詢等待。

本地緩存目錄統一放在 `data/cache`。

## 場景類型

| 標識 | 類型 | 說明 |
| --- | --- | --- |
| `CDN` | 內容分發 | CDN 節點或邊緣加速 IP，通常屬於機房、雲廠商或專門的內容分發網絡。 |
| `DNS` | 域名解析 | 公共 DNS、權威 DNS、遞歸 DNS 等域名解析服務 IP。 |
| `EDU` | 教育機構 | 學校、大學、科研教育網絡使用的 IP。 |
| `GTW` | 企業專線 | 企業固定出口、專線出口、中大型公司辦公網絡出口 IP。 |
| `GOV` | 政府機構 | 政府部門、公共機構、政務網絡使用的 IP。 |
| `DYN` | 家庭寬帶 | 家庭住宅寬帶、動態撥號、普通民用網絡出口 IP。 |
| `IDC` | 數據中心 | 機房、雲服務商、VPS、服務器託管、雲主機網絡 IP。 |
| `MOB` | 移動網絡 | 2G / 3G / 4G / 5G 基站出口、移動運營商 NAT 出口 IP。 |
| `ORG` | 組織機構 | 非營利組織、協會、基金會、公共組織使用的 IP。 |
| `NET` | 基礎設施 | 網絡基礎設施 IP，例如路由器、交換設備、傳輸設備、運營商骨幹設施。 |
| `BOGON` | 保留 IP | 私有地址、保留地址、未分配地址、特殊用途地址等公網不可正常路由的 IP。 |
| `UNROUTED` | 已分配未宣告 | 已被註冊局分配，但當前 BGP 數據裏沒有看到有效公網宣告。 |
| `STUN` | NAT 穿透 | STUN / TURN / WebRTC 連通性探測服務 IP。 |
| `VPN` | VPN 服務 | VPN 出口節點、商業 VPN、企業 VPN 或匿名網絡出口。 |
| `PROXY` | 代理服務 | HTTP、SOCKS、透明代理、住宅代理、數據中心代理等出口 IP。 |
| `TOR` | Tor 網絡 | Tor 出口節點或相關匿名網絡出口。 |
| `BOT` | 自動化訪問 | 搜索引擎爬蟲、自動化抓取、平臺機器人等 IP。 |
| `MAIL` | 郵件服務 | SMTP、郵件網關、郵件投遞、雲郵件服務使用的 IP。 |
| `MON` | 監控服務 | 可用性監控、撥測、探針、網站監控平臺使用的 IP。 |
| `IOT` | 物聯網 | 攝像頭、網關、IoT 平臺、設備雲服務或物聯網接入網絡 IP。 |
| `BLOCKLIST` | 風險網段 | 命中公開黑名單、DROP 列表、惡意或高風險網絡的 IP。 |

`scene` 表示技術場景，不直接等同於防火牆處置動作。Apple iCloud Private Relay、Google Fi VPN 這類運營商或系統級消費者隱私服務仍會歸入 `PROXY` / `VPN`，但查詢結果會額外返回 `service_policy`，標記爲正常用戶流量、低風險、默認不建議直接攔截。

## 規則維護

手工規則放在：

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

`rules/asn_scenes.yaml` 用於維護 ASN 級場景種子，適合全球 `GOV`、`EDU`、`MOB` 和弱 `DYN` 規則。明確 IP/CIDR 服務規則優先級高於 ASN 規則，避免公共 DNS、CDN、Tor 等高確定性命中被運營商 ASN 覆蓋。

動態規則會寫入：

```text
data/generated/services.json
```

自動來源覆蓋：

- `BOT`：Google Common Crawlers、Bingbot
- `TOR`：Tor 出口節點
- `MAIL`：常見郵件服務 SPF 記錄
- `MON`：UptimeRobot 監控 IP
- `BLOCKLIST`：Spamhaus DROP、FireHOL level1
- `CDN`：Cloudflare、Fastly、AWS CloudFront 官方 IP 段
- `IDC`：AWS、Google Cloud、Azure、Oracle Cloud 官方 IP 段
- `ORG`：GitHub 官方 Meta IP 段
- `PROXY`：Apple iCloud Private Relay 官方出口 IP 段
- `VPN`：Google Fi VPN、Mullvad、NordVPN、az0/vpn_ip 公開出口/中繼列表
- `PROXY`：可選 FireHOL anonymous 匿名代理聚合列表
- `VPN` / `PROXY` / `TOR`：IP2Proxy 離線庫

其中 FireHOL level1 默認啓用，覆蓋 DShield、Feodo、fullbogons、Spamhaus DROP 等第三方風險源；az0/vpn_ip 默認啓用，用於補充公開 VPN 服務 IP；FireHOL anonymous 體積較大，默認留空，按需啓用。Apple iCloud Private Relay 和 Google Fi VPN 會帶有消費者隱私服務策略元數據；Mullvad、NordVPN、IP2Proxy 等仍按 VPN / PROXY / TOR 風險來源處理，是否攔截應結合業務策略決定。

阿里雲、騰訊雲、華爲雲、火山引擎、網宿等需要賬號或 API 鑑權的來源，當前保留爲後續 provider 插件接入；沒有憑證時先通過 ASN 場景規則、RDAP/WHOIS、BGP 和商業庫增強輔助判斷。`IOT` 可以通過固定 IP、網段或反向 DNS 關鍵詞維護。

## 配置

正式配置寫在 `config.yaml`，模板是 `config.yaml.example`。

詳細說明見 [配置文件說明](docs/configuration.zh-Hant.md)。

`config.yaml` 可能包含商業授權下載地址、後臺 token、證書路徑等本機信息，默認不會提交。倉庫提交了一份初始化離線庫，`data/raw` 和部分 `data/generated` 文件通過 Git LFS 管理；克隆源碼後先執行 `git lfs pull`，即可直接使用隨倉庫帶的離線數據。

後臺更新只更新本機 `data` 文件，不會自動提交到 GitHub。運行緩存、評估輸出、構建產物和本機可執行文件不會提交，包括 `.DS_Store`、`.gocache/`、`.gomodcache/`、`bin/`、`data/cache/`、`data/evaluation/`、`data/generated/firewall/`、`data/generated/bgp-index.bin`、`data/processed/download-cache/`、`data/processed/download-state.json`、`data/processed/bgp-refresh-state.json`、`dist/`、`logs/`、`screenlog.*`、本機 `ipasn` 可執行文件和 zip 歸檔。

## 編譯和服務安裝

編譯本機 macOS、Linux 和 Windows 單文件：

```bash
./scripts/build-release.sh
```

推送到 `main` 後，GitHub Actions 會自動運行測試、創建 `vYYYY.MM.DD-短SHA` tag，併發布 Linux、Windows、macOS 的單文件可執行程序。Release 資產包含 `SHA256SUMS.txt` 校驗和。

安裝爲 Linux / Windows 服務：

```bash
./ipasn -config config.yaml -install-service
```

啓用 HTTPS：

```yaml
tls:
  enabled: true
  cert_file: "certs/server.crt"
  key_file: "certs/server.key"
```

## 驗證

```bash
go test ./... -count=1
go test -race ./...
./scripts/build-release.sh
git lfs fsck
git diff --check
```
