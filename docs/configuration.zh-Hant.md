# 配置文件說明

> 語言 / Language: [简体中文](configuration.md) | 繁體中文 | [English](configuration.en.md) | [返回 README](../README.zh-Hant.md)


默認配置文件名：

```text
config.yaml
```

啓動時指定：

```bash
./ipasn -config config.yaml
```

配置文件會先加載，環境變量和命令行參數可以覆蓋配置文件裏的值。

## 基礎配置

```yaml
addr: ":18080"
data_dir: "data"
rules_file: "rules/services.json"
asn_rules_file: "rules/asn_scenes.yaml"
update_interval_hours: 24
http_timeout_seconds: 90
```

- `addr`：監聽地址和端口。
- `data_dir`：離線數據庫目錄。
- `rules_file`：人工維護規則文件。
- `asn_rules_file`：ASN 場景規則文件，用於維護全球 `GOV`、`EDU`、`MOB` 和弱 `DYN` 種子規則。
- `update_interval_hours`：後臺自動更新間隔。設爲 `0` 可關閉定時更新。
- `http_timeout_seconds`：下載、聯網校驗和關閉服務的超時時間。

## HTTPS

```yaml
tls:
  enabled: false
  cert_file: "certs/server.crt"
  key_file: "certs/server.key"
```

- `enabled`：是否啓用 HTTPS。
- `cert_file`：證書文件。
- `key_file`：私鑰文件。

## AI

```yaml
ai:
  provider: "auto"
  openai_api_key: ""
  openai_model: "gpt-5.4-mini"
  openai_base_url: "https://api.openai.com/v1"
  openai_api_type: "responses"
  anthropic_api_key: ""
  anthropic_model: "claude-sonnet-4-6"
  anthropic_base_url: "https://api.anthropic.com"
  anthropic_version: "2023-06-01"
  gemini_api_key: ""
  gemini_model: "gemini-2.5-flash"
  gemini_base_url: "https://generativelanguage.googleapis.com/v1beta"
  confidence_cutoff: 0.7
  timeout_seconds: 8
  max_cache: 2048
```

- `provider`：`auto`、`off`、`openai`、`anthropic`、`gemini`。
- `confidence_cutoff`：低於這個置信度時才調用 AI。
- `openai_api_key`：OpenAI key，也可以繼續用環境變量 `OPENAI_API_KEY`。
- `openai_api_type`：`responses` 調用 `/v1/responses`；`chat_completions` 調用 `/v1/chat/completions`，適合 OpenAI 兼容服務。
- `anthropic_api_key` / `gemini_api_key`：分別對應 Anthropic 和 Gemini key，也可以用環境變量配置。

## 在線增強和緩存

```yaml
enrichment:
  enabled: true
  ttl_hours: 168
  timeout_seconds: 8
  async_on_miss: true
  foreground_timeout_ms: 1500
```

- `enabled`：啓用 Team Cymru、RIPEstat、RDAP、WHOIS 等當前校驗。
- `ttl_hours`：聯網查詢結果緩存時間。
- `timeout_seconds`：單次增強查詢超時時間。
- `async_on_miss`：緩存未命中時是否先返回離線結果，再後臺刷新在線增強。生產環境建議保持 `true`；排查單個 IP 時可以臨時設爲 `false` 同步等待完整結果。
- `foreground_timeout_ms`：緩存未命中時，前臺最多等待在線增強的時間。默認 `1500` 毫秒；如果 Team Cymru / RDAP / WHOIS / BGP 在這個窗口內完成，首次查詢就會顯示地理不一致和 AS Path。超過窗口後先返回離線結果，後臺繼續補全緩存。

聯網增強緩存統一保存在：

```text
data/cache/enrich
```

緩存內容包含 Team Cymru、RIPEstat 當前宣告、RIPE RIS AS Path、RDAP、WHOIS 和地理一致性分析。普通查詢會複用緩存結果；緩存未命中時會先短暫等待在線增強，超過前臺等待窗口後再返回本地離線判斷並後臺補全。

地理一致性分析會輸出：

- 註冊地：RDAP / WHOIS 的國家或地區。
- 宣告地：Team Cymru / BGP origin ASN 的國家或地區。
- 所在地：ip2region 返回的國家碼。
- BGP 路徑：RIPE RIS 多個觀察點看到的 AS Path、主上游 ASN、採集點數量。
- 衝突結論：註冊地、宣告地、所在地不一致時會標記爲衝突。

## 歷史路由

```yaml
history:
  snapshots: 4
```

- `snapshots`：保留最近幾個歷史 BGP 樣本。

## 全量 BGP 離線模式

```yaml
bgp:
  enabled: true
  mode: "full"
  routeviews_enabled: true
  ripe_ris_enabled: true
  collectors:
    - "all"
  include_updates: false
  history_snapshots: 7
  refresh_hours: 8
  max_parallel_downloads: 4
  download_timeout_seconds: 7200
  max_parallel_parse: 2
  keep_raw: true
  raw_retention_days: 30
  summary_file: "data/generated/bgp-observations-full.jsonl.gz"
  index_mode: "compact"
  index_file: "data/generated/bgp-index.bin"
  routeviews_base_url: "https://archive.routeviews.org/"
  ripe_ris_base_url: "https://data.ris.ripe.net/"
```

- `enabled`：是否啓用全量 BGP 離線構建。
- `mode`：當前支持 `full`，表示後臺下載 RIPE RIS 和 RouteViews collector 的最新 RIB。
- `routeviews_enabled` / `ripe_ris_enabled`：分別控制 RouteViews 和 RIPE RIS。
- `collectors`：`all` 表示自動發現全部 collector；也可以填寫 `rrc00`、`route-views.sg` 等指定 collector。
- `include_updates`：預留給 MRT UPDATE 增量流，當前默認關閉；第一版使用最新 RIB 和歷史快照。
- `history_snapshots`：全量 BGP 摘要的歷史快照保留數量預留項。
- `refresh_hours`：建議與 RIPE RIS dump 週期一致或更長，默認 8 小時。
- `max_parallel_downloads` / `max_parallel_parse`：後臺下載和解析併發上限。
- `download_timeout_seconds`：單個 RouteViews / RIPE RIS MRT RIB 大文件下載超時，默認 `7200` 秒。這個值隻影響全量 BGP 原始 RIB 下載，不影響普通查詢和在線增強超時。
- `keep_raw`：是否保留下載後的 MRT 原始文件。
- `raw_retention_days`：原始 BGP 文件保留天數。
- `summary_file`：生成的 BGP 多觀察點摘要，作爲後臺編譯緊湊索引的中間文件，也可作爲舊版 JSONL 兼容回退。
- `index_mode`：BGP 查詢索引模式，默認 `compact`。設爲 `jsonl` 時跳過緊湊索引，直接加載 `summary_file`；設爲 `off` 時不加載 BGP 多觀察點摘要。
- `index_file`：緊湊 BGP 查詢索引文件。後臺更新會在摘要生成或摘要已存在但索引缺失/過期時自動編譯它，查詢服務優先加載這個文件以降低啓動解析成本和內存佔用。
- `routeviews_base_url` / `ripe_ris_base_url`：公開離線 RIB 源地址。

全量 BGP 會明顯增加後臺更新時間和磁盤佔用，但不會讓普通查詢實時訪問公網。默認查詢路徑讀取 `index_file` 緊湊索引；索引不存在且未禁用時，後臺更新會從 `summary_file` 本地補齊，不需要重新下載 RIB。

`index_file` 是本機可重建索引，默認不提交到 Git。需要讓其他機器直接使用緊湊索引時，應把它作爲獨立部署資產分發，或在目標機器上執行一次離線庫更新生成。

## 下載狀態緩存

後臺更新會維護 `data/processed/download-state.json`，記錄公開源 URL、`ETag`、`Last-Modified`、`SHA256`、本地緩存文件和下載時間。再次更新同一 URL 時會發送 `If-None-Match` / `If-Modified-Since`；源站返回 `304 Not Modified` 時直接複用本地文件，不再重複下載 body。沒有提供 `ETag` / `Last-Modified` 的源，會在短時間內複用本地緩存，避免連續點擊造成重複拉取。

`download-state.json`、`download-cache/` 和 `bgp-refresh-state.json` 是本機更新狀態緩存，默認不提交。發佈新的初始化離線庫時，只提交需要分發的原始庫、生成庫和 `manifest.json`。

## 配置管理後臺

```yaml
admin:
  enabled: true
  path: "/admin"
  token: ""
  local_only: true
```

- `enabled`：是否啓用配置管理後臺。
- `path`：後臺訪問路徑。
- `token`：管理 API token。爲空時不校驗 token；公網部署時應設置。
- `local_only`：只允許本機訪問後臺。生產環境建議保持 `true` 或配合反向代理鑑權。

後臺地址默認是：

```text
http://127.0.0.1:18080/admin
```

後臺可以查看和保存 BGP 配置、觸發離線庫更新、查看數據庫狀態。保存配置會寫回 `config.yaml`；監聽端口、TLS 等啓動級配置需要重啓後生效。

## IP 質量評分

```yaml
quality:
  enabled: true
  include_default: false
  ai_low_confidence: true
  low_confidence_threshold: 0.6
  allow_score: 80
  review_score: 60
  challenge_score: 40
  rate_limit_score: 20
```

- `enabled`：是否啓用 IP 質量 / 純淨度評分。
- `include_default`：是否默認在 `/api/lookup` 輸出 `ip_quality`。關閉時可通過 `include_quality=1` 或 `/api/quality` 獲取。
- `ai_low_confidence`：預留給低置信度結果的 AI 輔助開關；第一版評分主邏輯仍以離線規則和多源證據爲準。
- `low_confidence_threshold`：低置信度閾值。
- `allow_score`、`review_score`、`challenge_score`、`rate_limit_score`：建議動作閾值。低於 `rate_limit_score` 時建議 `block`。

評分結果中的 `score` 爲 0-100，越高越乾淨；`recommendation` 是策略建議，不會直接改變 `scene`。

## 性能指標

```yaml
performance:
  enabled: true
  include_default: false
  third_party_default: true
```

- `enabled`：是否允許 `/api/lookup` 輸出性能指標。關閉後即使傳 `include_performance=1` 也不會輸出。
- `include_default`：是否默認輸出 `performance`。關閉時可通過 `include_performance=1` 按需返回。
- `third_party_default`：是否默認輸出 `performance.third_party`，包括 Team Cymru、RIPEstat、RDAP、WHOIS、RIPE RIS 等在線源的單獨耗時。可用 `include_third_party_timing=0/1` 覆蓋。

建議生產環境保持 `include_default: false`，需要排查慢查詢時再在前臺勾選“性能”或傳 API 參數。

## 動態規則

```yaml
dynamic_rules:
  enabled: true
  file: "data/generated/services.json"
  google_crawler_url: "https://developers.google.com/static/crawling/ipranges/common-crawlers.json"
  bingbot_url: "https://www.bing.com/toolbox/bingbot.json"
  tor_exit_url: "https://check.torproject.org/torbulkexitlist"
  uptimerobot_ip_url: "https://cdn.uptimerobot.com/api/IPv4andIPv6.txt"
  spamhaus_drop_v4_url: "https://www.spamhaus.org/drop/drop_v4.json"
  spamhaus_drop_v6_url: "https://www.spamhaus.org/drop/drop_v6.json"
  firehol_level1_url: "https://iplists.firehol.org/files/firehol_level1.netset"
  firehol_anonymous_url: ""
  az0_vpn_ip_url: "https://az0-vpnip-public.oooninja.com/ip.txt"
  cloudflare_v4_url: "https://www.cloudflare.com/ips-v4"
  cloudflare_v6_url: "https://www.cloudflare.com/ips-v6"
  fastly_url: "https://api.fastly.com/public-ip-list"
  aws_ip_ranges_url: "https://ip-ranges.amazonaws.com/ip-ranges.json"
  google_cloud_ip_ranges_url: "https://www.gstatic.com/ipranges/cloud.json"
  azure_service_tags_url: "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519"
  oracle_ip_ranges_url: "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json"
  github_meta_url: "https://api.github.com/meta"
  apple_private_relay_url: "https://mask-api.icloud.com/egress-ip-ranges.csv"
  google_fi_vpn_geofeed_url: "https://www.gstatic.com/fi/bridge/ipgeofeed.txt"
  mullvad_relays_url: "https://api.mullvad.net/www/relays/all/"
  nordvpn_servers_url: "https://api.nordvpn.com/v1/servers"
  mail_spf_domains:
    - "_spf.google.com"
    - "spf.protection.outlook.com"
  ip2proxy:
    enabled: true
    package: "PX11"
    token: ""
    local_files: []
    download_urls: []
```

- `file`：自動生成規則保存位置。
- `cloudflare_v4_url` / `cloudflare_v6_url`：Cloudflare 官方 CDN IP 段，生成 `CDN` 規則。
- `fastly_url`：Fastly 官方 public IP list，生成 `CDN` 規則。
- `aws_ip_ranges_url`：AWS 官方 IP 段，生成 AWS 總體 `IDC` 規則，並把 `CLOUDFRONT` service 單獨生成高置信度 `CDN` 規則。
- `google_cloud_ip_ranges_url`、`azure_service_tags_url`、`oracle_ip_ranges_url`：雲廠商官方 IP 段，生成 `IDC` 規則。
- `github_meta_url`：GitHub 官方 Meta IP 段，生成 `ORG` 規則。
- `firehol_level1_url`：FireHOL level1 聚合風險網段，包含 DShield、Feodo、fullbogons、Spamhaus DROP 等來源，生成 `BLOCKLIST` 規則。
- `firehol_anonymous_url`：FireHOL anonymous 匿名代理/Tor 聚合網段，生成 `PROXY` 規則。該列表體積很大，默認留空，只有需要擴大匿名代理覆蓋時再啓用。
- `az0_vpn_ip_url`：az0/vpn_ip 公開 VPN IP 列表，生成 `VPN` 規則。該來源覆蓋 ProtonVPN、Windscribe、Browsec、VeePN、Hoxx 等公開整理的 VPN / Proxy 服務 IP。
- `apple_private_relay_url`：Apple iCloud Private Relay 官方出口 CSV，生成高置信度 `PROXY` 規則。該列表較大，程序會先合併相鄰 CIDR 再寫入規則文件。
- `google_fi_vpn_geofeed_url`：Google Fi VPN geofeed，生成 `VPN` 規則。
- `mullvad_relays_url`：Mullvad relay API，生成 active relay 的 `VPN` 規則。
- `nordvpn_servers_url`：NordVPN servers API，生成在線服務器的 `VPN` 規則；不需要該第三方來源時可以置空。
- `mail_spf_domains`：郵件服務域名，程序會解析 SPF 生成郵件 IP 規則。
- `ip2proxy.local_files`：本地 IP2Proxy 文件。
- `ip2proxy.download_urls`：完整下載地址。
- `ip2proxy.token` 和 `package`：商業增強下載參數。

## ip2region

```yaml
ip2region:
  enabled: true
  include_default: false
  v4_file: "data/raw/ip2region_v4.xdb"
  v6_file: "data/raw/ip2region_v6.xdb"
  v4_version_url: "你的IPv4版本檢查API"
  v4_download_url: "你的IPv4全載下載API"
  v6_version_url: "你的IPv6版本檢查API"
  v6_download_url: "你的IPv6全載下載API"
```

- `enabled`：啓用所在地查詢。
- `include_default`：頁面和接口默認返回所在地。關閉後可用 `include_location=1` 按需返回。
- `v4_file` / `v6_file`：本地 xdb 文件。
- `v4_version_url` / `v6_version_url`：版本檢查地址。
- `v4_download_url` / `v6_download_url`：全載下載地址，商業版可填授權後的全載鏈接。

## 防火牆列表生成

```yaml
firewall_lists:
  enabled: true
  output_dir: "data/generated/firewall"
  countries: []
  companies: ["alibaba", "tencent", "cloudflare", "google", "aws", "azure"]
  scenes: ["IDC", "CDN", "TOR", "PROXY", "BLOCKLIST"]
  min_confidence: 0.8
  include_ipv4: true
  include_ipv6: true
  write_entries: false
```

執行：

```bash
./ipasn -config config.yaml -generate-firewall-lists
```

- `output_dir`：輸出目錄。
- `countries`：國家/地區代碼列表，例如 `CN`、`US`、`SG`。爲空表示按 ip2region 裏出現的全部國家/地區生成 `country-XX.cidr`。
- `companies`：要生成的公司列表。公司列表需要顯式配置，避免按全量 ASN/ISP 生成過多文件。
- `scenes`：要生成的場景列表，例如 `IDC`、`CDN`、`TOR`、`PROXY`。
- `min_confidence`：低於該置信度的記錄不會進入輸出。
- `include_ipv4` / `include_ipv6`：控制是否生成 IPv4 / IPv6 CIDR。默認兩個都開啓。
- `write_entries`：是否輸出 `entries.jsonl` 明細。默認關閉，需要審計每條命中來源時再開啓。

輸出文件示例：

```text
data/generated/firewall/index.json
data/generated/firewall/country-CN.cidr
data/generated/firewall/company-alibaba.cidr
data/generated/firewall/scene-IDC.cidr
data/generated/firewall/scene-TOR.cidr
```

開啓 `write_entries` 後會額外輸出 `data/generated/firewall/entries.jsonl`。

生成器會對同一個輸出文件裏的相鄰/重疊網段做合併，最終文件包含 IPv4 和 IPv6 CIDR。地區列表主要來自 ip2region 全量庫；公司和場景會結合 ip2region 的 `ISP` / `ASN` 字段、ASN 信息、離線服務規則和場景規則生成。`TOR` / `PROXY` 更依賴 Tor / IP2Proxy 等專用離線來源，ip2region 只補充所在地和 ASN 信息。

`output_dir` 是可重建輸出目錄，默認不提交到 Git。需要給防火牆系統使用時，建議從部署機直接生成，或把生成結果作爲單獨發佈包分發。

## 數據源

```yaml
sources:
  caida_v4_log_url: "https://data.caida.org/datasets/routing/routeviews-prefix2as/pfx2as-creation.log"
  caida_v4_base_url: "https://data.caida.org/datasets/routing/routeviews-prefix2as/"
  caida_v6_log_url: "https://data.caida.org/datasets/routing/routeviews6-prefix2as/pfx2as-creation.log"
  caida_v6_base_url: "https://data.caida.org/datasets/routing/routeviews6-prefix2as/"
  peeringdb_url: "https://www.peeringdb.com/api/net?fields=asn,name,aka,info_type,website"
  peeringdb_ix_url: "https://www.peeringdb.com/api/ix?fields=id,name,country,city"
  peeringdb_netixlan_url: "https://www.peeringdb.com/api/netixlan?fields=asn,ix_id,name,ipaddr4,ipaddr6,speed"
  peeringdb_facility_url: "https://www.peeringdb.com/api/fac?fields=id,name,country,city"
  peeringdb_netfac_url: "https://www.peeringdb.com/api/netfac?fields=local_asn,fac_id"
  rir_urls:
    afrinic: "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest"
    apnic: "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest"
    arin: "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest"
    lacnic: "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest"
    ripencc: "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest"
  iana_rdap_urls:
    asn: "https://data.iana.org/rdap/asn.json"
    ipv4: "https://data.iana.org/rdap/ipv4.json"
    ipv6: "https://data.iana.org/rdap/ipv6.json"
  rpki_vrp_urls:
    - "https://console.rpki-client.org/vrps.csv"
  irr_route_urls:
    - "https://ftp.ripe.net/ripe/dbase/split/ripe.db.route.gz"
    - "https://ftp.ripe.net/ripe/dbase/split/ripe.db.route6.gz"
    - "https://ftp.ripe.net/ripe/dbase/split/ripe-nonauth.db.route.gz"
    - "https://ftp.ripe.net/ripe/dbase/split/ripe-nonauth.db.route6.gz"
    - "https://ftp.apnic.net/apnic/whois/apnic.db.route.gz"
    - "https://ftp.apnic.net/apnic/whois/apnic.db.route6.gz"
    - "https://ftp.afrinic.net/dbase/afrinic.db.gz"
  bgp_observation_urls: []
  geofeed_urls:
    - "https://opengeofeed.org/feed/public.csv"
```

這些地址一般保持默認即可。`peeringdb_ix_url`、`peeringdb_netixlan_url`、`peeringdb_facility_url`、`peeringdb_netfac_url` 用於構建 ASN 的公開互聯點和機房 presence，查詢時會結合 AS Path 推斷機房/出口信息。

增強可靠性源爲可選項：

- `rpki_vrp_urls`：Routinator、rpki-client 或 FORT 導出的 VRP CSV。默認使用 `rpki-client` 公共控制檯 CSV；生產環境也可以換成本機 Routinator `/csv`。也可以手動放到 `data/raw/rpki-vrps*.csv`。
- `irr_route_urls`：IRR RPSL dump，解析 `route` / `route6`、`origin`、`source`。默認預置 RIPE、RIPE-NONAUTH、APNIC、AFRINIC 的 HTTP(S) dump。RADb 官方主要提供 FTP dump，當前下載器不直接寫入默認 URL，可手動轉存到 `data/raw/irr-routes*`。
- `bgp_observation_urls`：預處理後的 RouteViews / RIPE RIS 多觀察點摘要，支持 JSONL 或 CSV。全量 BGP 模式會生成 `data/generated/bgp-observations-full.jsonl.gz`，通常無需填寫這個字段；也可以手動放到 `data/raw/bgp-observations*`。
- `geofeed_urls`：RFC 8805 geofeed 文件。默認使用 OpenGeoFeed 聚合源增強實際所在地判斷；它是第三方聚合源，不作爲權威註冊依據。更新後文件會保存到 `data/raw/geofeed*.csv`，查詢所在地時優先匹配 geofeed，未命中再回退 ip2region。

RPKI CSV 支持兩種格式：

```text
AS3257,64.81.0.0/16,24,routinator
rsync://example/roa.cer,AS3257,64.81.0.0/16,24,2026-01-01,2026-12-31
```

BGP 摘要 JSONL 示例：

```json
{"prefix":"64.81.32.0/21","origin_asn":3257,"source":"routeviews","collector":"rv2","observation_count":8,"dominant_upstream":1299}
```

BGP 摘要 CSV 示例：

```text
64.81.32.0/21,3257,ripe_ris,rrc00,7,2914
```

## 常用覆蓋參數

```bash
./ipasn -config config.yaml -addr :8080
./ipasn -config config.yaml -tls -tls-cert certs/server.crt -tls-key certs/server.key
./ipasn -config config.yaml -ai-provider openai -openai-base-url http://127.0.0.1:8000/v1 -openai-api-type chat_completions
```
