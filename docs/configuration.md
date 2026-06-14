# 配置文件说明

默认配置文件名：

```text
config.yaml
```

启动时指定：

```bash
./ipasn -config config.yaml
```

配置文件会先加载，环境变量和命令行参数可以覆盖配置文件里的值。

## 基础配置

```yaml
addr: ":18080"
data_dir: "data"
rules_file: "rules/services.json"
asn_rules_file: "rules/asn_scenes.yaml"
update_interval_hours: 24
http_timeout_seconds: 90
```

- `addr`：监听地址和端口。
- `data_dir`：离线数据库目录。
- `rules_file`：人工维护规则文件。
- `asn_rules_file`：ASN 场景规则文件，用于维护全球 `GOV`、`EDU`、`MOB` 和弱 `DYN` 种子规则。
- `update_interval_hours`：后台自动更新间隔。设为 `0` 可关闭定时更新。
- `http_timeout_seconds`：下载、联网校验和关闭服务的超时时间。

## HTTPS

```yaml
tls:
  enabled: false
  cert_file: "certs/server.crt"
  key_file: "certs/server.key"
```

- `enabled`：是否启用 HTTPS。
- `cert_file`：证书文件。
- `key_file`：私钥文件。

## AI

```yaml
ai:
  provider: "auto"
  openai_api_key: ""
  openai_model: "gpt-5.4-mini"
  openai_base_url: "https://api.openai.com/v1/responses"
  ollama_model: "qwen3:8b"
  ollama_base_url: "http://localhost:11434"
  confidence_cutoff: 0.7
  timeout_seconds: 8
  max_cache: 2048
```

- `provider`：`auto`、`off`、`openai`、`ollama`。
- `confidence_cutoff`：低于这个置信度时才调用 AI。
- `ollama_base_url`：Ollama 服务地址。
- `openai_api_key`：OpenAI key，也可以继续用环境变量 `OPENAI_API_KEY`。

## 在线增强和缓存

```yaml
enrichment:
  enabled: true
  ttl_hours: 168
  timeout_seconds: 8
  async_on_miss: true
  foreground_timeout_ms: 1500
```

- `enabled`：启用 Team Cymru、RIPEstat、RDAP、WHOIS 等当前校验。
- `ttl_hours`：联网查询结果缓存时间。
- `timeout_seconds`：单次增强查询超时时间。
- `async_on_miss`：缓存未命中时是否先返回离线结果，再后台刷新在线增强。生产环境建议保持 `true`；排查单个 IP 时可以临时设为 `false` 同步等待完整结果。
- `foreground_timeout_ms`：缓存未命中时，前台最多等待在线增强的时间。默认 `1500` 毫秒；如果 Team Cymru / RDAP / WHOIS / BGP 在这个窗口内完成，首次查询就会显示地理不一致和 AS Path。超过窗口后先返回离线结果，后台继续补全缓存。

联网增强缓存统一保存在：

```text
data/cache/enrich
```

缓存内容包含 Team Cymru、RIPEstat 当前宣告、RIPE RIS AS Path、RDAP、WHOIS 和地理一致性分析。普通查询会复用缓存结果；缓存未命中时会先短暂等待在线增强，超过前台等待窗口后再返回本地离线判断并后台补全。

地理一致性分析会输出：

- 注册地：RDAP / WHOIS 的国家或地区。
- 宣告地：Team Cymru / BGP origin ASN 的国家或地区。
- 所在地：ip2region 返回的国家码。
- BGP 路径：RIPE RIS 多个观察点看到的 AS Path、主上游 ASN、采集点数量。
- 冲突结论：注册地、宣告地、所在地不一致时会标记为冲突。

## 历史路由

```yaml
history:
  snapshots: 4
```

- `snapshots`：保留最近几个历史 BGP 样本。

## 全量 BGP 离线模式

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
  max_parallel_parse: 2
  keep_raw: true
  raw_retention_days: 30
  summary_file: "data/generated/bgp-observations-full.jsonl.gz"
  routeviews_base_url: "https://archive.routeviews.org/"
  ripe_ris_base_url: "https://data.ris.ripe.net/"
```

- `enabled`：是否启用全量 BGP 离线构建。
- `mode`：当前支持 `full`，表示后台下载 RIPE RIS 和 RouteViews collector 的最新 RIB。
- `routeviews_enabled` / `ripe_ris_enabled`：分别控制 RouteViews 和 RIPE RIS。
- `collectors`：`all` 表示自动发现全部 collector；也可以填写 `rrc00`、`route-views.sg` 等指定 collector。
- `include_updates`：预留给 MRT UPDATE 增量流，当前默认关闭；第一版使用最新 RIB 和历史快照。
- `history_snapshots`：全量 BGP 摘要的历史快照保留数量预留项。
- `refresh_hours`：建议与 RIPE RIS dump 周期一致或更长，默认 8 小时。
- `max_parallel_downloads` / `max_parallel_parse`：后台下载和解析并发上限。
- `keep_raw`：是否保留下载后的 MRT 原始文件。
- `raw_retention_days`：原始 BGP 文件保留天数。
- `summary_file`：生成的 BGP 多观察点摘要。查询服务只加载这个汇总文件，不加载 MRT 原始文件。
- `routeviews_base_url` / `ripe_ris_base_url`：公开离线 RIB 源地址。

全量 BGP 会明显增加后台更新时间和磁盘占用，但不会让普通查询实时访问公网。查询路径只读取 `summary_file` 生成的本地索引。

## 配置管理后台

```yaml
admin:
  enabled: true
  path: "/admin"
  token: ""
  local_only: true
```

- `enabled`：是否启用配置管理后台。
- `path`：后台访问路径。
- `token`：管理 API token。为空时不校验 token；公网部署时应设置。
- `local_only`：只允许本机访问后台。生产环境建议保持 `true` 或配合反向代理鉴权。

后台地址默认是：

```text
http://127.0.0.1:18080/admin
```

后台可以查看和保存 BGP 配置、触发离线库更新、查看数据库状态。保存配置会写回 `config.yaml`；监听端口、TLS 等启动级配置需要重启后生效。

## 动态规则

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
  cloudflare_v4_url: "https://www.cloudflare.com/ips-v4"
  cloudflare_v6_url: "https://www.cloudflare.com/ips-v6"
  fastly_url: "https://api.fastly.com/public-ip-list"
  aws_ip_ranges_url: "https://ip-ranges.amazonaws.com/ip-ranges.json"
  google_cloud_ip_ranges_url: "https://www.gstatic.com/ipranges/cloud.json"
  azure_service_tags_url: "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519"
  oracle_ip_ranges_url: "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json"
  github_meta_url: "https://api.github.com/meta"
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

- `file`：自动生成规则保存位置。
- `cloudflare_v4_url` / `cloudflare_v6_url`：Cloudflare 官方 CDN IP 段，生成 `CDN` 规则。
- `fastly_url`：Fastly 官方 public IP list，生成 `CDN` 规则。
- `aws_ip_ranges_url`：AWS 官方 IP 段，生成 AWS 总体 `IDC` 规则，并把 `CLOUDFRONT` service 单独生成高置信度 `CDN` 规则。
- `google_cloud_ip_ranges_url`、`azure_service_tags_url`、`oracle_ip_ranges_url`：云厂商官方 IP 段，生成 `IDC` 规则。
- `github_meta_url`：GitHub 官方 Meta IP 段，生成 `ORG` 规则。
- `mail_spf_domains`：邮件服务域名，程序会解析 SPF 生成邮件 IP 规则。
- `ip2proxy.local_files`：本地 IP2Proxy 文件。
- `ip2proxy.download_urls`：完整下载地址。
- `ip2proxy.token` 和 `package`：商业增强下载参数。

## ip2region

```yaml
ip2region:
  enabled: true
  include_default: false
  v4_file: "data/raw/ip2region_v4.xdb"
  v6_file: "data/raw/ip2region_v6.xdb"
  v4_version_url: "你的IPv4版本检查API"
  v4_download_url: "你的IPv4全载下载API"
  v6_version_url: "你的IPv6版本检查API"
  v6_download_url: "你的IPv6全载下载API"
```

- `enabled`：启用所在地查询。
- `include_default`：页面和接口默认返回所在地。关闭后可用 `include_location=1` 按需返回。
- `v4_file` / `v6_file`：本地 xdb 文件。
- `v4_version_url` / `v6_version_url`：版本检查地址。
- `v4_download_url` / `v6_download_url`：全载下载地址，商业版可填授权后的全载链接。

## 防火墙列表生成

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

执行：

```bash
./ipasn -config config.yaml -generate-firewall-lists
```

- `output_dir`：输出目录。
- `countries`：国家/地区代码列表，例如 `CN`、`US`、`SG`。为空表示按 ip2region 里出现的全部国家/地区生成 `country-XX.cidr`。
- `companies`：要生成的公司列表。公司列表需要显式配置，避免按全量 ASN/ISP 生成过多文件。
- `scenes`：要生成的场景列表，例如 `IDC`、`CDN`、`TOR`、`PROXY`。
- `min_confidence`：低于该置信度的记录不会进入输出。
- `include_ipv4` / `include_ipv6`：控制是否生成 IPv4 / IPv6 CIDR。默认两个都开启。
- `write_entries`：是否输出 `entries.jsonl` 明细。默认关闭，需要审计每条命中来源时再开启。

输出文件示例：

```text
data/generated/firewall/index.json
data/generated/firewall/country-CN.cidr
data/generated/firewall/company-alibaba.cidr
data/generated/firewall/scene-IDC.cidr
data/generated/firewall/scene-TOR.cidr
```

开启 `write_entries` 后会额外输出 `data/generated/firewall/entries.jsonl`。

生成器会对同一个输出文件里的相邻/重叠网段做合并，最终文件包含 IPv4 和 IPv6 CIDR。地区列表主要来自 ip2region 全量库；公司和场景会结合 ip2region 的 `ISP` / `ASN` 字段、ASN 信息、离线服务规则和场景规则生成。`TOR` / `PROXY` 更依赖 Tor / IP2Proxy 等专用离线来源，ip2region 只补充所在地和 ASN 信息。

## 数据源

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

这些地址一般保持默认即可。`peeringdb_ix_url`、`peeringdb_netixlan_url`、`peeringdb_facility_url`、`peeringdb_netfac_url` 用于构建 ASN 的公开互联点和机房 presence，查询时会结合 AS Path 推断机房/出口信息。

增强可靠性源为可选项：

- `rpki_vrp_urls`：Routinator、rpki-client 或 FORT 导出的 VRP CSV。默认使用 `rpki-client` 公共控制台 CSV；生产环境也可以换成本机 Routinator `/csv`。也可以手动放到 `data/raw/rpki-vrps*.csv`。
- `irr_route_urls`：IRR RPSL dump，解析 `route` / `route6`、`origin`、`source`。默认预置 RIPE、RIPE-NONAUTH、APNIC、AFRINIC 的 HTTP(S) dump。RADb 官方主要提供 FTP dump，当前下载器不直接写入默认 URL，可手动转存到 `data/raw/irr-routes*`。
- `bgp_observation_urls`：预处理后的 RouteViews / RIPE RIS 多观察点摘要，支持 JSONL 或 CSV。全量 BGP 模式会生成 `data/generated/bgp-observations-full.jsonl.gz`，通常无需填写这个字段；也可以手动放到 `data/raw/bgp-observations*`。
- `geofeed_urls`：RFC 8805 geofeed 文件。默认使用 OpenGeoFeed 聚合源增强实际所在地判断；它是第三方聚合源，不作为权威注册依据。更新后文件会保存到 `data/raw/geofeed*.csv`，查询所在地时优先匹配 geofeed，未命中再回退 ip2region。

RPKI CSV 支持两种格式：

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

## 常用覆盖参数

```bash
./ipasn -config config.yaml -addr :8080
./ipasn -config config.yaml -tls -tls-cert certs/server.crt -tls-key certs/server.key
./ipasn -config config.yaml -ai-provider ollama -ollama-model qwen3:8b
```
