# Configuration Guide

> Language: [简体中文](configuration.md) | [繁體中文](configuration.zh-Hant.md) | English | [Back to README](../README.en.md)

Default configuration file:

```text
config.yaml
```

Start with an explicit configuration file:

```bash
./ipasn -config config.yaml
```

The service loads `config.yaml` first. Environment variables and command-line flags can override selected values.

## Basic

```yaml
addr: ":18080"
data_dir: "data"
rules_file: "rules/services.json"
asn_rules_file: "rules/asn_scenes.yaml"
update_interval_hours: 24
http_timeout_seconds: 90
```

- `addr`: HTTP or HTTPS listen address.
- `data_dir`: offline database directory.
- `rules_file`: manually maintained service rule file.
- `asn_rules_file`: ASN scene seed rules, commonly used for global `GOV`, `EDU`, `MOB`, and weak `DYN` seeds.
- `update_interval_hours`: background update interval. Set `0` to disable scheduled updates.
- `http_timeout_seconds`: timeout for downloads, online validation, and graceful shutdown.

## HTTPS

```yaml
tls:
  enabled: false
  cert_file: "certs/server.crt"
  key_file: "certs/server.key"
```

- `enabled`: enable HTTPS.
- `cert_file`: certificate file.
- `key_file`: private key file.

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

- `provider`: `auto`, `off`, `openai`, `anthropic`, or `gemini`.
- `confidence_cutoff`: AI is used only when the local confidence is below this value.
- `openai_api_key`: OpenAI key. `OPENAI_API_KEY` can also be used.
- `openai_api_type`: `responses` calls `/v1/responses`; `chat_completions` calls `/v1/chat/completions` and is suitable for OpenAI-compatible services.
- `anthropic_api_key` / `gemini_api_key`: Anthropic and Gemini keys. Environment variables can also be used.
- `timeout_seconds`: AI request timeout.
- `max_cache`: in-memory AI result cache size.

## Online Enrichment And Cache

```yaml
enrichment:
  enabled: true
  ttl_hours: 168
  cache_file: "data/cache/enrichment.json"
  async_on_miss: true
  foreground_timeout_ms: 1500
```

- `enabled`: enable Team Cymru, RIPEstat, RDAP, WHOIS, and RIPE RIS online enrichment.
- `ttl_hours`: cache lifetime.
- `cache_file`: enrichment cache file.
- `async_on_miss`: in `fast` mode, return quickly and refresh missing data in the background.
- `foreground_timeout_ms`: foreground wait window for cache misses in `fast` mode.

## Historical Routing

Historical CAIDA Prefix2AS samples are used to recognize previously announced ranges and route changes. They are loaded from the offline data directory and do not require live network access at query time.

## Full BGP Offline Mode

Full BGP mode downloads public MRT RIB snapshots from RouteViews and RIPE RIS during background update, summarizes multi-vantage origin and path observations, and compiles a compact query index:

```text
data/generated/bgp-observations-full.jsonl.gz
data/generated/bgp-index.bin
```

Query-time lookup reads the compact index instead of parsing MRT files. This keeps the service suitable for high concurrency while allowing multi-collector evidence.

Important controls usually include collector list, snapshot time, retry count, download timeout, freshness interval, and output paths. Keep full BGP mode enabled only when disk, bandwidth, and update duration are acceptable.

## Download State Cache

The updater maintains per-source state under `data/processed` and `data/processed/download-cache`. It uses file metadata, source freshness, last success time, ETag / Last-Modified when available, and failure state to avoid repeated downloads of unchanged data.

Failed or missing sources are retried independently. A recent success for one source should not suppress retry of another failed source.

## Admin

```yaml
admin:
  enabled: true
  token: ""
```

- `enabled`: enable the admin UI and admin APIs.
- `token`: optional admin token. Keep it local and do not commit it.

The admin UI can edit configuration, save changes, reload supported runtime fields, fetch AI model lists, show offline library status, and start update tasks with progress.

## IP Quality Scoring

```yaml
quality:
  include_default: false
```

- `include_default`: return `ip_quality` by default from `/api/lookup`.

When disabled, callers can still request quality scoring with `include_quality=1` or use `/api/quality`.

IP quality scoring uses scene, service rules, IP2Proxy, FireHOL / blocklist signals, routing security, registration evidence, user type, and positive signals to produce a score, grade, risk level, recommendation, and reasons.

## Performance Metrics

```yaml
performance:
  include_default: false
  third_party_default: false
```

- `include_default`: include `performance` in all lookup responses.
- `third_party_default`: include per-source third-party timing by default.

For production high-volume calls, keep these disabled and enable them per request with `include_performance=1`.

## Dynamic Rules

Dynamic rules download public service lists and generate `data/generated/services.json`.

Common sources include:

- Apple iCloud Private Relay egress ranges.
- Google Fi VPN geofeed.
- FireHOL level1 and anonymous lists.
- az0/vpn_ip.
- Tor exit list.
- Public crawler ranges.
- Mail and monitoring provider ranges.
- Cloud provider ranges such as AWS, Google Cloud, Azure, Alibaba Cloud, Tencent Cloud, Cloudflare, Fastly, Akamai, and other common providers.

Consumer privacy services can be classified as `PROXY` or `VPN` technically, while `service_policy` marks them as normal user privacy traffic and not default block targets.

## ip2region

```yaml
ip2region:
  enabled: true
  include_default: false
```

- `enabled`: enable geolocation lookup.
- `include_default`: return geolocation by default from `/api/lookup`.

When disabled by default, callers can use `include_location=1`. The project supports full IPv4 and IPv6 ip2region offline databases. Licensed download URLs should stay in `config.yaml`, not in Git.

## Firewall List Generation

`generate_firewall.yaml` is a dedicated configuration for generating country, company, cloud, CDN, IDC, and scene-based CIDR lists:

```bash
go run ./cmd/ipasn -config generate_firewall.yaml -generate-firewall-lists
```

The generator uses ip2region, ASN data, service rules, dynamic rules, and offline route indexes. Output is written to `data/generated/firewall`, which is reproducible and ignored by default.

## Data Sources

Offline and online sources are configured through `config.yaml`. Typical categories:

- CAIDA Prefix2AS and historical Prefix2AS.
- RIR delegated extended files.
- IANA RDAP Bootstrap.
- PeeringDB.
- RPKI VRP CSV.
- IRR route/route6 dumps.
- RouteViews and RIPE RIS MRT RIB snapshots.
- ip2region IPv4/IPv6 full databases.
- IP2Proxy commercial or local offline files.
- Public dynamic service lists.

Prefer offline public data where possible. Use online enrichment for low-confidence or explicitly requested `wait` mode results.

## Common Overrides

- `IPASN_CONFIG`: alternative configuration path when supported by the launcher.
- `OPENAI_API_KEY`: OpenAI API key.
- `ANTHROPIC_API_KEY`: Anthropic API key.
- `GEMINI_API_KEY`: Gemini API key.

Do not commit local secrets, licensed URLs, certificates, or generated caches.
