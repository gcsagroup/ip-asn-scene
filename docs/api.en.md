# API Documentation

> Language: [简体中文](api.md) | [繁體中文](api.zh-Hant.md) | English | [Back to README](../README.en.md)

Default service address:

```text
http://127.0.0.1:18080
```

All APIs return UTF-8 JSON unless stated otherwise.

## Lookup IP Or ASN

```text
GET /api/lookup
```

### Parameters

| Parameter | Required | Description |
| --- | --- | --- |
| `query` | Yes | IP or ASN, for example `8.8.8.8`, `223.119.20.239`, or `AS15169`. |
| `include_location` | No | `1`, `true`, `yes`, or `on` returns IP geolocation. Default is controlled by `ip2region.include_default`. |
| `include_quality` | No | `1`, `true`, `yes`, or `on` returns IP quality / cleanliness scoring. Default is controlled by `quality.include_default`. |
| `include_performance` | No | `1`, `true`, `yes`, or `on` returns query timing metrics. Default is controlled by `performance.include_default`. |
| `include_third_party_timing` | No | `1` returns third-party timing details in `performance.third_party`; `0` hides them. Default is controlled by `performance.third_party_default`. |
| `online_enrichment` | No | Online enrichment mode: `fast`, `wait`, or `off`. Default is `fast`. |

### online_enrichment

| Value | Behavior | Use Case |
| --- | --- | --- |
| `fast` | Prefer offline data and cache. On cache miss, wait briefly, then refresh in the background if needed. | High-concurrency production and default web queries. |
| `wait` | Wait for Team Cymru, RIPEstat, RIPE RIS, RDAP, and WHOIS until completion or timeout. | Debugging one IP and needing the first result to include online sources. |
| `off` | Do not trigger online enrichment. Return only offline data, rules, historical BGP, and geolocation. | Offline-only checks or environments without outbound network access. |

### Examples

```bash
curl "http://127.0.0.1:18080/api/lookup?query=8.8.8.8"
curl "http://127.0.0.1:18080/api/lookup?query=223.119.20.239&include_location=1"
curl "http://127.0.0.1:18080/api/lookup?query=223.119.20.239&include_location=1&online_enrichment=wait"
curl "http://127.0.0.1:18080/api/lookup?query=223.119.20.239&online_enrichment=off"
curl "http://127.0.0.1:18080/api/lookup?query=1.2.3.4&include_quality=1"
curl "http://127.0.0.1:18080/api/lookup?query=8.8.8.8&include_performance=1&include_third_party_timing=1&online_enrichment=wait"
curl "http://127.0.0.1:18080/api/lookup?query=AS15169"
```

### Main Response Fields

| Field | Description |
| --- | --- |
| `ok` | Whether the query succeeded. |
| `query_type` | `ip` or `asn`. |
| `ip` / `asn` | Matched IP or ASN. |
| `company` | Company or network name. |
| `country` / `registry` | Country/region and RIR from offline or allocation data. |
| `matched_prefix` | Matched CIDR prefix. |
| `routing_status` | Route status such as `announced` or `not_announced`. |
| `scene` / `scene_name` | Main application scene. Low-confidence results may be corrected by multi-source evidence. |
| `inferred_scene` / `inferred_scene_name` | Inferred usage scene. |
| `confidence` | Confidence of the main scene. |
| `inferred_confidence` / `inferred_source` | Confidence and source of the inferred scene. |
| `service_policy` | Service policy metadata. Consumer privacy proxy / VPN services can be marked as normal user traffic. |
| `evidence` | Evidence used by the classifier. |
| `sources` | Data sources used for this answer. |
| `registration` | Online enrichment summary. |
| `geo_consistency` | Geographic consistency analysis. |
| `egress` | Data-center or exit inference. |
| `routing_security` | RPKI / IRR / BGP route reliability analysis. |
| `data_quality` | Overall data quality score. |
| `ip_quality` | IP quality / cleanliness score. Requires default output or `include_quality=1`. |
| `performance` | Query performance metrics. Requires default output or `include_performance=1`. |
| `source_votes` | Multi-source scene votes. |
| `warnings` | Route, geography, or source conflict warnings. |
| `location` | IP geolocation. Requires default output or `include_location=1`. |
| `history` | Historical BGP samples. |
| `prefixes` | Related CIDR prefixes. |
| `db` | Offline database status. |

High-confidence primary rules are kept first, for example public DNS, DSL reverse DNS, and reserved ranges. Online egress and registration data are added as evidence. Low-confidence results combine primary rules, RDAP / WHOIS, AI, and egress inference through weighted votes.

### performance

`performance` helps identify where a query spends time. Units are milliseconds.

| Field | Description |
| --- | --- |
| `total_ms` | Total request time. |
| `local_offline_ms` | Local offline lookup time, including rules, Prefix2AS, ASN, allocation records, history, and reverse DNS before online enrichment. |
| `online_enrichment_ms` | Time spent waiting for online enrichment in the current request. |
| `location_ms` | Geolocation lookup time. |
| `quality_ms` | IP quality scoring time. |
| `ai_ms` | AI-assisted classification time, usually omitted when AI is disabled or not triggered. |
| `cache_hit` | Whether online enrichment hit cache. |
| `refresh_queued` / `refresh_in_progress` | Whether an online refresh was queued or already running in the background. |
| `third_party` | Timing list for Team Cymru, RIPEstat, RDAP, WHOIS, RIPE RIS, and other third-party sources actually waited for by this request. |

### ip_quality

`ip_quality` is intended for risk control and access policy. It does not overwrite `scene`.

| Field | Description |
| --- | --- |
| `score` | 0-100. Higher means cleaner. |
| `grade` | A/B/C/D/F. |
| `risk_level` | `low`, `medium`, `high`, or `critical`. |
| `recommendation` | `allow`, `review`, `challenge`, `rate_limit`, or `block`. |
| `confidence` | Scoring confidence. |
| `labels` | Quality labels such as `VPN`, `BLOCKLIST`, or `RPKI_INVALID`. |
| `risk_reasons` | Deduction reasons. |
| `positive_signals` | Positive signals. |
| `dimensions` | Dimension scores: reputation, anonymity, infrastructure, routing_trust, registration, and user_type. |

### Dedicated Quality API

```text
GET /api/quality
```

Parameters are the same as `/api/lookup`. The response always includes `ip_quality`:

```bash
curl "http://127.0.0.1:18080/api/quality?query=1.2.3.4"
```

### service_policy

`service_policy` separates technical scene from enforcement action. For example, Apple iCloud Private Relay is still `PROXY`, and Google Fi VPN is still `VPN`, but both can be marked as normal consumer privacy traffic and not recommended for default blocking.

| Field | Description |
| --- | --- |
| `service_name` | Service name, for example `Apple iCloud Private Relay`. |
| `service_subtype` | Subtype such as `consumer_privacy_proxy` or `carrier_privacy_vpn`. |
| `risk_level` | Risk level, for example `low`. |
| `block_recommended` | Whether default blocking is recommended. |
| `normal_user_traffic` | Whether the traffic looks like normal user traffic. |
| `rule_id` / `rule_name` | Matched offline service rule. |

### routing_security

`routing_security` comes from offline RPKI VRP, IRR route/route6 objects, and BGP multi-vantage summaries. It may be empty when the corresponding offline files are not available.

| Field | Description |
| --- | --- |
| `rpki` | `valid`, `invalid`, or `not_found`. |
| `rpki_reason` | RPKI decision reason. |
| `rpki_matched_prefix` / `rpki_max_length` | Matched ROA / VRP range. |
| `irr_matched` | Whether prefix + origin ASN matches an IRR route object. |
| `irr_conflict` / `irr_origin_asns` | Whether multiple or conflicting IRR origins exist. |
| `moas` | Whether multi-origin ASN was observed. |
| `route_leak_suspected` | Whether obvious route anomaly signals exist. |
| `prefix_visibility` | Number of BGP observation samples. |
| `origin_agreement` | Agreement ratio for the current origin ASN. |

### data_quality

`data_quality` is a confidence indicator for current evidence, not an absolute truth score.

| Field | Description |
| --- | --- |
| `score` | 0 to 1. |
| `level` | `high`, `medium`, or `low`. |
| `source_agreement` | Source agreement status such as `rpki_irr_bgp_agree` or `routing_conflict`. |
| `freshness` | Data freshness: `fresh`, `recent`, `stale`, or `unknown`. |
| `signals` | Main signals involved in the score. |

### registration

`registration` comes from online enrichment and cache. It may include:

| Field | Description |
| --- | --- |
| `cache_hit` | Whether enrichment cache was hit. |
| `refresh_queued` | Whether a background refresh was queued in `fast` mode. |
| `refresh_in_progress` | Whether the same IP is already being refreshed. |
| `team_cymru` | Team Cymru current ASN / prefix / country / registry. |
| `ripestat` | RIPEstat current announcement data. |
| `bgp_path` | RIPE RIS AS Path observations. |
| `rdap` | RDAP summary. |
| `whois` | WHOIS summary. |
| `inferred_scene` | RDAP / WHOIS text based scene inference. |

### geo_consistency

Geographic consistency compares registration country, current BGP country, AS Path observation, geofeed, ip2region, and PeeringDB public presence. A mismatch does not always mean the IP is wrong; it is evidence for exit-location and data-quality decisions.

### egress

`egress` describes data-center or exit inference. Typical fields include primary upstream ASN/name, upstream type, matched facility or exchange, inferred country/region/city, confidence, and evidence.

The service avoids reporting an upstream data center as the user location when the IP belongs to home broadband, mobile, education, government, organization, Anycast public DNS, or CDN service traffic.

## Health Check

```text
GET /api/health
```

Returns basic service health and build/runtime status.

## Admin UI

```text
GET /admin
```

The admin UI provides configuration editing, database status, update progress, AI model selection, and offline library overview.

### Read Configuration

```text
GET /api/admin/config
```

Returns the editable configuration model. Secret fields are masked and should be submitted only when changed.

### Fetch AI Model List

```text
POST /api/admin/ai/models
```

Reads the selected provider and API key from the submitted configuration, then fetches a model list when the provider supports listing. OpenAI-compatible services are queried through their configured Base URL.

### Save Configuration

```text
PUT /api/admin/config
```

Saves the submitted configuration to `config.yaml`. Runtime fields that can be reloaded are applied immediately; fields that affect process startup, certificates, or paths may require a service restart.

### Admin Status

```text
GET /api/admin/status
```

Returns background updater state, active task progress, local data size, and service status used by the admin UI.

### Trigger Update

```text
POST /api/admin/update
```

Starts the offline database update flow. The response is immediate; progress is exposed through admin status endpoints and the web UI.

## Database Status

```text
GET /api/db/status
```

Returns offline library manifest, file status, size, local path, update time, and source URL. It is intended for diagnostics and admin display.

## Update Database

```text
POST /api/db/update
```

Triggers the database update workflow. The updater checks per-source freshness and download state to avoid unnecessary repeated downloads, while failed or missing sources are retried independently.
