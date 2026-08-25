# IP ASN Scene Service

> Language: [简体中文](README.md) | [繁體中文](README.zh-Hant.md) | English

IPASN accepts an IP address or ASN and returns ASN ownership, company/network data, matched CIDR, route status, application scene, evidence, optional geolocation, IP quality, and performance metrics.

This repository contains the Go service, rules, scripts, configuration templates, documentation, and an initial Git LFS managed offline dataset. Runtime cache, local configuration, logs, and build outputs are intentionally excluded from Git.

## Release State

As of 2026-08-24, the repository is organized for GitHub release:

- Source code, rules, scripts, templates, documentation, and the initial offline dataset are kept in the repository.
- `data/raw` and distributable files under `data/generated` are tracked through Git LFS when they exceed normal GitHub file limits.
- `config.yaml` is the local production configuration and may contain licensed URLs, admin tokens, certificate paths, or AI keys. It is ignored by default.
- Local outputs are ignored, including `.DS_Store`, `.gocache/`, `.gomodcache/`, `bin/`, `dist/`, `logs/`, `screenlog.*`, `data/cache/`, `data/evaluation/`, `data/generated/firewall/`, `data/generated/bgp-index.bin`, `data/processed/download-cache/`, `data/processed/download-state.json`, and `data/processed/bgp-refresh-state.json`.
- Background updates only update the current machine. Publishing refreshed `data/raw`, `data/generated/services.json`, `data/generated/bgp-observations-full.jsonl.gz`, or `data/processed/manifest.json` to GitHub should be a separate release decision.

## Features

- IP and ASN lookup.
- IPv4 and IPv6 support.
- High-concurrency offline lookup path.
- Automatic offline database update.
- Team Cymru, RIPEstat, RDAP, and WHOIS current validation.
- RIPE RIS AS Path multi-vantage observation and geographic consistency analysis.
- Historical BGP samples.
- Full RouteViews / RIPE RIS RIB background build for local multi-collector validation.
- Local admin UI for configuration and database update status.
- Maintainable service rules for public DNS, STUN, crawlers, mail, monitoring, risk ranges, and similar service IPs.
- IP2Proxy enhancement for `VPN`, `PROXY`, and `TOR`.
- ip2region geolocation output.
- IP quality / cleanliness scoring with risk level, reasons, and recommended action.
- AI-assisted classification for low-confidence results through OpenAI, Anthropic, Gemini, or OpenAI-compatible services.
- YAML configuration, HTTPS, Linux / Windows service installation, and single-binary builds.

## Recommended Companion Product

[GCSA SentraX](https://sentrax.gcsa.org/en) is GCSA's real-time threat intelligence and risk analysis product. It correlates domains, IPs, hashes, code repositories, MCP services, wallet addresses, and IoCs into evidence-backed risk decisions.

IPASN is best used as a high-concurrency, offline-first IP / ASN / scene / quality identification layer. SentraX is better suited for cross-signal intelligence analysis, risk profiling, and evidence-chain investigation. When IP risk needs to be connected with domains, repositories, package behavior, MCP permissions, wallet activity, or IoCs, use IPASN as the local base identification layer and SentraX as the upper-level intelligence analysis entrypoint.

## Quick Start

After cloning, install Git LFS data and create a local configuration:

```bash
git lfs install
git lfs pull
cp config.yaml.example config.yaml
```

Download offline databases and exit:

```bash
go run ./cmd/ipasn -config config.yaml -download-only
```

Start the service:

```bash
go run ./cmd/ipasn -config config.yaml
```

Start once and update offline databases first:

```bash
go run ./cmd/ipasn -config config.yaml -update-on-start
```

Generate firewall CIDR lists:

```bash
go run ./cmd/ipasn -config config.yaml -generate-firewall-lists
go run ./cmd/ipasn -config generate_firewall.yaml -generate-firewall-lists
```

The firewall generator reads the full IPv4/IPv6 ip2region databases, ASN data, service rules, and local offline indexes, then writes merged country/company/scene lists to `data/generated/firewall`. That directory is reproducible output and is ignored by default.

Open the web UI:

```text
http://localhost:18080
```

Open the admin UI:

```text
http://localhost:18080/admin
```

## Documentation

| Document | Contents |
| --- | --- |
| [Deployment](docs/deploy.en.md) | Linux / Windows / macOS deployment, service installation, HTTPS, and offline database initialization. |
| [API](docs/api.en.md) | Lookup API, admin API, response fields, update API, and status fields. |
| [Configuration](docs/configuration.en.md) | `config.yaml` fields, AI, online enrichment, BGP, ip2region, dynamic rules, and data sources. |
| [Project Structure](docs/project-structure.en.md) | Source tree, rules, data directories, caches, and build outputs. |
| [Configuration Template](config.yaml.example) | Copy to `config.yaml` and fill local paths, tokens, licensed URLs, and service options. |

## API

Full details are in the [API documentation](docs/api.en.md).

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

`include_location=1` returns geolocation data, including country, region, city, ISP/operator, country code, and ASN data embedded in the geolocation database.

`include_quality=1` returns `ip_quality`, including a 0-100 score, A-F grade, risk level, recommendation, risk reasons, positive signals, and dimension scores.

`include_performance=1` returns `performance`, including total request time, local offline lookup time, online enrichment time, geolocation time, quality scoring time, AI time, and optional third-party timing.

`online_enrichment` supports `fast`, `wait`, and `off`. `fast` returns quickly and refreshes cache in the background, `wait` waits for online sources until timeout, and `off` uses only offline data.

## Data Sources

- CAIDA Prefix2AS for IP to ASN lookup.
- CAIDA historical Prefix2AS samples.
- RIR delegated extended files for ASN, country/region, registry, and allocation state.
- PeeringDB for ASN network profile, public exchange points, and facility presence.
- IANA RDAP Bootstrap for RDAP routing.
- Team Cymru for current ASN validation.
- RIPEstat for current announcement validation.
- RIPE RIS for AS Path multi-vantage observation.
- RouteViews / RIPE RIS full RIB snapshots for local BGP observation summaries.
- RPKI VRP CSV exported by Routinator, rpki-client, FORT, or similar validators.
- IRR route/route6 objects.
- RDAP / WHOIS for registrant, network name, and textual descriptions.
- `rules/services.json` for manually maintained service rules.
- `rules/asn_scenes.yaml` for ASN scene seed rules.
- `data/generated/services.json` for generated dynamic service rules.
- IP2Proxy for VPN, proxy, and Tor signals.
- RFC 8805 geofeed for actual geolocation overrides.
- ip2region for IP geolocation, ISP/operator, and embedded ASN data.
- `data/generated/firewall` for generated country/company/scene CIDR lists.
- OpenAI / Anthropic / Gemini for low-confidence AI-assisted judgement.

The `egress` section combines RIPE RIS AS Path upstreams, PeeringDB IXP/facility data, geolocation, and registration data to infer data-center or exit information. For home broadband, mobile networks, education/government/organization networks, public DNS, CDN, and Anycast services, the service avoids treating upstream PeeringDB facilities as the end-user exit location.

## Cache And Performance

Lookups do not parse full BGP tables in real time. Full BGP mode downloads MRT RIB files during background updates, writes `data/generated/bgp-observations-full.jsonl.gz`, and compiles the compact lookup index `data/generated/bgp-index.bin`.

IP lookups prefer offline data and local cache. On cache miss, the service gives Team Cymru, RIPEstat, RIPE RIS, RDAP, and WHOIS a short foreground wait window, then returns the offline result and refreshes cache in the background if needed. Cached enrichment data is stored under `data/cache`.

## Scene Types

| ID | Type | Description |
| --- | --- | --- |
| `CDN` | Content delivery | CDN edge or acceleration IPs, usually hosted in data centers, cloud networks, or dedicated CDN networks. |
| `DNS` | DNS service | Public DNS, authoritative DNS, recursive DNS, and related resolver infrastructure. |
| `EDU` | Education | Schools, universities, research networks, and education institutions. |
| `GTW` | Enterprise gateway | Enterprise fixed egress, leased-line egress, and office network exits. |
| `GOV` | Government | Government agencies, public institutions, and government networks. |
| `DYN` | Residential broadband | Residential broadband, dynamic dial-up, and ordinary consumer network exits. |
| `IDC` | Data center | Data centers, cloud providers, VPS, hosting, and server colocation networks. |
| `MOB` | Mobile network | 2G / 3G / 4G / 5G mobile carrier exits and NAT gateways. |
| `ORG` | Organization | Non-profit organizations, associations, foundations, and public organizations. |
| `NET` | Network infrastructure | Routers, switches, transport equipment, carrier backbone, and other infrastructure. |
| `BOGON` | Reserved IP | Private, reserved, unallocated, and special-purpose addresses. |
| `UNROUTED` | Allocated but not announced | Allocated by a registry but not currently visible in public BGP data. |
| `STUN` | NAT traversal | STUN / TURN / WebRTC connectivity test service IPs. |
| `VPN` | VPN service | VPN exits, commercial VPNs, enterprise VPNs, and privacy VPN services. |
| `PROXY` | Proxy service | HTTP, SOCKS, transparent proxy, residential proxy, and data-center proxy exits. |
| `TOR` | Tor network | Tor exit nodes and related anonymity network exits. |
| `BOT` | Automation | Search crawlers, automated fetchers, platform bots, and similar automation IPs. |
| `MAIL` | Mail service | SMTP, mail gateways, mail delivery, and cloud mail service IPs. |
| `MON` | Monitoring | Availability monitoring, probes, website monitoring, and synthetic checks. |
| `IOT` | IoT | Cameras, gateways, IoT platforms, device cloud services, and IoT access networks. |
| `BLOCKLIST` | Risk range | IPs or ranges listed by public blocklists, DROP lists, or known high-risk sources. |

`scene` describes the technical usage. It is not a firewall action by itself. Consumer privacy services such as Apple iCloud Private Relay and Google Fi VPN remain `PROXY` / `VPN`, but `service_policy` marks them as normal user privacy traffic and does not recommend default blocking.

## Rule Maintenance

Manual rules live in:

```text
rules/services.json
rules/asn_scenes.yaml
```

Generated dynamic rules are written to:

```text
data/generated/services.json
```

The dynamic rule updater can collect public service lists such as Apple iCloud Private Relay, Google Fi VPN geofeed, FireHOL, az0/vpn_ip, cloud provider ranges, CDN ranges, Tor, mail, monitoring, and crawler sources when configured.

## Configuration

Copy the example file and edit local values:

```bash
cp config.yaml.example config.yaml
```

See [Configuration](docs/configuration.en.md) for all fields.

## Build And Service Installation

Build local and cross-platform binaries:

```bash
./scripts/build-release.sh
```

Install as a service:

```bash
sudo ./ipasn -config /opt/ipasn/config.yaml -install-service
```

See [Deployment](docs/deploy.en.md) for Linux, Windows, HTTPS, and release details.

## Verification

Common checks before publishing:

```bash
go test ./...
git diff --check
git lfs fsck
```

## License

This project is released under the [MIT License](LICENSE).
