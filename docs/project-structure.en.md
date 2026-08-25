# Project Structure

> Language: [简体中文](project-structure.md) | [繁體中文](project-structure.zh-Hant.md) | English | [Back to README](../README.en.md)

This document uses `IPASN/` as the project root.

## Root

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

- `README.md`: Simplified Chinese project entry.
- `README.zh-Hant.md`: Traditional Chinese project entry.
- `README.en.md`: English project entry.
- `.github/workflows/release.yml`: GitHub Actions release workflow. It tests, tags, and uploads multi-platform binaries after pushes to `main`.
- `.gitattributes`: Git LFS tracking rules for large data files.
- `.gitignore`: local configuration, cache, build output, and log ignore rules.
- `config.yaml.example`: configuration template.
- `generate_firewall.yaml`: dedicated configuration for generating country, company, IDC/CDN, and scene CIDR lists.
- `go.mod` / `go.sum`: Go module dependency files.

Local files that should not be committed:

```text
config.yaml
ipasn
bin/
dist/
logs/
```

- `config.yaml`: local production configuration. It may contain ports, SSL paths, AI keys, licensed URLs, and tokens.
- `ipasn` / `bin/` / `dist/`: build outputs that can be regenerated.
- `logs/`: runtime logs.

## cmd

```text
cmd/ipasn/
```

- `main.go`: program entrypoint, configuration loading, web service startup, service installation, and SSL startup.
- `main_test.go`: command-line and service installation tests.
- `signals_unix.go` / `signals_windows.go`: platform-specific signal handling.

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

- `internal/ai`: AI-assisted low-confidence classification through OpenAI, Anthropic, Gemini, and OpenAI-compatible services.
- `internal/classify`: application scene rules and matching logic.
- `internal/config`: configuration file, environment variable, and default value loading.
- `internal/enrich`: Team Cymru, RIPEstat, RDAP, WHOIS, and related online enrichment plus cache.
- `internal/geo`: ip2region geolocation lookup.
- `internal/httpapi`: web UI and HTTP API handlers.
- `internal/lookup`: main IP / ASN lookup pipeline.
- `internal/store`: offline indexes, ASN data, CIDR data, historical routes, RPKI, IRR, and BGP observation structures.
- `internal/update`: offline database download, update, parsing, full BGP RIB summarization, and dynamic rule generation.

`*_test.go` files are module-specific tests.

## data

```text
data/raw
data/raw/bgp
data/generated
data/processed
data/cache
```

- `data/raw`: downloaded source files. Some files are distributed through Git LFS.
- `data/raw/bgp`: optional full BGP MRT downloads. Usually large and local.
- `data/generated`: generated service rules, BGP summaries, and compiled indexes that may be distributable when explicitly released.
- `data/processed`: manifests, parsed indexes, and update state.
- `data/cache`: runtime online enrichment cache and reverse DNS cache. It is local and ignored.

Important generated files:

```text
data/generated/services.json
data/generated/bgp-observations-full.jsonl.gz
data/generated/bgp-index.bin
data/generated/firewall/
data/processed/manifest.json
```

`data/generated/firewall/` and `data/generated/bgp-index.bin` are reproducible outputs and are ignored by default.

## rules

```text
rules/services.json
rules/asn_scenes.yaml
```

- `services.json`: manually maintained service IP rules, such as DNS, STUN, VPN, proxy, Tor, crawler, mail, monitoring, IoT, CDN, IDC, and blocklist signals.
- `asn_scenes.yaml`: ASN-level scene seeds, commonly used for government, education, mobile, organization, and weak residential hints.

## docs

```text
docs/api.md
docs/api.zh-Hant.md
docs/api.en.md
docs/configuration.md
docs/configuration.zh-Hant.md
docs/configuration.en.md
docs/deploy.md
docs/deploy.zh-Hant.md
docs/deploy.en.md
docs/project-structure.md
docs/project-structure.zh-Hant.md
docs/project-structure.en.md
```

- `*.md`: Simplified Chinese.
- `*.zh-Hant.md`: Traditional Chinese.
- `*.en.md`: English.

Every README and docs page should keep a language switch at the top.

## scripts

```text
scripts/build-release.sh
scripts/evaluate_ip_coverage.py
```

- `build-release.sh`: local and cross-platform release build helper.
- `evaluate_ip_coverage.py`: coverage evaluation helper that generates IPv4 / IPv6 samples, raw API results, and a Markdown evaluation report.

## dist

```text
dist/
```

Cross-platform build output. It is not required for source development because binaries can be rebuilt. It is ignored by default.

## Removable Local Files

These are safe to remove when cleaning the workspace because they can be regenerated or are local runtime state:

```text
.gocache/
.gomodcache/
bin/
dist/
logs/
screenlog.*
data/cache/
data/evaluation/
data/generated/firewall/
data/generated/bgp-index.bin
data/processed/download-cache/
data/processed/download-state.json
data/processed/bgp-refresh-state.json
```

Do not remove source files, rules, configuration templates, or Git LFS managed data unless the release plan explicitly says so.
