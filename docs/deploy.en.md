# Deployment Guide

> Language: [简体中文](deploy.md) | [繁體中文](deploy.zh-Hant.md) | English | [Back to README](../README.en.md)

## Recommended Layout

Linux:

```text
/opt/ipasn/
  ipasn
  config.yaml
  rules/services.json
  data/
  certs/
```

Windows:

```text
C:\ipasn\
  ipasn.exe
  config.yaml
  rules\services.json
  data\
  certs\
```

## Build

Run from the project root:

```bash
./scripts/build-release.sh
```

Expected local outputs:

```text
ipasn
dist/ipasn-darwin-arm64
dist/ipasn-linux-amd64
dist/ipasn-windows-amd64.exe
```

`ipasn` is the local macOS test binary. `dist` contains deployable Linux and Windows binaries. `ipasn`, `bin/`, and `dist/` are build outputs and are ignored by default.

## GitHub Automatic Release

The repository includes `.github/workflows/release.yml`. Each push to `main` runs tests, builds single-file binaries for Linux, Windows, and macOS, creates a `vYYYY.MM.DD-shortSHA` tag, and uploads release assets:

```text
ipasn-<version>-linux-amd64
ipasn-<version>-linux-arm64
ipasn-<version>-windows-amd64.exe
ipasn-<version>-windows-arm64.exe
ipasn-<version>-darwin-amd64
ipasn-<version>-darwin-arm64
SHA256SUMS.txt
```

If the tag for the same commit already exists, the workflow skips duplicate publishing.

## Clone From Source

The repository includes an initial offline dataset. Large files are managed by Git LFS. After cloning:

```bash
git lfs install
git lfs pull
cp config.yaml.example config.yaml
```

Edit `config.yaml` for local ports, paths, certificates, licensed URLs, and optional AI provider keys. Background updates only update local `data` files and do not commit or push them to GitHub.

## First Database Preparation

Download offline databases and exit:

```bash
go run ./cmd/ipasn -config config.yaml -download-only
```

Start and update on startup:

```bash
go run ./cmd/ipasn -config config.yaml -update-on-start
```

Use the admin UI to see update progress, file status, sizes, paths, timestamps, and source URLs.

## Generate Firewall CIDR Lists

Use the general configuration:

```bash
go run ./cmd/ipasn -config config.yaml -generate-firewall-lists
```

Or use the dedicated generator configuration:

```bash
go run ./cmd/ipasn -config generate_firewall.yaml -generate-firewall-lists
```

Output directory:

```text
data/generated/firewall
```

Generated firewall lists are reproducible output. They are ignored by default and should be regenerated in deployment or release pipelines when needed.

## Pre-release Checks

Run:

```bash
go test ./...
git diff --check
git lfs fsck
```

Recommended additional checks:

```bash
go run ./cmd/ipasn -config config.yaml -download-only
go run ./cmd/ipasn -config generate_firewall.yaml -generate-firewall-lists
```

Confirm that `config.yaml` and local secrets are not staged:

```bash
git status --short
```

## Start Service

Development:

```bash
go run ./cmd/ipasn -config config.yaml
```

Binary:

```bash
./ipasn -config config.yaml
```

Default URLs:

```text
http://127.0.0.1:18080/
http://127.0.0.1:18080/admin
```

## Linux Service

Copy files to `/opt/ipasn`, then install:

```bash
sudo /opt/ipasn/ipasn -config /opt/ipasn/config.yaml -install-service
sudo systemctl enable --now ipasn
```

Useful commands:

```bash
systemctl status ipasn
journalctl -u ipasn -f
sudo systemctl restart ipasn
```

Uninstall:

```bash
sudo /opt/ipasn/ipasn -uninstall-service
```

## Windows Service

Run PowerShell as Administrator:

```powershell
C:\ipasn\ipasn.exe -config C:\ipasn\config.yaml -install-service
Start-Service ipasn
```

Useful commands:

```powershell
Get-Service ipasn
Restart-Service ipasn
C:\ipasn\ipasn.exe -uninstall-service
```

## HTTPS

Configure certificate and key:

```yaml
tls:
  enabled: true
  cert_file: "certs/server.crt"
  key_file: "certs/server.key"
```

Then start the service normally. The same `addr` port serves HTTPS when TLS is enabled.

## Common Commands

```bash
./ipasn -config config.yaml
./ipasn -config config.yaml -download-only
./ipasn -config config.yaml -update-on-start
./ipasn -config config.yaml -generate-firewall-lists
./ipasn -config config.yaml -install-service
./ipasn -uninstall-service
```

## Optional Reliability Data

The service can use these optional offline datasets for stronger validation:

- RPKI VRP CSV for route authorization.
- IRR route/route6 dumps for registered route objects.
- RouteViews / RIPE RIS full RIB summaries for multi-vantage BGP consistency.
- PeeringDB for exchange and facility presence.
- geofeed for actual location overrides.

If these files are absent, lookup still works with the base offline databases and service rules, but route reliability and egress/location confidence may be lower.
