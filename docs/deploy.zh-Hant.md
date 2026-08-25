# 部署文檔

> 語言 / Language: [简体中文](deploy.md) | 繁體中文 | [English](deploy.en.md) | [返回 README](../README.zh-Hant.md)


## 目錄建議

Linux：

```text
/opt/ipasn/
  ipasn
  config.yaml
  rules/services.json
  data/
  certs/
```

Windows：

```text
C:\ipasn\
  ipasn.exe
  config.yaml
  rules\services.json
  data\
  certs\
```

## 編譯

在項目目錄執行：

```bash
./scripts/build-release.sh
```

生成文件：

```text
ipasn
dist/ipasn-darwin-arm64
dist/ipasn-linux-amd64
dist/ipasn-windows-amd64.exe
```

`ipasn` 是本機 macOS 測試用文件，`dist` 目錄裏的 Linux 和 Windows 文件可以直接部署。`ipasn`、`bin/` 和 `dist/` 都是構建產物，默認不提交到 Git。

## GitHub 自動發佈

倉庫已配置 `.github/workflows/release.yml`。以後每次推送到 `main`：

1. 運行 `go test ./...`。
2. 交叉編譯 Linux、Windows、macOS 的單文件可執行程序。
3. 自動創建 `vYYYY.MM.DD-短SHA` tag。
4. 自動創建 GitHub Release，並上傳：

```text
ipasn-<version>-linux-amd64
ipasn-<version>-linux-arm64
ipasn-<version>-windows-amd64.exe
ipasn-<version>-windows-arm64.exe
ipasn-<version>-darwin-amd64
ipasn-<version>-darwin-arm64
SHA256SUMS.txt
```

如果同一 commit 的 tag 已存在，工作流會跳過重複發佈。

## 從源碼克隆運行

倉庫提交了一份初始化離線庫，其中超過 GitHub 普通文件限制的大文件使用 Git LFS 管理。首次克隆後執行：

```bash
git lfs install
git lfs pull
cp config.yaml.example config.yaml
```

之後按需要修改 `config.yaml`，再啓動服務。後臺更新只會更新當前機器上的 `data` 文件，不會自動提交或推送到 GitHub。

## 首次準備數據庫

如果要換成自己的授權庫或重新拉取最新離線數據，把 `config.yaml.example` 複製爲 `config.yaml`，填入授權下載地址後執行：

```bash
./ipasn -config config.yaml -download-only
```

這一步會下載離線數據庫並生成查詢索引。以後服務會按 `update_interval_hours` 自動更新。

更新後的 `data/raw`、`data/generated/services.json`、`data/generated/bgp-observations-full.jsonl.gz`、`data/processed/manifest.json` 只有在你明確要發佈新的初始化離線庫時才提交。`data/generated/bgp-index.bin`、`data/processed/download-state.json`、`data/processed/download-cache/` 屬於本機狀態或可重建索引，默認不提交。

## 生成防火牆 CIDR 列表

確認 `config.yaml` 裏的 `firewall_lists` 已配置後執行：

```bash
./ipasn -config config.yaml -generate-firewall-lists
```

也可以使用專用配置生成更完整的國家、雲廠商、IDC/CDN 列表：

```bash
./ipasn -config generate_firewall.yaml -generate-firewall-lists
```

默認輸出到：

```text
data/generated/firewall/
```

主要文件：

```text
index.json
country-CN.cidr
company-alibaba.cidr
scene-IDC.cidr
scene-TOR.cidr
scene-PROXY.cidr
```

如果在 `firewall_lists.write_entries` 打開明細輸出，會額外生成 `entries.jsonl`。

生成過程讀取 ip2region IPv4/IPv6 xdb 全量庫，並結合 ASN、規則和本地離線索引。`data/generated/firewall/` 是可重建發佈產物，默認不提交；需要隨 Release 附帶時建議打包爲獨立資產，而不是混入源碼提交。

## 發佈前檢查

提交到 GitHub 前建議執行：

```bash
go test ./... -count=1
git lfs fsck
git diff --check
git status --ignored -s
```

發佈分支裏不應出現這些未忽略或待提交文件：

```text
.DS_Store
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

`config.yaml` 是本機配置，正常情況下應只顯示爲 ignored。若要發佈新的離線庫版本，先確認 LFS 文件完整，再提交對應的 `data/raw`、`data/generated` 和 `data/processed/manifest.json`。

## 啓動服務

控制檯啓動：

```bash
./ipasn -config config.yaml
```

後臺手動啓動：

```bash
nohup ./ipasn -config config.yaml -console > ipasn.log 2>&1 &
```

打開：

```text
http://服務器IP:18080/
```

## Linux 安裝爲服務

把文件放到 `/opt/ipasn` 後執行：

```bash
cd /opt/ipasn
sudo ./ipasn -config /opt/ipasn/config.yaml -install-service
sudo systemctl start ipasn
sudo systemctl status ipasn
```

卸載：

```bash
sudo systemctl stop ipasn
sudo ./ipasn -uninstall-service
```

查看日誌：

```bash
journalctl -u ipasn -f
```

## Windows 安裝爲服務

用管理員 PowerShell 執行：

```powershell
cd C:\ipasn
.\ipasn-windows-amd64.exe -config C:\ipasn\config.yaml -install-service
Start-Service ipasn
Get-Service ipasn
```

卸載：

```powershell
Stop-Service ipasn
.\ipasn-windows-amd64.exe -uninstall-service
```

## HTTPS

把證書放到 `certs` 目錄，然後修改 `config.yaml`：

```yaml
tls:
  enabled: true
  cert_file: "certs/server.crt"
  key_file: "certs/server.key"
```

啓動後訪問：

```text
https://服務器IP:18080/
```

生產環境建議用 Nginx 或 Caddy 管證書，後端繼續監聽本機端口。直接用程序啓用 HTTPS 也可以。

## 常用命令

手動更新數據庫：

```bash
curl -X POST http://127.0.0.1:18080/api/db/update
```

查詢健康狀態：

```bash
curl http://127.0.0.1:18080/api/health
```

查詢 IP：

```bash
curl "http://127.0.0.1:18080/api/lookup?query=8.8.8.8&include_location=1"
```

等待聯網增強並返回機房/出口推斷：

```bash
curl "http://127.0.0.1:18080/api/lookup?query=223.119.20.239&include_location=1&online_enrichment=wait"
```

## 可選可靠性增強數據

RPKI 推薦用本機 Routinator 生成離線 VRP：

```bash
routinator vrps --format csv > data/raw/rpki-vrps.csv
curl -X POST "http://127.0.0.1:18080/api/db/update?wait=1"
```

默認配置已預置 `https://console.rpki-client.org/vrps.csv`。生產環境也可以把本機 Routinator HTTP 服務的 `/csv` 地址填到 `sources.rpki_vrp_urls`，由後臺更新下載。

IRR dump 支持 RPSL `route` / `route6` 對象：

```bash
cp radb.db data/raw/irr-routes.db
curl -X POST "http://127.0.0.1:18080/api/db/update?wait=1"
```

默認配置已預置 RIPE、RIPE-NONAUTH、APNIC、AFRINIC 的 HTTP(S) route/route6 dump。RADb 官方主要提供 FTP dump，當前內置下載器不直接下載 FTP；需要 RADb 時可先轉存爲本地 `data/raw/irr-routes*` 文件。

BGP 多觀察點摘要需要先由外部腳本或批處理把 RouteViews / RIPE RIS MRT 轉成 JSONL 或 CSV，再放到 `data/raw/bgp-observations.jsonl`：

```json
{"prefix":"64.81.32.0/21","origin_asn":3257,"source":"routeviews","collector":"rv2","observation_count":8,"dominant_upstream":1299}
```

完整接口說明見 [API 文檔](api.zh-Hant.md)。
