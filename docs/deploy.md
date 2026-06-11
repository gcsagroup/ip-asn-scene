# 部署文档

## 目录建议

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

## 编译

在项目目录执行：

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

`ipasn` 是本机 macOS 测试用文件，`dist` 目录里的 Linux 和 Windows 文件可以直接部署。

## GitHub 自动发布

仓库已配置 `.github/workflows/release.yml`。以后每次推送到 `main`：

1. 运行 `go test ./...`。
2. 交叉编译 Linux、Windows、macOS 的单文件可执行程序。
3. 自动创建 `vYYYY.MM.DD-短SHA` tag。
4. 自动创建 GitHub Release，并上传：

```text
ipasn-<version>-linux-amd64
ipasn-<version>-linux-arm64
ipasn-<version>-windows-amd64.exe
ipasn-<version>-windows-arm64.exe
ipasn-<version>-darwin-amd64
ipasn-<version>-darwin-arm64
SHA256SUMS.txt
```

如果同一 commit 的 tag 已存在，工作流会跳过重复发布。

## 从源码克隆运行

仓库提交了一份初始化离线库，其中超过 GitHub 普通文件限制的大文件使用 Git LFS 管理。首次克隆后执行：

```bash
git lfs install
git lfs pull
```

之后可以直接启动服务。后台更新只会更新当前机器上的 `data` 文件，不会自动提交或推送到 GitHub。

## 首次准备数据库

如果要换成自己的授权库或重新拉取最新离线数据，把 `config.yaml.example` 复制为 `config.yaml`，填入授权下载地址后执行：

```bash
./ipasn -config config.yaml -download-only
```

这一步会下载离线数据库并生成查询索引。以后服务会按 `update_interval_hours` 自动更新。

## 启动服务

控制台启动：

```bash
./ipasn -config config.yaml
```

后台手动启动：

```bash
nohup ./ipasn -config config.yaml -console > ipasn.log 2>&1 &
```

打开：

```text
http://服务器IP:18080/
```

## Linux 安装为服务

把文件放到 `/opt/ipasn` 后执行：

```bash
cd /opt/ipasn
sudo ./ipasn -config /opt/ipasn/config.yaml -install-service
sudo systemctl start ipasn
sudo systemctl status ipasn
```

卸载：

```bash
sudo systemctl stop ipasn
sudo ./ipasn -uninstall-service
```

查看日志：

```bash
journalctl -u ipasn -f
```

## Windows 安装为服务

用管理员 PowerShell 执行：

```powershell
cd C:\ipasn
.\ipasn-windows-amd64.exe -config C:\ipasn\config.yaml -install-service
Start-Service ipasn
Get-Service ipasn
```

卸载：

```powershell
Stop-Service ipasn
.\ipasn-windows-amd64.exe -uninstall-service
```

## HTTPS

把证书放到 `certs` 目录，然后修改 `config.yaml`：

```yaml
tls:
  enabled: true
  cert_file: "certs/server.crt"
  key_file: "certs/server.key"
```

启动后访问：

```text
https://服务器IP:18080/
```

生产环境建议用 Nginx 或 Caddy 管证书，后端继续监听本机端口。直接用程序启用 HTTPS 也可以。

## 常用命令

手动更新数据库：

```bash
curl -X POST http://127.0.0.1:18080/api/db/update
```

查询健康状态：

```bash
curl http://127.0.0.1:18080/api/health
```

查询 IP：

```bash
curl "http://127.0.0.1:18080/api/lookup?query=8.8.8.8&include_location=1"
```

等待联网增强并返回机房/出口推断：

```bash
curl "http://127.0.0.1:18080/api/lookup?query=223.119.20.239&include_location=1&online_enrichment=wait"
```

## 可选可靠性增强数据

RPKI 推荐用本机 Routinator 生成离线 VRP：

```bash
routinator vrps --format csv > data/raw/rpki-vrps.csv
curl -X POST "http://127.0.0.1:18080/api/db/update?wait=1"
```

默认配置已预置 `https://console.rpki-client.org/vrps.csv`。生产环境也可以把本机 Routinator HTTP 服务的 `/csv` 地址填到 `sources.rpki_vrp_urls`，由后台更新下载。

IRR dump 支持 RPSL `route` / `route6` 对象：

```bash
cp radb.db data/raw/irr-routes.db
curl -X POST "http://127.0.0.1:18080/api/db/update?wait=1"
```

默认配置已预置 RIPE、RIPE-NONAUTH、APNIC、AFRINIC 的 HTTP(S) route/route6 dump。RADb 官方主要提供 FTP dump，当前内置下载器不直接下载 FTP；需要 RADb 时可先转存为本地 `data/raw/irr-routes*` 文件。

BGP 多观察点摘要需要先由外部脚本或批处理把 RouteViews / RIPE RIS MRT 转成 JSONL 或 CSV，再放到 `data/raw/bgp-observations.jsonl`：

```json
{"prefix":"64.81.32.0/21","origin_asn":3257,"source":"routeviews","collector":"rv2","observation_count":8,"dominant_upstream":1299}
```

完整接口说明见 [API 文档](api.md)。
