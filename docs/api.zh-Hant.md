# API 文檔

> 語言 / Language: [简体中文](api.md) | 繁體中文 | [English](api.en.md) | [返回 README](../README.zh-Hant.md)


默認服務地址：

```text
http://127.0.0.1:18080
```

所有接口默認返回 JSON，編碼爲 UTF-8。

## 查詢 IP 或 ASN

```text
GET /api/lookup
```

### 參數

| 參數 | 必填 | 說明 |
| --- | --- | --- |
| `query` | 是 | IP 或 ASN，例如 `8.8.8.8`、`223.119.20.239`、`AS15169`。 |
| `include_location` | 否 | `1`、`true`、`yes`、`on` 表示返回 IP 所在地。默認由 `ip2region.include_default` 決定。 |
| `include_quality` | 否 | `1`、`true`、`yes`、`on` 表示返回 IP 質量 / 純淨度評分。默認由 `quality.include_default` 決定。 |
| `include_performance` | 否 | `1`、`true`、`yes`、`on` 表示返回本次查詢性能指標。默認由 `performance.include_default` 決定。 |
| `include_third_party_timing` | 否 | `1` 表示在 `performance.third_party` 裏返回第三方源耗時；`0` 表示隱藏第三方明細。默認由 `performance.third_party_default` 決定。 |
| `online_enrichment` | 否 | 在線增強模式：`fast`、`wait`、`off`。默認 `fast`。 |

### online_enrichment

| 值 | 行爲 | 適用場景 |
| --- | --- | --- |
| `fast` | 優先返回離線庫和緩存；緩存未命中時短暫等待，超時後後臺刷新。 | 高併發、頁面默認查詢。 |
| `wait` | 等 Team Cymru、RIPEstat、RIPE RIS、RDAP、WHOIS 完成或超時後返回。 | 調試單個 IP，需要首次結果完整。 |
| `off` | 不觸發在線增強，只返回離線庫、規則、歷史 BGP 和所在地。 | 只看離線結果或避免外網請求。 |

### 示例

快速查詢：

```bash
curl "http://127.0.0.1:18080/api/lookup?query=8.8.8.8"
```

返回所在地：

```bash
curl "http://127.0.0.1:18080/api/lookup?query=223.119.20.239&include_location=1"
```

等待聯網增強結果：

```bash
curl "http://127.0.0.1:18080/api/lookup?query=223.119.20.239&include_location=1&online_enrichment=wait"
```

只使用離線庫：

```bash
curl "http://127.0.0.1:18080/api/lookup?query=223.119.20.239&online_enrichment=off"
```

返回質量評分：

```bash
curl "http://127.0.0.1:18080/api/lookup?query=1.2.3.4&include_quality=1"
```

返回性能指標並等待在線增強：

```bash
curl "http://127.0.0.1:18080/api/lookup?query=8.8.8.8&include_performance=1&include_third_party_timing=1&online_enrichment=wait"
```

查詢 ASN：

```bash
curl "http://127.0.0.1:18080/api/lookup?query=AS15169"
```

### 主要響應字段

| 字段 | 說明 |
| --- | --- |
| `ok` | 查詢是否成功。 |
| `query_type` | `ip` 或 `asn`。 |
| `ip` / `asn` | 命中的 IP 或 ASN。 |
| `company` | 公司或網絡名稱。 |
| `country` / `registry` | 離線庫或分配記錄裏的國家/地區和註冊局。 |
| `matched_prefix` | 命中的網段。 |
| `routing_status` | `announced`、`not_announced` 等。 |
| `scene` / `scene_name` | 主應用場景。低置信度時可被多源證據修正。 |
| `inferred_scene` / `inferred_scene_name` | 推斷用途。 |
| `confidence` | 主場景置信度。 |
| `inferred_confidence` / `inferred_source` | 推斷用途置信度和來源。 |
| `service_policy` | 服務處置策略元數據。消費者隱私代理 / VPN 等正常用戶流量會在這裏標記是否建議攔截。 |
| `evidence` | 判斷依據。 |
| `sources` | 使用的數據源。 |
| `registration` | 在線增強信息。 |
| `geo_consistency` | 地理一致性分析。 |
| `egress` | 機房/出口推斷。 |
| `routing_security` | RPKI / IRR / BGP 多源路由可靠性分析。 |
| `data_quality` | 綜合數據質量評分。 |
| `ip_quality` | IP 質量 / 純淨度評分，需啓用默認輸出或傳 `include_quality=1`。 |
| `performance` | 查詢性能指標，需啓用默認輸出或傳 `include_performance=1`。 |
| `source_votes` | 場景判斷的多源投票。 |
| `warnings` | 路由、地理或來源衝突提示。 |
| `location` | IP 所在地，需啓用或傳 `include_location=1`。 |
| `history` | 歷史 BGP 樣本。 |
| `prefixes` | 相關網段。 |
| `db` | 當前離線庫狀態。 |

用途融合邏輯：主規則高置信度命中時優先保留主規則，例如公共 DNS、DSL 反向 DNS、保留地址等；在線增強裏的機房/出口信息會作爲參考證據寫入 `evidence`，`inferred_source` 會顯示 `主場景規則 + 在線增強參考`。主規則低置信度時，會把主規則、RDAP / WHOIS、AI 和機房/出口推斷放入 `source_votes` 做加權投票；只有多源一致且分數明顯高於原結論時，才修正 `scene` 和 `inferred_scene`。

### performance

`performance` 用於調試查詢慢在哪裏，不建議對所有生產調用默認開啓。字段單位都是毫秒。

| 字段 | 說明 |
| --- | --- |
| `total_ms` | 本次請求總耗時。 |
| `local_offline_ms` | 本地離線查詢耗時，包括規則、Prefix2AS、ASN、分配記錄、歷史 BGP、反向 DNS 等在線增強前步驟。 |
| `online_enrichment_ms` | 當前請求等待在線增強的耗時。`fast` 模式緩存未命中時可能只是前臺等待窗口。 |
| `location_ms` | IP 所在地查詢耗時。 |
| `quality_ms` | IP 質量評分耗時。 |
| `ai_ms` | AI 輔助判斷耗時，未啓用或未觸發時通常不輸出。 |
| `cache_hit` | 在線增強是否命中緩存。 |
| `refresh_queued` / `refresh_in_progress` | 在線增強是否已轉後臺刷新。 |
| `third_party` | 第三方源耗時列表，包含 `name`、`url`、`duration_ms`、`ok`。只記錄當前請求實際等待的 Team Cymru、RIPEstat、RDAP、WHOIS、RIPE RIS 等調用。 |

### ip_quality

`ip_quality` 用於風控或訪問策略，不改變 `scene`。`scene` 表示技術場景，`ip_quality.recommendation` 表示建議動作。

| 字段 | 說明 |
| --- | --- |
| `score` | 0-100，越高越乾淨。 |
| `grade` | A/B/C/D/F。 |
| `risk_level` | `low`、`medium`、`high`、`critical`。 |
| `recommendation` | `allow`、`review`、`challenge`、`rate_limit`、`block`。 |
| `confidence` | 評分置信度。 |
| `labels` | 命中的質量標籤，例如 `VPN`、`BLOCKLIST`、`RPKI_INVALID`。 |
| `risk_reasons` | 扣分原因。 |
| `positive_signals` | 正向信號。 |
| `dimensions` | reputation、anonymity、infrastructure、routing_trust、registration、user_type 分維度評分。 |

### 單獨質量接口

```text
GET /api/quality
```

參數與 `/api/lookup` 一致，固定返回 `ip_quality`：

```bash
curl "http://127.0.0.1:18080/api/quality?query=1.2.3.4"
```

### service_policy

`service_policy` 用於把技術場景和處置策略分開。例如 Apple iCloud Private Relay 仍屬於 `PROXY`，Google Fi VPN 仍屬於 `VPN`，但它們是系統級或運營商級消費者隱私服務，默認不建議直接按高風險代理封禁。

| 字段 | 說明 |
| --- | --- |
| `service_name` | 服務名稱，例如 `Apple iCloud Private Relay`。 |
| `service_subtype` | 服務子類型，例如 `consumer_privacy_proxy`、`carrier_privacy_vpn`。 |
| `risk_level` | 風險等級，當前可爲 `low` 等。 |
| `block_recommended` | 是否建議默認攔截。消費者隱私服務通常爲 `false`。 |
| `normal_user_traffic` | 是否更接近正常用戶流量。 |
| `rule_id` / `rule_name` | 命中的離線服務規則。 |

### routing_security

`routing_security` 來自離線 RPKI VRP、IRR route/route6 對象和 BGP 多觀察點摘要。沒有對應離線文件時該字段可能爲空。

| 字段 | 說明 |
| --- | --- |
| `rpki` | `valid`、`invalid`、`not_found`。 |
| `rpki_reason` | RPKI 判斷原因。 |
| `rpki_matched_prefix` / `rpki_max_length` | 命中的 ROA / VRP 範圍。 |
| `irr_matched` | 當前 prefix + origin ASN 是否命中 IRR route object。 |
| `irr_conflict` / `irr_origin_asns` | IRR 是否存在多 Origin 或衝突 Origin。 |
| `moas` | BGP 多觀察點中是否看到多 Origin ASN。 |
| `route_leak_suspected` | 是否存在明顯路由異常信號。 |
| `prefix_visibility` | BGP 摘要樣本數。 |
| `origin_agreement` | 當前 ASN 在 BGP 摘要中的一致率。 |

### data_quality

`data_quality` 是綜合評分，不代表絕對真值，只表示當前證據是否一致、完整、夠新。

| 字段 | 說明 |
| --- | --- |
| `score` | 0 到 1 的綜合評分。 |
| `level` | `high`、`medium`、`low`。 |
| `source_agreement` | 多源一致性，例如 `rpki_irr_bgp_agree`、`routing_conflict`。 |
| `freshness` | 離線庫新鮮度：`fresh`、`recent`、`stale`、`unknown`。 |
| `signals` | 參與評分的主要信號。 |

### registration

`registration` 來自在線增強和緩存，可能包含：

| 字段 | 說明 |
| --- | --- |
| `cache_hit` | 是否命中在線增強緩存。 |
| `refresh_queued` | `fast` 模式下緩存未命中並已進入後臺刷新。 |
| `refresh_in_progress` | 同一 IP 正在後臺刷新。 |
| `team_cymru` | Team Cymru 當前 ASN / prefix / 國家 / 註冊局。 |
| `ripestat` | RIPEstat 當前宣告信息。 |
| `bgp_path` | RIPE RIS AS Path 多點觀察。 |
| `rdap` | RDAP 摘要。 |
| `whois` | WHOIS 摘要。 |
| `inferred_scene` | 基於 RDAP / WHOIS 文本的場景推斷。 |

### geo_consistency

地理一致性分析會對比：

- `registered_country`：RDAP / WHOIS 註冊地。
- `announced_country`：Team Cymru 當前宣告地。
- `location_country`：ip2region 所在地。
- `bgp_path_hint`：AS Path 主上游。
- `conflict`：是否存在不一致。
- `summary`：簡要結論。

示例：

```json
{
  "registered_country": "SG",
  "announced_country": "HK",
  "location_country": "HK",
  "bgp_path_hint": "AS1299",
  "conflict": true,
  "confidence": 0.65,
  "summary": "註冊地 SG，宣告地 HK，所在地 HK，BGP 主上游 AS1299"
}
```

### egress

`egress` 用於機房/出口推斷，結合 RIPE RIS AS Path 主上游、PeeringDB IXP / Facility、Team Cymru 宣告地和所在地。判斷時優先使用 IP 當前宣告前綴、Team Cymru 宣告地和 IP 所在地去匹配 PeeringDB presence；ASN 級 presence 只作爲輔助。若目標國家/地區已知但沒有匹配的機房或 IXP，不會輸出外地機房，只保留 `TRANSIT` 結論和不匹配證據。家庭寬帶、移動網絡、教育/政府/組織機構，以及公共 DNS/CDN 等 Anycast 服務，會避免把主上游 PeeringDB 機房當成用戶、基站、校園或辦公出口。它會參與用途融合：低置信度 `NET` 等結果可被提升爲 `IDC`，但不會覆蓋高置信度的 DSL、公共 DNS 等明確用途。

| 字段 | 說明 |
| --- | --- |
| `type` | 推斷類型，例如 `IXP`、`IDC`、`TRANSIT`、`ANYCAST`。`TRANSIT` 表示只保留主上游/路徑輔助信息，未給出具體出口機房；`ANYCAST` 表示公共 DNS/CDN 等全球服務，不把主上游 PeeringDB 機房當成單點出口。 |
| `summary` | 簡要結論。 |
| `origin_asn` | BGP Origin ASN。 |
| `dominant_upstream` | AS Path 主上游 ASN。 |
| `upstream_name` | 主上游名稱。 |
| `presence_asn` | 本次採用 PeeringDB IXP / Facility presence 的 ASN。可能是主上游，也可能是 origin ASN。 |
| `presence_name` | 本次採用 presence 的 ASN 名稱。 |
| `likely_country` / `likely_city` | 疑似出口國家/城市。 |
| `ixps` | PeeringDB 公開互聯點。 |
| `facilities` | PeeringDB 機房 presence。 |
| `confidence` | 推斷置信度。 |
| `evidence` | 推斷依據。 |

示例：

```json
{
  "type": "IDC",
  "summary": "疑似出口 Tsuen Wan HK，主上游 AS1299 Arelion (Twelve99)，機房 Equinix HK1 - Hong Kong/MEGA-i (iAdvantage Hong Kong)",
  "origin_asn": 58453,
  "dominant_upstream": 1299,
  "upstream_name": "Arelion (Twelve99)",
  "likely_country": "HK",
  "likely_city": "Tsuen Wan",
  "facilities": [
    "Equinix HK1 - Hong Kong",
    "MEGA-i (iAdvantage Hong Kong)"
  ],
  "confidence": 0.65
}
```

## 健康檢查

```text
GET /api/health
```

示例：

```bash
curl "http://127.0.0.1:18080/api/health"
```

響應：

```json
{"ok": true}
```

## 配置管理後臺

```text
GET /admin
```

默認只允許本機訪問，地址：

```text
http://127.0.0.1:18080/admin
```

如果 `admin.token` 不爲空，管理 API 需要帶請求頭：

```text
X-Admin-Token: 你的token
```

### 讀取配置

```text
GET /api/admin/config
```

返回當前配置。敏感字段會隱藏，例如 `admin.token`、`openai_api_key`、`anthropic_api_key`、`gemini_api_key`、`ip2proxy.token`。

### 拉取 AI 模型列表

```text
POST /api/admin/ai/models
```

用於後臺配置頁按 provider 在線拉取可用模型。請求字段：

```json
{
  "provider": "openai",
  "api_key": "可選，留空使用已保存配置",
  "base_url": "可選",
  "version": "可選，Anthropic 使用"
}
```

支持 `openai`、`anthropic`、`gemini`。`openai` 會調用 OpenAI 兼容的 `/v1/models`，適合官方 OpenAI 和兼容服務。

### 保存配置

```text
PUT /api/admin/config
```

可保存後臺支持的配置塊，包括 BGP、在線增強、動態規則、IP2Proxy、ip2region 等。示例：

```bash
curl -X PUT "http://127.0.0.1:18080/api/admin/config" \
  -H "Content-Type: application/json" \
  -d '{"bgp":{"enabled":true,"mode":"full","collectors":["all"],"include_updates":false,"refresh_hours":8}}'
```

響應：

```json
{
  "ok": true,
  "restart_required": true
}
```

動態規則來源也可以通過該接口更新，例如：

```bash
curl -X PUT "http://127.0.0.1:18080/api/admin/config" \
  -H "Content-Type: application/json" \
  -d '{"dynamic_rules":{"firehol_level1_url":"https://iplists.firehol.org/files/firehol_level1.netset","firehol_anonymous_url":"","az0_vpn_ip_url":"https://az0-vpnip-public.oooninja.com/ip.txt"}}'
```

### 查看後臺狀態

```text
GET /api/admin/status
```

返回當前配置摘要和離線庫狀態。

### 觸發更新

```text
POST /api/admin/update
```

等價於 `POST /api/db/update`，會啓動後臺離線庫更新。啓用 full BGP 時，會下載 RouteViews / RIPE RIS 最新 RIB，生成本地 BGP 摘要，並編譯 `bgp-index.bin` 緊湊查詢索引。該索引是本機可重建文件，默認不提交到 Git。

## 數據庫狀態

```text
GET /api/db/status
```

示例：

```bash
curl "http://127.0.0.1:18080/api/db/status"
```

常見字段：

| 字段 | 說明 |
| --- | --- |
| `loaded` | 離線庫是否已加載。 |
| `updating` | 是否正在更新。 |
| `prefix_count` | Prefix2AS 網段數量。 |
| `allocation_count` | RIR 分配記錄數量。 |
| `asn_count` | ASN 記錄數量。 |
| `egress_asn_count` | PeeringDB 機房/出口索引裏的 ASN 數量。 |
| `rpki_count` | 已加載的 RPKI VRP 數量。 |
| `irr_route_count` | 已加載的 IRR route/route6 數量。 |
| `bgp_observation_count` | 已加載的 BGP 多觀察點摘要數量。 |
| `history_snapshots` | 歷史 BGP 樣本數量。 |
| `last_error` | 最近一次更新錯誤。 |

## 更新數據庫

```text
POST /api/db/update
```

後臺啓動更新：

```bash
curl -X POST "http://127.0.0.1:18080/api/db/update"
```

等待更新完成：

```bash
curl -X POST "http://127.0.0.1:18080/api/db/update?wait=1"
```

後臺模式返回 `202 Accepted`，等待模式成功返回 `200 OK`。
