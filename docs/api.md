# API 文档

默认服务地址：

```text
http://127.0.0.1:18080
```

所有接口默认返回 JSON，编码为 UTF-8。

## 查询 IP 或 ASN

```text
GET /api/lookup
```

### 参数

| 参数 | 必填 | 说明 |
| --- | --- | --- |
| `query` | 是 | IP 或 ASN，例如 `8.8.8.8`、`223.119.20.239`、`AS15169`。 |
| `include_location` | 否 | `1`、`true`、`yes`、`on` 表示返回 IP 所在地。默认由 `ip2region.include_default` 决定。 |
| `include_quality` | 否 | `1`、`true`、`yes`、`on` 表示返回 IP 质量 / 纯净度评分。默认由 `quality.include_default` 决定。 |
| `include_performance` | 否 | `1`、`true`、`yes`、`on` 表示返回本次查询性能指标。默认由 `performance.include_default` 决定。 |
| `include_third_party_timing` | 否 | `1` 表示在 `performance.third_party` 里返回第三方源耗时；`0` 表示隐藏第三方明细。默认由 `performance.third_party_default` 决定。 |
| `online_enrichment` | 否 | 在线增强模式：`fast`、`wait`、`off`。默认 `fast`。 |

### online_enrichment

| 值 | 行为 | 适用场景 |
| --- | --- | --- |
| `fast` | 优先返回离线库和缓存；缓存未命中时短暂等待，超时后后台刷新。 | 高并发、页面默认查询。 |
| `wait` | 等 Team Cymru、RIPEstat、RIPE RIS、RDAP、WHOIS 完成或超时后返回。 | 调试单个 IP，需要首次结果完整。 |
| `off` | 不触发在线增强，只返回离线库、规则、历史 BGP 和所在地。 | 只看离线结果或避免外网请求。 |

### 示例

快速查询：

```bash
curl "http://127.0.0.1:18080/api/lookup?query=8.8.8.8"
```

返回所在地：

```bash
curl "http://127.0.0.1:18080/api/lookup?query=223.119.20.239&include_location=1"
```

等待联网增强结果：

```bash
curl "http://127.0.0.1:18080/api/lookup?query=223.119.20.239&include_location=1&online_enrichment=wait"
```

只使用离线库：

```bash
curl "http://127.0.0.1:18080/api/lookup?query=223.119.20.239&online_enrichment=off"
```

返回质量评分：

```bash
curl "http://127.0.0.1:18080/api/lookup?query=1.2.3.4&include_quality=1"
```

返回性能指标并等待在线增强：

```bash
curl "http://127.0.0.1:18080/api/lookup?query=8.8.8.8&include_performance=1&include_third_party_timing=1&online_enrichment=wait"
```

查询 ASN：

```bash
curl "http://127.0.0.1:18080/api/lookup?query=AS15169"
```

### 主要响应字段

| 字段 | 说明 |
| --- | --- |
| `ok` | 查询是否成功。 |
| `query_type` | `ip` 或 `asn`。 |
| `ip` / `asn` | 命中的 IP 或 ASN。 |
| `company` | 公司或网络名称。 |
| `country` / `registry` | 离线库或分配记录里的国家/地区和注册局。 |
| `matched_prefix` | 命中的网段。 |
| `routing_status` | `announced`、`not_announced` 等。 |
| `scene` / `scene_name` | 主应用场景。低置信度时可被多源证据修正。 |
| `inferred_scene` / `inferred_scene_name` | 推断用途。 |
| `confidence` | 主场景置信度。 |
| `inferred_confidence` / `inferred_source` | 推断用途置信度和来源。 |
| `service_policy` | 服务处置策略元数据。消费者隐私代理 / VPN 等正常用户流量会在这里标记是否建议拦截。 |
| `evidence` | 判断依据。 |
| `sources` | 使用的数据源。 |
| `registration` | 在线增强信息。 |
| `geo_consistency` | 地理一致性分析。 |
| `egress` | 机房/出口推断。 |
| `routing_security` | RPKI / IRR / BGP 多源路由可靠性分析。 |
| `data_quality` | 综合数据质量评分。 |
| `ip_quality` | IP 质量 / 纯净度评分，需启用默认输出或传 `include_quality=1`。 |
| `performance` | 查询性能指标，需启用默认输出或传 `include_performance=1`。 |
| `source_votes` | 场景判断的多源投票。 |
| `warnings` | 路由、地理或来源冲突提示。 |
| `location` | IP 所在地，需启用或传 `include_location=1`。 |
| `history` | 历史 BGP 样本。 |
| `prefixes` | 相关网段。 |
| `db` | 当前离线库状态。 |

用途融合逻辑：主规则高置信度命中时优先保留主规则，例如公共 DNS、DSL 反向 DNS、保留地址等；在线增强里的机房/出口信息会作为参考证据写入 `evidence`，`inferred_source` 会显示 `主场景规则 + 在线增强参考`。主规则低置信度时，会把主规则、RDAP / WHOIS、AI 和机房/出口推断放入 `source_votes` 做加权投票；只有多源一致且分数明显高于原结论时，才修正 `scene` 和 `inferred_scene`。

### performance

`performance` 用于调试查询慢在哪里，不建议对所有生产调用默认开启。字段单位都是毫秒。

| 字段 | 说明 |
| --- | --- |
| `total_ms` | 本次请求总耗时。 |
| `local_offline_ms` | 本地离线查询耗时，包括规则、Prefix2AS、ASN、分配记录、历史 BGP、反向 DNS 等在线增强前步骤。 |
| `online_enrichment_ms` | 当前请求等待在线增强的耗时。`fast` 模式缓存未命中时可能只是前台等待窗口。 |
| `location_ms` | IP 所在地查询耗时。 |
| `quality_ms` | IP 质量评分耗时。 |
| `ai_ms` | AI 辅助判断耗时，未启用或未触发时通常不输出。 |
| `cache_hit` | 在线增强是否命中缓存。 |
| `refresh_queued` / `refresh_in_progress` | 在线增强是否已转后台刷新。 |
| `third_party` | 第三方源耗时列表，包含 `name`、`url`、`duration_ms`、`ok`。只记录当前请求实际等待的 Team Cymru、RIPEstat、RDAP、WHOIS、RIPE RIS 等调用。 |

### ip_quality

`ip_quality` 用于风控或访问策略，不改变 `scene`。`scene` 表示技术场景，`ip_quality.recommendation` 表示建议动作。

| 字段 | 说明 |
| --- | --- |
| `score` | 0-100，越高越干净。 |
| `grade` | A/B/C/D/F。 |
| `risk_level` | `low`、`medium`、`high`、`critical`。 |
| `recommendation` | `allow`、`review`、`challenge`、`rate_limit`、`block`。 |
| `confidence` | 评分置信度。 |
| `labels` | 命中的质量标签，例如 `VPN`、`BLOCKLIST`、`RPKI_INVALID`。 |
| `risk_reasons` | 扣分原因。 |
| `positive_signals` | 正向信号。 |
| `dimensions` | reputation、anonymity、infrastructure、routing_trust、registration、user_type 分维度评分。 |

### 单独质量接口

```text
GET /api/quality
```

参数与 `/api/lookup` 一致，固定返回 `ip_quality`：

```bash
curl "http://127.0.0.1:18080/api/quality?query=1.2.3.4"
```

### service_policy

`service_policy` 用于把技术场景和处置策略分开。例如 Apple iCloud Private Relay 仍属于 `PROXY`，Google Fi VPN 仍属于 `VPN`，但它们是系统级或运营商级消费者隐私服务，默认不建议直接按高风险代理封禁。

| 字段 | 说明 |
| --- | --- |
| `service_name` | 服务名称，例如 `Apple iCloud Private Relay`。 |
| `service_subtype` | 服务子类型，例如 `consumer_privacy_proxy`、`carrier_privacy_vpn`。 |
| `risk_level` | 风险等级，当前可为 `low` 等。 |
| `block_recommended` | 是否建议默认拦截。消费者隐私服务通常为 `false`。 |
| `normal_user_traffic` | 是否更接近正常用户流量。 |
| `rule_id` / `rule_name` | 命中的离线服务规则。 |

### routing_security

`routing_security` 来自离线 RPKI VRP、IRR route/route6 对象和 BGP 多观察点摘要。没有对应离线文件时该字段可能为空。

| 字段 | 说明 |
| --- | --- |
| `rpki` | `valid`、`invalid`、`not_found`。 |
| `rpki_reason` | RPKI 判断原因。 |
| `rpki_matched_prefix` / `rpki_max_length` | 命中的 ROA / VRP 范围。 |
| `irr_matched` | 当前 prefix + origin ASN 是否命中 IRR route object。 |
| `irr_conflict` / `irr_origin_asns` | IRR 是否存在多 Origin 或冲突 Origin。 |
| `moas` | BGP 多观察点中是否看到多 Origin ASN。 |
| `route_leak_suspected` | 是否存在明显路由异常信号。 |
| `prefix_visibility` | BGP 摘要样本数。 |
| `origin_agreement` | 当前 ASN 在 BGP 摘要中的一致率。 |

### data_quality

`data_quality` 是综合评分，不代表绝对真值，只表示当前证据是否一致、完整、够新。

| 字段 | 说明 |
| --- | --- |
| `score` | 0 到 1 的综合评分。 |
| `level` | `high`、`medium`、`low`。 |
| `source_agreement` | 多源一致性，例如 `rpki_irr_bgp_agree`、`routing_conflict`。 |
| `freshness` | 离线库新鲜度：`fresh`、`recent`、`stale`、`unknown`。 |
| `signals` | 参与评分的主要信号。 |

### registration

`registration` 来自在线增强和缓存，可能包含：

| 字段 | 说明 |
| --- | --- |
| `cache_hit` | 是否命中在线增强缓存。 |
| `refresh_queued` | `fast` 模式下缓存未命中并已进入后台刷新。 |
| `refresh_in_progress` | 同一 IP 正在后台刷新。 |
| `team_cymru` | Team Cymru 当前 ASN / prefix / 国家 / 注册局。 |
| `ripestat` | RIPEstat 当前宣告信息。 |
| `bgp_path` | RIPE RIS AS Path 多点观察。 |
| `rdap` | RDAP 摘要。 |
| `whois` | WHOIS 摘要。 |
| `inferred_scene` | 基于 RDAP / WHOIS 文本的场景推断。 |

### geo_consistency

地理一致性分析会对比：

- `registered_country`：RDAP / WHOIS 注册地。
- `announced_country`：Team Cymru 当前宣告地。
- `location_country`：ip2region 所在地。
- `bgp_path_hint`：AS Path 主上游。
- `conflict`：是否存在不一致。
- `summary`：简要结论。

示例：

```json
{
  "registered_country": "SG",
  "announced_country": "HK",
  "location_country": "HK",
  "bgp_path_hint": "AS1299",
  "conflict": true,
  "confidence": 0.65,
  "summary": "注册地 SG，宣告地 HK，所在地 HK，BGP 主上游 AS1299"
}
```

### egress

`egress` 用于机房/出口推断，结合 RIPE RIS AS Path 主上游、PeeringDB IXP / Facility、Team Cymru 宣告地和所在地。判断时优先使用 IP 当前宣告前缀、Team Cymru 宣告地和 IP 所在地去匹配 PeeringDB presence；ASN 级 presence 只作为辅助。若目标国家/地区已知但没有匹配的机房或 IXP，不会输出外地机房，只保留 `TRANSIT` 结论和不匹配证据。家庭宽带、移动网络、教育/政府/组织机构，以及公共 DNS/CDN 等 Anycast 服务，会避免把主上游 PeeringDB 机房当成用户、基站、校园或办公出口。它会参与用途融合：低置信度 `NET` 等结果可被提升为 `IDC`，但不会覆盖高置信度的 DSL、公共 DNS 等明确用途。

| 字段 | 说明 |
| --- | --- |
| `type` | 推断类型，例如 `IXP`、`IDC`、`TRANSIT`、`ANYCAST`。`TRANSIT` 表示只保留主上游/路径辅助信息，未给出具体出口机房；`ANYCAST` 表示公共 DNS/CDN 等全球服务，不把主上游 PeeringDB 机房当成单点出口。 |
| `summary` | 简要结论。 |
| `origin_asn` | BGP Origin ASN。 |
| `dominant_upstream` | AS Path 主上游 ASN。 |
| `upstream_name` | 主上游名称。 |
| `presence_asn` | 本次采用 PeeringDB IXP / Facility presence 的 ASN。可能是主上游，也可能是 origin ASN。 |
| `presence_name` | 本次采用 presence 的 ASN 名称。 |
| `likely_country` / `likely_city` | 疑似出口国家/城市。 |
| `ixps` | PeeringDB 公开互联点。 |
| `facilities` | PeeringDB 机房 presence。 |
| `confidence` | 推断置信度。 |
| `evidence` | 推断依据。 |

示例：

```json
{
  "type": "IDC",
  "summary": "疑似出口 Tsuen Wan HK，主上游 AS1299 Arelion (Twelve99)，机房 Equinix HK1 - Hong Kong/MEGA-i (iAdvantage Hong Kong)",
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

## 健康检查

```text
GET /api/health
```

示例：

```bash
curl "http://127.0.0.1:18080/api/health"
```

响应：

```json
{"ok": true}
```

## 配置管理后台

```text
GET /admin
```

默认只允许本机访问，地址：

```text
http://127.0.0.1:18080/admin
```

如果 `admin.token` 不为空，管理 API 需要带请求头：

```text
X-Admin-Token: 你的token
```

### 读取配置

```text
GET /api/admin/config
```

返回当前配置。敏感字段会隐藏，例如 `admin.token`、`openai_api_key`、`anthropic_api_key`、`gemini_api_key`、`ip2proxy.token`。

### 拉取 AI 模型列表

```text
POST /api/admin/ai/models
```

用于后台配置页按 provider 在线拉取可用模型。请求字段：

```json
{
  "provider": "openai",
  "api_key": "可选，留空使用已保存配置",
  "base_url": "可选",
  "version": "可选，Anthropic 使用"
}
```

支持 `openai`、`anthropic`、`gemini`。`openai` 会调用 OpenAI 兼容的 `/v1/models`，适合官方 OpenAI 和兼容服务。

### 保存配置

```text
PUT /api/admin/config
```

可保存后台支持的配置块，包括 BGP、在线增强、动态规则、IP2Proxy、ip2region 等。示例：

```bash
curl -X PUT "http://127.0.0.1:18080/api/admin/config" \
  -H "Content-Type: application/json" \
  -d '{"bgp":{"enabled":true,"mode":"full","collectors":["all"],"include_updates":false,"refresh_hours":8}}'
```

响应：

```json
{
  "ok": true,
  "restart_required": true
}
```

动态规则来源也可以通过该接口更新，例如：

```bash
curl -X PUT "http://127.0.0.1:18080/api/admin/config" \
  -H "Content-Type: application/json" \
  -d '{"dynamic_rules":{"firehol_level1_url":"https://iplists.firehol.org/files/firehol_level1.netset","firehol_anonymous_url":"","az0_vpn_ip_url":"https://az0-vpnip-public.oooninja.com/ip.txt"}}'
```

### 查看后台状态

```text
GET /api/admin/status
```

返回当前配置摘要和离线库状态。

### 触发更新

```text
POST /api/admin/update
```

等价于 `POST /api/db/update`，会启动后台离线库更新。启用 full BGP 时，会下载 RouteViews / RIPE RIS 最新 RIB，生成本地 BGP 摘要，并编译 `bgp-index.bin` 紧凑查询索引。该索引是本机可重建文件，默认不提交到 Git。

## 数据库状态

```text
GET /api/db/status
```

示例：

```bash
curl "http://127.0.0.1:18080/api/db/status"
```

常见字段：

| 字段 | 说明 |
| --- | --- |
| `loaded` | 离线库是否已加载。 |
| `updating` | 是否正在更新。 |
| `prefix_count` | Prefix2AS 网段数量。 |
| `allocation_count` | RIR 分配记录数量。 |
| `asn_count` | ASN 记录数量。 |
| `egress_asn_count` | PeeringDB 机房/出口索引里的 ASN 数量。 |
| `rpki_count` | 已加载的 RPKI VRP 数量。 |
| `irr_route_count` | 已加载的 IRR route/route6 数量。 |
| `bgp_observation_count` | 已加载的 BGP 多观察点摘要数量。 |
| `history_snapshots` | 历史 BGP 样本数量。 |
| `last_error` | 最近一次更新错误。 |

## 更新数据库

```text
POST /api/db/update
```

后台启动更新：

```bash
curl -X POST "http://127.0.0.1:18080/api/db/update"
```

等待更新完成：

```bash
curl -X POST "http://127.0.0.1:18080/api/db/update?wait=1"
```

后台模式返回 `202 Accepted`，等待模式成功返回 `200 OK`。
