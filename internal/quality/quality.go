package quality

import (
	"math"
	"sort"
	"strings"

	"ipasn/internal/classify"
	"ipasn/internal/enrich"
)

type Config struct {
	Enabled                bool
	IncludeDefault         bool
	AILowConfidence        bool
	LowConfidenceThreshold float64
	AllowScore             int
	ReviewScore            int
	ChallengeScore         int
	RateLimitScore         int
}

type Input struct {
	QueryType          string
	IP                 string
	ASN                int
	Scene              string
	SceneName          string
	InferredScene      string
	InferredSceneName  string
	Confidence         float64
	InferredConfidence float64
	RoutingStatus      string
	AllocationStatus   string
	Evidence           []string
	ServicePolicy      *classify.ServicePolicy
	Registration       *enrich.Result
	GeoConsistency     *enrich.GeoConsistencyAnalysis
	Egress             *EgressInput
	RoutingSecurity    *RoutingSecurityInput
	DataQualityScore   float64
}

type EgressInput struct {
	Type       string
	Confidence float64
}

type RoutingSecurityInput struct {
	RPKI               string
	IRRConflict        bool
	MOAS               bool
	RouteLeakSuspected bool
	OriginAgreement    float64
}

type Result struct {
	Score           int            `json:"score"`
	Grade           string         `json:"grade"`
	RiskLevel       string         `json:"risk_level"`
	Recommendation  string         `json:"recommendation"`
	Confidence      float64        `json:"confidence"`
	Labels          []string       `json:"labels,omitempty"`
	RiskReasons     []string       `json:"risk_reasons,omitempty"`
	PositiveSignals []string       `json:"positive_signals,omitempty"`
	Dimensions      map[string]int `json:"dimensions,omitempty"`
	Evidence        []string       `json:"evidence,omitempty"`
}

func DefaultConfig() Config {
	return Config{
		Enabled:                true,
		IncludeDefault:         false,
		AILowConfidence:        true,
		LowConfidenceThreshold: 0.6,
		AllowScore:             80,
		ReviewScore:            60,
		ChallengeScore:         40,
		RateLimitScore:         20,
	}
}

func Evaluate(input Input, cfg Config) Result {
	cfg = normalizeConfig(cfg)
	scene := strings.ToUpper(strings.TrimSpace(input.Scene))
	if scene == "" {
		scene = strings.ToUpper(strings.TrimSpace(input.InferredScene))
	}
	score := 82
	labels := []string{}
	riskReasons := []string{}
	positiveSignals := []string{}
	dimensions := map[string]int{
		"reputation":     100,
		"anonymity":      100,
		"infrastructure": 90,
		"routing_trust":  80,
		"registration":   70,
		"user_type":      70,
	}
	addRisk := func(points int, reason string) {
		score -= points
		if reason != "" {
			riskReasons = appendUnique(riskReasons, reason)
		}
	}
	addPositive := func(points int, signal string) {
		score += points
		if signal != "" {
			positiveSignals = appendUnique(positiveSignals, signal)
		}
	}

	if scene != "" {
		labels = appendUnique(labels, scene)
	}
	switch scene {
	case "BLOCKLIST":
		addRisk(78, "命中公开风险名单或 DROP 列表")
		dimensions["reputation"] = 10
	case "TOR":
		addRisk(70, "命中 Tor 出口节点")
		dimensions["anonymity"] = 10
	case "PROXY":
		addRisk(45, "命中代理服务")
		dimensions["anonymity"] = 45
	case "VPN":
		addRisk(40, "命中 VPN 出口")
		dimensions["anonymity"] = 50
	case "IDC":
		addRisk(25, "命中数据中心或云服务网络")
		dimensions["infrastructure"] = 55
	case "CDN":
		addRisk(10, "命中 CDN / Anycast 公共服务网络")
		dimensions["infrastructure"] = 75
	case "BOT":
		addRisk(18, "命中搜索爬虫或自动化访问来源")
	case "MON":
		addRisk(12, "命中监控探测来源")
	case "BOGON":
		addRisk(82, "命中保留地址或不可公网路由地址")
		dimensions["reputation"] = 5
	case "DYN":
		addPositive(8, "家庭宽带倾向，接近正常用户来源")
		dimensions["user_type"] = 90
	case "MOB":
		addPositive(7, "移动网络倾向，接近正常用户来源")
		dimensions["user_type"] = 88
	case "EDU", "GOV", "ORG", "GTW":
		addPositive(4, "机构或企业网络来源")
		dimensions["user_type"] = 82
	}

	applyServicePolicy(input.ServicePolicy, &score, &labels, &riskReasons, &positiveSignals, dimensions)
	applyEvidenceHints(input.Evidence, &labels, &riskReasons)
	applyRouting(input.RoutingSecurity, &score, &labels, &riskReasons, &positiveSignals, dimensions)
	if input.GeoConsistency != nil && input.GeoConsistency.Conflict {
		addRisk(8, "注册地、宣告地或所在地存在差异")
		dimensions["registration"] = minInt(dimensions["registration"], 55)
	}
	if strings.EqualFold(input.RoutingStatus, "not_announced") {
		addRisk(8, "当前 BGP 未宣告")
	}
	if input.Registration != nil {
		addPositive(3, "RDAP / WHOIS 注册信息可用")
		dimensions["registration"] = maxInt(dimensions["registration"], 78)
	}
	if input.Egress != nil {
		switch input.Egress.Type {
		case "IDC":
			addRisk(10, "机房/出口推断显示为数据中心")
			dimensions["infrastructure"] = minInt(dimensions["infrastructure"], 55)
		case "IXP":
			addRisk(5, "机房/出口推断显示为公开互联基础设施")
		case "ANYCAST":
			addPositive(2, "Anycast / 公共服务不定位单点出口")
		}
	}
	if input.DataQualityScore >= 0.8 {
		addPositive(2, "数据质量较高")
	} else if input.DataQualityScore > 0 && input.DataQualityScore < 0.55 {
		addRisk(5, "数据质量偏低")
	}

	score = clampInt(score, 0, 100)
	confidence := qualityConfidence(input, len(riskReasons), len(positiveSignals))
	if cfg.AILowConfidence && confidence < cfg.LowConfidenceThreshold {
		labels = appendUnique(labels, "AI_REVIEW")
		riskReasons = appendUnique(riskReasons, "质量评分低置信度，建议 AI 复核")
	}
	sort.Strings(labels)
	return Result{
		Score:           score,
		Grade:           grade(score),
		RiskLevel:       riskLevel(score),
		Recommendation:  recommendation(score, cfg),
		Confidence:      confidence,
		Labels:          labels,
		RiskReasons:     riskReasons,
		PositiveSignals: positiveSignals,
		Dimensions:      dimensions,
		Evidence:        trimEvidence(input.Evidence, 12),
	}
}

func applyServicePolicy(policy *classify.ServicePolicy, score *int, labels, riskReasons, positiveSignals *[]string, dimensions map[string]int) {
	if policy == nil {
		return
	}
	if policy.ServiceSubtype != "" {
		*labels = appendUnique(*labels, strings.ToUpper(policy.ServiceSubtype))
	}
	if policy.NormalUserTraffic != nil && *policy.NormalUserTraffic {
		*score += 25
		*positiveSignals = appendUnique(*positiveSignals, "服务策略标记为正常用户隐私服务")
		dimensions["anonymity"] = maxInt(dimensions["anonymity"], 72)
	}
	if policy.BlockRecommended != nil && !*policy.BlockRecommended {
		*score += 8
		*positiveSignals = appendUnique(*positiveSignals, "服务规则不建议默认拦截")
	}
	if strings.EqualFold(policy.RiskLevel, "low") {
		*score += 6
		*positiveSignals = appendUnique(*positiveSignals, "服务规则风险等级为 low")
	}
	if strings.EqualFold(policy.RiskLevel, "high") {
		*score -= 12
		*riskReasons = appendUnique(*riskReasons, "服务规则风险等级为 high")
	}
}

func applyEvidenceHints(evidence []string, labels, riskReasons *[]string) {
	for _, item := range evidence {
		lower := strings.ToLower(item)
		switch {
		case strings.Contains(lower, "spamhaus") || strings.Contains(lower, "firehol level1"):
			*labels = appendUnique(*labels, "BLOCKLIST")
			*riskReasons = appendUnique(*riskReasons, "命中公开风险名单或 DROP 列表")
		case strings.Contains(lower, "az0/vpn_ip") || strings.Contains(lower, "ip2proxy 离线库标记为 vpn"):
			*labels = appendUnique(*labels, "VPN")
		case strings.Contains(lower, "tor"):
			*labels = appendUnique(*labels, "TOR")
		}
	}
}

func applyRouting(security *RoutingSecurityInput, score *int, labels, riskReasons, positiveSignals *[]string, dimensions map[string]int) {
	if security == nil {
		return
	}
	switch strings.ToLower(security.RPKI) {
	case "valid":
		*score += 4
		*positiveSignals = appendUnique(*positiveSignals, "RPKI Valid")
		dimensions["routing_trust"] = maxInt(dimensions["routing_trust"], 88)
	case "invalid":
		*score -= 25
		*labels = appendUnique(*labels, "RPKI_INVALID")
		*riskReasons = appendUnique(*riskReasons, "RPKI Invalid：ROA 与当前宣告不一致")
		dimensions["routing_trust"] = 35
	}
	if security.IRRConflict {
		*score -= 8
		*labels = appendUnique(*labels, "IRR_CONFLICT")
		*riskReasons = appendUnique(*riskReasons, "IRR route object 存在冲突")
		dimensions["routing_trust"] = minInt(dimensions["routing_trust"], 60)
	}
	if security.MOAS {
		*score -= 10
		*labels = appendUnique(*labels, "MOAS")
		*riskReasons = appendUnique(*riskReasons, "BGP MOAS：同一前缀存在多个 Origin ASN")
		dimensions["routing_trust"] = minInt(dimensions["routing_trust"], 55)
	}
	if security.RouteLeakSuspected {
		*score -= 18
		*labels = appendUnique(*labels, "ROUTE_ANOMALY")
		*riskReasons = appendUnique(*riskReasons, "疑似路由异常")
		dimensions["routing_trust"] = minInt(dimensions["routing_trust"], 35)
	}
	if security.OriginAgreement >= 0.9 {
		*score += 3
		*positiveSignals = appendUnique(*positiveSignals, "BGP Origin 高一致")
	}
}

func normalizeConfig(cfg Config) Config {
	defaults := DefaultConfig()
	if cfg.AllowScore <= 0 {
		cfg.AllowScore = defaults.AllowScore
	}
	if cfg.ReviewScore <= 0 {
		cfg.ReviewScore = defaults.ReviewScore
	}
	if cfg.ChallengeScore <= 0 {
		cfg.ChallengeScore = defaults.ChallengeScore
	}
	if cfg.RateLimitScore <= 0 {
		cfg.RateLimitScore = defaults.RateLimitScore
	}
	if cfg.LowConfidenceThreshold <= 0 || cfg.LowConfidenceThreshold > 1 {
		cfg.LowConfidenceThreshold = defaults.LowConfidenceThreshold
	}
	return cfg
}

func recommendation(score int, cfg Config) string {
	switch {
	case score >= cfg.AllowScore:
		return "allow"
	case score >= cfg.ReviewScore:
		return "review"
	case score >= cfg.ChallengeScore:
		return "challenge"
	case score >= cfg.RateLimitScore:
		return "rate_limit"
	default:
		return "block"
	}
}

func grade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}

func riskLevel(score int) string {
	switch {
	case score >= 80:
		return "low"
	case score >= 60:
		return "medium"
	case score >= 40:
		return "high"
	default:
		return "critical"
	}
}

func qualityConfidence(input Input, riskCount, positiveCount int) float64 {
	confidence := 0.52
	if input.Confidence > 0 {
		confidence += math.Min(input.Confidence, 1) * 0.25
	}
	if input.ServicePolicy != nil {
		confidence += 0.08
	}
	if input.RoutingSecurity != nil {
		confidence += 0.08
	}
	if len(input.Evidence) > 0 {
		confidence += 0.05
	}
	if riskCount+positiveCount >= 3 {
		confidence += 0.04
	}
	return clampFloat(confidence, 0.35, 0.98)
}

func trimEvidence(values []string, limit int) []string {
	if limit <= 0 || len(values) <= limit {
		return append([]string(nil), values...)
	}
	return append([]string(nil), values[:limit]...)
}

func appendUnique(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func clampInt(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func clampFloat(value, minValue, maxValue float64) float64 {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
