package quality

import (
	"strings"
	"testing"

	"ipasn/internal/classify"
)

func TestEvaluateMarksBlocklistAsCritical(t *testing.T) {
	result := Evaluate(Input{
		QueryType:     "ip",
		Scene:         "BLOCKLIST",
		SceneName:     "风险名单",
		Confidence:    0.99,
		Evidence:      []string{"Spamhaus DROP 风险网段", "FireHOL level1 聚合风险网段"},
		RoutingStatus: "announced",
	}, DefaultConfig())

	if result.Score > 20 {
		t.Fatalf("expected low score for blocklist, got %#v", result)
	}
	if result.Grade != "F" || result.RiskLevel != "critical" || result.Recommendation != "block" {
		t.Fatalf("unexpected blocklist quality decision: %#v", result)
	}
	if !containsText(result.RiskReasons, "公开风险名单") {
		t.Fatalf("expected blocklist reason, got %#v", result.RiskReasons)
	}
}

func TestEvaluateDoesNotTreatConsumerPrivacyVPNAsHighRisk(t *testing.T) {
	blockRecommended := false
	normalUserTraffic := true
	result := Evaluate(Input{
		QueryType:  "ip",
		Scene:      "VPN",
		SceneName:  "VPN 出口",
		Confidence: 0.98,
		Evidence:   []string{"Google Fi VPN geofeed"},
		ServicePolicy: &classify.ServicePolicy{
			ServiceName:       "Google Fi VPN",
			ServiceSubtype:    "carrier_privacy_vpn",
			RiskLevel:         "low",
			BlockRecommended:  &blockRecommended,
			NormalUserTraffic: &normalUserTraffic,
		},
	}, DefaultConfig())

	if result.Score < 65 {
		t.Fatalf("expected consumer privacy VPN to keep reasonable score, got %#v", result)
	}
	if result.RiskLevel == "high" || result.RiskLevel == "critical" || result.Recommendation == "block" {
		t.Fatalf("expected no high-risk/block decision for consumer privacy VPN, got %#v", result)
	}
	if !containsText(result.PositiveSignals, "正常用户隐私服务") {
		t.Fatalf("expected privacy positive signal, got %#v", result.PositiveSignals)
	}
}

func TestEvaluateSeparatesIDCFromResidential(t *testing.T) {
	idc := Evaluate(Input{
		QueryType:  "ip",
		Scene:      "IDC",
		SceneName:  "数据中心",
		Confidence: 0.9,
		Egress:     &EgressInput{Type: "IDC", Confidence: 0.7},
	}, DefaultConfig())
	residential := Evaluate(Input{
		QueryType:  "ip",
		Scene:      "DYN",
		SceneName:  "家庭宽带",
		Confidence: 0.86,
	}, DefaultConfig())

	if idc.Score >= residential.Score {
		t.Fatalf("expected IDC score below residential score, idc=%#v residential=%#v", idc, residential)
	}
	if residential.Score < 80 || residential.Recommendation != "allow" {
		t.Fatalf("expected residential IP to be generally clean, got %#v", residential)
	}
	if idc.Recommendation == "block" {
		t.Fatalf("IDC alone should not be a block decision, got %#v", idc)
	}
}

func TestEvaluatePenalizesRoutingConflicts(t *testing.T) {
	result := Evaluate(Input{
		QueryType:  "ip",
		Scene:      "DNS",
		SceneName:  "域名解析",
		Confidence: 0.95,
		RoutingSecurity: &RoutingSecurityInput{
			RPKI:               "invalid",
			IRRConflict:        true,
			RouteLeakSuspected: true,
		},
	}, DefaultConfig())

	if result.Score >= 70 {
		t.Fatalf("expected routing conflict to reduce score, got %#v", result)
	}
	if !containsText(result.RiskReasons, "RPKI Invalid") || !containsText(result.RiskReasons, "路由异常") {
		t.Fatalf("expected routing risk reasons, got %#v", result.RiskReasons)
	}
}

func TestEvaluateAddsAIReviewSignalForLowConfidence(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AILowConfidence = true
	cfg.LowConfidenceThreshold = 0.7
	result := Evaluate(Input{
		QueryType: "ip",
		Scene:     "NET",
	}, cfg)

	if !containsText(result.Labels, "AI_REVIEW") {
		t.Fatalf("expected AI review label for low confidence quality result, got %#v", result)
	}
	if !containsText(result.RiskReasons, "AI 复核") {
		t.Fatalf("expected AI review reason, got %#v", result.RiskReasons)
	}
}

func containsText(values []string, needle string) bool {
	for _, value := range values {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}
