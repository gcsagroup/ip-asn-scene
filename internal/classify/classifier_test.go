package classify

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ipasn/internal/store"
)

func TestClassifierReturnsBogonForPrivateIP(t *testing.T) {
	result := Classify(Input{IP: netip.MustParseAddr("192.168.1.1")})
	if result.Scene != "BOGON" {
		t.Fatalf("expected BOGON, got %s", result.Scene)
	}
	if result.Confidence < 0.99 {
		t.Fatalf("expected high confidence, got %f", result.Confidence)
	}
}

func TestClassifierDetectsKnownDNS(t *testing.T) {
	result := Classify(Input{
		IP:      netip.MustParseAddr("8.8.8.8"),
		Profile: store.ASNProfile{ASN: 15169, Name: "Google LLC", InfoType: "Content"},
		RDNS:    "dns.google",
	})
	if result.Scene != "DNS" {
		t.Fatalf("expected DNS, got %s", result.Scene)
	}
}

func TestClassifierDetects114DNS(t *testing.T) {
	result := Classify(Input{
		IP:      netip.MustParseAddr("114.114.114.114"),
		Profile: store.ASNProfile{ASN: 21859, Name: "Zenlayer Inc", InfoType: "Content"},
		RDNS:    "public1.114dns.com",
	})
	if result.Scene != "DNS" {
		t.Fatalf("expected DNS, got %s with evidence %#v", result.Scene, result.Evidence)
	}
}

func TestClassifierLoadsOfflineServiceRules(t *testing.T) {
	resetServiceRulesForTest(t)
	path := filepath.Join(t.TempDir(), "services.json")
	body := []byte(`{
		"version": "test",
		"rules": [
			{
				"id": "test-stun",
				"name": "Test STUN",
				"scene": "STUN",
				"scene_name": "NAT 穿透",
				"confidence": 0.99,
				"prefixes": ["203.0.114.10/32"]
			}
		]
	}`)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := LoadServiceRules(path); err != nil {
		t.Fatal(err)
	}

	result := Classify(Input{IP: netip.MustParseAddr("203.0.114.10")})
	if result.Scene != "STUN" || result.SceneName != "NAT 穿透" {
		t.Fatalf("expected STUN from offline service rules, got %#v", result)
	}
	if len(result.Evidence) == 0 || result.Evidence[0] != "命中离线服务规则：Test STUN" {
		t.Fatalf("unexpected evidence: %#v", result.Evidence)
	}
}

func TestClassifierAcceptsExtendedOfflineServiceScenes(t *testing.T) {
	resetServiceRulesForTest(t)
	path := filepath.Join(t.TempDir(), "services.json")
	body := []byte(`{
		"version": "test",
		"rules": [
			{"id": "vpn", "name": "VPN", "scene": "VPN", "prefixes": ["45.45.45.1/32"]},
			{"id": "proxy", "name": "Proxy", "scene": "PROXY", "prefixes": ["45.45.45.2/32"]},
			{"id": "tor", "name": "Tor", "scene": "TOR", "prefixes": ["45.45.45.3/32"]},
			{"id": "bot", "name": "Bot", "scene": "BOT", "prefixes": ["45.45.45.4/32"]},
			{"id": "mail", "name": "Mail", "scene": "MAIL", "prefixes": ["45.45.45.5/32"]},
			{"id": "mon", "name": "Monitor", "scene": "MON", "prefixes": ["45.45.45.6/32"]},
			{"id": "iot", "name": "IoT", "scene": "IOT", "prefixes": ["45.45.45.7/32"]},
			{"id": "blocklist", "name": "Blocklist", "scene": "BLOCKLIST", "prefixes": ["45.45.45.8/32"]}
		]
	}`)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := LoadServiceRules(path); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		ip    string
		scene string
		name  string
	}{
		{"45.45.45.1", "VPN", "VPN 出口"},
		{"45.45.45.2", "PROXY", "代理服务"},
		{"45.45.45.3", "TOR", "Tor 出口"},
		{"45.45.45.4", "BOT", "搜索爬虫"},
		{"45.45.45.5", "MAIL", "邮件服务"},
		{"45.45.45.6", "MON", "监控探测"},
		{"45.45.45.7", "IOT", "物联网平台"},
		{"45.45.45.8", "BLOCKLIST", "风险名单"},
	}
	for _, tc := range cases {
		result := Classify(Input{IP: netip.MustParseAddr(tc.ip)})
		if result.Scene != tc.scene || result.SceneName != tc.name {
			t.Fatalf("expected %s %s for %s, got %#v", tc.scene, tc.name, tc.ip, result)
		}
	}
}

func TestLoadServiceRuleFilesMergesExistingFiles(t *testing.T) {
	resetServiceRulesForTest(t)
	dir := t.TempDir()
	staticPath := filepath.Join(dir, "static.json")
	generatedPath := filepath.Join(dir, "generated.json")
	if err := os.WriteFile(staticPath, []byte(`{"rules":[{"id":"static-dns","name":"Static DNS","scene":"DNS","prefixes":["45.45.45.10/32"]}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(generatedPath, []byte(`{"rules":[{"id":"generated-tor","name":"Generated Tor","scene":"TOR","prefixes":["45.45.45.11/32"]}]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := LoadServiceRuleFiles(staticPath, filepath.Join(dir, "missing.json"), generatedPath); err != nil {
		t.Fatal(err)
	}

	dns := Classify(Input{IP: netip.MustParseAddr("45.45.45.10")})
	if dns.Scene != "DNS" {
		t.Fatalf("expected static DNS rule, got %#v", dns)
	}
	tor := Classify(Input{IP: netip.MustParseAddr("45.45.45.11")})
	if tor.Scene != "TOR" {
		t.Fatalf("expected generated TOR rule, got %#v", tor)
	}
}

func TestLoadServiceRuleFilesWatchesMissingGeneratedFile(t *testing.T) {
	resetServiceRulesForTest(t)
	dir := t.TempDir()
	staticPath := filepath.Join(dir, "static.json")
	generatedPath := filepath.Join(dir, "generated.json")
	if err := os.WriteFile(staticPath, []byte(`{"rules":[{"id":"static-dns","name":"Static DNS","scene":"DNS","prefixes":["45.45.45.20/32"]}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := LoadServiceRuleFiles(staticPath, generatedPath); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(generatedPath, []byte(`{"rules":[{"id":"generated-tor","name":"Generated Tor","scene":"TOR","prefixes":["45.45.45.21/32"]}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	serviceRules.Lock()
	serviceRules.nextReloadCheck = time.Now().Add(-time.Second)
	serviceRules.Unlock()

	tor := Classify(Input{IP: netip.MustParseAddr("45.45.45.21")})
	if tor.Scene != "TOR" {
		t.Fatalf("expected generated TOR rule after file appears, got %#v", tor)
	}
}

func TestBundledServiceRulesCoverPublicDNSAndSTUN(t *testing.T) {
	resetServiceRulesForTest(t)
	path := filepath.Join("..", "..", "rules", "services.json")
	if err := LoadServiceRules(path); err != nil {
		t.Fatal(err)
	}

	dns := Classify(Input{IP: netip.MustParseAddr("114.114.114.114")})
	if dns.Scene != "DNS" {
		t.Fatalf("expected bundled DNS rule, got %#v", dns)
	}
	stun := Classify(Input{IP: netip.MustParseAddr("74.125.250.129")})
	if stun.Scene != "STUN" {
		t.Fatalf("expected bundled STUN rule, got %#v", stun)
	}
}

func TestOfflineServiceRulesOverrideProviderProfile(t *testing.T) {
	resetServiceRulesForTest(t)
	path := filepath.Join("..", "..", "rules", "services.json")
	if err := LoadServiceRules(path); err != nil {
		t.Fatal(err)
	}

	result := Classify(Input{
		IP:      netip.MustParseAddr("162.159.207.0"),
		Profile: store.ASNProfile{Name: "Cloudflare", InfoType: "Content"},
	})
	if result.Scene != "STUN" {
		t.Fatalf("expected exact STUN service rule to win, got %#v", result)
	}
}

func TestClassifierLoadsASNSceneRules(t *testing.T) {
	resetServiceRulesForTest(t)
	resetASNSceneRulesForTest(t)
	path := filepath.Join(t.TempDir(), "asn_scenes.yaml")
	body := []byte(`rules:
  - asn: 721
    scene: GOV
    name: US DoD
    confidence: 0.9
    source: manual_gov
  - asn: 786
    scene: EDU
    name: Janet
    confidence: 0.88
    source: manual_nren
  - asn: 20057
    scene: MOB
    name: AT&T Mobility
    confidence: 0.88
    source: manual_mobile
`)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := LoadASNSceneRules(path); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		asn  int
		want string
	}{
		{721, "GOV"},
		{786, "EDU"},
		{20057, "MOB"},
	}
	for _, tc := range cases {
		result := Classify(Input{Profile: store.ASNProfile{ASN: tc.asn}})
		if result.Scene != tc.want {
			t.Fatalf("expected AS%d to classify as %s, got %#v", tc.asn, tc.want, result)
		}
	}
}

func TestServicePrefixRulesOverrideASNSceneRules(t *testing.T) {
	resetServiceRulesForTest(t)
	resetASNSceneRulesForTest(t)
	dir := t.TempDir()
	asnPath := filepath.Join(dir, "asn_scenes.yaml")
	if err := os.WriteFile(asnPath, []byte(`rules:
  - asn: 45102
    scene: IDC
    name: Alibaba Cloud
    confidence: 0.9
`), 0o644); err != nil {
		t.Fatal(err)
	}
	servicePath := filepath.Join(dir, "services.json")
	if err := os.WriteFile(servicePath, []byte(`{"rules":[{"id":"alidns","name":"AliDNS","scene":"DNS","confidence":0.99,"prefixes":["223.5.5.5/32"]}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := LoadASNSceneRules(asnPath); err != nil {
		t.Fatal(err)
	}
	if err := LoadServiceRules(servicePath); err != nil {
		t.Fatal(err)
	}
	if matches := currentPrefixMatches(netip.MustParseAddr("223.5.5.5")); len(matches) == 0 {
		t.Fatalf("expected service prefix match")
	} else if matches[0].Points < 190 {
		t.Fatalf("expected high priority service prefix match, got %#v", matches)
	}

	result := Classify(Input{
		IP:      netip.MustParseAddr("223.5.5.5"),
		Profile: store.ASNProfile{ASN: 45102, Name: "Alibaba"},
	})
	if result.Scene != "DNS" {
		t.Fatalf("expected service prefix DNS to override ASN IDC, got %#v", result)
	}
}

func TestMoreSpecificServicePrefixWinsWhenServiceRulesOverlap(t *testing.T) {
	resetServiceRulesForTest(t)
	resetASNSceneRulesForTest(t)
	path := filepath.Join(t.TempDir(), "services.json")
	body := []byte(`{"rules":[
		{"id":"example-cdn","name":"Example CDN","scene":"CDN","confidence":0.99,"prefixes":["2001:db9::/32"]},
		{"id":"example-dns","name":"Example DNS","scene":"DNS","confidence":0.99,"prefixes":["2001:db9::1/128"]}
	]}`)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := LoadServiceRules(path); err != nil {
		t.Fatal(err)
	}

	result := Classify(Input{
		IP:      netip.MustParseAddr("2001:db9::1"),
		Profile: store.ASNProfile{ASN: 64500, Name: "Example Network"},
	})
	if result.Scene != "DNS" {
		t.Fatalf("expected more specific DNS service prefix to win, got %#v", result)
	}
}

func TestClassifierDetectsCloudProviderAsIDC(t *testing.T) {
	result := Classify(Input{
		Profile: store.ASNProfile{ASN: 16509, Name: "Amazon.com, Inc.", InfoType: "NSP", Website: "https://aws.amazon.com"},
	})
	if result.Scene != "IDC" {
		t.Fatalf("expected IDC, got %s", result.Scene)
	}
}

func TestClassifierTreatsKnownCloudProvidersAsIDCDespiteEnterpriseInfoType(t *testing.T) {
	cases := []store.ASNProfile{
		{ASN: 16509, Name: "Amazon Technologies Inc.", AKA: "Amazon.com", InfoType: "Enterprise", Website: "https://aws.amazon.com"},
		{ASN: 45102, Name: "Alibaba Cloud LLC", AKA: "Aliyun", InfoType: "Enterprise", Website: "https://www.alibabacloud.com"},
	}
	for _, profile := range cases {
		result := Classify(Input{Profile: profile})
		if result.Scene != "IDC" {
			t.Fatalf("expected IDC for %#v, got %#v", profile, result)
		}
	}
}

func TestClassifierDetectsUSMobileCarrierSignals(t *testing.T) {
	cases := []Input{
		{
			Profile: store.ASNProfile{Name: "T-Mobile USA", AKA: "TMobile Wireless", InfoType: "Cable/DSL/ISP"},
			RDNS:    "208-54-86-1.t-mobile.com",
		},
		{
			Profile: store.ASNProfile{Name: "Cellco Partnership DBA Verizon Wireless", AKA: "WIRELESSDATANETWORK"},
			RDNS:    "1.sub-70-192-0.myvzw.com",
		},
	}
	for _, input := range cases {
		result := Classify(input)
		if result.Scene != "MOB" {
			t.Fatalf("expected MOB for %#v, got %#v", input, result)
		}
	}
}

func TestClassifierDetectsFrontierResidentialRDNS(t *testing.T) {
	result := Classify(Input{
		Profile: store.ASNProfile{Name: "Frontier Communications", InfoType: "NSP"},
		RDNS:    "47-151-0-1.fdr01.wmns.ca.ip.frontiernet.net",
	})
	if result.Scene != "DYN" {
		t.Fatalf("expected DYN, got %#v", result)
	}
}

func TestClassifierDetectsEducationGovernmentAndMobile(t *testing.T) {
	cases := []struct {
		name    string
		profile store.ASNProfile
		want    string
	}{
		{name: "education", profile: store.ASNProfile{Name: "Example University"}, want: "EDU"},
		{name: "government", profile: store.ASNProfile{Name: "Department of Government Services"}, want: "GOV"},
		{name: "mobile", profile: store.ASNProfile{Name: "Example Mobile 5G Network"}, want: "MOB"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := Classify(Input{Profile: tc.profile})
			if result.Scene != tc.want {
				t.Fatalf("expected %s, got %s", tc.want, result.Scene)
			}
		})
	}
}
