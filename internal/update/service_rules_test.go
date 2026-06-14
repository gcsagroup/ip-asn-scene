package update

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"ipasn/internal/config"
)

func TestRefreshDynamicServiceRulesLive(t *testing.T) {
	if os.Getenv("LIVE_DYNAMIC_RULES") != "1" {
		t.Skip("set LIVE_DYNAMIC_RULES=1 to refresh live dynamic service rules")
	}
	cfg := config.Default()
	cfg.DataDir = "data"
	if value := os.Getenv("DYNAMIC_RULES_FILE"); value != "" {
		cfg.DynamicRules.File = value
	}
	if value := os.Getenv("IP2PROXY_LOCAL_FILE"); value != "" {
		cfg.DynamicRules.IP2Proxy.Enabled = true
		cfg.DynamicRules.IP2Proxy.LocalFile = value
	}
	if value := os.Getenv("IP2PROXY_LOCAL_FILES"); value != "" {
		cfg.DynamicRules.IP2Proxy.Enabled = true
		cfg.DynamicRules.IP2Proxy.LocalFiles = strings.Split(value, ",")
	}
	if value := os.Getenv("IP2PROXY_TOKEN"); value != "" {
		cfg.DynamicRules.IP2Proxy.Enabled = true
		cfg.DynamicRules.IP2Proxy.Token = value
	}
	if value := os.Getenv("IP2PROXY_PACKAGE"); value != "" {
		cfg.DynamicRules.IP2Proxy.Package = value
	}
	if value := os.Getenv("IP2PROXY_PACKAGES"); value != "" {
		cfg.DynamicRules.IP2Proxy.Packages = strings.Split(value, ",")
	}
	path, err := RefreshDynamicServiceRules(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Rules []struct {
			ID       string   `json:"id"`
			Prefixes []string `json:"prefixes"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(body, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Rules) == 0 {
		t.Fatalf("expected live dynamic rules in %s", path)
	}
}

func TestRefreshDynamicServiceRulesBuildsGeneratedFile(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/google.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"66.249.64.0/19"},{"ipv6Prefix":"2001:4860:4801::/48"}]}`))
	})
	mux.HandleFunc("/bing.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"157.55.39.0/24"}]}`))
	})
	mux.HandleFunc("/tor.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("185.220.101.1\n# comment\n2001:db8::1\nbad-value\n"))
	})
	mux.HandleFunc("/uptimerobot.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("3.12.251.153 2600:1f18:179:f900:4b7d:d1cc:2d10:211"))
	})
	mux.HandleFunc("/drop_v4.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"cidr":"203.0.114.0/24","sblid":"SBL1"}` + "\n" + `{"type":"metadata","timestamp":1770000000}`))
	})
	mux.HandleFunc("/drop_v6.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"cidr":"2001:db9::/32","sblid":"SBL2"}`))
	})
	mux.HandleFunc("/cloudflare-v4.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("173.245.48.0/20\n198.41.128.0/17\n"))
	})
	mux.HandleFunc("/cloudflare-v6.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("2400:cb00::/32\n2a06:98c0::/29\n"))
	})
	mux.HandleFunc("/fastly.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"addresses":["151.101.0.0/16"],"ipv6_addresses":["2a04:4e42::/32"]}`))
	})
	mux.HandleFunc("/aws.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"prefixes":[{"ip_prefix":"15.230.15.29/32","service":"EC2"},{"ip_prefix":"205.251.192.0/19","service":"CLOUDFRONT"}],"ipv6_prefixes":[{"ipv6_prefix":"2600:f0f0:70::/45","service":"EC2"},{"ipv6_prefix":"2600:9000::/28","service":"CLOUDFRONT"}]}`))
	})
	mux.HandleFunc("/google-cloud.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"34.80.0.0/15"},{"ipv6Prefix":"2600:1900::/28"}]}`))
	})
	mux.HandleFunc("/oracle.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"regions":[{"cidrs":[{"cidr":"129.146.0.0/16"},{"cidr":"2603:c020::/32"}]}]}`))
	})
	mux.HandleFunc("/azure-tags.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"values":[{"name":"AzureFrontDoor","properties":{"addressPrefixes":["13.107.42.0/24","2620:1ec:21::/48"]}}]}`))
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.DynamicRules.File = filepath.Join(cfg.DataDir, "generated", "services.json")
	cfg.DynamicRules.GoogleCrawlerURL = server.URL + "/google.json"
	cfg.DynamicRules.BingbotURL = server.URL + "/bing.json"
	cfg.DynamicRules.TorExitURL = server.URL + "/tor.txt"
	cfg.DynamicRules.UptimeRobotURL = server.URL + "/uptimerobot.txt"
	cfg.DynamicRules.SpamhausDropV4URL = server.URL + "/drop_v4.json"
	cfg.DynamicRules.SpamhausDropV6URL = server.URL + "/drop_v6.json"
	cfg.DynamicRules.CloudflareV4URL = server.URL + "/cloudflare-v4.txt"
	cfg.DynamicRules.CloudflareV6URL = server.URL + "/cloudflare-v6.txt"
	cfg.DynamicRules.FastlyURL = server.URL + "/fastly.json"
	cfg.DynamicRules.AWSIPRangesURL = server.URL + "/aws.json"
	cfg.DynamicRules.GoogleCloudIPRangesURL = server.URL + "/google-cloud.json"
	cfg.DynamicRules.OracleIPRangesURL = server.URL + "/oracle.json"
	cfg.DynamicRules.AzureServiceTagsURL = server.URL + "/azure-tags.json"
	cfg.DynamicRules.GitHubMetaURL = ""
	cfg.DynamicRules.MailSPFDomains = []string{"_spf.example.test"}
	cfg.DynamicRules.IP2Proxy.Enabled = true
	cfg.DynamicRules.IP2Proxy.LocalFile = filepath.Join(cfg.DataDir, "ip2proxy.csv")
	if err := os.WriteFile(cfg.DynamicRules.IP2Proxy.LocalFile, []byte(strings.Join([]string{
		`"3405804032","3405804287","VPN","US","United States"`,
		`"3405804288","3405804543","PUB","US","United States"`,
		`"2001:db9::/32","TOR","US","United States"`,
	}, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}

	resolver := spfTXTLookupFunc(func(ctx context.Context, name string) ([]string, error) {
		switch name {
		case "_spf.example.test":
			return []string{"v=spf1 ip4:192.0.3.0/24 include:_spf.child.example.test -all"}, nil
		case "_spf.child.example.test":
			return []string{"v=spf1 ip6:2001:db9:1::/48 -all"}, nil
		default:
			return nil, nil
		}
	})

	path, err := RefreshDynamicServiceRulesWithClient(context.Background(), cfg, server.Client(), resolver)
	if err != nil {
		t.Fatal(err)
	}
	if path != cfg.DynamicRules.File {
		t.Fatalf("unexpected generated path: %s", path)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Rules []struct {
			ID       string   `json:"id"`
			Scene    string   `json:"scene"`
			Prefixes []string `json:"prefixes"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(body, &file); err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"dynamic-bot-google-common-crawlers": "BOT",
		"dynamic-bot-bingbot":                "BOT",
		"dynamic-tor-exit-nodes":             "TOR",
		"dynamic-mail-spf":                   "MAIL",
		"dynamic-mon-uptimerobot":            "MON",
		"dynamic-blocklist-spamhaus-drop":    "BLOCKLIST",
		"dynamic-ip2proxy-vpn":               "VPN",
		"dynamic-ip2proxy-proxy":             "PROXY",
		"dynamic-ip2proxy-tor":               "TOR",
		"dynamic-cdn-cloudflare":             "CDN",
		"dynamic-cdn-fastly":                 "CDN",
		"dynamic-cdn-aws-cloudfront":         "CDN",
		"dynamic-idc-aws":                    "IDC",
		"dynamic-idc-google-cloud":           "IDC",
		"dynamic-idc-azure":                  "IDC",
		"dynamic-idc-oracle-cloud":           "IDC",
	}
	seen := map[string]bool{}
	for _, rule := range file.Rules {
		if scene, ok := want[rule.ID]; ok {
			seen[rule.ID] = true
			if rule.Scene != scene {
				t.Fatalf("rule %s expected scene %s, got %s", rule.ID, scene, rule.Scene)
			}
			if len(rule.Prefixes) == 0 {
				t.Fatalf("rule %s has no prefixes", rule.ID)
			}
		}
	}
	for id := range want {
		if !seen[id] {
			t.Fatalf("missing generated rule %s in %#v", id, file.Rules)
		}
	}
	if !generatedRuleHasPrefix(file.Rules, "dynamic-mail-spf", "192.0.3.0/24") {
		t.Fatalf("mail SPF rule did not include parsed IPv4 prefix")
	}
	if !generatedRuleHasPrefix(file.Rules, "dynamic-mail-spf", "2001:db9:1::/48") {
		t.Fatalf("mail SPF rule did not include recursive IPv6 prefix")
	}
	if !generatedRuleHasPrefix(file.Rules, "dynamic-ip2proxy-vpn", "203.0.114.0/24") {
		t.Fatalf("IP2Proxy VPN rule did not include parsed range")
	}
	if !generatedRuleHasPrefix(file.Rules, "dynamic-ip2proxy-proxy", "203.0.115.0/24") {
		t.Fatalf("IP2Proxy PROXY rule did not include parsed range")
	}
	if !generatedRuleHasPrefix(file.Rules, "dynamic-ip2proxy-tor", "2001:db9::/32") {
		t.Fatalf("IP2Proxy TOR rule did not include parsed CIDR")
	}
	if !generatedRuleHasPrefix(file.Rules, "dynamic-cdn-cloudflare", "2400:cb00::/32") {
		t.Fatalf("Cloudflare rule did not include IPv6 prefix")
	}
	if !generatedRuleHasPrefix(file.Rules, "dynamic-idc-aws", "15.230.15.29/32") {
		t.Fatalf("AWS rule did not include IPv4 prefix")
	}
	if !generatedRuleHasPrefix(file.Rules, "dynamic-cdn-aws-cloudfront", "205.251.192.0/19") {
		t.Fatalf("AWS CloudFront rule did not include IPv4 prefix")
	}
	if !generatedRuleHasPrefix(file.Rules, "dynamic-cdn-aws-cloudfront", "2600:9000::/28") {
		t.Fatalf("AWS CloudFront rule did not include IPv6 prefix")
	}
	if !generatedRuleHasPrefix(file.Rules, "dynamic-idc-azure", "13.107.42.0/24") {
		t.Fatalf("Azure rule did not include service tag prefix")
	}
}

func TestRefreshDynamicServiceRulesCombinesMultipleIP2ProxySources(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ip2proxy.zip", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("file") == "PX11" {
			_, _ = w.Write([]byte(`"3405804032","3405804287","VPN","US","United States"`))
			return
		}
		if r.URL.Query().Get("file") == "PX11_IPV6" {
			_, _ = w.Write([]byte(`"2001:db9::/32","TOR","US","United States"`))
			return
		}
		http.Error(w, "unexpected package", http.StatusBadRequest)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.DynamicRules.File = filepath.Join(cfg.DataDir, "generated", "services.json")
	cfg.DynamicRules.GoogleCrawlerURL = ""
	cfg.DynamicRules.BingbotURL = ""
	cfg.DynamicRules.TorExitURL = ""
	cfg.DynamicRules.UptimeRobotURL = ""
	cfg.DynamicRules.SpamhausDropV4URL = ""
	cfg.DynamicRules.SpamhausDropV6URL = ""
	cfg.DynamicRules.CloudflareV4URL = ""
	cfg.DynamicRules.CloudflareV6URL = ""
	cfg.DynamicRules.FastlyURL = ""
	cfg.DynamicRules.AWSIPRangesURL = ""
	cfg.DynamicRules.GoogleCloudIPRangesURL = ""
	cfg.DynamicRules.AzureServiceTagsURL = ""
	cfg.DynamicRules.OracleIPRangesURL = ""
	cfg.DynamicRules.GitHubMetaURL = ""
	cfg.DynamicRules.MailSPFDomains = nil
	cfg.DynamicRules.IP2Proxy.Enabled = true
	cfg.DynamicRules.IP2Proxy.DownloadURL = server.URL + "/ip2proxy.zip"
	cfg.DynamicRules.IP2Proxy.Token = "test-token"
	cfg.DynamicRules.IP2Proxy.Packages = []string{"PX11", "PX11_IPV6"}

	path, err := RefreshDynamicServiceRulesWithClient(context.Background(), cfg, server.Client(), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Rules []struct {
			ID       string   `json:"id"`
			Scene    string   `json:"scene"`
			Prefixes []string `json:"prefixes"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(body, &file); err != nil {
		t.Fatal(err)
	}
	if !generatedRuleHasPrefix(file.Rules, "dynamic-ip2proxy-vpn", "203.0.114.0/24") {
		t.Fatalf("expected IPv4 IP2Proxy package prefix in generated rules")
	}
	if !generatedRuleHasPrefix(file.Rules, "dynamic-ip2proxy-tor", "2001:db9::/32") {
		t.Fatalf("expected IPv6 IP2Proxy package prefix in generated rules")
	}
}

func TestRefreshDynamicServiceRulesRetainsPreviousRuleOnSourceFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/tor.txt", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "temporary failure", http.StatusBadGateway)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.DynamicRules.File = filepath.Join(cfg.DataDir, "generated", "services.json")
	cfg.DynamicRules.GoogleCrawlerURL = ""
	cfg.DynamicRules.BingbotURL = ""
	cfg.DynamicRules.TorExitURL = server.URL + "/tor.txt"
	cfg.DynamicRules.UptimeRobotURL = ""
	cfg.DynamicRules.SpamhausDropV4URL = ""
	cfg.DynamicRules.SpamhausDropV6URL = ""
	cfg.DynamicRules.CloudflareV4URL = ""
	cfg.DynamicRules.CloudflareV6URL = ""
	cfg.DynamicRules.FastlyURL = ""
	cfg.DynamicRules.AWSIPRangesURL = ""
	cfg.DynamicRules.GoogleCloudIPRangesURL = ""
	cfg.DynamicRules.AzureServiceTagsURL = ""
	cfg.DynamicRules.OracleIPRangesURL = ""
	cfg.DynamicRules.GitHubMetaURL = ""
	cfg.DynamicRules.MailSPFDomains = nil
	cfg.DynamicRules.IP2Proxy.Enabled = false

	previous := generatedServiceRuleFile{
		Version:   "previous",
		UpdatedAt: time.Now().UTC(),
		Rules: []generatedServiceRule{{
			ID:         "dynamic-tor-exit-nodes",
			Name:       "Tor Exit Nodes",
			Scene:      "TOR",
			SceneName:  "Tor 出口",
			Confidence: 0.99,
			Prefixes:   []string{"185.220.101.1/32"},
			Evidence:   "Tor 官方出口节点列表",
		}},
	}
	body, err := json.Marshal(previous)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.DynamicRules.File), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.DynamicRules.File, body, 0o644); err != nil {
		t.Fatal(err)
	}

	path, err := RefreshDynamicServiceRulesWithClient(context.Background(), cfg, server.Client(), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		SourceErrors []string `json:"source_errors"`
		Rules        []struct {
			ID       string   `json:"id"`
			Scene    string   `json:"scene"`
			Prefixes []string `json:"prefixes"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(body, &file); err != nil {
		t.Fatal(err)
	}
	if !generatedRuleHasPrefix(file.Rules, "dynamic-tor-exit-nodes", "185.220.101.1/32") {
		t.Fatalf("expected previous Tor rule to be retained, got %#v", file.Rules)
	}
	if len(file.SourceErrors) == 0 || !strings.Contains(strings.Join(file.SourceErrors, "; "), "retained previous rule dynamic-tor-exit-nodes") {
		t.Fatalf("expected retained-rule source error, got %#v", file.SourceErrors)
	}
}

func generatedRuleHasPrefix(rules []struct {
	ID       string   `json:"id"`
	Scene    string   `json:"scene"`
	Prefixes []string `json:"prefixes"`
}, id string, prefix string) bool {
	for _, rule := range rules {
		if rule.ID == id {
			return slices.Contains(rule.Prefixes, prefix)
		}
	}
	return false
}
