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

type generatedRuleForTest struct {
	ID                string   `json:"id"`
	Scene             string   `json:"scene"`
	ServiceName       string   `json:"service_name"`
	ServiceSubtype    string   `json:"service_subtype"`
	RiskLevel         string   `json:"risk_level"`
	BlockRecommended  *bool    `json:"block_recommended"`
	NormalUserTraffic *bool    `json:"normal_user_traffic"`
	Prefixes          []string `json:"prefixes"`
}

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
		Rules []generatedRuleForTest `json:"rules"`
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
	mux.HandleFunc("/firehol-level1.netset", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("# firehol level1\n203.0.116.0/24\n198.51.100.10\n"))
	})
	mux.HandleFunc("/firehol-anonymous.netset", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("# firehol anonymous\n203.0.117.0/24\n2001:db9:2::/48\n"))
	})
	mux.HandleFunc("/az0-vpn-ip.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("# az0 vpn_ip\n198.51.101.1 # protonvpn\n2001:db9:3::1 # vpn\n"))
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
	mux.HandleFunc("/apple-private-relay.csv", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Join([]string{
			"172.224.226.0/28,GB,GB-EN,London,",
			"172.224.226.16/28,GB,GB-EN,London,",
			"2a01:b740::/48,GB,GB-EN,London,",
		}, "\n")))
	})
	mux.HandleFunc("/google-fi.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("# Google Fi VPN Geofeed\n136.22.118.0/29,AT,,,\n2600:1900:4000::/48,US,,,\n"))
	})
	mux.HandleFunc("/mullvad.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[
			{"hostname":"al-tia-wg-001","active":true,"ipv4_addr_in":"103.124.165.2","ipv6_addr_in":"2a04:27c0:0:e::f001"},
			{"hostname":"disabled","active":false,"ipv4_addr_in":"198.51.100.10","ipv6_addr_in":"2001:db8::10"}
		]`))
	})
	mux.HandleFunc("/nordvpn.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[
			{"hostname":"pl128.nordvpn.com","status":"online","station":"194.99.105.99","ipv6_station":"2a0d:5600:1::1"},
			{"hostname":"offline.nordvpn.com","status":"offline","station":"198.51.100.20"}
		]`))
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
	cfg.DynamicRules.FireHOLLevel1URL = server.URL + "/firehol-level1.netset"
	cfg.DynamicRules.FireHOLAnonymousURL = server.URL + "/firehol-anonymous.netset"
	cfg.DynamicRules.Az0VPNIPURL = server.URL + "/az0-vpn-ip.txt"
	cfg.DynamicRules.CloudflareV4URL = server.URL + "/cloudflare-v4.txt"
	cfg.DynamicRules.CloudflareV6URL = server.URL + "/cloudflare-v6.txt"
	cfg.DynamicRules.FastlyURL = server.URL + "/fastly.json"
	cfg.DynamicRules.AWSIPRangesURL = server.URL + "/aws.json"
	cfg.DynamicRules.GoogleCloudIPRangesURL = server.URL + "/google-cloud.json"
	cfg.DynamicRules.OracleIPRangesURL = server.URL + "/oracle.json"
	cfg.DynamicRules.AzureServiceTagsURL = server.URL + "/azure-tags.json"
	cfg.DynamicRules.GitHubMetaURL = ""
	cfg.DynamicRules.ApplePrivateRelayURL = server.URL + "/apple-private-relay.csv"
	cfg.DynamicRules.GoogleFiVPNGeofeedURL = server.URL + "/google-fi.txt"
	cfg.DynamicRules.MullvadRelaysURL = server.URL + "/mullvad.json"
	cfg.DynamicRules.NordVPNServersURL = server.URL + "/nordvpn.json"
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
		Rules []generatedRuleForTest `json:"rules"`
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
		"dynamic-blocklist-firehol-level1":   "BLOCKLIST",
		"dynamic-proxy-firehol-anonymous":    "PROXY",
		"dynamic-vpn-az0-vpn-ip":             "VPN",
		"dynamic-ip2proxy-vpn":               "VPN",
		"dynamic-ip2proxy-proxy":             "PROXY",
		"dynamic-ip2proxy-tor":               "TOR",
		"dynamic-cdn-cloudflare":             "CDN",
		"dynamic-cdn-fastly":                 "CDN",
		"dynamic-cdn-aws-cloudfront":         "CDN",
		"dynamic-proxy-apple-private-relay":  "PROXY",
		"dynamic-vpn-google-fi":              "VPN",
		"dynamic-vpn-mullvad":                "VPN",
		"dynamic-vpn-nordvpn":                "VPN",
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
	if !generatedRuleHasPrefix(file.Rules, "dynamic-blocklist-firehol-level1", "203.0.116.0/24") {
		t.Fatalf("FireHOL level1 rule did not include IPv4 prefix")
	}
	if !generatedRuleHasPrefix(file.Rules, "dynamic-blocklist-firehol-level1", "198.51.100.10/32") {
		t.Fatalf("FireHOL level1 rule did not normalize bare IPv4 address")
	}
	if !generatedRuleHasPrefix(file.Rules, "dynamic-proxy-firehol-anonymous", "203.0.117.0/24") {
		t.Fatalf("FireHOL anonymous rule did not include IPv4 prefix")
	}
	if !generatedRuleHasPrefix(file.Rules, "dynamic-proxy-firehol-anonymous", "2001:db9:2::/48") {
		t.Fatalf("FireHOL anonymous rule did not include IPv6 prefix")
	}
	if !generatedRuleHasPrefix(file.Rules, "dynamic-vpn-az0-vpn-ip", "198.51.101.1/32") {
		t.Fatalf("az0/vpn_ip rule did not include IPv4 address")
	}
	if !generatedRuleHasPrefix(file.Rules, "dynamic-vpn-az0-vpn-ip", "2001:db9:3::1/128") {
		t.Fatalf("az0/vpn_ip rule did not include IPv6 address")
	}
	if !generatedRuleHasPrefix(file.Rules, "dynamic-idc-azure", "13.107.42.0/24") {
		t.Fatalf("Azure rule did not include service tag prefix")
	}
	if !generatedRuleHasPrefix(file.Rules, "dynamic-proxy-apple-private-relay", "172.224.226.0/27") {
		t.Fatalf("Apple Private Relay rule did not coalesce adjacent IPv4 prefixes")
	}
	if !generatedRuleHasPrefix(file.Rules, "dynamic-proxy-apple-private-relay", "2a01:b740::/48") {
		t.Fatalf("Apple Private Relay rule did not include IPv6 prefix")
	}
	if !generatedRuleHasPrefix(file.Rules, "dynamic-vpn-google-fi", "136.22.118.0/29") {
		t.Fatalf("Google Fi VPN rule did not include IPv4 prefix")
	}
	if !generatedRuleHasPrefix(file.Rules, "dynamic-vpn-google-fi", "2600:1900:4000::/48") {
		t.Fatalf("Google Fi VPN rule did not include IPv6 prefix")
	}
	assertConsumerPrivacyPolicy(t, file.Rules, "dynamic-proxy-apple-private-relay", "Apple iCloud Private Relay", "consumer_privacy_proxy")
	assertConsumerPrivacyPolicy(t, file.Rules, "dynamic-vpn-google-fi", "Google Fi VPN", "carrier_privacy_vpn")
	if !generatedRuleHasPrefix(file.Rules, "dynamic-vpn-mullvad", "103.124.165.2/32") {
		t.Fatalf("Mullvad rule did not include active IPv4 relay")
	}
	if generatedRuleHasPrefix(file.Rules, "dynamic-vpn-mullvad", "198.51.100.10/32") {
		t.Fatalf("Mullvad rule included inactive relay")
	}
	if !generatedRuleHasPrefix(file.Rules, "dynamic-vpn-nordvpn", "194.99.105.99/32") {
		t.Fatalf("NordVPN rule did not include online IPv4 station")
	}
	if generatedRuleHasPrefix(file.Rules, "dynamic-vpn-nordvpn", "198.51.100.20/32") {
		t.Fatalf("NordVPN rule included offline station")
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
	cfg.DynamicRules.FireHOLLevel1URL = ""
	cfg.DynamicRules.FireHOLAnonymousURL = ""
	cfg.DynamicRules.Az0VPNIPURL = ""
	cfg.DynamicRules.CloudflareV4URL = ""
	cfg.DynamicRules.CloudflareV6URL = ""
	cfg.DynamicRules.FastlyURL = ""
	cfg.DynamicRules.AWSIPRangesURL = ""
	cfg.DynamicRules.GoogleCloudIPRangesURL = ""
	cfg.DynamicRules.AzureServiceTagsURL = ""
	cfg.DynamicRules.OracleIPRangesURL = ""
	cfg.DynamicRules.GitHubMetaURL = ""
	cfg.DynamicRules.ApplePrivateRelayURL = ""
	cfg.DynamicRules.GoogleFiVPNGeofeedURL = ""
	cfg.DynamicRules.MullvadRelaysURL = ""
	cfg.DynamicRules.NordVPNServersURL = ""
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
		Rules []generatedRuleForTest `json:"rules"`
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
	cfg.DynamicRules.FireHOLLevel1URL = ""
	cfg.DynamicRules.FireHOLAnonymousURL = ""
	cfg.DynamicRules.Az0VPNIPURL = ""
	cfg.DynamicRules.CloudflareV4URL = ""
	cfg.DynamicRules.CloudflareV6URL = ""
	cfg.DynamicRules.FastlyURL = ""
	cfg.DynamicRules.AWSIPRangesURL = ""
	cfg.DynamicRules.GoogleCloudIPRangesURL = ""
	cfg.DynamicRules.AzureServiceTagsURL = ""
	cfg.DynamicRules.OracleIPRangesURL = ""
	cfg.DynamicRules.GitHubMetaURL = ""
	cfg.DynamicRules.ApplePrivateRelayURL = ""
	cfg.DynamicRules.GoogleFiVPNGeofeedURL = ""
	cfg.DynamicRules.MullvadRelaysURL = ""
	cfg.DynamicRules.NordVPNServersURL = ""
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
		SourceErrors []string               `json:"source_errors"`
		Rules        []generatedRuleForTest `json:"rules"`
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

func generatedRuleHasPrefix(rules []generatedRuleForTest, id string, prefix string) bool {
	for _, rule := range rules {
		if rule.ID == id {
			return slices.Contains(rule.Prefixes, prefix)
		}
	}
	return false
}

func assertConsumerPrivacyPolicy(t *testing.T, rules []generatedRuleForTest, id, serviceName, subtype string) {
	t.Helper()
	for _, rule := range rules {
		if rule.ID != id {
			continue
		}
		if rule.ServiceName != serviceName || rule.ServiceSubtype != subtype || rule.RiskLevel != "low" {
			t.Fatalf("unexpected consumer privacy policy for %s: %#v", id, rule)
		}
		if rule.BlockRecommended == nil || *rule.BlockRecommended {
			t.Fatalf("expected %s to default to no block recommendation, got %#v", id, rule.BlockRecommended)
		}
		if rule.NormalUserTraffic == nil || !*rule.NormalUserTraffic {
			t.Fatalf("expected %s to mark normal user traffic, got %#v", id, rule.NormalUserTraffic)
		}
		return
	}
	t.Fatalf("missing generated rule %s", id)
}
