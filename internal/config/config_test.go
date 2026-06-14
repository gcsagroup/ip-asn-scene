package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadAIProviderFromEnv(t *testing.T) {
	t.Setenv("AI_PROVIDER", "ollama")
	t.Setenv("OLLAMA_BASE_URL", "http://localhost:11434")
	t.Setenv("OLLAMA_MODEL", "qwen3:8b")
	t.Setenv("AI_CONFIDENCE_CUTOFF", "0.62")
	t.Setenv("RULES_FILE", "rules/test-services.json")

	cfg := Load()
	if cfg.AI.Provider != "ollama" {
		t.Fatalf("expected ollama provider, got %q", cfg.AI.Provider)
	}
	if cfg.AI.OllamaBaseURL != "http://localhost:11434" {
		t.Fatalf("unexpected Ollama base URL: %q", cfg.AI.OllamaBaseURL)
	}
	if cfg.AI.OllamaModel != "qwen3:8b" {
		t.Fatalf("unexpected Ollama model: %q", cfg.AI.OllamaModel)
	}
	if cfg.AI.ConfidenceCutoff != 0.62 {
		t.Fatalf("unexpected cutoff: %f", cfg.AI.ConfidenceCutoff)
	}
	if cfg.RulesFile != "rules/test-services.json" {
		t.Fatalf("unexpected rules file: %q", cfg.RulesFile)
	}
}

func TestLoadAutoProviderKeepsOpenAICompatibility(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "test-key")
	t.Setenv("OPENAI_MODEL", "gpt-5.4-mini")

	cfg := Load()
	if cfg.AI.Provider != "auto" {
		t.Fatalf("expected auto provider, got %q", cfg.AI.Provider)
	}
	if cfg.AI.OpenAIAPIKey != "test-key" {
		t.Fatalf("expected OpenAI API key from env")
	}
	if cfg.AI.OpenAIModel != "gpt-5.4-mini" {
		t.Fatalf("unexpected OpenAI model: %q", cfg.AI.OpenAIModel)
	}
}

func TestLoadDynamicRulesFromEnv(t *testing.T) {
	t.Setenv("DYNAMIC_RULES_ENABLED", "0")
	t.Setenv("DYNAMIC_RULES_FILE", "data/custom/services.json")
	t.Setenv("GOOGLE_CRAWLER_URL", "https://example.test/google.json")
	t.Setenv("BINGBOT_URL", "https://example.test/bing.json")
	t.Setenv("TOR_EXIT_URL", "https://example.test/tor.txt")
	t.Setenv("UPTIMEROBOT_IP_URL", "https://example.test/uptimerobot.txt")
	t.Setenv("SPAMHAUS_DROP_V4_URL", "https://example.test/drop_v4.json")
	t.Setenv("SPAMHAUS_DROP_V6_URL", "https://example.test/drop_v6.json")
	t.Setenv("MAIL_SPF_DOMAINS", "_spf.example.test, spf.mail.example.test")
	t.Setenv("IP2PROXY_ENABLED", "1")
	t.Setenv("IP2PROXY_LOCAL_FILE", "data/raw/ip2proxy.csv")
	t.Setenv("IP2PROXY_LOCAL_FILES", "data/raw/ip2proxy.csv,data/raw/ip2proxy-ipv6.csv")
	t.Setenv("IP2PROXY_DOWNLOAD_URL", "https://example.test/ip2proxy.zip")
	t.Setenv("IP2PROXY_DOWNLOAD_URLS", "https://example.test/ip2proxy.zip,https://example.test/ip2proxy-ipv6.zip")
	t.Setenv("IP2PROXY_TOKEN", "test-token")
	t.Setenv("IP2PROXY_PACKAGE", "PX11")
	t.Setenv("IP2PROXY_PACKAGES", "PX11,PX11_IPV6")

	cfg := Load()
	if cfg.DynamicRules.Enabled {
		t.Fatal("expected dynamic rules to be disabled")
	}
	if cfg.DynamicRules.File != "data/custom/services.json" {
		t.Fatalf("unexpected dynamic rules file: %q", cfg.DynamicRules.File)
	}
	if cfg.DynamicRules.GoogleCrawlerURL != "https://example.test/google.json" {
		t.Fatalf("unexpected Google crawler URL: %q", cfg.DynamicRules.GoogleCrawlerURL)
	}
	if cfg.DynamicRules.BingbotURL != "https://example.test/bing.json" {
		t.Fatalf("unexpected Bingbot URL: %q", cfg.DynamicRules.BingbotURL)
	}
	if cfg.DynamicRules.TorExitURL != "https://example.test/tor.txt" {
		t.Fatalf("unexpected Tor URL: %q", cfg.DynamicRules.TorExitURL)
	}
	if cfg.DynamicRules.UptimeRobotURL != "https://example.test/uptimerobot.txt" {
		t.Fatalf("unexpected UptimeRobot URL: %q", cfg.DynamicRules.UptimeRobotURL)
	}
	if cfg.DynamicRules.SpamhausDropV4URL != "https://example.test/drop_v4.json" {
		t.Fatalf("unexpected Spamhaus IPv4 URL: %q", cfg.DynamicRules.SpamhausDropV4URL)
	}
	if cfg.DynamicRules.SpamhausDropV6URL != "https://example.test/drop_v6.json" {
		t.Fatalf("unexpected Spamhaus IPv6 URL: %q", cfg.DynamicRules.SpamhausDropV6URL)
	}
	if len(cfg.DynamicRules.MailSPFDomains) != 2 || cfg.DynamicRules.MailSPFDomains[0] != "_spf.example.test" || cfg.DynamicRules.MailSPFDomains[1] != "spf.mail.example.test" {
		t.Fatalf("unexpected SPF domains: %#v", cfg.DynamicRules.MailSPFDomains)
	}
	if !cfg.DynamicRules.IP2Proxy.Enabled {
		t.Fatal("expected IP2Proxy to be enabled")
	}
	if cfg.DynamicRules.IP2Proxy.LocalFile != "data/raw/ip2proxy.csv" {
		t.Fatalf("unexpected IP2Proxy local file: %q", cfg.DynamicRules.IP2Proxy.LocalFile)
	}
	if len(cfg.DynamicRules.IP2Proxy.LocalFiles) != 2 || cfg.DynamicRules.IP2Proxy.LocalFiles[1] != "data/raw/ip2proxy-ipv6.csv" {
		t.Fatalf("unexpected IP2Proxy local files: %#v", cfg.DynamicRules.IP2Proxy.LocalFiles)
	}
	if cfg.DynamicRules.IP2Proxy.DownloadURL != "https://example.test/ip2proxy.zip" {
		t.Fatalf("unexpected IP2Proxy download URL: %q", cfg.DynamicRules.IP2Proxy.DownloadURL)
	}
	if len(cfg.DynamicRules.IP2Proxy.DownloadURLs) != 2 || cfg.DynamicRules.IP2Proxy.DownloadURLs[1] != "https://example.test/ip2proxy-ipv6.zip" {
		t.Fatalf("unexpected IP2Proxy download URLs: %#v", cfg.DynamicRules.IP2Proxy.DownloadURLs)
	}
	if cfg.DynamicRules.IP2Proxy.Token != "test-token" {
		t.Fatalf("unexpected IP2Proxy token: %q", cfg.DynamicRules.IP2Proxy.Token)
	}
	if cfg.DynamicRules.IP2Proxy.Package != "PX11" {
		t.Fatalf("unexpected IP2Proxy package: %q", cfg.DynamicRules.IP2Proxy.Package)
	}
	if len(cfg.DynamicRules.IP2Proxy.Packages) != 2 || cfg.DynamicRules.IP2Proxy.Packages[1] != "PX11_IPV6" {
		t.Fatalf("unexpected IP2Proxy packages: %#v", cfg.DynamicRules.IP2Proxy.Packages)
	}
}

func TestLoadIP2RegionFromEnv(t *testing.T) {
	t.Setenv("IP2REGION_ENABLED", "1")
	t.Setenv("IP2REGION_INCLUDE_DEFAULT", "1")
	t.Setenv("IP2REGION_V4_FILE", "data/raw/ip2region_v4.xdb")
	t.Setenv("IP2REGION_V6_FILE", "data/raw/ip2region_v6.xdb")
	t.Setenv("IP2REGION_V4_VERSION_URL", "https://example.test/v4/version")
	t.Setenv("IP2REGION_V4_DOWNLOAD_URL", "https://example.test/v4/download")
	t.Setenv("IP2REGION_V6_VERSION_URL", "https://example.test/v6/version")
	t.Setenv("IP2REGION_V6_DOWNLOAD_URL", "https://example.test/v6/download")

	cfg := Load()
	if !cfg.IP2Region.Enabled {
		t.Fatal("expected ip2region to be enabled")
	}
	if !cfg.IP2Region.IncludeDefault {
		t.Fatal("expected ip2region include default")
	}
	if cfg.IP2Region.V4File != "data/raw/ip2region_v4.xdb" || cfg.IP2Region.V6File != "data/raw/ip2region_v6.xdb" {
		t.Fatalf("unexpected xdb files: %#v", cfg.IP2Region)
	}
	if cfg.IP2Region.V4VersionURL != "https://example.test/v4/version" || cfg.IP2Region.V4DownloadURL != "https://example.test/v4/download" {
		t.Fatalf("unexpected v4 URLs: %#v", cfg.IP2Region)
	}
	if cfg.IP2Region.V6VersionURL != "https://example.test/v6/version" || cfg.IP2Region.V6DownloadURL != "https://example.test/v6/download" {
		t.Fatalf("unexpected v6 URLs: %#v", cfg.IP2Region)
	}
}

func TestLoadFirewallListsFromYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(`
firewall_lists:
  enabled: true
  output_dir: "data/generated/firewall-test"
  countries: ["CN", "US"]
  companies: ["alibaba", "cloudflare"]
  scenes: ["IDC", "CDN", "TOR", "PROXY"]
  min_confidence: 0.82
  include_ipv4: true
  include_ipv6: false
  write_entries: true
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.FirewallLists.Enabled {
		t.Fatal("expected firewall list generation enabled")
	}
	if cfg.FirewallLists.OutputDir != "data/generated/firewall-test" {
		t.Fatalf("unexpected output dir: %#v", cfg.FirewallLists)
	}
	if len(cfg.FirewallLists.Countries) != 2 || cfg.FirewallLists.Countries[0] != "CN" {
		t.Fatalf("unexpected countries: %#v", cfg.FirewallLists.Countries)
	}
	if len(cfg.FirewallLists.Companies) != 2 || cfg.FirewallLists.Companies[1] != "cloudflare" {
		t.Fatalf("unexpected companies: %#v", cfg.FirewallLists.Companies)
	}
	if len(cfg.FirewallLists.Scenes) != 4 || cfg.FirewallLists.Scenes[2] != "TOR" {
		t.Fatalf("unexpected scenes: %#v", cfg.FirewallLists.Scenes)
	}
	if cfg.FirewallLists.MinConfidence != 0.82 {
		t.Fatalf("unexpected min confidence: %f", cfg.FirewallLists.MinConfidence)
	}
	if !cfg.FirewallLists.IncludeIPv4 || cfg.FirewallLists.IncludeIPv6 {
		t.Fatalf("unexpected IP version flags: %#v", cfg.FirewallLists)
	}
	if !cfg.FirewallLists.WriteEntries {
		t.Fatalf("expected write_entries to be enabled")
	}
}

func TestLoadGenerateFirewallYAML(t *testing.T) {
	cfg, err := LoadFromFile(filepath.Join("..", "..", "generate_firewall.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.FirewallLists.Countries) != 0 {
		t.Fatalf("generate_firewall.yaml should export all countries, got %#v", cfg.FirewallLists.Countries)
	}
	if !cfg.FirewallLists.IncludeIPv4 || !cfg.FirewallLists.IncludeIPv6 {
		t.Fatalf("generate_firewall.yaml should include IPv4 and IPv6: %#v", cfg.FirewallLists)
	}
	if cfg.FirewallLists.WriteEntries {
		t.Fatal("generate_firewall.yaml should keep entries output disabled by default")
	}
	for _, company := range []string{"aws", "azure", "google", "alibaba", "tencent", "cloudflare", "oracle", "digitalocean"} {
		if !containsString(cfg.FirewallLists.Companies, company) {
			t.Fatalf("generate_firewall.yaml missing company %q: %#v", company, cfg.FirewallLists.Companies)
		}
	}
	if len(cfg.FirewallLists.Scenes) != 2 || cfg.FirewallLists.Scenes[0] != "CDN" || cfg.FirewallLists.Scenes[1] != "IDC" {
		t.Fatalf("generate_firewall.yaml should generate CDN and IDC scenes: %#v", cfg.FirewallLists.Scenes)
	}
}

func TestLoadReliabilitySourcesFromEnv(t *testing.T) {
	t.Setenv("RPKI_VRP_URLS", "https://example.test/vrps.csv,https://example.test/vrps-v6.csv")
	t.Setenv("IRR_ROUTE_URLS", "https://example.test/radb.db.gz")
	t.Setenv("BGP_OBSERVATION_URLS", "https://example.test/bgp.jsonl")
	t.Setenv("GEOFEED_URLS", "https://example.test/geofeed.csv")

	cfg := Load()
	if len(cfg.Sources.RPKIVRPURLs) != 2 || cfg.Sources.RPKIVRPURLs[1] != "https://example.test/vrps-v6.csv" {
		t.Fatalf("unexpected RPKI URLs: %#v", cfg.Sources.RPKIVRPURLs)
	}
	if len(cfg.Sources.IRRRouteURLs) != 1 || cfg.Sources.IRRRouteURLs[0] != "https://example.test/radb.db.gz" {
		t.Fatalf("unexpected IRR URLs: %#v", cfg.Sources.IRRRouteURLs)
	}
	if len(cfg.Sources.BGPObservationURLs) != 1 || cfg.Sources.BGPObservationURLs[0] != "https://example.test/bgp.jsonl" {
		t.Fatalf("unexpected BGP observation URLs: %#v", cfg.Sources.BGPObservationURLs)
	}
	if len(cfg.Sources.GeofeedURLs) != 1 || cfg.Sources.GeofeedURLs[0] != "https://example.test/geofeed.csv" {
		t.Fatalf("unexpected geofeed URLs: %#v", cfg.Sources.GeofeedURLs)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestDefaultIncludesMaintainedReliabilitySources(t *testing.T) {
	cfg := Default()
	if len(cfg.Sources.RPKIVRPURLs) != 1 || cfg.Sources.RPKIVRPURLs[0] != "https://console.rpki-client.org/vrps.csv" {
		t.Fatalf("unexpected default RPKI URLs: %#v", cfg.Sources.RPKIVRPURLs)
	}
	if len(cfg.Sources.IRRRouteURLs) < 6 {
		t.Fatalf("expected default IRR route dumps, got %#v", cfg.Sources.IRRRouteURLs)
	}
	expectedIRR := map[string]bool{
		"https://ftp.ripe.net/ripe/dbase/split/ripe.db.route.gz":         false,
		"https://ftp.ripe.net/ripe/dbase/split/ripe.db.route6.gz":        false,
		"https://ftp.apnic.net/apnic/whois/apnic.db.route.gz":            false,
		"https://ftp.apnic.net/apnic/whois/apnic.db.route6.gz":           false,
		"https://ftp.afrinic.net/dbase/afrinic.db.gz":                    false,
		"https://ftp.ripe.net/ripe/dbase/split/ripe-nonauth.db.route.gz": false,
	}
	for _, url := range cfg.Sources.IRRRouteURLs {
		if _, ok := expectedIRR[url]; ok {
			expectedIRR[url] = true
		}
	}
	for url, found := range expectedIRR {
		if !found {
			t.Fatalf("missing default IRR source %q in %#v", url, cfg.Sources.IRRRouteURLs)
		}
	}
	if len(cfg.Sources.GeofeedURLs) != 1 || cfg.Sources.GeofeedURLs[0] != "https://opengeofeed.org/feed/public.csv" {
		t.Fatalf("unexpected default geofeed URLs: %#v", cfg.Sources.GeofeedURLs)
	}
	if len(cfg.Sources.BGPObservationURLs) != 0 {
		t.Fatalf("BGP observation URL defaults should stay empty because full BGP mode generates them locally: %#v", cfg.Sources.BGPObservationURLs)
	}
}

func TestYAMLEmptyReliabilitySourcesOverrideDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(`
sources:
  rpki_vrp_urls: []
  irr_route_urls: []
  bgp_observation_urls: []
  geofeed_urls: []
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Sources.RPKIVRPURLs) != 0 || len(cfg.Sources.IRRRouteURLs) != 0 || len(cfg.Sources.GeofeedURLs) != 0 || len(cfg.Sources.BGPObservationURLs) != 0 {
		t.Fatalf("expected empty reliability sources to override defaults, got %#v", cfg.Sources)
	}
}

func TestLoadBGPAndAdminFromEnv(t *testing.T) {
	t.Setenv("BGP_ENABLED", "1")
	t.Setenv("BGP_MODE", "full")
	t.Setenv("BGP_COLLECTORS", "all")
	t.Setenv("BGP_INCLUDE_UPDATES", "1")
	t.Setenv("BGP_HISTORY_SNAPSHOTS", "9")
	t.Setenv("BGP_REFRESH_HOURS", "4")
	t.Setenv("BGP_MAX_PARALLEL_DOWNLOADS", "6")
	t.Setenv("BGP_MAX_PARALLEL_PARSE", "3")
	t.Setenv("BGP_KEEP_RAW", "0")
	t.Setenv("BGP_RAW_RETENTION_DAYS", "14")
	t.Setenv("BGP_SUMMARY_FILE", "data/generated/custom-bgp.jsonl.gz")
	t.Setenv("BGP_ROUTEVIEWS_BASE_URL", "https://routeviews.example.test")
	t.Setenv("BGP_RIPE_RIS_BASE_URL", "https://ris.example.test")
	t.Setenv("ADMIN_ENABLED", "1")
	t.Setenv("ADMIN_PATH", "/settings")
	t.Setenv("ADMIN_TOKEN", "secret")
	t.Setenv("ADMIN_LOCAL_ONLY", "0")

	cfg := Load()
	if !cfg.BGP.Enabled || cfg.BGP.Mode != "full" || len(cfg.BGP.Collectors) != 1 || cfg.BGP.Collectors[0] != "all" {
		t.Fatalf("unexpected BGP mode config: %#v", cfg.BGP)
	}
	if !cfg.BGP.IncludeUpdates || cfg.BGP.HistorySnapshots != 9 || cfg.BGP.RefreshInterval != 4*time.Hour {
		t.Fatalf("unexpected BGP update config: %#v", cfg.BGP)
	}
	if cfg.BGP.MaxParallelDownloads != 6 || cfg.BGP.MaxParallelParse != 3 || cfg.BGP.KeepRaw || cfg.BGP.RawRetentionDays != 14 {
		t.Fatalf("unexpected BGP worker/raw config: %#v", cfg.BGP)
	}
	if cfg.BGP.SummaryFile != "data/generated/custom-bgp.jsonl.gz" || cfg.BGP.RouteViewsBaseURL != "https://routeviews.example.test" || cfg.BGP.RIPERISBaseURL != "https://ris.example.test" {
		t.Fatalf("unexpected BGP path/source config: %#v", cfg.BGP)
	}
	if !cfg.Admin.Enabled || cfg.Admin.Path != "/settings" || cfg.Admin.Token != "secret" || cfg.Admin.LocalOnly {
		t.Fatalf("unexpected admin config: %#v", cfg.Admin)
	}
}

func TestLoadFromYAMLConfigFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	err := os.WriteFile(path, []byte(`
addr: ":19090"
data_dir: "custom-data"
rules_file: "rules/custom.json"
update_interval_hours: 12
http_timeout_seconds: 30
tls:
  enabled: true
  cert_file: "certs/server.crt"
  key_file: "certs/server.key"
ai:
  provider: "ollama"
  openai_api_key: "file-key"
  ollama_model: "qwen3:14b"
  ollama_base_url: "http://localhost:11434"
  confidence_cutoff: 0.66
  timeout_seconds: 11
enrichment:
  enabled: true
  ttl_hours: 48
  timeout_seconds: 5
  async_on_miss: false
  foreground_timeout_ms: 1200
history:
  snapshots: 2
bgp:
  enabled: true
  mode: "full"
  routeviews_enabled: false
  ripe_ris_enabled: true
  collectors:
    - "rrc00"
    - "route-views2"
  include_updates: true
  history_snapshots: 5
  refresh_hours: 6
  max_parallel_downloads: 8
  max_parallel_parse: 4
  keep_raw: false
  raw_retention_days: 10
  summary_file: "data/generated/full-bgp.jsonl.gz"
  routeviews_base_url: "https://routeviews.example.test"
  ripe_ris_base_url: "https://ris.example.test"
admin:
  enabled: true
  path: "/admin"
  token: "file-token"
  local_only: false
ip2region:
  enabled: true
  include_default: true
  v4_file: "data/raw/ip2region_v4.xdb"
  v6_file: "data/raw/ip2region_v6.xdb"
  v4_version_url: "https://example.test/v4/version"
  v4_download_url: "https://example.test/v4/full"
dynamic_rules:
  enabled: false
  file: "data/generated/custom.json"
  mail_spf_domains:
    - "_spf.example.test"
  ip2proxy:
    enabled: true
    local_files:
      - "data/raw/ip2proxy-ipv4.csv"
      - "data/raw/ip2proxy-ipv6.csv"
sources:
  peeringdb_url: "https://example.test/peeringdb"
  rpki_vrp_urls:
    - "https://example.test/vrps.csv"
  irr_route_urls:
    - "https://example.test/radb.db"
  bgp_observation_urls:
    - "https://example.test/bgp.jsonl"
  geofeed_urls:
    - "https://example.test/geofeed.csv"
  rir_urls:
    apnic: "https://example.test/apnic"
`), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != ":19090" || cfg.DataDir != "custom-data" || cfg.RulesFile != "rules/custom.json" {
		t.Fatalf("unexpected top-level config: %#v", cfg)
	}
	if cfg.UpdateInterval != 12*time.Hour || cfg.HTTPTimeout != 30*time.Second {
		t.Fatalf("unexpected durations: %s / %s", cfg.UpdateInterval, cfg.HTTPTimeout)
	}
	if !cfg.TLS.Enabled || cfg.TLS.CertFile != "certs/server.crt" || cfg.TLS.KeyFile != "certs/server.key" {
		t.Fatalf("unexpected tls config: %#v", cfg.TLS)
	}
	if cfg.AI.Provider != "ollama" || cfg.AI.OpenAIAPIKey != "file-key" || cfg.AI.OllamaModel != "qwen3:14b" || cfg.AI.ConfidenceCutoff != 0.66 || cfg.AI.Timeout != 11*time.Second {
		t.Fatalf("unexpected AI config: %#v", cfg.AI)
	}
	if cfg.Enrichment.TTL != 48*time.Hour || cfg.Enrichment.Timeout != 5*time.Second || cfg.Enrichment.AsyncOnMiss || cfg.Enrichment.ForegroundTimeout != 1200*time.Millisecond {
		t.Fatalf("unexpected enrichment config: %#v", cfg.Enrichment)
	}
	if cfg.History.Snapshots != 2 {
		t.Fatalf("unexpected history config: %#v", cfg.History)
	}
	if !cfg.BGP.Enabled || cfg.BGP.Mode != "full" || cfg.BGP.RouteViewsEnabled || !cfg.BGP.RIPERISEnabled || len(cfg.BGP.Collectors) != 2 {
		t.Fatalf("unexpected BGP config: %#v", cfg.BGP)
	}
	if !cfg.BGP.IncludeUpdates || cfg.BGP.HistorySnapshots != 5 || cfg.BGP.RefreshInterval != 6*time.Hour || cfg.BGP.KeepRaw {
		t.Fatalf("unexpected BGP update config: %#v", cfg.BGP)
	}
	if cfg.BGP.MaxParallelDownloads != 8 || cfg.BGP.MaxParallelParse != 4 || cfg.BGP.RawRetentionDays != 10 || cfg.BGP.SummaryFile != "data/generated/full-bgp.jsonl.gz" {
		t.Fatalf("unexpected BGP worker config: %#v", cfg.BGP)
	}
	if !cfg.Admin.Enabled || cfg.Admin.Path != "/admin" || cfg.Admin.Token != "file-token" || cfg.Admin.LocalOnly {
		t.Fatalf("unexpected admin config: %#v", cfg.Admin)
	}
	if !cfg.IP2Region.Enabled || !cfg.IP2Region.IncludeDefault || cfg.IP2Region.V4DownloadURL != "https://example.test/v4/full" {
		t.Fatalf("unexpected ip2region config: %#v", cfg.IP2Region)
	}
	if cfg.DynamicRules.Enabled || cfg.DynamicRules.File != "data/generated/custom.json" || len(cfg.DynamicRules.MailSPFDomains) != 1 {
		t.Fatalf("unexpected dynamic rules config: %#v", cfg.DynamicRules)
	}
	if !cfg.DynamicRules.IP2Proxy.Enabled || len(cfg.DynamicRules.IP2Proxy.LocalFiles) != 2 {
		t.Fatalf("unexpected ip2proxy config: %#v", cfg.DynamicRules.IP2Proxy)
	}
	if cfg.Sources.PeeringDBURL != "https://example.test/peeringdb" || cfg.Sources.RIRURLs["apnic"] != "https://example.test/apnic" {
		t.Fatalf("unexpected source config: %#v", cfg.Sources)
	}
	if len(cfg.Sources.RPKIVRPURLs) != 1 || len(cfg.Sources.IRRRouteURLs) != 1 || len(cfg.Sources.BGPObservationURLs) != 1 || len(cfg.Sources.GeofeedURLs) != 1 {
		t.Fatalf("unexpected reliability source URLs: %#v", cfg.Sources)
	}
}

func TestLoadFromYAMLThenEnvironmentOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(`addr: ":19090"`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RULES_FILE", "rules/from-env.json")
	t.Setenv("TLS_ENABLED", "1")
	t.Setenv("TLS_CERT_FILE", "certs/env.crt")
	t.Setenv("TLS_KEY_FILE", "certs/env.key")
	t.Setenv("ENRICHMENT_ASYNC_ON_MISS", "0")
	t.Setenv("ENRICHMENT_FOREGROUND_TIMEOUT_MS", "900")

	cfg, err := LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != ":19090" {
		t.Fatalf("expected addr from config file, got %q", cfg.Addr)
	}
	if cfg.RulesFile != "rules/from-env.json" {
		t.Fatalf("expected rules file from env, got %q", cfg.RulesFile)
	}
	if !cfg.TLS.Enabled || cfg.TLS.CertFile != "certs/env.crt" || cfg.TLS.KeyFile != "certs/env.key" {
		t.Fatalf("expected TLS config from env, got %#v", cfg.TLS)
	}
	if cfg.Enrichment.AsyncOnMiss {
		t.Fatalf("expected enrichment async_on_miss override from env, got %#v", cfg.Enrichment)
	}
	if cfg.Enrichment.ForegroundTimeout != 900*time.Millisecond {
		t.Fatalf("expected enrichment foreground timeout override from env, got %#v", cfg.Enrichment)
	}
}

func TestSaveToFileRoundTripsBGPAndAdminConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	cfg := Default()
	cfg.ConfigPath = path
	cfg.Addr = ":19091"
	cfg.BGP.Collectors = []string{"rrc00", "route-views.sg"}
	cfg.BGP.IncludeUpdates = true
	cfg.BGP.RefreshInterval = 6 * time.Hour
	cfg.BGP.KeepRaw = false
	cfg.Admin.Path = "/settings"
	cfg.Admin.Token = "secret"
	cfg.Admin.LocalOnly = false

	if err := SaveToFile(path, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Addr != ":19091" || len(loaded.BGP.Collectors) != 2 || loaded.BGP.Collectors[1] != "route-views.sg" {
		t.Fatalf("unexpected loaded config: %#v", loaded)
	}
	if !loaded.BGP.IncludeUpdates || loaded.BGP.RefreshInterval != 6*time.Hour || loaded.BGP.KeepRaw {
		t.Fatalf("unexpected loaded BGP config: %#v", loaded.BGP)
	}
	if loaded.Admin.Path != "/settings" || loaded.Admin.Token != "secret" || loaded.Admin.LocalOnly {
		t.Fatalf("unexpected loaded admin config: %#v", loaded.Admin)
	}
}
