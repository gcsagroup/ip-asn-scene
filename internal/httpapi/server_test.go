package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ipasn/internal/config"
	"ipasn/internal/enrich"
	"ipasn/internal/geo"
	"ipasn/internal/lookup"
	"ipasn/internal/store"
)

type fakeGeoLocator struct{}

type modeEnricher struct{}

type fakeConfigStore struct {
	cfg   config.Config
	saved bool
}

type fakeRuntimeConfigApplier struct {
	cfg    config.Config
	called bool
}

type fakeManager struct {
	status store.Status
}

func (fakeGeoLocator) Lookup(ctx context.Context, ip string) (geo.Location, bool) {
	return geo.Location{
		Country:     "美国",
		Province:    "加利福尼亚",
		City:        "山景城",
		ISP:         "Google",
		CountryCode: "US",
		ASN:         "AS15169",
		Source:      "ip2region",
		DBVersion:   "2026-05-20",
	}, true
}

func (modeEnricher) EnrichIP(ctx context.Context, ip string, allocation store.AllocationRecord) (enrich.Result, error) {
	return enrich.Result{Organization: "fast"}, nil
}

func (modeEnricher) EnrichIPWithOptions(ctx context.Context, ip string, allocation store.AllocationRecord, options enrich.RequestOptions) (enrich.Result, error) {
	return enrich.Result{Organization: string(options.Mode)}, nil
}

func (s *fakeConfigStore) Config() config.Config {
	return s.cfg
}

func (s *fakeConfigStore) UpdateConfig(cfg config.Config) error {
	s.cfg = cfg
	s.saved = true
	return nil
}

func (a *fakeRuntimeConfigApplier) ApplyRuntimeConfig(cfg config.Config) error {
	a.cfg = cfg
	a.called = true
	return nil
}

func (m *fakeManager) Status() store.Status {
	return m.status
}

func (m *fakeManager) Refresh(ctx context.Context) error {
	return nil
}

func TestLookupAPI(t *testing.T) {
	prefixes := store.NewPrefixIndex()
	if err := prefixes.Add("8.8.8.0/24", 15169, "test"); err != nil {
		t.Fatal(err)
	}
	asns := store.NewASNIndex()
	asns.Upsert(store.ASNProfile{ASN: 15169, Name: "Google LLC"})
	svc := lookup.NewService(store.NewSnapshot(prefixes, asns, store.Status{Version: "test"}))
	server := New(ServerOptions{Lookup: svc})

	req := httptest.NewRequest(http.MethodGet, "/api/lookup?query=8.8.8.8", nil)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["asn"].(float64) != 15169 {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}

func TestLookupAPIIncludesQualityByParameter(t *testing.T) {
	prefixes := store.NewPrefixIndex()
	if err := prefixes.Add("8.8.8.0/24", 15169, "test"); err != nil {
		t.Fatal(err)
	}
	asns := store.NewASNIndex()
	asns.Upsert(store.ASNProfile{ASN: 15169, Name: "Google LLC"})
	svc := lookup.NewService(store.NewSnapshot(prefixes, asns, store.Status{Version: "test"}))
	server := New(ServerOptions{Lookup: svc, Config: config.Default()})

	req := httptest.NewRequest(http.MethodGet, "/api/lookup?query=8.8.8.8", nil)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	var ordinary map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &ordinary); err != nil {
		t.Fatal(err)
	}
	if _, ok := ordinary["ip_quality"]; ok {
		t.Fatalf("expected quality to be omitted by default: %s", rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/lookup?query=8.8.8.8&include_quality=1", nil)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	var withQuality struct {
		Quality struct {
			Score          int    `json:"score"`
			Grade          string `json:"grade"`
			RiskLevel      string `json:"risk_level"`
			Recommendation string `json:"recommendation"`
		} `json:"ip_quality"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &withQuality); err != nil {
		t.Fatal(err)
	}
	if withQuality.Quality.Score == 0 || withQuality.Quality.Grade == "" || withQuality.Quality.RiskLevel == "" || withQuality.Quality.Recommendation == "" {
		t.Fatalf("expected quality result in lookup response: %s", rec.Body.String())
	}
}

func TestLookupAPIIncludesPerformanceByParameter(t *testing.T) {
	prefixes := store.NewPrefixIndex()
	if err := prefixes.Add("8.8.8.0/24", 15169, "test"); err != nil {
		t.Fatal(err)
	}
	asns := store.NewASNIndex()
	asns.Upsert(store.ASNProfile{ASN: 15169, Name: "Google LLC"})
	svc := lookup.NewService(store.NewSnapshot(prefixes, asns, store.Status{Version: "test"}))
	server := New(ServerOptions{Lookup: svc, Config: config.Default()})

	req := httptest.NewRequest(http.MethodGet, "/api/lookup?query=8.8.8.8", nil)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	var ordinary map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &ordinary); err != nil {
		t.Fatal(err)
	}
	if _, ok := ordinary["performance"]; ok {
		t.Fatalf("expected performance to be omitted by default: %s", rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/lookup?query=8.8.8.8&include_performance=1", nil)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	var withPerformance map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &withPerformance); err != nil {
		t.Fatal(err)
	}
	performance, ok := withPerformance["performance"].(map[string]any)
	if !ok {
		t.Fatalf("expected performance in response: %s", rec.Body.String())
	}
	total, totalOK := performance["total_ms"].(float64)
	local, localOK := performance["local_offline_ms"].(float64)
	if !totalOK || !localOK || total < 0 || local < 0 {
		t.Fatalf("expected performance metrics in lookup response: %s", rec.Body.String())
	}
}

func TestQualityAPI(t *testing.T) {
	prefixes := store.NewPrefixIndex()
	if err := prefixes.Add("1.2.3.0/24", 64500, "test"); err != nil {
		t.Fatal(err)
	}
	asns := store.NewASNIndex()
	asns.Upsert(store.ASNProfile{ASN: 64500, Name: "Example VPN Hosting"})
	svc := lookup.NewService(store.NewSnapshot(prefixes, asns, store.Status{Version: "test"}))
	server := New(ServerOptions{Lookup: svc, Config: config.Default()})

	req := httptest.NewRequest(http.MethodGet, "/api/quality?query=1.2.3.4", nil)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		OK      bool `json:"ok"`
		Quality struct {
			Score          int      `json:"score"`
			Labels         []string `json:"labels"`
			Recommendation string   `json:"recommendation"`
		} `json:"ip_quality"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.OK || body.Quality.Score == 0 || body.Quality.Recommendation == "" {
		t.Fatalf("expected quality API response, got %s", rec.Body.String())
	}
}

func TestLookupAPIParsesOnlineEnrichmentMode(t *testing.T) {
	prefixes := store.NewPrefixIndex()
	if err := prefixes.Add("223.119.0.0/16", 58453, "test"); err != nil {
		t.Fatal(err)
	}
	asns := store.NewASNIndex()
	asns.Upsert(store.ASNProfile{ASN: 58453, Name: "China Mobile International", Country: "HK", Registry: "apnic"})
	svc := lookup.NewServiceWithOptions(store.NewSnapshot(prefixes, asns, store.Status{Version: "test"}), lookup.Options{
		Enricher: modeEnricher{},
	})
	server := New(ServerOptions{Lookup: svc})

	req := httptest.NewRequest(http.MethodGet, "/api/lookup?query=223.119.20.239&online_enrichment=wait", nil)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	var body struct {
		Registration *enrich.Result `json:"registration"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Registration == nil || body.Registration.Organization != "wait" {
		t.Fatalf("expected wait mode registration, got %s", rec.Body.String())
	}
}

func TestLookupAPIIncludesLocationByParameter(t *testing.T) {
	prefixes := store.NewPrefixIndex()
	if err := prefixes.Add("8.8.8.0/24", 15169, "test"); err != nil {
		t.Fatal(err)
	}
	asns := store.NewASNIndex()
	asns.Upsert(store.ASNProfile{ASN: 15169, Name: "Google LLC"})
	svc := lookup.NewServiceWithOptions(store.NewSnapshot(prefixes, asns, store.Status{Version: "test"}), lookup.Options{
		GeoLocator: fakeGeoLocator{},
	})
	server := New(ServerOptions{Lookup: svc})

	req := httptest.NewRequest(http.MethodGet, "/api/lookup?query=8.8.8.8", nil)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	var ordinary map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &ordinary); err != nil {
		t.Fatal(err)
	}
	if _, ok := ordinary["location"]; ok {
		t.Fatalf("expected location to be omitted by default: %s", rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/lookup?query=8.8.8.8&include_location=1", nil)
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	var withLocation map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &withLocation); err != nil {
		t.Fatal(err)
	}
	location, ok := withLocation["location"].(map[string]any)
	if !ok {
		t.Fatalf("expected location in response: %s", rec.Body.String())
	}
	if location["country"] != "美国" || location["city"] != "山景城" || location["country_code"] != "US" || location["asn"] != "AS15169" {
		t.Fatalf("unexpected location: %#v", location)
	}
	if _, ok := location["source"]; ok {
		t.Fatalf("expected location source to be hidden: %#v", location)
	}
	if _, ok := location["db_version"]; ok {
		t.Fatalf("expected location db version to be hidden: %#v", location)
	}
}

func TestIndexPageRendersLocationWithoutInternalMetadata(t *testing.T) {
	server := New(ServerOptions{Lookup: lookup.NewService(store.EmptySnapshot())})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	body := rec.Body.String()
	for _, expected := range []string{"位置", "国家码", "ASN", "country_code", "location.asn", "online-enrichment", "等待联网结果", "数据质量", "IP 质量", "include_quality", "性能指标", "include_performance", "路由安全", "多源投票", "风险提示", "服务策略", "建议拦截", "正常用户流量"} {
		if !strings.Contains(body, expected) {
			t.Fatalf("expected index page to contain %q", expected)
		}
	}
	for _, hidden := range []string{"数据源", "库版本", "location.source", "location.db_version"} {
		if strings.Contains(body, hidden) {
			t.Fatalf("expected index page to hide %q", hidden)
		}
	}
}

func TestIndexPageServed(t *testing.T) {
	server := New(ServerOptions{Lookup: lookup.NewService(store.EmptySnapshot())})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "IP / ASN") {
		t.Fatalf("expected index page, got %s", rec.Body.String())
	}
}

func TestAdminPageAndConfigAPI(t *testing.T) {
	cfg := config.Default()
	cfg.Admin.Enabled = true
	cfg.Admin.Path = "/admin"
	cfg.Admin.Token = "secret"
	cfg.Admin.LocalOnly = true
	cfg.BGP.Enabled = true
	cfg.BGP.Mode = "full"
	cfg.BGP.Collectors = []string{"all"}
	store := &fakeConfigStore{cfg: cfg}
	applier := &fakeRuntimeConfigApplier{}
	server := New(ServerOptions{Lookup: lookup.NewService(store2EmptySnapshot()), Config: cfg, ConfigStore: store, RuntimeConfigApplier: applier})

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "配置管理") {
		t.Fatalf("expected admin page, code=%d body=%s", rec.Code, rec.Body.String())
	}
	for _, expected := range []string{
		"admin-tabs",
		"data-tab=\"overview\"",
		"data-tab=\"libraries\"",
		"data-tab=\"config\"",
		"data-tab=\"help\"",
		"tab-panel active",
		"switchAdminTab",
		"更新进度",
		"离线库列表",
		"配置帮助",
		"填充公开默认源",
		"applyPublicDefaults",
		"renderOfflineLibraries",
		"renderConfigHelp",
		"progress-bar",
		"update-progress",
		"/api/admin/status",
		"pollStatus",
		"config-table",
		"config-actions",
		"id=\"save-config-inline\"",
		"save-config-inline",
		"cfg-addr",
		"cfg-data-dir",
		"cfg-bgp-mode",
		"cfg-ip2region-enabled",
		"cfg-quality-enabled",
		"cfg-quality-include-default",
		"cfg-quality-allow-score",
		"cfg-performance-enabled",
		"cfg-performance-include-default",
		"cfg-performance-third-party-default",
		"cfg-ai-provider",
		"cfg-ai-openai-api-type",
		"data-model-select-provider=\"openai\"",
		"data-model-select-provider=\"anthropic\"",
		"data-model-select-provider=\"gemini\"",
		"cfg-ai-anthropic-api-key",
		"cfg-ai-anthropic-model",
		"cfg-ai-gemini-api-key",
		"cfg-ai-gemini-model",
		"data-ai-provider-scope=\"openai\"",
		"data-ai-provider-scope=\"anthropic\"",
		"data-ai-provider-scope=\"gemini\"",
		"updateAIProviderVisibility",
		"refreshAIModels",
		"data-model-provider=\"openai\"",
		"data-model-provider=\"anthropic\"",
		"data-model-provider=\"gemini\"",
		"cfg-apple-private-relay-url",
		"cfg-google-fi-vpn-geofeed-url",
		"cfg-mullvad-relays-url",
		"cfg-nordvpn-servers-url",
		"saveConfigFromForm",
		"可选增强源",
		"已预置 rpki-client 公共 CSV",
		"全量 BGP 模式会生成本地摘要",
		"OpenGeoFeed",
	} {
		if !strings.Contains(rec.Body.String(), expected) {
			t.Fatalf("expected admin page to contain %q", expected)
		}
	}
	if strings.Contains(rec.Body.String(), `<textarea id="config"`) {
		t.Fatalf("admin page should render structured controls instead of a raw config textarea")
	}
	if strings.Contains(rec.Body.String(), "cfg-ai-ollama") {
		t.Fatalf("admin page should not render Ollama-specific controls")
	}
	if strings.Contains(rec.Body.String(), `list="ai-openai-models"`) || strings.Contains(rec.Body.String(), `<datalist id="ai-openai-models"`) {
		t.Fatalf("admin page should use selectable model controls instead of datalist inputs")
	}
	saveIndex := strings.Index(rec.Body.String(), `id="save-config-inline"`)
	geofeedIndex := strings.Index(rec.Body.String(), "Geofeed URLs")
	if saveIndex < 0 || geofeedIndex < 0 || saveIndex < geofeedIndex {
		t.Fatalf("expected inline config save button near bottom after data-source controls")
	}

	req = httptest.NewRequest(http.MethodGet, "/api/admin/config", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Admin-Token", "secret")
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected config 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Admin    config.AdminConfig     `json:"admin"`
		BGP      config.BGPConfig       `json:"bgp"`
		Defaults map[string]any         `json:"defaults"`
		Help     map[string]interface{} `json:"help"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.BGP.Enabled || body.BGP.Mode != "full" || body.Admin.Token != "" {
		t.Fatalf("unexpected admin config body: %#v", body)
	}
	if body.Defaults == nil || body.Defaults["dynamic_rules"] == nil || body.Defaults["sources"] == nil {
		t.Fatalf("expected config defaults in admin config body: %#v", body.Defaults)
	}
	if _, ok := body.Help["dynamic_rules.firehol_anonymous_url"]; !ok {
		t.Fatalf("expected detailed config help for optional FireHOL anonymous URL: %#v", body.Help)
	}
	if _, ok := body.Help["dynamic_rules.ip2proxy.download_url"]; !ok {
		t.Fatalf("expected detailed config help for IP2Proxy download URL: %#v", body.Help)
	}
	if _, ok := body.Help["bgp.download_timeout_seconds"]; !ok {
		t.Fatalf("expected detailed config help for BGP download timeout: %#v", body.Help)
	}
	if _, ok := body.Help["performance.include_default"]; !ok {
		t.Fatalf("expected detailed config help for performance metrics: %#v", body.Help)
	}

	req = httptest.NewRequest(http.MethodPut, "/api/admin/config", strings.NewReader(`{"bgp":{"enabled":true,"mode":"full","collectors":["rrc00"],"include_updates":true,"history_snapshots":3,"refresh_hours":8,"max_parallel_downloads":2,"download_timeout_seconds":3600,"max_parallel_parse":1,"keep_raw":true,"raw_retention_days":7,"summary_file":"data/generated/admin-bgp.jsonl.gz"}}`))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Admin-Token", "secret")
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected update 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !store.saved || len(store.cfg.BGP.Collectors) != 1 || store.cfg.BGP.Collectors[0] != "rrc00" || !store.cfg.BGP.IncludeUpdates {
		t.Fatalf("expected config update, got saved=%v cfg=%#v", store.saved, store.cfg.BGP)
	}
	if store.cfg.BGP.DownloadTimeout != time.Hour {
		t.Fatalf("expected BGP download timeout update, got %#v", store.cfg.BGP)
	}
	if !strings.Contains(rec.Body.String(), "restart_required") {
		t.Fatalf("expected restart hint, got %s", rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPut, "/api/admin/config", strings.NewReader(`{"addr":":19999","data_dir":"data-test","update_interval_hours":12,"http_timeout_seconds":9,"tls":{"enabled":true,"cert_file":"cert.pem","key_file":"key.pem"},"ip2region":{"enabled":true,"include_default":true,"v4_file":"data/raw/v4.xdb","v6_file":"data/raw/v6.xdb"},"quality":{"enabled":true,"include_default":true,"ai_low_confidence":false,"low_confidence_threshold":0.52,"allow_score":82,"review_score":64,"challenge_score":43,"rate_limit_score":21},"performance":{"enabled":true,"include_default":true,"third_party_default":false},"enrichment":{"enabled":true,"ttl_hours":48,"timeout_seconds":6,"async_on_miss":false,"foreground_timeout_ms":2500},"history":{"snapshots":5},"admin":{"enabled":true,"path":"/manage","local_only":false},"ai":{"provider":"anthropic","openai_model":"gpt-test","openai_base_url":"https://openai.example.test/v1","openai_api_type":"chat_completions","anthropic_api_key":"anthropic-key","anthropic_model":"claude-test","anthropic_base_url":"https://anthropic.example.test","anthropic_version":"2023-06-01","gemini_api_key":"gemini-key","gemini_model":"gemini-test","gemini_base_url":"https://gemini.example.test/v1beta","confidence_cutoff":0.55,"timeout_seconds":20,"max_cache":2000},"dynamic_rules":{"firehol_level1_url":"https://example.test/firehol_level1.netset","firehol_anonymous_url":"https://example.test/firehol_anonymous.netset","az0_vpn_ip_url":"https://example.test/az0-vpn-ip.txt","apple_private_relay_url":"https://example.test/apple.csv","google_fi_vpn_geofeed_url":"https://example.test/google-fi.txt","mullvad_relays_url":"https://example.test/mullvad.json","nordvpn_servers_url":"https://example.test/nordvpn.json"}}`))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Admin-Token", "secret")
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected full config update 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if store.cfg.Addr != ":19999" || store.cfg.DataDir != "data-test" || !store.cfg.TLS.Enabled || store.cfg.TLS.CertFile != "cert.pem" || store.cfg.HTTPTimeout.String() != "9s" {
		t.Fatalf("expected top-level config update, got %#v", store.cfg)
	}
	if !store.cfg.IP2Region.Enabled || !store.cfg.IP2Region.IncludeDefault || store.cfg.IP2Region.V4File != "data/raw/v4.xdb" {
		t.Fatalf("expected ip2region config update, got %#v", store.cfg.IP2Region)
	}
	if !store.cfg.Quality.Enabled || !store.cfg.Quality.IncludeDefault || store.cfg.Quality.AILowConfidence || store.cfg.Quality.LowConfidenceThreshold != 0.52 || store.cfg.Quality.AllowScore != 82 {
		t.Fatalf("expected quality config update, got %#v", store.cfg.Quality)
	}
	if !store.cfg.Performance.Enabled || !store.cfg.Performance.IncludeDefault || store.cfg.Performance.ThirdPartyDefault {
		t.Fatalf("expected performance config update, got %#v", store.cfg.Performance)
	}
	if !store.cfg.Enrichment.Enabled || store.cfg.Enrichment.TTL.String() != "48h0m0s" || store.cfg.Enrichment.AsyncOnMiss {
		t.Fatalf("expected enrichment config update, got %#v", store.cfg.Enrichment)
	}
	if store.cfg.History.Snapshots != 5 || store.cfg.Admin.Path != "/manage" || store.cfg.Admin.LocalOnly {
		t.Fatalf("expected history/admin config update, got history=%#v admin=%#v", store.cfg.History, store.cfg.Admin)
	}
	if store.cfg.AI.Provider != "anthropic" || store.cfg.AI.OpenAIAPIType != "chat_completions" || store.cfg.AI.AnthropicAPIKey != "anthropic-key" || store.cfg.AI.AnthropicModel != "claude-test" || store.cfg.AI.GeminiAPIKey != "gemini-key" || store.cfg.AI.GeminiModel != "gemini-test" || store.cfg.AI.ConfidenceCutoff != 0.55 {
		t.Fatalf("expected ai config update, got %#v", store.cfg.AI)
	}
	if !applier.called || applier.cfg.AI.Provider != "anthropic" || applier.cfg.AI.AnthropicModel != "claude-test" {
		t.Fatalf("expected runtime config applier to receive AI config, called=%v cfg=%#v", applier.called, applier.cfg.AI)
	}
	if !strings.Contains(rec.Body.String(), `"runtime_applied":true`) {
		t.Fatalf("expected runtime_applied response, got %s", rec.Body.String())
	}
	if store.cfg.DynamicRules.ApplePrivateRelayURL != "https://example.test/apple.csv" || store.cfg.DynamicRules.GoogleFiVPNGeofeedURL != "https://example.test/google-fi.txt" {
		t.Fatalf("expected privacy proxy dynamic URLs update, got %#v", store.cfg.DynamicRules)
	}
	if store.cfg.DynamicRules.FireHOLLevel1URL != "https://example.test/firehol_level1.netset" || store.cfg.DynamicRules.FireHOLAnonymousURL != "https://example.test/firehol_anonymous.netset" {
		t.Fatalf("expected FireHOL dynamic URLs update, got %#v", store.cfg.DynamicRules)
	}
	if store.cfg.DynamicRules.Az0VPNIPURL != "https://example.test/az0-vpn-ip.txt" {
		t.Fatalf("expected az0/vpn_ip dynamic URL update, got %#v", store.cfg.DynamicRules)
	}
	if store.cfg.DynamicRules.MullvadRelaysURL != "https://example.test/mullvad.json" || store.cfg.DynamicRules.NordVPNServersURL != "https://example.test/nordvpn.json" {
		t.Fatalf("expected VPN provider dynamic URLs update, got %#v", store.cfg.DynamicRules)
	}

	store.cfg.Sources.RPKIVRPURLs = []string{"https://example.test/old.csv"}
	store.cfg.Sources.IRRRouteURLs = []string{"https://example.test/old.db.gz"}
	store.cfg.Sources.BGPObservationURLs = []string{"https://example.test/old.jsonl"}
	store.cfg.Sources.GeofeedURLs = []string{"https://example.test/old-geofeed.csv"}
	req = httptest.NewRequest(http.MethodPut, "/api/admin/config", strings.NewReader(`{"sources":{"rpki_vrp_urls":[],"irr_route_urls":[],"bgp_observation_urls":[],"geofeed_urls":[]}}`))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Admin-Token", "secret")
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected reliability source clear 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if len(store.cfg.Sources.RPKIVRPURLs) != 0 || len(store.cfg.Sources.IRRRouteURLs) != 0 || len(store.cfg.Sources.BGPObservationURLs) != 0 || len(store.cfg.Sources.GeofeedURLs) != 0 {
		t.Fatalf("expected reliability sources to be cleared, got %#v", store.cfg.Sources)
	}

	req = httptest.NewRequest(http.MethodPut, "/api/admin/config", strings.NewReader(`{"sources":{"rpki_vrp_urls":["https://console.rpki-client.org/vrps.csv"],"irr_route_urls":["https://ftp.ripe.net/ripe/dbase/split/ripe.db.route.gz"],"geofeed_urls":["https://opengeofeed.org/feed/public.csv"]}}`))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Admin-Token", "secret")
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected reliability source update 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if len(store.cfg.Sources.RPKIVRPURLs) != 1 || store.cfg.Sources.RPKIVRPURLs[0] != "https://console.rpki-client.org/vrps.csv" {
		t.Fatalf("expected RPKI source update, got %#v", store.cfg.Sources.RPKIVRPURLs)
	}
	if len(store.cfg.Sources.IRRRouteURLs) != 1 || store.cfg.Sources.IRRRouteURLs[0] != "https://ftp.ripe.net/ripe/dbase/split/ripe.db.route.gz" {
		t.Fatalf("expected IRR source update, got %#v", store.cfg.Sources.IRRRouteURLs)
	}
	if len(store.cfg.Sources.GeofeedURLs) != 1 || store.cfg.Sources.GeofeedURLs[0] != "https://opengeofeed.org/feed/public.csv" {
		t.Fatalf("expected geofeed source update, got %#v", store.cfg.Sources.GeofeedURLs)
	}
}

func TestAdminStatusIncludesOfflineLibraryList(t *testing.T) {
	dataDir := t.TempDir()
	rawDir := filepath.Join(dataDir, "raw")
	generatedDir := filepath.Join(dataDir, "generated")
	if err := os.MkdirAll(rawDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(generatedDir, 0o755); err != nil {
		t.Fatal(err)
	}
	rawFile := filepath.Join(rawDir, "caida-ipv4.pfx2as.gz")
	if err := os.WriteFile(rawFile, []byte("prefix"), 0o644); err != nil {
		t.Fatal(err)
	}
	irrFile := filepath.Join(rawDir, "irr-routes.route.gz")
	if err := os.WriteFile(irrFile, []byte("irr"), 0o644); err != nil {
		t.Fatal(err)
	}
	generatedFile := filepath.Join(generatedDir, "services.json")
	if err := os.WriteFile(generatedFile, []byte(`{"version":"20260623T010203Z","updated_at":"2026-06-23T01:02:03Z","rules":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	processedDir := filepath.Join(dataDir, "processed")
	if err := os.MkdirAll(processedDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(processedDir, "download-state.json"), []byte(`{"version":1,"updated_at":"2026-06-23T02:03:04Z","entries":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	bgpSummaryFile := filepath.Join(dataDir, "custom", "current-bgp.jsonl.gz")
	if err := os.MkdirAll(filepath.Dir(bgpSummaryFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bgpSummaryFile, []byte("bgp"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Admin.Enabled = true
	cfg.Admin.Path = "/admin"
	cfg.Admin.LocalOnly = true
	cfg.DataDir = dataDir
	cfg.BGP.SummaryFile = filepath.Join("custom", "current-bgp.jsonl.gz")
	cfg.DynamicRules.File = generatedFile
	cfg.IP2Region.V4File = filepath.Join(rawDir, "missing-v4.xdb")
	status := store.Status{
		Version:   "snapshot-version",
		Loaded:    true,
		UpdatedAt: time.Date(2026, 6, 23, 1, 3, 0, 0, time.UTC),
		DataDir:   dataDir,
		RawFiles: map[string]string{
			"caida_ipv4": rawFile,
		},
	}
	manager := &fakeManager{status: status}
	server := New(ServerOptions{Lookup: lookup.NewService(store2EmptySnapshot()), Config: cfg, Manager: manager})

	req := httptest.NewRequest(http.MethodGet, "/api/admin/status", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var body struct {
		OfflineLibraries []struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			Kind      string `json:"kind"`
			Path      string `json:"path"`
			SourceURL string `json:"source_url"`
			Exists    bool   `json:"exists"`
			Size      string `json:"size"`
			UpdatedAt string `json:"updated_at"`
			Version   string `json:"version"`
		} `json:"offline_libraries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.OfflineLibraries) == 0 {
		t.Fatalf("expected offline library rows, got %s", rec.Body.String())
	}
	foundCAIDA := false
	foundIRR := false
	foundDynamic := false
	foundDownloadState := false
	foundBGP := false
	foundMissingIP2Region := false
	for _, item := range body.OfflineLibraries {
		switch item.ID {
		case "caida_ipv4":
			foundCAIDA = true
			if !item.Exists || item.Size == "" || item.UpdatedAt == "" || item.SourceURL == "" {
				t.Fatalf("expected CAIDA row with file metadata and source URL: %#v", item)
			}
		case "irr_route_0":
			foundIRR = true
			if !item.Exists || !strings.HasSuffix(item.Path, "irr-routes.route.gz") {
				t.Fatalf("expected IRR row to use downloaded .route.gz file, got %#v", item)
			}
		case "dynamic_rules":
			foundDynamic = true
			if !item.Exists || item.Version != "20260623T010203Z" || item.UpdatedAt == "" {
				t.Fatalf("expected dynamic rules row with parsed version: %#v", item)
			}
		case "download_state":
			foundDownloadState = true
			if !item.Exists || item.Version != "1" || item.UpdatedAt != "2026-06-23T02:03:04Z" {
				t.Fatalf("expected download state row with parsed version and updated_at: %#v", item)
			}
		case "bgp_full_summary":
			foundBGP = true
			if !item.Exists || item.Path != bgpSummaryFile {
				t.Fatalf("expected BGP row to resolve summary path under data_dir, got %#v", item)
			}
		case "ip2region_v4":
			foundMissingIP2Region = true
			if item.Exists {
				t.Fatalf("expected missing ip2region file to be marked missing: %#v", item)
			}
		}
	}
	if !foundCAIDA || !foundIRR || !foundDynamic || !foundDownloadState || !foundBGP || !foundMissingIP2Region {
		t.Fatalf("expected CAIDA, IRR, dynamic rules, download state, BGP and ip2region rows, got %#v", body.OfflineLibraries)
	}
}

func TestAdminLocalOnlyRejectsRemoteAddress(t *testing.T) {
	cfg := config.Default()
	cfg.Admin.Enabled = true
	cfg.Admin.LocalOnly = true
	store := &fakeConfigStore{cfg: cfg}
	server := New(ServerOptions{Lookup: lookup.NewService(store2EmptySnapshot()), Config: cfg, ConfigStore: store})

	req := httptest.NewRequest(http.MethodGet, "/api/admin/config", nil)
	req.RemoteAddr = "203.0.113.10:12345"
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for remote admin request, got %d", rec.Code)
	}
}

func TestAdminAIModelsAPIUsesConfiguredProvider(t *testing.T) {
	modelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Fatalf("unexpected model path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer openai-key" {
			t.Fatalf("missing model API authorization header")
		}
		_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"gpt-test","owned_by":"test-owner"}]}`))
	}))
	defer modelServer.Close()

	cfg := config.Default()
	cfg.Admin.Enabled = true
	cfg.Admin.LocalOnly = true
	cfg.AI.Provider = "openai"
	cfg.AI.OpenAIAPIKey = "openai-key"
	cfg.AI.OpenAIBaseURL = modelServer.URL + "/v1"
	server := New(ServerOptions{Lookup: lookup.NewService(store2EmptySnapshot()), Config: cfg})

	req := httptest.NewRequest(http.MethodPost, "/api/admin/ai/models", strings.NewReader(`{"provider":"openai"}`))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected models 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		OK       bool   `json:"ok"`
		Provider string `json:"provider"`
		Source   string `json:"source"`
		Models   []struct {
			ID      string `json:"id"`
			OwnedBy string `json:"owned_by"`
		} `json:"models"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	foundOnlineModel := false
	for _, model := range body.Models {
		if model.ID == "gpt-test" && model.OwnedBy == "test-owner" {
			foundOnlineModel = true
		}
	}
	if !body.OK || body.Provider != "openai" || body.Source != "online" || !foundOnlineModel {
		t.Fatalf("unexpected models body: %#v", body)
	}
}

func TestAdminAIModelsAPIMergesOnlineConfiguredAndBuiltInModels(t *testing.T) {
	modelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Fatalf("unexpected model path: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"online-only","owned_by":"test-owner"}]}`))
	}))
	defer modelServer.Close()

	cfg := config.Default()
	cfg.Admin.Enabled = true
	cfg.Admin.LocalOnly = true
	cfg.AI.Provider = "openai"
	cfg.AI.OpenAIAPIKey = "openai-key"
	cfg.AI.OpenAIBaseURL = modelServer.URL + "/v1"
	cfg.AI.OpenAIModel = "configured-custom"
	server := New(ServerOptions{Lookup: lookup.NewService(store2EmptySnapshot()), Config: cfg})

	req := httptest.NewRequest(http.MethodPost, "/api/admin/ai/models", strings.NewReader(`{"provider":"openai"}`))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected models 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var body struct {
		OK     bool `json:"ok"`
		Models []struct {
			ID string `json:"id"`
		} `json:"models"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, model := range body.Models {
		ids[model.ID] = true
	}
	for _, expected := range []string{"online-only", "configured-custom", "gpt-5.4-mini"} {
		if !ids[expected] {
			t.Fatalf("expected merged model list to include %q, got %#v", expected, body.Models)
		}
	}
}

func TestAdminAIModelsAPIFallsBackToBuiltInModelsWithoutAPIKey(t *testing.T) {
	cfg := config.Default()
	cfg.Admin.Enabled = true
	cfg.Admin.LocalOnly = true
	cfg.AI.Provider = "openai"
	cfg.AI.OpenAIAPIKey = ""
	cfg.AI.OpenAIModel = "configured-custom"
	server := New(ServerOptions{Lookup: lookup.NewService(store2EmptySnapshot()), Config: cfg})

	req := httptest.NewRequest(http.MethodPost, "/api/admin/ai/models", strings.NewReader(`{"provider":"openai"}`))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected fallback models 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var body struct {
		OK     bool   `json:"ok"`
		Source string `json:"source"`
		Models []struct {
			ID string `json:"id"`
		} `json:"models"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, model := range body.Models {
		ids[model.ID] = true
	}
	if !body.OK || body.Source != "fallback" || !ids["configured-custom"] || !ids["gpt-5.4-mini"] {
		t.Fatalf("expected built-in fallback models, got %#v", body)
	}
}

func TestAdminAIModelsAPISanitizesProviderErrors(t *testing.T) {
	modelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"Incorrect API key provided: sk-secret-value"}}`))
	}))
	defer modelServer.Close()

	cfg := config.Default()
	cfg.Admin.Enabled = true
	cfg.Admin.LocalOnly = true
	cfg.AI.Provider = "openai"
	cfg.AI.OpenAIAPIKey = "sk-secret-value"
	cfg.AI.OpenAIBaseURL = modelServer.URL + "/v1"
	server := New(ServerOptions{Lookup: lookup.NewService(store2EmptySnapshot()), Config: cfg})

	req := httptest.NewRequest(http.MethodPost, "/api/admin/ai/models", strings.NewReader(`{"provider":"openai"}`))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected fallback models 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "sk-secret-value") || strings.Contains(rec.Body.String(), "Incorrect API key provided") {
		t.Fatalf("provider error should be sanitized, got %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "AI provider authentication failed") {
		t.Fatalf("expected sanitized auth error, got %s", rec.Body.String())
	}
}

func TestAdminAIModelsAPIUsesShortLivedCache(t *testing.T) {
	requests := 0
	modelServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests > 1 {
			http.Error(w, "unexpected second online request", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"cached-online","owned_by":"test-owner"}]}`))
	}))
	defer modelServer.Close()

	cfg := config.Default()
	cfg.Admin.Enabled = true
	cfg.Admin.LocalOnly = true
	cfg.AI.Provider = "openai"
	cfg.AI.OpenAIAPIKey = "openai-key"
	cfg.AI.OpenAIBaseURL = modelServer.URL + "/v1"
	server := New(ServerOptions{Lookup: lookup.NewService(store2EmptySnapshot()), Config: cfg})

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/admin/ai/models", strings.NewReader(`{"provider":"openai"}`))
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d expected models 200, got %d body=%s", i+1, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "cached-online") {
			t.Fatalf("request %d expected cached online model, got %s", i+1, rec.Body.String())
		}
	}
	if requests != 1 {
		t.Fatalf("expected one online models request because second call should use cache, got %d", requests)
	}
}

func store2EmptySnapshot() *store.Snapshot {
	return store.EmptySnapshot()
}
