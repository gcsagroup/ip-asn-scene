package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
	for _, expected := range []string{"位置", "国家码", "ASN", "country_code", "location.asn", "online-enrichment", "等待联网结果", "数据质量", "IP 质量", "include_quality", "路由安全", "多源投票", "风险提示", "服务策略", "建议拦截", "正常用户流量"} {
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
	server := New(ServerOptions{Lookup: lookup.NewService(store2EmptySnapshot()), Config: cfg, ConfigStore: store})

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "配置管理") {
		t.Fatalf("expected admin page, code=%d body=%s", rec.Code, rec.Body.String())
	}
	for _, expected := range []string{
		"更新进度",
		"progress-bar",
		"update-progress",
		"/api/admin/status",
		"pollStatus",
		"config-table",
		"cfg-addr",
		"cfg-data-dir",
		"cfg-bgp-mode",
		"cfg-ip2region-enabled",
		"cfg-quality-enabled",
		"cfg-quality-include-default",
		"cfg-quality-allow-score",
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

	req = httptest.NewRequest(http.MethodGet, "/api/admin/config", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Admin-Token", "secret")
	rec = httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected config 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Admin config.AdminConfig `json:"admin"`
		BGP   config.BGPConfig   `json:"bgp"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.BGP.Enabled || body.BGP.Mode != "full" || body.Admin.Token != "" {
		t.Fatalf("unexpected admin config body: %#v", body)
	}

	req = httptest.NewRequest(http.MethodPut, "/api/admin/config", strings.NewReader(`{"bgp":{"enabled":true,"mode":"full","collectors":["rrc00"],"include_updates":true,"history_snapshots":3,"refresh_hours":8,"max_parallel_downloads":2,"max_parallel_parse":1,"keep_raw":true,"raw_retention_days":7,"summary_file":"data/generated/admin-bgp.jsonl.gz"}}`))
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
	if !strings.Contains(rec.Body.String(), "restart_required") {
		t.Fatalf("expected restart hint, got %s", rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPut, "/api/admin/config", strings.NewReader(`{"addr":":19999","data_dir":"data-test","update_interval_hours":12,"http_timeout_seconds":9,"tls":{"enabled":true,"cert_file":"cert.pem","key_file":"key.pem"},"ip2region":{"enabled":true,"include_default":true,"v4_file":"data/raw/v4.xdb","v6_file":"data/raw/v6.xdb"},"quality":{"enabled":true,"include_default":true,"ai_low_confidence":false,"low_confidence_threshold":0.52,"allow_score":82,"review_score":64,"challenge_score":43,"rate_limit_score":21},"enrichment":{"enabled":true,"ttl_hours":48,"timeout_seconds":6,"async_on_miss":false,"foreground_timeout_ms":2500},"history":{"snapshots":5},"admin":{"enabled":true,"path":"/manage","local_only":false},"ai":{"provider":"ollama","ollama_model":"qwen3:8b","ollama_base_url":"http://127.0.0.1:11434","confidence_cutoff":0.55,"timeout_seconds":20,"max_cache":2000},"dynamic_rules":{"firehol_level1_url":"https://example.test/firehol_level1.netset","firehol_anonymous_url":"https://example.test/firehol_anonymous.netset","az0_vpn_ip_url":"https://example.test/az0-vpn-ip.txt","apple_private_relay_url":"https://example.test/apple.csv","google_fi_vpn_geofeed_url":"https://example.test/google-fi.txt","mullvad_relays_url":"https://example.test/mullvad.json","nordvpn_servers_url":"https://example.test/nordvpn.json"}}`))
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
	if !store.cfg.Enrichment.Enabled || store.cfg.Enrichment.TTL.String() != "48h0m0s" || store.cfg.Enrichment.AsyncOnMiss {
		t.Fatalf("expected enrichment config update, got %#v", store.cfg.Enrichment)
	}
	if store.cfg.History.Snapshots != 5 || store.cfg.Admin.Path != "/manage" || store.cfg.Admin.LocalOnly {
		t.Fatalf("expected history/admin config update, got history=%#v admin=%#v", store.cfg.History, store.cfg.Admin)
	}
	if store.cfg.AI.Provider != "ollama" || store.cfg.AI.OllamaModel != "qwen3:8b" || store.cfg.AI.ConfidenceCutoff != 0.55 {
		t.Fatalf("expected ai config update, got %#v", store.cfg.AI)
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

func store2EmptySnapshot() *store.Snapshot {
	return store.EmptySnapshot()
}
