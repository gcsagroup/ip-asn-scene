package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"ipasn/internal/config"
	"ipasn/internal/lookup"
	"ipasn/internal/store"
)

type Manager interface {
	Status() store.Status
	Refresh(context.Context) error
}

type ConfigStore interface {
	Config() config.Config
	UpdateConfig(config.Config) error
}

type ServerOptions struct {
	Lookup                 *lookup.Service
	Manager                Manager
	IncludeLocationDefault bool
	Config                 config.Config
	ConfigStore            ConfigStore
}

type Server struct {
	mux                    *http.ServeMux
	lookup                 *lookup.Service
	manager                Manager
	includeLocationDefault bool
	cfg                    config.Config
	configStore            ConfigStore
}

func New(options ServerOptions) *Server {
	if options.Lookup == nil {
		options.Lookup = lookup.NewService(store.EmptySnapshot())
	}
	server := &Server{
		mux:                    http.NewServeMux(),
		lookup:                 options.Lookup,
		manager:                options.Manager,
		includeLocationDefault: options.IncludeLocationDefault,
		cfg:                    options.Config,
		configStore:            options.ConfigStore,
	}
	server.routes()
	return server
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	if s.cfg.Admin.Enabled {
		s.mux.HandleFunc(s.cfg.Admin.Path, s.adminPage)
		s.mux.HandleFunc("/api/admin/config", s.adminConfigHandler)
		s.mux.HandleFunc("/api/admin/status", s.adminStatusHandler)
		s.mux.HandleFunc("/api/admin/update", s.adminUpdateHandler)
	}
	s.mux.HandleFunc("/", s.index)
	s.mux.HandleFunc("/favicon.ico", s.favicon)
	s.mux.HandleFunc("/api/lookup", s.lookupHandler)
	s.mux.HandleFunc("/api/health", s.healthHandler)
	s.mux.HandleFunc("/api/db/status", s.statusHandler)
	s.mux.HandleFunc("/api/db/update", s.updateHandler)
}

func (s *Server) adminPage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != s.cfg.Admin.Path {
		http.NotFound(w, r)
		return
	}
	if !s.authorizeAdmin(w, r, false) {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(adminHTML))
}

func (s *Server) adminConfigHandler(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r, true) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		cfg := s.currentConfig()
		writeJSON(w, http.StatusOK, publicConfig(cfg))
	case http.MethodPut:
		cfg := s.currentConfig()
		body, err := io.ReadAll(io.LimitReader(r.Body, 1024*1024))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		updated, err := applyAdminConfigPatch(cfg, body)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		if s.configStore != nil {
			if err := s.configStore.UpdateConfig(updated); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
				return
			}
		}
		s.cfg = updated
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "restart_required": true, "config": publicConfig(updated)})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) adminStatusHandler(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r, true) {
		return
	}
	status := map[string]any{"ok": true, "config": publicConfig(s.currentConfig())}
	if s.manager != nil {
		status["database"] = s.manager.Status()
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) adminUpdateHandler(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r, true) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.updateHandler(w, r)
}

func (s *Server) authorizeAdmin(w http.ResponseWriter, r *http.Request, requireToken bool) bool {
	admin := s.currentConfig().Admin
	if !admin.Enabled {
		http.NotFound(w, r)
		return false
	}
	if admin.LocalOnly && !isLocalRequest(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	if token := strings.TrimSpace(admin.Token); token != "" && requireToken {
		provided := strings.TrimSpace(r.Header.Get("X-Admin-Token"))
		if provided == "" {
			provided = strings.TrimSpace(r.URL.Query().Get("token"))
		}
		if provided != token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return false
		}
	}
	return true
}

func (s *Server) currentConfig() config.Config {
	if s.configStore != nil {
		return s.configStore.Config()
	}
	return s.cfg
}

func isLocalRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func publicConfig(cfg config.Config) map[string]any {
	cfg.Admin.Token = ""
	cfg.AI.OpenAIAPIKey = ""
	cfg.DynamicRules.IP2Proxy.Token = ""
	return map[string]any{
		"addr":                  cfg.Addr,
		"data_dir":              cfg.DataDir,
		"rules_file":            cfg.RulesFile,
		"asn_rules_file":        cfg.ASNRulesFile,
		"update_interval_hours": int(cfg.UpdateInterval / time.Hour),
		"http_timeout_seconds":  int(cfg.HTTPTimeout / time.Second),
		"tls":                   publicTLSConfig(cfg.TLS),
		"ai":                    publicAIConfig(cfg.AI),
		"enrichment":            publicEnrichmentConfig(cfg.Enrichment),
		"history":               map[string]any{"snapshots": cfg.History.Snapshots},
		"dynamic_rules":         publicDynamicRulesConfig(cfg.DynamicRules),
		"ip2region":             publicIP2RegionConfig(cfg.IP2Region),
		"bgp":                   publicBGPConfig(cfg.BGP),
		"admin":                 cfg.Admin,
		"sources":               publicSourcesConfig(cfg.Sources),
	}
}

func publicTLSConfig(cfg config.TLSConfig) map[string]any {
	return map[string]any{
		"enabled":   cfg.Enabled,
		"cert_file": cfg.CertFile,
		"key_file":  cfg.KeyFile,
	}
}

func publicAIConfig(cfg config.AIConfig) map[string]any {
	return map[string]any{
		"provider":          cfg.Provider,
		"openai_api_key":    "",
		"openai_model":      cfg.OpenAIModel,
		"openai_base_url":   cfg.OpenAIBaseURL,
		"ollama_model":      cfg.OllamaModel,
		"ollama_base_url":   cfg.OllamaBaseURL,
		"confidence_cutoff": cfg.ConfidenceCutoff,
		"timeout_seconds":   int(cfg.Timeout / time.Second),
		"max_cache":         cfg.MaxCache,
	}
}

func publicEnrichmentConfig(cfg config.EnrichmentConfig) map[string]any {
	return map[string]any{
		"enabled":               cfg.Enabled,
		"ttl_hours":             int(cfg.TTL / time.Hour),
		"timeout_seconds":       int(cfg.Timeout / time.Second),
		"async_on_miss":         cfg.AsyncOnMiss,
		"foreground_timeout_ms": int(cfg.ForegroundTimeout / time.Millisecond),
	}
}

func publicDynamicRulesConfig(cfg config.DynamicRulesConfig) map[string]any {
	return map[string]any{
		"enabled":                    cfg.Enabled,
		"file":                       cfg.File,
		"google_crawler_url":         cfg.GoogleCrawlerURL,
		"bingbot_url":                cfg.BingbotURL,
		"tor_exit_url":               cfg.TorExitURL,
		"uptimerobot_ip_url":         cfg.UptimeRobotURL,
		"spamhaus_drop_v4_url":       cfg.SpamhausDropV4URL,
		"spamhaus_drop_v6_url":       cfg.SpamhausDropV6URL,
		"cloudflare_v4_url":          cfg.CloudflareV4URL,
		"cloudflare_v6_url":          cfg.CloudflareV6URL,
		"fastly_url":                 cfg.FastlyURL,
		"aws_ip_ranges_url":          cfg.AWSIPRangesURL,
		"google_cloud_ip_ranges_url": cfg.GoogleCloudIPRangesURL,
		"azure_service_tags_url":     cfg.AzureServiceTagsURL,
		"oracle_ip_ranges_url":       cfg.OracleIPRangesURL,
		"github_meta_url":            cfg.GitHubMetaURL,
		"mail_spf_domains":           cfg.MailSPFDomains,
		"ip2proxy": map[string]any{
			"enabled":       cfg.IP2Proxy.Enabled,
			"local_file":    cfg.IP2Proxy.LocalFile,
			"local_files":   cfg.IP2Proxy.LocalFiles,
			"download_url":  cfg.IP2Proxy.DownloadURL,
			"download_urls": cfg.IP2Proxy.DownloadURLs,
			"token":         "",
			"package":       cfg.IP2Proxy.Package,
			"packages":      cfg.IP2Proxy.Packages,
		},
	}
}

func publicIP2RegionConfig(cfg config.IP2RegionConfig) map[string]any {
	return map[string]any{
		"enabled":         cfg.Enabled,
		"include_default": cfg.IncludeDefault,
		"v4_file":         cfg.V4File,
		"v6_file":         cfg.V6File,
		"v4_version_url":  cfg.V4VersionURL,
		"v4_download_url": cfg.V4DownloadURL,
		"v6_version_url":  cfg.V6VersionURL,
		"v6_download_url": cfg.V6DownloadURL,
	}
}

func publicBGPConfig(cfg config.BGPConfig) map[string]any {
	return map[string]any{
		"enabled":                cfg.Enabled,
		"mode":                   cfg.Mode,
		"routeviews_enabled":     cfg.RouteViewsEnabled,
		"ripe_ris_enabled":       cfg.RIPERISEnabled,
		"collectors":             cfg.Collectors,
		"include_updates":        cfg.IncludeUpdates,
		"history_snapshots":      cfg.HistorySnapshots,
		"refresh_hours":          int(cfg.RefreshInterval / time.Hour),
		"max_parallel_downloads": cfg.MaxParallelDownloads,
		"max_parallel_parse":     cfg.MaxParallelParse,
		"keep_raw":               cfg.KeepRaw,
		"raw_retention_days":     cfg.RawRetentionDays,
		"summary_file":           cfg.SummaryFile,
		"routeviews_base_url":    cfg.RouteViewsBaseURL,
		"ripe_ris_base_url":      cfg.RIPERISBaseURL,
		"month":                  cfg.Month,
	}
}

func publicSourcesConfig(cfg config.Sources) map[string]any {
	return map[string]any{
		"caida_v4_log_url":       cfg.CAIDAv4LogURL,
		"caida_v4_base_url":      cfg.CAIDAv4BaseURL,
		"caida_v6_log_url":       cfg.CAIDAv6LogURL,
		"caida_v6_base_url":      cfg.CAIDAv6BaseURL,
		"rir_urls":               cfg.RIRURLs,
		"peeringdb_url":          cfg.PeeringDBURL,
		"peeringdb_ix_url":       cfg.PeeringDBIXURL,
		"peeringdb_netixlan_url": cfg.PeeringDBNetIXLANURL,
		"peeringdb_facility_url": cfg.PeeringDBFacilityURL,
		"peeringdb_netfac_url":   cfg.PeeringDBNetFacilityURL,
		"iana_rdap_urls":         cfg.IANARDAPURLs,
		"rpki_vrp_urls":          nonNilStrings(cfg.RPKIVRPURLs),
		"irr_route_urls":         nonNilStrings(cfg.IRRRouteURLs),
		"bgp_observation_urls":   nonNilStrings(cfg.BGPObservationURLs),
		"geofeed_urls":           nonNilStrings(cfg.GeofeedURLs),
	}
}

type adminConfigPatch struct {
	Addr                string `json:"addr"`
	DataDir             string `json:"data_dir"`
	RulesFile           string `json:"rules_file"`
	ASNRulesFile        string `json:"asn_rules_file"`
	UpdateIntervalHours *int   `json:"update_interval_hours"`
	HTTPTimeoutSeconds  *int   `json:"http_timeout_seconds"`
	TLS                 *struct {
		Enabled  *bool  `json:"enabled"`
		CertFile string `json:"cert_file"`
		KeyFile  string `json:"key_file"`
	} `json:"tls"`
	AI *struct {
		Provider         string   `json:"provider"`
		OpenAIAPIKey     string   `json:"openai_api_key"`
		OpenAIModel      string   `json:"openai_model"`
		OpenAIBaseURL    string   `json:"openai_base_url"`
		OllamaModel      string   `json:"ollama_model"`
		OllamaBaseURL    string   `json:"ollama_base_url"`
		ConfidenceCutoff *float64 `json:"confidence_cutoff"`
		TimeoutSeconds   *int     `json:"timeout_seconds"`
		MaxCache         *int     `json:"max_cache"`
	} `json:"ai"`
	Enrichment *struct {
		Enabled             *bool `json:"enabled"`
		TTLHours            *int  `json:"ttl_hours"`
		TimeoutSeconds      *int  `json:"timeout_seconds"`
		AsyncOnMiss         *bool `json:"async_on_miss"`
		ForegroundTimeoutMS *int  `json:"foreground_timeout_ms"`
	} `json:"enrichment"`
	History *struct {
		Snapshots *int `json:"snapshots"`
	} `json:"history"`
	DynamicRules *struct {
		Enabled                *bool    `json:"enabled"`
		File                   string   `json:"file"`
		GoogleCrawlerURL       string   `json:"google_crawler_url"`
		BingbotURL             string   `json:"bingbot_url"`
		TorExitURL             string   `json:"tor_exit_url"`
		UptimeRobotURL         string   `json:"uptimerobot_ip_url"`
		SpamhausDropV4URL      string   `json:"spamhaus_drop_v4_url"`
		SpamhausDropV6URL      string   `json:"spamhaus_drop_v6_url"`
		CloudflareV4URL        string   `json:"cloudflare_v4_url"`
		CloudflareV6URL        string   `json:"cloudflare_v6_url"`
		FastlyURL              string   `json:"fastly_url"`
		AWSIPRangesURL         string   `json:"aws_ip_ranges_url"`
		GoogleCloudIPRangesURL string   `json:"google_cloud_ip_ranges_url"`
		AzureServiceTagsURL    string   `json:"azure_service_tags_url"`
		OracleIPRangesURL      string   `json:"oracle_ip_ranges_url"`
		GitHubMetaURL          string   `json:"github_meta_url"`
		MailSPFDomains         []string `json:"mail_spf_domains"`
		IP2Proxy               *struct {
			Enabled      *bool    `json:"enabled"`
			LocalFile    string   `json:"local_file"`
			LocalFiles   []string `json:"local_files"`
			DownloadURL  string   `json:"download_url"`
			DownloadURLs []string `json:"download_urls"`
			Token        string   `json:"token"`
			Package      string   `json:"package"`
			Packages     []string `json:"packages"`
		} `json:"ip2proxy"`
	} `json:"dynamic_rules"`
	IP2Region *struct {
		Enabled        *bool  `json:"enabled"`
		IncludeDefault *bool  `json:"include_default"`
		V4File         string `json:"v4_file"`
		V6File         string `json:"v6_file"`
		V4VersionURL   string `json:"v4_version_url"`
		V4DownloadURL  string `json:"v4_download_url"`
		V6VersionURL   string `json:"v6_version_url"`
		V6DownloadURL  string `json:"v6_download_url"`
	} `json:"ip2region"`
	BGP *struct {
		Enabled              *bool    `json:"enabled"`
		Mode                 string   `json:"mode"`
		RouteViewsEnabled    *bool    `json:"routeviews_enabled"`
		RIPERISEnabled       *bool    `json:"ripe_ris_enabled"`
		Collectors           []string `json:"collectors"`
		IncludeUpdates       *bool    `json:"include_updates"`
		HistorySnapshots     *int     `json:"history_snapshots"`
		RefreshHours         *int     `json:"refresh_hours"`
		MaxParallelDownloads *int     `json:"max_parallel_downloads"`
		MaxParallelParse     *int     `json:"max_parallel_parse"`
		KeepRaw              *bool    `json:"keep_raw"`
		RawRetentionDays     *int     `json:"raw_retention_days"`
		SummaryFile          string   `json:"summary_file"`
		RouteViewsBaseURL    string   `json:"routeviews_base_url"`
		RIPERISBaseURL       string   `json:"ripe_ris_base_url"`
		Month                string   `json:"month"`
	} `json:"bgp"`
	Admin *struct {
		Enabled   *bool  `json:"enabled"`
		Path      string `json:"path"`
		Token     string `json:"token"`
		LocalOnly *bool  `json:"local_only"`
	} `json:"admin"`
	Sources *struct {
		CAIDAv4LogURL           string            `json:"caida_v4_log_url"`
		CAIDAv4BaseURL          string            `json:"caida_v4_base_url"`
		CAIDAv6LogURL           string            `json:"caida_v6_log_url"`
		CAIDAv6BaseURL          string            `json:"caida_v6_base_url"`
		RIRURLs                 map[string]string `json:"rir_urls"`
		PeeringDBURL            string            `json:"peeringdb_url"`
		PeeringDBIXURL          string            `json:"peeringdb_ix_url"`
		PeeringDBNetIXLANURL    string            `json:"peeringdb_netixlan_url"`
		PeeringDBFacilityURL    string            `json:"peeringdb_facility_url"`
		PeeringDBNetFacilityURL string            `json:"peeringdb_netfac_url"`
		IANARDAPURLs            map[string]string `json:"iana_rdap_urls"`
		RPKIVRPURLs             []string          `json:"rpki_vrp_urls"`
		IRRRouteURLs            []string          `json:"irr_route_urls"`
		BGPObservationURLs      []string          `json:"bgp_observation_urls"`
		GeofeedURLs             []string          `json:"geofeed_urls"`
	} `json:"sources"`
}

func applyAdminConfigPatch(cfg config.Config, body []byte) (config.Config, error) {
	var patch adminConfigPatch
	if err := json.Unmarshal(body, &patch); err != nil {
		return config.Config{}, err
	}
	if strings.TrimSpace(patch.Addr) != "" {
		cfg.Addr = strings.TrimSpace(patch.Addr)
	}
	if strings.TrimSpace(patch.DataDir) != "" {
		cfg.DataDir = strings.TrimSpace(patch.DataDir)
	}
	if strings.TrimSpace(patch.RulesFile) != "" {
		cfg.RulesFile = strings.TrimSpace(patch.RulesFile)
	}
	if strings.TrimSpace(patch.ASNRulesFile) != "" {
		cfg.ASNRulesFile = strings.TrimSpace(patch.ASNRulesFile)
	}
	if patch.UpdateIntervalHours != nil && *patch.UpdateIntervalHours >= 0 {
		cfg.UpdateInterval = time.Duration(*patch.UpdateIntervalHours) * time.Hour
	}
	if patch.HTTPTimeoutSeconds != nil && *patch.HTTPTimeoutSeconds > 0 {
		cfg.HTTPTimeout = time.Duration(*patch.HTTPTimeoutSeconds) * time.Second
	}
	if patch.TLS != nil {
		if patch.TLS.Enabled != nil {
			cfg.TLS.Enabled = *patch.TLS.Enabled
		}
		if strings.TrimSpace(patch.TLS.CertFile) != "" {
			cfg.TLS.CertFile = strings.TrimSpace(patch.TLS.CertFile)
		}
		if strings.TrimSpace(patch.TLS.KeyFile) != "" {
			cfg.TLS.KeyFile = strings.TrimSpace(patch.TLS.KeyFile)
		}
	}
	if patch.AI != nil {
		if strings.TrimSpace(patch.AI.Provider) != "" {
			cfg.AI.Provider = strings.TrimSpace(patch.AI.Provider)
		}
		if strings.TrimSpace(patch.AI.OpenAIAPIKey) != "" {
			cfg.AI.OpenAIAPIKey = strings.TrimSpace(patch.AI.OpenAIAPIKey)
		}
		if strings.TrimSpace(patch.AI.OpenAIModel) != "" {
			cfg.AI.OpenAIModel = strings.TrimSpace(patch.AI.OpenAIModel)
		}
		if strings.TrimSpace(patch.AI.OpenAIBaseURL) != "" {
			cfg.AI.OpenAIBaseURL = strings.TrimSpace(patch.AI.OpenAIBaseURL)
		}
		if strings.TrimSpace(patch.AI.OllamaModel) != "" {
			cfg.AI.OllamaModel = strings.TrimSpace(patch.AI.OllamaModel)
		}
		if strings.TrimSpace(patch.AI.OllamaBaseURL) != "" {
			cfg.AI.OllamaBaseURL = strings.TrimSpace(patch.AI.OllamaBaseURL)
		}
		if patch.AI.ConfidenceCutoff != nil && *patch.AI.ConfidenceCutoff > 0 && *patch.AI.ConfidenceCutoff <= 1 {
			cfg.AI.ConfidenceCutoff = *patch.AI.ConfidenceCutoff
		}
		if patch.AI.TimeoutSeconds != nil && *patch.AI.TimeoutSeconds > 0 {
			cfg.AI.Timeout = time.Duration(*patch.AI.TimeoutSeconds) * time.Second
		}
		if patch.AI.MaxCache != nil && *patch.AI.MaxCache > 0 {
			cfg.AI.MaxCache = *patch.AI.MaxCache
		}
	}
	if patch.Enrichment != nil {
		if patch.Enrichment.Enabled != nil {
			cfg.Enrichment.Enabled = *patch.Enrichment.Enabled
		}
		if patch.Enrichment.TTLHours != nil && *patch.Enrichment.TTLHours > 0 {
			cfg.Enrichment.TTL = time.Duration(*patch.Enrichment.TTLHours) * time.Hour
		}
		if patch.Enrichment.TimeoutSeconds != nil && *patch.Enrichment.TimeoutSeconds > 0 {
			cfg.Enrichment.Timeout = time.Duration(*patch.Enrichment.TimeoutSeconds) * time.Second
		}
		if patch.Enrichment.AsyncOnMiss != nil {
			cfg.Enrichment.AsyncOnMiss = *patch.Enrichment.AsyncOnMiss
		}
		if patch.Enrichment.ForegroundTimeoutMS != nil && *patch.Enrichment.ForegroundTimeoutMS >= 0 {
			cfg.Enrichment.ForegroundTimeout = time.Duration(*patch.Enrichment.ForegroundTimeoutMS) * time.Millisecond
		}
	}
	if patch.History != nil && patch.History.Snapshots != nil && *patch.History.Snapshots >= 0 {
		cfg.History.Snapshots = *patch.History.Snapshots
	}
	if patch.DynamicRules != nil {
		applyAdminDynamicRulesPatch(&cfg, patch.DynamicRules)
	}
	if patch.IP2Region != nil {
		if patch.IP2Region.Enabled != nil {
			cfg.IP2Region.Enabled = *patch.IP2Region.Enabled
		}
		if patch.IP2Region.IncludeDefault != nil {
			cfg.IP2Region.IncludeDefault = *patch.IP2Region.IncludeDefault
		}
		if strings.TrimSpace(patch.IP2Region.V4File) != "" {
			cfg.IP2Region.V4File = strings.TrimSpace(patch.IP2Region.V4File)
		}
		if strings.TrimSpace(patch.IP2Region.V6File) != "" {
			cfg.IP2Region.V6File = strings.TrimSpace(patch.IP2Region.V6File)
		}
		if strings.TrimSpace(patch.IP2Region.V4VersionURL) != "" {
			cfg.IP2Region.V4VersionURL = strings.TrimSpace(patch.IP2Region.V4VersionURL)
		}
		if strings.TrimSpace(patch.IP2Region.V4DownloadURL) != "" {
			cfg.IP2Region.V4DownloadURL = strings.TrimSpace(patch.IP2Region.V4DownloadURL)
		}
		if strings.TrimSpace(patch.IP2Region.V6VersionURL) != "" {
			cfg.IP2Region.V6VersionURL = strings.TrimSpace(patch.IP2Region.V6VersionURL)
		}
		if strings.TrimSpace(patch.IP2Region.V6DownloadURL) != "" {
			cfg.IP2Region.V6DownloadURL = strings.TrimSpace(patch.IP2Region.V6DownloadURL)
		}
	}
	if patch.BGP != nil {
		if patch.BGP.Enabled != nil {
			cfg.BGP.Enabled = *patch.BGP.Enabled
		}
		if patch.BGP.Mode != "" {
			cfg.BGP.Mode = patch.BGP.Mode
		}
		if patch.BGP.RouteViewsEnabled != nil {
			cfg.BGP.RouteViewsEnabled = *patch.BGP.RouteViewsEnabled
		}
		if patch.BGP.RIPERISEnabled != nil {
			cfg.BGP.RIPERISEnabled = *patch.BGP.RIPERISEnabled
		}
		if len(patch.BGP.Collectors) > 0 {
			cfg.BGP.Collectors = patch.BGP.Collectors
		}
		if patch.BGP.IncludeUpdates != nil {
			cfg.BGP.IncludeUpdates = *patch.BGP.IncludeUpdates
		}
		if patch.BGP.HistorySnapshots != nil && *patch.BGP.HistorySnapshots >= 0 {
			cfg.BGP.HistorySnapshots = *patch.BGP.HistorySnapshots
		}
		if patch.BGP.RefreshHours != nil && *patch.BGP.RefreshHours > 0 {
			cfg.BGP.RefreshInterval = time.Duration(*patch.BGP.RefreshHours) * time.Hour
		}
		if patch.BGP.MaxParallelDownloads != nil && *patch.BGP.MaxParallelDownloads > 0 {
			cfg.BGP.MaxParallelDownloads = *patch.BGP.MaxParallelDownloads
		}
		if patch.BGP.MaxParallelParse != nil && *patch.BGP.MaxParallelParse > 0 {
			cfg.BGP.MaxParallelParse = *patch.BGP.MaxParallelParse
		}
		if patch.BGP.KeepRaw != nil {
			cfg.BGP.KeepRaw = *patch.BGP.KeepRaw
		}
		if patch.BGP.RawRetentionDays != nil && *patch.BGP.RawRetentionDays >= 0 {
			cfg.BGP.RawRetentionDays = *patch.BGP.RawRetentionDays
		}
		if patch.BGP.SummaryFile != "" {
			cfg.BGP.SummaryFile = patch.BGP.SummaryFile
		}
		if patch.BGP.RouteViewsBaseURL != "" {
			cfg.BGP.RouteViewsBaseURL = patch.BGP.RouteViewsBaseURL
		}
		if patch.BGP.RIPERISBaseURL != "" {
			cfg.BGP.RIPERISBaseURL = patch.BGP.RIPERISBaseURL
		}
		if patch.BGP.Month != "" {
			cfg.BGP.Month = patch.BGP.Month
		}
	}
	if patch.Admin != nil {
		if patch.Admin.Enabled != nil {
			cfg.Admin.Enabled = *patch.Admin.Enabled
		}
		if strings.TrimSpace(patch.Admin.Path) != "" {
			cfg.Admin.Path = strings.TrimSpace(patch.Admin.Path)
		}
		if strings.TrimSpace(patch.Admin.Token) != "" {
			cfg.Admin.Token = strings.TrimSpace(patch.Admin.Token)
		}
		if patch.Admin.LocalOnly != nil {
			cfg.Admin.LocalOnly = *patch.Admin.LocalOnly
		}
	}
	if patch.Sources != nil {
		applyAdminSourcesPatch(&cfg, patch.Sources)
	}
	return cfg, nil
}

func applyAdminDynamicRulesPatch(cfg *config.Config, patch *struct {
	Enabled                *bool    `json:"enabled"`
	File                   string   `json:"file"`
	GoogleCrawlerURL       string   `json:"google_crawler_url"`
	BingbotURL             string   `json:"bingbot_url"`
	TorExitURL             string   `json:"tor_exit_url"`
	UptimeRobotURL         string   `json:"uptimerobot_ip_url"`
	SpamhausDropV4URL      string   `json:"spamhaus_drop_v4_url"`
	SpamhausDropV6URL      string   `json:"spamhaus_drop_v6_url"`
	CloudflareV4URL        string   `json:"cloudflare_v4_url"`
	CloudflareV6URL        string   `json:"cloudflare_v6_url"`
	FastlyURL              string   `json:"fastly_url"`
	AWSIPRangesURL         string   `json:"aws_ip_ranges_url"`
	GoogleCloudIPRangesURL string   `json:"google_cloud_ip_ranges_url"`
	AzureServiceTagsURL    string   `json:"azure_service_tags_url"`
	OracleIPRangesURL      string   `json:"oracle_ip_ranges_url"`
	GitHubMetaURL          string   `json:"github_meta_url"`
	MailSPFDomains         []string `json:"mail_spf_domains"`
	IP2Proxy               *struct {
		Enabled      *bool    `json:"enabled"`
		LocalFile    string   `json:"local_file"`
		LocalFiles   []string `json:"local_files"`
		DownloadURL  string   `json:"download_url"`
		DownloadURLs []string `json:"download_urls"`
		Token        string   `json:"token"`
		Package      string   `json:"package"`
		Packages     []string `json:"packages"`
	} `json:"ip2proxy"`
}) {
	if patch.Enabled != nil {
		cfg.DynamicRules.Enabled = *patch.Enabled
	}
	setString(&cfg.DynamicRules.File, patch.File)
	setString(&cfg.DynamicRules.GoogleCrawlerURL, patch.GoogleCrawlerURL)
	setString(&cfg.DynamicRules.BingbotURL, patch.BingbotURL)
	setString(&cfg.DynamicRules.TorExitURL, patch.TorExitURL)
	setString(&cfg.DynamicRules.UptimeRobotURL, patch.UptimeRobotURL)
	setString(&cfg.DynamicRules.SpamhausDropV4URL, patch.SpamhausDropV4URL)
	setString(&cfg.DynamicRules.SpamhausDropV6URL, patch.SpamhausDropV6URL)
	setString(&cfg.DynamicRules.CloudflareV4URL, patch.CloudflareV4URL)
	setString(&cfg.DynamicRules.CloudflareV6URL, patch.CloudflareV6URL)
	setString(&cfg.DynamicRules.FastlyURL, patch.FastlyURL)
	setString(&cfg.DynamicRules.AWSIPRangesURL, patch.AWSIPRangesURL)
	setString(&cfg.DynamicRules.GoogleCloudIPRangesURL, patch.GoogleCloudIPRangesURL)
	setString(&cfg.DynamicRules.AzureServiceTagsURL, patch.AzureServiceTagsURL)
	setString(&cfg.DynamicRules.OracleIPRangesURL, patch.OracleIPRangesURL)
	setString(&cfg.DynamicRules.GitHubMetaURL, patch.GitHubMetaURL)
	if len(patch.MailSPFDomains) > 0 {
		cfg.DynamicRules.MailSPFDomains = patch.MailSPFDomains
	}
	if patch.IP2Proxy == nil {
		return
	}
	if patch.IP2Proxy.Enabled != nil {
		cfg.DynamicRules.IP2Proxy.Enabled = *patch.IP2Proxy.Enabled
	}
	setString(&cfg.DynamicRules.IP2Proxy.LocalFile, patch.IP2Proxy.LocalFile)
	if len(patch.IP2Proxy.LocalFiles) > 0 {
		cfg.DynamicRules.IP2Proxy.LocalFiles = patch.IP2Proxy.LocalFiles
	}
	setString(&cfg.DynamicRules.IP2Proxy.DownloadURL, patch.IP2Proxy.DownloadURL)
	if len(patch.IP2Proxy.DownloadURLs) > 0 {
		cfg.DynamicRules.IP2Proxy.DownloadURLs = patch.IP2Proxy.DownloadURLs
	}
	setString(&cfg.DynamicRules.IP2Proxy.Token, patch.IP2Proxy.Token)
	setString(&cfg.DynamicRules.IP2Proxy.Package, patch.IP2Proxy.Package)
	if len(patch.IP2Proxy.Packages) > 0 {
		cfg.DynamicRules.IP2Proxy.Packages = patch.IP2Proxy.Packages
	}
}

func applyAdminSourcesPatch(cfg *config.Config, patch *struct {
	CAIDAv4LogURL           string            `json:"caida_v4_log_url"`
	CAIDAv4BaseURL          string            `json:"caida_v4_base_url"`
	CAIDAv6LogURL           string            `json:"caida_v6_log_url"`
	CAIDAv6BaseURL          string            `json:"caida_v6_base_url"`
	RIRURLs                 map[string]string `json:"rir_urls"`
	PeeringDBURL            string            `json:"peeringdb_url"`
	PeeringDBIXURL          string            `json:"peeringdb_ix_url"`
	PeeringDBNetIXLANURL    string            `json:"peeringdb_netixlan_url"`
	PeeringDBFacilityURL    string            `json:"peeringdb_facility_url"`
	PeeringDBNetFacilityURL string            `json:"peeringdb_netfac_url"`
	IANARDAPURLs            map[string]string `json:"iana_rdap_urls"`
	RPKIVRPURLs             []string          `json:"rpki_vrp_urls"`
	IRRRouteURLs            []string          `json:"irr_route_urls"`
	BGPObservationURLs      []string          `json:"bgp_observation_urls"`
	GeofeedURLs             []string          `json:"geofeed_urls"`
}) {
	setString(&cfg.Sources.CAIDAv4LogURL, patch.CAIDAv4LogURL)
	setString(&cfg.Sources.CAIDAv4BaseURL, patch.CAIDAv4BaseURL)
	setString(&cfg.Sources.CAIDAv6LogURL, patch.CAIDAv6LogURL)
	setString(&cfg.Sources.CAIDAv6BaseURL, patch.CAIDAv6BaseURL)
	mergeStringMap(&cfg.Sources.RIRURLs, patch.RIRURLs)
	setString(&cfg.Sources.PeeringDBURL, patch.PeeringDBURL)
	setString(&cfg.Sources.PeeringDBIXURL, patch.PeeringDBIXURL)
	setString(&cfg.Sources.PeeringDBNetIXLANURL, patch.PeeringDBNetIXLANURL)
	setString(&cfg.Sources.PeeringDBFacilityURL, patch.PeeringDBFacilityURL)
	setString(&cfg.Sources.PeeringDBNetFacilityURL, patch.PeeringDBNetFacilityURL)
	mergeStringMap(&cfg.Sources.IANARDAPURLs, patch.IANARDAPURLs)
	if patch.RPKIVRPURLs != nil {
		cfg.Sources.RPKIVRPURLs = cleanAdminStrings(patch.RPKIVRPURLs)
	}
	if patch.IRRRouteURLs != nil {
		cfg.Sources.IRRRouteURLs = cleanAdminStrings(patch.IRRRouteURLs)
	}
	if patch.BGPObservationURLs != nil {
		cfg.Sources.BGPObservationURLs = cleanAdminStrings(patch.BGPObservationURLs)
	}
	if patch.GeofeedURLs != nil {
		cfg.Sources.GeofeedURLs = cleanAdminStrings(patch.GeofeedURLs)
	}
}

func setString(target *string, value string) {
	if strings.TrimSpace(value) != "" {
		*target = strings.TrimSpace(value)
	}
}

func mergeStringMap(target *map[string]string, source map[string]string) {
	if len(source) == 0 {
		return
	}
	if *target == nil {
		*target = map[string]string{}
	}
	for key, value := range source {
		if strings.TrimSpace(key) != "" && strings.TrimSpace(value) != "" {
			(*target)[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
}

func cleanAdminStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

func (s *Server) favicon(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) lookupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("query"))
	includeLocation := s.includeLocationDefault
	if r.URL.Query().Has("include_location") {
		includeLocation = boolQuery(r.URL.Query().Get("include_location"))
	}
	writeJSON(w, http.StatusOK, s.lookup.LookupWithOptions(r.Context(), query, lookup.LookupOptions{
		IncludeLocation:  includeLocation,
		OnlineEnrichment: parseOnlineEnrichment(r.URL.Query().Get("online_enrichment")),
	}))
}

func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) statusHandler(w http.ResponseWriter, r *http.Request) {
	if s.manager == nil {
		writeJSON(w, http.StatusOK, map[string]any{"loaded": true})
		return
	}
	writeJSON(w, http.StatusOK, s.manager.Status())
}

func (s *Server) updateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.manager == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "update manager is not configured"})
		return
	}

	if r.URL.Query().Get("wait") == "1" {
		if err := s.manager.Refresh(r.Context()); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": s.manager.Status()})
		return
	}

	go func() {
		_ = s.manager.Refresh(context.Background())
	}()
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "message": "update started", "status": s.manager.Status()})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func boolQuery(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func parseOnlineEnrichment(value string) lookup.OnlineEnrichmentMode {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "wait":
		return lookup.OnlineEnrichmentWait
	case "off":
		return lookup.OnlineEnrichmentOff
	default:
		return lookup.OnlineEnrichmentFast
	}
}

const indexHTML = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>IP / ASN 场景查询</title>
  <style>
    :root { color-scheme: light; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    body { margin: 0; background: #f4f6f8; color: #1d2733; }
    main { max-width: 980px; margin: 0 auto; padding: 32px 18px; }
    h1 { font-size: 28px; margin: 0 0 18px; letter-spacing: 0; }
    form { display: flex; gap: 10px; margin-bottom: 18px; }
    input { flex: 1; min-width: 0; padding: 12px 14px; border: 1px solid #c9d1d9; border-radius: 8px; font-size: 16px; background: #fff; }
    .check { display: flex; align-items: center; gap: 6px; white-space: nowrap; color: #334155; font-size: 14px; }
    .check input { flex: none; width: 16px; height: 16px; padding: 0; }
    button { padding: 0 16px; border: 0; border-radius: 8px; background: #1b5f9e; color: #fff; font-size: 15px; cursor: pointer; }
    button.secondary { background: #4b5563; }
    .grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
    .panel { background: #fff; border: 1px solid #d8dee6; border-radius: 8px; padding: 14px; }
    .label { color: #65758b; font-size: 13px; margin-bottom: 4px; }
    .value { font-size: 18px; overflow-wrap: anywhere; }
    .wide { grid-column: 1 / -1; }
    .meta-list { display: grid; grid-template-columns: 96px minmax(0, 1fr); gap: 8px 12px; margin: 8px 0 0; }
    .meta-list dt { color: #65758b; font-size: 13px; }
    .meta-list dd { margin: 0; overflow-wrap: anywhere; font-size: 16px; }
    ul { margin: 8px 0 0; padding-left: 20px; }
    pre { white-space: pre-wrap; overflow-wrap: anywhere; background: #111827; color: #e5e7eb; padding: 12px; border-radius: 8px; }
    @media (max-width: 720px) { form { flex-direction: column; } button { height: 42px; } .grid { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
<main>
  <h1>IP / ASN 场景查询</h1>
  <form id="lookup-form">
    <input id="query" placeholder="输入 IP 或 ASN，例如 8.8.8.8 或 AS15169" autocomplete="off">
    <label class="check"><input id="include-location" type="checkbox">所在地</label>
    <label class="check">在线增强
      <select id="online-enrichment">
        <option value="fast">快速</option>
        <option value="wait">等待联网结果</option>
        <option value="off">关闭</option>
      </select>
    </label>
    <button type="submit">查询</button>
    <button class="secondary" type="button" id="refresh">更新库</button>
  </form>
  <section id="result" class="grid"></section>
</main>
<script>
const form = document.getElementById('lookup-form');
const query = document.getElementById('query');
const result = document.getElementById('result');
const refresh = document.getElementById('refresh');
const includeLocation = document.getElementById('include-location');
const onlineEnrichment = document.getElementById('online-enrichment');

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  await lookup(query.value.trim());
});

refresh.addEventListener('click', async () => {
  result.innerHTML = '<div class="panel wide">数据库更新已开始。</div>';
  await fetch('/api/db/update', { method: 'POST' });
});

async function lookup(value) {
  result.innerHTML = '<div class="panel wide">' + (onlineEnrichment.value === 'wait' ? '联网增强查询中...' : '查询中...') + '</div>';
  const params = new URLSearchParams({ query: value, online_enrichment: onlineEnrichment.value });
  if (includeLocation.checked) params.set('include_location', '1');
  const response = await fetch('/api/lookup?' + params.toString());
  const data = await response.json();
  if (!data.ok) {
    result.innerHTML = '<div class="panel wide"><div class="label">错误</div><div class="value">' + escapeHTML(data.error || '查询失败') + '</div></div>';
    return;
  }
  const prefixes = (data.prefixes || []).slice(0, 20).map(x => '<li>' + escapeHTML(x) + '</li>').join('');
  const evidence = (data.evidence || []).map(x => '<li>' + escapeHTML(x) + '</li>').join('');
  const history = (data.history || []).map(x => '<li>AS' + escapeHTML(x.asn || '-') + ' / ' + escapeHTML(x.prefix || '-') + ' / ' + escapeHTML(x.label || '-') + '</li>').join('');
  const inferredSource = data.inferred_source ? '（' + data.inferred_source + '）' : '';
  const inferred = data.inferred_scene ? escapeHTML(data.inferred_scene + ' ' + (data.inferred_scene_name || '') + ' ' + Math.round((data.inferred_confidence || 0) * 100) + '%' + inferredSource) : '-';
  const bgpPath = data.registration && data.registration.bgp_path ? data.registration.bgp_path : null;
  const panels = [
    '<div class="panel"><div class="label">场景</div><div class="value">' + escapeHTML(data.scene || '') + ' ' + escapeHTML(data.scene_name || '') + '</div></div>',
    '<div class="panel"><div class="label">置信度</div><div class="value">' + Math.round((data.confidence || 0) * 100) + '%</div></div>',
    '<div class="panel"><div class="label">推断用途</div><div class="value">' + inferred + '</div></div>',
    '<div class="panel"><div class="label">ASN</div><div class="value">' + (data.asn ? 'AS' + data.asn : '-') + '</div></div>',
    '<div class="panel"><div class="label">公司</div><div class="value">' + escapeHTML(data.company || '-') + '</div></div>',
    '<div class="panel"><div class="label">网络名</div><div class="value">' + escapeHTML(data.netname || '-') + '</div></div>',
    '<div class="panel"><div class="label">国家 / 注册局</div><div class="value">' + escapeHTML([data.country, data.registry].filter(Boolean).join(' / ') || '-') + '</div></div>',
    '<div class="panel"><div class="label">匹配网段</div><div class="value">' + escapeHTML(data.matched_prefix || '-') + '</div></div>',
    '<div class="panel"><div class="label">路由状态</div><div class="value">' + escapeHTML(data.routing_status || 'announced') + '</div></div>',
    '<div class="panel"><div class="label">分配状态</div><div class="value">' + escapeHTML(data.allocation_status || '-') + '</div></div>',
    '<div class="panel wide"><div class="label">历史 BGP</div><ul>' + (history || '<li>-</li>') + '</ul></div>',
    '<div class="panel wide"><div class="label">判断依据</div><ul>' + (evidence || '<li>-</li>') + '</ul></div>',
    '<div class="panel wide"><div class="label">相关网段</div><ul>' + (prefixes || '<li>-</li>') + '</ul></div>'
  ];
  if (data.location) {
    panels.splice(10, 0, '<div class="panel wide"><div class="label">IP 所在地</div><dl class="meta-list">' + renderLocation(data.location) + '</dl></div>');
  }
  if (data.warnings && data.warnings.length) {
    panels.splice(10, 0, '<div class="panel wide"><div class="label">风险提示</div><ul>' + data.warnings.map(x => '<li>' + escapeHTML(x) + '</li>').join('') + '</ul></div>');
  }
  if (data.source_votes && data.source_votes.length) {
    panels.splice(10, 0, '<div class="panel wide"><div class="label">多源投票</div><ul>' + renderSourceVotes(data.source_votes) + '</ul></div>');
  }
  if (data.routing_security) {
    panels.splice(10, 0, '<div class="panel wide"><div class="label">路由安全</div><dl class="meta-list">' + renderRoutingSecurity(data.routing_security) + '</dl></div>');
  }
  if (data.data_quality) {
    panels.splice(10, 0, '<div class="panel wide"><div class="label">数据质量</div><dl class="meta-list">' + renderDataQuality(data.data_quality) + '</dl></div>');
  }
  if (data.registration && (data.registration.refresh_queued || data.registration.refresh_in_progress)) {
    panels.splice(10, 0, '<div class="panel wide"><div class="label">在线增强状态</div><div class="value">' + (data.registration.refresh_queued ? '已后台刷新，稍后重新查询可查看 RDAP / WHOIS / BGP 补充信息' : '同一 IP 正在后台刷新') + '</div></div>');
  }
  if (data.geo_consistency) {
    panels.splice(10, 0, '<div class="panel wide"><div class="label">地理一致性分析</div><dl class="meta-list">' + renderGeoConsistency(data.geo_consistency) + '</dl></div>');
  }
  if (data.egress) {
    panels.splice(10, 0, '<div class="panel wide"><div class="label">机房 / 出口信息</div><dl class="meta-list">' + renderEgress(data.egress) + '</dl></div>');
  }
  if (bgpPath) {
    panels.splice(11, 0, '<div class="panel wide"><div class="label">AS Path 多点观察</div><dl class="meta-list">' + renderBGPPath(bgpPath) + '</dl></div>');
  }
  result.innerHTML = panels.join('');
}

function renderLocation(location) {
  const position = [location.country, location.province, location.city, location.isp].filter(Boolean).join(' / ');
  return [
    ['位置', position],
    ['国家', location.country],
    ['省/州', location.province],
    ['城市', location.city],
    ['运营商', location.isp],
    ['国家码', location.country_code],
    ['ASN', location.asn]
  ].map(([label, value]) => '<dt>' + escapeHTML(label) + '</dt><dd>' + escapeHTML(value || '-') + '</dd>').join('');
}

function renderGeoConsistency(info) {
  return [
    ['结论', info.summary || (info.conflict ? '存在差异' : '一致')],
    ['注册地', info.registered_country],
    ['宣告地', info.announced_country],
    ['所在地', info.location_country],
    ['BGP路径', info.bgp_path_hint],
    ['置信度', info.confidence ? Math.round(info.confidence * 100) + '%' : '-']
  ].map(([label, value]) => '<dt>' + escapeHTML(label) + '</dt><dd>' + escapeHTML(value || '-') + '</dd>').join('');
}

function renderDataQuality(info) {
  return [
    ['等级', info.level || '-'],
    ['评分', typeof info.score === 'number' ? Math.round(info.score * 100) + '%' : '-'],
    ['一致性', info.source_agreement || '-'],
    ['新鲜度', info.freshness || '-'],
    ['信号', (info.signals || []).join(' / ')]
  ].map(([label, value]) => '<dt>' + escapeHTML(label) + '</dt><dd>' + escapeHTML(value || '-') + '</dd>').join('');
}

function renderRoutingSecurity(info) {
  return [
    ['RPKI', info.rpki || '-'],
    ['RPKI说明', info.rpki_reason || '-'],
    ['ROA前缀', info.rpki_matched_prefix || '-'],
    ['IRR匹配', info.irr_matched ? '是' : '否'],
    ['IRR冲突', info.irr_conflict ? '是' : '否'],
    ['IRR Origin', (info.irr_origin_asns || []).map(asn => 'AS' + asn).join(' / ')],
    ['MOAS', info.moas ? '是' : '否'],
    ['疑似异常', info.route_leak_suspected ? '是' : '否'],
    ['BGP可见度', info.prefix_visibility || '-'],
    ['Origin一致率', typeof info.origin_agreement === 'number' ? Math.round(info.origin_agreement * 100) + '%' : '-']
  ].map(([label, value]) => '<dt>' + escapeHTML(label) + '</dt><dd>' + escapeHTML(value || '-') + '</dd>').join('');
}

function renderSourceVotes(votes) {
  return votes.map(vote => {
    const confidence = vote.confidence ? ' ' + Math.round(vote.confidence * 100) + '%' : '';
    const detail = vote.detail ? ' - ' + vote.detail : '';
    return '<li>' + escapeHTML(vote.source + ': ' + vote.scene + ' ' + (vote.scene_name || '') + confidence + detail) + '</li>';
  }).join('');
}

function renderBGPPath(path) {
  const upstreams = (path.upstream_asns || []).slice(0, 5).map(x => 'AS' + x.asn + ' x' + x.count).join(' / ');
  const locations = (path.collector_locations || []).slice(0, 5).join(' / ');
  const samples = (path.paths || []).slice(0, 3).map(x => (x.rrc || '-') + ': ' + (x.as_path || []).map(asn => 'AS' + asn).join(' ')).join('； ');
  return [
    ['来源', path.source || 'ripe_ris'],
    ['观察点', path.observation_count],
    ['前缀', path.prefix],
    ['Origin', path.origin_asn ? 'AS' + path.origin_asn : ''],
    ['主上游', path.dominant_upstream ? 'AS' + path.dominant_upstream : ''],
    ['上游统计', upstreams],
    ['采集点', locations],
    ['样本路径', samples]
  ].map(([label, value]) => '<dt>' + escapeHTML(label) + '</dt><dd>' + escapeHTML(value || '-') + '</dd>').join('');
}

function renderEgress(info) {
  return [
    ['结论', info.summary],
    ['类型', info.type],
    ['Origin', info.origin_asn ? 'AS' + info.origin_asn : ''],
    ['主上游', info.dominant_upstream ? 'AS' + info.dominant_upstream + (info.upstream_name ? ' ' + info.upstream_name : '') : ''],
    ['Presence来源', info.presence_asn ? 'AS' + info.presence_asn + (info.presence_name ? ' ' + info.presence_name : '') : ''],
    ['疑似地点', [info.likely_city, info.likely_country].filter(Boolean).join(' / ')],
    ['IXP', (info.ixps || []).join(' / ')],
    ['机房', (info.facilities || []).join(' / ')],
    ['置信度', info.confidence ? Math.round(info.confidence * 100) + '%' : '-']
  ].map(([label, value]) => '<dt>' + escapeHTML(label) + '</dt><dd>' + escapeHTML(value || '-') + '</dd>').join('');
}

function escapeHTML(value) {
  return String(value).replace(/[&<>"']/g, ch => ({'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'}[ch]));
}
</script>
</body>
</html>`

const adminHTML = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>IPASN 配置管理</title>
  <style>
    :root { color-scheme: light; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    body { margin: 0; background: #f4f6f8; color: #1d2733; font-size: 14px; }
    main { max-width: 1240px; margin: 0 auto; padding: 28px 18px 48px; }
    h1 { margin: 0 0 16px; font-size: 26px; letter-spacing: 0; }
    h2 { margin: 24px 0 10px; font-size: 18px; letter-spacing: 0; }
    h3 { margin: 18px 0 8px; font-size: 15px; letter-spacing: 0; }
    .toolbar { display: flex; gap: 10px; margin-bottom: 16px; flex-wrap: wrap; align-items: center; }
    button { height: 38px; padding: 0 14px; border: 0; border-radius: 8px; background: #1b5f9e; color: #fff; cursor: pointer; }
    button.secondary { background: #4b5563; }
    button:disabled { opacity: .6; cursor: not-allowed; }
    .hint { color: #667085; }
    .surface { background: #fff; border: 1px solid #d8dee6; border-radius: 8px; padding: 14px; margin-bottom: 14px; }
    .status-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; }
    .metric { border: 1px solid #e2e8f0; border-radius: 8px; padding: 10px; background: #fafbfc; }
    .metric .label { color: #667085; font-size: 12px; margin-bottom: 4px; }
    .metric .value { font-size: 16px; overflow-wrap: anywhere; }
    .progress-head { display: flex; justify-content: space-between; gap: 12px; align-items: center; margin-bottom: 8px; }
    .progress-track { height: 12px; background: #e5eaf0; border-radius: 999px; overflow: hidden; }
    .progress-bar { height: 100%; width: 0%; background: #1b5f9e; transition: width .25s ease; }
    .progress-current { margin-top: 8px; color: #334155; overflow-wrap: anywhere; }
    .progress-steps { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 8px; margin: 12px 0 0; padding: 0; list-style: none; }
    .progress-steps li { border: 1px solid #d8dee6; border-radius: 8px; padding: 8px; background: #fafbfc; min-height: 70px; }
    .step-name { font-weight: 600; margin-bottom: 4px; }
    .step-status { color: #667085; font-size: 12px; }
    .step-detail { color: #334155; font-size: 12px; margin-top: 4px; overflow-wrap: anywhere; }
    .step-running { border-color: #1b5f9e; background: #eef6ff; }
    .step-done { border-color: #16a34a; background: #f0fdf4; }
    .step-failed { border-color: #dc2626; background: #fff1f2; }
    .config-section { margin-top: 18px; }
    .config-table { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #d8dee6; border-radius: 8px; overflow: hidden; }
    .config-table th, .config-table td { border-bottom: 1px solid #e5eaf0; padding: 9px 10px; vertical-align: top; text-align: left; }
    .config-table th { width: 220px; background: #f8fafc; color: #334155; font-weight: 600; }
    .config-table tr:last-child th, .config-table tr:last-child td { border-bottom: 0; }
    input, select, textarea { width: 100%; box-sizing: border-box; border: 1px solid #c9d1d9; border-radius: 6px; padding: 8px 9px; font: inherit; background: #fff; color: #1d2733; }
    input[type="checkbox"] { width: 18px; height: 18px; padding: 0; }
    textarea { min-height: 74px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; }
    .field-help { margin-top: 6px; color: #667085; font-size: 12px; line-height: 1.45; }
    .optional-source { color: #475569; font-size: 12px; font-weight: 500; margin-left: 6px; }
    details { margin-top: 14px; }
    summary { cursor: pointer; font-weight: 600; color: #1b5f9e; }
    pre { white-space: pre-wrap; overflow-wrap: anywhere; background: #111827; color: #e5e7eb; padding: 12px; border-radius: 8px; max-height: 260px; overflow: auto; }
    @media (max-width: 900px) { .status-grid, .progress-steps { grid-template-columns: 1fr; } .config-table th { width: 150px; } }
  </style>
</head>
<body>
<main>
  <h1>配置管理</h1>
  <div class="toolbar">
    <button id="load">读取配置</button>
    <button id="save">保存配置</button>
    <button class="secondary" id="update">更新离线库</button>
    <span class="hint" id="toolbar-hint"></span>
  </div>

  <section id="update-progress" class="surface">
    <div class="progress-head">
      <strong>更新进度</strong>
      <span id="progress-percent">0%</span>
    </div>
    <div class="progress-track"><div id="progress-bar" class="progress-bar"></div></div>
    <div id="progress-current" class="progress-current">未开始</div>
    <ol id="progress-steps" class="progress-steps"></ol>
  </section>

  <section class="surface">
    <h2>数据库状态</h2>
    <div id="db-status" class="status-grid"></div>
  </section>

  <form id="config-form">
    <section class="config-section">
      <h2>基础配置</h2>
      <table class="config-table">
        <tbody>
          <tr><th>监听地址</th><td><input id="cfg-addr" data-path="addr" autocomplete="off"></td></tr>
          <tr><th>数据目录</th><td><input id="cfg-data-dir" data-path="data_dir" autocomplete="off"></td></tr>
          <tr><th>服务规则文件</th><td><input id="cfg-rules-file" data-path="rules_file" autocomplete="off"></td></tr>
          <tr><th>ASN 规则文件</th><td><input id="cfg-asn-rules-file" data-path="asn_rules_file" autocomplete="off"></td></tr>
          <tr><th>自动更新间隔(小时)</th><td><input id="cfg-update-interval-hours" data-path="update_interval_hours" data-type="number" type="number" min="0"></td></tr>
          <tr><th>HTTP 超时(秒)</th><td><input id="cfg-http-timeout-seconds" data-path="http_timeout_seconds" data-type="number" type="number" min="1"></td></tr>
        </tbody>
      </table>
    </section>

    <section class="config-section">
      <h2>后台与 SSL</h2>
      <table class="config-table">
        <tbody>
          <tr><th>后台启用</th><td><input id="cfg-admin-enabled" data-path="admin.enabled" type="checkbox"></td></tr>
          <tr><th>后台路径</th><td><input id="cfg-admin-path" data-path="admin.path" autocomplete="off"></td></tr>
          <tr><th>仅允许本机访问</th><td><input id="cfg-admin-local-only" data-path="admin.local_only" type="checkbox"></td></tr>
          <tr><th>后台 Token(留空不修改)</th><td><input id="cfg-admin-token" data-path="admin.token" data-secret="true" type="password" autocomplete="new-password"></td></tr>
          <tr><th>启用 HTTPS</th><td><input id="cfg-tls-enabled" data-path="tls.enabled" type="checkbox"></td></tr>
          <tr><th>证书文件</th><td><input id="cfg-tls-cert-file" data-path="tls.cert_file" autocomplete="off"></td></tr>
          <tr><th>私钥文件</th><td><input id="cfg-tls-key-file" data-path="tls.key_file" autocomplete="off"></td></tr>
        </tbody>
      </table>
    </section>

    <section class="config-section">
      <h2>AI 与在线增强</h2>
      <table class="config-table">
        <tbody>
          <tr><th>AI Provider</th><td><select id="cfg-ai-provider" data-path="ai.provider"><option value="auto">auto</option><option value="off">off</option><option value="openai">openai</option><option value="ollama">ollama</option></select></td></tr>
          <tr><th>OpenAI API Key(留空不修改)</th><td><input id="cfg-ai-openai-api-key" data-path="ai.openai_api_key" data-secret="true" type="password" autocomplete="new-password"></td></tr>
          <tr><th>OpenAI 模型</th><td><input id="cfg-ai-openai-model" data-path="ai.openai_model"></td></tr>
          <tr><th>OpenAI Base URL</th><td><input id="cfg-ai-openai-base-url" data-path="ai.openai_base_url"></td></tr>
          <tr><th>Ollama 模型</th><td><input id="cfg-ai-ollama-model" data-path="ai.ollama_model"></td></tr>
          <tr><th>Ollama Base URL</th><td><input id="cfg-ai-ollama-base-url" data-path="ai.ollama_base_url"></td></tr>
          <tr><th>AI 低置信度阈值</th><td><input id="cfg-ai-confidence-cutoff" data-path="ai.confidence_cutoff" data-type="float" type="number" min="0" max="1" step="0.01"></td></tr>
          <tr><th>AI 超时(秒)</th><td><input id="cfg-ai-timeout-seconds" data-path="ai.timeout_seconds" data-type="number" type="number" min="1"></td></tr>
          <tr><th>AI 缓存数量</th><td><input id="cfg-ai-max-cache" data-path="ai.max_cache" data-type="number" type="number" min="1"></td></tr>
          <tr><th>在线增强启用</th><td><input id="cfg-enrichment-enabled" data-path="enrichment.enabled" type="checkbox"></td></tr>
          <tr><th>在线增强 TTL(小时)</th><td><input id="cfg-enrichment-ttl-hours" data-path="enrichment.ttl_hours" data-type="number" type="number" min="1"></td></tr>
          <tr><th>在线增强超时(秒)</th><td><input id="cfg-enrichment-timeout-seconds" data-path="enrichment.timeout_seconds" data-type="number" type="number" min="1"></td></tr>
          <tr><th>未命中时后台刷新</th><td><input id="cfg-enrichment-async-on-miss" data-path="enrichment.async_on_miss" type="checkbox"></td></tr>
          <tr><th>前台等待时间(ms)</th><td><input id="cfg-enrichment-foreground-timeout-ms" data-path="enrichment.foreground_timeout_ms" data-type="number" type="number" min="0"></td></tr>
        </tbody>
      </table>
    </section>

    <section class="config-section">
      <h2>IP 所在地库</h2>
      <table class="config-table">
        <tbody>
          <tr><th>启用 ip2region</th><td><input id="cfg-ip2region-enabled" data-path="ip2region.enabled" type="checkbox"></td></tr>
          <tr><th>默认输出所在地</th><td><input id="cfg-ip2region-include-default" data-path="ip2region.include_default" type="checkbox"></td></tr>
          <tr><th>IPv4 XDB 文件</th><td><input id="cfg-ip2region-v4-file" data-path="ip2region.v4_file"></td></tr>
          <tr><th>IPv6 XDB 文件</th><td><input id="cfg-ip2region-v6-file" data-path="ip2region.v6_file"></td></tr>
          <tr><th>IPv4 版本 API</th><td><input id="cfg-ip2region-v4-version-url" data-path="ip2region.v4_version_url"></td></tr>
          <tr><th>IPv4 下载地址</th><td><input id="cfg-ip2region-v4-download-url" data-path="ip2region.v4_download_url"></td></tr>
          <tr><th>IPv6 版本 API</th><td><input id="cfg-ip2region-v6-version-url" data-path="ip2region.v6_version_url"></td></tr>
          <tr><th>IPv6 下载地址</th><td><input id="cfg-ip2region-v6-download-url" data-path="ip2region.v6_download_url"></td></tr>
        </tbody>
      </table>
    </section>

    <section class="config-section">
      <h2>全量 BGP</h2>
      <table class="config-table">
        <tbody>
          <tr><th>启用 BGP</th><td><input id="cfg-bgp-enabled" data-path="bgp.enabled" type="checkbox"></td></tr>
          <tr><th>模式</th><td><select id="cfg-bgp-mode" data-path="bgp.mode"><option value="full">full</option><option value="off">off</option></select></td></tr>
          <tr><th>RouteViews</th><td><input id="cfg-bgp-routeviews-enabled" data-path="bgp.routeviews_enabled" type="checkbox"></td></tr>
          <tr><th>RIPE RIS</th><td><input id="cfg-bgp-ripe-ris-enabled" data-path="bgp.ripe_ris_enabled" type="checkbox"></td></tr>
          <tr><th>Collectors</th><td><textarea id="cfg-bgp-collectors" data-path="bgp.collectors" data-type="list"></textarea></td></tr>
          <tr><th>Include Updates</th><td><input id="cfg-bgp-include-updates" data-path="bgp.include_updates" type="checkbox"></td></tr>
          <tr><th>历史快照数</th><td><input id="cfg-bgp-history-snapshots" data-path="bgp.history_snapshots" data-type="number" type="number" min="0"></td></tr>
          <tr><th>刷新间隔(小时)</th><td><input id="cfg-bgp-refresh-hours" data-path="bgp.refresh_hours" data-type="number" type="number" min="1"></td></tr>
          <tr><th>并发下载数</th><td><input id="cfg-bgp-max-parallel-downloads" data-path="bgp.max_parallel_downloads" data-type="number" type="number" min="1"></td></tr>
          <tr><th>并发解析数</th><td><input id="cfg-bgp-max-parallel-parse" data-path="bgp.max_parallel_parse" data-type="number" type="number" min="1"></td></tr>
          <tr><th>保留原始 MRT</th><td><input id="cfg-bgp-keep-raw" data-path="bgp.keep_raw" type="checkbox"></td></tr>
          <tr><th>原始文件保留天数</th><td><input id="cfg-bgp-raw-retention-days" data-path="bgp.raw_retention_days" data-type="number" type="number" min="0"></td></tr>
          <tr><th>汇总文件</th><td><input id="cfg-bgp-summary-file" data-path="bgp.summary_file"></td></tr>
          <tr><th>RouteViews Base URL</th><td><input id="cfg-bgp-routeviews-base-url" data-path="bgp.routeviews_base_url"></td></tr>
          <tr><th>RIPE RIS Base URL</th><td><input id="cfg-bgp-ripe-ris-base-url" data-path="bgp.ripe_ris_base_url"></td></tr>
          <tr><th>指定月份</th><td><input id="cfg-bgp-month" data-path="bgp.month" placeholder="例如 2026.06，留空自动选择"></td></tr>
        </tbody>
      </table>
    </section>

    <details class="config-section" open>
      <summary>动态规则与商业补充库</summary>
      <table class="config-table">
        <tbody>
          <tr><th>启用动态规则</th><td><input id="cfg-dynamic-rules-enabled" data-path="dynamic_rules.enabled" type="checkbox"></td></tr>
          <tr><th>生成规则文件</th><td><input id="cfg-dynamic-rules-file" data-path="dynamic_rules.file"></td></tr>
          <tr><th>Google Crawler URL</th><td><input id="cfg-google-crawler-url" data-path="dynamic_rules.google_crawler_url"></td></tr>
          <tr><th>Bingbot URL</th><td><input id="cfg-bingbot-url" data-path="dynamic_rules.bingbot_url"></td></tr>
          <tr><th>Tor Exit URL</th><td><input id="cfg-tor-exit-url" data-path="dynamic_rules.tor_exit_url"></td></tr>
          <tr><th>UptimeRobot URL</th><td><input id="cfg-uptimerobot-url" data-path="dynamic_rules.uptimerobot_ip_url"></td></tr>
          <tr><th>Spamhaus DROP IPv4</th><td><input id="cfg-spamhaus-drop-v4-url" data-path="dynamic_rules.spamhaus_drop_v4_url"></td></tr>
          <tr><th>Spamhaus DROP IPv6</th><td><input id="cfg-spamhaus-drop-v6-url" data-path="dynamic_rules.spamhaus_drop_v6_url"></td></tr>
          <tr><th>Cloudflare IPv4</th><td><input id="cfg-cloudflare-v4-url" data-path="dynamic_rules.cloudflare_v4_url"></td></tr>
          <tr><th>Cloudflare IPv6</th><td><input id="cfg-cloudflare-v6-url" data-path="dynamic_rules.cloudflare_v6_url"></td></tr>
          <tr><th>Fastly URL</th><td><input id="cfg-fastly-url" data-path="dynamic_rules.fastly_url"></td></tr>
          <tr><th>AWS IP Ranges</th><td><input id="cfg-aws-ip-ranges-url" data-path="dynamic_rules.aws_ip_ranges_url"></td></tr>
          <tr><th>Google Cloud IP Ranges</th><td><input id="cfg-google-cloud-ip-ranges-url" data-path="dynamic_rules.google_cloud_ip_ranges_url"></td></tr>
          <tr><th>Azure Service Tags</th><td><input id="cfg-azure-service-tags-url" data-path="dynamic_rules.azure_service_tags_url"></td></tr>
          <tr><th>Oracle IP Ranges</th><td><input id="cfg-oracle-ip-ranges-url" data-path="dynamic_rules.oracle_ip_ranges_url"></td></tr>
          <tr><th>GitHub Meta URL</th><td><input id="cfg-github-meta-url" data-path="dynamic_rules.github_meta_url"></td></tr>
          <tr><th>邮件 SPF 域名</th><td><textarea id="cfg-mail-spf-domains" data-path="dynamic_rules.mail_spf_domains" data-type="list"></textarea></td></tr>
          <tr><th>IP2Proxy 启用</th><td><input id="cfg-ip2proxy-enabled" data-path="dynamic_rules.ip2proxy.enabled" type="checkbox"></td></tr>
          <tr><th>IP2Proxy 本地文件</th><td><input id="cfg-ip2proxy-local-file" data-path="dynamic_rules.ip2proxy.local_file"></td></tr>
          <tr><th>IP2Proxy 本地文件列表</th><td><textarea id="cfg-ip2proxy-local-files" data-path="dynamic_rules.ip2proxy.local_files" data-type="list"></textarea></td></tr>
          <tr><th>IP2Proxy 下载地址</th><td><input id="cfg-ip2proxy-download-url" data-path="dynamic_rules.ip2proxy.download_url"></td></tr>
          <tr><th>IP2Proxy 下载地址列表</th><td><textarea id="cfg-ip2proxy-download-urls" data-path="dynamic_rules.ip2proxy.download_urls" data-type="list"></textarea></td></tr>
          <tr><th>IP2Proxy Token(留空不修改)</th><td><input id="cfg-ip2proxy-token" data-path="dynamic_rules.ip2proxy.token" data-secret="true" type="password" autocomplete="new-password"></td></tr>
          <tr><th>IP2Proxy Package</th><td><input id="cfg-ip2proxy-package" data-path="dynamic_rules.ip2proxy.package"></td></tr>
          <tr><th>IP2Proxy Packages</th><td><textarea id="cfg-ip2proxy-packages" data-path="dynamic_rules.ip2proxy.packages" data-type="list"></textarea></td></tr>
        </tbody>
      </table>
    </details>

    <details class="config-section">
      <summary>公开离线数据源</summary>
      <table class="config-table">
        <tbody>
          <tr><th>CAIDA IPv4 Log</th><td><input id="cfg-caida-v4-log-url" data-path="sources.caida_v4_log_url"></td></tr>
          <tr><th>CAIDA IPv4 Base</th><td><input id="cfg-caida-v4-base-url" data-path="sources.caida_v4_base_url"></td></tr>
          <tr><th>CAIDA IPv6 Log</th><td><input id="cfg-caida-v6-log-url" data-path="sources.caida_v6_log_url"></td></tr>
          <tr><th>CAIDA IPv6 Base</th><td><input id="cfg-caida-v6-base-url" data-path="sources.caida_v6_base_url"></td></tr>
          <tr><th>RIR URLs</th><td><textarea id="cfg-rir-urls" data-path="sources.rir_urls" data-type="map"></textarea></td></tr>
          <tr><th>PeeringDB Net</th><td><input id="cfg-peeringdb-url" data-path="sources.peeringdb_url"></td></tr>
          <tr><th>PeeringDB IX</th><td><input id="cfg-peeringdb-ix-url" data-path="sources.peeringdb_ix_url"></td></tr>
          <tr><th>PeeringDB NetIXLAN</th><td><input id="cfg-peeringdb-netixlan-url" data-path="sources.peeringdb_netixlan_url"></td></tr>
          <tr><th>PeeringDB Facility</th><td><input id="cfg-peeringdb-facility-url" data-path="sources.peeringdb_facility_url"></td></tr>
          <tr><th>PeeringDB NetFacility</th><td><input id="cfg-peeringdb-netfac-url" data-path="sources.peeringdb_netfac_url"></td></tr>
          <tr><th>IANA RDAP URLs</th><td><textarea id="cfg-iana-rdap-urls" data-path="sources.iana_rdap_urls" data-type="map"></textarea></td></tr>
          <tr><th>RPKI VRP URLs <span class="optional-source">可选增强源</span></th><td><textarea id="cfg-rpki-vrp-urls" data-path="sources.rpki_vrp_urls" data-type="list" placeholder="未配置时只加载 data/raw/rpki-vrps*.csv"></textarea><div class="field-help">已预置 rpki-client 公共 CSV。生产环境也可以换成本机 Routinator /csv、rpki-client 导出的 CSV，或 FORT 导出的 VRP CSV。</div></td></tr>
          <tr><th>IRR Route URLs <span class="optional-source">可选增强源</span></th><td><textarea id="cfg-irr-route-urls" data-path="sources.irr_route_urls" data-type="list" placeholder="未配置时只加载 data/raw/irr-routes*"></textarea><div class="field-help">已预置 RIPE、RIPE-NONAUTH、APNIC、AFRINIC 的 HTTP(S) route/route6 dump。RADb 官方主要提供 FTP dump，当前下载器不直接写入默认值。</div></td></tr>
          <tr><th>BGP Observation URLs <span class="optional-source">可选增强源</span></th><td><textarea id="cfg-bgp-observation-urls" data-path="sources.bgp_observation_urls" data-type="list" placeholder="全量 BGP 模式自动生成，通常无需填写"></textarea><div class="field-help">全量 BGP 模式会生成本地摘要 data/generated/bgp-observations-full.jsonl.gz。这里仅用于你另有 HTTP(S) 预处理摘要时补充。</div></td></tr>
          <tr><th>Geofeed URLs <span class="optional-source">可选增强源</span></th><td><textarea id="cfg-geofeed-urls" data-path="sources.geofeed_urls" data-type="list" placeholder="未配置时只加载 data/raw/geofeed*"></textarea><div class="field-help">已预置 OpenGeoFeed 聚合源，适合增强实际所在地判断；它是第三方聚合源，不作为权威注册依据。</div></td></tr>
        </tbody>
      </table>
    </details>
  </form>

  <h2>操作结果</h2>
  <pre id="status"></pre>
</main>
<script>
const statusBox = document.getElementById('status');
const toolbarHint = document.getElementById('toolbar-hint');
const updateButton = document.getElementById('update');
const progressBar = document.getElementById('progress-bar');
const progressPercent = document.getElementById('progress-percent');
const progressCurrent = document.getElementById('progress-current');
const progressSteps = document.getElementById('progress-steps');
const dbStatus = document.getElementById('db-status');
let pollTimer = null;

document.getElementById('load').onclick = loadConfig;
document.getElementById('save').onclick = saveConfigFromForm;
updateButton.onclick = updateDB;

async function loadConfig() {
  const res = await adminFetch('/api/admin/config');
  const data = await res.json();
  if (!res.ok || data.ok === false) {
    writeLog(data);
    return;
  }
  fillConfigForm(data);
  writeLog({ ok: true, message: '配置已读取' });
  await pollStatus();
}

async function saveConfigFromForm() {
  const payload = buildConfigPatch();
  const res = await adminFetch('/api/admin/config', { method: 'PUT', body: JSON.stringify(payload) });
  const data = await res.json();
  writeLog(data);
  if (res.ok && data.config) {
    fillConfigForm(data.config);
  }
}

async function updateDB() {
  updateButton.disabled = true;
  toolbarHint.textContent = '更新任务提交中...';
  const res = await adminFetch('/api/admin/update', { method: 'POST' });
  const data = await res.json();
  writeLog(data);
  if (data.status) {
    renderDatabase(data.status);
    renderProgress(data.status.update_progress);
  }
  startPolling();
}

async function pollStatus() {
  const res = await adminFetch('/api/admin/status');
  const data = await res.json();
  if (!res.ok || data.ok === false) {
    writeLog(data);
    return;
  }
  if (data.config) {
    toolbarHint.textContent = '配置文件已加载';
  }
  const database = data.database || {};
  renderDatabase(database);
  renderProgress(database.update_progress);
  const active = !!(database.updating || (database.update_progress && database.update_progress.active));
  if (!active && pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
    updateButton.disabled = false;
    toolbarHint.textContent = '更新任务已结束';
  }
}

function startPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollStatus();
  pollTimer = setInterval(pollStatus, 1500);
}

function fillConfigForm(config) {
  document.querySelectorAll('[data-path]').forEach((field) => {
    const value = readPath(config, field.dataset.path);
    if (field.dataset.secret === 'true') {
      field.value = '';
      field.placeholder = value ? '已配置，留空不修改' : '未配置';
      return;
    }
    if (field.type === 'checkbox') {
      field.checked = !!value;
      return;
    }
    if (field.dataset.type === 'list') {
      field.value = Array.isArray(value) ? value.join('\n') : '';
      return;
    }
    if (field.dataset.type === 'map') {
      field.value = mapToLines(value);
      return;
    }
    field.value = value === undefined || value === null ? '' : String(value);
  });
}

function buildConfigPatch() {
  const patch = {};
  document.querySelectorAll('[data-path]').forEach((field) => {
    if (field.dataset.secret === 'true' && !field.value.trim()) return;
    let value;
    if (field.type === 'checkbox') {
      value = field.checked;
    } else if (field.dataset.type === 'number') {
      if (field.value.trim() === '') return;
      value = Number.parseInt(field.value, 10);
    } else if (field.dataset.type === 'float') {
      if (field.value.trim() === '') return;
      value = Number.parseFloat(field.value);
    } else if (field.dataset.type === 'list') {
      value = parseList(field.value);
    } else if (field.dataset.type === 'map') {
      value = parseMap(field.value);
    } else {
      value = field.value.trim();
    }
    if (Number.isNaN(value)) return;
    writePath(patch, field.dataset.path, value);
  });
  return patch;
}

function renderDatabase(database) {
  const rows = [
    ['更新中', database.updating ? '是' : '否'],
    ['版本', database.version || '-'],
    ['data 目录', database.data_dir || '-'],
    ['data 大小', database.data_dir_size || '-'],
    ['data 文件数', database.data_dir_file_count || 0],
    ['前缀数', database.prefix_count || 0],
    ['ASN 数', database.asn_count || 0],
    ['BGP 观察数', database.bgp_observation_count || 0],
    ['历史快照', database.history_snapshots || 0],
    ['最近耗时', database.last_duration || '-'],
    ['最近错误', database.last_error || '-'],
    ['更新时间', formatTime(database.updated_at)]
  ];
  dbStatus.innerHTML = rows.map((row) => '<div class="metric"><div class="label">' + escapeHTML(row[0]) + '</div><div class="value">' + escapeHTML(row[1]) + '</div></div>').join('');
}

function renderProgress(progress) {
  const percent = clampPercent(progress && typeof progress.percent === 'number' ? progress.percent : 0);
  progressBar.style.width = percent + '%';
  progressPercent.textContent = percent + '%';
  if (!progress) {
    progressCurrent.textContent = '未开始';
    progressSteps.innerHTML = '';
    return;
  }
  const detail = progress.current_detail ? '：' + progress.current_detail : '';
  const error = progress.last_error ? '，错误：' + progress.last_error : '';
  progressCurrent.textContent = (progress.current_step || (progress.active ? '更新中' : '未开始')) + detail + error;
  progressSteps.innerHTML = (progress.steps || []).map((step) => {
    const cls = step.status ? ' step-' + step.status : '';
    const status = step.status || 'pending';
    const duration = step.duration ? ' / ' + step.duration : '';
    return '<li class="' + cls.trim() + '"><div class="step-name">' + escapeHTML((step.index + 1) + '. ' + step.name) + '</div><div class="step-status">' + escapeHTML(status + duration) + '</div><div class="step-detail">' + escapeHTML(step.detail || '-') + '</div></li>';
  }).join('');
}

async function adminFetch(url, options = {}) {
  options.headers = Object.assign({}, options.headers || {});
  if (options.body && !options.headers['Content-Type']) {
    options.headers['Content-Type'] = 'application/json';
  }
  const token = localStorage.getItem('ipasnAdminToken') || '';
  if (token) options.headers['X-Admin-Token'] = token;
  let res = await fetch(url, options);
  if (res.status === 401) {
    const nextToken = prompt('Admin Token');
    if (nextToken) {
      localStorage.setItem('ipasnAdminToken', nextToken);
      options.headers['X-Admin-Token'] = nextToken;
      res = await fetch(url, options);
    }
  }
  return res;
}

function readPath(object, path) {
  return path.split('.').reduce((current, key) => current && current[key] !== undefined ? current[key] : undefined, object);
}

function writePath(object, path, value) {
  const keys = path.split('.');
  let current = object;
  for (let index = 0; index < keys.length - 1; index++) {
    const key = keys[index];
    if (!current[key] || typeof current[key] !== 'object' || Array.isArray(current[key])) current[key] = {};
    current = current[key];
  }
  current[keys[keys.length - 1]] = value;
}

function parseList(value) {
  return value.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean);
}

function parseMap(value) {
  const result = {};
  value.split('\n').forEach((line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    const index = trimmed.indexOf('=');
    if (index <= 0) return;
    const key = trimmed.slice(0, index).trim();
    const itemValue = trimmed.slice(index + 1).trim();
    if (key && itemValue) result[key] = itemValue;
  });
  return result;
}

function mapToLines(value) {
  if (!value || typeof value !== 'object') return '';
  return Object.keys(value).sort().map((key) => key + '=' + value[key]).join('\n');
}

function clampPercent(value) {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(100, Math.round(value)));
}

function formatTime(value) {
  if (!value || value === '0001-01-01T00:00:00Z') return '-';
  const time = new Date(value);
  if (Number.isNaN(time.getTime())) return '-';
  return time.toLocaleString();
}

function writeLog(value) {
  statusBox.textContent = JSON.stringify(value, null, 2);
}

function escapeHTML(value) {
  return String(value === undefined || value === null ? '' : value).replace(/[&<>"']/g, (ch) => ({'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'}[ch]));
}

loadConfig();
</script>
</body>
</html>`
