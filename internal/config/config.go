package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ConfigPath     string `json:"-" yaml:"-"`
	Addr           string
	DataDir        string
	RulesFile      string
	ASNRulesFile   string
	UpdateInterval time.Duration
	HTTPTimeout    time.Duration
	TLS            TLSConfig
	Sources        Sources
	AI             AIConfig
	Enrichment     EnrichmentConfig
	History        HistoryConfig
	DynamicRules   DynamicRulesConfig
	IP2Region      IP2RegionConfig
	BGP            BGPConfig
	Admin          AdminConfig
}

type TLSConfig struct {
	Enabled  bool
	CertFile string
	KeyFile  string
}

type AIConfig struct {
	Provider         string
	OpenAIAPIKey     string
	OpenAIModel      string
	OpenAIBaseURL    string
	OllamaModel      string
	OllamaBaseURL    string
	ConfidenceCutoff float64
	Timeout          time.Duration
	MaxCache         int
}

type EnrichmentConfig struct {
	Enabled           bool
	TTL               time.Duration
	Timeout           time.Duration
	AsyncOnMiss       bool
	ForegroundTimeout time.Duration
}

type HistoryConfig struct {
	Snapshots int
}

type BGPConfig struct {
	Enabled              bool          `json:"enabled" yaml:"enabled"`
	Mode                 string        `json:"mode" yaml:"mode"`
	RouteViewsEnabled    bool          `json:"routeviews_enabled" yaml:"routeviews_enabled"`
	RIPERISEnabled       bool          `json:"ripe_ris_enabled" yaml:"ripe_ris_enabled"`
	Collectors           []string      `json:"collectors" yaml:"collectors"`
	IncludeUpdates       bool          `json:"include_updates" yaml:"include_updates"`
	HistorySnapshots     int           `json:"history_snapshots" yaml:"history_snapshots"`
	RefreshInterval      time.Duration `json:"-" yaml:"-"`
	MaxParallelDownloads int           `json:"max_parallel_downloads" yaml:"max_parallel_downloads"`
	MaxParallelParse     int           `json:"max_parallel_parse" yaml:"max_parallel_parse"`
	KeepRaw              bool          `json:"keep_raw" yaml:"keep_raw"`
	RawRetentionDays     int           `json:"raw_retention_days" yaml:"raw_retention_days"`
	SummaryFile          string        `json:"summary_file" yaml:"summary_file"`
	RouteViewsBaseURL    string        `json:"routeviews_base_url" yaml:"routeviews_base_url"`
	RIPERISBaseURL       string        `json:"ripe_ris_base_url" yaml:"ripe_ris_base_url"`
	Month                string        `json:"month,omitempty" yaml:"month,omitempty"`
}

type AdminConfig struct {
	Enabled   bool   `json:"enabled" yaml:"enabled"`
	Path      string `json:"path" yaml:"path"`
	Token     string `json:"token,omitempty" yaml:"token,omitempty"`
	LocalOnly bool   `json:"local_only" yaml:"local_only"`
}

type DynamicRulesConfig struct {
	Enabled                bool
	File                   string
	GoogleCrawlerURL       string
	BingbotURL             string
	TorExitURL             string
	UptimeRobotURL         string
	SpamhausDropV4URL      string
	SpamhausDropV6URL      string
	CloudflareV4URL        string
	CloudflareV6URL        string
	FastlyURL              string
	AWSIPRangesURL         string
	GoogleCloudIPRangesURL string
	AzureServiceTagsURL    string
	OracleIPRangesURL      string
	GitHubMetaURL          string
	MailSPFDomains         []string
	IP2Proxy               IP2ProxyConfig
}

type IP2ProxyConfig struct {
	Enabled      bool
	LocalFile    string
	LocalFiles   []string
	DownloadURL  string
	DownloadURLs []string
	Token        string
	Package      string
	Packages     []string
}

type IP2RegionConfig struct {
	Enabled        bool
	IncludeDefault bool
	V4File         string
	V6File         string
	V4VersionURL   string
	V4DownloadURL  string
	V6VersionURL   string
	V6DownloadURL  string
}

type Sources struct {
	CAIDAv4LogURL           string
	CAIDAv4BaseURL          string
	CAIDAv6LogURL           string
	CAIDAv6BaseURL          string
	RIRURLs                 map[string]string
	PeeringDBURL            string
	PeeringDBIXURL          string
	PeeringDBNetIXLANURL    string
	PeeringDBFacilityURL    string
	PeeringDBNetFacilityURL string
	IANARDAPURLs            map[string]string
	RPKIVRPURLs             []string
	IRRRouteURLs            []string
	BGPObservationURLs      []string
	GeofeedURLs             []string
}

type fileConfig struct {
	Addr                string                 `yaml:"addr"`
	DataDir             string                 `yaml:"data_dir"`
	RulesFile           string                 `yaml:"rules_file"`
	ASNRulesFile        string                 `yaml:"asn_rules_file"`
	UpdateIntervalHours *int                   `yaml:"update_interval_hours"`
	HTTPTimeoutSeconds  *int                   `yaml:"http_timeout_seconds"`
	TLS                 fileTLSConfig          `yaml:"tls"`
	AI                  fileAIConfig           `yaml:"ai"`
	Enrichment          fileEnrichmentConfig   `yaml:"enrichment"`
	History             fileHistoryConfig      `yaml:"history"`
	DynamicRules        fileDynamicRulesConfig `yaml:"dynamic_rules"`
	IP2Region           fileIP2RegionConfig    `yaml:"ip2region"`
	BGP                 fileBGPConfig          `yaml:"bgp"`
	Admin               fileAdminConfig        `yaml:"admin"`
	Sources             fileSourcesConfig      `yaml:"sources"`
}

type fileTLSConfig struct {
	Enabled  *bool  `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type fileAIConfig struct {
	Provider         string   `yaml:"provider"`
	OpenAIAPIKey     string   `yaml:"openai_api_key"`
	OpenAIModel      string   `yaml:"openai_model"`
	OpenAIBaseURL    string   `yaml:"openai_base_url"`
	OllamaModel      string   `yaml:"ollama_model"`
	OllamaBaseURL    string   `yaml:"ollama_base_url"`
	ConfidenceCutoff *float64 `yaml:"confidence_cutoff"`
	TimeoutSeconds   *int     `yaml:"timeout_seconds"`
	MaxCache         *int     `yaml:"max_cache"`
}

type fileEnrichmentConfig struct {
	Enabled             *bool `yaml:"enabled"`
	TTLHours            *int  `yaml:"ttl_hours"`
	TimeoutSeconds      *int  `yaml:"timeout_seconds"`
	AsyncOnMiss         *bool `yaml:"async_on_miss"`
	ForegroundTimeoutMS *int  `yaml:"foreground_timeout_ms"`
}

type fileHistoryConfig struct {
	Snapshots *int `yaml:"snapshots"`
}

type fileBGPConfig struct {
	Enabled              *bool    `yaml:"enabled"`
	Mode                 string   `yaml:"mode"`
	RouteViewsEnabled    *bool    `yaml:"routeviews_enabled"`
	RIPERISEnabled       *bool    `yaml:"ripe_ris_enabled"`
	Collectors           []string `yaml:"collectors"`
	IncludeUpdates       *bool    `yaml:"include_updates"`
	HistorySnapshots     *int     `yaml:"history_snapshots"`
	RefreshHours         *int     `yaml:"refresh_hours"`
	MaxParallelDownloads *int     `yaml:"max_parallel_downloads"`
	MaxParallelParse     *int     `yaml:"max_parallel_parse"`
	KeepRaw              *bool    `yaml:"keep_raw"`
	RawRetentionDays     *int     `yaml:"raw_retention_days"`
	SummaryFile          string   `yaml:"summary_file"`
	RouteViewsBaseURL    string   `yaml:"routeviews_base_url"`
	RIPERISBaseURL       string   `yaml:"ripe_ris_base_url"`
	Month                string   `yaml:"month"`
}

type fileAdminConfig struct {
	Enabled   *bool  `yaml:"enabled"`
	Path      string `yaml:"path"`
	Token     string `yaml:"token"`
	LocalOnly *bool  `yaml:"local_only"`
}

type fileDynamicRulesConfig struct {
	Enabled                *bool              `yaml:"enabled"`
	File                   string             `yaml:"file"`
	GoogleCrawlerURL       string             `yaml:"google_crawler_url"`
	BingbotURL             string             `yaml:"bingbot_url"`
	TorExitURL             string             `yaml:"tor_exit_url"`
	UptimeRobotURL         string             `yaml:"uptimerobot_ip_url"`
	SpamhausDropV4URL      string             `yaml:"spamhaus_drop_v4_url"`
	SpamhausDropV6URL      string             `yaml:"spamhaus_drop_v6_url"`
	CloudflareV4URL        string             `yaml:"cloudflare_v4_url"`
	CloudflareV6URL        string             `yaml:"cloudflare_v6_url"`
	FastlyURL              string             `yaml:"fastly_url"`
	AWSIPRangesURL         string             `yaml:"aws_ip_ranges_url"`
	GoogleCloudIPRangesURL string             `yaml:"google_cloud_ip_ranges_url"`
	AzureServiceTagsURL    string             `yaml:"azure_service_tags_url"`
	OracleIPRangesURL      string             `yaml:"oracle_ip_ranges_url"`
	GitHubMetaURL          string             `yaml:"github_meta_url"`
	MailSPFDomains         []string           `yaml:"mail_spf_domains"`
	IP2Proxy               fileIP2ProxyConfig `yaml:"ip2proxy"`
}

type fileIP2ProxyConfig struct {
	Enabled      *bool    `yaml:"enabled"`
	LocalFile    string   `yaml:"local_file"`
	LocalFiles   []string `yaml:"local_files"`
	DownloadURL  string   `yaml:"download_url"`
	DownloadURLs []string `yaml:"download_urls"`
	Token        string   `yaml:"token"`
	Package      string   `yaml:"package"`
	Packages     []string `yaml:"packages"`
}

type fileIP2RegionConfig struct {
	Enabled        *bool  `yaml:"enabled"`
	IncludeDefault *bool  `yaml:"include_default"`
	V4File         string `yaml:"v4_file"`
	V6File         string `yaml:"v6_file"`
	V4VersionURL   string `yaml:"v4_version_url"`
	V4DownloadURL  string `yaml:"v4_download_url"`
	V6VersionURL   string `yaml:"v6_version_url"`
	V6DownloadURL  string `yaml:"v6_download_url"`
}

type fileSourcesConfig struct {
	CAIDAv4LogURL           string            `yaml:"caida_v4_log_url"`
	CAIDAv4BaseURL          string            `yaml:"caida_v4_base_url"`
	CAIDAv6LogURL           string            `yaml:"caida_v6_log_url"`
	CAIDAv6BaseURL          string            `yaml:"caida_v6_base_url"`
	RIRURLs                 map[string]string `yaml:"rir_urls"`
	PeeringDBURL            string            `yaml:"peeringdb_url"`
	PeeringDBIXURL          string            `yaml:"peeringdb_ix_url"`
	PeeringDBNetIXLANURL    string            `yaml:"peeringdb_netixlan_url"`
	PeeringDBFacilityURL    string            `yaml:"peeringdb_facility_url"`
	PeeringDBNetFacilityURL string            `yaml:"peeringdb_netfac_url"`
	IANARDAPURLs            map[string]string `yaml:"iana_rdap_urls"`
	RPKIVRPURLs             *[]string         `yaml:"rpki_vrp_urls"`
	IRRRouteURLs            *[]string         `yaml:"irr_route_urls"`
	BGPObservationURLs      *[]string         `yaml:"bgp_observation_urls"`
	GeofeedURLs             *[]string         `yaml:"geofeed_urls"`
}

func Default() Config {
	return Config{
		Addr:           ":8080",
		DataDir:        "data",
		RulesFile:      "rules/services.json",
		ASNRulesFile:   "rules/asn_scenes.yaml",
		UpdateInterval: 24 * time.Hour,
		HTTPTimeout:    90 * time.Second,
		AI: AIConfig{
			Provider:         "auto",
			OpenAIModel:      "gpt-5.4-mini",
			OpenAIBaseURL:    "https://api.openai.com/v1/responses",
			OllamaModel:      "qwen3:8b",
			OllamaBaseURL:    "http://localhost:11434",
			ConfidenceCutoff: 0.7,
			Timeout:          8 * time.Second,
			MaxCache:         2048,
		},
		Enrichment: EnrichmentConfig{
			Enabled:           true,
			TTL:               7 * 24 * time.Hour,
			Timeout:           8 * time.Second,
			AsyncOnMiss:       true,
			ForegroundTimeout: 1500 * time.Millisecond,
		},
		History: HistoryConfig{
			Snapshots: 4,
		},
		BGP: BGPConfig{
			Enabled:              true,
			Mode:                 "full",
			RouteViewsEnabled:    true,
			RIPERISEnabled:       true,
			Collectors:           []string{"all"},
			IncludeUpdates:       false,
			HistorySnapshots:     7,
			RefreshInterval:      8 * time.Hour,
			MaxParallelDownloads: 4,
			MaxParallelParse:     2,
			KeepRaw:              true,
			RawRetentionDays:     30,
			SummaryFile:          "data/generated/bgp-observations-full.jsonl.gz",
			RouteViewsBaseURL:    "https://archive.routeviews.org/",
			RIPERISBaseURL:       "https://data.ris.ripe.net/",
		},
		Admin: AdminConfig{
			Enabled:   true,
			Path:      "/admin",
			LocalOnly: true,
		},
		DynamicRules: DynamicRulesConfig{
			Enabled:                true,
			GoogleCrawlerURL:       "https://developers.google.com/static/crawling/ipranges/common-crawlers.json",
			BingbotURL:             "https://www.bing.com/toolbox/bingbot.json",
			TorExitURL:             "https://check.torproject.org/torbulkexitlist",
			UptimeRobotURL:         "https://cdn.uptimerobot.com/api/IPv4andIPv6.txt",
			SpamhausDropV4URL:      "https://www.spamhaus.org/drop/drop_v4.json",
			SpamhausDropV6URL:      "https://www.spamhaus.org/drop/drop_v6.json",
			CloudflareV4URL:        "https://www.cloudflare.com/ips-v4",
			CloudflareV6URL:        "https://www.cloudflare.com/ips-v6",
			FastlyURL:              "https://api.fastly.com/public-ip-list",
			AWSIPRangesURL:         "https://ip-ranges.amazonaws.com/ip-ranges.json",
			GoogleCloudIPRangesURL: "https://www.gstatic.com/ipranges/cloud.json",
			AzureServiceTagsURL:    "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519",
			OracleIPRangesURL:      "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json",
			GitHubMetaURL:          "https://api.github.com/meta",
			MailSPFDomains: []string{
				"_spf.google.com",
				"spf.protection.outlook.com",
				"sendgrid.net",
				"mailgun.org",
				"amazonses.com",
				"spf.mandrillapp.com",
			},
			IP2Proxy: IP2ProxyConfig{
				Enabled: true,
				Package: "PX11",
			},
		},
		IP2Region: IP2RegionConfig{
			Enabled:        false,
			IncludeDefault: false,
			V4File:         "data/raw/ip2region_v4.xdb",
			V6File:         "data/raw/ip2region_v6.xdb",
		},
		Sources: Sources{
			CAIDAv4LogURL:  "https://data.caida.org/datasets/routing/routeviews-prefix2as/pfx2as-creation.log",
			CAIDAv4BaseURL: "https://data.caida.org/datasets/routing/routeviews-prefix2as/",
			CAIDAv6LogURL:  "https://data.caida.org/datasets/routing/routeviews6-prefix2as/pfx2as-creation.log",
			CAIDAv6BaseURL: "https://data.caida.org/datasets/routing/routeviews6-prefix2as/",
			RIRURLs: map[string]string{
				"afrinic": "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
				"apnic":   "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
				"arin":    "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
				"lacnic":  "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
				"ripencc": "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
			},
			PeeringDBURL:            "https://www.peeringdb.com/api/net?fields=asn,name,aka,info_type,website",
			PeeringDBIXURL:          "https://www.peeringdb.com/api/ix?fields=id,name,country,city",
			PeeringDBNetIXLANURL:    "https://www.peeringdb.com/api/netixlan?fields=asn,ix_id,name,ipaddr4,ipaddr6,speed",
			PeeringDBFacilityURL:    "https://www.peeringdb.com/api/fac?fields=id,name,country,city",
			PeeringDBNetFacilityURL: "https://www.peeringdb.com/api/netfac?fields=local_asn,fac_id",
			IANARDAPURLs: map[string]string{
				"asn":  "https://data.iana.org/rdap/asn.json",
				"ipv4": "https://data.iana.org/rdap/ipv4.json",
				"ipv6": "https://data.iana.org/rdap/ipv6.json",
			},
			RPKIVRPURLs: []string{
				"https://console.rpki-client.org/vrps.csv",
			},
			IRRRouteURLs: []string{
				"https://ftp.ripe.net/ripe/dbase/split/ripe.db.route.gz",
				"https://ftp.ripe.net/ripe/dbase/split/ripe.db.route6.gz",
				"https://ftp.ripe.net/ripe/dbase/split/ripe-nonauth.db.route.gz",
				"https://ftp.ripe.net/ripe/dbase/split/ripe-nonauth.db.route6.gz",
				"https://ftp.apnic.net/apnic/whois/apnic.db.route.gz",
				"https://ftp.apnic.net/apnic/whois/apnic.db.route6.gz",
				"https://ftp.afrinic.net/dbase/afrinic.db.gz",
			},
			GeofeedURLs: []string{
				"https://opengeofeed.org/feed/public.csv",
			},
		},
	}
}

func Load() Config {
	cfg, err := LoadFromFile("")
	if err != nil {
		return Default()
	}
	return cfg
}

func LoadFromFile(path string) (Config, error) {
	cfg := Default()
	cfg.ConfigPath = strings.TrimSpace(path)
	if strings.TrimSpace(path) != "" {
		if err := applyConfigFile(&cfg, path); err != nil {
			return Config{}, err
		}
	}
	applyEnv(&cfg)
	return cfg, nil
}

func SaveToFile(path string, cfg Config) error {
	path = strings.TrimSpace(path)
	if path == "" {
		path = "config.yaml"
	}
	updateHours := int(cfg.UpdateInterval / time.Hour)
	httpTimeoutSeconds := int(cfg.HTTPTimeout / time.Second)
	refreshHours := int(cfg.BGP.RefreshInterval / time.Hour)
	aiTimeoutSeconds := int(cfg.AI.Timeout / time.Second)
	enrichmentTTLHours := int(cfg.Enrichment.TTL / time.Hour)
	enrichmentTimeoutSeconds := int(cfg.Enrichment.Timeout / time.Second)
	enrichmentForegroundMS := int(cfg.Enrichment.ForegroundTimeout / time.Millisecond)
	file := fileConfig{
		Addr:                cfg.Addr,
		DataDir:             cfg.DataDir,
		RulesFile:           cfg.RulesFile,
		ASNRulesFile:        cfg.ASNRulesFile,
		UpdateIntervalHours: intPtr(updateHours),
		HTTPTimeoutSeconds:  intPtr(httpTimeoutSeconds),
		TLS: fileTLSConfig{
			Enabled:  boolPtr(cfg.TLS.Enabled),
			CertFile: cfg.TLS.CertFile,
			KeyFile:  cfg.TLS.KeyFile,
		},
		AI: fileAIConfig{
			Provider:         cfg.AI.Provider,
			OpenAIAPIKey:     cfg.AI.OpenAIAPIKey,
			OpenAIModel:      cfg.AI.OpenAIModel,
			OpenAIBaseURL:    cfg.AI.OpenAIBaseURL,
			OllamaModel:      cfg.AI.OllamaModel,
			OllamaBaseURL:    cfg.AI.OllamaBaseURL,
			ConfidenceCutoff: floatPtr(cfg.AI.ConfidenceCutoff),
			TimeoutSeconds:   intPtr(aiTimeoutSeconds),
			MaxCache:         intPtr(cfg.AI.MaxCache),
		},
		Enrichment: fileEnrichmentConfig{
			Enabled:             boolPtr(cfg.Enrichment.Enabled),
			TTLHours:            intPtr(enrichmentTTLHours),
			TimeoutSeconds:      intPtr(enrichmentTimeoutSeconds),
			AsyncOnMiss:         boolPtr(cfg.Enrichment.AsyncOnMiss),
			ForegroundTimeoutMS: intPtr(enrichmentForegroundMS),
		},
		History: fileHistoryConfig{
			Snapshots: intPtr(cfg.History.Snapshots),
		},
		BGP: fileBGPConfig{
			Enabled:              boolPtr(cfg.BGP.Enabled),
			Mode:                 cfg.BGP.Mode,
			RouteViewsEnabled:    boolPtr(cfg.BGP.RouteViewsEnabled),
			RIPERISEnabled:       boolPtr(cfg.BGP.RIPERISEnabled),
			Collectors:           cfg.BGP.Collectors,
			IncludeUpdates:       boolPtr(cfg.BGP.IncludeUpdates),
			HistorySnapshots:     intPtr(cfg.BGP.HistorySnapshots),
			RefreshHours:         intPtr(refreshHours),
			MaxParallelDownloads: intPtr(cfg.BGP.MaxParallelDownloads),
			MaxParallelParse:     intPtr(cfg.BGP.MaxParallelParse),
			KeepRaw:              boolPtr(cfg.BGP.KeepRaw),
			RawRetentionDays:     intPtr(cfg.BGP.RawRetentionDays),
			SummaryFile:          cfg.BGP.SummaryFile,
			RouteViewsBaseURL:    cfg.BGP.RouteViewsBaseURL,
			RIPERISBaseURL:       cfg.BGP.RIPERISBaseURL,
			Month:                cfg.BGP.Month,
		},
		Admin: fileAdminConfig{
			Enabled:   boolPtr(cfg.Admin.Enabled),
			Path:      cfg.Admin.Path,
			Token:     cfg.Admin.Token,
			LocalOnly: boolPtr(cfg.Admin.LocalOnly),
		},
		DynamicRules: fileDynamicRulesConfig{
			Enabled:                boolPtr(cfg.DynamicRules.Enabled),
			File:                   cfg.DynamicRules.File,
			GoogleCrawlerURL:       cfg.DynamicRules.GoogleCrawlerURL,
			BingbotURL:             cfg.DynamicRules.BingbotURL,
			TorExitURL:             cfg.DynamicRules.TorExitURL,
			UptimeRobotURL:         cfg.DynamicRules.UptimeRobotURL,
			SpamhausDropV4URL:      cfg.DynamicRules.SpamhausDropV4URL,
			SpamhausDropV6URL:      cfg.DynamicRules.SpamhausDropV6URL,
			CloudflareV4URL:        cfg.DynamicRules.CloudflareV4URL,
			CloudflareV6URL:        cfg.DynamicRules.CloudflareV6URL,
			FastlyURL:              cfg.DynamicRules.FastlyURL,
			AWSIPRangesURL:         cfg.DynamicRules.AWSIPRangesURL,
			GoogleCloudIPRangesURL: cfg.DynamicRules.GoogleCloudIPRangesURL,
			AzureServiceTagsURL:    cfg.DynamicRules.AzureServiceTagsURL,
			OracleIPRangesURL:      cfg.DynamicRules.OracleIPRangesURL,
			GitHubMetaURL:          cfg.DynamicRules.GitHubMetaURL,
			MailSPFDomains:         cfg.DynamicRules.MailSPFDomains,
			IP2Proxy: fileIP2ProxyConfig{
				Enabled:      boolPtr(cfg.DynamicRules.IP2Proxy.Enabled),
				LocalFile:    cfg.DynamicRules.IP2Proxy.LocalFile,
				LocalFiles:   cfg.DynamicRules.IP2Proxy.LocalFiles,
				DownloadURL:  cfg.DynamicRules.IP2Proxy.DownloadURL,
				DownloadURLs: cfg.DynamicRules.IP2Proxy.DownloadURLs,
				Token:        cfg.DynamicRules.IP2Proxy.Token,
				Package:      cfg.DynamicRules.IP2Proxy.Package,
				Packages:     cfg.DynamicRules.IP2Proxy.Packages,
			},
		},
		IP2Region: fileIP2RegionConfig{
			Enabled:        boolPtr(cfg.IP2Region.Enabled),
			IncludeDefault: boolPtr(cfg.IP2Region.IncludeDefault),
			V4File:         cfg.IP2Region.V4File,
			V6File:         cfg.IP2Region.V6File,
			V4VersionURL:   cfg.IP2Region.V4VersionURL,
			V4DownloadURL:  cfg.IP2Region.V4DownloadURL,
			V6VersionURL:   cfg.IP2Region.V6VersionURL,
			V6DownloadURL:  cfg.IP2Region.V6DownloadURL,
		},
		Sources: fileSourcesConfig{
			CAIDAv4LogURL:           cfg.Sources.CAIDAv4LogURL,
			CAIDAv4BaseURL:          cfg.Sources.CAIDAv4BaseURL,
			CAIDAv6LogURL:           cfg.Sources.CAIDAv6LogURL,
			CAIDAv6BaseURL:          cfg.Sources.CAIDAv6BaseURL,
			RIRURLs:                 cfg.Sources.RIRURLs,
			PeeringDBURL:            cfg.Sources.PeeringDBURL,
			PeeringDBIXURL:          cfg.Sources.PeeringDBIXURL,
			PeeringDBNetIXLANURL:    cfg.Sources.PeeringDBNetIXLANURL,
			PeeringDBFacilityURL:    cfg.Sources.PeeringDBFacilityURL,
			PeeringDBNetFacilityURL: cfg.Sources.PeeringDBNetFacilityURL,
			IANARDAPURLs:            cfg.Sources.IANARDAPURLs,
			RPKIVRPURLs:             stringSlicePtr(cfg.Sources.RPKIVRPURLs),
			IRRRouteURLs:            stringSlicePtr(cfg.Sources.IRRRouteURLs),
			BGPObservationURLs:      stringSlicePtr(cfg.Sources.BGPObservationURLs),
			GeofeedURLs:             stringSlicePtr(cfg.Sources.GeofeedURLs),
		},
	}
	encoded, err := yaml.Marshal(file)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o775); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, encoded, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func applyConfigFile(cfg *Config, path string) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config file %s: %w", path, err)
	}
	var file fileConfig
	if err := yaml.Unmarshal(body, &file); err != nil {
		return fmt.Errorf("parse config file %s: %w", path, err)
	}

	if file.Addr != "" {
		cfg.Addr = file.Addr
	}
	if file.DataDir != "" {
		cfg.DataDir = file.DataDir
	}
	if file.RulesFile != "" {
		cfg.RulesFile = file.RulesFile
	}
	if file.ASNRulesFile != "" {
		cfg.ASNRulesFile = file.ASNRulesFile
	}
	if file.UpdateIntervalHours != nil && *file.UpdateIntervalHours >= 0 {
		cfg.UpdateInterval = time.Duration(*file.UpdateIntervalHours) * time.Hour
	}
	if file.HTTPTimeoutSeconds != nil && *file.HTTPTimeoutSeconds > 0 {
		cfg.HTTPTimeout = time.Duration(*file.HTTPTimeoutSeconds) * time.Second
	}
	if file.TLS.Enabled != nil {
		cfg.TLS.Enabled = *file.TLS.Enabled
	}
	if file.TLS.CertFile != "" {
		cfg.TLS.CertFile = file.TLS.CertFile
	}
	if file.TLS.KeyFile != "" {
		cfg.TLS.KeyFile = file.TLS.KeyFile
	}

	applyAIFileConfig(&cfg.AI, file.AI)
	applyEnrichmentFileConfig(&cfg.Enrichment, file.Enrichment)
	if file.History.Snapshots != nil && *file.History.Snapshots >= 0 {
		cfg.History.Snapshots = *file.History.Snapshots
	}
	applyBGPFileConfig(&cfg.BGP, file.BGP)
	applyAdminFileConfig(&cfg.Admin, file.Admin)
	applyDynamicRulesFileConfig(&cfg.DynamicRules, file.DynamicRules)
	applyIP2RegionFileConfig(&cfg.IP2Region, file.IP2Region)
	applySourcesFileConfig(&cfg.Sources, file.Sources)
	return nil
}

func applyBGPFileConfig(cfg *BGPConfig, file fileBGPConfig) {
	if file.Enabled != nil {
		cfg.Enabled = *file.Enabled
	}
	if file.Mode != "" {
		cfg.Mode = file.Mode
	}
	if file.RouteViewsEnabled != nil {
		cfg.RouteViewsEnabled = *file.RouteViewsEnabled
	}
	if file.RIPERISEnabled != nil {
		cfg.RIPERISEnabled = *file.RIPERISEnabled
	}
	if len(file.Collectors) > 0 {
		cfg.Collectors = file.Collectors
	}
	if file.IncludeUpdates != nil {
		cfg.IncludeUpdates = *file.IncludeUpdates
	}
	if file.HistorySnapshots != nil && *file.HistorySnapshots >= 0 {
		cfg.HistorySnapshots = *file.HistorySnapshots
	}
	if file.RefreshHours != nil && *file.RefreshHours > 0 {
		cfg.RefreshInterval = time.Duration(*file.RefreshHours) * time.Hour
	}
	if file.MaxParallelDownloads != nil && *file.MaxParallelDownloads > 0 {
		cfg.MaxParallelDownloads = *file.MaxParallelDownloads
	}
	if file.MaxParallelParse != nil && *file.MaxParallelParse > 0 {
		cfg.MaxParallelParse = *file.MaxParallelParse
	}
	if file.KeepRaw != nil {
		cfg.KeepRaw = *file.KeepRaw
	}
	if file.RawRetentionDays != nil && *file.RawRetentionDays >= 0 {
		cfg.RawRetentionDays = *file.RawRetentionDays
	}
	if file.SummaryFile != "" {
		cfg.SummaryFile = file.SummaryFile
	}
	if file.RouteViewsBaseURL != "" {
		cfg.RouteViewsBaseURL = file.RouteViewsBaseURL
	}
	if file.RIPERISBaseURL != "" {
		cfg.RIPERISBaseURL = file.RIPERISBaseURL
	}
	if file.Month != "" {
		cfg.Month = file.Month
	}
	normalizeBGPConfig(cfg)
}

func applyAdminFileConfig(cfg *AdminConfig, file fileAdminConfig) {
	if file.Enabled != nil {
		cfg.Enabled = *file.Enabled
	}
	if file.Path != "" {
		cfg.Path = file.Path
	}
	if file.Token != "" {
		cfg.Token = file.Token
	}
	if file.LocalOnly != nil {
		cfg.LocalOnly = *file.LocalOnly
	}
	normalizeAdminConfig(cfg)
}

func applyAIFileConfig(cfg *AIConfig, file fileAIConfig) {
	if file.Provider != "" {
		cfg.Provider = file.Provider
	}
	if file.OpenAIAPIKey != "" {
		cfg.OpenAIAPIKey = file.OpenAIAPIKey
	}
	if file.OpenAIModel != "" {
		cfg.OpenAIModel = file.OpenAIModel
	}
	if file.OpenAIBaseURL != "" {
		cfg.OpenAIBaseURL = file.OpenAIBaseURL
	}
	if file.OllamaModel != "" {
		cfg.OllamaModel = file.OllamaModel
	}
	if file.OllamaBaseURL != "" {
		cfg.OllamaBaseURL = file.OllamaBaseURL
	}
	if file.ConfidenceCutoff != nil && *file.ConfidenceCutoff > 0 && *file.ConfidenceCutoff <= 1 {
		cfg.ConfidenceCutoff = *file.ConfidenceCutoff
	}
	if file.TimeoutSeconds != nil && *file.TimeoutSeconds > 0 {
		cfg.Timeout = time.Duration(*file.TimeoutSeconds) * time.Second
	}
	if file.MaxCache != nil && *file.MaxCache > 0 {
		cfg.MaxCache = *file.MaxCache
	}
}

func applyEnrichmentFileConfig(cfg *EnrichmentConfig, file fileEnrichmentConfig) {
	if file.Enabled != nil {
		cfg.Enabled = *file.Enabled
	}
	if file.TTLHours != nil && *file.TTLHours > 0 {
		cfg.TTL = time.Duration(*file.TTLHours) * time.Hour
	}
	if file.TimeoutSeconds != nil && *file.TimeoutSeconds > 0 {
		cfg.Timeout = time.Duration(*file.TimeoutSeconds) * time.Second
	}
	if file.AsyncOnMiss != nil {
		cfg.AsyncOnMiss = *file.AsyncOnMiss
	}
	if file.ForegroundTimeoutMS != nil && *file.ForegroundTimeoutMS >= 0 {
		cfg.ForegroundTimeout = time.Duration(*file.ForegroundTimeoutMS) * time.Millisecond
	}
}

func applyDynamicRulesFileConfig(cfg *DynamicRulesConfig, file fileDynamicRulesConfig) {
	if file.Enabled != nil {
		cfg.Enabled = *file.Enabled
	}
	if file.File != "" {
		cfg.File = file.File
	}
	if file.GoogleCrawlerURL != "" {
		cfg.GoogleCrawlerURL = file.GoogleCrawlerURL
	}
	if file.BingbotURL != "" {
		cfg.BingbotURL = file.BingbotURL
	}
	if file.TorExitURL != "" {
		cfg.TorExitURL = file.TorExitURL
	}
	if file.UptimeRobotURL != "" {
		cfg.UptimeRobotURL = file.UptimeRobotURL
	}
	if file.SpamhausDropV4URL != "" {
		cfg.SpamhausDropV4URL = file.SpamhausDropV4URL
	}
	if file.SpamhausDropV6URL != "" {
		cfg.SpamhausDropV6URL = file.SpamhausDropV6URL
	}
	if file.CloudflareV4URL != "" {
		cfg.CloudflareV4URL = file.CloudflareV4URL
	}
	if file.CloudflareV6URL != "" {
		cfg.CloudflareV6URL = file.CloudflareV6URL
	}
	if file.FastlyURL != "" {
		cfg.FastlyURL = file.FastlyURL
	}
	if file.AWSIPRangesURL != "" {
		cfg.AWSIPRangesURL = file.AWSIPRangesURL
	}
	if file.GoogleCloudIPRangesURL != "" {
		cfg.GoogleCloudIPRangesURL = file.GoogleCloudIPRangesURL
	}
	if file.AzureServiceTagsURL != "" {
		cfg.AzureServiceTagsURL = file.AzureServiceTagsURL
	}
	if file.OracleIPRangesURL != "" {
		cfg.OracleIPRangesURL = file.OracleIPRangesURL
	}
	if file.GitHubMetaURL != "" {
		cfg.GitHubMetaURL = file.GitHubMetaURL
	}
	if len(file.MailSPFDomains) > 0 {
		cfg.MailSPFDomains = file.MailSPFDomains
	}
	applyIP2ProxyFileConfig(&cfg.IP2Proxy, file.IP2Proxy)
}

func applyIP2ProxyFileConfig(cfg *IP2ProxyConfig, file fileIP2ProxyConfig) {
	if file.Enabled != nil {
		cfg.Enabled = *file.Enabled
	}
	if file.LocalFile != "" {
		cfg.LocalFile = file.LocalFile
	}
	if len(file.LocalFiles) > 0 {
		cfg.LocalFiles = file.LocalFiles
	}
	if file.DownloadURL != "" {
		cfg.DownloadURL = file.DownloadURL
	}
	if len(file.DownloadURLs) > 0 {
		cfg.DownloadURLs = file.DownloadURLs
	}
	if file.Token != "" {
		cfg.Token = file.Token
	}
	if file.Package != "" {
		cfg.Package = file.Package
	}
	if len(file.Packages) > 0 {
		cfg.Packages = file.Packages
	}
}

func applyIP2RegionFileConfig(cfg *IP2RegionConfig, file fileIP2RegionConfig) {
	if file.Enabled != nil {
		cfg.Enabled = *file.Enabled
	}
	if file.IncludeDefault != nil {
		cfg.IncludeDefault = *file.IncludeDefault
	}
	if file.V4File != "" {
		cfg.V4File = file.V4File
	}
	if file.V6File != "" {
		cfg.V6File = file.V6File
	}
	if file.V4VersionURL != "" {
		cfg.V4VersionURL = file.V4VersionURL
	}
	if file.V4DownloadURL != "" {
		cfg.V4DownloadURL = file.V4DownloadURL
	}
	if file.V6VersionURL != "" {
		cfg.V6VersionURL = file.V6VersionURL
	}
	if file.V6DownloadURL != "" {
		cfg.V6DownloadURL = file.V6DownloadURL
	}
}

func applySourcesFileConfig(cfg *Sources, file fileSourcesConfig) {
	if file.CAIDAv4LogURL != "" {
		cfg.CAIDAv4LogURL = file.CAIDAv4LogURL
	}
	if file.CAIDAv4BaseURL != "" {
		cfg.CAIDAv4BaseURL = file.CAIDAv4BaseURL
	}
	if file.CAIDAv6LogURL != "" {
		cfg.CAIDAv6LogURL = file.CAIDAv6LogURL
	}
	if file.CAIDAv6BaseURL != "" {
		cfg.CAIDAv6BaseURL = file.CAIDAv6BaseURL
	}
	if len(file.RIRURLs) > 0 {
		if cfg.RIRURLs == nil {
			cfg.RIRURLs = map[string]string{}
		}
		for key, value := range file.RIRURLs {
			cfg.RIRURLs[key] = value
		}
	}
	if file.PeeringDBURL != "" {
		cfg.PeeringDBURL = file.PeeringDBURL
	}
	if file.PeeringDBIXURL != "" {
		cfg.PeeringDBIXURL = file.PeeringDBIXURL
	}
	if file.PeeringDBNetIXLANURL != "" {
		cfg.PeeringDBNetIXLANURL = file.PeeringDBNetIXLANURL
	}
	if file.PeeringDBFacilityURL != "" {
		cfg.PeeringDBFacilityURL = file.PeeringDBFacilityURL
	}
	if file.PeeringDBNetFacilityURL != "" {
		cfg.PeeringDBNetFacilityURL = file.PeeringDBNetFacilityURL
	}
	if len(file.IANARDAPURLs) > 0 {
		if cfg.IANARDAPURLs == nil {
			cfg.IANARDAPURLs = map[string]string{}
		}
		for key, value := range file.IANARDAPURLs {
			cfg.IANARDAPURLs[key] = value
		}
	}
	if file.RPKIVRPURLs != nil {
		cfg.RPKIVRPURLs = cleanStringSlice(*file.RPKIVRPURLs)
	}
	if file.IRRRouteURLs != nil {
		cfg.IRRRouteURLs = cleanStringSlice(*file.IRRRouteURLs)
	}
	if file.BGPObservationURLs != nil {
		cfg.BGPObservationURLs = cleanStringSlice(*file.BGPObservationURLs)
	}
	if file.GeofeedURLs != nil {
		cfg.GeofeedURLs = cleanStringSlice(*file.GeofeedURLs)
	}
}

func applyEnv(cfg *Config) {
	if value := os.Getenv("ADDR"); value != "" {
		cfg.Addr = value
	}
	if value := os.Getenv("DATA_DIR"); value != "" {
		cfg.DataDir = value
	}
	if value := os.Getenv("AI_PROVIDER"); value != "" {
		cfg.AI.Provider = value
	}
	if value := os.Getenv("RULES_FILE"); value != "" {
		cfg.RulesFile = value
	}
	if value := os.Getenv("ASN_RULES_FILE"); value != "" {
		cfg.ASNRulesFile = value
	}
	if value := os.Getenv("UPDATE_INTERVAL_HOURS"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed >= 0 {
			cfg.UpdateInterval = time.Duration(parsed) * time.Hour
		}
	}
	if value := os.Getenv("HTTP_TIMEOUT_SECONDS"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 {
			cfg.HTTPTimeout = time.Duration(parsed) * time.Second
		}
	}
	if value := os.Getenv("TLS_ENABLED"); value != "" {
		cfg.TLS.Enabled = value != "0" && strings.ToLower(value) != "false"
	}
	if value := os.Getenv("TLS_CERT_FILE"); value != "" {
		cfg.TLS.CertFile = value
	}
	if value := os.Getenv("TLS_KEY_FILE"); value != "" {
		cfg.TLS.KeyFile = value
	}
	if value := os.Getenv("OPENAI_API_KEY"); value != "" {
		cfg.AI.OpenAIAPIKey = value
	}
	if value := os.Getenv("OPENAI_MODEL"); value != "" {
		cfg.AI.OpenAIModel = value
	}
	if value := os.Getenv("OPENAI_BASE_URL"); value != "" {
		cfg.AI.OpenAIBaseURL = value
	}
	if value := os.Getenv("OLLAMA_MODEL"); value != "" {
		cfg.AI.OllamaModel = value
	}
	if value := os.Getenv("OLLAMA_BASE_URL"); value != "" {
		cfg.AI.OllamaBaseURL = value
	}
	if value := os.Getenv("AI_CONFIDENCE_CUTOFF"); value != "" {
		if parsed, err := strconv.ParseFloat(value, 64); err == nil && parsed > 0 && parsed <= 1 {
			cfg.AI.ConfidenceCutoff = parsed
		}
	}
	if value := os.Getenv("AI_TIMEOUT_SECONDS"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 {
			cfg.AI.Timeout = time.Duration(parsed) * time.Second
		}
	}
	if value := os.Getenv("AI_MAX_CACHE"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 {
			cfg.AI.MaxCache = parsed
		}
	}
	if value := os.Getenv("ENRICHMENT_ENABLED"); value != "" {
		cfg.Enrichment.Enabled = value != "0" && strings.ToLower(value) != "false"
	}
	if value := os.Getenv("ENRICHMENT_TTL_HOURS"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 {
			cfg.Enrichment.TTL = time.Duration(parsed) * time.Hour
		}
	}
	if value := os.Getenv("ENRICHMENT_TIMEOUT_SECONDS"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 {
			cfg.Enrichment.Timeout = time.Duration(parsed) * time.Second
		}
	}
	if value := os.Getenv("ENRICHMENT_ASYNC_ON_MISS"); value != "" {
		cfg.Enrichment.AsyncOnMiss = value != "0" && strings.ToLower(value) != "false"
	}
	if value := os.Getenv("ENRICHMENT_FOREGROUND_TIMEOUT_MS"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed >= 0 {
			cfg.Enrichment.ForegroundTimeout = time.Duration(parsed) * time.Millisecond
		}
	}
	if value := os.Getenv("HISTORY_SNAPSHOTS"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed >= 0 {
			cfg.History.Snapshots = parsed
		}
	}
	if value := os.Getenv("BGP_ENABLED"); value != "" {
		cfg.BGP.Enabled = parseEnvBool(value)
	}
	if value := os.Getenv("BGP_MODE"); value != "" {
		cfg.BGP.Mode = value
	}
	if value := os.Getenv("BGP_ROUTEVIEWS_ENABLED"); value != "" {
		cfg.BGP.RouteViewsEnabled = parseEnvBool(value)
	}
	if value := os.Getenv("BGP_RIPE_RIS_ENABLED"); value != "" {
		cfg.BGP.RIPERISEnabled = parseEnvBool(value)
	}
	if value := os.Getenv("BGP_COLLECTORS"); value != "" {
		cfg.BGP.Collectors = splitList(value)
	}
	if value := os.Getenv("BGP_INCLUDE_UPDATES"); value != "" {
		cfg.BGP.IncludeUpdates = parseEnvBool(value)
	}
	if value := os.Getenv("BGP_HISTORY_SNAPSHOTS"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed >= 0 {
			cfg.BGP.HistorySnapshots = parsed
		}
	}
	if value := os.Getenv("BGP_REFRESH_HOURS"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 {
			cfg.BGP.RefreshInterval = time.Duration(parsed) * time.Hour
		}
	}
	if value := os.Getenv("BGP_MAX_PARALLEL_DOWNLOADS"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 {
			cfg.BGP.MaxParallelDownloads = parsed
		}
	}
	if value := os.Getenv("BGP_MAX_PARALLEL_PARSE"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 {
			cfg.BGP.MaxParallelParse = parsed
		}
	}
	if value := os.Getenv("BGP_KEEP_RAW"); value != "" {
		cfg.BGP.KeepRaw = parseEnvBool(value)
	}
	if value := os.Getenv("BGP_RAW_RETENTION_DAYS"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed >= 0 {
			cfg.BGP.RawRetentionDays = parsed
		}
	}
	if value := os.Getenv("BGP_SUMMARY_FILE"); value != "" {
		cfg.BGP.SummaryFile = value
	}
	if value := os.Getenv("BGP_ROUTEVIEWS_BASE_URL"); value != "" {
		cfg.BGP.RouteViewsBaseURL = value
	}
	if value := os.Getenv("BGP_RIPE_RIS_BASE_URL"); value != "" {
		cfg.BGP.RIPERISBaseURL = value
	}
	if value := os.Getenv("BGP_MONTH"); value != "" {
		cfg.BGP.Month = value
	}
	if value := os.Getenv("ADMIN_ENABLED"); value != "" {
		cfg.Admin.Enabled = parseEnvBool(value)
	}
	if value := os.Getenv("ADMIN_PATH"); value != "" {
		cfg.Admin.Path = value
	}
	if value := os.Getenv("ADMIN_TOKEN"); value != "" {
		cfg.Admin.Token = value
	}
	if value := os.Getenv("ADMIN_LOCAL_ONLY"); value != "" {
		cfg.Admin.LocalOnly = parseEnvBool(value)
	}
	if value := os.Getenv("DYNAMIC_RULES_ENABLED"); value != "" {
		cfg.DynamicRules.Enabled = parseEnvBool(value)
	}
	if value := os.Getenv("DYNAMIC_RULES_FILE"); value != "" {
		cfg.DynamicRules.File = value
	}
	if value := os.Getenv("GOOGLE_CRAWLER_URL"); value != "" {
		cfg.DynamicRules.GoogleCrawlerURL = value
	}
	if value := os.Getenv("BINGBOT_URL"); value != "" {
		cfg.DynamicRules.BingbotURL = value
	}
	if value := os.Getenv("TOR_EXIT_URL"); value != "" {
		cfg.DynamicRules.TorExitURL = value
	}
	if value := os.Getenv("UPTIMEROBOT_IP_URL"); value != "" {
		cfg.DynamicRules.UptimeRobotURL = value
	}
	if value := os.Getenv("SPAMHAUS_DROP_V4_URL"); value != "" {
		cfg.DynamicRules.SpamhausDropV4URL = value
	}
	if value := os.Getenv("SPAMHAUS_DROP_V6_URL"); value != "" {
		cfg.DynamicRules.SpamhausDropV6URL = value
	}
	if value := os.Getenv("MAIL_SPF_DOMAINS"); value != "" {
		cfg.DynamicRules.MailSPFDomains = splitList(value)
	}
	if value := os.Getenv("IP2PROXY_ENABLED"); value != "" {
		cfg.DynamicRules.IP2Proxy.Enabled = parseEnvBool(value)
	}
	if value := os.Getenv("IP2PROXY_LOCAL_FILE"); value != "" {
		cfg.DynamicRules.IP2Proxy.LocalFile = value
	}
	if value := os.Getenv("IP2PROXY_LOCAL_FILES"); value != "" {
		cfg.DynamicRules.IP2Proxy.LocalFiles = splitList(value)
	}
	if value := os.Getenv("IP2PROXY_DOWNLOAD_URL"); value != "" {
		cfg.DynamicRules.IP2Proxy.DownloadURL = value
	}
	if value := os.Getenv("IP2PROXY_DOWNLOAD_URLS"); value != "" {
		cfg.DynamicRules.IP2Proxy.DownloadURLs = splitList(value)
	}
	if value := os.Getenv("IP2PROXY_TOKEN"); value != "" {
		cfg.DynamicRules.IP2Proxy.Token = value
	}
	if value := os.Getenv("IP2PROXY_PACKAGE"); value != "" {
		cfg.DynamicRules.IP2Proxy.Package = value
	}
	if value := os.Getenv("IP2PROXY_PACKAGES"); value != "" {
		cfg.DynamicRules.IP2Proxy.Packages = splitList(value)
	}
	if value := os.Getenv("IP2REGION_ENABLED"); value != "" {
		cfg.IP2Region.Enabled = parseEnvBool(value)
	}
	if value := os.Getenv("IP2REGION_INCLUDE_DEFAULT"); value != "" {
		cfg.IP2Region.IncludeDefault = parseEnvBool(value)
	}
	if value := os.Getenv("IP2REGION_V4_FILE"); value != "" {
		cfg.IP2Region.V4File = value
	}
	if value := os.Getenv("IP2REGION_V6_FILE"); value != "" {
		cfg.IP2Region.V6File = value
	}
	if value := os.Getenv("IP2REGION_V4_VERSION_URL"); value != "" {
		cfg.IP2Region.V4VersionURL = value
	}
	if value := os.Getenv("IP2REGION_V4_DOWNLOAD_URL"); value != "" {
		cfg.IP2Region.V4DownloadURL = value
	}
	if value := os.Getenv("IP2REGION_V6_VERSION_URL"); value != "" {
		cfg.IP2Region.V6VersionURL = value
	}
	if value := os.Getenv("IP2REGION_V6_DOWNLOAD_URL"); value != "" {
		cfg.IP2Region.V6DownloadURL = value
	}
	if value := os.Getenv("RPKI_VRP_URLS"); value != "" {
		cfg.Sources.RPKIVRPURLs = splitList(value)
	}
	if value := os.Getenv("IRR_ROUTE_URLS"); value != "" {
		cfg.Sources.IRRRouteURLs = splitList(value)
	}
	if value := os.Getenv("BGP_OBSERVATION_URLS"); value != "" {
		cfg.Sources.BGPObservationURLs = splitList(value)
	}
	if value := os.Getenv("GEOFEED_URLS"); value != "" {
		cfg.Sources.GeofeedURLs = splitList(value)
	}
	normalizeBGPConfig(&cfg.BGP)
	normalizeAdminConfig(&cfg.Admin)
}

func splitList(value string) []string {
	parts := strings.Split(value, ",")
	return cleanStringSlice(parts)
}

func cleanStringSlice(parts []string) []string {
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parseEnvBool(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	return normalized != "0" && normalized != "false" && normalized != "no" && normalized != "off"
}

func normalizeBGPConfig(cfg *BGPConfig) {
	cfg.Mode = strings.ToLower(strings.TrimSpace(cfg.Mode))
	if cfg.Mode == "" {
		cfg.Mode = "full"
	}
	if len(cfg.Collectors) == 0 {
		cfg.Collectors = []string{"all"}
	}
	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = 8 * time.Hour
	}
	if cfg.MaxParallelDownloads <= 0 {
		cfg.MaxParallelDownloads = 1
	}
	if cfg.MaxParallelParse <= 0 {
		cfg.MaxParallelParse = 1
	}
	if cfg.SummaryFile == "" {
		cfg.SummaryFile = "data/generated/bgp-observations-full.jsonl.gz"
	}
	if cfg.RouteViewsBaseURL == "" {
		cfg.RouteViewsBaseURL = "https://archive.routeviews.org/"
	}
	if cfg.RIPERISBaseURL == "" {
		cfg.RIPERISBaseURL = "https://data.ris.ripe.net/"
	}
}

func normalizeAdminConfig(cfg *AdminConfig) {
	if strings.TrimSpace(cfg.Path) == "" {
		cfg.Path = "/admin"
	}
	if !strings.HasPrefix(cfg.Path, "/") {
		cfg.Path = "/" + cfg.Path
	}
}

func boolPtr(value bool) *bool {
	return &value
}

func intPtr(value int) *int {
	return &value
}

func floatPtr(value float64) *float64 {
	return &value
}

func stringSlicePtr(value []string) *[]string {
	copied := append([]string(nil), value...)
	return &copied
}
