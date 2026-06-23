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
	Quality        QualityConfig
	Performance    PerformanceConfig
	DynamicRules   DynamicRulesConfig
	IP2Region      IP2RegionConfig
	FirewallLists  FirewallListsConfig
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
	OpenAIAPIType    string
	AnthropicAPIKey  string
	AnthropicModel   string
	AnthropicBaseURL string
	AnthropicVersion string
	GeminiAPIKey     string
	GeminiModel      string
	GeminiBaseURL    string
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

type QualityConfig struct {
	Enabled                bool
	IncludeDefault         bool
	AILowConfidence        bool
	LowConfidenceThreshold float64
	AllowScore             int
	ReviewScore            int
	ChallengeScore         int
	RateLimitScore         int
}

type PerformanceConfig struct {
	Enabled           bool
	IncludeDefault    bool
	ThirdPartyDefault bool
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
	DownloadTimeout      time.Duration `json:"-" yaml:"-"`
	MaxParallelParse     int           `json:"max_parallel_parse" yaml:"max_parallel_parse"`
	KeepRaw              bool          `json:"keep_raw" yaml:"keep_raw"`
	RawRetentionDays     int           `json:"raw_retention_days" yaml:"raw_retention_days"`
	SummaryFile          string        `json:"summary_file" yaml:"summary_file"`
	IndexMode            string        `json:"index_mode" yaml:"index_mode"`
	IndexFile            string        `json:"index_file" yaml:"index_file"`
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
	FireHOLLevel1URL       string
	FireHOLAnonymousURL    string
	Az0VPNIPURL            string
	CloudflareV4URL        string
	CloudflareV6URL        string
	FastlyURL              string
	AWSIPRangesURL         string
	GoogleCloudIPRangesURL string
	AzureServiceTagsURL    string
	OracleIPRangesURL      string
	GitHubMetaURL          string
	ApplePrivateRelayURL   string
	GoogleFiVPNGeofeedURL  string
	MullvadRelaysURL       string
	NordVPNServersURL      string
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

type FirewallListsConfig struct {
	Enabled       bool     `json:"enabled" yaml:"enabled"`
	OutputDir     string   `json:"output_dir" yaml:"output_dir"`
	Countries     []string `json:"countries" yaml:"countries"`
	Companies     []string `json:"companies" yaml:"companies"`
	Scenes        []string `json:"scenes" yaml:"scenes"`
	MinConfidence float64  `json:"min_confidence" yaml:"min_confidence"`
	IncludeIPv4   bool     `json:"include_ipv4" yaml:"include_ipv4"`
	IncludeIPv6   bool     `json:"include_ipv6" yaml:"include_ipv6"`
	WriteEntries  bool     `json:"write_entries" yaml:"write_entries"`
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
	Addr                string                  `yaml:"addr"`
	DataDir             string                  `yaml:"data_dir"`
	RulesFile           string                  `yaml:"rules_file"`
	ASNRulesFile        string                  `yaml:"asn_rules_file"`
	UpdateIntervalHours *int                    `yaml:"update_interval_hours"`
	HTTPTimeoutSeconds  *int                    `yaml:"http_timeout_seconds"`
	TLS                 fileTLSConfig           `yaml:"tls"`
	AI                  fileAIConfig            `yaml:"ai"`
	Enrichment          fileEnrichmentConfig    `yaml:"enrichment"`
	History             fileHistoryConfig       `yaml:"history"`
	Quality             fileQualityConfig       `yaml:"quality"`
	Performance         filePerformanceConfig   `yaml:"performance"`
	DynamicRules        fileDynamicRulesConfig  `yaml:"dynamic_rules"`
	IP2Region           fileIP2RegionConfig     `yaml:"ip2region"`
	FirewallLists       fileFirewallListsConfig `yaml:"firewall_lists"`
	BGP                 fileBGPConfig           `yaml:"bgp"`
	Admin               fileAdminConfig         `yaml:"admin"`
	Sources             fileSourcesConfig       `yaml:"sources"`
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
	OpenAIAPIType    string   `yaml:"openai_api_type"`
	AnthropicAPIKey  string   `yaml:"anthropic_api_key"`
	AnthropicModel   string   `yaml:"anthropic_model"`
	AnthropicBaseURL string   `yaml:"anthropic_base_url"`
	AnthropicVersion string   `yaml:"anthropic_version"`
	GeminiAPIKey     string   `yaml:"gemini_api_key"`
	GeminiModel      string   `yaml:"gemini_model"`
	GeminiBaseURL    string   `yaml:"gemini_base_url"`
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

type fileQualityConfig struct {
	Enabled                *bool    `yaml:"enabled"`
	IncludeDefault         *bool    `yaml:"include_default"`
	AILowConfidence        *bool    `yaml:"ai_low_confidence"`
	LowConfidenceThreshold *float64 `yaml:"low_confidence_threshold"`
	AllowScore             *int     `yaml:"allow_score"`
	ReviewScore            *int     `yaml:"review_score"`
	ChallengeScore         *int     `yaml:"challenge_score"`
	RateLimitScore         *int     `yaml:"rate_limit_score"`
}

type filePerformanceConfig struct {
	Enabled           *bool `yaml:"enabled"`
	IncludeDefault    *bool `yaml:"include_default"`
	ThirdPartyDefault *bool `yaml:"third_party_default"`
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
	DownloadTimeoutSecs  *int     `yaml:"download_timeout_seconds"`
	MaxParallelParse     *int     `yaml:"max_parallel_parse"`
	KeepRaw              *bool    `yaml:"keep_raw"`
	RawRetentionDays     *int     `yaml:"raw_retention_days"`
	SummaryFile          string   `yaml:"summary_file"`
	IndexMode            string   `yaml:"index_mode"`
	IndexFile            string   `yaml:"index_file"`
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
	FireHOLLevel1URL       string             `yaml:"firehol_level1_url"`
	FireHOLAnonymousURL    string             `yaml:"firehol_anonymous_url"`
	Az0VPNIPURL            string             `yaml:"az0_vpn_ip_url"`
	CloudflareV4URL        string             `yaml:"cloudflare_v4_url"`
	CloudflareV6URL        string             `yaml:"cloudflare_v6_url"`
	FastlyURL              string             `yaml:"fastly_url"`
	AWSIPRangesURL         string             `yaml:"aws_ip_ranges_url"`
	GoogleCloudIPRangesURL string             `yaml:"google_cloud_ip_ranges_url"`
	AzureServiceTagsURL    string             `yaml:"azure_service_tags_url"`
	OracleIPRangesURL      string             `yaml:"oracle_ip_ranges_url"`
	GitHubMetaURL          string             `yaml:"github_meta_url"`
	ApplePrivateRelayURL   string             `yaml:"apple_private_relay_url"`
	GoogleFiVPNGeofeedURL  string             `yaml:"google_fi_vpn_geofeed_url"`
	MullvadRelaysURL       string             `yaml:"mullvad_relays_url"`
	NordVPNServersURL      string             `yaml:"nordvpn_servers_url"`
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

type fileFirewallListsConfig struct {
	Enabled       *bool    `yaml:"enabled"`
	OutputDir     string   `yaml:"output_dir"`
	Countries     []string `yaml:"countries"`
	Companies     []string `yaml:"companies"`
	Scenes        []string `yaml:"scenes"`
	MinConfidence *float64 `yaml:"min_confidence"`
	IncludeIPv4   *bool    `yaml:"include_ipv4"`
	IncludeIPv6   *bool    `yaml:"include_ipv6"`
	WriteEntries  *bool    `yaml:"write_entries"`
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
			OpenAIBaseURL:    "https://api.openai.com/v1",
			OpenAIAPIType:    "responses",
			AnthropicModel:   "claude-sonnet-4-6",
			AnthropicBaseURL: "https://api.anthropic.com",
			AnthropicVersion: "2023-06-01",
			GeminiModel:      "gemini-2.5-flash",
			GeminiBaseURL:    "https://generativelanguage.googleapis.com/v1beta",
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
		Quality: QualityConfig{
			Enabled:                true,
			IncludeDefault:         false,
			AILowConfidence:        true,
			LowConfidenceThreshold: 0.6,
			AllowScore:             80,
			ReviewScore:            60,
			ChallengeScore:         40,
			RateLimitScore:         20,
		},
		Performance: PerformanceConfig{
			Enabled:           true,
			IncludeDefault:    false,
			ThirdPartyDefault: true,
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
			DownloadTimeout:      2 * time.Hour,
			MaxParallelParse:     2,
			KeepRaw:              true,
			RawRetentionDays:     30,
			SummaryFile:          "data/generated/bgp-observations-full.jsonl.gz",
			IndexMode:            "compact",
			IndexFile:            "data/generated/bgp-index.bin",
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
			FireHOLLevel1URL:       "https://iplists.firehol.org/files/firehol_level1.netset",
			Az0VPNIPURL:            "https://az0-vpnip-public.oooninja.com/ip.txt",
			CloudflareV4URL:        "https://www.cloudflare.com/ips-v4",
			CloudflareV6URL:        "https://www.cloudflare.com/ips-v6",
			FastlyURL:              "https://api.fastly.com/public-ip-list",
			AWSIPRangesURL:         "https://ip-ranges.amazonaws.com/ip-ranges.json",
			GoogleCloudIPRangesURL: "https://www.gstatic.com/ipranges/cloud.json",
			AzureServiceTagsURL:    "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519",
			OracleIPRangesURL:      "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json",
			GitHubMetaURL:          "https://api.github.com/meta",
			ApplePrivateRelayURL:   "https://mask-api.icloud.com/egress-ip-ranges.csv",
			GoogleFiVPNGeofeedURL:  "https://www.gstatic.com/fi/bridge/ipgeofeed.txt",
			MullvadRelaysURL:       "https://api.mullvad.net/www/relays/all/",
			NordVPNServersURL:      "https://api.nordvpn.com/v1/servers",
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
		FirewallLists: FirewallListsConfig{
			Enabled:       true,
			OutputDir:     "data/generated/firewall",
			Scenes:        []string{"IDC", "CDN", "TOR", "PROXY", "BLOCKLIST"},
			MinConfidence: 0.8,
			IncludeIPv4:   true,
			IncludeIPv6:   true,
			WriteEntries:  false,
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
	bgpDownloadTimeoutSeconds := int(cfg.BGP.DownloadTimeout / time.Second)
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
			OpenAIAPIType:    cfg.AI.OpenAIAPIType,
			AnthropicAPIKey:  cfg.AI.AnthropicAPIKey,
			AnthropicModel:   cfg.AI.AnthropicModel,
			AnthropicBaseURL: cfg.AI.AnthropicBaseURL,
			AnthropicVersion: cfg.AI.AnthropicVersion,
			GeminiAPIKey:     cfg.AI.GeminiAPIKey,
			GeminiModel:      cfg.AI.GeminiModel,
			GeminiBaseURL:    cfg.AI.GeminiBaseURL,
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
		Quality: fileQualityConfig{
			Enabled:                boolPtr(cfg.Quality.Enabled),
			IncludeDefault:         boolPtr(cfg.Quality.IncludeDefault),
			AILowConfidence:        boolPtr(cfg.Quality.AILowConfidence),
			LowConfidenceThreshold: floatPtr(cfg.Quality.LowConfidenceThreshold),
			AllowScore:             intPtr(cfg.Quality.AllowScore),
			ReviewScore:            intPtr(cfg.Quality.ReviewScore),
			ChallengeScore:         intPtr(cfg.Quality.ChallengeScore),
			RateLimitScore:         intPtr(cfg.Quality.RateLimitScore),
		},
		Performance: filePerformanceConfig{
			Enabled:           boolPtr(cfg.Performance.Enabled),
			IncludeDefault:    boolPtr(cfg.Performance.IncludeDefault),
			ThirdPartyDefault: boolPtr(cfg.Performance.ThirdPartyDefault),
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
			DownloadTimeoutSecs:  intPtr(bgpDownloadTimeoutSeconds),
			MaxParallelParse:     intPtr(cfg.BGP.MaxParallelParse),
			KeepRaw:              boolPtr(cfg.BGP.KeepRaw),
			RawRetentionDays:     intPtr(cfg.BGP.RawRetentionDays),
			SummaryFile:          cfg.BGP.SummaryFile,
			IndexMode:            cfg.BGP.IndexMode,
			IndexFile:            cfg.BGP.IndexFile,
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
			FireHOLLevel1URL:       cfg.DynamicRules.FireHOLLevel1URL,
			FireHOLAnonymousURL:    cfg.DynamicRules.FireHOLAnonymousURL,
			Az0VPNIPURL:            cfg.DynamicRules.Az0VPNIPURL,
			CloudflareV4URL:        cfg.DynamicRules.CloudflareV4URL,
			CloudflareV6URL:        cfg.DynamicRules.CloudflareV6URL,
			FastlyURL:              cfg.DynamicRules.FastlyURL,
			AWSIPRangesURL:         cfg.DynamicRules.AWSIPRangesURL,
			GoogleCloudIPRangesURL: cfg.DynamicRules.GoogleCloudIPRangesURL,
			AzureServiceTagsURL:    cfg.DynamicRules.AzureServiceTagsURL,
			OracleIPRangesURL:      cfg.DynamicRules.OracleIPRangesURL,
			GitHubMetaURL:          cfg.DynamicRules.GitHubMetaURL,
			ApplePrivateRelayURL:   cfg.DynamicRules.ApplePrivateRelayURL,
			GoogleFiVPNGeofeedURL:  cfg.DynamicRules.GoogleFiVPNGeofeedURL,
			MullvadRelaysURL:       cfg.DynamicRules.MullvadRelaysURL,
			NordVPNServersURL:      cfg.DynamicRules.NordVPNServersURL,
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
		FirewallLists: fileFirewallListsConfig{
			Enabled:       boolPtr(cfg.FirewallLists.Enabled),
			OutputDir:     cfg.FirewallLists.OutputDir,
			Countries:     cfg.FirewallLists.Countries,
			Companies:     cfg.FirewallLists.Companies,
			Scenes:        cfg.FirewallLists.Scenes,
			MinConfidence: floatPtr(cfg.FirewallLists.MinConfidence),
			IncludeIPv4:   boolPtr(cfg.FirewallLists.IncludeIPv4),
			IncludeIPv6:   boolPtr(cfg.FirewallLists.IncludeIPv6),
			WriteEntries:  boolPtr(cfg.FirewallLists.WriteEntries),
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
	applyQualityFileConfig(&cfg.Quality, file.Quality)
	applyPerformanceFileConfig(&cfg.Performance, file.Performance)
	applyBGPFileConfig(&cfg.BGP, file.BGP)
	applyAdminFileConfig(&cfg.Admin, file.Admin)
	applyDynamicRulesFileConfig(&cfg.DynamicRules, file.DynamicRules)
	applyIP2RegionFileConfig(&cfg.IP2Region, file.IP2Region)
	applyFirewallListsFileConfig(&cfg.FirewallLists, file.FirewallLists)
	applySourcesFileConfig(&cfg.Sources, file.Sources)
	return nil
}

func applyQualityFileConfig(cfg *QualityConfig, file fileQualityConfig) {
	if file.Enabled != nil {
		cfg.Enabled = *file.Enabled
	}
	if file.IncludeDefault != nil {
		cfg.IncludeDefault = *file.IncludeDefault
	}
	if file.AILowConfidence != nil {
		cfg.AILowConfidence = *file.AILowConfidence
	}
	if file.LowConfidenceThreshold != nil && *file.LowConfidenceThreshold > 0 && *file.LowConfidenceThreshold <= 1 {
		cfg.LowConfidenceThreshold = *file.LowConfidenceThreshold
	}
	if file.AllowScore != nil && *file.AllowScore > 0 && *file.AllowScore <= 100 {
		cfg.AllowScore = *file.AllowScore
	}
	if file.ReviewScore != nil && *file.ReviewScore > 0 && *file.ReviewScore <= 100 {
		cfg.ReviewScore = *file.ReviewScore
	}
	if file.ChallengeScore != nil && *file.ChallengeScore > 0 && *file.ChallengeScore <= 100 {
		cfg.ChallengeScore = *file.ChallengeScore
	}
	if file.RateLimitScore != nil && *file.RateLimitScore > 0 && *file.RateLimitScore <= 100 {
		cfg.RateLimitScore = *file.RateLimitScore
	}
}

func applyPerformanceFileConfig(cfg *PerformanceConfig, file filePerformanceConfig) {
	if file.Enabled != nil {
		cfg.Enabled = *file.Enabled
	}
	if file.IncludeDefault != nil {
		cfg.IncludeDefault = *file.IncludeDefault
	}
	if file.ThirdPartyDefault != nil {
		cfg.ThirdPartyDefault = *file.ThirdPartyDefault
	}
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
	if file.DownloadTimeoutSecs != nil && *file.DownloadTimeoutSecs > 0 {
		cfg.DownloadTimeout = time.Duration(*file.DownloadTimeoutSecs) * time.Second
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
	if file.IndexMode != "" {
		cfg.IndexMode = file.IndexMode
	}
	if file.IndexFile != "" {
		cfg.IndexFile = file.IndexFile
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
	if file.OpenAIAPIType != "" {
		cfg.OpenAIAPIType = file.OpenAIAPIType
	}
	if file.AnthropicAPIKey != "" {
		cfg.AnthropicAPIKey = file.AnthropicAPIKey
	}
	if file.AnthropicModel != "" {
		cfg.AnthropicModel = file.AnthropicModel
	}
	if file.AnthropicBaseURL != "" {
		cfg.AnthropicBaseURL = file.AnthropicBaseURL
	}
	if file.AnthropicVersion != "" {
		cfg.AnthropicVersion = file.AnthropicVersion
	}
	if file.GeminiAPIKey != "" {
		cfg.GeminiAPIKey = file.GeminiAPIKey
	}
	if file.GeminiModel != "" {
		cfg.GeminiModel = file.GeminiModel
	}
	if file.GeminiBaseURL != "" {
		cfg.GeminiBaseURL = file.GeminiBaseURL
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
	normalizeAIConfig(cfg)
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
	if file.FireHOLLevel1URL != "" {
		cfg.FireHOLLevel1URL = file.FireHOLLevel1URL
	}
	if file.FireHOLAnonymousURL != "" {
		cfg.FireHOLAnonymousURL = file.FireHOLAnonymousURL
	}
	if file.Az0VPNIPURL != "" {
		cfg.Az0VPNIPURL = file.Az0VPNIPURL
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
	if file.ApplePrivateRelayURL != "" {
		cfg.ApplePrivateRelayURL = file.ApplePrivateRelayURL
	}
	if file.GoogleFiVPNGeofeedURL != "" {
		cfg.GoogleFiVPNGeofeedURL = file.GoogleFiVPNGeofeedURL
	}
	if file.MullvadRelaysURL != "" {
		cfg.MullvadRelaysURL = file.MullvadRelaysURL
	}
	if file.NordVPNServersURL != "" {
		cfg.NordVPNServersURL = file.NordVPNServersURL
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

func applyFirewallListsFileConfig(cfg *FirewallListsConfig, file fileFirewallListsConfig) {
	if file.Enabled != nil {
		cfg.Enabled = *file.Enabled
	}
	if file.OutputDir != "" {
		cfg.OutputDir = file.OutputDir
	}
	if len(file.Countries) > 0 {
		cfg.Countries = cleanUpperStringSlice(file.Countries)
	}
	if len(file.Companies) > 0 {
		cfg.Companies = cleanStringSlice(file.Companies)
	}
	if len(file.Scenes) > 0 {
		cfg.Scenes = cleanUpperStringSlice(file.Scenes)
	}
	if file.MinConfidence != nil && *file.MinConfidence > 0 && *file.MinConfidence <= 1 {
		cfg.MinConfidence = *file.MinConfidence
	}
	if file.IncludeIPv4 != nil {
		cfg.IncludeIPv4 = *file.IncludeIPv4
	}
	if file.IncludeIPv6 != nil {
		cfg.IncludeIPv6 = *file.IncludeIPv6
	}
	if file.WriteEntries != nil {
		cfg.WriteEntries = *file.WriteEntries
	}
	normalizeFirewallListsConfig(cfg)
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
	if value := os.Getenv("OPENAI_API_TYPE"); value != "" {
		cfg.AI.OpenAIAPIType = value
	}
	if value := os.Getenv("ANTHROPIC_API_KEY"); value != "" {
		cfg.AI.AnthropicAPIKey = value
	}
	if value := os.Getenv("ANTHROPIC_MODEL"); value != "" {
		cfg.AI.AnthropicModel = value
	}
	if value := os.Getenv("ANTHROPIC_BASE_URL"); value != "" {
		cfg.AI.AnthropicBaseURL = value
	}
	if value := os.Getenv("ANTHROPIC_VERSION"); value != "" {
		cfg.AI.AnthropicVersion = value
	}
	if value := os.Getenv("GEMINI_API_KEY"); value != "" {
		cfg.AI.GeminiAPIKey = value
	}
	if value := os.Getenv("GEMINI_MODEL"); value != "" {
		cfg.AI.GeminiModel = value
	}
	if value := os.Getenv("GEMINI_BASE_URL"); value != "" {
		cfg.AI.GeminiBaseURL = value
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
	if value := os.Getenv("QUALITY_ENABLED"); value != "" {
		cfg.Quality.Enabled = parseEnvBool(value)
	}
	if value := os.Getenv("QUALITY_INCLUDE_DEFAULT"); value != "" {
		cfg.Quality.IncludeDefault = parseEnvBool(value)
	}
	if value := os.Getenv("QUALITY_AI_LOW_CONFIDENCE"); value != "" {
		cfg.Quality.AILowConfidence = parseEnvBool(value)
	}
	if value := os.Getenv("QUALITY_LOW_CONFIDENCE_THRESHOLD"); value != "" {
		if parsed, err := strconv.ParseFloat(value, 64); err == nil && parsed > 0 && parsed <= 1 {
			cfg.Quality.LowConfidenceThreshold = parsed
		}
	}
	if value := os.Getenv("QUALITY_ALLOW_SCORE"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 && parsed <= 100 {
			cfg.Quality.AllowScore = parsed
		}
	}
	if value := os.Getenv("QUALITY_REVIEW_SCORE"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 && parsed <= 100 {
			cfg.Quality.ReviewScore = parsed
		}
	}
	if value := os.Getenv("QUALITY_CHALLENGE_SCORE"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 && parsed <= 100 {
			cfg.Quality.ChallengeScore = parsed
		}
	}
	if value := os.Getenv("QUALITY_RATE_LIMIT_SCORE"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 && parsed <= 100 {
			cfg.Quality.RateLimitScore = parsed
		}
	}
	if value := os.Getenv("PERFORMANCE_ENABLED"); value != "" {
		cfg.Performance.Enabled = parseEnvBool(value)
	}
	if value := os.Getenv("PERFORMANCE_INCLUDE_DEFAULT"); value != "" {
		cfg.Performance.IncludeDefault = parseEnvBool(value)
	}
	if value := os.Getenv("PERFORMANCE_THIRD_PARTY_DEFAULT"); value != "" {
		cfg.Performance.ThirdPartyDefault = parseEnvBool(value)
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
	if value := os.Getenv("BGP_DOWNLOAD_TIMEOUT_SECONDS"); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 {
			cfg.BGP.DownloadTimeout = time.Duration(parsed) * time.Second
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
	if value := os.Getenv("BGP_INDEX_MODE"); value != "" {
		cfg.BGP.IndexMode = value
	}
	if value := os.Getenv("BGP_INDEX_FILE"); value != "" {
		cfg.BGP.IndexFile = value
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
	if value := os.Getenv("FIREHOL_LEVEL1_URL"); value != "" {
		cfg.DynamicRules.FireHOLLevel1URL = value
	}
	if value := os.Getenv("FIREHOL_ANONYMOUS_URL"); value != "" {
		cfg.DynamicRules.FireHOLAnonymousURL = value
	}
	if value := os.Getenv("AZ0_VPN_IP_URL"); value != "" {
		cfg.DynamicRules.Az0VPNIPURL = value
	}
	if value := os.Getenv("APPLE_PRIVATE_RELAY_URL"); value != "" {
		cfg.DynamicRules.ApplePrivateRelayURL = value
	}
	if value := os.Getenv("GOOGLE_FI_VPN_GEOFEED_URL"); value != "" {
		cfg.DynamicRules.GoogleFiVPNGeofeedURL = value
	}
	if value := os.Getenv("MULLVAD_RELAYS_URL"); value != "" {
		cfg.DynamicRules.MullvadRelaysURL = value
	}
	if value := os.Getenv("NORDVPN_SERVERS_URL"); value != "" {
		cfg.DynamicRules.NordVPNServersURL = value
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
	if value := os.Getenv("FIREWALL_LISTS_ENABLED"); value != "" {
		cfg.FirewallLists.Enabled = parseEnvBool(value)
	}
	if value := os.Getenv("FIREWALL_LISTS_OUTPUT_DIR"); value != "" {
		cfg.FirewallLists.OutputDir = value
	}
	if value := os.Getenv("FIREWALL_LISTS_COUNTRIES"); value != "" {
		cfg.FirewallLists.Countries = cleanUpperStringSlice(splitList(value))
	}
	if value := os.Getenv("FIREWALL_LISTS_COMPANIES"); value != "" {
		cfg.FirewallLists.Companies = splitList(value)
	}
	if value := os.Getenv("FIREWALL_LISTS_SCENES"); value != "" {
		cfg.FirewallLists.Scenes = cleanUpperStringSlice(splitList(value))
	}
	if value := os.Getenv("FIREWALL_LISTS_MIN_CONFIDENCE"); value != "" {
		if parsed, err := strconv.ParseFloat(value, 64); err == nil && parsed > 0 && parsed <= 1 {
			cfg.FirewallLists.MinConfidence = parsed
		}
	}
	if value := os.Getenv("FIREWALL_LISTS_INCLUDE_IPV4"); value != "" {
		cfg.FirewallLists.IncludeIPv4 = parseEnvBool(value)
	}
	if value := os.Getenv("FIREWALL_LISTS_INCLUDE_IPV6"); value != "" {
		cfg.FirewallLists.IncludeIPv6 = parseEnvBool(value)
	}
	if value := os.Getenv("FIREWALL_LISTS_WRITE_ENTRIES"); value != "" {
		cfg.FirewallLists.WriteEntries = parseEnvBool(value)
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
	normalizeAIConfig(&cfg.AI)
	normalizeBGPConfig(&cfg.BGP)
	normalizeAdminConfig(&cfg.Admin)
	normalizeFirewallListsConfig(&cfg.FirewallLists)
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

func cleanUpperStringSlice(parts []string) []string {
	out := cleanStringSlice(parts)
	for i := range out {
		out[i] = strings.ToUpper(out[i])
	}
	return out
}

func parseEnvBool(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	return normalized != "0" && normalized != "false" && normalized != "no" && normalized != "off"
}

func normalizeAIConfig(cfg *AIConfig) {
	cfg.Provider = strings.ToLower(strings.TrimSpace(cfg.Provider))
	switch cfg.Provider {
	case "", "auto":
		cfg.Provider = "auto"
	case "off", "openai", "anthropic", "gemini":
	default:
		cfg.Provider = "auto"
	}
	if strings.TrimSpace(cfg.OpenAIModel) == "" {
		cfg.OpenAIModel = "gpt-5.4-mini"
	}
	if strings.TrimSpace(cfg.OpenAIBaseURL) == "" {
		cfg.OpenAIBaseURL = "https://api.openai.com/v1"
	}
	cfg.OpenAIAPIType = strings.ToLower(strings.TrimSpace(cfg.OpenAIAPIType))
	switch cfg.OpenAIAPIType {
	case "", "responses":
		cfg.OpenAIAPIType = "responses"
	case "chat_completions":
	default:
		cfg.OpenAIAPIType = "responses"
	}
	if strings.TrimSpace(cfg.AnthropicModel) == "" {
		cfg.AnthropicModel = "claude-sonnet-4-6"
	}
	if strings.TrimSpace(cfg.AnthropicBaseURL) == "" {
		cfg.AnthropicBaseURL = "https://api.anthropic.com"
	}
	if strings.TrimSpace(cfg.AnthropicVersion) == "" {
		cfg.AnthropicVersion = "2023-06-01"
	}
	if strings.TrimSpace(cfg.GeminiModel) == "" {
		cfg.GeminiModel = "gemini-2.5-flash"
	}
	if strings.TrimSpace(cfg.GeminiBaseURL) == "" {
		cfg.GeminiBaseURL = "https://generativelanguage.googleapis.com/v1beta"
	}
	if cfg.ConfidenceCutoff <= 0 || cfg.ConfidenceCutoff > 1 {
		cfg.ConfidenceCutoff = 0.7
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 8 * time.Second
	}
	if cfg.MaxCache <= 0 {
		cfg.MaxCache = 2048
	}
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
	if cfg.DownloadTimeout <= 0 {
		cfg.DownloadTimeout = 2 * time.Hour
	}
	if cfg.MaxParallelParse <= 0 {
		cfg.MaxParallelParse = 1
	}
	if cfg.SummaryFile == "" {
		cfg.SummaryFile = "data/generated/bgp-observations-full.jsonl.gz"
	}
	cfg.IndexMode = strings.ToLower(strings.TrimSpace(cfg.IndexMode))
	if cfg.IndexMode == "" {
		cfg.IndexMode = "compact"
	}
	if cfg.IndexFile == "" {
		cfg.IndexFile = "data/generated/bgp-index.bin"
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

func normalizeFirewallListsConfig(cfg *FirewallListsConfig) {
	if strings.TrimSpace(cfg.OutputDir) == "" {
		cfg.OutputDir = filepath.Join("data", "generated", "firewall")
	}
	if cfg.MinConfidence <= 0 || cfg.MinConfidence > 1 {
		cfg.MinConfidence = 0.8
	}
	if !cfg.IncludeIPv4 && !cfg.IncludeIPv6 {
		cfg.IncludeIPv4 = true
		cfg.IncludeIPv6 = true
	}
	if len(cfg.Scenes) == 0 {
		cfg.Scenes = []string{"IDC", "CDN", "TOR", "PROXY", "BLOCKLIST"}
	} else {
		cfg.Scenes = cleanUpperStringSlice(cfg.Scenes)
	}
	cfg.Countries = cleanUpperStringSlice(cfg.Countries)
	cfg.Companies = cleanStringSlice(cfg.Companies)
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
