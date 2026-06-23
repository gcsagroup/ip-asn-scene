package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	svcmanager "github.com/kardianos/service"
	"ipasn/internal/ai"
	"ipasn/internal/classify"
	"ipasn/internal/config"
	"ipasn/internal/enrich"
	"ipasn/internal/firewall"
	"ipasn/internal/geo"
	"ipasn/internal/httpapi"
	"ipasn/internal/lookup"
	"ipasn/internal/quality"
	"ipasn/internal/update"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	configPath := configPathFromArgs(args)
	cfg, err := config.LoadFromFile(configPath)
	if err != nil {
		log.Printf("config load failed: %v", err)
		return 1
	}

	fs := flag.NewFlagSet("ipasn", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	downloadOnly := fs.Bool("download-only", false, "download offline databases, build index, then exit")
	updateOnStart := fs.Bool("update-on-start", false, "download offline databases before serving")
	generateFirewallLists := fs.Bool("generate-firewall-lists", false, "generate offline firewall CIDR lists from ip2region and local rules")
	forceConsole := fs.Bool("console", false, "run in console mode even without a terminal")
	installService := fs.Bool("install-service", false, "install as an operating system service")
	uninstallService := fs.Bool("uninstall-service", false, "uninstall the operating system service")
	serviceName := fs.String("service-name", "ipasn", "operating system service name")
	serviceDisplayName := fs.String("service-display-name", "IP ASN Scene Service", "operating system service display name")
	serviceDescription := fs.String("service-description", "IP and ASN scene lookup service", "operating system service description")
	fs.StringVar(&configPath, "config", configPath, "YAML config file")
	fs.StringVar(&cfg.Addr, "addr", cfg.Addr, "HTTP bind address")
	fs.StringVar(&cfg.DataDir, "data-dir", cfg.DataDir, "data directory")
	fs.StringVar(&cfg.RulesFile, "rules-file", cfg.RulesFile, "offline service rules file")
	fs.StringVar(&cfg.ASNRulesFile, "asn-rules-file", cfg.ASNRulesFile, "ASN scene rules file")
	fs.BoolVar(&cfg.TLS.Enabled, "tls", cfg.TLS.Enabled, "enable HTTPS")
	fs.StringVar(&cfg.TLS.CertFile, "tls-cert", cfg.TLS.CertFile, "TLS certificate file")
	fs.StringVar(&cfg.TLS.CertFile, "tls-cert-file", cfg.TLS.CertFile, "TLS certificate file")
	fs.StringVar(&cfg.TLS.KeyFile, "tls-key", cfg.TLS.KeyFile, "TLS private key file")
	fs.StringVar(&cfg.TLS.KeyFile, "tls-key-file", cfg.TLS.KeyFile, "TLS private key file")
	fs.StringVar(&cfg.AI.Provider, "ai-provider", cfg.AI.Provider, "AI provider: auto, off, openai, anthropic, gemini")
	fs.StringVar(&cfg.AI.OpenAIModel, "openai-model", cfg.AI.OpenAIModel, "OpenAI model")
	fs.StringVar(&cfg.AI.OpenAIBaseURL, "openai-base-url", cfg.AI.OpenAIBaseURL, "OpenAI-compatible base URL")
	fs.StringVar(&cfg.AI.OpenAIAPIType, "openai-api-type", cfg.AI.OpenAIAPIType, "OpenAI API type: responses or chat_completions")
	fs.StringVar(&cfg.AI.AnthropicModel, "anthropic-model", cfg.AI.AnthropicModel, "Anthropic model")
	fs.StringVar(&cfg.AI.AnthropicBaseURL, "anthropic-base-url", cfg.AI.AnthropicBaseURL, "Anthropic base URL")
	fs.StringVar(&cfg.AI.GeminiModel, "gemini-model", cfg.AI.GeminiModel, "Gemini model")
	fs.StringVar(&cfg.AI.GeminiBaseURL, "gemini-base-url", cfg.AI.GeminiBaseURL, "Gemini base URL")
	fs.BoolVar(&cfg.Enrichment.Enabled, "enrichment", cfg.Enrichment.Enabled, "enable online enrichment for unannounced allocated IPs")
	fs.BoolVar(&cfg.Enrichment.AsyncOnMiss, "enrichment-async-on-miss", cfg.Enrichment.AsyncOnMiss, "return cached/offline results immediately and refresh online enrichment in background")
	enrichmentForegroundTimeoutMS := fs.Int("enrichment-foreground-timeout-ms", int(cfg.Enrichment.ForegroundTimeout/time.Millisecond), "foreground wait budget for online enrichment cache misses")
	fs.IntVar(&cfg.History.Snapshots, "history-snapshots", cfg.History.Snapshots, "recent CAIDA BGP snapshots to keep for history lookup")
	fs.BoolVar(&cfg.IP2Region.Enabled, "ip2region", cfg.IP2Region.Enabled, "enable ip2region location lookup")
	fs.BoolVar(&cfg.IP2Region.IncludeDefault, "include-location-default", cfg.IP2Region.IncludeDefault, "include IP location by default")
	fs.StringVar(&cfg.IP2Region.V4File, "ip2region-v4-file", cfg.IP2Region.V4File, "ip2region IPv4 xdb file")
	fs.StringVar(&cfg.IP2Region.V6File, "ip2region-v6-file", cfg.IP2Region.V6File, "ip2region IPv6 xdb file")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if *enrichmentForegroundTimeoutMS >= 0 {
		cfg.Enrichment.ForegroundTimeout = time.Duration(*enrichmentForegroundTimeoutMS) * time.Millisecond
	}

	if *generateFirewallLists {
		ctx, cancel := signal.NotifyContext(context.Background(), shutdownSignals()...)
		defer cancel()
		if err := generateFirewallListsCommand(ctx, cfg); err != nil {
			log.Printf("firewall list generation failed: %v", err)
			return 1
		}
		return 0
	}

	program := &serviceProgram{cfg: cfg, downloadOnly: *downloadOnly, updateOnStart: *updateOnStart}
	if *installService || *uninstallService {
		svcConfig, err := newServiceConfig(*serviceName, *serviceDisplayName, *serviceDescription, configPath, *updateOnStart, *installService)
		if err != nil {
			log.Printf("service config failed: %v", err)
			return 1
		}
		svc, err := svcmanager.New(program, svcConfig)
		if err != nil {
			log.Printf("service setup failed: %v", err)
			return 1
		}
		if *installService {
			if err := svc.Install(); err != nil {
				log.Printf("service install failed: %v", err)
				return 1
			}
			fmt.Printf("service installed: %s\n", *serviceName)
			return 0
		}
		if err := svc.Uninstall(); err != nil {
			log.Printf("service uninstall failed: %v", err)
			return 1
		}
		fmt.Printf("service uninstalled: %s\n", *serviceName)
		return 0
	}

	if !*forceConsole && !svcmanager.Interactive() {
		svcConfig, err := newServiceConfig(*serviceName, *serviceDisplayName, *serviceDescription, configPath, *updateOnStart, false)
		if err != nil {
			log.Printf("service config failed: %v", err)
			return 1
		}
		svc, err := svcmanager.New(program, svcConfig)
		if err != nil {
			log.Printf("service setup failed: %v", err)
			return 1
		}
		if err := svc.Run(); err != nil {
			log.Printf("service run failed: %v", err)
			return 1
		}
		return 0
	}

	ctx, stop := signal.NotifyContext(context.Background(), shutdownSignals()...)
	defer stop()
	if err := serve(ctx, cfg, *downloadOnly, *updateOnStart); err != nil {
		log.Printf("%v", err)
		return 1
	}
	return 0
}

func serve(ctx context.Context, cfg config.Config, downloadOnly, updateOnStart bool) error {
	loadServiceRules(cfg)

	manager := update.NewManager(cfg)
	if downloadOnly || updateOnStart {
		if err := manager.Refresh(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("database update failed: %w", err)
		}
		loadServiceRules(cfg)
		if downloadOnly {
			status := manager.Status()
			fmt.Printf("downloaded database: prefixes=%d asns=%d data_dir=%s\n", status.PrefixCount, status.ASNCount, status.DataDir)
			return nil
		}
	}
	if err := validateTLSConfig(cfg); err != nil {
		return err
	}

	manager.StartAutoUpdate(ctx)
	advisor := buildAdvisor(cfg)
	lookupService := lookup.NewServiceFromProviderWithOptions(manager, lookup.Options{
		AIAdvisor:          advisor,
		Enricher:           buildEnricher(cfg),
		GeoLocator:         buildGeoLocator(cfg),
		AIConfidenceCutoff: cfg.AI.ConfidenceCutoff,
		QualityConfig:      qualityConfig(cfg),
	})
	server := httpapi.New(httpapi.ServerOptions{
		Lookup:                 lookupService,
		Manager:                manager,
		IncludeLocationDefault: cfg.IP2Region.IncludeDefault,
		Config:                 cfg,
		ConfigStore:            manager,
		RuntimeConfigApplier:   aiRuntimeConfigApplier{service: lookupService},
	})

	httpServer := &http.Server{Addr: cfg.Addr, Handler: server}

	serverErr := make(chan error, 1)
	go func() {
		log.Printf("listening on %s", listenURL(cfg))
		var err error
		if cfg.TLS.Enabled {
			err = httpServer.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		} else {
			err = httpServer.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.HTTPTimeout)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			return err
		}
		select {
		case err := <-serverErr:
			return err
		case <-time.After(time.Second):
			return nil
		}
	case err := <-serverErr:
		return err
	}
}

type aiRuntimeConfigApplier struct {
	service *lookup.Service
}

func (a aiRuntimeConfigApplier) ApplyRuntimeConfig(cfg config.Config) error {
	if a.service == nil {
		return nil
	}
	a.service.SetAIAdvisor(buildAdvisor(cfg), cfg.AI.ConfidenceCutoff)
	return nil
}

func qualityConfig(cfg config.Config) quality.Config {
	return quality.Config{
		Enabled:                cfg.Quality.Enabled,
		IncludeDefault:         cfg.Quality.IncludeDefault,
		AILowConfidence:        cfg.Quality.AILowConfidence,
		LowConfidenceThreshold: cfg.Quality.LowConfidenceThreshold,
		AllowScore:             cfg.Quality.AllowScore,
		ReviewScore:            cfg.Quality.ReviewScore,
		ChallengeScore:         cfg.Quality.ChallengeScore,
		RateLimitScore:         cfg.Quality.RateLimitScore,
	}
}

func generateFirewallListsCommand(ctx context.Context, cfg config.Config) error {
	if !cfg.FirewallLists.Enabled {
		return fmt.Errorf("firewall_lists.enabled is false")
	}
	loadServiceRules(cfg)
	manager := update.NewManager(cfg)
	snapshot := manager.Snapshot()
	summary, err := firewall.GenerateFromIP2Region(ctx, cfg, snapshot)
	if err != nil {
		return err
	}
	fmt.Printf("generated firewall lists: records=%d exported=%d files=%d output_dir=%s\n",
		summary.TotalRecords,
		summary.ExportedRecord,
		len(summary.Files),
		cfg.FirewallLists.OutputDir,
	)
	return nil
}

type serviceProgram struct {
	cfg           config.Config
	downloadOnly  bool
	updateOnStart bool

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan error
}

func (p *serviceProgram) Start(_ svcmanager.Service) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done != nil {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.done = make(chan error, 1)
	go func() {
		p.done <- serve(ctx, p.cfg, p.downloadOnly, p.updateOnStart)
	}()
	return nil
}

func (p *serviceProgram) Stop(_ svcmanager.Service) error {
	p.mu.Lock()
	cancel := p.cancel
	done := p.done
	p.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done == nil {
		return nil
	}
	select {
	case err := <-done:
		return err
	case <-time.After(30 * time.Second):
		return fmt.Errorf("service stop timeout")
	}
}

func configPathFromArgs(args []string) string {
	for index, arg := range args {
		switch {
		case arg == "-config" || arg == "--config":
			if index+1 < len(args) {
				return args[index+1]
			}
		case strings.HasPrefix(arg, "-config="):
			return strings.TrimPrefix(arg, "-config=")
		case strings.HasPrefix(arg, "--config="):
			return strings.TrimPrefix(arg, "--config=")
		}
	}
	return ""
}

func newServiceConfig(name, displayName, description, configPath string, updateOnStart, requireConfig bool) (*svcmanager.Config, error) {
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("service name is required")
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve executable: %w", err)
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("resolve working directory: %w", err)
	}

	arguments := []string{}
	if resolvedConfigPath, err := resolveServiceConfigPath(configPath, requireConfig); err != nil {
		return nil, err
	} else if resolvedConfigPath != "" {
		arguments = append(arguments, "-config", resolvedConfigPath)
	}
	if updateOnStart {
		arguments = append(arguments, "-update-on-start")
	}

	cfg := &svcmanager.Config{
		Name:             name,
		DisplayName:      displayName,
		Description:      description,
		Executable:       executable,
		Arguments:        arguments,
		WorkingDirectory: workingDirectory,
		Option:           serviceOptions(),
	}
	if runtime.GOOS == "linux" {
		cfg.Dependencies = []string{
			"After=network-online.target",
			"Wants=network-online.target",
		}
	}
	return cfg, nil
}

func resolveServiceConfigPath(configPath string, requireConfig bool) (string, error) {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		if !requireConfig {
			return "", nil
		}
		configPath = "config.yaml"
	}
	absPath, err := filepath.Abs(configPath)
	if err != nil {
		return "", fmt.Errorf("resolve config file: %w", err)
	}
	if _, err := os.Stat(absPath); err != nil {
		return "", fmt.Errorf("config file is not readable: %w", err)
	}
	return absPath, nil
}

func serviceOptions() svcmanager.KeyValue {
	options := svcmanager.KeyValue{}
	switch runtime.GOOS {
	case "linux":
		options["Restart"] = "always"
		options["LimitNOFILE"] = 1048576
	case "windows":
		options["StartType"] = "automatic"
		options["DelayedAutoStart"] = true
		options["OnFailure"] = "restart"
		options["OnFailureDelayDuration"] = "5s"
	}
	return options
}

func validateTLSConfig(cfg config.Config) error {
	if !cfg.TLS.Enabled {
		return nil
	}
	if strings.TrimSpace(cfg.TLS.CertFile) == "" || strings.TrimSpace(cfg.TLS.KeyFile) == "" {
		return fmt.Errorf("TLS is enabled but cert_file or key_file is empty")
	}
	if _, err := os.Stat(cfg.TLS.CertFile); err != nil {
		return fmt.Errorf("TLS cert file is not readable: %w", err)
	}
	if _, err := os.Stat(cfg.TLS.KeyFile); err != nil {
		return fmt.Errorf("TLS key file is not readable: %w", err)
	}
	return nil
}

func listenURL(cfg config.Config) string {
	scheme := "http"
	if cfg.TLS.Enabled {
		scheme = "https"
	}
	addr := cfg.Addr
	if strings.HasPrefix(addr, ":") {
		addr = "localhost" + addr
	}
	return scheme + "://" + addr
}

func loadServiceRules(cfg config.Config) {
	paths := []string{}
	if cfg.RulesFile != "" {
		if _, err := os.Stat(cfg.RulesFile); err != nil && !os.IsNotExist(err) {
			log.Printf("service rules stat failed: %v", err)
		}
		paths = append(paths, cfg.RulesFile)
	}
	if cfg.DynamicRules.Enabled {
		paths = append(paths, update.DynamicServiceRulesPath(cfg))
	}
	if len(paths) == 0 {
		return
	}
	if err := classify.LoadServiceRuleFiles(paths...); err != nil {
		log.Printf("service rules load failed: %v", err)
	}
	if strings.TrimSpace(cfg.ASNRulesFile) != "" {
		if err := classify.LoadASNSceneRuleFiles(cfg.ASNRulesFile); err != nil {
			log.Printf("ASN scene rules load failed: %v", err)
		}
	}
}

func buildEnricher(cfg config.Config) lookup.Enricher {
	if !cfg.Enrichment.Enabled {
		return nil
	}
	return enrich.NewClient(enrich.Config{
		CacheDir:          filepath.Join(cfg.DataDir, "cache", "enrich"),
		TTL:               cfg.Enrichment.TTL,
		Timeout:           cfg.Enrichment.Timeout,
		AsyncOnMiss:       cfg.Enrichment.AsyncOnMiss,
		ForegroundTimeout: cfg.Enrichment.ForegroundTimeout,
	})
}

func buildGeoLocator(cfg config.Config) geo.Locator {
	locators := []geo.Locator{}
	geofeedLocator, err := geo.NewGeofeedLocatorFromDir(cfg.DataDir)
	if err != nil {
		log.Printf("geofeed load failed: %v", err)
	} else if geofeedLocator != nil {
		locators = append(locators, geofeedLocator)
	}
	ip2regionLocator, err := geo.NewIP2RegionLocator(cfg.IP2Region)
	if err != nil {
		log.Printf("ip2region load failed: %v", err)
	} else if ip2regionLocator != nil {
		locators = append(locators, ip2regionLocator)
	}
	return geo.NewCompositeLocator(locators...)
}

func buildAdvisor(cfg config.Config) ai.Advisor {
	switch strings.ToLower(strings.TrimSpace(cfg.AI.Provider)) {
	case "off":
		return nil
	case "openai":
		return buildOpenAIAdvisor(cfg, true)
	case "anthropic":
		return buildAnthropicAdvisor(cfg, true)
	case "gemini":
		return buildGeminiAdvisor(cfg, true)
	default:
		if cfg.AI.OpenAIAPIKey != "" {
			return buildOpenAIAdvisor(cfg, false)
		}
		if cfg.AI.AnthropicAPIKey != "" {
			return buildAnthropicAdvisor(cfg, false)
		}
		if cfg.AI.GeminiAPIKey != "" {
			return buildGeminiAdvisor(cfg, false)
		}
		return nil
	}
}

func buildOpenAIAdvisor(cfg config.Config, logMissing bool) ai.Advisor {
	if strings.TrimSpace(cfg.AI.OpenAIAPIKey) == "" {
		if logMissing {
			log.Printf("AI provider openai selected, but OPENAI_API_KEY is empty")
		}
		return nil
	}
	return ai.NewOpenAIAdvisor(ai.Config{
		APIKey:   cfg.AI.OpenAIAPIKey,
		Model:    cfg.AI.OpenAIModel,
		BaseURL:  cfg.AI.OpenAIBaseURL,
		APIType:  cfg.AI.OpenAIAPIType,
		Timeout:  cfg.AI.Timeout,
		MaxCache: cfg.AI.MaxCache,
	})
}

func buildAnthropicAdvisor(cfg config.Config, logMissing bool) ai.Advisor {
	if strings.TrimSpace(cfg.AI.AnthropicAPIKey) == "" {
		if logMissing {
			log.Printf("AI provider anthropic selected, but ANTHROPIC_API_KEY is empty")
		}
		return nil
	}
	return ai.NewAnthropicAdvisor(ai.Config{
		APIKey:   cfg.AI.AnthropicAPIKey,
		Model:    cfg.AI.AnthropicModel,
		BaseURL:  cfg.AI.AnthropicBaseURL,
		Version:  cfg.AI.AnthropicVersion,
		Timeout:  cfg.AI.Timeout,
		MaxCache: cfg.AI.MaxCache,
	})
}

func buildGeminiAdvisor(cfg config.Config, logMissing bool) ai.Advisor {
	if strings.TrimSpace(cfg.AI.GeminiAPIKey) == "" {
		if logMissing {
			log.Printf("AI provider gemini selected, but GEMINI_API_KEY is empty")
		}
		return nil
	}
	return ai.NewGeminiAdvisor(ai.Config{
		APIKey:   cfg.AI.GeminiAPIKey,
		Model:    cfg.AI.GeminiModel,
		BaseURL:  cfg.AI.GeminiBaseURL,
		Timeout:  cfg.AI.Timeout,
		MaxCache: cfg.AI.MaxCache,
	})
}
