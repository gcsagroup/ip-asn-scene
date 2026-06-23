package httpapi

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"ipasn/internal/ai"
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

type RuntimeConfigApplier interface {
	ApplyRuntimeConfig(config.Config) error
}

type ServerOptions struct {
	Lookup                 *lookup.Service
	Manager                Manager
	IncludeLocationDefault bool
	Config                 config.Config
	ConfigStore            ConfigStore
	RuntimeConfigApplier   RuntimeConfigApplier
}

type Server struct {
	mux                    *http.ServeMux
	lookup                 *lookup.Service
	manager                Manager
	includeLocationDefault bool
	cfg                    config.Config
	configStore            ConfigStore
	runtimeConfigApplier   RuntimeConfigApplier
	modelCacheMu           sync.Mutex
	modelCache             map[string]cachedAIModels
}

type cachedAIModels struct {
	provider  string
	models    []ai.ModelInfo
	expiresAt time.Time
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
		runtimeConfigApplier:   options.RuntimeConfigApplier,
		modelCache:             map[string]cachedAIModels{},
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
		s.mux.HandleFunc("/api/admin/ai/models", s.adminAIModelsHandler)
		s.mux.HandleFunc("/api/admin/status", s.adminStatusHandler)
		s.mux.HandleFunc("/api/admin/update", s.adminUpdateHandler)
	}
	s.mux.HandleFunc("/", s.index)
	s.mux.HandleFunc("/favicon.ico", s.favicon)
	s.mux.HandleFunc("/api/lookup", s.lookupHandler)
	s.mux.HandleFunc("/api/quality", s.qualityHandler)
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
		runtimeApplied := false
		if s.runtimeConfigApplier != nil {
			if err := s.runtimeConfigApplier.ApplyRuntimeConfig(updated); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
				return
			}
			runtimeApplied = true
		}
		s.cfg = updated
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "restart_required": true, "runtime_applied": runtimeApplied, "config": publicConfig(updated)})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

type adminAIModelsRequest struct {
	Provider string `json:"provider"`
	APIKey   string `json:"api_key"`
	BaseURL  string `json:"base_url"`
	Version  string `json:"version"`
}

func (s *Server) adminAIModelsHandler(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r, true) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var request adminAIModelsRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &request); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
			return
		}
	}
	listConfig, err := s.modelListConfig(request)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	currentModel := configuredAIModel(s.currentConfig().AI, listConfig.Provider)
	cacheKey := modelCacheKey(listConfig)
	if cached, ok := s.getCachedAIModels(cacheKey); ok {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":       true,
			"provider": listConfig.Provider,
			"source":   "cache",
			"models":   ai.MergeModelOptions(listConfig.Provider, currentModel, cached.models),
		})
		return
	}
	models, err := ai.ListModels(r.Context(), listConfig)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":       true,
			"provider": listConfig.Provider,
			"source":   "fallback",
			"error":    sanitizeAIModelError(err),
			"models":   ai.MergeModelOptions(listConfig.Provider, currentModel, nil),
		})
		return
	}
	s.setCachedAIModels(cacheKey, listConfig.Provider, models)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"provider": listConfig.Provider,
		"source":   "online",
		"models":   ai.MergeModelOptions(listConfig.Provider, currentModel, models),
	})
}

func (s *Server) modelListConfig(request adminAIModelsRequest) (ai.ModelListConfig, error) {
	cfg := s.currentConfig()
	provider := strings.ToLower(strings.TrimSpace(request.Provider))
	if provider == "" || provider == "auto" {
		provider = firstConfiguredAIProvider(cfg.AI)
	}
	listConfig := ai.ModelListConfig{
		Provider: provider,
		Timeout:  cfg.AI.Timeout,
	}
	switch provider {
	case "openai":
		listConfig.APIKey = firstNonEmptyString(request.APIKey, cfg.AI.OpenAIAPIKey)
		listConfig.BaseURL = firstNonEmptyString(request.BaseURL, cfg.AI.OpenAIBaseURL)
	case "anthropic":
		listConfig.APIKey = firstNonEmptyString(request.APIKey, cfg.AI.AnthropicAPIKey)
		listConfig.BaseURL = firstNonEmptyString(request.BaseURL, cfg.AI.AnthropicBaseURL)
		listConfig.Version = firstNonEmptyString(request.Version, cfg.AI.AnthropicVersion)
	case "gemini":
		listConfig.APIKey = firstNonEmptyString(request.APIKey, cfg.AI.GeminiAPIKey)
		listConfig.BaseURL = firstNonEmptyString(request.BaseURL, cfg.AI.GeminiBaseURL)
	default:
		return ai.ModelListConfig{}, fmt.Errorf("unsupported AI provider %q", provider)
	}
	return listConfig, nil
}

func firstConfiguredAIProvider(cfg config.AIConfig) string {
	if strings.TrimSpace(cfg.OpenAIAPIKey) != "" {
		return "openai"
	}
	if strings.TrimSpace(cfg.AnthropicAPIKey) != "" {
		return "anthropic"
	}
	if strings.TrimSpace(cfg.GeminiAPIKey) != "" {
		return "gemini"
	}
	return strings.ToLower(strings.TrimSpace(cfg.Provider))
}

func configuredAIModel(cfg config.AIConfig, provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "openai":
		return cfg.OpenAIModel
	case "anthropic":
		return cfg.AnthropicModel
	case "gemini":
		return cfg.GeminiModel
	default:
		return ""
	}
}

func sanitizeAIModelError(err error) string {
	if err == nil {
		return ""
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "api key") || strings.Contains(message, "unauthorized") || strings.Contains(message, "forbidden") || strings.Contains(message, "401") || strings.Contains(message, "403") {
		return "AI provider authentication failed; please check API key and provider settings"
	}
	if strings.Contains(message, "timeout") || strings.Contains(message, "deadline") {
		return "AI provider model list request timed out"
	}
	return "AI provider model list request failed"
}

func modelCacheKey(cfg ai.ModelListConfig) string {
	return strings.Join([]string{
		strings.ToLower(strings.TrimSpace(cfg.Provider)),
		strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/"),
		strings.TrimSpace(cfg.Version),
	}, "\x00")
}

func (s *Server) getCachedAIModels(key string) (cachedAIModels, bool) {
	s.modelCacheMu.Lock()
	defer s.modelCacheMu.Unlock()
	cached, ok := s.modelCache[key]
	if !ok || time.Now().After(cached.expiresAt) {
		if ok {
			delete(s.modelCache, key)
		}
		return cachedAIModels{}, false
	}
	return cached, true
}

func (s *Server) setCachedAIModels(key, provider string, models []ai.ModelInfo) {
	s.modelCacheMu.Lock()
	defer s.modelCacheMu.Unlock()
	copied := append([]ai.ModelInfo(nil), models...)
	s.modelCache[key] = cachedAIModels{
		provider:  provider,
		models:    copied,
		expiresAt: time.Now().Add(10 * time.Minute),
	}
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (s *Server) adminStatusHandler(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAdmin(w, r, true) {
		return
	}
	cfg := s.currentConfig()
	status := map[string]any{"ok": true, "config": publicConfig(cfg)}
	if s.manager != nil {
		database := s.manager.Status()
		status["database"] = database
		status["offline_libraries"] = offlineLibraries(cfg, database)
	} else {
		status["offline_libraries"] = offlineLibraries(cfg, store.Status{DataDir: cfg.DataDir})
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
	value := publicConfigBase(cfg)
	value["defaults"] = publicConfigDefaults()
	value["help"] = configHelp()
	return value
}

func publicConfigBase(cfg config.Config) map[string]any {
	cfg.Admin.Token = ""
	cfg.AI.OpenAIAPIKey = ""
	cfg.AI.AnthropicAPIKey = ""
	cfg.AI.GeminiAPIKey = ""
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
		"quality":               publicQualityConfig(cfg.Quality),
		"performance":           publicPerformanceConfig(cfg.Performance),
		"dynamic_rules":         publicDynamicRulesConfig(cfg.DynamicRules),
		"ip2region":             publicIP2RegionConfig(cfg.IP2Region),
		"bgp":                   publicBGPConfig(cfg.BGP),
		"admin":                 cfg.Admin,
		"sources":               publicSourcesConfig(cfg.Sources),
	}
}

func publicConfigDefaults() map[string]any {
	defaults := publicConfigBase(config.Default())
	if dynamicRules, ok := defaults["dynamic_rules"].(map[string]any); ok {
		dynamicRules["firehol_anonymous_url"] = "https://iplists.firehol.org/files/firehol_anonymous.netset"
	}
	return defaults
}

type configHelpItem struct {
	Group   string `json:"group"`
	Title   string `json:"title"`
	Help    string `json:"help"`
	Impact  string `json:"impact,omitempty"`
	Default string `json:"default,omitempty"`
}

func configHelp() map[string]configHelpItem {
	return map[string]configHelpItem{
		"addr":                                    {Group: "基础配置", Title: "监听地址", Help: "服务监听地址，例如 :18080。修改后需要重启进程生效。", Impact: "影响 Web 页面和 API 访问入口。"},
		"data_dir":                                {Group: "基础配置", Title: "数据目录", Help: "离线库、生成规则、BGP 汇总和缓存的主目录。", Impact: "目录越大，更新和备份成本越高。"},
		"rules_file":                              {Group: "基础配置", Title: "服务规则文件", Help: "手工维护的 DNS、STUN、公共服务、风险网段等规则。", Impact: "明确 CIDR 规则优先级高于弱推断。"},
		"asn_rules_file":                          {Group: "基础配置", Title: "ASN 场景规则", Help: "维护 ASN 级场景种子，适合教育网、政府、运营商、云厂商等粗粒度规则。"},
		"update_interval_hours":                   {Group: "基础配置", Title: "自动更新间隔", Help: "后台自动刷新离线数据的周期，0 表示不自动更新。"},
		"http_timeout_seconds":                    {Group: "基础配置", Title: "HTTP 超时", Help: "下载公开数据源、在线增强和规则更新时的单请求超时时间。"},
		"admin.token":                             {Group: "后台与 SSL", Title: "后台 Token", Help: "配置后访问后台 API 需要 X-Admin-Token。页面会保存在浏览器 localStorage。", Impact: "生产环境建议配置。"},
		"tls.enabled":                             {Group: "后台与 SSL", Title: "启用 HTTPS", Help: "启用后使用证书和私钥提供 HTTPS。修改后需要重启。"},
		"ai.provider":                             {Group: "AI 与在线增强", Title: "AI Provider", Help: "auto 会按 OpenAI、Anthropic、Gemini 的顺序选择已配置 key；off 禁用 AI；也可以固定某个 provider。"},
		"ai.openai_api_type":                      {Group: "AI 与在线增强", Title: "OpenAI 接口类型", Help: "responses 使用 /v1/responses；chat_completions 使用 /v1/chat/completions，适合很多 OpenAI 兼容服务。"},
		"ai.anthropic_model":                      {Group: "AI 与在线增强", Title: "Anthropic 模型", Help: "Claude 模型 ID，可点击模型列表按钮从 Anthropic Models API 获取。"},
		"ai.anthropic_base_url":                   {Group: "AI 与在线增强", Title: "Anthropic Base URL", Help: "默认 https://api.anthropic.com；代理服务可填写自定义地址。"},
		"ai.anthropic_version":                    {Group: "AI 与在线增强", Title: "Anthropic API Version", Help: "Anthropic API 要求的版本请求头，默认 2023-06-01。"},
		"ai.gemini_model":                         {Group: "AI 与在线增强", Title: "Gemini 模型", Help: "Gemini 模型 ID，可点击模型列表按钮从 Gemini Models API 获取。"},
		"ai.gemini_base_url":                      {Group: "AI 与在线增强", Title: "Gemini Base URL", Help: "默认 https://generativelanguage.googleapis.com/v1beta；代理服务可填写自定义地址。"},
		"ai.confidence_cutoff":                    {Group: "AI 与在线增强", Title: "AI 置信度阈值", Help: "低于该阈值时才考虑 AI 辅助，避免把高置信度离线规则交给模型覆盖。"},
		"enrichment.enabled":                      {Group: "AI 与在线增强", Title: "在线增强", Help: "启用 Team Cymru、RIPEstat、RDAP、WHOIS、RIPE RIS 等当前校验。", Impact: "提高准确度，但首次未缓存查询会增加等待或后台刷新。"},
		"enrichment.foreground_timeout_ms":        {Group: "AI 与在线增强", Title: "前台等待时间", Help: "fast 模式下缓存未命中时最多等待多久，超过后先返回离线结果并后台刷新。"},
		"quality.enabled":                         {Group: "IP 质量评分", Title: "启用评分", Help: "根据场景、公开风险源、路由安全、服务策略、数据质量给出 IP 纯净度评分。"},
		"quality.include_default":                 {Group: "IP 质量评分", Title: "默认输出评分", Help: "开启后 /api/lookup 默认返回 ip_quality；关闭时需要 include_quality=1 或调用 /api/quality。"},
		"performance.enabled":                     {Group: "性能指标", Title: "启用性能指标", Help: "允许 /api/lookup 返回本次查询耗时、在线增强耗时和第三方源耗时。"},
		"performance.include_default":             {Group: "性能指标", Title: "默认输出性能指标", Help: "开启后 /api/lookup 默认返回 performance；关闭时需要 include_performance=1。", Impact: "会让响应体变大，生产 API 一般建议按需开启。"},
		"performance.third_party_default":         {Group: "性能指标", Title: "默认输出第三方耗时", Help: "输出 Team Cymru、RIPEstat、RDAP、WHOIS、RIPE RIS 等在线源的单独耗时。", Impact: "只记录当前请求实际等待的第三方调用；缓存命中不会产生第三方明细。"},
		"ip2region.enabled":                       {Group: "IP 所在地库", Title: "启用 ip2region", Help: "启用后查询可返回国家、省市、运营商和库内 ASN。需要配置并下载 XDB 文件。"},
		"ip2region.v4_version_url":                {Group: "IP 所在地库", Title: "IPv4 版本 API", Help: "ip2region 离线库版本检查接口，用于判断本地 XDB 是否需要更新。", Default: "商业授权地址由你提供，不能公开内置。"},
		"ip2region.v4_download_url":               {Group: "IP 所在地库", Title: "IPv4 下载地址", Help: "ip2region IPv4 全载库下载地址。", Default: "商业授权地址由你提供，不能公开内置。"},
		"ip2region.v6_version_url":                {Group: "IP 所在地库", Title: "IPv6 版本 API", Help: "ip2region IPv6 离线库版本检查接口。"},
		"ip2region.v6_download_url":               {Group: "IP 所在地库", Title: "IPv6 下载地址", Help: "ip2region IPv6 全载库下载地址。"},
		"bgp.enabled":                             {Group: "全量 BGP", Title: "启用全量 BGP", Help: "后台下载 RouteViews / RIPE RIS RIB 并生成本地多观察点 BGP 摘要。", Impact: "磁盘和更新时间开销较大，查询阶段只读本地摘要。"},
		"bgp.collectors":                          {Group: "全量 BGP", Title: "Collectors", Help: "all 表示自动选择全部可用 collector；也可以填写指定 collector 名称。"},
		"bgp.download_timeout_seconds":            {Group: "全量 BGP", Title: "RIB 下载超时", Help: "单个 RouteViews / RIPE RIS MRT RIB 大文件下载的超时时间。", Impact: "网络慢或 collector 多时建议调大；只影响 BGP 原始 RIB 下载，不影响普通查询超时。", Default: "7200"},
		"sources.rpki_vrp_urls":                   {Group: "公开离线数据源", Title: "RPKI VRP URLs", Help: "ROA 授权数据，用于判断 RPKI valid/invalid/not_found。"},
		"sources.irr_route_urls":                  {Group: "公开离线数据源", Title: "IRR Route URLs", Help: "IRR route/route6 对象，用于辅助判断 origin ASN 是否与注册路由对象一致。"},
		"sources.bgp_observation_urls":            {Group: "公开离线数据源", Title: "BGP Observation URLs", Help: "外部预处理 BGP 摘要。全量 BGP 模式会本地生成，一般保持为空。"},
		"sources.geofeed_urls":                    {Group: "公开离线数据源", Title: "Geofeed URLs", Help: "RFC 8805 geofeed，用于增强实际所在地，优先级高于 ip2region。"},
		"dynamic_rules.enabled":                   {Group: "动态规则", Title: "启用动态规则", Help: "后台更新时自动拉取公开服务 IP 列表并生成 data/generated/services.json。"},
		"dynamic_rules.firehol_level1_url":        {Group: "动态规则", Title: "FireHOL level1", Help: "低误报风险网段聚合，生成 BLOCKLIST 规则。"},
		"dynamic_rules.firehol_anonymous_url":     {Group: "动态规则", Title: "FireHOL anonymous", Help: "匿名代理/Tor 聚合列表，生成 PROXY 规则。体积较大，默认不自动启用；可用“填充公开默认源”填入。", Impact: "可能扩大代理识别面，拦截策略应结合业务场景。", Default: "https://iplists.firehol.org/files/firehol_anonymous.netset"},
		"dynamic_rules.az0_vpn_ip_url":            {Group: "动态规则", Title: "az0/vpn_ip", Help: "公开 VPN IP 列表，生成 VPN 规则。"},
		"dynamic_rules.apple_private_relay_url":   {Group: "动态规则", Title: "Apple iCloud Private Relay", Help: "Apple 官方隐私代理出口 CSV。技术场景为 PROXY，但服务策略会标记为正常用户隐私流量。"},
		"dynamic_rules.google_fi_vpn_geofeed_url": {Group: "动态规则", Title: "Google Fi VPN Geofeed", Help: "Google Fi VPN geofeed。技术场景为 VPN，但服务策略会标记为运营商隐私服务。"},
		"dynamic_rules.ip2proxy.local_file":       {Group: "动态规则 / IP2Proxy", Title: "IP2Proxy 本地文件", Help: "本地 IP2Proxy CSV 或 ZIP 文件路径。适合商业库手工放置后离线加载。", Default: "没有通用默认路径。"},
		"dynamic_rules.ip2proxy.download_url":     {Group: "动态规则 / IP2Proxy", Title: "IP2Proxy 下载地址", Help: "可填写商业库下载基址或完整下载地址；如果只配置 Token 和 Package，程序会使用 IP2Location 官方下载基址。", Default: "需要授权 Token，不自动公开内置。"},
		"dynamic_rules.ip2proxy.token":            {Group: "动态规则 / IP2Proxy", Title: "IP2Proxy Token", Help: "商业授权 Token。后台不会回显，留空表示不修改。"},
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
		"provider":           cfg.Provider,
		"openai_api_key":     "",
		"openai_model":       cfg.OpenAIModel,
		"openai_base_url":    cfg.OpenAIBaseURL,
		"openai_api_type":    cfg.OpenAIAPIType,
		"anthropic_api_key":  "",
		"anthropic_model":    cfg.AnthropicModel,
		"anthropic_base_url": cfg.AnthropicBaseURL,
		"anthropic_version":  cfg.AnthropicVersion,
		"gemini_api_key":     "",
		"gemini_model":       cfg.GeminiModel,
		"gemini_base_url":    cfg.GeminiBaseURL,
		"confidence_cutoff":  cfg.ConfidenceCutoff,
		"timeout_seconds":    int(cfg.Timeout / time.Second),
		"max_cache":          cfg.MaxCache,
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

func publicQualityConfig(cfg config.QualityConfig) map[string]any {
	return map[string]any{
		"enabled":                  cfg.Enabled,
		"include_default":          cfg.IncludeDefault,
		"ai_low_confidence":        cfg.AILowConfidence,
		"low_confidence_threshold": cfg.LowConfidenceThreshold,
		"allow_score":              cfg.AllowScore,
		"review_score":             cfg.ReviewScore,
		"challenge_score":          cfg.ChallengeScore,
		"rate_limit_score":         cfg.RateLimitScore,
	}
}

func publicPerformanceConfig(cfg config.PerformanceConfig) map[string]any {
	return map[string]any{
		"enabled":             cfg.Enabled,
		"include_default":     cfg.IncludeDefault,
		"third_party_default": cfg.ThirdPartyDefault,
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
		"firehol_level1_url":         cfg.FireHOLLevel1URL,
		"firehol_anonymous_url":      cfg.FireHOLAnonymousURL,
		"az0_vpn_ip_url":             cfg.Az0VPNIPURL,
		"cloudflare_v4_url":          cfg.CloudflareV4URL,
		"cloudflare_v6_url":          cfg.CloudflareV6URL,
		"fastly_url":                 cfg.FastlyURL,
		"aws_ip_ranges_url":          cfg.AWSIPRangesURL,
		"google_cloud_ip_ranges_url": cfg.GoogleCloudIPRangesURL,
		"azure_service_tags_url":     cfg.AzureServiceTagsURL,
		"oracle_ip_ranges_url":       cfg.OracleIPRangesURL,
		"github_meta_url":            cfg.GitHubMetaURL,
		"apple_private_relay_url":    cfg.ApplePrivateRelayURL,
		"google_fi_vpn_geofeed_url":  cfg.GoogleFiVPNGeofeedURL,
		"mullvad_relays_url":         cfg.MullvadRelaysURL,
		"nordvpn_servers_url":        cfg.NordVPNServersURL,
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
		"enabled":                  cfg.Enabled,
		"mode":                     cfg.Mode,
		"routeviews_enabled":       cfg.RouteViewsEnabled,
		"ripe_ris_enabled":         cfg.RIPERISEnabled,
		"collectors":               cfg.Collectors,
		"include_updates":          cfg.IncludeUpdates,
		"history_snapshots":        cfg.HistorySnapshots,
		"refresh_hours":            int(cfg.RefreshInterval / time.Hour),
		"max_parallel_downloads":   cfg.MaxParallelDownloads,
		"download_timeout_seconds": int(cfg.DownloadTimeout / time.Second),
		"max_parallel_parse":       cfg.MaxParallelParse,
		"keep_raw":                 cfg.KeepRaw,
		"raw_retention_days":       cfg.RawRetentionDays,
		"summary_file":             cfg.SummaryFile,
		"index_mode":               cfg.IndexMode,
		"index_file":               cfg.IndexFile,
		"routeviews_base_url":      cfg.RouteViewsBaseURL,
		"ripe_ris_base_url":        cfg.RIPERISBaseURL,
		"month":                    cfg.Month,
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
		OpenAIAPIType    string   `json:"openai_api_type"`
		AnthropicAPIKey  string   `json:"anthropic_api_key"`
		AnthropicModel   string   `json:"anthropic_model"`
		AnthropicBaseURL string   `json:"anthropic_base_url"`
		AnthropicVersion string   `json:"anthropic_version"`
		GeminiAPIKey     string   `json:"gemini_api_key"`
		GeminiModel      string   `json:"gemini_model"`
		GeminiBaseURL    string   `json:"gemini_base_url"`
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
	Quality *struct {
		Enabled                *bool    `json:"enabled"`
		IncludeDefault         *bool    `json:"include_default"`
		AILowConfidence        *bool    `json:"ai_low_confidence"`
		LowConfidenceThreshold *float64 `json:"low_confidence_threshold"`
		AllowScore             *int     `json:"allow_score"`
		ReviewScore            *int     `json:"review_score"`
		ChallengeScore         *int     `json:"challenge_score"`
		RateLimitScore         *int     `json:"rate_limit_score"`
	} `json:"quality"`
	Performance *struct {
		Enabled           *bool `json:"enabled"`
		IncludeDefault    *bool `json:"include_default"`
		ThirdPartyDefault *bool `json:"third_party_default"`
	} `json:"performance"`
	DynamicRules *struct {
		Enabled                *bool    `json:"enabled"`
		File                   string   `json:"file"`
		GoogleCrawlerURL       string   `json:"google_crawler_url"`
		BingbotURL             string   `json:"bingbot_url"`
		TorExitURL             string   `json:"tor_exit_url"`
		UptimeRobotURL         string   `json:"uptimerobot_ip_url"`
		SpamhausDropV4URL      string   `json:"spamhaus_drop_v4_url"`
		SpamhausDropV6URL      string   `json:"spamhaus_drop_v6_url"`
		FireHOLLevel1URL       string   `json:"firehol_level1_url"`
		FireHOLAnonymousURL    string   `json:"firehol_anonymous_url"`
		Az0VPNIPURL            string   `json:"az0_vpn_ip_url"`
		CloudflareV4URL        string   `json:"cloudflare_v4_url"`
		CloudflareV6URL        string   `json:"cloudflare_v6_url"`
		FastlyURL              string   `json:"fastly_url"`
		AWSIPRangesURL         string   `json:"aws_ip_ranges_url"`
		GoogleCloudIPRangesURL string   `json:"google_cloud_ip_ranges_url"`
		AzureServiceTagsURL    string   `json:"azure_service_tags_url"`
		OracleIPRangesURL      string   `json:"oracle_ip_ranges_url"`
		GitHubMetaURL          string   `json:"github_meta_url"`
		ApplePrivateRelayURL   string   `json:"apple_private_relay_url"`
		GoogleFiVPNGeofeedURL  string   `json:"google_fi_vpn_geofeed_url"`
		MullvadRelaysURL       string   `json:"mullvad_relays_url"`
		NordVPNServersURL      string   `json:"nordvpn_servers_url"`
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
		DownloadTimeoutSecs  *int     `json:"download_timeout_seconds"`
		MaxParallelParse     *int     `json:"max_parallel_parse"`
		KeepRaw              *bool    `json:"keep_raw"`
		RawRetentionDays     *int     `json:"raw_retention_days"`
		SummaryFile          string   `json:"summary_file"`
		IndexMode            string   `json:"index_mode"`
		IndexFile            string   `json:"index_file"`
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
		if strings.TrimSpace(patch.AI.OpenAIAPIType) != "" {
			cfg.AI.OpenAIAPIType = strings.TrimSpace(patch.AI.OpenAIAPIType)
		}
		if strings.TrimSpace(patch.AI.AnthropicAPIKey) != "" {
			cfg.AI.AnthropicAPIKey = strings.TrimSpace(patch.AI.AnthropicAPIKey)
		}
		if strings.TrimSpace(patch.AI.AnthropicModel) != "" {
			cfg.AI.AnthropicModel = strings.TrimSpace(patch.AI.AnthropicModel)
		}
		if strings.TrimSpace(patch.AI.AnthropicBaseURL) != "" {
			cfg.AI.AnthropicBaseURL = strings.TrimSpace(patch.AI.AnthropicBaseURL)
		}
		if strings.TrimSpace(patch.AI.AnthropicVersion) != "" {
			cfg.AI.AnthropicVersion = strings.TrimSpace(patch.AI.AnthropicVersion)
		}
		if strings.TrimSpace(patch.AI.GeminiAPIKey) != "" {
			cfg.AI.GeminiAPIKey = strings.TrimSpace(patch.AI.GeminiAPIKey)
		}
		if strings.TrimSpace(patch.AI.GeminiModel) != "" {
			cfg.AI.GeminiModel = strings.TrimSpace(patch.AI.GeminiModel)
		}
		if strings.TrimSpace(patch.AI.GeminiBaseURL) != "" {
			cfg.AI.GeminiBaseURL = strings.TrimSpace(patch.AI.GeminiBaseURL)
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
	if patch.Quality != nil {
		applyAdminQualityPatch(&cfg, patch.Quality)
	}
	if patch.Performance != nil {
		applyAdminPerformancePatch(&cfg, patch.Performance)
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
		if patch.BGP.DownloadTimeoutSecs != nil && *patch.BGP.DownloadTimeoutSecs > 0 {
			cfg.BGP.DownloadTimeout = time.Duration(*patch.BGP.DownloadTimeoutSecs) * time.Second
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
		if patch.BGP.IndexMode != "" {
			cfg.BGP.IndexMode = patch.BGP.IndexMode
		}
		if patch.BGP.IndexFile != "" {
			cfg.BGP.IndexFile = patch.BGP.IndexFile
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

func applyAdminQualityPatch(cfg *config.Config, patch *struct {
	Enabled                *bool    `json:"enabled"`
	IncludeDefault         *bool    `json:"include_default"`
	AILowConfidence        *bool    `json:"ai_low_confidence"`
	LowConfidenceThreshold *float64 `json:"low_confidence_threshold"`
	AllowScore             *int     `json:"allow_score"`
	ReviewScore            *int     `json:"review_score"`
	ChallengeScore         *int     `json:"challenge_score"`
	RateLimitScore         *int     `json:"rate_limit_score"`
}) {
	if patch.Enabled != nil {
		cfg.Quality.Enabled = *patch.Enabled
	}
	if patch.IncludeDefault != nil {
		cfg.Quality.IncludeDefault = *patch.IncludeDefault
	}
	if patch.AILowConfidence != nil {
		cfg.Quality.AILowConfidence = *patch.AILowConfidence
	}
	if patch.LowConfidenceThreshold != nil && *patch.LowConfidenceThreshold > 0 && *patch.LowConfidenceThreshold <= 1 {
		cfg.Quality.LowConfidenceThreshold = *patch.LowConfidenceThreshold
	}
	if patch.AllowScore != nil && *patch.AllowScore > 0 && *patch.AllowScore <= 100 {
		cfg.Quality.AllowScore = *patch.AllowScore
	}
	if patch.ReviewScore != nil && *patch.ReviewScore > 0 && *patch.ReviewScore <= 100 {
		cfg.Quality.ReviewScore = *patch.ReviewScore
	}
	if patch.ChallengeScore != nil && *patch.ChallengeScore > 0 && *patch.ChallengeScore <= 100 {
		cfg.Quality.ChallengeScore = *patch.ChallengeScore
	}
	if patch.RateLimitScore != nil && *patch.RateLimitScore > 0 && *patch.RateLimitScore <= 100 {
		cfg.Quality.RateLimitScore = *patch.RateLimitScore
	}
}

func applyAdminPerformancePatch(cfg *config.Config, patch *struct {
	Enabled           *bool `json:"enabled"`
	IncludeDefault    *bool `json:"include_default"`
	ThirdPartyDefault *bool `json:"third_party_default"`
}) {
	if patch.Enabled != nil {
		cfg.Performance.Enabled = *patch.Enabled
	}
	if patch.IncludeDefault != nil {
		cfg.Performance.IncludeDefault = *patch.IncludeDefault
	}
	if patch.ThirdPartyDefault != nil {
		cfg.Performance.ThirdPartyDefault = *patch.ThirdPartyDefault
	}
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
	FireHOLLevel1URL       string   `json:"firehol_level1_url"`
	FireHOLAnonymousURL    string   `json:"firehol_anonymous_url"`
	Az0VPNIPURL            string   `json:"az0_vpn_ip_url"`
	CloudflareV4URL        string   `json:"cloudflare_v4_url"`
	CloudflareV6URL        string   `json:"cloudflare_v6_url"`
	FastlyURL              string   `json:"fastly_url"`
	AWSIPRangesURL         string   `json:"aws_ip_ranges_url"`
	GoogleCloudIPRangesURL string   `json:"google_cloud_ip_ranges_url"`
	AzureServiceTagsURL    string   `json:"azure_service_tags_url"`
	OracleIPRangesURL      string   `json:"oracle_ip_ranges_url"`
	GitHubMetaURL          string   `json:"github_meta_url"`
	ApplePrivateRelayURL   string   `json:"apple_private_relay_url"`
	GoogleFiVPNGeofeedURL  string   `json:"google_fi_vpn_geofeed_url"`
	MullvadRelaysURL       string   `json:"mullvad_relays_url"`
	NordVPNServersURL      string   `json:"nordvpn_servers_url"`
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
	setString(&cfg.DynamicRules.FireHOLLevel1URL, patch.FireHOLLevel1URL)
	setString(&cfg.DynamicRules.FireHOLAnonymousURL, patch.FireHOLAnonymousURL)
	setString(&cfg.DynamicRules.Az0VPNIPURL, patch.Az0VPNIPURL)
	setString(&cfg.DynamicRules.CloudflareV4URL, patch.CloudflareV4URL)
	setString(&cfg.DynamicRules.CloudflareV6URL, patch.CloudflareV6URL)
	setString(&cfg.DynamicRules.FastlyURL, patch.FastlyURL)
	setString(&cfg.DynamicRules.AWSIPRangesURL, patch.AWSIPRangesURL)
	setString(&cfg.DynamicRules.GoogleCloudIPRangesURL, patch.GoogleCloudIPRangesURL)
	setString(&cfg.DynamicRules.AzureServiceTagsURL, patch.AzureServiceTagsURL)
	setString(&cfg.DynamicRules.OracleIPRangesURL, patch.OracleIPRangesURL)
	setString(&cfg.DynamicRules.GitHubMetaURL, patch.GitHubMetaURL)
	setString(&cfg.DynamicRules.ApplePrivateRelayURL, patch.ApplePrivateRelayURL)
	setString(&cfg.DynamicRules.GoogleFiVPNGeofeedURL, patch.GoogleFiVPNGeofeedURL)
	setString(&cfg.DynamicRules.MullvadRelaysURL, patch.MullvadRelaysURL)
	setString(&cfg.DynamicRules.NordVPNServersURL, patch.NordVPNServersURL)
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

type offlineLibraryInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Path        string `json:"path,omitempty"`
	SourceURL   string `json:"source_url,omitempty"`
	Exists      bool   `json:"exists"`
	Status      string `json:"status"`
	Size        string `json:"size,omitempty"`
	SizeBytes   int64  `json:"size_bytes,omitempty"`
	UpdatedAt   string `json:"updated_at,omitempty"`
	Version     string `json:"version,omitempty"`
	Description string `json:"description,omitempty"`
}

func offlineLibraries(cfg config.Config, status store.Status) []offlineLibraryInfo {
	rawSources, manifestVersion, manifestUpdatedAt := rawManifest(cfg.DataDir)
	rawFiles := status.RawFiles
	if rawFiles == nil {
		rawFiles = map[string]string{}
	}
	rawPath := func(key, fallback string) string {
		if path := strings.TrimSpace(rawFiles[key]); path != "" {
			return path
		}
		if fallback == "" {
			return ""
		}
		return filepath.Join(cfg.DataDir, "raw", fallback)
	}
	source := func(key, fallback string) string {
		if value := strings.TrimSpace(rawSources[key]); value != "" {
			return value
		}
		return fallback
	}

	rows := []offlineLibraryInfo{}
	addFile := func(id, name, kind, path, sourceURL, description string) {
		rows = append(rows, libraryFileInfo(id, name, kind, path, sourceURL, description))
	}
	addFile("caida_ipv4", "CAIDA Prefix2AS IPv4", "基础路由库", rawPath("caida_ipv4", "caida-ipv4.pfx2as.gz"), source("caida_ipv4", cfg.Sources.CAIDAv4LogURL), "IPv4 IP 到 ASN 的主离线库")
	addFile("caida_ipv6", "CAIDA Prefix2AS IPv6", "基础路由库", rawPath("caida_ipv6", "caida-ipv6.pfx2as.gz"), source("caida_ipv6", cfg.Sources.CAIDAv6LogURL), "IPv6 IP 到 ASN 的主离线库")

	rirNames := sortedMapKeys(cfg.Sources.RIRURLs)
	for _, name := range rirNames {
		key := "rir_" + name
		path := rawPath(key, "rir-"+name+".txt")
		if strings.TrimSpace(rawFiles["rir-"+name]) != "" {
			path = rawFiles["rir-"+name]
		}
		addFile(key, "RIR delegated "+name, "注册分配库", path, source(key, cfg.Sources.RIRURLs[name]), "ASN、国家、注册局和分配状态")
	}

	peeringRows := []struct {
		id, name, file, url, description string
	}{
		{"peeringdb", "PeeringDB Networks", "peeringdb-net.json", cfg.Sources.PeeringDBURL, "ASN 网络画像"},
		{"peeringdb_ix", "PeeringDB IX", "peeringdb-ix.json", cfg.Sources.PeeringDBIXURL, "IXP 基础信息"},
		{"peeringdb_netixlan", "PeeringDB NetIXLAN", "peeringdb-netixlan.json", cfg.Sources.PeeringDBNetIXLANURL, "ASN 与 IXP 连接信息"},
		{"peeringdb_facility", "PeeringDB Facilities", "peeringdb-fac.json", cfg.Sources.PeeringDBFacilityURL, "机房基础信息"},
		{"peeringdb_netfac", "PeeringDB NetFacility", "peeringdb-netfac.json", cfg.Sources.PeeringDBNetFacilityURL, "ASN 与机房 presence"},
	}
	for _, row := range peeringRows {
		addFile(row.id, row.name, "互联与机房库", rawPath(row.id, row.file), source(row.id, row.url), row.description)
	}

	ianaNames := sortedMapKeys(cfg.Sources.IANARDAPURLs)
	for _, name := range ianaNames {
		key := "iana_rdap_" + name
		addFile(key, "IANA RDAP "+name, "RDAP 引导库", rawPath(key, "iana-rdap-"+name+".json"), source(key, cfg.Sources.IANARDAPURLs[name]), "RDAP 查询入口")
	}

	for index, url := range cfg.Sources.RPKIVRPURLs {
		key := "rpki_vrp_" + strconv.Itoa(index)
		file := optionalDownloadName("rpki-vrps", index, ".csv", url)
		addFile(key, "RPKI VRP "+strconv.Itoa(index+1), "路由安全库", rawPath(key, file), source(key, url), "ROA 授权校验")
	}
	for index, url := range cfg.Sources.IRRRouteURLs {
		key := "irr_route_" + strconv.Itoa(index)
		file := optionalDownloadName("irr-routes", index, ".db", url)
		addFile(key, "IRR Route "+strconv.Itoa(index+1), "路由安全库", rawPath(key, file), source(key, url), "IRR route/route6 对象")
	}
	for index, url := range cfg.Sources.GeofeedURLs {
		key := "geofeed_" + strconv.Itoa(index)
		file := optionalDownloadName("geofeed", index, ".csv", url)
		addFile(key, "Geofeed "+strconv.Itoa(index+1), "所在地增强库", rawPath(key, file), source(key, url), "RFC 8805 实际所在地")
	}

	dynamicRulesPath := cfg.DynamicRules.File
	if strings.TrimSpace(dynamicRulesPath) == "" {
		dynamicRulesPath = filepath.Join(cfg.DataDir, "generated", "services.json")
	}
	dynamic := libraryFileInfo("dynamic_rules", "动态服务规则", "生成规则库", dynamicRulesPath, "多个公开服务源", "爬虫、Tor、邮件、监控、云厂商、VPN/Proxy、风险网段等聚合规则")
	if version, updatedAt := generatedRulesVersion(dynamicRulesPath); version != "" || updatedAt != "" {
		dynamic.Version = version
		dynamic.UpdatedAt = firstNonEmpty(updatedAt, dynamic.UpdatedAt)
	}
	rows = append(rows, dynamic)

	rows = append(rows, ip2RegionLibraryInfo("ip2region_v4", "ip2region IPv4 XDB", cfg.IP2Region.V4File, cfg.IP2Region.V4DownloadURL, "IPv4 所在地全载库"))
	rows = append(rows, ip2RegionLibraryInfo("ip2region_v6", "ip2region IPv6 XDB", cfg.IP2Region.V6File, cfg.IP2Region.V6DownloadURL, "IPv6 所在地全载库"))
	rows = append(rows, libraryFileInfo("bgp_full_summary", "全量 BGP 多观察点摘要", "BGP 汇总库", resolveDataPath(cfg.DataDir, cfg.BGP.SummaryFile), cfg.BGP.RouteViewsBaseURL+" / "+cfg.BGP.RIPERISBaseURL, "RouteViews / RIPE RIS RIB 生成的本地查询摘要"))
	rows = append(rows, libraryFileInfo("bgp_compact_index", "BGP 紧凑查询索引", "BGP 查询索引", resolveDataPath(cfg.DataDir, cfg.BGP.IndexFile), "本地生成", "由 BGP 摘要编译生成，查询优先加载以降低内存和启动解析成本"))
	rows = append(rows, libraryDirInfo("firewall_lists", "防火墙 CIDR 输出", "生成列表", cfg.FirewallLists.OutputDir, "", "按国家、公司、场景生成的 CIDR 列表"))

	if manifestVersion != "" || manifestUpdatedAt != "" {
		rows = append([]offlineLibraryInfo{{
			ID:          "base_manifest",
			Name:        "基础离线库 Manifest",
			Kind:        "更新清单",
			Path:        filepath.Join(cfg.DataDir, "processed", "manifest.json"),
			SourceURL:   "本地生成",
			Exists:      fileExists(filepath.Join(cfg.DataDir, "processed", "manifest.json")),
			Status:      statusFromExists(fileExists(filepath.Join(cfg.DataDir, "processed", "manifest.json"))),
			Version:     manifestVersion,
			UpdatedAt:   manifestUpdatedAt,
			Description: "基础公开数据下载清单和来源 URL",
		}}, rows...)
	}
	stateVersion, stateUpdatedAt := downloadStateVersion(filepath.Join(cfg.DataDir, "processed", "download-state.json"))
	stateInfo := libraryFileInfo("download_state", "下载状态缓存", "更新状态", filepath.Join(cfg.DataDir, "processed", "download-state.json"), "本地生成", "记录公开源 ETag、Last-Modified、SHA256 和本地缓存文件，避免重复下载未变化内容")
	stateInfo.Version = stateVersion
	if stateUpdatedAt != "" {
		stateInfo.UpdatedAt = stateUpdatedAt
	}
	rows = append([]offlineLibraryInfo{stateInfo}, rows...)

	return rows
}

func downloadStateVersion(filePath string) (string, string) {
	body, err := os.ReadFile(filePath)
	if err != nil {
		return "", ""
	}
	var state struct {
		Version   int       `json:"version"`
		UpdatedAt time.Time `json:"updated_at"`
	}
	if err := json.Unmarshal(body, &state); err != nil {
		return "", ""
	}
	version := ""
	if state.Version > 0 {
		version = strconv.Itoa(state.Version)
	}
	updatedAt := ""
	if !state.UpdatedAt.IsZero() {
		updatedAt = state.UpdatedAt.Format(time.RFC3339)
	}
	return version, updatedAt
}

func libraryFileInfo(id, name, kind, path, sourceURL, description string) offlineLibraryInfo {
	info := offlineLibraryInfo{
		ID:          id,
		Name:        name,
		Kind:        kind,
		Path:        strings.TrimSpace(path),
		SourceURL:   strings.TrimSpace(sourceURL),
		Description: description,
		Status:      "missing",
	}
	if info.Path == "" {
		info.Status = "not_configured"
		return info
	}
	file, err := os.Stat(info.Path)
	if err != nil {
		return info
	}
	info.Exists = true
	info.Status = "ready"
	info.SizeBytes = file.Size()
	info.Size = humanBytes(file.Size())
	info.UpdatedAt = file.ModTime().Format(time.RFC3339)
	return info
}

func libraryDirInfo(id, name, kind, path, sourceURL, description string) offlineLibraryInfo {
	info := libraryFileInfo(id, name, kind, path, sourceURL, description)
	if info.Path == "" || !info.Exists {
		return info
	}
	sizeBytes, fileCount, err := dirStats(info.Path)
	if err != nil {
		return info
	}
	info.SizeBytes = sizeBytes
	info.Size = humanBytes(sizeBytes)
	if fileCount > 0 {
		info.Version = strconv.Itoa(fileCount) + " files"
	}
	return info
}

func ip2RegionLibraryInfo(id, name, path, sourceURL, description string) offlineLibraryInfo {
	info := libraryFileInfo(id, name, "IP 所在地库", path, sourceURL, description)
	if info.Exists {
		if createdAt, err := readXDBCreatedAt(path); err == nil && createdAt > 0 {
			info.Version = time.Unix(createdAt, 0).Format("2006-01-02 15:04:05")
		}
	}
	if info.SourceURL == "" {
		info.SourceURL = "需要在配置中填写授权下载地址"
	}
	return info
}

func optionalDownloadName(prefix string, index int, defaultExt string, sourceURL string) string {
	name := prefix
	if index > 0 {
		name = prefix + "-" + strconv.Itoa(index)
	}
	ext := extensionFromURL(sourceURL)
	if ext == "" {
		ext = defaultExt
	}
	return name + ext
}

func resolveDataPath(dataDir, filePath string) string {
	if filepath.IsAbs(filePath) {
		return filePath
	}
	cleanData := filepath.Clean(dataDir)
	cleanPath := filepath.Clean(filePath)
	if cleanPath == cleanData || strings.HasPrefix(cleanPath, cleanData+string(os.PathSeparator)) {
		return cleanPath
	}
	return filepath.Join(dataDir, filePath)
}

func extensionFromURL(sourceURL string) string {
	base := path.Base(strings.Split(sourceURL, "?")[0])
	if base == "." || base == "/" {
		return ""
	}
	ext := path.Ext(base)
	if ext == ".gz" {
		withoutGzip := strings.TrimSuffix(base, ".gz")
		inner := path.Ext(withoutGzip)
		if inner != "" {
			return inner + ".gz"
		}
	}
	return ext
}

func rawManifest(dataDir string) (map[string]string, string, string) {
	path := filepath.Join(dataDir, "processed", "manifest.json")
	body, err := os.ReadFile(path)
	if err != nil {
		return map[string]string{}, "", ""
	}
	var payload struct {
		Version   string            `json:"version"`
		UpdatedAt time.Time         `json:"updated_at"`
		RawFiles  map[string]string `json:"raw_files"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return map[string]string{}, "", ""
	}
	updatedAt := ""
	if !payload.UpdatedAt.IsZero() {
		updatedAt = payload.UpdatedAt.Format(time.RFC3339)
	}
	return payload.RawFiles, payload.Version, updatedAt
}

func generatedRulesVersion(path string) (string, string) {
	body, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}
	var payload struct {
		Version   string    `json:"version"`
		UpdatedAt time.Time `json:"updated_at"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", ""
	}
	updatedAt := ""
	if !payload.UpdatedAt.IsZero() {
		updatedAt = payload.UpdatedAt.Format(time.RFC3339)
	}
	return payload.Version, updatedAt
}

func readXDBCreatedAt(path string) (int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	buf := make([]byte, 8)
	if _, err := io.ReadFull(file, buf); err != nil {
		return 0, err
	}
	return int64(binary.LittleEndian.Uint32(buf[4:8])), nil
}

func sortedMapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func statusFromExists(exists bool) string {
	if exists {
		return "ready"
	}
	return "missing"
}

func dirStats(root string) (int64, int, error) {
	var sizeBytes int64
	var fileCount int
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return nil
		}
		sizeBytes += info.Size()
		fileCount++
		return nil
	})
	return sizeBytes, fileCount, err
}

func humanBytes(size int64) string {
	const unit = 1024
	if size < unit {
		return strconv.FormatInt(size, 10) + " B"
	}
	value := float64(size)
	for _, suffix := range []string{"KB", "MB", "GB", "TB"} {
		value /= unit
		if value < unit {
			return strconv.FormatFloat(value, 'f', 2, 64) + " " + suffix
		}
	}
	return strconv.FormatFloat(value/unit, 'f', 2, 64) + " PB"
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
	includeQuality := s.currentConfig().Quality.IncludeDefault
	if r.URL.Query().Has("include_quality") {
		includeQuality = boolQuery(r.URL.Query().Get("include_quality"))
	}
	performanceCfg := s.currentConfig().Performance
	includePerformance := performanceCfg.Enabled && performanceCfg.IncludeDefault
	if r.URL.Query().Has("include_performance") {
		includePerformance = performanceCfg.Enabled && boolQuery(r.URL.Query().Get("include_performance"))
	}
	includeThirdPartyTiming := performanceCfg.ThirdPartyDefault
	if r.URL.Query().Has("include_third_party_timing") {
		includeThirdPartyTiming = boolQuery(r.URL.Query().Get("include_third_party_timing"))
	}
	writeJSON(w, http.StatusOK, s.lookup.LookupWithOptions(r.Context(), query, lookup.LookupOptions{
		IncludeLocation:       includeLocation,
		IncludeQuality:        includeQuality,
		IncludePerformance:    includePerformance,
		PerformanceThirdParty: includeThirdPartyTiming,
		OnlineEnrichment:      parseOnlineEnrichment(r.URL.Query().Get("online_enrichment")),
	}))
}

func (s *Server) qualityHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	query := strings.TrimSpace(r.URL.Query().Get("query"))
	result := s.lookup.LookupWithOptions(r.Context(), query, lookup.LookupOptions{
		IncludeQuality:   true,
		OnlineEnrichment: parseOnlineEnrichment(r.URL.Query().Get("online_enrichment")),
	})
	if !result.OK {
		writeJSON(w, http.StatusOK, result)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"query":       result.Query,
		"query_type":  result.QueryType,
		"ip":          result.IP,
		"asn":         result.ASN,
		"company":     result.Company,
		"scene":       result.Scene,
		"scene_name":  result.SceneName,
		"ip_quality":  result.Quality,
		"db":          result.DB,
		"risk_source": result.Evidence,
	})
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
    <label class="check"><input id="include-quality" type="checkbox">IP 质量</label>
    <label class="check"><input id="include-performance" type="checkbox">性能</label>
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
const includeQuality = document.getElementById('include-quality');
const includePerformance = document.getElementById('include-performance');
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
  if (includeQuality.checked) params.set('include_quality', '1');
  if (includePerformance.checked) params.set('include_performance', '1');
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
  if (data.ip_quality) {
    panels.splice(10, 0, '<div class="panel wide"><div class="label">IP 质量 / 纯净度</div><dl class="meta-list">' + renderIPQuality(data.ip_quality) + '</dl></div>');
  }
  if (data.performance) {
    panels.splice(10, 0, '<div class="panel wide"><div class="label">性能指标</div><dl class="meta-list">' + renderPerformance(data.performance) + '</dl></div>');
  }
  if (data.service_policy) {
    panels.splice(10, 0, '<div class="panel wide"><div class="label">服务策略</div><dl class="meta-list">' + renderServicePolicy(data.service_policy) + '</dl></div>');
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

function renderIPQuality(info) {
  return [
    ['评分', typeof info.score === 'number' ? info.score + '/100' : '-'],
    ['等级', info.grade || '-'],
    ['风险等级', info.risk_level || '-'],
    ['建议动作', info.recommendation || '-'],
    ['置信度', typeof info.confidence === 'number' ? Math.round(info.confidence * 100) + '%' : '-'],
    ['标签', (info.labels || []).join(' / ')],
    ['扣分原因', (info.risk_reasons || []).join(' / ')],
    ['正向信号', (info.positive_signals || []).join(' / ')]
  ].map(([label, value]) => '<dt>' + escapeHTML(label) + '</dt><dd>' + escapeHTML(value || '-') + '</dd>').join('');
}

function renderPerformance(info) {
  const thirdParty = (info.third_party || []).map(item => {
    const status = item.ok ? '成功' : '失败';
    const url = item.url ? ' ' + item.url : '';
    return item.name + ' ' + status + ' ' + (item.duration_ms || 0) + 'ms' + url;
  }).join('； ');
  return [
    ['总耗时', msValue(info.total_ms)],
    ['本地离线', msValue(info.local_offline_ms)],
    ['在线增强', msValue(info.online_enrichment_ms)],
    ['IP所在地', msValue(info.location_ms)],
    ['质量评分', msValue(info.quality_ms)],
    ['AI判断', msValue(info.ai_ms)],
    ['在线缓存', info.cache_hit ? '命中' : '-'],
    ['后台刷新', info.refresh_queued || info.refresh_in_progress ? '是' : '-'],
    ['第三方源', thirdParty || '-']
  ].map(([label, value]) => '<dt>' + escapeHTML(label) + '</dt><dd>' + escapeHTML(value || '-') + '</dd>').join('');
}

function msValue(value) {
  return typeof value === 'number' ? value + 'ms' : '-';
}

function renderServicePolicy(policy) {
  return [
    ['服务', policy.service_name || policy.rule_name || '-'],
    ['子类型', policy.service_subtype || '-'],
    ['风险等级', policy.risk_level || '-'],
    ['建议拦截', policy.block_recommended === true ? '是' : (policy.block_recommended === false ? '否' : '-')],
    ['正常用户流量', policy.normal_user_traffic === true ? '是' : (policy.normal_user_traffic === false ? '否' : '-')]
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
    .admin-tabs { display: flex; gap: 6px; align-items: end; border-bottom: 1px solid #d8dee6; margin: 0 0 16px; overflow-x: auto; }
    .tab-button { height: 40px; border: 1px solid transparent; border-bottom: 0; border-radius: 8px 8px 0 0; background: transparent; color: #334155; font-weight: 600; white-space: nowrap; }
    .tab-button.active { background: #fff; border-color: #d8dee6; color: #1b5f9e; }
    .tab-button:focus-visible { outline: 2px solid #1b5f9e; outline-offset: 2px; }
    .tab-panel { display: none; }
    .tab-panel.active { display: block; }
    .hint { color: #667085; }
    .surface { background: #fff; border: 1px solid #d8dee6; border-radius: 8px; padding: 14px; margin-bottom: 14px; }
    .status-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; }
    .metric { border: 1px solid #e2e8f0; border-radius: 8px; padding: 10px; background: #fafbfc; }
    .metric .label { color: #667085; font-size: 12px; margin-bottom: 4px; }
    .metric .value { font-size: 16px; overflow-wrap: anywhere; }
    .data-table { width: 100%; border-collapse: collapse; border: 1px solid #d8dee6; border-radius: 8px; overflow: hidden; background: #fff; }
    .data-table th, .data-table td { border-bottom: 1px solid #e5eaf0; padding: 8px 9px; text-align: left; vertical-align: top; }
    .data-table th { background: #f8fafc; color: #334155; font-weight: 600; }
    .data-table tr:last-child td { border-bottom: 0; }
    .data-table td { overflow-wrap: anywhere; }
    .status-ready { color: #15803d; font-weight: 600; }
    .status-missing, .status-not_configured { color: #b45309; font-weight: 600; }
    .help-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
    .help-item { border: 1px solid #e2e8f0; border-radius: 8px; padding: 10px; background: #fafbfc; }
    .help-title { font-weight: 700; margin-bottom: 4px; }
    .help-group { color: #667085; font-size: 12px; margin-bottom: 6px; }
    .help-impact { margin-top: 6px; color: #475569; font-size: 12px; }
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
    .config-actions { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin: 0 0 14px; padding: 10px; border: 1px solid #d8dee6; border-radius: 8px; background: #fff; }
    .config-table { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #d8dee6; border-radius: 8px; overflow: hidden; }
    .config-table th, .config-table td { border-bottom: 1px solid #e5eaf0; padding: 9px 10px; vertical-align: top; text-align: left; }
    .config-table th { width: 220px; background: #f8fafc; color: #334155; font-weight: 600; }
    .config-table tr:last-child th, .config-table tr:last-child td { border-bottom: 0; }
    input, select, textarea { width: 100%; box-sizing: border-box; border: 1px solid #c9d1d9; border-radius: 6px; padding: 8px 9px; font: inherit; background: #fff; color: #1d2733; }
    input[type="checkbox"] { width: 18px; height: 18px; padding: 0; }
    .inline-control { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 8px; align-items: center; }
    button.small { height: 36px; white-space: nowrap; }
    textarea { min-height: 74px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; }
    .field-help { margin-top: 6px; color: #667085; font-size: 12px; line-height: 1.45; }
    .optional-source { color: #475569; font-size: 12px; font-weight: 500; margin-left: 6px; }
    details { margin-top: 14px; }
    summary { cursor: pointer; font-weight: 600; color: #1b5f9e; }
    pre { white-space: pre-wrap; overflow-wrap: anywhere; background: #111827; color: #e5e7eb; padding: 12px; border-radius: 8px; max-height: 260px; overflow: auto; }
    @media (max-width: 900px) { .status-grid, .progress-steps, .help-grid { grid-template-columns: 1fr; } .config-table th { width: 150px; } .inline-control { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
<main>
  <h1>配置管理</h1>
  <div class="toolbar">
    <button id="load">读取配置</button>
    <button id="save">保存配置</button>
    <button class="secondary" type="button" id="apply-defaults">填充公开默认源</button>
    <button class="secondary" id="update">更新离线库</button>
    <span class="hint" id="toolbar-hint"></span>
  </div>

  <nav class="admin-tabs" role="tablist" aria-label="后台页面">
    <button class="tab-button active" type="button" role="tab" aria-selected="true" data-tab="overview">概览</button>
    <button class="tab-button" type="button" role="tab" aria-selected="false" data-tab="libraries">离线库</button>
    <button class="tab-button" type="button" role="tab" aria-selected="false" data-tab="config">配置</button>
    <button class="tab-button" type="button" role="tab" aria-selected="false" data-tab="help">帮助</button>
  </nav>

  <section id="tab-overview" class="tab-panel active" data-tab-panel="overview">
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

    <section class="surface">
      <h2>操作结果</h2>
      <pre id="status"></pre>
    </section>
  </section>

  <section id="tab-libraries" class="tab-panel" data-tab-panel="libraries">
    <section class="surface">
      <h2>离线库列表</h2>
      <div id="offline-libraries"></div>
    </section>
  </section>

  <section id="tab-config" class="tab-panel" data-tab-panel="config">
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
          <tr><th>AI Provider</th><td><select id="cfg-ai-provider" data-path="ai.provider"><option value="auto">auto</option><option value="off">off</option><option value="openai">openai</option><option value="anthropic">anthropic</option><option value="gemini">gemini</option></select></td></tr>
          <tr data-ai-provider-scope="openai"><th>OpenAI API Key(留空不修改)</th><td><input id="cfg-ai-openai-api-key" data-path="ai.openai_api_key" data-secret="true" type="password" autocomplete="new-password"></td></tr>
          <tr data-ai-provider-scope="openai"><th>OpenAI 模型</th><td><div class="inline-control"><select id="cfg-ai-openai-model" data-path="ai.openai_model" data-model-select-provider="openai"></select><button type="button" class="secondary small" data-model-provider="openai">刷新模型</button></div></td></tr>
          <tr data-ai-provider-scope="openai"><th>OpenAI Base URL</th><td><input id="cfg-ai-openai-base-url" data-path="ai.openai_base_url"></td></tr>
          <tr data-ai-provider-scope="openai"><th>OpenAI 接口类型</th><td><select id="cfg-ai-openai-api-type" data-path="ai.openai_api_type"><option value="responses">responses</option><option value="chat_completions">chat_completions</option></select></td></tr>
          <tr data-ai-provider-scope="anthropic"><th>Anthropic API Key(留空不修改)</th><td><input id="cfg-ai-anthropic-api-key" data-path="ai.anthropic_api_key" data-secret="true" type="password" autocomplete="new-password"></td></tr>
          <tr data-ai-provider-scope="anthropic"><th>Anthropic 模型</th><td><div class="inline-control"><select id="cfg-ai-anthropic-model" data-path="ai.anthropic_model" data-model-select-provider="anthropic"></select><button type="button" class="secondary small" data-model-provider="anthropic">刷新模型</button></div></td></tr>
          <tr data-ai-provider-scope="anthropic"><th>Anthropic Base URL</th><td><input id="cfg-ai-anthropic-base-url" data-path="ai.anthropic_base_url"></td></tr>
          <tr data-ai-provider-scope="anthropic"><th>Anthropic Version</th><td><input id="cfg-ai-anthropic-version" data-path="ai.anthropic_version"></td></tr>
          <tr data-ai-provider-scope="gemini"><th>Gemini API Key(留空不修改)</th><td><input id="cfg-ai-gemini-api-key" data-path="ai.gemini_api_key" data-secret="true" type="password" autocomplete="new-password"></td></tr>
          <tr data-ai-provider-scope="gemini"><th>Gemini 模型</th><td><div class="inline-control"><select id="cfg-ai-gemini-model" data-path="ai.gemini_model" data-model-select-provider="gemini"></select><button type="button" class="secondary small" data-model-provider="gemini">刷新模型</button></div></td></tr>
          <tr data-ai-provider-scope="gemini"><th>Gemini Base URL</th><td><input id="cfg-ai-gemini-base-url" data-path="ai.gemini_base_url"></td></tr>
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
      <h2>IP 质量评分</h2>
      <table class="config-table">
        <tbody>
          <tr><th>启用评分</th><td><input id="cfg-quality-enabled" data-path="quality.enabled" type="checkbox"></td></tr>
          <tr><th>默认输出评分</th><td><input id="cfg-quality-include-default" data-path="quality.include_default" type="checkbox"><div class="field-help">关闭时只有 include_quality=1 或 /api/quality 会输出。</div></td></tr>
          <tr><th>AI 低置信度辅助</th><td><input id="cfg-quality-ai-low-confidence" data-path="quality.ai_low_confidence" type="checkbox"></td></tr>
          <tr><th>低置信度阈值</th><td><input id="cfg-quality-low-confidence-threshold" data-path="quality.low_confidence_threshold" data-type="float" type="number" min="0" max="1" step="0.01"></td></tr>
          <tr><th>Allow 分数</th><td><input id="cfg-quality-allow-score" data-path="quality.allow_score" data-type="number" type="number" min="1" max="100"></td></tr>
          <tr><th>Review 分数</th><td><input id="cfg-quality-review-score" data-path="quality.review_score" data-type="number" type="number" min="1" max="100"></td></tr>
          <tr><th>Challenge 分数</th><td><input id="cfg-quality-challenge-score" data-path="quality.challenge_score" data-type="number" type="number" min="1" max="100"></td></tr>
          <tr><th>Rate Limit 分数</th><td><input id="cfg-quality-rate-limit-score" data-path="quality.rate_limit_score" data-type="number" type="number" min="1" max="100"></td></tr>
        </tbody>
      </table>
    </section>

    <section class="config-section">
      <h2>性能指标</h2>
      <table class="config-table">
        <tbody>
          <tr><th>启用性能指标</th><td><input id="cfg-performance-enabled" data-path="performance.enabled" type="checkbox"></td></tr>
          <tr><th>默认输出性能指标</th><td><input id="cfg-performance-include-default" data-path="performance.include_default" type="checkbox"><div class="field-help">关闭时只有 include_performance=1 才会输出 performance。</div></td></tr>
          <tr><th>默认输出第三方耗时</th><td><input id="cfg-performance-third-party-default" data-path="performance.third_party_default" type="checkbox"><div class="field-help">开启后会输出当前请求等待到的 Team Cymru、RIPEstat、RDAP、WHOIS、RIPE RIS 等在线源耗时。</div></td></tr>
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
          <tr><th>下载超时(秒)</th><td><input id="cfg-bgp-download-timeout-seconds" data-path="bgp.download_timeout_seconds" data-type="number" type="number" min="1"><div class="field-help">单个 RIB 大文件下载超时，默认 7200 秒；网络慢时可以继续调大。</div></td></tr>
          <tr><th>并发解析数</th><td><input id="cfg-bgp-max-parallel-parse" data-path="bgp.max_parallel_parse" data-type="number" type="number" min="1"></td></tr>
          <tr><th>保留原始 MRT</th><td><input id="cfg-bgp-keep-raw" data-path="bgp.keep_raw" type="checkbox"></td></tr>
          <tr><th>原始文件保留天数</th><td><input id="cfg-bgp-raw-retention-days" data-path="bgp.raw_retention_days" data-type="number" type="number" min="0"></td></tr>
          <tr><th>汇总文件</th><td><input id="cfg-bgp-summary-file" data-path="bgp.summary_file"></td></tr>
          <tr><th>索引模式</th><td><input id="cfg-bgp-index-mode" data-path="bgp.index_mode"><div class="field-help">compact 为默认紧凑索引；jsonl 表示兼容旧的 JSONL 直接加载。</div></td></tr>
          <tr><th>索引文件</th><td><input id="cfg-bgp-index-file" data-path="bgp.index_file"><div class="field-help">后台更新会从汇总文件编译生成，查询优先加载这个文件。</div></td></tr>
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
          <tr><th>FireHOL level1</th><td><input id="cfg-firehol-level1-url" data-path="dynamic_rules.firehol_level1_url"><div class="field-help">FireHOL 聚合低误报风险网段，默认启用并生成 BLOCKLIST 规则。</div></td></tr>
          <tr><th>FireHOL anonymous</th><td><input id="cfg-firehol-anonymous-url" data-path="dynamic_rules.firehol_anonymous_url"><div class="field-help">FireHOL 匿名代理聚合列表，体积较大，按需填写后生成 PROXY 规则。</div></td></tr>
          <tr><th>az0/vpn_ip</th><td><input id="cfg-az0-vpn-ip-url" data-path="dynamic_rules.az0_vpn_ip_url"><div class="field-help">公开 VPN IP 列表，默认启用并生成 VPN 规则。</div></td></tr>
          <tr><th>Cloudflare IPv4</th><td><input id="cfg-cloudflare-v4-url" data-path="dynamic_rules.cloudflare_v4_url"></td></tr>
          <tr><th>Cloudflare IPv6</th><td><input id="cfg-cloudflare-v6-url" data-path="dynamic_rules.cloudflare_v6_url"></td></tr>
          <tr><th>Fastly URL</th><td><input id="cfg-fastly-url" data-path="dynamic_rules.fastly_url"></td></tr>
          <tr><th>AWS IP Ranges</th><td><input id="cfg-aws-ip-ranges-url" data-path="dynamic_rules.aws_ip_ranges_url"><div class="field-help">AWS 总体生成 IDC 规则，CLOUDFRONT service 会单独拆成 CDN 规则。</div></td></tr>
          <tr><th>Google Cloud IP Ranges</th><td><input id="cfg-google-cloud-ip-ranges-url" data-path="dynamic_rules.google_cloud_ip_ranges_url"></td></tr>
          <tr><th>Azure Service Tags</th><td><input id="cfg-azure-service-tags-url" data-path="dynamic_rules.azure_service_tags_url"></td></tr>
          <tr><th>Oracle IP Ranges</th><td><input id="cfg-oracle-ip-ranges-url" data-path="dynamic_rules.oracle_ip_ranges_url"></td></tr>
          <tr><th>GitHub Meta URL</th><td><input id="cfg-github-meta-url" data-path="dynamic_rules.github_meta_url"></td></tr>
          <tr><th>Apple iCloud Private Relay</th><td><input id="cfg-apple-private-relay-url" data-path="dynamic_rules.apple_private_relay_url"><div class="field-help">Apple 官方隐私代理出口 CSV，生成 PROXY 规则，并在生成前合并相邻 CIDR。</div></td></tr>
          <tr><th>Google Fi VPN Geofeed</th><td><input id="cfg-google-fi-vpn-geofeed-url" data-path="dynamic_rules.google_fi_vpn_geofeed_url"><div class="field-help">Google Fi VPN RFC 8805 geofeed，生成 VPN 规则。</div></td></tr>
          <tr><th>Mullvad Relays URL</th><td><input id="cfg-mullvad-relays-url" data-path="dynamic_rules.mullvad_relays_url"><div class="field-help">Mullvad relay API，生成 active relay 的 VPN 规则。</div></td></tr>
          <tr><th>NordVPN Servers URL</th><td><input id="cfg-nordvpn-servers-url" data-path="dynamic_rules.nordvpn_servers_url"><div class="field-help">NordVPN servers API，生成在线服务器的 VPN 规则；如不需要可留空。</div></td></tr>
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
          <tr><th>Geofeed URLs <span class="optional-source">可选增强源</span></th><td><textarea id="cfg-geofeed-urls" data-path="sources.geofeed_urls" data-type="list" placeholder="未配置时只加载 data/raw/geofeed*"></textarea><div class="field-help">已预置 OpenGeoFeed 聚合源，适合增强实际所在地判断；查询所在地时优先匹配 geofeed，未命中再回退 ip2region。</div></td></tr>
        </tbody>
      </table>
    </details>
    <div class="config-actions">
      <button type="button" id="save-config-inline">保存配置</button>
      <button type="button" class="secondary" id="load-config-inline">重新读取</button>
      <span class="hint">修改配置后点击这里保存。</span>
    </div>
    </form>
  </section>

  <section id="tab-help" class="tab-panel" data-tab-panel="help">
    <section class="surface">
      <h2>配置帮助</h2>
      <div id="config-help" class="help-grid"></div>
    </section>
  </section>
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
const offlineLibraries = document.getElementById('offline-libraries');
const configHelp = document.getElementById('config-help');
const tabButtons = document.querySelectorAll('[data-tab]');
const tabPanels = document.querySelectorAll('[data-tab-panel]');
let pollTimer = null;
let currentDefaults = {};
let currentHelp = {};
const builtInAIModels = {
  openai: ['gpt-5.4-mini', 'gpt-5.4', 'gpt-5.4-nano', 'gpt-4.1', 'gpt-4.1-mini', 'gpt-4o', 'gpt-4o-mini'],
  anthropic: ['claude-sonnet-4-6', 'claude-opus-4-6', 'claude-haiku-4-5', 'claude-sonnet-4-5', 'claude-3-7-sonnet-latest'],
  gemini: ['gemini-2.5-flash', 'gemini-2.5-pro', 'gemini-2.5-flash-lite', 'gemini-2.0-flash']
};

document.getElementById('load').onclick = loadConfig;
document.getElementById('save').onclick = saveConfigFromForm;
document.getElementById('load-config-inline').onclick = loadConfig;
document.getElementById('save-config-inline').onclick = saveConfigFromForm;
document.getElementById('apply-defaults').onclick = () => applyPublicDefaults({ silent: false });
updateButton.onclick = updateDB;
tabButtons.forEach((button) => {
  button.addEventListener('click', () => switchAdminTab(button.dataset.tab));
});
document.querySelectorAll('[data-model-provider]').forEach((button) => {
  button.addEventListener('click', () => refreshAIModels(button.dataset.modelProvider, button));
});
const aiProviderSelect = document.getElementById('cfg-ai-provider');
if (aiProviderSelect) {
  aiProviderSelect.addEventListener('change', updateAIProviderVisibility);
}

function switchAdminTab(tabName) {
  tabButtons.forEach((button) => {
    const active = button.dataset.tab === tabName;
    button.classList.toggle('active', active);
    button.setAttribute('aria-selected', active ? 'true' : 'false');
  });
  tabPanels.forEach((panel) => {
    const active = panel.dataset.tabPanel === tabName;
    panel.classList.toggle('active', active);
  });
}

async function loadConfig() {
  const res = await adminFetch('/api/admin/config');
  const data = await res.json();
  if (!res.ok || data.ok === false) {
    writeLog(data);
    return;
  }
  currentDefaults = data.defaults || {};
  currentHelp = data.help || {};
  fillConfigForm(data);
  renderConfigHelp(currentHelp);
  writeLog({ ok: true, message: '配置已读取' });
  await pollStatus();
}

async function saveConfigFromForm() {
  const payload = buildConfigPatch();
  const res = await adminFetch('/api/admin/config', { method: 'PUT', body: JSON.stringify(payload) });
  const data = await res.json();
  if (res.ok && data.ok !== false) {
    data.message = data.runtime_applied ? '配置已保存，AI 设置已热生效；监听地址、TLS 等仍需按提示重启。' : '配置已保存。';
  }
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
    currentDefaults = data.config.defaults || currentDefaults || {};
    currentHelp = data.config.help || currentHelp || {};
    renderConfigHelp(currentHelp);
  }
  const database = data.database || {};
  renderDatabase(database);
  renderOfflineLibraries(data.offline_libraries || []);
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
  seedAIModelSelects((config && config.ai) || {});
  document.querySelectorAll('[data-path]').forEach((field) => {
    const value = readPath(config, field.dataset.path);
    if (field.dataset.secret === 'true') {
      field.value = '';
      field.placeholder = value ? '已配置，留空不修改' : '未配置';
      applyFieldHelp(field);
      return;
    }
    if (field.type === 'checkbox') {
      field.checked = !!value;
      applyFieldHelp(field);
      return;
    }
    if (field.dataset.type === 'list') {
      field.value = Array.isArray(value) ? value.join('\n') : '';
      applyFieldHelp(field);
      return;
    }
    if (field.dataset.type === 'map') {
      field.value = mapToLines(value);
      applyFieldHelp(field);
      return;
    }
    field.value = value === undefined || value === null ? '' : String(value);
    applyFieldHelp(field);
  });
  applyPublicDefaults({ silent: true });
  updateAIProviderVisibility();
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

function renderOfflineLibraries(items) {
  if (!items.length) {
    offlineLibraries.innerHTML = '<div class="hint">暂无离线库明细。先触发一次更新或检查数据目录。</div>';
    return;
  }
  const rows = items.map((item) => {
    const statusClass = 'status-' + escapeHTML(item.status || 'missing');
    return '<tr>' +
      '<td><strong>' + escapeHTML(item.name || item.id) + '</strong><div class="hint">' + escapeHTML(item.description || '') + '</div></td>' +
      '<td>' + escapeHTML(item.kind || '-') + '</td>' +
      '<td><span class="' + statusClass + '">' + escapeHTML(statusText(item.status, item.exists)) + '</span></td>' +
      '<td>' + escapeHTML(item.size || '-') + '</td>' +
      '<td>' + escapeHTML(item.version || '-') + '</td>' +
      '<td>' + escapeHTML(formatTime(item.updated_at) || '-') + '</td>' +
      '<td>' + escapeHTML(item.path || '-') + '</td>' +
      '<td>' + escapeHTML(item.source_url || '-') + '</td>' +
      '</tr>';
  }).join('');
  offlineLibraries.innerHTML = '<table class="data-table"><thead><tr><th>名称</th><th>类型</th><th>状态</th><th>大小</th><th>版本</th><th>更新时间</th><th>本地文件</th><th>来源</th></tr></thead><tbody>' + rows + '</tbody></table>';
}

function renderConfigHelp(help) {
  const keys = Object.keys(help || {}).sort((a, b) => {
    const ag = help[a].group || '';
    const bg = help[b].group || '';
    if (ag !== bg) return ag.localeCompare(bg);
    return (help[a].title || a).localeCompare(help[b].title || b);
  });
  if (!keys.length) {
    configHelp.innerHTML = '<div class="hint">暂无配置帮助。</div>';
    return;
  }
  configHelp.innerHTML = keys.map((key) => {
    const item = help[key] || {};
    const impact = item.impact ? '<div class="help-impact">影响：' + escapeHTML(item.impact) + '</div>' : '';
    const defaultText = item.default ? '<div class="help-impact">默认：' + escapeHTML(item.default) + '</div>' : '';
    return '<div class="help-item"><div class="help-group">' + escapeHTML(item.group || '-') + ' / ' + escapeHTML(key) + '</div><div class="help-title">' + escapeHTML(item.title || key) + '</div><div>' + escapeHTML(item.help || '-') + '</div>' + impact + defaultText + '</div>';
  }).join('');
}

function statusText(status, exists) {
  if (status === 'ready' || exists) return '已下载';
  if (status === 'not_configured') return '未配置';
  return '缺失';
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

function updateAIProviderVisibility() {
  const provider = (document.getElementById('cfg-ai-provider')?.value || 'auto').toLowerCase();
  document.querySelectorAll('[data-ai-provider-scope]').forEach((row) => {
    const scope = row.getAttribute('data-ai-provider-scope');
    row.hidden = provider === 'off' || (provider !== 'auto' && scope !== provider);
  });
}

async function refreshAIModels(provider, button) {
  const originalText = button ? button.textContent : '';
  if (button) {
    button.disabled = true;
    button.textContent = '加载中';
  }
  try {
    const res = await adminFetch('/api/admin/ai/models', {
      method: 'POST',
      body: JSON.stringify(aiModelPayload(provider))
    });
    const data = await res.json();
    if (!res.ok || data.ok === false) {
      writeLog(data);
      return;
    }
    populateAIModelList(provider, data.models || []);
    const sourceText = data.source === 'cache' ? '缓存' : (data.source === 'fallback' ? '内置候选' : '在线');
    writeLog({ ok: true, message: provider + ' 模型列表已更新（' + sourceText + '）', count: (data.models || []).length, source: data.source || 'online', error: data.error || '' });
  } finally {
    if (button) {
      button.disabled = false;
      button.textContent = originalText;
    }
  }
}

function seedAIModelSelects(aiConfig) {
  populateAIModelList('openai', aiModelsWithConfigured('openai', aiConfig.openai_model));
  populateAIModelList('anthropic', aiModelsWithConfigured('anthropic', aiConfig.anthropic_model));
  populateAIModelList('gemini', aiModelsWithConfigured('gemini', aiConfig.gemini_model));
}

function aiModelsWithConfigured(provider, configured) {
  const values = [];
  if (configured) values.push(configured);
  (builtInAIModels[provider] || []).forEach((id) => values.push(id));
  return values.map((id) => ({ id, name: id, provider }));
}

function aiModelPayload(provider) {
  const payload = { provider };
  const keyField = document.getElementById('cfg-ai-' + provider + '-api-key');
  const baseField = document.getElementById('cfg-ai-' + provider + '-base-url');
  const versionField = document.getElementById('cfg-ai-' + provider + '-version');
  if (keyField && keyField.value.trim()) payload.api_key = keyField.value.trim();
  if (baseField && baseField.value.trim()) payload.base_url = baseField.value.trim();
  if (versionField && versionField.value.trim()) payload.version = versionField.value.trim();
  return payload;
}

function populateAIModelList(provider, models) {
  const select = document.getElementById('cfg-ai-' + provider + '-model');
  if (!select) return;
  const currentValue = select.value.trim();
  const merged = mergeAIModelOptions(provider, currentValue, models);
  select.innerHTML = merged.map((model) => {
    const id = model.id || '';
    const label = [model.name && model.name !== id ? model.name : '', model.owned_by].filter(Boolean).join(' / ');
    const text = label ? id + ' - ' + label : id;
    return '<option value="' + escapeHTML(id) + '">' + escapeHTML(text) + '</option>';
  }).join('');
  if (currentValue) {
    select.value = currentValue;
  } else if (merged.length && merged[0].id) {
    select.value = merged[0].id;
  }
}

function mergeAIModelOptions(provider, currentValue, models) {
  const merged = [];
  const seen = new Set();
  const add = (model) => {
    const id = String((model && model.id) || '').trim();
    if (!id || seen.has(id.toLowerCase())) return;
    seen.add(id.toLowerCase());
    merged.push(Object.assign({ name: id, provider }, model, { id }));
  };
  if (currentValue) add({ id: currentValue, name: currentValue, provider });
  (builtInAIModels[provider] || []).forEach((id) => add({ id, name: id, provider }));
  (models || []).forEach(add);
  return merged;
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

function applyFieldHelp(field) {
  const item = currentHelp && currentHelp[field.dataset.path];
  const defaultValue = readPath(currentDefaults, field.dataset.path);
  if (item && item.help) {
    field.title = item.help;
    field.setAttribute('aria-label', (item.title || field.dataset.path) + '：' + item.help);
  }
  if (field.dataset.secret === 'true') return;
  if ((field.value === '' || field.value === undefined) && defaultValue !== undefined && defaultValue !== null && defaultValue !== '' && !Array.isArray(defaultValue)) {
    field.placeholder = '默认：' + defaultValue;
  }
  if (item && item.default && !field.placeholder) {
    field.placeholder = item.default;
  }
}

function applyPublicDefaults(options = {}) {
  let changed = 0;
  document.querySelectorAll('[data-path]').forEach((field) => {
    const path = field.dataset.path;
    if (!isPublicDefaultPath(path) || field.dataset.secret === 'true' || field.type === 'checkbox') return;
    const current = field.value.trim();
    if (current) return;
    const value = readPath(currentDefaults, path);
    if (value === undefined || value === null || value === '' || (Array.isArray(value) && value.length === 0)) return;
    if (field.dataset.type === 'list') {
      field.value = Array.isArray(value) ? value.join('\n') : String(value);
    } else if (field.dataset.type === 'map') {
      field.value = mapToLines(value);
    } else {
      field.value = String(value);
    }
    changed++;
  });
  if (!options.silent) {
    writeLog({ ok: true, message: changed ? '已填充 ' + changed + ' 个公开默认源，保存配置后生效。' : '没有可填充的公开默认源。商业授权、本地路径和 Token 需要手动配置。' });
  }
}

function isPublicDefaultPath(path) {
  return path.startsWith('sources.') ||
    (path.startsWith('dynamic_rules.') && !path.startsWith('dynamic_rules.ip2proxy.') && path !== 'dynamic_rules.file') ||
    path === 'bgp.routeviews_base_url' ||
    path === 'bgp.ripe_ris_base_url';
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
