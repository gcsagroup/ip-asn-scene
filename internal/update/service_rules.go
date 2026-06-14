package update

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"ipasn/internal/config"
)

type generatedServiceRuleFile struct {
	Version      string                 `json:"version"`
	UpdatedAt    time.Time              `json:"updated_at"`
	SourceErrors []string               `json:"source_errors,omitempty"`
	Rules        []generatedServiceRule `json:"rules"`
}

type generatedServiceRule struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Scene        string   `json:"scene"`
	SceneName    string   `json:"scene_name"`
	Confidence   float64  `json:"confidence"`
	Prefixes     []string `json:"prefixes"`
	RDNSContains []string `json:"rdns_contains,omitempty"`
	Evidence     string   `json:"evidence"`
}

type spfTXTLookup interface {
	LookupTXT(context.Context, string) ([]string, error)
}

type spfTXTLookupFunc func(context.Context, string) ([]string, error)

func (f spfTXTLookupFunc) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return f(ctx, name)
}

func DynamicServiceRulesPath(cfg config.Config) string {
	if strings.TrimSpace(cfg.DynamicRules.File) != "" {
		return cfg.DynamicRules.File
	}
	return filepath.Join(cfg.DataDir, "generated", "services.json")
}

func RefreshDynamicServiceRules(ctx context.Context, cfg config.Config) (string, error) {
	client := &http.Client{Timeout: cfg.HTTPTimeout}
	resolver := spfTXTLookupFunc(func(ctx context.Context, name string) ([]string, error) {
		var r net.Resolver
		return r.LookupTXT(ctx, name)
	})
	return RefreshDynamicServiceRulesWithClient(ctx, cfg, client, resolver)
}

func RefreshDynamicServiceRulesWithClient(ctx context.Context, cfg config.Config, client *http.Client, resolver spfTXTLookup) (string, error) {
	path := DynamicServiceRulesPath(cfg)
	if !cfg.DynamicRules.Enabled {
		return path, nil
	}
	if client == nil {
		client = &http.Client{Timeout: cfg.HTTPTimeout}
	}
	if resolver == nil {
		resolver = spfTXTLookupFunc(func(ctx context.Context, name string) ([]string, error) {
			var r net.Resolver
			return r.LookupTXT(ctx, name)
		})
	}

	previousRules := previousGeneratedRules(path)
	rules := []generatedServiceRule{}
	sourceErrors := []string{}
	addRule := func(id string, rule generatedServiceRule, err error) {
		if err != nil {
			sourceErrors = append(sourceErrors, err.Error())
			if previous, ok := previousRules[id]; ok && len(previous.Prefixes) > 0 {
				rules = append(rules, previous)
				sourceErrors = append(sourceErrors, "retained previous rule "+id)
			}
			return
		}
		if len(rule.Prefixes) > 0 {
			rules = append(rules, rule)
		}
	}

	rule, err := fetchBotRule(ctx, client, cfg.DynamicRules.GoogleCrawlerURL, "dynamic-bot-google-common-crawlers", "Google Common Crawlers", "Google 官方爬虫网段", "Google 官方 common-crawlers.json")
	addRule("dynamic-bot-google-common-crawlers", rule, err)
	rule, err = fetchBotRule(ctx, client, cfg.DynamicRules.BingbotURL, "dynamic-bot-bingbot", "Bingbot", "Bing 官方爬虫网段", "Microsoft 官方 bingbot.json")
	addRule("dynamic-bot-bingbot", rule, err)
	rule, err = fetchAddressListRule(ctx, client, cfg.DynamicRules.TorExitURL, "dynamic-tor-exit-nodes", "Tor Exit Nodes", "TOR", "Tor 出口", 0.99, "Tor 官方出口节点列表")
	addRule("dynamic-tor-exit-nodes", rule, err)
	rule, err = fetchMailSPFRule(ctx, resolver, cfg.DynamicRules.MailSPFDomains)
	addRule("dynamic-mail-spf", rule, err)
	rule, err = fetchAddressListRule(ctx, client, cfg.DynamicRules.UptimeRobotURL, "dynamic-mon-uptimerobot", "UptimeRobot Monitoring", "MON", "监控探测", 0.98, "UptimeRobot 官方监控 IP 列表")
	addRule("dynamic-mon-uptimerobot", rule, err)
	rule, err = fetchSpamhausDropRule(ctx, client, cfg.DynamicRules.SpamhausDropV4URL, cfg.DynamicRules.SpamhausDropV6URL)
	addRule("dynamic-blocklist-spamhaus-drop", rule, err)
	rule, err = fetchCombinedAddressListRule(ctx, client, []string{cfg.DynamicRules.CloudflareV4URL, cfg.DynamicRules.CloudflareV6URL}, "dynamic-cdn-cloudflare", "Cloudflare CDN", "CDN", "内容分发", 0.99, "Cloudflare 官方 CDN IP 段")
	addRule("dynamic-cdn-cloudflare", rule, err)
	rule, err = fetchFastlyRule(ctx, client, cfg.DynamicRules.FastlyURL)
	addRule("dynamic-cdn-fastly", rule, err)
	rule, err = fetchCloudJSONRule(ctx, client, cfg.DynamicRules.AWSIPRangesURL, "dynamic-idc-aws", "AWS", "AWS 官方 ip-ranges.json")
	addRule("dynamic-idc-aws", rule, err)
	rule, err = fetchCloudJSONServiceRule(ctx, client, cfg.DynamicRules.AWSIPRangesURL, "dynamic-cdn-aws-cloudfront", "AWS CloudFront", "CDN", "内容分发", 0.99, "AWS 官方 ip-ranges.json CLOUDFRONT", "CLOUDFRONT")
	addRule("dynamic-cdn-aws-cloudfront", rule, err)
	rule, err = fetchCloudJSONRule(ctx, client, cfg.DynamicRules.GoogleCloudIPRangesURL, "dynamic-idc-google-cloud", "Google Cloud", "Google Cloud 官方 cloud.json")
	addRule("dynamic-idc-google-cloud", rule, err)
	rule, err = fetchAzureServiceTagsRule(ctx, client, cfg.DynamicRules.AzureServiceTagsURL)
	addRule("dynamic-idc-azure", rule, err)
	rule, err = fetchOracleRule(ctx, client, cfg.DynamicRules.OracleIPRangesURL)
	addRule("dynamic-idc-oracle-cloud", rule, err)
	rule, err = fetchGitHubMetaRule(ctx, client, cfg.DynamicRules.GitHubMetaURL)
	addRule("dynamic-org-github", rule, err)
	ip2proxyRules, err := fetchIP2ProxyRules(ctx, client, cfg)
	if err != nil {
		sourceErrors = append(sourceErrors, err.Error())
		for _, id := range []string{"dynamic-ip2proxy-vpn", "dynamic-ip2proxy-proxy", "dynamic-ip2proxy-tor"} {
			if previous, ok := previousRules[id]; ok && len(previous.Prefixes) > 0 {
				rules = append(rules, previous)
				sourceErrors = append(sourceErrors, "retained previous rule "+id)
			}
		}
	}
	rules = append(rules, ip2proxyRules...)

	sort.Slice(rules, func(i, j int) bool {
		return rules[i].ID < rules[j].ID
	})

	encoded, err := json.MarshalIndent(generatedServiceRuleFile{
		Version:      time.Now().UTC().Format("20060102T150405Z"),
		UpdatedAt:    time.Now().UTC(),
		SourceErrors: sourceErrors,
		Rules:        rules,
	}, "", "  ")
	if err != nil {
		return "", err
	}
	if err := atomicWrite(path, encoded); err != nil {
		return "", err
	}
	return path, nil
}

func previousGeneratedRules(path string) map[string]generatedServiceRule {
	out := map[string]generatedServiceRule{}
	body, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	var file generatedServiceRuleFile
	if err := json.Unmarshal(body, &file); err != nil {
		return out
	}
	for _, rule := range file.Rules {
		if rule.ID != "" && len(rule.Prefixes) > 0 {
			out[rule.ID] = rule
		}
	}
	return out
}

func fetchBotRule(ctx context.Context, client *http.Client, url, id, name, evidence, sourceName string) (generatedServiceRule, error) {
	if strings.TrimSpace(url) == "" {
		return generatedServiceRule{}, nil
	}
	body, err := downloadBytes(ctx, client, url)
	if err != nil {
		return generatedServiceRule{}, fmt.Errorf("%s: %w", sourceName, err)
	}
	prefixes, err := parseCrawlerPrefixes(body)
	if err != nil {
		return generatedServiceRule{}, fmt.Errorf("%s: %w", sourceName, err)
	}
	return newGeneratedServiceRule(id, name, "BOT", "搜索爬虫", 0.98, prefixes, evidence), nil
}

func fetchAddressListRule(ctx context.Context, client *http.Client, url, id, name, scene, sceneName string, confidence float64, evidence string) (generatedServiceRule, error) {
	if strings.TrimSpace(url) == "" {
		return generatedServiceRule{}, nil
	}
	body, err := downloadBytes(ctx, client, url)
	if err != nil {
		return generatedServiceRule{}, fmt.Errorf("%s: %w", name, err)
	}
	return newGeneratedServiceRule(id, name, scene, sceneName, confidence, parseAddressListPrefixes(body), evidence), nil
}

func fetchCombinedAddressListRule(ctx context.Context, client *http.Client, urls []string, id, name, scene, sceneName string, confidence float64, evidence string) (generatedServiceRule, error) {
	prefixes := []string{}
	sourceErrors := []string{}
	for _, sourceURL := range urls {
		if strings.TrimSpace(sourceURL) == "" {
			continue
		}
		body, err := downloadBytes(ctx, client, sourceURL)
		if err != nil {
			sourceErrors = append(sourceErrors, err.Error())
			continue
		}
		prefixes = append(prefixes, parseAddressListPrefixes(body)...)
	}
	rule := newGeneratedServiceRule(id, name, scene, sceneName, confidence, prefixes, evidence)
	if len(sourceErrors) > 0 && len(rule.Prefixes) == 0 {
		return generatedServiceRule{}, fmt.Errorf("%s: %s", name, strings.Join(sourceErrors, "; "))
	}
	return rule, nil
}

func fetchFastlyRule(ctx context.Context, client *http.Client, url string) (generatedServiceRule, error) {
	if strings.TrimSpace(url) == "" {
		return generatedServiceRule{}, nil
	}
	body, err := downloadBytes(ctx, client, url)
	if err != nil {
		return generatedServiceRule{}, fmt.Errorf("Fastly: %w", err)
	}
	prefixes, err := parseFastlyPrefixes(body)
	if err != nil {
		return generatedServiceRule{}, fmt.Errorf("Fastly: %w", err)
	}
	return newGeneratedServiceRule("dynamic-cdn-fastly", "Fastly CDN", "CDN", "内容分发", 0.99, prefixes, "Fastly 官方 public IP list"), nil
}

func fetchCloudJSONRule(ctx context.Context, client *http.Client, url, id, name, evidence string) (generatedServiceRule, error) {
	if strings.TrimSpace(url) == "" {
		return generatedServiceRule{}, nil
	}
	body, err := downloadBytes(ctx, client, url)
	if err != nil {
		return generatedServiceRule{}, fmt.Errorf("%s: %w", name, err)
	}
	prefixes, err := parseCloudJSONPrefixes(body)
	if err != nil {
		return generatedServiceRule{}, fmt.Errorf("%s: %w", name, err)
	}
	return newGeneratedServiceRule(id, name, "IDC", "数据中心", 0.97, prefixes, evidence), nil
}

func fetchCloudJSONServiceRule(ctx context.Context, client *http.Client, url, id, name, scene, sceneName string, confidence float64, evidence string, services ...string) (generatedServiceRule, error) {
	if strings.TrimSpace(url) == "" {
		return generatedServiceRule{}, nil
	}
	body, err := downloadBytes(ctx, client, url)
	if err != nil {
		return generatedServiceRule{}, fmt.Errorf("%s: %w", name, err)
	}
	prefixes, err := parseCloudJSONServicePrefixes(body, services...)
	if err != nil {
		return generatedServiceRule{}, fmt.Errorf("%s: %w", name, err)
	}
	return newGeneratedServiceRule(id, name, scene, sceneName, confidence, prefixes, evidence), nil
}

func fetchAzureServiceTagsRule(ctx context.Context, client *http.Client, url string) (generatedServiceRule, error) {
	if strings.TrimSpace(url) == "" {
		return generatedServiceRule{}, nil
	}
	body, err := downloadBytes(ctx, client, url)
	if err != nil {
		return generatedServiceRule{}, fmt.Errorf("Azure Service Tags: %w", err)
	}
	prefixes, err := parseAzureServiceTagsPrefixes(body)
	if err != nil {
		if nextURL := extractAzureDownloadURL(body); nextURL != "" {
			body, err = downloadBytes(ctx, client, nextURL)
			if err != nil {
				return generatedServiceRule{}, fmt.Errorf("Azure Service Tags: %w", err)
			}
			prefixes, err = parseAzureServiceTagsPrefixes(body)
		}
		if err != nil {
			return generatedServiceRule{}, fmt.Errorf("Azure Service Tags: %w", err)
		}
	}
	return newGeneratedServiceRule("dynamic-idc-azure", "Microsoft Azure", "IDC", "数据中心", 0.97, prefixes, "Microsoft Azure 官方 Service Tags"), nil
}

func fetchOracleRule(ctx context.Context, client *http.Client, url string) (generatedServiceRule, error) {
	if strings.TrimSpace(url) == "" {
		return generatedServiceRule{}, nil
	}
	body, err := downloadBytes(ctx, client, url)
	if err != nil {
		return generatedServiceRule{}, fmt.Errorf("Oracle Cloud: %w", err)
	}
	prefixes, err := parseOraclePrefixes(body)
	if err != nil {
		return generatedServiceRule{}, fmt.Errorf("Oracle Cloud: %w", err)
	}
	return newGeneratedServiceRule("dynamic-idc-oracle-cloud", "Oracle Cloud", "IDC", "数据中心", 0.97, prefixes, "Oracle Cloud 官方 public_ip_ranges.json"), nil
}

func fetchGitHubMetaRule(ctx context.Context, client *http.Client, url string) (generatedServiceRule, error) {
	if strings.TrimSpace(url) == "" {
		return generatedServiceRule{}, nil
	}
	body, err := downloadBytes(ctx, client, url)
	if err != nil {
		return generatedServiceRule{}, fmt.Errorf("GitHub Meta: %w", err)
	}
	prefixes, err := parseGitHubMetaPrefixes(body)
	if err != nil {
		return generatedServiceRule{}, fmt.Errorf("GitHub Meta: %w", err)
	}
	return newGeneratedServiceRule("dynamic-org-github", "GitHub", "ORG", "组织机构", 0.92, prefixes, "GitHub 官方 Meta IP 段"), nil
}

func fetchMailSPFRule(ctx context.Context, resolver spfTXTLookup, domains []string) (generatedServiceRule, error) {
	prefixes := []string{}
	visited := map[string]bool{}
	var sourceErrors []string
	for _, domain := range domains {
		next, err := collectSPFPrefixes(ctx, resolver, domain, visited, 0)
		if err != nil {
			sourceErrors = append(sourceErrors, err.Error())
			continue
		}
		prefixes = append(prefixes, next...)
	}
	rule := newGeneratedServiceRule("dynamic-mail-spf", "Major Mail SPF", "MAIL", "邮件服务", 0.96, prefixes, "常见邮件服务 SPF 记录")
	if len(sourceErrors) > 0 && len(rule.Prefixes) == 0 {
		return generatedServiceRule{}, fmt.Errorf("mail SPF: %s", strings.Join(sourceErrors, "; "))
	}
	return rule, nil
}

func fetchSpamhausDropRule(ctx context.Context, client *http.Client, v4URL, v6URL string) (generatedServiceRule, error) {
	prefixes := []string{}
	sourceErrors := []string{}
	for _, source := range []struct {
		name string
		url  string
	}{
		{name: "Spamhaus DROP IPv4", url: v4URL},
		{name: "Spamhaus DROP IPv6", url: v6URL},
	} {
		if strings.TrimSpace(source.url) == "" {
			continue
		}
		body, err := downloadBytes(ctx, client, source.url)
		if err != nil {
			sourceErrors = append(sourceErrors, fmt.Sprintf("%s: %v", source.name, err))
			continue
		}
		prefixes = append(prefixes, parseSpamhausDropPrefixes(body)...)
	}
	rule := newGeneratedServiceRule("dynamic-blocklist-spamhaus-drop", "Spamhaus DROP", "BLOCKLIST", "风险名单", 0.99, prefixes, "Spamhaus DROP 风险网段")
	if len(sourceErrors) > 0 && len(rule.Prefixes) == 0 {
		return generatedServiceRule{}, errors.New(strings.Join(sourceErrors, "; "))
	}
	return rule, nil
}

func fetchIP2ProxyRules(ctx context.Context, client *http.Client, cfg config.Config) ([]generatedServiceRule, error) {
	ip2proxy := cfg.DynamicRules.IP2Proxy
	if !ip2proxy.Enabled {
		return nil, nil
	}

	bodies, err := loadIP2ProxyBodies(ctx, client, ip2proxy)
	if err != nil {
		return nil, err
	}
	if len(bodies) == 0 {
		return nil, nil
	}

	prefixes := map[string][]string{}
	for _, body := range bodies {
		next, err := parseIP2ProxyPrefixes(body)
		if err != nil {
			return nil, fmt.Errorf("IP2Proxy parse: %w", err)
		}
		mergeIP2ProxyPrefixes(prefixes, next)
	}

	rules := []generatedServiceRule{}
	if len(prefixes["VPN"]) > 0 {
		rules = append(rules, newGeneratedServiceRule("dynamic-ip2proxy-vpn", "IP2Proxy VPN", "VPN", "VPN 出口", 0.97, prefixes["VPN"], "IP2Proxy 离线库标记为 VPN"))
	}
	if len(prefixes["PROXY"]) > 0 {
		rules = append(rules, newGeneratedServiceRule("dynamic-ip2proxy-proxy", "IP2Proxy Proxy", "PROXY", "代理服务", 0.96, prefixes["PROXY"], "IP2Proxy 离线库标记为代理"))
	}
	if len(prefixes["TOR"]) > 0 {
		rules = append(rules, newGeneratedServiceRule("dynamic-ip2proxy-tor", "IP2Proxy Tor", "TOR", "Tor 出口", 0.98, prefixes["TOR"], "IP2Proxy 离线库标记为 Tor 出口"))
	}
	return rules, nil
}

func loadIP2ProxyBodies(ctx context.Context, client *http.Client, cfg config.IP2ProxyConfig) ([][]byte, error) {
	bodies := [][]byte{}
	localFiles := append([]string{}, cfg.LocalFiles...)
	if strings.TrimSpace(cfg.LocalFile) != "" {
		localFiles = append([]string{cfg.LocalFile}, localFiles...)
	}
	for _, source := range uniqueStrings(localFiles) {
		source = strings.TrimSpace(source)
		if source == "" {
			continue
		}
		body, err := os.ReadFile(source)
		if err != nil {
			if os.IsNotExist(err) && cfg.DownloadURL == "" && len(cfg.DownloadURLs) == 0 && cfg.Token == "" {
				continue
			}
			return nil, fmt.Errorf("IP2Proxy local file %s: %w", source, err)
		}
		bodies = append(bodies, body)
	}

	downloadURLs := append([]string{}, cfg.DownloadURLs...)
	if strings.TrimSpace(cfg.DownloadURL) != "" {
		downloadURLs = append([]string{cfg.DownloadURL}, downloadURLs...)
	}
	packageCodes := ip2proxyPackageCodes(cfg)
	if len(downloadURLs) > 0 {
		for _, source := range uniqueStrings(downloadURLs) {
			source = strings.TrimSpace(source)
			if source == "" {
				continue
			}
			if len(packageCodes) > 0 && strings.TrimSpace(cfg.Token) != "" {
				for _, packageCode := range packageCodes {
					body, err := downloadBytes(ctx, client, ip2proxyDownloadURLFromBase(source, cfg.Token, packageCode))
					if err != nil {
						return nil, fmt.Errorf("IP2Proxy download %s: %w", packageCode, err)
					}
					bodies = append(bodies, body)
				}
				continue
			}
			body, err := downloadBytes(ctx, client, source)
			if err != nil {
				return nil, fmt.Errorf("IP2Proxy download: %w", err)
			}
			bodies = append(bodies, body)
		}
		return bodies, nil
	}

	if strings.TrimSpace(cfg.Token) != "" {
		for _, packageCode := range packageCodes {
			body, err := downloadBytes(ctx, client, ip2proxyDownloadURLFromBase("https://www.ip2location.com/download", cfg.Token, packageCode))
			if err != nil {
				return nil, fmt.Errorf("IP2Proxy download %s: %w", packageCode, err)
			}
			bodies = append(bodies, body)
		}
	}
	return bodies, nil
}

func ip2proxyPackageCodes(cfg config.IP2ProxyConfig) []string {
	codes := append([]string{}, cfg.Packages...)
	if strings.TrimSpace(cfg.Package) != "" {
		codes = append([]string{cfg.Package}, codes...)
	}
	if len(codes) == 0 {
		codes = []string{"PX11"}
	}
	return uniqueStrings(codes)
}

func ip2proxyDownloadURLFromBase(baseURL, token, packageCode string) string {
	packageCode = strings.TrimSpace(packageCode)
	if packageCode == "" {
		packageCode = "PX11"
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		parsed = &url.URL{Scheme: "https", Host: "www.ip2location.com", Path: "/download"}
	}
	query := url.Values{}
	for key, values := range parsed.Query() {
		for _, value := range values {
			query.Add(key, value)
		}
	}
	query.Set("token", token)
	query.Set("file", packageCode)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func parseIP2ProxyPrefixes(body []byte) (map[string][]string, error) {
	if zipReader, err := zip.NewReader(bytes.NewReader(body), int64(len(body))); err == nil {
		out := map[string][]string{}
		for _, file := range zipReader.File {
			name := strings.ToLower(file.Name)
			if !strings.HasSuffix(name, ".csv") && !strings.Contains(name, "cidr") {
				continue
			}
			rc, err := file.Open()
			if err != nil {
				return nil, err
			}
			next, parseErr := parseIP2ProxyCSV(rc)
			closeErr := rc.Close()
			if parseErr != nil {
				return nil, parseErr
			}
			if closeErr != nil {
				return nil, closeErr
			}
			mergeIP2ProxyPrefixes(out, next)
		}
		return out, nil
	}
	return parseIP2ProxyCSV(bytes.NewReader(body))
}

func parseIP2ProxyCSV(r io.Reader) (map[string][]string, error) {
	reader := csv.NewReader(r)
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = true
	out := map[string][]string{}
	for {
		row, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(row) < 2 {
			continue
		}
		for i := range row {
			row[i] = strings.TrimSpace(strings.Trim(row[i], `"`))
		}
		scene, prefixes := ip2proxyRowSceneAndPrefixes(row)
		if scene == "" || len(prefixes) == 0 {
			continue
		}
		out[scene] = append(out[scene], prefixes...)
	}
	return out, nil
}

func ip2proxyRowSceneAndPrefixes(row []string) (string, []string) {
	if len(row) >= 2 {
		if prefix, err := netip.ParsePrefix(row[0]); err == nil {
			scene := ip2proxyScene(row[1])
			if scene == "" {
				return "", nil
			}
			return scene, []string{prefix.Masked().String()}
		}
	}
	if len(row) < 3 {
		return "", nil
	}
	scene := ip2proxyScene(row[2])
	if scene == "" {
		return "", nil
	}
	start, ok := new(big.Int).SetString(row[0], 10)
	if !ok {
		return "", nil
	}
	end, ok := new(big.Int).SetString(row[1], 10)
	if !ok || start.Sign() < 0 || end.Cmp(start) < 0 {
		return "", nil
	}
	bits := 32
	if end.BitLen() > 32 {
		bits = 128
	}
	return scene, bigRangeToPrefixes(start, end, bits)
}

func ip2proxyScene(proxyType string) string {
	switch strings.ToUpper(strings.TrimSpace(proxyType)) {
	case "VPN", "EPN":
		return "VPN"
	case "TOR":
		return "TOR"
	case "PUB", "WEB", "RES", "CPN":
		return "PROXY"
	default:
		return ""
	}
}

func mergeIP2ProxyPrefixes(dst, src map[string][]string) {
	for scene, prefixes := range src {
		dst[scene] = append(dst[scene], prefixes...)
	}
}

func newGeneratedServiceRule(id, name, scene, sceneName string, confidence float64, prefixes []string, evidence string) generatedServiceRule {
	return generatedServiceRule{
		ID:         id,
		Name:       name,
		Scene:      scene,
		SceneName:  sceneName,
		Confidence: confidence,
		Prefixes:   uniqueSortedPrefixes(prefixes),
		Evidence:   evidence,
	}
}

func bigRangeToPrefixes(start, end *big.Int, bits int) []string {
	current := new(big.Int).Set(start)
	one := big.NewInt(1)
	out := []string{}
	for current.Cmp(end) <= 0 {
		blockBits := trailingZeroBits(current, bits)
		remaining := new(big.Int).Sub(end, current)
		remaining.Add(remaining, one)
		for blockBits > 0 {
			blockSize := new(big.Int).Lsh(one, uint(blockBits))
			if blockSize.Cmp(remaining) <= 0 {
				break
			}
			blockBits--
		}
		addr, ok := bigIntToAddr(current, bits)
		if !ok {
			return out
		}
		out = append(out, netip.PrefixFrom(addr, bits-blockBits).Masked().String())
		current.Add(current, new(big.Int).Lsh(one, uint(blockBits)))
	}
	return out
}

func trailingZeroBits(value *big.Int, bits int) int {
	if value.Sign() == 0 {
		return bits
	}
	for i := 0; i < bits; i++ {
		if value.Bit(i) == 1 {
			return i
		}
	}
	return bits
}

func bigIntToAddr(value *big.Int, bits int) (netip.Addr, bool) {
	if value.Sign() < 0 || value.BitLen() > bits {
		return netip.Addr{}, false
	}
	if bits == 32 {
		return netip.AddrFrom4([4]byte{
			byte(value.Uint64() >> 24),
			byte(value.Uint64() >> 16),
			byte(value.Uint64() >> 8),
			byte(value.Uint64()),
		}), true
	}
	raw := value.Bytes()
	if len(raw) > 16 {
		return netip.Addr{}, false
	}
	var out [16]byte
	copy(out[16-len(raw):], raw)
	return netip.AddrFrom16(out), true
}

func downloadBytes(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func parseCrawlerPrefixes(body []byte) ([]string, error) {
	var payload struct {
		Prefixes []struct {
			IPv4Prefix string `json:"ipv4Prefix"`
			IPv6Prefix string `json:"ipv6Prefix"`
		} `json:"prefixes"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	out := []string{}
	for _, prefix := range payload.Prefixes {
		out = appendNormalizedPrefix(out, prefix.IPv4Prefix)
		out = appendNormalizedPrefix(out, prefix.IPv6Prefix)
	}
	return out, nil
}

func parseFastlyPrefixes(body []byte) ([]string, error) {
	var payload struct {
		Addresses     []string `json:"addresses"`
		IPv6Addresses []string `json:"ipv6_addresses"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	out := []string{}
	for _, prefix := range payload.Addresses {
		out = appendNormalizedPrefix(out, prefix)
	}
	for _, prefix := range payload.IPv6Addresses {
		out = appendNormalizedPrefix(out, prefix)
	}
	return out, nil
}

func parseCloudJSONPrefixes(body []byte) ([]string, error) {
	return parseCloudJSONServicePrefixes(body)
}

func parseCloudJSONServicePrefixes(body []byte, services ...string) ([]string, error) {
	var payload struct {
		Prefixes []struct {
			IPPrefix    string `json:"ip_prefix"`
			IPv4Prefix  string `json:"ipv4Prefix"`
			IPv6Prefix  string `json:"ipv6_prefix"`
			IPv6Prefix2 string `json:"ipv6Prefix"`
			Service     string `json:"service"`
		} `json:"prefixes"`
		IPv6Prefixes []struct {
			IPv6Prefix string `json:"ipv6_prefix"`
			Service    string `json:"service"`
		} `json:"ipv6_prefixes"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	serviceSet := map[string]bool{}
	for _, service := range services {
		service = strings.ToUpper(strings.TrimSpace(service))
		if service != "" {
			serviceSet[service] = true
		}
	}
	includeService := func(service string) bool {
		return len(serviceSet) == 0 || serviceSet[strings.ToUpper(strings.TrimSpace(service))]
	}
	out := []string{}
	for _, prefix := range payload.Prefixes {
		if !includeService(prefix.Service) {
			continue
		}
		out = appendNormalizedPrefix(out, prefix.IPPrefix)
		out = appendNormalizedPrefix(out, prefix.IPv4Prefix)
		out = appendNormalizedPrefix(out, prefix.IPv6Prefix)
		out = appendNormalizedPrefix(out, prefix.IPv6Prefix2)
	}
	for _, prefix := range payload.IPv6Prefixes {
		if !includeService(prefix.Service) {
			continue
		}
		out = appendNormalizedPrefix(out, prefix.IPv6Prefix)
	}
	return out, nil
}

func parseAzureServiceTagsPrefixes(body []byte) ([]string, error) {
	var payload struct {
		Values []struct {
			Properties struct {
				AddressPrefixes []string `json:"addressPrefixes"`
			} `json:"properties"`
		} `json:"values"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	out := []string{}
	for _, value := range payload.Values {
		for _, prefix := range value.Properties.AddressPrefixes {
			out = appendNormalizedPrefix(out, prefix)
		}
	}
	return out, nil
}

func extractAzureDownloadURL(body []byte) string {
	re := regexp.MustCompile(`https://download\.microsoft\.com/download/[^"'<> ]+?ServiceTags_Public_[^"'<> ]+?\.json`)
	return re.FindString(string(body))
}

func parseOraclePrefixes(body []byte) ([]string, error) {
	var payload struct {
		Regions []struct {
			CIDRs []struct {
				CIDR string `json:"cidr"`
			} `json:"cidrs"`
		} `json:"regions"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	out := []string{}
	for _, region := range payload.Regions {
		for _, cidr := range region.CIDRs {
			out = appendNormalizedPrefix(out, cidr.CIDR)
		}
	}
	return out, nil
}

func parseGitHubMetaPrefixes(body []byte) ([]string, error) {
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	keys := []string{"web", "api", "git", "pages", "hooks", "actions"}
	out := []string{}
	for _, key := range keys {
		var prefixes []string
		if err := json.Unmarshal(payload[key], &prefixes); err != nil {
			continue
		}
		for _, prefix := range prefixes {
			out = appendNormalizedPrefix(out, prefix)
		}
	}
	return out, nil
}

func parseAddressListPrefixes(body []byte) []string {
	out := []string{}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Split(bufio.ScanWords)
	for scanner.Scan() {
		token := strings.TrimSpace(scanner.Text())
		if token == "" || strings.HasPrefix(token, "#") || strings.HasPrefix(token, ";") {
			continue
		}
		out = appendNormalizedPrefix(out, token)
	}
	return out
}

func parseSpamhausDropPrefixes(body []byte) []string {
	out := []string{}
	if prefixes := parseSpamhausDropJSONArray(body); len(prefixes) > 0 {
		return prefixes
	}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if left, _, ok := strings.Cut(line, ";"); ok {
			out = appendNormalizedPrefix(out, strings.TrimSpace(left))
			continue
		}
		var row struct {
			CIDR string `json:"cidr"`
		}
		if err := json.Unmarshal([]byte(line), &row); err == nil {
			out = appendNormalizedPrefix(out, row.CIDR)
		}
	}
	return out
}

func parseSpamhausDropJSONArray(body []byte) []string {
	var rows []struct {
		CIDR string `json:"cidr"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil
	}
	out := []string{}
	for _, row := range rows {
		out = appendNormalizedPrefix(out, row.CIDR)
	}
	return out
}

func collectSPFPrefixes(ctx context.Context, resolver spfTXTLookup, domain string, visited map[string]bool, depth int) ([]string, error) {
	domain = strings.TrimSpace(strings.TrimSuffix(domain, "."))
	if domain == "" || visited[domain] {
		return nil, nil
	}
	if depth > 10 {
		return nil, fmt.Errorf("SPF include depth exceeded at %s", domain)
	}
	visited[domain] = true
	txts, err := resolver.LookupTXT(ctx, domain)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, txt := range txts {
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(txt)), "v=spf1") {
			continue
		}
		parsed := parseSPFRecord(txt)
		out = append(out, parsed.prefixes...)
		for _, include := range parsed.includes {
			next, err := collectSPFPrefixes(ctx, resolver, include, visited, depth+1)
			if err != nil {
				return out, err
			}
			out = append(out, next...)
		}
		if parsed.redirect != "" {
			next, err := collectSPFPrefixes(ctx, resolver, parsed.redirect, visited, depth+1)
			if err != nil {
				return out, err
			}
			out = append(out, next...)
		}
	}
	return out, nil
}

type parsedSPFRecord struct {
	prefixes []string
	includes []string
	redirect string
}

func parseSPFRecord(record string) parsedSPFRecord {
	out := parsedSPFRecord{}
	for _, term := range strings.Fields(record) {
		term = strings.TrimSpace(term)
		if term == "" || strings.EqualFold(term, "v=spf1") {
			continue
		}
		if strings.ContainsRune("+-~?", rune(term[0])) {
			term = term[1:]
		}
		switch {
		case strings.HasPrefix(term, "ip4:"):
			out.prefixes = appendNormalizedPrefix(out.prefixes, strings.TrimPrefix(term, "ip4:"))
		case strings.HasPrefix(term, "ip6:"):
			out.prefixes = appendNormalizedPrefix(out.prefixes, strings.TrimPrefix(term, "ip6:"))
		case strings.HasPrefix(term, "include:"):
			out.includes = append(out.includes, strings.TrimPrefix(term, "include:"))
		case strings.HasPrefix(term, "redirect="):
			out.redirect = strings.TrimPrefix(term, "redirect=")
		}
	}
	return out
}

func appendNormalizedPrefix(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return append(values, prefix.Masked().String())
	}
	if addr, err := netip.ParseAddr(value); err == nil {
		if addr.Is4() {
			return append(values, netip.PrefixFrom(addr, 32).String())
		}
		return append(values, netip.PrefixFrom(addr, 128).String())
	}
	return values
}

func uniqueSortedPrefixes(prefixes []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, prefix := range prefixes {
		if prefix == "" || seen[prefix] {
			continue
		}
		seen[prefix] = true
		out = append(out, prefix)
	}
	sort.Strings(out)
	return out
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}
