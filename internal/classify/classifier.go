package classify

import (
	"net/netip"
	"sort"
	"strings"

	"ipasn/internal/store"
)

type Input struct {
	IP            netip.Addr
	MatchedPrefix string
	Profile       store.ASNProfile
	RDNS          string
}

type Result struct {
	Scene         string         `json:"scene"`
	SceneName     string         `json:"scene_name"`
	Confidence    float64        `json:"confidence"`
	Evidence      []string       `json:"evidence"`
	ServicePolicy *ServicePolicy `json:"service_policy,omitempty"`
}

type ServicePolicy struct {
	RuleID            string `json:"rule_id,omitempty"`
	RuleName          string `json:"rule_name,omitempty"`
	ServiceName       string `json:"service_name,omitempty"`
	ServiceSubtype    string `json:"service_subtype,omitempty"`
	RiskLevel         string `json:"risk_level,omitempty"`
	BlockRecommended  *bool  `json:"block_recommended,omitempty"`
	NormalUserTraffic *bool  `json:"normal_user_traffic,omitempty"`
}

type score struct {
	points       int
	evidence     []string
	policy       *ServicePolicy
	policyPoints int
}

var sceneNames = map[string]string{
	"CDN":       "内容分发",
	"DNS":       "域名解析",
	"EDU":       "教育机构",
	"GTW":       "企业专线",
	"GOV":       "政府机构",
	"DYN":       "家庭宽带",
	"IDC":       "数据中心",
	"MOB":       "移动网络",
	"ORG":       "组织机构",
	"NET":       "基础设施",
	"BOGON":     "保留 IP",
	"UNROUTED":  "已分配未宣告",
	"STUN":      "NAT 穿透",
	"VPN":       "VPN 出口",
	"PROXY":     "代理服务",
	"TOR":       "Tor 出口",
	"BOT":       "搜索爬虫",
	"MAIL":      "邮件服务",
	"MON":       "监控探测",
	"IOT":       "物联网平台",
	"BLOCKLIST": "风险名单",
}

var bogonPrefixes = mustPrefixes([]string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
	"224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "fc00::/7",
	"fe80::/10", "2001:db8::/32", "ff00::/8",
})

var knownDNSPrefixes = mustPrefixes([]string{
	"1.1.1.0/24", "1.0.0.0/24", "8.8.8.0/24", "8.8.4.0/24",
	"9.9.9.0/24", "149.112.112.0/24", "208.67.222.0/24", "208.67.220.0/24",
	"114.114.114.114/32", "114.114.115.115/32", "114.114.114.119/32", "114.114.115.119/32",
	"2001:4860:4860::/48", "2606:4700:4700::/48", "2620:fe::/48",
})

func Classify(input Input) Result {
	if input.IP.IsValid() && containsPrefix(bogonPrefixes, input.IP) {
		return Result{Scene: "BOGON", SceneName: sceneNames["BOGON"], Confidence: 1, Evidence: []string{"IP 命中保留地址范围"}}
	}

	scores := map[string]*score{}
	addWithPolicy := func(scene string, points int, evidence string, policy *ServicePolicy) {
		if scores[scene] == nil {
			scores[scene] = &score{}
		}
		scores[scene].points += points
		if evidence != "" {
			scores[scene].evidence = append(scores[scene].evidence, evidence)
		}
		if policy != nil && points > scores[scene].policyPoints {
			scores[scene].policy = policy
			scores[scene].policyPoints = points
		}
	}
	add := func(scene string, points int, evidence string) {
		addWithPolicy(scene, points, evidence, nil)
	}

	text := strings.ToLower(strings.Join([]string{
		input.Profile.Name,
		input.Profile.AKA,
		input.Profile.InfoType,
		input.Profile.Website,
		input.RDNS,
	}, " "))

	if input.IP.IsValid() && containsPrefix(knownDNSPrefixes, input.IP) {
		add("DNS", 95, "IP 命中已知公共 DNS 网段")
	}
	applyServiceRules(input, addWithPolicy)
	applyASNSceneRules(input, add)
	if rdnsLooksLikeDNS(input.RDNS) {
		add("DNS", 90, "反向 DNS 显示为公共 DNS")
	}
	if containsAny(text,
		"amazon technologies", "amazon.com", "amazon web services", "aws.amazon.com", "aws",
		"alibaba", "alibaba cloud", "alicdn", "aliyun", "alibabacloud",
		"tencent", "tencent global", "tencent cloud", "google cloud", "cloud.google.com", "microsoft azure", "azure.com",
		"oracle cloud", "huawei cloud",
	) {
		add("IDC", 125, "命中云厂商特征")
	}
	if containsAny(text,
		"t-mobile", "tmobile", "myvzw", "verizon wireless", "cellco", "wirelessdatanetwork",
		"at&t mobility", "att mobility", "china mobile", "mobile international",
	) {
		add("MOB", 115, "命中移动运营商特征")
	}
	if containsAny(text,
		"frontiernet.net", "frontier communications", "comcast cable", "charter communications",
		"spectrum residential", "cox communications", "verizon fios",
	) {
		add("DYN", 115, "命中家庭宽带运营商特征")
	}

	keywordRules := []struct {
		scene    string
		points   int
		keywords []string
	}{
		{"DNS", 75, []string{" dns", "resolver", "quad9", "opendns", "public dns"}},
		{"TOR", 92, []string{"tor exit", "tor relay"}},
		{"VPN", 86, []string{" vpn", "virtual private network"}},
		{"PROXY", 84, []string{" proxy", "open proxy"}},
		{"BOT", 82, []string{"googlebot", "bingbot", "crawler", "spider"}},
		{"MAIL", 80, []string{"smtp", "mail server", "email service", "mx"}},
		{"MON", 78, []string{"uptime", "monitoring", "probe"}},
		{"IOT", 76, []string{" iot", "internet of things"}},
		{"CDN", 80, []string{"cloudflare", "akamai", "fastly", "cloudfront", "cdn77", "edgecast", "bunnycdn", "cachefly", " cdn"}},
		{"IDC", 78, []string{"amazon", "aws", "google cloud", "microsoft", "azure", "oracle cloud", "alibaba cloud", "tencent cloud", "huawei cloud", "hetzner", "ovh", "digitalocean", "linode", "vultr", "datacenter", "data center", "hosting", "cloud", "server", "colo"}},
		{"EDU", 85, []string{"university", "college", "school", ".edu", "institute of technology"}},
		{"GOV", 85, []string{"government", ".gov", "ministry", "department of", "military"}},
		{"MOB", 82, []string{"mobile", "cellular", "wireless", "lte", "5g", "4g", "3g"}},
		{"DYN", 82, []string{"residential", "broadband", "dynamic", "cable", "dsl", "pppoe", "home internet"}},
		{"ORG", 70, []string{"foundation", "non-profit", "nonprofit", "association", "ngo"}},
		{"NET", 72, []string{"internet exchange", " ixp", "backbone", "router", "transport", "carrier", "noc", "infrastructure", "peering"}},
		{"GTW", 68, []string{"enterprise", "corporate", "business", "leased line", "dedicated", "office"}},
	}

	for _, rule := range keywordRules {
		for _, keyword := range rule.keywords {
			if strings.Contains(text, keyword) {
				add(rule.scene, rule.points, "命中关键词："+strings.TrimSpace(keyword))
				break
			}
		}
	}

	switch strings.ToLower(input.Profile.InfoType) {
	case "content":
		add("CDN", 45, "PeeringDB 网络类型为 Content")
	case "enterprise":
		add("GTW", 45, "PeeringDB 网络类型为 Enterprise")
	case "network service provider", "nsp":
		add("NET", 30, "PeeringDB 网络类型为 NSP")
	}

	if len(scores) == 0 {
		return Result{Scene: "NET", SceneName: sceneNames["NET"], Confidence: 0.35, Evidence: []string{"未命中明确规则，按网络基础设施处理"}}
	}

	type ranked struct {
		scene string
		score *score
	}
	ranking := make([]ranked, 0, len(scores))
	for scene, score := range scores {
		ranking = append(ranking, ranked{scene: scene, score: score})
	}
	sort.Slice(ranking, func(i, j int) bool {
		if ranking[i].score.points == ranking[j].score.points {
			return ranking[i].scene < ranking[j].scene
		}
		return ranking[i].score.points > ranking[j].score.points
	})

	best := ranking[0]
	confidence := float64(best.score.points) / 100
	if confidence > 0.99 {
		confidence = 0.99
	}
	if confidence < 0.3 {
		confidence = 0.3
	}

	return Result{
		Scene:         best.scene,
		SceneName:     sceneNames[best.scene],
		Confidence:    confidence,
		Evidence:      best.score.evidence,
		ServicePolicy: best.score.policy,
	}
}

func rdnsLooksLikeDNS(rdns string) bool {
	rdns = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rdns), "."))
	if rdns == "" {
		return false
	}
	labels := strings.Split(rdns, ".")
	for _, label := range labels {
		if label == "dns" || strings.HasSuffix(label, "dns") || strings.HasPrefix(label, "dns") {
			return true
		}
	}
	return strings.Contains(rdns, "resolver")
}

func containsAny(text string, keywords ...string) bool {
	for _, keyword := range keywords {
		if strings.Contains(text, keyword) {
			return true
		}
	}
	return false
}

func containsPrefix(prefixes []netip.Prefix, addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func mustPrefixes(values []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		out = append(out, netip.MustParsePrefix(value))
	}
	return out
}
