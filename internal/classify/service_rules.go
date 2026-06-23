package classify

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

type serviceRuleFile struct {
	Version string        `json:"version"`
	Rules   []ServiceRule `json:"rules"`
}

type ServiceRule struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Scene             string   `json:"scene"`
	SceneName         string   `json:"scene_name"`
	Confidence        float64  `json:"confidence"`
	Prefixes          []string `json:"prefixes"`
	RDNSContains      []string `json:"rdns_contains"`
	Evidence          string   `json:"evidence"`
	ServiceName       string   `json:"service_name,omitempty"`
	ServiceSubtype    string   `json:"service_subtype,omitempty"`
	RiskLevel         string   `json:"risk_level,omitempty"`
	BlockRecommended  *bool    `json:"block_recommended,omitempty"`
	NormalUserTraffic *bool    `json:"normal_user_traffic,omitempty"`

	parsedPrefixes []netip.Prefix
}

type serviceRulePrefixMatch struct {
	RuleID   string
	Scene    string
	Points   int
	Evidence string
	Policy   *ServicePolicy
}

type serviceRulePrefixIndex struct {
	v4 [33]map[uint32][]serviceRulePrefixMatch
	v6 [129]map[[2]uint64][]serviceRulePrefixMatch
}

var serviceRules = struct {
	sync.RWMutex
	values          []ServiceRule
	prefixIndex     serviceRulePrefixIndex
	paths           []string
	modTimes        map[string]time.Time
	nextReloadCheck time.Time
}{}

const serviceRulesReloadInterval = 30 * time.Second

func LoadServiceRules(path string) error {
	if strings.TrimSpace(path) == "" {
		setServiceRules(nil, nil, nil)
		return nil
	}
	return loadServiceRuleFiles([]string{path}, false)
}

func LoadServiceRuleFiles(paths ...string) error {
	return loadServiceRuleFiles(paths, true)
}

func loadServiceRuleFiles(paths []string, skipMissing bool) error {
	cleanPaths := make([]string, 0, len(paths))
	rules := []ServiceRule{}
	modTimes := map[string]time.Time{}
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		stat, err := os.Stat(path)
		if err != nil {
			if skipMissing && os.IsNotExist(err) {
				cleanPaths = append(cleanPaths, path)
				continue
			}
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		parsed, err := parseServiceRules(body)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		cleanPaths = append(cleanPaths, path)
		rules = append(rules, parsed...)
		modTimes[path] = stat.ModTime()
	}
	setServiceRules(rules, cleanPaths, modTimes)
	return nil
}

func parseServiceRules(body []byte) ([]ServiceRule, error) {
	var file serviceRuleFile
	if err := json.Unmarshal(body, &file); err != nil {
		return nil, err
	}
	out := make([]ServiceRule, 0, len(file.Rules))
	for i, rule := range file.Rules {
		rule.Scene = strings.ToUpper(strings.TrimSpace(rule.Scene))
		if rule.Scene == "" {
			return nil, fmt.Errorf("service rule %d missing scene", i)
		}
		if _, ok := sceneNames[rule.Scene]; !ok {
			return nil, fmt.Errorf("service rule %s uses unknown scene %s", rule.ID, rule.Scene)
		}
		if rule.SceneName == "" {
			rule.SceneName = sceneNames[rule.Scene]
		}
		if rule.Confidence <= 0 {
			rule.Confidence = 0.95
		}
		if rule.Confidence > 0.99 {
			rule.Confidence = 0.99
		}
		for _, prefixText := range rule.Prefixes {
			prefix, err := netip.ParsePrefix(prefixText)
			if err != nil {
				return nil, fmt.Errorf("service rule %s prefix %q: %w", rule.ID, prefixText, err)
			}
			rule.parsedPrefixes = append(rule.parsedPrefixes, prefix.Masked())
		}
		for i := range rule.RDNSContains {
			rule.RDNSContains[i] = strings.ToLower(strings.TrimSpace(rule.RDNSContains[i]))
		}
		out = append(out, rule)
	}
	return out, nil
}

func setServiceRules(rules []ServiceRule, paths []string, modTimes map[string]time.Time) {
	serviceRules.Lock()
	defer serviceRules.Unlock()
	serviceRules.values = append([]ServiceRule(nil), rules...)
	serviceRules.prefixIndex = buildServiceRulePrefixIndex(rules)
	serviceRules.paths = append([]string(nil), paths...)
	serviceRules.modTimes = cloneModTimes(modTimes)
	serviceRules.nextReloadCheck = time.Now().Add(serviceRulesReloadInterval)
}

func currentServiceRules() []ServiceRule {
	maybeReloadServiceRules()
	serviceRules.RLock()
	defer serviceRules.RUnlock()
	return append([]ServiceRule(nil), serviceRules.values...)
}

func currentPrefixMatches(addr netip.Addr) []serviceRulePrefixMatch {
	maybeReloadServiceRules()
	serviceRules.RLock()
	defer serviceRules.RUnlock()
	return serviceRules.prefixIndex.lookup(addr)
}

func maybeReloadServiceRules() {
	serviceRules.RLock()
	paths := append([]string(nil), serviceRules.paths...)
	nextCheck := serviceRules.nextReloadCheck
	serviceRules.RUnlock()
	if len(paths) == 0 || time.Now().Before(nextCheck) {
		return
	}

	serviceRules.Lock()
	if time.Now().Before(serviceRules.nextReloadCheck) {
		serviceRules.Unlock()
		return
	}
	changed := false
	for _, path := range paths {
		stat, err := os.Stat(path)
		if err != nil {
			changed = true
			break
		}
		if !stat.ModTime().Equal(serviceRules.modTimes[path]) {
			changed = true
			break
		}
	}
	serviceRules.nextReloadCheck = time.Now().Add(serviceRulesReloadInterval)
	serviceRules.Unlock()

	if changed {
		_ = LoadServiceRuleFiles(paths...)
	}
}

func cloneModTimes(values map[string]time.Time) map[string]time.Time {
	if values == nil {
		return nil
	}
	out := make(map[string]time.Time, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func applyServiceRules(input Input, add func(scene string, points int, evidence string, policy *ServicePolicy)) {
	if !input.IP.IsValid() && strings.TrimSpace(input.RDNS) == "" {
		return
	}
	seen := map[string]bool{}
	for _, match := range currentPrefixMatches(input.IP) {
		seen[match.RuleID] = true
		add(match.Scene, match.Points, match.Evidence, match.Policy)
	}
	rdns := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(input.RDNS), "."))
	for _, rule := range currentServiceRules() {
		if !seen[rule.ID] && serviceRuleRDNSMatches(rule, rdns) {
			points := serviceRulePoints(rule.Confidence)
			evidence := rule.Evidence
			if evidence == "" {
				evidence = "命中离线服务规则：" + rule.Name
			}
			add(rule.Scene, points, evidence, servicePolicyFromRule(rule))
		}
	}
}

func serviceRuleRDNSMatches(rule ServiceRule, rdns string) bool {
	if rdns == "" {
		return false
	}
	for _, needle := range rule.RDNSContains {
		if needle != "" && strings.Contains(rdns, needle) {
			return true
		}
	}
	return false
}

func buildServiceRulePrefixIndex(rules []ServiceRule) serviceRulePrefixIndex {
	var idx serviceRulePrefixIndex
	for _, rule := range rules {
		points := serviceRulePoints(rule.Confidence)
		evidence := rule.Evidence
		if evidence == "" {
			evidence = "命中离线服务规则：" + rule.Name
		}
		policy := servicePolicyFromRule(rule)
		for _, prefix := range rule.parsedPrefixes {
			match := serviceRulePrefixMatch{
				RuleID:   rule.ID,
				Scene:    rule.Scene,
				Points:   points + prefix.Bits(),
				Evidence: evidence,
				Policy:   policy,
			}
			idx.add(prefix, match)
		}
	}
	return idx
}

func servicePolicyFromRule(rule ServiceRule) *ServicePolicy {
	if rule.ServiceName == "" && rule.ServiceSubtype == "" && rule.RiskLevel == "" && rule.BlockRecommended == nil && rule.NormalUserTraffic == nil {
		return nil
	}
	serviceName := strings.TrimSpace(rule.ServiceName)
	if serviceName == "" {
		serviceName = strings.TrimSpace(rule.Name)
	}
	return &ServicePolicy{
		RuleID:            rule.ID,
		RuleName:          rule.Name,
		ServiceName:       serviceName,
		ServiceSubtype:    strings.TrimSpace(rule.ServiceSubtype),
		RiskLevel:         strings.TrimSpace(rule.RiskLevel),
		BlockRecommended:  rule.BlockRecommended,
		NormalUserTraffic: rule.NormalUserTraffic,
	}
}

func serviceRulePoints(confidence float64) int {
	return int(confidence*100) + 300
}

func (idx *serviceRulePrefixIndex) add(prefix netip.Prefix, match serviceRulePrefixMatch) {
	prefix = prefix.Masked()
	addr := prefix.Addr().Unmap()
	if addr.Is4() {
		bits := prefix.Bits()
		if bits < 0 || bits > 32 {
			return
		}
		if idx.v4[bits] == nil {
			idx.v4[bits] = map[uint32][]serviceRulePrefixMatch{}
		}
		key := serviceRuleMaskIPv4(addr, bits)
		idx.v4[bits][key] = append(idx.v4[bits][key], match)
		return
	}
	if addr.Is6() {
		bits := prefix.Bits()
		if bits < 0 || bits > 128 {
			return
		}
		if idx.v6[bits] == nil {
			idx.v6[bits] = map[[2]uint64][]serviceRulePrefixMatch{}
		}
		key := serviceRuleMaskIPv6(addr, bits)
		idx.v6[bits][key] = append(idx.v6[bits][key], match)
	}
}

func (idx serviceRulePrefixIndex) lookup(addr netip.Addr) []serviceRulePrefixMatch {
	if !addr.IsValid() {
		return nil
	}
	addr = addr.Unmap()
	out := []serviceRulePrefixMatch{}
	if addr.Is4() {
		for bits := 32; bits >= 0; bits-- {
			bucket := idx.v4[bits]
			if bucket == nil {
				continue
			}
			out = append(out, bucket[serviceRuleMaskIPv4(addr, bits)]...)
		}
		return out
	}
	if addr.Is6() {
		for bits := 128; bits >= 0; bits-- {
			bucket := idx.v6[bits]
			if bucket == nil {
				continue
			}
			out = append(out, bucket[serviceRuleMaskIPv6(addr, bits)]...)
		}
	}
	return out
}

func serviceRuleMaskIPv4(addr netip.Addr, bits int) uint32 {
	raw := addr.As4()
	value := binary.BigEndian.Uint32(raw[:])
	if bits == 0 {
		return 0
	}
	return value & (uint32(0xffffffff) << (32 - bits))
}

func serviceRuleMaskIPv6(addr netip.Addr, bits int) [2]uint64 {
	raw := addr.As16()
	hi := binary.BigEndian.Uint64(raw[0:8])
	lo := binary.BigEndian.Uint64(raw[8:16])
	switch {
	case bits <= 0:
		return [2]uint64{0, 0}
	case bits < 64:
		return [2]uint64{hi & (uint64(0xffffffffffffffff) << (64 - bits)), 0}
	case bits == 64:
		return [2]uint64{hi, 0}
	case bits < 128:
		return [2]uint64{hi, lo & (uint64(0xffffffffffffffff) << (128 - bits))}
	default:
		return [2]uint64{hi, lo}
	}
}

func resetServiceRulesForTest(t interface{ Cleanup(func()) }) {
	serviceRules.RLock()
	previous := append([]ServiceRule(nil), serviceRules.values...)
	previousPaths := append([]string(nil), serviceRules.paths...)
	previousModTimes := cloneModTimes(serviceRules.modTimes)
	serviceRules.RUnlock()
	setServiceRules(nil, nil, nil)
	t.Cleanup(func() {
		setServiceRules(previous, previousPaths, previousModTimes)
	})
}
