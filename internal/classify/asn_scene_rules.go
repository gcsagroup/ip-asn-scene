package classify

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

type asnSceneRuleFile struct {
	Rules []ASNSceneRule `yaml:"rules" json:"rules"`
}

type ASNSceneRule struct {
	ASN        int     `yaml:"asn" json:"asn"`
	Scene      string  `yaml:"scene" json:"scene"`
	SceneName  string  `yaml:"scene_name" json:"scene_name"`
	Name       string  `yaml:"name" json:"name"`
	Country    string  `yaml:"country" json:"country"`
	Region     string  `yaml:"region" json:"region"`
	Confidence float64 `yaml:"confidence" json:"confidence"`
	Source     string  `yaml:"source" json:"source"`
	Reason     string  `yaml:"reason" json:"reason"`
}

var asnSceneRules = struct {
	sync.RWMutex
	values          map[int]ASNSceneRule
	paths           []string
	modTimes        map[string]time.Time
	nextReloadCheck time.Time
}{values: map[int]ASNSceneRule{}}

func LoadASNSceneRules(path string) error {
	if strings.TrimSpace(path) == "" {
		setASNSceneRules(nil, nil, nil)
		return nil
	}
	return LoadASNSceneRuleFiles(path)
}

func LoadASNSceneRuleFiles(paths ...string) error {
	cleanPaths := make([]string, 0, len(paths))
	rules := map[int]ASNSceneRule{}
	modTimes := map[string]time.Time{}
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		stat, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				cleanPaths = append(cleanPaths, path)
				continue
			}
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		parsed, err := parseASNSceneRules(body)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		for _, rule := range parsed {
			rules[rule.ASN] = rule
		}
		cleanPaths = append(cleanPaths, path)
		modTimes[path] = stat.ModTime()
	}
	setASNSceneRules(rules, cleanPaths, modTimes)
	return nil
}

func parseASNSceneRules(body []byte) ([]ASNSceneRule, error) {
	var file asnSceneRuleFile
	if err := yaml.Unmarshal(body, &file); err != nil {
		return nil, err
	}
	out := make([]ASNSceneRule, 0, len(file.Rules))
	for i, rule := range file.Rules {
		rule.Scene = strings.ToUpper(strings.TrimSpace(rule.Scene))
		if rule.ASN <= 0 {
			return nil, fmt.Errorf("asn scene rule %d missing ASN", i)
		}
		if rule.Scene == "" {
			return nil, fmt.Errorf("asn scene rule AS%d missing scene", rule.ASN)
		}
		if _, ok := sceneNames[rule.Scene]; !ok {
			return nil, fmt.Errorf("asn scene rule AS%d uses unknown scene %s", rule.ASN, rule.Scene)
		}
		if rule.SceneName == "" {
			rule.SceneName = sceneNames[rule.Scene]
		}
		if rule.Confidence <= 0 {
			rule.Confidence = 0.85
		}
		if rule.Confidence > 0.99 {
			rule.Confidence = 0.99
		}
		out = append(out, rule)
	}
	return out, nil
}

func setASNSceneRules(rules map[int]ASNSceneRule, paths []string, modTimes map[string]time.Time) {
	asnSceneRules.Lock()
	defer asnSceneRules.Unlock()
	if rules == nil {
		rules = map[int]ASNSceneRule{}
	}
	asnSceneRules.values = rules
	asnSceneRules.paths = append([]string(nil), paths...)
	asnSceneRules.modTimes = cloneModTimes(modTimes)
	asnSceneRules.nextReloadCheck = time.Now().Add(serviceRulesReloadInterval)
}

func currentASNSceneRule(asn int) (ASNSceneRule, bool) {
	maybeReloadASNSceneRules()
	asnSceneRules.RLock()
	defer asnSceneRules.RUnlock()
	rule, ok := asnSceneRules.values[asn]
	return rule, ok
}

func maybeReloadASNSceneRules() {
	asnSceneRules.RLock()
	paths := append([]string(nil), asnSceneRules.paths...)
	nextCheck := asnSceneRules.nextReloadCheck
	asnSceneRules.RUnlock()
	if len(paths) == 0 || time.Now().Before(nextCheck) {
		return
	}

	asnSceneRules.Lock()
	if time.Now().Before(asnSceneRules.nextReloadCheck) {
		asnSceneRules.Unlock()
		return
	}
	changed := false
	for _, path := range paths {
		stat, err := os.Stat(path)
		if err != nil {
			changed = true
			break
		}
		if !stat.ModTime().Equal(asnSceneRules.modTimes[path]) {
			changed = true
			break
		}
	}
	asnSceneRules.nextReloadCheck = time.Now().Add(serviceRulesReloadInterval)
	asnSceneRules.Unlock()

	if changed {
		_ = LoadASNSceneRuleFiles(paths...)
	}
}

func applyASNSceneRules(input Input, add func(scene string, points int, evidence string)) {
	if input.Profile.ASN <= 0 {
		return
	}
	rule, ok := currentASNSceneRule(input.Profile.ASN)
	if !ok {
		return
	}
	points := int(rule.Confidence*100) + 40
	name := strings.TrimSpace(rule.Name)
	if name == "" {
		name = fmt.Sprintf("AS%d", rule.ASN)
	}
	evidence := "命中 ASN 场景规则：" + name
	if rule.Source != "" {
		evidence += " / " + rule.Source
	}
	add(rule.Scene, points, evidence)
}

func resetASNSceneRulesForTest(t interface{ Cleanup(func()) }) {
	setASNSceneRules(nil, nil, nil)
	t.Cleanup(func() {
		setASNSceneRules(nil, nil, nil)
	})
}
