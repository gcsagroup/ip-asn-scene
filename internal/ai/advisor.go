package ai

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Advisor interface {
	Advise(ctx context.Context, input AdviceInput) (Decision, error)
}

type Config struct {
	APIKey   string
	Model    string
	BaseURL  string
	APIType  string
	Version  string
	Timeout  time.Duration
	MaxCache int
}

type AdviceInput struct {
	Query          string   `json:"query"`
	QueryType      string   `json:"query_type"`
	IP             string   `json:"ip,omitempty"`
	ASN            int      `json:"asn,omitempty"`
	Company        string   `json:"company,omitempty"`
	Country        string   `json:"country,omitempty"`
	Registry       string   `json:"registry,omitempty"`
	InfoType       string   `json:"info_type,omitempty"`
	Website        string   `json:"website,omitempty"`
	MatchedPrefix  string   `json:"matched_prefix,omitempty"`
	RDNS           string   `json:"rdns,omitempty"`
	RuleScene      string   `json:"rule_scene"`
	RuleSceneName  string   `json:"rule_scene_name"`
	RuleConfidence float64  `json:"rule_confidence"`
	RuleEvidence   []string `json:"rule_evidence"`
}

type Decision struct {
	Scene      string  `json:"scene"`
	SceneName  string  `json:"scene_name,omitempty"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
	Model      string  `json:"model,omitempty"`
}

type OpenAIAdvisor struct {
	cfg    Config
	client *http.Client
	mu     sync.Mutex
	cache  map[string]Decision
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

func NewOpenAIAdvisor(cfg Config) *OpenAIAdvisor {
	if cfg.Model == "" {
		cfg.Model = "gpt-5.4-mini"
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.openai.com/v1"
	}
	if cfg.APIType == "" {
		cfg.APIType = "responses"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 8 * time.Second
	}
	if cfg.MaxCache <= 0 {
		cfg.MaxCache = 2048
	}
	return &OpenAIAdvisor{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.Timeout},
		cache:  map[string]Decision{},
	}
}

func (a *OpenAIAdvisor) Advise(ctx context.Context, input AdviceInput) (Decision, error) {
	if strings.TrimSpace(a.cfg.APIKey) == "" {
		return Decision{}, fmt.Errorf("OPENAI_API_KEY is empty")
	}

	key := cacheKey(input)
	if decision, ok := a.readCache(key); ok {
		return decision, nil
	}

	body, err := json.Marshal(a.requestBody(input))
	if err != nil {
		return Decision{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint(), bytes.NewReader(body))
	if err != nil {
		return Decision{}, err
	}
	req.Header.Set("Authorization", "Bearer "+a.cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return Decision{}, err
	}
	defer resp.Body.Close()

	var response responseBody
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return Decision{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if response.Error.Message != "" {
			return Decision{}, fmt.Errorf("OpenAI API HTTP %d: %s", resp.StatusCode, response.Error.Message)
		}
		return Decision{}, fmt.Errorf("OpenAI API HTTP %d", resp.StatusCode)
	}

	text := response.outputText()
	if text == "" {
		return Decision{}, fmt.Errorf("OpenAI response did not contain output text")
	}

	var decision Decision
	if err := json.Unmarshal([]byte(text), &decision); err != nil {
		return Decision{}, err
	}
	decision, err = normalizeDecision(decision)
	if err != nil {
		return Decision{}, err
	}
	decision.Model = a.cfg.Model

	a.writeCache(key, decision)
	return decision, nil
}

func (a *OpenAIAdvisor) requestBody(input AdviceInput) map[string]any {
	if a.cfg.APIType == "chat_completions" {
		return map[string]any{
			"model": a.cfg.Model,
			"messages": []map[string]string{
				{"role": "system", "content": advisorInstructions()},
				{"role": "user", "content": mustJSON(input)},
			},
			"max_tokens": 200,
			"response_format": map[string]any{
				"type":        "json_schema",
				"json_schema": sceneDecisionJSONSchema(),
			},
		}
	}
	return map[string]any{
		"model":             a.cfg.Model,
		"instructions":      advisorInstructions(),
		"input":             input,
		"max_output_tokens": 200,
		"text": map[string]any{
			"format": map[string]any{
				"type":        "json_schema",
				"name":        "ip_asn_scene_decision",
				"description": "IP 或 ASN 的应用场景判断结果",
				"strict":      true,
				"schema":      sceneDecisionSchema(),
			},
		},
	}
}

func (a *OpenAIAdvisor) endpoint() string {
	return providerEndpoint(a.cfg.BaseURL, a.cfg.APIType)
}

func (a *OpenAIAdvisor) readCache(key string) (Decision, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	decision, ok := a.cache[key]
	return decision, ok
}

func (a *OpenAIAdvisor) writeCache(key string, decision Decision) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.cache) >= a.cfg.MaxCache {
		a.cache = map[string]Decision{}
	}
	a.cache[key] = decision
}

func cacheKey(input AdviceInput) string {
	encoded, _ := json.Marshal(input)
	sum := sha1.Sum(encoded)
	return hex.EncodeToString(sum[:])
}

func normalizeDecision(decision Decision) (Decision, error) {
	decision.Scene = strings.ToUpper(strings.TrimSpace(decision.Scene))
	sceneName, ok := sceneNames[decision.Scene]
	if !ok {
		return Decision{}, fmt.Errorf("invalid scene from AI: %s", decision.Scene)
	}
	decision.SceneName = sceneName
	if decision.Confidence < 0 {
		decision.Confidence = 0
	}
	if decision.Confidence > 1 {
		decision.Confidence = 1
	}
	if decision.Reason == "" {
		decision.Reason = "AI 根据低置信度结果补充判断"
	}
	return decision, nil
}

func sceneDecisionSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"scene", "confidence", "reason"},
		"properties": map[string]any{
			"scene": map[string]any{
				"type": "string",
				"enum": []string{"CDN", "DNS", "EDU", "GTW", "GOV", "DYN", "IDC", "MOB", "ORG", "NET", "BOGON", "UNROUTED", "STUN", "VPN", "PROXY", "TOR", "BOT", "MAIL", "MON", "IOT", "BLOCKLIST"},
			},
			"confidence": map[string]any{
				"type":    "number",
				"minimum": 0,
				"maximum": 1,
			},
			"reason": map[string]any{
				"type": "string",
			},
		},
	}
}

func advisorInstructions() string {
	return strings.Join([]string{
		"你是 IP/ASN 场景分类助手。",
		"只根据输入里的证据判断，输出一个场景。",
		"场景只能是 CDN、DNS、EDU、GTW、GOV、DYN、IDC、MOB、ORG、NET、BOGON、UNROUTED、STUN、VPN、PROXY、TOR、BOT、MAIL、MON、IOT、BLOCKLIST。",
		"confidence 使用 0 到 1 的数字。",
		"reason 用一句中文说明关键依据。",
	}, "\n")
}

type responseBody struct {
	Output []struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	} `json:"output"`
	OutputText string `json:"output_text"`
	Choices    []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error struct {
		Message string `json:"message"`
	} `json:"error"`
}

func (r responseBody) outputText() string {
	if r.OutputText != "" {
		return r.OutputText
	}
	for _, choice := range r.Choices {
		if choice.Message.Content != "" {
			return choice.Message.Content
		}
	}
	for _, output := range r.Output {
		for _, content := range output.Content {
			if content.Type == "output_text" && content.Text != "" {
				return content.Text
			}
		}
	}
	return ""
}

func sceneDecisionJSONSchema() map[string]any {
	return map[string]any{
		"name":        "ip_asn_scene_decision",
		"description": "IP 或 ASN 的应用场景判断结果",
		"strict":      true,
		"schema":      sceneDecisionSchema(),
	}
}

func mustJSON(value any) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func providerEndpoint(baseURL, apiType string) string {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}
	if strings.HasSuffix(baseURL, "/responses") || strings.HasSuffix(baseURL, "/chat/completions") || strings.HasSuffix(baseURL, "/messages") || strings.Contains(baseURL, ":generateContent") {
		return baseURL
	}
	switch apiType {
	case "chat_completions":
		return baseURL + "/chat/completions"
	default:
		return baseURL + "/responses"
	}
}

func modelListBaseURL(baseURL string) string {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	for _, suffix := range []string{"/responses", "/chat/completions", "/messages"} {
		if strings.HasSuffix(baseURL, suffix) {
			baseURL = strings.TrimSuffix(baseURL, suffix)
			break
		}
	}
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}
	return baseURL
}
