package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type AnthropicAdvisor struct {
	cfg    Config
	client *http.Client
	mu     sync.Mutex
	cache  map[string]Decision
}

type GeminiAdvisor struct {
	cfg    Config
	client *http.Client
	mu     sync.Mutex
	cache  map[string]Decision
}

func NewAnthropicAdvisor(cfg Config) *AnthropicAdvisor {
	if cfg.Model == "" {
		cfg.Model = "claude-sonnet-4-6"
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.anthropic.com"
	}
	if cfg.Version == "" {
		cfg.Version = "2023-06-01"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 8 * time.Second
	}
	if cfg.MaxCache <= 0 {
		cfg.MaxCache = 2048
	}
	return &AnthropicAdvisor{cfg: cfg, client: &http.Client{Timeout: cfg.Timeout}, cache: map[string]Decision{}}
}

func (a *AnthropicAdvisor) Advise(ctx context.Context, input AdviceInput) (Decision, error) {
	if strings.TrimSpace(a.cfg.APIKey) == "" {
		return Decision{}, fmt.Errorf("ANTHROPIC_API_KEY is empty")
	}
	key := cacheKey(input)
	if decision, ok := a.readCache(key); ok {
		return decision, nil
	}
	body, err := json.Marshal(map[string]any{
		"model":      a.cfg.Model,
		"max_tokens": 200,
		"system":     advisorInstructions(),
		"messages": []map[string]string{
			{"role": "user", "content": mustJSON(input)},
		},
	})
	if err != nil {
		return Decision{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(a.cfg.BaseURL, "/")+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		return Decision{}, err
	}
	req.Header.Set("x-api-key", a.cfg.APIKey)
	req.Header.Set("anthropic-version", a.cfg.Version)
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return Decision{}, err
	}
	defer resp.Body.Close()
	var response struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return Decision{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if response.Error.Message != "" {
			return Decision{}, fmt.Errorf("Anthropic API HTTP %d: %s", resp.StatusCode, response.Error.Message)
		}
		return Decision{}, fmt.Errorf("Anthropic API HTTP %d", resp.StatusCode)
	}
	text := ""
	for _, content := range response.Content {
		if content.Type == "text" && content.Text != "" {
			text = content.Text
			break
		}
	}
	if text == "" {
		return Decision{}, fmt.Errorf("Anthropic response did not contain text")
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

func (a *AnthropicAdvisor) readCache(key string) (Decision, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	decision, ok := a.cache[key]
	return decision, ok
}

func (a *AnthropicAdvisor) writeCache(key string, decision Decision) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.cache) >= a.cfg.MaxCache {
		a.cache = map[string]Decision{}
	}
	a.cache[key] = decision
}

func NewGeminiAdvisor(cfg Config) *GeminiAdvisor {
	if cfg.Model == "" {
		cfg.Model = "gemini-2.5-flash"
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://generativelanguage.googleapis.com/v1beta"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 8 * time.Second
	}
	if cfg.MaxCache <= 0 {
		cfg.MaxCache = 2048
	}
	return &GeminiAdvisor{cfg: cfg, client: &http.Client{Timeout: cfg.Timeout}, cache: map[string]Decision{}}
}

func (a *GeminiAdvisor) Advise(ctx context.Context, input AdviceInput) (Decision, error) {
	if strings.TrimSpace(a.cfg.APIKey) == "" {
		return Decision{}, fmt.Errorf("GEMINI_API_KEY is empty")
	}
	key := cacheKey(input)
	if decision, ok := a.readCache(key); ok {
		return decision, nil
	}
	body, err := json.Marshal(map[string]any{
		"contents": []map[string]any{
			{
				"role": "user",
				"parts": []map[string]string{
					{"text": advisorInstructions() + "\n输入 JSON：\n" + mustJSON(input)},
				},
			},
		},
		"generationConfig": map[string]any{
			"responseMimeType": "application/json",
			"maxOutputTokens":  200,
		},
	})
	if err != nil {
		return Decision{}, err
	}
	endpoint := strings.TrimRight(a.cfg.BaseURL, "/") + "/" + geminiModelPath(a.cfg.Model) + ":generateContent"
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return Decision{}, err
	}
	query := parsed.Query()
	query.Set("key", a.cfg.APIKey)
	parsed.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, parsed.String(), bytes.NewReader(body))
	if err != nil {
		return Decision{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return Decision{}, err
	}
	defer resp.Body.Close()
	var response struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return Decision{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if response.Error.Message != "" {
			return Decision{}, fmt.Errorf("Gemini API HTTP %d: %s", resp.StatusCode, response.Error.Message)
		}
		return Decision{}, fmt.Errorf("Gemini API HTTP %d", resp.StatusCode)
	}
	text := ""
	for _, candidate := range response.Candidates {
		for _, part := range candidate.Content.Parts {
			if part.Text != "" {
				text = part.Text
				break
			}
		}
		if text != "" {
			break
		}
	}
	if text == "" {
		return Decision{}, fmt.Errorf("Gemini response did not contain text")
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

func (a *GeminiAdvisor) readCache(key string) (Decision, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	decision, ok := a.cache[key]
	return decision, ok
}

func (a *GeminiAdvisor) writeCache(key string, decision Decision) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.cache) >= a.cfg.MaxCache {
		a.cache = map[string]Decision{}
	}
	a.cache[key] = decision
}

func geminiModelPath(model string) string {
	model = strings.Trim(strings.TrimSpace(model), "/")
	if strings.HasPrefix(model, "models/") {
		return model
	}
	return "models/" + model
}
