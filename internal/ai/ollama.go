package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type OllamaAdvisor struct {
	cfg    Config
	client *http.Client
}

func NewOllamaAdvisor(cfg Config) *OllamaAdvisor {
	if cfg.Model == "" {
		cfg.Model = "qwen3:8b"
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "http://localhost:11434"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &OllamaAdvisor{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.Timeout},
	}
}

func (a *OllamaAdvisor) Advise(ctx context.Context, input AdviceInput) (Decision, error) {
	promptBytes, err := json.MarshalIndent(input, "", "  ")
	if err != nil {
		return Decision{}, err
	}

	body, err := json.Marshal(map[string]any{
		"model":  a.cfg.Model,
		"stream": false,
		"format": sceneDecisionSchema(),
		"messages": []map[string]string{
			{"role": "system", "content": advisorInstructions()},
			{"role": "user", "content": "请判断以下 IP/ASN 信息的应用场景，只输出 JSON：\n" + string(promptBytes)},
		},
		"options": map[string]any{
			"temperature": 0,
		},
	})
	if err != nil {
		return Decision{}, err
	}

	endpoint := strings.TrimRight(a.cfg.BaseURL, "/") + "/api/chat"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
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
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return Decision{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if response.Error != "" {
			return Decision{}, fmt.Errorf("Ollama API HTTP %d: %s", resp.StatusCode, response.Error)
		}
		return Decision{}, fmt.Errorf("Ollama API HTTP %d", resp.StatusCode)
	}
	if response.Message.Content == "" {
		return Decision{}, fmt.Errorf("Ollama response did not contain message content")
	}

	var decision Decision
	if err := json.Unmarshal([]byte(response.Message.Content), &decision); err != nil {
		return Decision{}, err
	}
	decision, err = normalizeDecision(decision)
	if err != nil {
		return Decision{}, err
	}
	decision.Model = "ollama:" + a.cfg.Model
	return decision, nil
}
