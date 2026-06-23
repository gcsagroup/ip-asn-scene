package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type ModelInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name,omitempty"`
	Provider string `json:"provider"`
	OwnedBy  string `json:"owned_by,omitempty"`
	Created  int64  `json:"created,omitempty"`
}

type ModelListConfig struct {
	Provider string
	APIKey   string
	BaseURL  string
	Version  string
	Timeout  time.Duration
}

func ListModels(ctx context.Context, cfg ModelListConfig) ([]ModelInfo, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Provider)) {
	case "openai", "auto", "":
		return listOpenAIModels(ctx, cfg)
	case "anthropic":
		return listAnthropicModels(ctx, cfg)
	case "gemini":
		return listGeminiModels(ctx, cfg)
	default:
		return nil, fmt.Errorf("unsupported AI provider %q", cfg.Provider)
	}
}

func MergeModelOptions(provider, configured string, online []ModelInfo) []ModelInfo {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "auto" || provider == "" {
		provider = "openai"
	}
	merged := make([]ModelInfo, 0, len(online)+8)
	seen := map[string]bool{}
	add := func(model ModelInfo) {
		model.ID = strings.TrimSpace(model.ID)
		if model.ID == "" {
			return
		}
		key := strings.ToLower(model.ID)
		if seen[key] {
			return
		}
		seen[key] = true
		if model.Provider == "" {
			model.Provider = provider
		}
		if model.Name == "" {
			model.Name = model.ID
		}
		merged = append(merged, model)
	}
	if strings.TrimSpace(configured) != "" {
		add(ModelInfo{ID: configured, Name: configured, Provider: provider})
	}
	for _, model := range BuiltInModelOptions(provider) {
		add(model)
	}
	for _, model := range online {
		add(model)
	}
	return merged
}

func BuiltInModelOptions(provider string) []ModelInfo {
	provider = strings.ToLower(strings.TrimSpace(provider))
	modelsByProvider := map[string][]string{
		"openai": {
			"gpt-5.4-mini",
			"gpt-5.4",
			"gpt-5.4-nano",
			"gpt-4.1",
			"gpt-4.1-mini",
			"gpt-4o",
			"gpt-4o-mini",
		},
		"anthropic": {
			"claude-sonnet-4-6",
			"claude-opus-4-6",
			"claude-haiku-4-5",
			"claude-sonnet-4-5",
			"claude-3-7-sonnet-latest",
		},
		"gemini": {
			"gemini-2.5-flash",
			"gemini-2.5-pro",
			"gemini-2.5-flash-lite",
			"gemini-2.0-flash",
		},
	}
	ids := modelsByProvider[provider]
	models := make([]ModelInfo, 0, len(ids))
	for _, id := range ids {
		models = append(models, ModelInfo{ID: id, Name: id, Provider: provider})
	}
	return models
}

func listOpenAIModels(ctx context.Context, cfg ModelListConfig) ([]ModelInfo, error) {
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, fmt.Errorf("OPENAI_API_KEY is empty")
	}
	client := &http.Client{Timeout: modelListTimeout(cfg.Timeout)}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, modelListBaseURL(cfg.BaseURL)+"/models", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response struct {
		Data []struct {
			ID      string `json:"id"`
			OwnedBy string `json:"owned_by"`
			Created int64  `json:"created"`
		} `json:"data"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if response.Error.Message != "" {
			return nil, fmt.Errorf("OpenAI models HTTP %d: %s", resp.StatusCode, response.Error.Message)
		}
		return nil, fmt.Errorf("OpenAI models HTTP %d", resp.StatusCode)
	}
	models := make([]ModelInfo, 0, len(response.Data))
	for _, item := range response.Data {
		if strings.TrimSpace(item.ID) == "" {
			continue
		}
		models = append(models, ModelInfo{ID: item.ID, Name: item.ID, Provider: "openai", OwnedBy: item.OwnedBy, Created: item.Created})
	}
	sortModels(models)
	return models, nil
}

func listAnthropicModels(ctx context.Context, cfg ModelListConfig) ([]ModelInfo, error) {
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, fmt.Errorf("ANTHROPIC_API_KEY is empty")
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.anthropic.com"
	}
	if cfg.Version == "" {
		cfg.Version = "2023-06-01"
	}
	client := &http.Client{Timeout: modelListTimeout(cfg.Timeout)}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(cfg.BaseURL, "/")+"/v1/models", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-api-key", cfg.APIKey)
	req.Header.Set("anthropic-version", cfg.Version)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response struct {
		Data []struct {
			ID          string `json:"id"`
			DisplayName string `json:"display_name"`
			CreatedAt   string `json:"created_at"`
		} `json:"data"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if response.Error.Message != "" {
			return nil, fmt.Errorf("Anthropic models HTTP %d: %s", resp.StatusCode, response.Error.Message)
		}
		return nil, fmt.Errorf("Anthropic models HTTP %d", resp.StatusCode)
	}
	models := make([]ModelInfo, 0, len(response.Data))
	for _, item := range response.Data {
		if strings.TrimSpace(item.ID) == "" {
			continue
		}
		models = append(models, ModelInfo{ID: item.ID, Name: firstNonEmpty(item.DisplayName, item.ID), Provider: "anthropic", OwnedBy: "anthropic"})
	}
	sortModels(models)
	return models, nil
}

func listGeminiModels(ctx context.Context, cfg ModelListConfig) ([]ModelInfo, error) {
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, fmt.Errorf("GEMINI_API_KEY is empty")
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://generativelanguage.googleapis.com/v1beta"
	}
	client := &http.Client{Timeout: modelListTimeout(cfg.Timeout)}
	endpoint := strings.TrimRight(cfg.BaseURL, "/") + "/models"
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	query := parsed.Query()
	query.Set("key", cfg.APIKey)
	query.Set("pageSize", "1000")
	parsed.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var response struct {
		Models []struct {
			Name                       string   `json:"name"`
			BaseModelID                string   `json:"baseModelId"`
			DisplayName                string   `json:"displayName"`
			SupportedGenerationMethods []string `json:"supportedGenerationMethods"`
			SupportedActions           []string `json:"supported_actions"`
		} `json:"models"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if response.Error.Message != "" {
			return nil, fmt.Errorf("Gemini models HTTP %d: %s", resp.StatusCode, response.Error.Message)
		}
		return nil, fmt.Errorf("Gemini models HTTP %d", resp.StatusCode)
	}
	models := make([]ModelInfo, 0, len(response.Models))
	for _, item := range response.Models {
		if !supportsGeminiGenerateContent(item.SupportedGenerationMethods, item.SupportedActions) {
			continue
		}
		id := firstNonEmpty(item.BaseModelID, strings.TrimPrefix(item.Name, "models/"))
		if id == "" {
			continue
		}
		models = append(models, ModelInfo{ID: id, Name: firstNonEmpty(item.DisplayName, id), Provider: "gemini", OwnedBy: "google"})
	}
	sortModels(models)
	return models, nil
}

func modelListTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return 8 * time.Second
	}
	return timeout
}

func sortModels(models []ModelInfo) {
	sort.SliceStable(models, func(i, j int) bool {
		return models[i].ID < models[j].ID
	})
}

func supportsGeminiGenerateContent(methods, actions []string) bool {
	values := append([]string{}, methods...)
	values = append(values, actions...)
	if len(values) == 0 {
		return true
	}
	for _, value := range values {
		if value == "generateContent" {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
