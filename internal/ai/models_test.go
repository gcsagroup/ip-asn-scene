package ai

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestListModelsSupportsOpenAICompatibleEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer openai-key" {
			t.Fatalf("missing authorization header")
		}
		_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"gpt-test","created":1,"owned_by":"openai"}]}`))
	}))
	defer server.Close()

	models, err := ListModels(context.Background(), ModelListConfig{
		Provider: "openai",
		APIKey:   "openai-key",
		BaseURL:  server.URL + "/v1/responses",
		Timeout:  time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(models) != 1 || models[0].ID != "gpt-test" || models[0].Provider != "openai" || models[0].OwnedBy != "openai" {
		t.Fatalf("unexpected models: %#v", models)
	}
}

func TestListModelsSupportsAnthropicEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("x-api-key") != "anthropic-key" || r.Header.Get("anthropic-version") != "2023-06-01" {
			t.Fatalf("unexpected anthropic headers")
		}
		_, _ = w.Write([]byte(`{"data":[{"id":"claude-test","display_name":"Claude Test","created_at":"2026-01-01T00:00:00Z"}]}`))
	}))
	defer server.Close()

	models, err := ListModels(context.Background(), ModelListConfig{
		Provider: "anthropic",
		APIKey:   "anthropic-key",
		BaseURL:  server.URL,
		Version:  "2023-06-01",
		Timeout:  time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(models) != 1 || models[0].ID != "claude-test" || models[0].Name != "Claude Test" || models[0].Provider != "anthropic" {
		t.Fatalf("unexpected models: %#v", models)
	}
}

func TestListModelsSupportsGeminiEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1beta/models" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("key") != "gemini-key" {
			t.Fatalf("missing gemini key")
		}
		_, _ = w.Write([]byte(`{"models":[{"name":"models/gemini-test","baseModelId":"gemini-test","displayName":"Gemini Test","supportedGenerationMethods":["generateContent"]}]}`))
	}))
	defer server.Close()

	models, err := ListModels(context.Background(), ModelListConfig{
		Provider: "gemini",
		APIKey:   "gemini-key",
		BaseURL:  server.URL + "/v1beta",
		Timeout:  time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(models) != 1 || models[0].ID != "gemini-test" || models[0].Name != "Gemini Test" || models[0].Provider != "gemini" {
		t.Fatalf("unexpected models: %#v", models)
	}
}
