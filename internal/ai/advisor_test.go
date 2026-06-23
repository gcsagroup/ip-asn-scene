package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOpenAIAdvisorSendsStructuredRequestAndParsesDecision(t *testing.T) {
	var request map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Fatalf("missing authorization header")
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"output": [
				{
					"type": "message",
					"content": [
						{
							"type": "output_text",
							"text": "{\"scene\":\"ORG\",\"confidence\":0.82,\"reason\":\"组织名和描述更接近非营利机构\"}"
						}
					]
				}
			]
		}`))
	}))
	defer server.Close()

	advisor := NewOpenAIAdvisor(Config{
		APIKey:  "test-key",
		Model:   "gpt-5.4-mini",
		BaseURL: server.URL,
		Timeout: time.Second,
	})

	decision, err := advisor.Advise(context.Background(), AdviceInput{
		Query:          "AS64500",
		QueryType:      "asn",
		ASN:            64500,
		Company:        "Example Foundation",
		RuleScene:      "NET",
		RuleSceneName:  "基础设施",
		RuleConfidence: 0.35,
		RuleEvidence:   []string{"未命中明确规则"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Scene != "ORG" || decision.SceneName != "组织机构" || decision.Confidence != 0.82 {
		t.Fatalf("unexpected decision: %#v", decision)
	}
	if decision.Reason == "" {
		t.Fatal("expected AI reason")
	}

	textConfig := request["text"].(map[string]any)
	format := textConfig["format"].(map[string]any)
	if format["type"] != "json_schema" {
		t.Fatalf("expected json_schema format, got %#v", format)
	}
	if request["model"] != "gpt-5.4-mini" {
		t.Fatalf("unexpected model: %#v", request["model"])
	}
}

func TestOpenAIAdvisorRejectsInvalidScene(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"output":[{"content":[{"type":"output_text","text":"{\"scene\":\"OTHER\",\"confidence\":0.9,\"reason\":\"bad\"}"}]}]}`))
	}))
	defer server.Close()

	advisor := NewOpenAIAdvisor(Config{APIKey: "test-key", BaseURL: server.URL, Timeout: time.Second})
	_, err := advisor.Advise(context.Background(), AdviceInput{Query: "AS64500", RuleScene: "NET"})
	if err == nil || !strings.Contains(err.Error(), "invalid scene") {
		t.Fatalf("expected invalid scene error, got %v", err)
	}
}

func TestOpenAIAdvisorSupportsChatCompletionsCompatibleEndpoint(t *testing.T) {
	var request map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Fatalf("missing authorization header")
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"scene\":\"IDC\",\"confidence\":0.77,\"reason\":\"OpenAI compatible endpoint\"}"}}]}`))
	}))
	defer server.Close()

	advisor := NewOpenAIAdvisor(Config{
		APIKey:  "test-key",
		Model:   "compatible-model",
		BaseURL: server.URL + "/v1",
		APIType: "chat_completions",
		Timeout: time.Second,
	})

	decision, err := advisor.Advise(context.Background(), AdviceInput{Query: "1.2.3.4", QueryType: "ip", RuleScene: "NET"})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Scene != "IDC" || decision.Model != "compatible-model" {
		t.Fatalf("unexpected decision: %#v", decision)
	}
	if request["model"] != "compatible-model" {
		t.Fatalf("unexpected model: %#v", request["model"])
	}
	if _, ok := request["messages"].([]any); !ok {
		t.Fatalf("expected chat messages request, got %#v", request)
	}
}

func TestAnthropicAdvisorSendsMessagesRequestAndParsesDecision(t *testing.T) {
	var request map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("x-api-key") != "anthropic-key" {
			t.Fatalf("missing anthropic api key")
		}
		if r.Header.Get("anthropic-version") != "2023-06-01" {
			t.Fatalf("missing anthropic version")
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"content":[{"type":"text","text":"{\"scene\":\"ORG\",\"confidence\":0.81,\"reason\":\"Anthropic native API\"}"}]}`))
	}))
	defer server.Close()

	advisor := NewAnthropicAdvisor(Config{
		APIKey:  "anthropic-key",
		Model:   "claude-sonnet-test",
		BaseURL: server.URL,
		Version: "2023-06-01",
		Timeout: time.Second,
	})

	decision, err := advisor.Advise(context.Background(), AdviceInput{Query: "AS64500", QueryType: "asn", RuleScene: "NET"})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Scene != "ORG" || decision.Model != "claude-sonnet-test" {
		t.Fatalf("unexpected decision: %#v", decision)
	}
	if request["model"] != "claude-sonnet-test" || request["system"] == "" {
		t.Fatalf("unexpected anthropic request: %#v", request)
	}
}

func TestGeminiAdvisorSendsGenerateContentRequestAndParsesDecision(t *testing.T) {
	var request map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1beta/models/gemini-test:generateContent" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("key") != "gemini-key" {
			t.Fatalf("missing gemini api key")
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"{\"scene\":\"DNS\",\"confidence\":0.88,\"reason\":\"Gemini native API\"}"}]}}]}`))
	}))
	defer server.Close()

	advisor := NewGeminiAdvisor(Config{
		APIKey:  "gemini-key",
		Model:   "gemini-test",
		BaseURL: server.URL + "/v1beta",
		Timeout: time.Second,
	})

	decision, err := advisor.Advise(context.Background(), AdviceInput{Query: "8.8.8.8", QueryType: "ip", RuleScene: "NET"})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Scene != "DNS" || decision.Model != "gemini-test" {
		t.Fatalf("unexpected decision: %#v", decision)
	}
	if _, ok := request["contents"].([]any); !ok {
		t.Fatalf("expected gemini contents request, got %#v", request)
	}
}
