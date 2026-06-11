package ai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOllamaAdvisorSendsStructuredChatRequestAndParsesDecision(t *testing.T) {
	var request map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"model": "qwen3:8b",
			"message": {
				"role": "assistant",
				"content": "{\"scene\":\"IDC\",\"confidence\":0.81,\"reason\":\"组织信息更接近云服务数据中心\"}"
			},
			"done": true
		}`))
	}))
	defer server.Close()

	advisor := NewOllamaAdvisor(Config{
		Model:   "qwen3:8b",
		BaseURL: server.URL,
		Timeout: time.Second,
	})

	decision, err := advisor.Advise(context.Background(), AdviceInput{
		Query:          "AS64500",
		QueryType:      "asn",
		ASN:            64500,
		Company:        "Example Holder",
		RuleScene:      "NET",
		RuleSceneName:  "基础设施",
		RuleConfidence: 0.35,
		RuleEvidence:   []string{"未命中明确规则"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Scene != "IDC" || decision.SceneName != "数据中心" || decision.Confidence != 0.81 {
		t.Fatalf("unexpected decision: %#v", decision)
	}
	if decision.Model != "ollama:qwen3:8b" {
		t.Fatalf("unexpected model marker: %s", decision.Model)
	}

	if request["model"] != "qwen3:8b" {
		t.Fatalf("unexpected model: %#v", request["model"])
	}
	if request["stream"] != false {
		t.Fatalf("expected stream false, got %#v", request["stream"])
	}
	format := request["format"].(map[string]any)
	if format["type"] != "object" {
		t.Fatalf("expected JSON schema object, got %#v", format)
	}
	messages := request["messages"].([]any)
	if len(messages) != 2 {
		t.Fatalf("expected system and user messages, got %#v", messages)
	}
}
