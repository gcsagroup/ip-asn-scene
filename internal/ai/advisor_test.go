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
