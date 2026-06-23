package update

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ipasn/internal/config"
)

func TestDownloadCacheReusesFileOnNotModified(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			w.Header().Set("ETag", `"v1"`)
			w.Header().Set("Last-Modified", "Tue, 23 Jun 2026 10:00:00 GMT")
			_, _ = w.Write([]byte("first-body"))
			return
		}
		if got := r.Header.Get("If-None-Match"); got != `"v1"` {
			t.Fatalf("expected conditional ETag request, got %q", got)
		}
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()

	dataDir := t.TempDir()
	cache := newDownloadCache(dataDir, server.Client())
	downloader := &Downloader{client: server.Client()}
	destination := filepath.Join(dataDir, "raw", "rir-test.txt")

	if err := downloader.download(context.Background(), cache, server.URL+"/rir.txt", destination); err != nil {
		t.Fatal(err)
	}
	if err := downloader.download(context.Background(), cache, server.URL+"/rir.txt", destination); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "first-body" {
		t.Fatalf("expected cached local file body, got %q", body)
	}
	if requests != 2 {
		t.Fatalf("expected two requests with second 304, got %d", requests)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "processed", "download-state.json")); err != nil {
		t.Fatalf("expected download state file: %v", err)
	}
	stats := cache.Stats()
	if stats.Downloaded != 1 || stats.ReusedNotModified != 1 || stats.ReusedFresh != 0 {
		t.Fatalf("unexpected download stats: %#v", stats)
	}
}

func TestDownloadCacheReusesFreshSourceWithoutValidators(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		_, _ = w.Write([]byte("first-body"))
	}))
	defer server.Close()

	dataDir := t.TempDir()
	cache := newDownloadCache(dataDir, server.Client())
	downloader := &Downloader{client: server.Client()}
	destination := filepath.Join(dataDir, "raw", "source.txt")

	if err := downloader.download(context.Background(), cache, server.URL+"/source.txt", destination); err != nil {
		t.Fatal(err)
	}
	if err := downloader.download(context.Background(), cache, server.URL+"/source.txt", destination); err != nil {
		t.Fatal(err)
	}
	if requests != 1 {
		t.Fatalf("expected fresh no-validator cache to avoid second request, got %d requests", requests)
	}
	stats := cache.Stats()
	if stats.Downloaded != 1 || stats.ReusedFresh != 1 {
		t.Fatalf("unexpected no-validator cache stats: %#v", stats)
	}
}

func TestDynamicServiceRulesReuseCachedSourceOnNotModified(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			w.Header().Set("ETag", `"google-v1"`)
			_, _ = w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"66.249.64.0/19"}]}`))
			return
		}
		if got := r.Header.Get("If-None-Match"); got != `"google-v1"` {
			t.Fatalf("expected conditional ETag request, got %q", got)
		}
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()

	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.DynamicRules.File = filepath.Join(cfg.DataDir, "generated", "services.json")
	clearDynamicRuleURLs(&cfg)
	cfg.DynamicRules.GoogleCrawlerURL = server.URL + "/google.json"

	if _, err := RefreshDynamicServiceRulesWithClient(context.Background(), cfg, server.Client(), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := RefreshDynamicServiceRulesWithClient(context.Background(), cfg, server.Client(), nil); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(cfg.DynamicRules.File)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "66.249.64.0/19") {
		t.Fatalf("expected generated rule to reuse cached source body, got %s", body)
	}
	if requests != 2 {
		t.Fatalf("expected two requests with second 304, got %d", requests)
	}
	var generated generatedServiceRuleFile
	if err := json.Unmarshal(body, &generated); err != nil {
		t.Fatal(err)
	}
	if generated.DownloadStats.ReusedNotModified != 1 {
		t.Fatalf("expected dynamic rule file to record 304 reuse stats, got %#v", generated.DownloadStats)
	}
}

func clearDynamicRuleURLs(cfg *config.Config) {
	cfg.DynamicRules.GoogleCrawlerURL = ""
	cfg.DynamicRules.BingbotURL = ""
	cfg.DynamicRules.TorExitURL = ""
	cfg.DynamicRules.UptimeRobotURL = ""
	cfg.DynamicRules.SpamhausDropV4URL = ""
	cfg.DynamicRules.SpamhausDropV6URL = ""
	cfg.DynamicRules.FireHOLLevel1URL = ""
	cfg.DynamicRules.FireHOLAnonymousURL = ""
	cfg.DynamicRules.Az0VPNIPURL = ""
	cfg.DynamicRules.CloudflareV4URL = ""
	cfg.DynamicRules.CloudflareV6URL = ""
	cfg.DynamicRules.FastlyURL = ""
	cfg.DynamicRules.AWSIPRangesURL = ""
	cfg.DynamicRules.GoogleCloudIPRangesURL = ""
	cfg.DynamicRules.AzureServiceTagsURL = ""
	cfg.DynamicRules.OracleIPRangesURL = ""
	cfg.DynamicRules.GitHubMetaURL = ""
	cfg.DynamicRules.ApplePrivateRelayURL = ""
	cfg.DynamicRules.GoogleFiVPNGeofeedURL = ""
	cfg.DynamicRules.MullvadRelaysURL = ""
	cfg.DynamicRules.NordVPNServersURL = ""
	cfg.DynamicRules.MailSPFDomains = nil
	cfg.DynamicRules.IP2Proxy.Enabled = false
	cfg.DynamicRules.IP2Proxy.LocalFile = ""
	cfg.DynamicRules.IP2Proxy.LocalFiles = nil
	cfg.DynamicRules.IP2Proxy.DownloadURL = ""
	cfg.DynamicRules.IP2Proxy.DownloadURLs = nil
}
