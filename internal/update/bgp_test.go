package update

import (
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ipasn/internal/config"
	"ipasn/internal/store"
)

func TestDiscoverBGPRIBSourcesFindsLatestRouteViewsAndRISFiles(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/routeviews/":
			_, _ = w.Write([]byte(`<a href="/route-views2/bgpdata">route-views2</a><a href="/hkix.hkg/bgpdata">hkix</a>`))
		case "/routeviews/route-views2/bgpdata/2026.06/RIBS/":
			_, _ = w.Write([]byte(`<a href="rib.20260611.0000.bz2">old</a><a href="rib.20260611.0800.bz2">new</a>`))
		case "/routeviews/hkix.hkg/bgpdata/2026.06/RIBS/":
			_, _ = w.Write([]byte(`<a href="rib.20260611.0400.bz2">sg</a>`))
		case "/ris/":
			_, _ = w.Write([]byte(`<html><title>RIS docs</title></html>`))
		case "/ris/rrc00/2026.06/":
			_, _ = w.Write([]byte(`<a href="bview.20260611.0000.gz">old</a><a href="bview.20260611.0800.gz">new</a>`))
		case "/ris/rrc01/2026.06/":
			_, _ = w.Write([]byte(`<a href="bview.20260611.0400.gz">rrc01</a>`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := config.Default()
	cfg.BGP.RouteViewsBaseURL = server.URL + "/routeviews/"
	cfg.BGP.RIPERISBaseURL = server.URL + "/ris/"
	cfg.BGP.Collectors = []string{"all"}
	cfg.BGP.Month = "2026.06"

	sources, err := DiscoverBGPRIBSources(context.Background(), server.Client(), cfg.BGP)
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 4 {
		t.Fatalf("expected four RIB sources, got %#v", sources)
	}
	wantURLs := []string{
		server.URL + "/routeviews/route-views2/bgpdata/2026.06/RIBS/rib.20260611.0800.bz2",
		server.URL + "/routeviews/hkix.hkg/bgpdata/2026.06/RIBS/rib.20260611.0400.bz2",
		server.URL + "/ris/rrc00/2026.06/bview.20260611.0800.gz",
		server.URL + "/ris/rrc01/2026.06/bview.20260611.0400.gz",
	}
	for _, want := range wantURLs {
		if !containsRIBURL(sources, want) {
			t.Fatalf("expected discovered URL %s, got %#v", want, sources)
		}
	}
}

func TestWriteBGPObservationSummaryDeduplicatesCollectorRecords(t *testing.T) {
	out := filepath.Join(t.TempDir(), "bgp-observations-full.jsonl.gz")
	observations := []BGPObservationInput{
		{Prefix: "64.81.32.0/21", OriginASN: 3257, Source: "routeviews", Collector: "route-views2", DominantUpstream: 1299},
		{Prefix: "64.81.32.0/21", OriginASN: 3257, Source: "routeviews", Collector: "route-views.sg", DominantUpstream: 1299},
		{Prefix: "64.81.32.0/21", OriginASN: 64500, Source: "ripe_ris", Collector: "rrc00", DominantUpstream: 2914},
		{Prefix: "2001:db8::/32", OriginASN: 64496, Source: "ripe_ris", Collector: "rrc01"},
	}
	if err := WriteBGPObservationSummary(out, observations); err != nil {
		t.Fatal(err)
	}

	file, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	body, err := os.ReadFile(out)
	if err != nil || len(body) == 0 {
		t.Fatalf("expected compressed summary file, len=%d err=%v", len(body), err)
	}
	decoded, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	text := string(decoded)
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected three summary lines, got %d: %s", len(lines), text)
	}
	if !strings.Contains(text, `"observation_count":2`) || !strings.Contains(text, `"collector":"routeviews:2"`) {
		t.Fatalf("expected routeviews collector aggregation, got %s", text)
	}
}

func TestDownloadBGPSourcesUsesDedicatedDownloadTimeoutForRIBBody(t *testing.T) {
	body := strings.Repeat("x", 4096)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rib.bz2" {
			http.NotFound(w, r)
			return
		}
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		time.Sleep(75 * time.Millisecond)
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	client := server.Client()
	client.Timeout = 25 * time.Millisecond
	rawDir := t.TempDir()
	downloaded, err := downloadBGPSources(
		context.Background(),
		client,
		rawDir,
		[]BGPRIBSource{{Source: "routeviews", Collector: "rv2", URL: server.URL + "/rib.bz2"}},
		1,
		500*time.Millisecond,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(downloaded) != 1 {
		t.Fatalf("expected one downloaded RIB, got %#v", downloaded)
	}
	got, err := os.ReadFile(downloaded[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Fatalf("unexpected downloaded body length=%d", len(got))
	}
}

func TestDownloadBGPFileRetriesUnexpectedEOFWithRangeResume(t *testing.T) {
	body := []byte("complete-rib-body")
	firstChunk := 7
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if requests == 1 {
			w.Header().Set("Content-Length", "17")
			_, _ = w.Write(body[:firstChunk])
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			return
		}
		if got := r.Header.Get("Range"); got != "bytes=7-" {
			t.Fatalf("expected resume range bytes=7-, got %q", got)
		}
		w.Header().Set("Content-Range", "bytes 7-16/17")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(body[firstChunk:])
	}))
	defer server.Close()

	originalDelay := bgpDownloadRetryDelay
	bgpDownloadRetryDelay = 0
	t.Cleanup(func() { bgpDownloadRetryDelay = originalDelay })

	destination := filepath.Join(t.TempDir(), "rib.gz")
	if err := downloadBGPFile(context.Background(), server.Client(), server.URL+"/rib.gz", destination); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("expected complete resumed body %q, got %q", body, got)
	}
	if requests != 2 {
		t.Fatalf("expected two requests, got %d", requests)
	}
}

func TestRefreshFullBGPSkipsFreshSummaryWithoutNetwork(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Error(w, "network should not be used for fresh summary", http.StatusInternalServerError)
	}))
	defer server.Close()

	dataDir := t.TempDir()
	cfg := config.Default()
	cfg.DataDir = dataDir
	cfg.BGP.Enabled = true
	cfg.BGP.Mode = "full"
	cfg.BGP.RefreshInterval = time.Hour
	cfg.BGP.RouteViewsBaseURL = server.URL + "/routeviews/"
	cfg.BGP.RIPERISBaseURL = server.URL + "/ris/"
	cfg.BGP.SummaryFile = filepath.Join(dataDir, "generated", "bgp-observations-full.jsonl.gz")
	if err := os.MkdirAll(filepath.Dir(cfg.BGP.SummaryFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := WriteBGPObservationSummary(cfg.BGP.SummaryFile, []BGPObservationInput{
		{Prefix: "64.81.32.0/21", OriginASN: 3257, Source: "routeviews", Collector: "rv2", DominantUpstream: 1299},
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := os.Chtimes(cfg.BGP.SummaryFile, now, now); err != nil {
		t.Fatal(err)
	}
	recordBGPRefreshSuccess(cfg, 2)

	count, err := RefreshFullBGP(context.Background(), cfg, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("expected skipped refresh source count 0, got %d", count)
	}
	if requests != 0 {
		t.Fatalf("expected fresh BGP summary to avoid network, got %d requests", requests)
	}
}

func TestRefreshFullBGPCompilesFreshSummaryWhenIndexMissing(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Error(w, "network should not be used when compiling fresh summary", http.StatusInternalServerError)
	}))
	defer server.Close()

	dataDir := t.TempDir()
	cfg := config.Default()
	cfg.DataDir = dataDir
	cfg.BGP.Enabled = true
	cfg.BGP.Mode = "full"
	cfg.BGP.RefreshInterval = time.Hour
	cfg.BGP.RouteViewsBaseURL = server.URL + "/routeviews/"
	cfg.BGP.RIPERISBaseURL = server.URL + "/ris/"
	cfg.BGP.SummaryFile = filepath.Join(dataDir, "generated", "bgp-observations-full.jsonl.gz")
	cfg.BGP.IndexFile = filepath.Join(dataDir, "generated", "bgp-index.bin")
	cfg.BGP.IndexMode = "compact"
	if err := WriteBGPObservationSummary(cfg.BGP.SummaryFile, []BGPObservationInput{
		{Prefix: "64.81.32.0/21", OriginASN: 3257, Source: "routeviews", Collector: "rv2", DominantUpstream: 1299},
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := os.Chtimes(cfg.BGP.SummaryFile, now, now); err != nil {
		t.Fatal(err)
	}
	recordBGPRefreshSuccess(cfg, 2)

	count, err := RefreshFullBGP(context.Background(), cfg, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("expected compile-only source count 0, got %d", count)
	}
	if requests != 0 {
		t.Fatalf("expected compile-only path to avoid network, got %d requests", requests)
	}
	loaded, err := store.LoadBGPObservationIndex(cfg.BGP.IndexFile)
	if err != nil {
		t.Fatal(err)
	}
	if summary := loaded.Summarize("64.81.32.32", 3257); summary.Visibility != 1 || summary.DominantUpstreams[0].ASN != 1299 {
		t.Fatalf("unexpected compiled summary: %#v", summary)
	}
}

func TestFreshBGPSummaryDoesNotSkipAfterNewerFailure(t *testing.T) {
	dataDir := t.TempDir()
	cfg := config.Default()
	cfg.DataDir = dataDir
	cfg.BGP.Enabled = true
	cfg.BGP.Mode = "full"
	cfg.BGP.RefreshInterval = time.Hour
	cfg.BGP.SummaryFile = filepath.Join(dataDir, "generated", "bgp-observations-full.jsonl.gz")
	if err := os.MkdirAll(filepath.Dir(cfg.BGP.SummaryFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.BGP.SummaryFile, []byte("fresh-summary"), 0o644); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 6, 23, 10, 0, 0, 0, time.UTC)
	if err := saveBGPRefreshState(dataDir, bgpRefreshState{
		Version:       1,
		SummaryFile:   cfg.BGP.SummaryFile,
		LastSuccessAt: base,
		LastErrorAt:   base.Add(time.Minute),
		LastError:     "previous bgp update failed",
	}); err != nil {
		t.Fatal(err)
	}

	skip, detail := shouldSkipFreshBGPSummary(cfg, base.Add(2*time.Minute))
	if skip {
		t.Fatalf("expected newer failure to allow immediate retry, detail=%q", detail)
	}
}

func containsRIBURL(sources []BGPRIBSource, want string) bool {
	for _, source := range sources {
		if source.URL == want {
			return true
		}
	}
	return false
}
