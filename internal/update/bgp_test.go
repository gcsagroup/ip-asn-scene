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

	"ipasn/internal/config"
)

func TestDiscoverBGPRIBSourcesFindsLatestRouteViewsAndRISFiles(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/routeviews/":
			_, _ = w.Write([]byte(`<a href="route-views2/">route-views2/</a><a href="route-views.sg/">route-views.sg/</a>`))
		case "/routeviews/route-views2/bgpdata/2026.06/RIBS/":
			_, _ = w.Write([]byte(`<a href="rib.20260611.0000.bz2">old</a><a href="rib.20260611.0800.bz2">new</a>`))
		case "/routeviews/route-views.sg/bgpdata/2026.06/RIBS/":
			_, _ = w.Write([]byte(`<a href="rib.20260611.0400.bz2">sg</a>`))
		case "/ris/":
			_, _ = w.Write([]byte(`<a href="rrc00/">rrc00/</a><a href="rrc01/">rrc01/</a>`))
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
		server.URL + "/routeviews/route-views.sg/bgpdata/2026.06/RIBS/rib.20260611.0400.bz2",
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

func containsRIBURL(sources []BGPRIBSource, want string) bool {
	for _, source := range sources {
		if source.URL == want {
			return true
		}
	}
	return false
}
