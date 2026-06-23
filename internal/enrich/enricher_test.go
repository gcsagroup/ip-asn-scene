package enrich

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ipasn/internal/perf"
	"ipasn/internal/store"
)

func TestParseCymruTXT(t *testing.T) {
	result, ok := ParseCymruTXT("15169 | 8.8.8.0/24 | US | arin | 1992-12-01 | GOOGLE - Google LLC")
	if !ok {
		t.Fatal("expected Team Cymru result")
	}
	if result.ASN != 15169 || result.Prefix != "8.8.8.0/24" || result.Country != "US" || result.Registry != "arin" {
		t.Fatalf("unexpected result: %#v", result)
	}

	_, ok = ParseCymruTXT("NA | 1.1.10.0/23 | CN | apnic | 2011-04-12 | NA")
	if ok {
		t.Fatal("expected NA ASN to be treated as no ASN")
	}
}

func TestParseRDAPSummary(t *testing.T) {
	summary := ParseRDAPSummary([]byte(`{
		"name": "CHINANET-GD",
		"type": "ALLOCATED PORTABLE",
		"country": "CN",
		"startAddress": "1.1.9.0",
		"endAddress": "1.1.15.255",
		"status": ["active"],
		"remarks": [
			{"title": "description", "description": ["CHINANET Guangdong province network", "China Telecom"]},
			{"title": "remarks", "description": ["service provider"]}
		]
	}`))
	if summary.Name != "CHINANET-GD" || summary.Country != "CN" {
		t.Fatalf("unexpected summary: %#v", summary)
	}
	if !strings.Contains(strings.Join(summary.Descriptions, " "), "China Telecom") {
		t.Fatalf("expected RDAP descriptions, got %#v", summary.Descriptions)
	}
}

func TestParseWhoisSummary(t *testing.T) {
	summary := ParseWhoisSummary(`inetnum:        1.1.9.0 - 1.1.15.255
netname:        CHINANET-GD
descr:          CHINANET Guangdong province network
descr:          China Telecom
country:        CN
status:         ALLOCATED PORTABLE
remarks:        service provider
source:         APNIC`)
	if summary.NetName != "CHINANET-GD" || summary.Country != "CN" || summary.Status != "ALLOCATED PORTABLE" {
		t.Fatalf("unexpected whois summary: %#v", summary)
	}
	if len(summary.Descriptions) != 2 {
		t.Fatalf("expected descriptions, got %#v", summary.Descriptions)
	}
}

func TestParseRIPEStatLookingGlass(t *testing.T) {
	analysis, ok := ParseRIPEStatLookingGlass([]byte(`{
		"status": "ok",
		"data": {
			"rrcs": [
				{"rrc":"RRC01","location":"London, United Kingdom","peers":[
					{"asn_origin":"45753","as_path":"2914 9744 9744 45753","prefix":"148.66.51.0/24","peer":"195.66.224.138"},
					{"asn_origin":"45753","as_path":"6461 3257 9744 9744 45753","prefix":"148.66.51.0/24","peer":"195.66.224.76"}
				]},
				{"rrc":"RRC06","location":"Tokyo, Japan","peers":[
					{"asn_origin":"45753","as_path":"6939 9744 45753","prefix":"148.66.51.0/24","peer":"2001:7fa:7::1"}
				]}
			]
		}
	}`))
	if !ok {
		t.Fatal("expected looking-glass analysis")
	}
	if analysis.ObservationCount != 3 {
		t.Fatalf("unexpected observation count: %#v", analysis)
	}
	if analysis.OriginASN != 45753 || analysis.Prefix != "148.66.51.0/24" {
		t.Fatalf("unexpected origin or prefix: %#v", analysis)
	}
	if len(analysis.UpstreamASNs) == 0 || analysis.UpstreamASNs[0].ASN != 9744 || analysis.UpstreamASNs[0].Count != 3 {
		t.Fatalf("expected AS9744 as dominant upstream, got %#v", analysis.UpstreamASNs)
	}
	if len(analysis.Paths) != 3 || analysis.Paths[0].RRC != "RRC01" {
		t.Fatalf("unexpected paths: %#v", analysis.Paths)
	}
}

func TestBuildGeoConsistencyDetectsCountryConflict(t *testing.T) {
	analysis := BuildGeoConsistency(GeoConsistencyInput{
		RegisteredCountry: "TW",
		AnnouncedCountry:  "HK",
		LocationCountry:   "HK",
		BGP: &BGPPathAnalysis{
			OriginASN:         45753,
			Prefix:            "148.66.51.0/24",
			ObservationCount:  3,
			DominantUpstream:  9744,
			DominantUpstreams: []int{9744},
		},
	})
	if !analysis.Conflict {
		t.Fatalf("expected country conflict: %#v", analysis)
	}
	if analysis.RegisteredCountry != "TW" || analysis.AnnouncedCountry != "HK" || analysis.LocationCountry != "HK" {
		t.Fatalf("unexpected countries: %#v", analysis)
	}
	if analysis.Confidence < 0.6 {
		t.Fatalf("expected medium confidence, got %#v", analysis)
	}
	if !strings.Contains(strings.Join(analysis.Evidence, " "), "注册地 TW") {
		t.Fatalf("expected conflict evidence, got %#v", analysis.Evidence)
	}
}

func TestRDAPURLUsesRegistrySpecificEndpoints(t *testing.T) {
	client := NewClient(Config{})
	if got := client.rdapURL("8.8.8.8", "arin"); got != "https://rdap.arin.net/registry/ip/8.8.8.8" {
		t.Fatalf("unexpected ARIN RDAP URL: %s", got)
	}
	if got := client.rdapURL("1.1.10.23", "apnic"); got != "https://rdap.apnic.net/ip/1.1.10.23" {
		t.Fatalf("unexpected APNIC RDAP URL: %s", got)
	}
}

func TestInferSceneIgnoresNotAnISPRemark(t *testing.T) {
	scene, _, _ := inferScene(Result{
		Whois: &WhoisSummary{
			NetName:      "XFInfo",
			Descriptions: []string{"NanJing XinFeng Information Technologies, Inc."},
			Remarks:      []string{"Please note that CNNIC is not an ISP and is not empowered to investigate complaints."},
		},
	}, store.AllocationRecord{Prefix: "114.114.0.0/15", Country: "CN", Registry: "apnic"})
	if scene == "DYN" {
		t.Fatalf("expected not-an-ISP remark not to infer DYN")
	}
}

func TestInferSceneDoesNotTreatAbuseContactEmailAsMailService(t *testing.T) {
	scene, _, _ := inferScene(Result{
		Organization: "Alibaba Cloud LLC",
		NetName:      "ALICLOUD-HK",
		RDAP: &RDAPSummary{
			Name:         "ALICLOUD-HK",
			Descriptions: []string{"For abuse reports, please send email to abuse@alibaba-inc.com"},
		},
		Whois: &WhoisSummary{
			NetName:      "ALICLOUD-HK",
			Descriptions: []string{"Alibaba Cloud - HK"},
			Remarks:      []string{"Please send email to the abuse contact."},
		},
	}, store.AllocationRecord{Prefix: "47.75.0.0/16", Country: "HK", Registry: "apnic"})
	if scene != "IDC" {
		t.Fatalf("expected Alibaba Cloud abuse contact text to infer IDC, got %s", scene)
	}
}

func TestClientEnrichesWithRipeRDAPWhoisAndCache(t *testing.T) {
	var mu sync.Mutex
	requests := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests[r.URL.Path]++
		mu.Unlock()
		switch r.URL.Path {
		case "/ripestat/network-info":
			_, _ = w.Write([]byte(`{"status":"ok","data":{"asns":[],"prefix":""}}`))
		case "/ripestat/prefix-overview":
			_, _ = w.Write([]byte(`{"status":"ok","data":{"announced":false,"asns":[],"query_time":"2026-05-20T08:00:00"}}`))
		case "/rdap/ip/1.1.10.23":
			_, _ = w.Write([]byte(`{"name":"CHINANET-GD","country":"CN","startAddress":"1.1.9.0","endAddress":"1.1.15.255","remarks":[{"description":["CHINANET Guangdong province network","China Telecom","service provider"]}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cacheDir := t.TempDir()
	client := NewClient(Config{
		CacheDir:           cacheDir,
		TTL:                time.Hour,
		RIPEStatNetworkURL: server.URL + "/ripestat/network-info?resource={ip}",
		RIPEStatPrefixURL:  server.URL + "/ripestat/prefix-overview?resource={ip}",
		RDAPURLTemplate:    server.URL + "/rdap/ip/{ip}",
		TeamCymruTXTLookup: func(ctx context.Context, ip string) ([]string, error) { return nil, nil },
		WhoisLookup: func(ctx context.Context, registry, ip string) (string, error) {
			return "netname: CHINANET-GD\ndescr: China Telecom\nremarks: service provider\ncountry: CN\nstatus: ALLOCATED PORTABLE\nsource: APNIC", nil
		},
	})
	allocation := store.AllocationRecord{Prefix: "1.1.10.0/23", Country: "CN", Registry: "apnic", Status: "allocated", Source: "rir:apnic"}

	result, err := client.EnrichIP(context.Background(), "1.1.10.23", allocation)
	if err != nil {
		t.Fatal(err)
	}
	if result.InferredScene != "DYN" {
		t.Fatalf("expected DYN inference from China Telecom service provider data, got %#v", result)
	}
	if len(result.Evidence) < 4 {
		t.Fatalf("expected multi-source evidence, got %#v", result.Evidence)
	}

	result, err = client.EnrichIP(context.Background(), "1.1.10.23", allocation)
	if err != nil {
		t.Fatal(err)
	}
	if !result.CacheHit {
		t.Fatal("expected second enrichment to use cache")
	}
	mu.Lock()
	rdapRequests := requests["/rdap/ip/1.1.10.23"]
	mu.Unlock()
	if rdapRequests != 1 {
		t.Fatalf("expected RDAP request to be cached, got %d requests", rdapRequests)
	}
}

func TestClientEnrichesOnlineSourcesConcurrently(t *testing.T) {
	delay := 120 * time.Millisecond
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
		switch r.URL.Path {
		case "/ripestat/prefix-overview":
			_, _ = w.Write([]byte(`{"status":"ok","data":{"announced":true,"asns":[{"asn":15169}],"resource":"8.8.8.0/24","query_time":"2026-05-20T08:00:00"}}`))
		case "/ripestat/looking-glass":
			_, _ = w.Write([]byte(`{"status":"ok","data":{"rrcs":[{"rrc":"RRC01","location":"London, United Kingdom","peers":[{"asn_origin":"15169","as_path":"2914 15169","prefix":"8.8.8.0/24","peer":"192.0.2.1"}]}]}}`))
		case "/rdap/ip/8.8.8.8":
			_, _ = w.Write([]byte(`{"name":"GOGL","country":"US","remarks":[{"description":["Google LLC"]}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	var cymruCalls atomic.Int32
	var whoisCalls atomic.Int32
	client := NewClient(Config{
		CacheDir:           t.TempDir(),
		TTL:                time.Hour,
		Timeout:            2 * time.Second,
		RIPEStatPrefixURL:  server.URL + "/ripestat/prefix-overview?resource={ip}",
		RIPEStatBGPPathURL: server.URL + "/ripestat/looking-glass?resource={prefix}",
		RDAPURLTemplate:    server.URL + "/rdap/ip/{ip}",
		TeamCymruTXTLookup: func(ctx context.Context, ip string) ([]string, error) {
			cymruCalls.Add(1)
			time.Sleep(delay)
			return []string{"15169 | 8.8.8.0/24 | US | arin | 1992-12-01 | GOOGLE - Google LLC"}, nil
		},
		WhoisLookup: func(ctx context.Context, registry, ip string) (string, error) {
			whoisCalls.Add(1)
			time.Sleep(delay)
			return "netname: GOGL\ndescr: Google LLC\ncountry: US\nsource: ARIN", nil
		},
	})

	start := time.Now()
	result, err := client.EnrichIP(context.Background(), "8.8.8.8", store.AllocationRecord{Prefix: "8.8.8.0/24", Country: "US", Registry: "arin", Source: "rir:arin"})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if result.TeamCymru == nil || result.RIPEStat == nil || result.RDAP == nil || result.Whois == nil {
		t.Fatalf("expected all online sources, got %#v", result)
	}
	if cymruCalls.Load() != 1 || whoisCalls.Load() != 1 {
		t.Fatalf("expected one cymru and whois call, got %d/%d", cymruCalls.Load(), whoisCalls.Load())
	}
	if elapsed >= 320*time.Millisecond {
		t.Fatalf("expected online enrichment to run concurrently, took %s", elapsed)
	}
}

func TestClientRecordsThirdPartyTimings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ripestat/prefix-overview":
			_, _ = w.Write([]byte(`{"status":"ok","data":{"announced":true,"asns":[{"asn":15169}],"resource":"8.8.8.0/24","query_time":"2026-05-20T08:00:00"}}`))
		case "/ripestat/looking-glass":
			_, _ = w.Write([]byte(`{"status":"ok","data":{"rrcs":[{"rrc":"RRC01","location":"London, United Kingdom","peers":[{"asn_origin":"15169","as_path":"2914 15169","prefix":"8.8.8.0/24","peer":"192.0.2.1"}]}]}}`))
		case "/rdap/ip/8.8.8.8":
			_, _ = w.Write([]byte(`{"name":"GOGL","country":"US","remarks":[{"description":["Google LLC"]}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewClient(Config{
		CacheDir:           t.TempDir(),
		TTL:                time.Hour,
		Timeout:            2 * time.Second,
		RIPEStatPrefixURL:  server.URL + "/ripestat/prefix-overview?resource={ip}",
		RIPEStatBGPPathURL: server.URL + "/ripestat/looking-glass?resource={prefix}",
		RDAPURLTemplate:    server.URL + "/rdap/ip/{ip}",
		TeamCymruTXTLookup: func(ctx context.Context, ip string) ([]string, error) {
			return []string{"15169 | 8.8.8.0/24 | US | arin | 1992-12-01 | GOOGLE - Google LLC"}, nil
		},
		WhoisLookup: func(ctx context.Context, registry, ip string) (string, error) {
			return "netname: GOGL\ndescr: Google LLC\ncountry: US\nsource: ARIN", nil
		},
	})

	recorder := perf.NewRecorder()
	ctx := perf.WithRecorder(context.Background(), recorder)
	_, err := client.EnrichIPWithOptions(ctx, "8.8.8.8", store.AllocationRecord{Prefix: "8.8.8.0/24", Country: "US", Registry: "arin", Source: "rir:arin"}, RequestOptions{Mode: ModeWait})
	if err != nil {
		t.Fatal(err)
	}
	report := recorder.Finish(true)
	names := map[string]bool{}
	for _, item := range report.ThirdParty {
		names[item.Name] = true
		if item.DurationMS < 0 {
			t.Fatalf("expected non-negative third-party duration: %#v", item)
		}
		if item.URL == "" {
			t.Fatalf("expected third-party URL: %#v", item)
		}
	}
	for _, expected := range []string{"team_cymru", "ripestat_prefix", "rdap", "whois", "ripe_ris_looking_glass"} {
		if !names[expected] {
			t.Fatalf("expected timing for %s, got %#v", expected, report.ThirdParty)
		}
	}
}

func TestClientAsyncOnMissReturnsImmediatelyAndRefreshesCache(t *testing.T) {
	delay := 150 * time.Millisecond
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
		switch r.URL.Path {
		case "/ripestat/prefix-overview":
			_, _ = w.Write([]byte(`{"status":"ok","data":{"announced":true,"asns":[{"asn":15169}],"resource":"8.8.8.0/24","query_time":"2026-05-20T08:00:00"}}`))
		case "/ripestat/looking-glass":
			_, _ = w.Write([]byte(`{"status":"ok","data":{"rrcs":[{"rrc":"RRC01","location":"London, United Kingdom","peers":[{"asn_origin":"15169","as_path":"2914 15169","prefix":"8.8.8.0/24","peer":"192.0.2.1"}]}]}}`))
		case "/rdap/ip/8.8.8.8":
			_, _ = w.Write([]byte(`{"name":"GOGL","country":"US","remarks":[{"description":["Google LLC"]}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewClient(Config{
		CacheDir:           t.TempDir(),
		TTL:                time.Hour,
		Timeout:            2 * time.Second,
		AsyncOnMiss:        true,
		ForegroundTimeout:  20 * time.Millisecond,
		RIPEStatPrefixURL:  server.URL + "/ripestat/prefix-overview?resource={ip}",
		RIPEStatBGPPathURL: server.URL + "/ripestat/looking-glass?resource={prefix}",
		RDAPURLTemplate:    server.URL + "/rdap/ip/{ip}",
		TeamCymruTXTLookup: func(ctx context.Context, ip string) ([]string, error) {
			time.Sleep(delay)
			return []string{"15169 | 8.8.8.0/24 | US | arin | 1992-12-01 | GOOGLE - Google LLC"}, nil
		},
		WhoisLookup: func(ctx context.Context, registry, ip string) (string, error) {
			time.Sleep(delay)
			return "netname: GOGL\ndescr: Google LLC\ncountry: US\nsource: ARIN", nil
		},
	})

	start := time.Now()
	result, err := client.EnrichIP(context.Background(), "8.8.8.8", store.AllocationRecord{Prefix: "8.8.8.0/24", Country: "US", Registry: "arin", Source: "rir:arin"})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if !result.RefreshQueued {
		t.Fatalf("expected refresh to be queued on cache miss, got %#v", result)
	}
	if result.RDAP != nil || result.BGPPath != nil {
		t.Fatalf("expected first async miss to return without online data, got %#v", result)
	}
	if elapsed >= delay/2 {
		t.Fatalf("expected async miss to return immediately, took %s", elapsed)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(40 * time.Millisecond)
		result, err = client.EnrichIP(context.Background(), "8.8.8.8", store.AllocationRecord{Prefix: "8.8.8.0/24", Country: "US", Registry: "arin", Source: "rir:arin"})
		if err != nil {
			t.Fatal(err)
		}
		if result.CacheHit && result.RDAP != nil && result.BGPPath != nil {
			return
		}
	}
	t.Fatalf("expected background refresh to populate cache, got %#v", result)
}

func TestClientAsyncOnMissReturnsForegroundEnrichmentWhenReady(t *testing.T) {
	delay := 20 * time.Millisecond
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
		switch r.URL.Path {
		case "/ripestat/prefix-overview":
			_, _ = w.Write([]byte(`{"status":"ok","data":{"announced":true,"asns":[{"asn":45753}],"resource":"148.66.51.0/24","query_time":"2026-05-20T08:00:00"}}`))
		case "/ripestat/looking-glass":
			_, _ = w.Write([]byte(`{"status":"ok","data":{"rrcs":[{"rrc":"RRC01","location":"London, United Kingdom","peers":[{"asn_origin":"45753","as_path":"2914 9744 45753","prefix":"148.66.51.0/24","peer":"192.0.2.1"}]}]}}`))
		case "/rdap/ip/148.66.51.30":
			_, _ = w.Write([]byte(`{"name":"Netsec","country":"TW","remarks":[{"description":["Netsec"]}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewClient(Config{
		CacheDir:           t.TempDir(),
		TTL:                time.Hour,
		Timeout:            2 * time.Second,
		AsyncOnMiss:        true,
		ForegroundTimeout:  500 * time.Millisecond,
		RIPEStatPrefixURL:  server.URL + "/ripestat/prefix-overview?resource={ip}",
		RIPEStatBGPPathURL: server.URL + "/ripestat/looking-glass?resource={prefix}",
		RDAPURLTemplate:    server.URL + "/rdap/ip/{ip}",
		TeamCymruTXTLookup: func(ctx context.Context, ip string) ([]string, error) {
			time.Sleep(delay)
			return []string{"45753 | 148.66.51.0/24 | HK | apnic | 2011-04-12 | NETSEC - Netsec"}, nil
		},
		WhoisLookup: func(ctx context.Context, registry, ip string) (string, error) {
			time.Sleep(delay)
			return "netname: Netsec\ndescr: Netsec\ncountry: TW\nsource: APNIC", nil
		},
	})

	start := time.Now()
	result, err := client.EnrichIP(context.Background(), "148.66.51.30", store.AllocationRecord{Prefix: "148.66.48.0/20", Country: "HK", Registry: "apnic", Source: "rir:apnic"})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if result.RefreshQueued || result.RefreshInProgress {
		t.Fatalf("expected foreground result instead of queued refresh, got %#v", result)
	}
	if result.GeoConsistency == nil || !result.GeoConsistency.Conflict {
		t.Fatalf("expected first miss to include geo conflict, got %#v", result.GeoConsistency)
	}
	if result.BGPPath == nil || result.BGPPath.DominantUpstream != 9744 {
		t.Fatalf("expected first miss to include BGP path, got %#v", result.BGPPath)
	}
	if elapsed >= 300*time.Millisecond {
		t.Fatalf("expected foreground enrichment to stay within short wait budget, took %s", elapsed)
	}
}

func TestClientAsyncOnMissDeduplicatesConcurrentRefresh(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	client := NewClient(Config{
		CacheDir:          t.TempDir(),
		TTL:               time.Hour,
		Timeout:           time.Second,
		AsyncOnMiss:       true,
		ForegroundTimeout: time.Millisecond,
		RIPEStatPrefixURL: "http://127.0.0.1:1/ripestat/prefix-overview?resource={ip}",
		RDAPURLTemplate:   "http://127.0.0.1:1/rdap/ip/{ip}",
		TeamCymruTXTLookup: func(ctx context.Context, ip string) ([]string, error) {
			calls.Add(1)
			select {
			case <-release:
				return []string{"15169 | 8.8.8.0/24 | US | arin | 1992-12-01 | GOOGLE - Google LLC"}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
		WhoisLookup: func(ctx context.Context, registry, ip string) (string, error) {
			return "", nil
		},
	})
	allocation := store.AllocationRecord{Prefix: "8.8.8.0/24", Country: "US", Registry: "arin", Source: "rir:arin"}

	for i := 0; i < 10; i++ {
		result, err := client.EnrichIP(context.Background(), "8.8.8.8", allocation)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 && !result.RefreshQueued {
			t.Fatalf("expected first miss to queue refresh, got %#v", result)
		}
	}

	deadline := time.Now().Add(500 * time.Millisecond)
	for calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected one background refresh, got %d", calls.Load())
	}
	close(release)
}

func TestClientWaitModeIgnoresAsyncMissAndReturnsOnlineResult(t *testing.T) {
	delay := 60 * time.Millisecond
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
		switch r.URL.Path {
		case "/ripestat/prefix-overview":
			_, _ = w.Write([]byte(`{"status":"ok","data":{"announced":true,"asns":[{"asn":58453}],"resource":"223.119.0.0/16","query_time":"2026-06-10T08:00:00"}}`))
		case "/ripestat/looking-glass":
			_, _ = w.Write([]byte(`{"status":"ok","data":{"rrcs":[{"rrc":"RRC01","location":"London, United Kingdom","peers":[{"asn_origin":"58453","as_path":"1299 58453","prefix":"223.119.0.0/16","peer":"192.0.2.1"}]}]}}`))
		case "/rdap/ip/223.119.20.239":
			_, _ = w.Write([]byte(`{"name":"CMI-SG","country":"SG","remarks":[{"description":["China Mobile International - Singapore Network"]}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewClient(Config{
		CacheDir:           t.TempDir(),
		TTL:                time.Hour,
		Timeout:            2 * time.Second,
		AsyncOnMiss:        true,
		ForegroundTimeout:  time.Millisecond,
		RIPEStatPrefixURL:  server.URL + "/ripestat/prefix-overview?resource={ip}",
		RIPEStatBGPPathURL: server.URL + "/ripestat/looking-glass?resource={prefix}",
		RDAPURLTemplate:    server.URL + "/rdap/ip/{ip}",
		TeamCymruTXTLookup: func(ctx context.Context, ip string) ([]string, error) {
			time.Sleep(delay)
			return []string{"58453 | 223.119.0.0/16 | HK | apnic | 2010-07-01 | CMI-INT-HK - China Mobile International Limited, HK"}, nil
		},
		WhoisLookup: func(ctx context.Context, registry, ip string) (string, error) {
			time.Sleep(delay)
			return "netname: CMI-SG\ndescr: China Mobile International - Singapore Network\ncountry: SG\nsource: APNIC", nil
		},
	})

	result, err := client.EnrichIPWithOptions(context.Background(), "223.119.20.239", store.AllocationRecord{Prefix: "223.118.0.0/15", Country: "HK", Registry: "apnic", Source: "rir:apnic"}, RequestOptions{Mode: ModeWait})
	if err != nil {
		t.Fatal(err)
	}
	if result.RefreshQueued || result.RefreshInProgress {
		t.Fatalf("expected wait mode to return online result, got %#v", result)
	}
	if result.RDAP == nil || result.Whois == nil || result.BGPPath == nil || result.BGPPath.DominantUpstream != 1299 {
		t.Fatalf("expected wait mode online details, got %#v", result)
	}
}
