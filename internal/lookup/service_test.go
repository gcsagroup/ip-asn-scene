package lookup

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ipasn/internal/ai"
	"ipasn/internal/classify"
	"ipasn/internal/enrich"
	"ipasn/internal/geo"
	"ipasn/internal/store"
)

type fakeAdvisor struct {
	calls    int
	decision ai.Decision
	err      error
}

type fakeEnricher struct {
	result enrich.Result
	err    error
}

type optionRecordingEnricher struct {
	mode   enrich.Mode
	calls  atomic.Int32
	result enrich.Result
}

type fakeGeoLocator struct {
	location geo.Location
	ok       bool
}

func (f fakeEnricher) EnrichIP(ctx context.Context, ip string, allocation store.AllocationRecord) (enrich.Result, error) {
	return f.result, f.err
}

func (f *optionRecordingEnricher) EnrichIP(ctx context.Context, ip string, allocation store.AllocationRecord) (enrich.Result, error) {
	f.calls.Add(1)
	f.mode = enrich.ModeFast
	return f.result, nil
}

func (f *optionRecordingEnricher) EnrichIPWithOptions(ctx context.Context, ip string, allocation store.AllocationRecord, options enrich.RequestOptions) (enrich.Result, error) {
	f.calls.Add(1)
	f.mode = options.Mode
	out := f.result
	out.Organization = string(options.Mode)
	return out, nil
}

func (f fakeGeoLocator) Lookup(ctx context.Context, ip string) (geo.Location, bool) {
	return f.location, f.ok
}

func (f *fakeAdvisor) Advise(ctx context.Context, input ai.AdviceInput) (ai.Decision, error) {
	f.calls++
	return f.decision, f.err
}

func setReverseDNSForTest(lookup func(string) ([]string, error), ttl time.Duration) func() {
	previousLookup := reverseDNSLookup
	previousCache := defaultReverseDNSCache
	reverseDNSLookup = lookup
	defaultReverseDNSCache = newReverseDNSCache(ttl)
	return func() {
		reverseDNSLookup = previousLookup
		defaultReverseDNSCache = previousCache
	}
}

func TestReverseDNSUsesCache(t *testing.T) {
	var calls atomic.Int32
	restore := setReverseDNSForTest(func(addr string) ([]string, error) {
		calls.Add(1)
		return []string{"dns.google."}, nil
	}, 7*24*time.Hour)
	defer restore()

	addr := netip.MustParseAddr("8.8.8.8")
	if got := reverseDNS(addr); got != "dns.google" {
		t.Fatalf("unexpected rdns: %q", got)
	}
	if got := reverseDNS(addr); got != "dns.google" {
		t.Fatalf("unexpected cached rdns: %q", got)
	}
	if calls.Load() != 1 {
		t.Fatalf("expected one reverse DNS lookup, got %d", calls.Load())
	}
}

func TestReverseDNSDoesNotCacheExpiredEntries(t *testing.T) {
	var calls atomic.Int32
	restore := setReverseDNSForTest(func(addr string) ([]string, error) {
		calls.Add(1)
		return []string{"dns.google."}, nil
	}, time.Nanosecond)
	defer restore()

	addr := netip.MustParseAddr("8.8.8.8")
	_ = reverseDNS(addr)
	time.Sleep(time.Millisecond)
	_ = reverseDNS(addr)
	if calls.Load() != 2 {
		t.Fatalf("expected expired cache to refresh, got %d lookups", calls.Load())
	}
}

func TestServiceIncludesLocationOnlyWhenRequested(t *testing.T) {
	prefixes := store.NewPrefixIndex()
	if err := prefixes.Add("8.8.8.0/24", 15169, "test"); err != nil {
		t.Fatal(err)
	}
	asns := store.NewASNIndex()
	asns.Upsert(store.ASNProfile{ASN: 15169, Name: "Google LLC"})
	svc := NewServiceWithOptions(store.NewSnapshot(prefixes, asns, store.Status{Version: "test"}), Options{
		GeoLocator: fakeGeoLocator{ok: true, location: geo.Location{
			Country:     "美国",
			Province:    "加利福尼亚",
			City:        "山景城",
			ISP:         "Google",
			CountryCode: "US",
			Source:      "ip2region",
			DBVersion:   "2026-05-20",
		}},
	})

	ordinary := svc.Lookup("8.8.8.8")
	if ordinary.Location != nil {
		t.Fatalf("expected location to be omitted by default, got %#v", ordinary.Location)
	}

	withLocation := svc.LookupWithOptions(context.Background(), "8.8.8.8", LookupOptions{IncludeLocation: true})
	if withLocation.Location == nil {
		t.Fatalf("expected location when requested")
	}
	if withLocation.Location.Country != "美国" || withLocation.Location.CountryCode != "US" {
		t.Fatalf("unexpected location: %#v", withLocation.Location)
	}
	if !containsEvidence(withLocation.Evidence, "IP 所在地：美国 加利福尼亚 山景城 Google") {
		t.Fatalf("expected location evidence, got %#v", withLocation.Evidence)
	}
}

func TestServiceLookupIP(t *testing.T) {
	prefixes := store.NewPrefixIndex()
	if err := prefixes.Add("8.8.8.0/24", 15169, "test"); err != nil {
		t.Fatal(err)
	}
	if err := prefixes.Add("8.8.4.0/24", 15169, "test"); err != nil {
		t.Fatal(err)
	}
	asns := store.NewASNIndex()
	asns.Upsert(store.ASNProfile{ASN: 15169, Name: "Google LLC", InfoType: "Content"})
	svc := NewService(store.NewSnapshot(prefixes, asns, store.Status{Version: "test"}))

	result := svc.Lookup("8.8.8.8")
	if !result.OK {
		t.Fatalf("expected success: %s", result.Error)
	}
	if result.ASN != 15169 || result.MatchedPrefix != "8.8.8.0/24" {
		t.Fatalf("unexpected lookup result: %#v", result)
	}
	if result.Company != "Google LLC" {
		t.Fatalf("expected company, got %q", result.Company)
	}
	if len(result.Prefixes) != 2 {
		t.Fatalf("expected related prefixes for IP lookup, got %#v", result.Prefixes)
	}
	if result.Prefixes[0] != "8.8.8.0/24" {
		t.Fatalf("expected matched prefix first, got %#v", result.Prefixes)
	}
	if result.InferredScene != "DNS" || result.InferredSource != "主场景规则" {
		t.Fatalf("expected fallback inferred usage for ordinary IP, got %#v", result)
	}
}

func TestServiceUsesEnrichmentForAnnouncedIP(t *testing.T) {
	prefixes := store.NewPrefixIndex()
	if err := prefixes.Add("8.8.8.0/24", 15169, "caida"); err != nil {
		t.Fatal(err)
	}
	asns := store.NewASNIndex()
	asns.Upsert(store.ASNProfile{ASN: 15169, Name: "Google LLC", Country: "US", Registry: "arin"})
	allocations := store.NewAllocationIndex()
	if err := allocations.Add(store.AllocationRecord{Prefix: "8.8.8.0/24", Country: "US", Registry: "arin", Status: "allocated", Source: "rir:arin"}); err != nil {
		t.Fatal(err)
	}
	historyPrefixes := store.NewPrefixIndex()
	if err := historyPrefixes.Add("8.8.8.0/24", 15169, "caida_history"); err != nil {
		t.Fatal(err)
	}
	history := store.NewHistoryIndex()
	history.AddSnapshot("ipv4-routeviews-rv2-20260518-1200", historyPrefixes)

	snapshot := store.NewSnapshotFull(prefixes, allocations, asns, history, store.Status{Version: "test"})
	svc := NewServiceWithOptions(snapshot, Options{
		Enricher: fakeEnricher{result: enrich.Result{
			Organization:       "Google LLC",
			NetName:            "GOGL",
			InferredScene:      "IDC",
			InferredSceneName:  "数据中心",
			InferredConfidence: 0.76,
			Sources:            []string{"team_cymru", "ripestat", "rdap", "whois"},
			Evidence: []string{
				"Team Cymru 当前命中 AS15169 / 8.8.8.0/24",
				"RIPEstat 当前宣告 AS15169 / 8.8.8.0/24",
				"RDAP: GOGL / Google LLC",
				"WHOIS: GOGL / Google LLC",
			},
		}},
	})

	result := svc.Lookup("8.8.8.8")
	if !result.OK {
		t.Fatalf("expected success: %s", result.Error)
	}
	if result.Registration == nil {
		t.Fatalf("expected registration enrichment")
	}
	if result.NetName != "GOGL" || result.AllocationStatus != "allocated" {
		t.Fatalf("expected RDAP/WHOIS and allocation fields, got %#v", result)
	}
	if result.InferredScene != "DNS" || result.InferredSource != "主场景规则" {
		t.Fatalf("expected high-confidence DNS inferred usage, got %#v", result)
	}
	if len(result.History) != 1 || result.History[0].ASN != 15169 {
		t.Fatalf("expected historical BGP hit, got %#v", result.History)
	}
	if !containsEvidence(result.Evidence, "Team Cymru 当前命中 AS15169") {
		t.Fatalf("expected Team Cymru evidence, got %#v", result.Evidence)
	}
	if !containsEvidence(result.Evidence, "历史 BGP 样本曾命中 AS15169") {
		t.Fatalf("expected historical BGP evidence, got %#v", result.Evidence)
	}
}

func TestServicePassesOnlineEnrichmentMode(t *testing.T) {
	prefixes := store.NewPrefixIndex()
	if err := prefixes.Add("223.119.0.0/16", 58453, "caida"); err != nil {
		t.Fatal(err)
	}
	asns := store.NewASNIndex()
	asns.Upsert(store.ASNProfile{ASN: 58453, Name: "China Mobile International", Country: "HK", Registry: "apnic"})
	allocations := store.NewAllocationIndex()
	if err := allocations.Add(store.AllocationRecord{Prefix: "223.118.0.0/15", Country: "HK", Registry: "apnic", Status: "allocated", Source: "rir:apnic"}); err != nil {
		t.Fatal(err)
	}
	enricher := &optionRecordingEnricher{result: enrich.Result{NetName: "CMI-SG"}}
	svc := NewServiceWithOptions(store.NewSnapshotFull(prefixes, allocations, asns, store.NewHistoryIndex(), store.Status{Version: "test"}), Options{
		Enricher: enricher,
	})

	result := svc.LookupWithOptions(context.Background(), "223.119.20.239", LookupOptions{OnlineEnrichment: OnlineEnrichmentWait})
	if !result.OK {
		t.Fatalf("expected success: %s", result.Error)
	}
	if enricher.mode != enrich.ModeWait {
		t.Fatalf("expected wait mode to be passed to enricher, got %q", enricher.mode)
	}
	if result.Registration == nil || result.Registration.Organization != "wait" {
		t.Fatalf("expected wait-mode organization in registration, got %#v", result.Registration)
	}

	result = svc.LookupWithOptions(context.Background(), "223.119.20.239", LookupOptions{OnlineEnrichment: OnlineEnrichmentOff})
	if !result.OK {
		t.Fatalf("expected success: %s", result.Error)
	}
	if enricher.calls.Load() != 1 {
		t.Fatalf("expected online_enrichment=off to skip enricher, got %d calls", enricher.calls.Load())
	}
}

func TestServiceAddsGeoConsistencyWithLocationCountry(t *testing.T) {
	prefixes := store.NewPrefixIndex()
	if err := prefixes.Add("148.66.51.0/24", 45753, "caida"); err != nil {
		t.Fatal(err)
	}
	asns := store.NewASNIndex()
	asns.Upsert(store.ASNProfile{ASN: 45753, Name: "Simcentric Solutions Limited", Country: "HK", Registry: "apnic"})
	allocations := store.NewAllocationIndex()
	if err := allocations.Add(store.AllocationRecord{Prefix: "148.66.48.0/20", Country: "HK", Registry: "apnic", Status: "allocated", Source: "rir:apnic"}); err != nil {
		t.Fatal(err)
	}
	snapshot := store.NewSnapshotFull(prefixes, allocations, asns, store.NewHistoryIndex(), store.Status{Version: "test"})
	svc := NewServiceWithOptions(snapshot, Options{
		Enricher: fakeEnricher{result: enrich.Result{
			Organization: "Netsec",
			TeamCymru:    &enrich.CymruResult{ASN: 45753, Prefix: "148.66.51.0/24", Country: "HK"},
			RDAP:         &enrich.RDAPSummary{Name: "Netsec", Country: "TW"},
			Whois:        &enrich.WhoisSummary{NetName: "Netsec", Country: "TW"},
			BGPPath:      &enrich.BGPPathAnalysis{OriginASN: 45753, Prefix: "148.66.51.0/24", ObservationCount: 3, DominantUpstream: 9744},
		}},
		GeoLocator: fakeGeoLocator{ok: true, location: geo.Location{
			Country:     "中国",
			Province:    "香港",
			City:        "香港",
			ISP:         "Netsec",
			CountryCode: "HK",
		}},
	})

	result := svc.LookupWithOptions(context.Background(), "148.66.51.30", LookupOptions{IncludeLocation: true})
	if !result.OK {
		t.Fatalf("expected success: %s", result.Error)
	}
	if result.GeoConsistency == nil || !result.GeoConsistency.Conflict {
		t.Fatalf("expected geo consistency conflict, got %#v", result.GeoConsistency)
	}
	if result.GeoConsistency.RegisteredCountry != "TW" || result.GeoConsistency.AnnouncedCountry != "HK" || result.GeoConsistency.LocationCountry != "HK" {
		t.Fatalf("unexpected geo consistency countries: %#v", result.GeoConsistency)
	}
}

func TestApplyWeightedSourceDecisionPromotesConsensus(t *testing.T) {
	result := &Result{
		QueryType:          "ip",
		Scene:              "NET",
		SceneName:          "基础设施",
		Confidence:         0.72,
		InferredScene:      "NET",
		InferredSceneName:  "基础设施",
		InferredConfidence: 0.72,
		InferredSource:     "主场景规则",
		Registration: &enrich.Result{
			InferredScene:      "IDC",
			InferredSceneName:  "数据中心",
			InferredConfidence: 0.84,
			NetName:            "Example Cloud Hosting",
		},
		Egress: &EgressInfo{
			Type:       "IDC",
			Summary:    "机房 Example Facility",
			Confidence: 0.65,
		},
	}

	applyWeightedSourceDecision(result)

	if result.Scene != "IDC" || result.InferredScene != "IDC" {
		t.Fatalf("expected IDC consensus promotion, got %#v", result)
	}
	if result.Confidence < 0.8 {
		t.Fatalf("expected promoted confidence, got %f", result.Confidence)
	}
	if !containsEvidence(result.Evidence, "多源投票修正用途") {
		t.Fatalf("expected weighted decision evidence, got %#v", result.Evidence)
	}
}

func TestServiceAddsEgressInferenceForMultipleIPs(t *testing.T) {
	tests := []struct {
		name         string
		ip           string
		prefix       string
		asn          int
		company      string
		upstreamASN  int
		upstreamName string
		ixp          string
		country      string
		facility     string
		asPath       []int
		wantEvidence string
		wantTransit  bool
	}{
		{
			name:         "netsec via xlc global hong kong",
			ip:           "148.66.51.30",
			prefix:       "148.66.51.0/24",
			asn:          45753,
			company:      "Simcentric Solutions Limited",
			upstreamASN:  9744,
			upstreamName: "XLC GLOBAL",
			ixp:          "HKIX",
			country:      "HK",
			facility:     "Mega-iAdvantage",
			asPath:       []int{2914, 9744, 45753},
			wantEvidence: "AS9744",
		},
		{
			name:         "cmi via arelion hong kong",
			ip:           "223.119.20.239",
			prefix:       "223.119.0.0/16",
			asn:          58453,
			company:      "China Mobile International",
			upstreamASN:  1299,
			upstreamName: "Arelion",
			ixp:          "HKIX",
			country:      "HK",
			facility:     "Equinix HK1",
			asPath:       []int{1299, 58453},
			wantEvidence: "AS1299",
			wantTransit:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefixes := store.NewPrefixIndex()
			if err := prefixes.Add(tt.prefix, tt.asn, "caida"); err != nil {
				t.Fatal(err)
			}
			asns := store.NewASNIndex()
			asns.Upsert(store.ASNProfile{ASN: tt.asn, Name: tt.company, Country: tt.country, Registry: "apnic"})
			asns.Upsert(store.ASNProfile{ASN: tt.upstreamASN, Name: tt.upstreamName, Country: tt.country, Sources: []string{"peeringdb"}})
			allocations := store.NewAllocationIndex()
			if err := allocations.Add(store.AllocationRecord{Prefix: tt.prefix, Country: tt.country, Registry: "apnic", Status: "allocated", Source: "rir:apnic"}); err != nil {
				t.Fatal(err)
			}
			egress := store.NewEgressIndex()
			egress.AddIXP(store.IXPPresence{ASN: tt.upstreamASN, Name: tt.ixp, Country: tt.country, City: "Hong Kong", Speed: 100000, IP: "123.255.92.18"})
			egress.AddFacility(store.FacilityPresence{ASN: tt.upstreamASN, Name: "123.NET - DC1", Country: "US", City: "Southfield"})
			egress.AddFacility(store.FacilityPresence{ASN: tt.upstreamASN, Name: tt.facility, Country: tt.country, City: "Hong Kong"})
			snapshot := store.NewSnapshotFullWithEgress(prefixes, allocations, asns, store.NewHistoryIndex(), egress, store.Status{Version: "test"})
			svc := NewServiceWithOptions(snapshot, Options{
				Enricher: fakeEnricher{result: enrich.Result{
					TeamCymru: &enrich.CymruResult{ASN: tt.asn, Prefix: tt.prefix, Country: tt.country},
					BGPPath: &enrich.BGPPathAnalysis{
						OriginASN:         tt.asn,
						Prefix:            tt.prefix,
						ObservationCount:  8,
						DominantUpstream:  tt.upstreamASN,
						DominantUpstreams: []int{tt.upstreamASN},
						Paths: []enrich.BGPPathObservation{{
							Source:    "ripe_ris",
							RRC:       "RRC01",
							Location:  "London, United Kingdom",
							Prefix:    tt.prefix,
							OriginASN: tt.asn,
							ASPath:    tt.asPath,
						}},
					},
				}},
			})

			result := svc.Lookup(tt.ip)
			if !result.OK {
				t.Fatalf("expected success: %s", result.Error)
			}
			if result.Egress == nil {
				t.Fatalf("expected egress inference")
			}
			if result.Egress.DominantUpstream != tt.upstreamASN || result.Egress.UpstreamName != tt.upstreamName {
				t.Fatalf("unexpected egress upstream: %#v", result.Egress)
			}
			if tt.wantTransit {
				if result.Egress.Type != "TRANSIT" || result.Egress.LikelyCountry != "" || len(result.Egress.Facilities) != 0 || len(result.Egress.IXPs) != 0 {
					t.Fatalf("expected mobile egress to be transit-only, got %#v", result.Egress)
				}
			} else {
				if result.Egress.LikelyCountry != tt.country || !containsString(result.Egress.IXPs, tt.ixp) || !containsString(result.Egress.Facilities, tt.facility) {
					t.Fatalf("unexpected egress location: %#v", result.Egress)
				}
				if containsString(result.Egress.Facilities, "123.NET - DC1") && result.Egress.LikelyCountry == "US" {
					t.Fatalf("expected egress to prefer announced/location country, got %#v", result.Egress)
				}
			}
			if !containsEvidence(result.Egress.Evidence, tt.wantEvidence) {
				t.Fatalf("expected egress evidence %q, got %#v", tt.wantEvidence, result.Egress.Evidence)
			}
		})
	}
}

func TestServiceEgressPrefersAnnouncedCountryFacility(t *testing.T) {
	prefixes := store.NewPrefixIndex()
	if err := prefixes.Add("223.119.0.0/16", 58453, "caida"); err != nil {
		t.Fatal(err)
	}
	asns := store.NewASNIndex()
	asns.Upsert(store.ASNProfile{ASN: 58453, Name: "China Mobile International", Country: "HK", Registry: "apnic"})
	asns.Upsert(store.ASNProfile{ASN: 1299, Name: "Arelion (Twelve99)", Sources: []string{"peeringdb"}})
	allocations := store.NewAllocationIndex()
	if err := allocations.Add(store.AllocationRecord{Prefix: "223.119.0.0/16", Country: "HK", Registry: "apnic", Status: "allocated", Source: "rir:apnic"}); err != nil {
		t.Fatal(err)
	}
	egress := store.NewEgressIndex()
	egress.AddFacility(store.FacilityPresence{ASN: 1299, Name: "123.NET - DC1", Country: "US", City: "Southfield"})
	egress.AddFacility(store.FacilityPresence{ASN: 1299, Name: "MEGA-i", Country: "HK", City: "Hong Kong"})
	snapshot := store.NewSnapshotFullWithEgress(prefixes, allocations, asns, store.NewHistoryIndex(), egress, store.Status{Version: "test"})
	svc := NewServiceWithOptions(snapshot, Options{
		Enricher: fakeEnricher{result: enrich.Result{
			TeamCymru: &enrich.CymruResult{ASN: 58453, Prefix: "223.119.0.0/16", Country: "HK"},
			BGPPath: &enrich.BGPPathAnalysis{
				OriginASN:         58453,
				Prefix:            "223.119.0.0/16",
				ObservationCount:  8,
				DominantUpstream:  1299,
				DominantUpstreams: []int{1299},
			},
		}},
	})

	result := svc.Lookup("223.119.20.239")
	if result.Egress == nil {
		t.Fatal("expected egress inference")
	}
	if result.Egress.Type != "TRANSIT" || result.Egress.LikelyCountry != "" || len(result.Egress.Facilities) != 0 {
		t.Fatalf("expected mobile network egress to avoid concrete facility, got %#v", result.Egress)
	}
	if !containsEvidence(result.Egress.Evidence, "移动网络") {
		t.Fatalf("expected mobile egress suppression evidence, got %#v", result.Egress.Evidence)
	}
}

func TestServiceEgressDoesNotUseForeignTransitFacilityWhenTargetCountryIsKnown(t *testing.T) {
	prefixes := store.NewPrefixIndex()
	if err := prefixes.Add("14.144.0.0/12", 4134, "caida"); err != nil {
		t.Fatal(err)
	}
	asns := store.NewASNIndex()
	asns.Upsert(store.ASNProfile{ASN: 4134, Name: "China Telecom", Country: "CN", Registry: "apnic"})
	asns.Upsert(store.ASNProfile{ASN: 1299, Name: "Arelion (Twelve99)", Sources: []string{"peeringdb"}})
	allocations := store.NewAllocationIndex()
	if err := allocations.Add(store.AllocationRecord{Prefix: "14.144.0.0/12", Country: "CN", Registry: "apnic", Status: "allocated", Source: "rir:apnic"}); err != nil {
		t.Fatal(err)
	}
	egress := store.NewEgressIndex()
	egress.AddFacility(store.FacilityPresence{ASN: 1299, Name: "123.NET - DC1", Country: "US", City: "Southfield"})
	egress.AddFacility(store.FacilityPresence{ASN: 4134, Name: "CoreSite - Los Angeles", Country: "US", City: "Los Angeles"})
	snapshot := store.NewSnapshotFullWithEgress(prefixes, allocations, asns, store.NewHistoryIndex(), egress, store.Status{Version: "test"})
	svc := NewServiceWithOptions(snapshot, Options{
		Enricher: fakeEnricher{result: enrich.Result{
			TeamCymru: &enrich.CymruResult{ASN: 4134, Prefix: "14.144.0.0/12", Country: "CN"},
			BGPPath: &enrich.BGPPathAnalysis{
				OriginASN:         4134,
				Prefix:            "14.144.0.0/12",
				ObservationCount:  8,
				DominantUpstream:  1299,
				DominantUpstreams: []int{1299},
			},
		}},
	})

	result := svc.Lookup("14.145.60.215")
	if result.Egress == nil {
		t.Fatal("expected transit egress metadata")
	}
	if result.Egress.Type != "TRANSIT" || result.Egress.LikelyCountry != "" || len(result.Egress.Facilities) != 0 {
		t.Fatalf("expected foreign PeeringDB facilities to be suppressed, got %#v", result.Egress)
	}
	if !containsEvidence(result.Egress.Evidence, "未匹配目标国家") {
		t.Fatalf("expected mismatch evidence, got %#v", result.Egress.Evidence)
	}
}

func TestServiceEgressFallsBackToOriginPresenceMatchingTargetCountry(t *testing.T) {
	prefixes := store.NewPrefixIndex()
	if err := prefixes.Add("203.0.115.0/24", 64500, "caida"); err != nil {
		t.Fatal(err)
	}
	asns := store.NewASNIndex()
	asns.Upsert(store.ASNProfile{ASN: 64500, Name: "Example Origin", Country: "SG", Registry: "apnic"})
	asns.Upsert(store.ASNProfile{ASN: 64501, Name: "Example Transit", Country: "US", Sources: []string{"peeringdb"}})
	allocations := store.NewAllocationIndex()
	if err := allocations.Add(store.AllocationRecord{Prefix: "203.0.115.0/24", Country: "SG", Registry: "apnic", Status: "allocated", Source: "rir:apnic"}); err != nil {
		t.Fatal(err)
	}
	egress := store.NewEgressIndex()
	egress.AddFacility(store.FacilityPresence{ASN: 64501, Name: "Transit Los Angeles", Country: "US", City: "Los Angeles"})
	egress.AddFacility(store.FacilityPresence{ASN: 64500, Name: "Origin Singapore DC", Country: "SG", City: "Singapore"})
	snapshot := store.NewSnapshotFullWithEgress(prefixes, allocations, asns, store.NewHistoryIndex(), egress, store.Status{Version: "test"})
	svc := NewServiceWithOptions(snapshot, Options{
		Enricher: fakeEnricher{result: enrich.Result{
			TeamCymru: &enrich.CymruResult{ASN: 64500, Prefix: "203.0.115.0/24", Country: "SG"},
			BGPPath: &enrich.BGPPathAnalysis{
				OriginASN:         64500,
				Prefix:            "203.0.115.0/24",
				ObservationCount:  8,
				DominantUpstream:  64501,
				DominantUpstreams: []int{64501},
			},
		}},
	})

	result := svc.Lookup("203.0.115.10")
	if result.Egress == nil {
		t.Fatal("expected egress inference")
	}
	if result.Egress.DominantUpstream != 64501 || result.Egress.UpstreamName != "Example Transit" {
		t.Fatalf("expected dominant upstream to remain AS64501 Example Transit, got %#v", result.Egress)
	}
	if result.Egress.PresenceASN != 64500 || result.Egress.PresenceName != "Example Origin" {
		t.Fatalf("expected origin ASN presence to be selected, got %#v", result.Egress)
	}
	if result.Egress.Type != "IDC" || result.Egress.LikelyCountry != "SG" || !containsString(result.Egress.Facilities, "Origin Singapore DC") {
		t.Fatalf("expected Singapore origin facility, got %#v", result.Egress)
	}
	if containsString(result.Egress.Facilities, "Transit Los Angeles") {
		t.Fatalf("expected foreign transit facility to be ignored, got %#v", result.Egress)
	}
}

func TestServiceEgressAvoidsConcreteFacilityForPublicAnycastService(t *testing.T) {
	prefixes := store.NewPrefixIndex()
	if err := prefixes.Add("1.1.1.0/24", 13335, "caida"); err != nil {
		t.Fatal(err)
	}
	asns := store.NewASNIndex()
	asns.Upsert(store.ASNProfile{ASN: 13335, Name: "Cloudflare", Country: "AU", Registry: "apnic"})
	asns.Upsert(store.ASNProfile{ASN: 24482, Name: "SG.GS", Country: "AU", Sources: []string{"peeringdb"}})
	allocations := store.NewAllocationIndex()
	if err := allocations.Add(store.AllocationRecord{Prefix: "1.1.1.0/24", Country: "AU", Registry: "apnic", Status: "allocated", Source: "rir:apnic"}); err != nil {
		t.Fatal(err)
	}
	egress := store.NewEgressIndex()
	egress.AddFacility(store.FacilityPresence{ASN: 24482, Name: "Equinix PE2/PE3 - Perth", Country: "AU", City: "Perth"})
	snapshot := store.NewSnapshotFullWithEgress(prefixes, allocations, asns, store.NewHistoryIndex(), egress, store.Status{Version: "test"})
	svc := NewServiceWithOptions(snapshot, Options{
		Enricher: fakeEnricher{result: enrich.Result{
			PrimaryScene:      "DNS",
			PrimarySceneName:  "域名解析",
			InferredScene:     "IDC",
			InferredSceneName: "数据中心",
			TeamCymru:         &enrich.CymruResult{ASN: 13335, Prefix: "1.1.1.0/24", Country: "AU"},
			BGPPath: &enrich.BGPPathAnalysis{
				OriginASN:         13335,
				Prefix:            "1.1.1.0/24",
				ObservationCount:  8,
				DominantUpstream:  24482,
				DominantUpstreams: []int{24482},
			},
		}},
	})

	result := svc.Lookup("1.1.1.1")
	if result.Egress == nil {
		t.Fatal("expected egress metadata")
	}
	if result.Egress.Type != "ANYCAST" || len(result.Egress.Facilities) != 0 || result.Egress.LikelyCountry != "" {
		t.Fatalf("expected public DNS egress to avoid concrete facility, got %#v", result.Egress)
	}
	if !containsEvidence(result.Egress.Evidence, "Anycast") {
		t.Fatalf("expected anycast evidence, got %#v", result.Egress.Evidence)
	}
}

func TestServiceEgressUsesTransitForLowConfidenceCDN(t *testing.T) {
	prefixes := store.NewPrefixIndex()
	if err := prefixes.Add("148.66.51.0/24", 45753, "caida"); err != nil {
		t.Fatal(err)
	}
	asns := store.NewASNIndex()
	asns.Upsert(store.ASNProfile{ASN: 45753, Name: "Netsec Limited", Country: "HK", Registry: "apnic"})
	asns.Upsert(store.ASNProfile{ASN: 9744, Name: "XLC", Country: "HK", Sources: []string{"peeringdb"}})
	allocations := store.NewAllocationIndex()
	if err := allocations.Add(store.AllocationRecord{Prefix: "148.66.51.0/24", Country: "HK", Registry: "apnic", Status: "allocated", Source: "rir:apnic"}); err != nil {
		t.Fatal(err)
	}
	egress := store.NewEgressIndex()
	egress.AddIXP(store.IXPPresence{ASN: 9744, Name: "HKIX: HKIX Peering LAN", Country: "HK", City: "Hong Kong"})
	snapshot := store.NewSnapshotFullWithEgress(prefixes, allocations, asns, store.NewHistoryIndex(), egress, store.Status{Version: "test"})
	svc := NewServiceWithOptions(snapshot, Options{
		Enricher: fakeEnricher{result: enrich.Result{
			PrimaryScene:       "CDN",
			PrimarySceneName:   "内容分发",
			InferredScene:      "CDN",
			InferredSceneName:  "内容分发",
			InferredConfidence: 0.45,
			TeamCymru:          &enrich.CymruResult{ASN: 45753, Prefix: "148.66.51.0/24", Country: "HK"},
			BGPPath: &enrich.BGPPathAnalysis{
				OriginASN:         45753,
				Prefix:            "148.66.51.0/24",
				ObservationCount:  8,
				DominantUpstream:  9744,
				DominantUpstreams: []int{9744},
			},
		}},
	})

	result := svc.Lookup("148.66.51.30")
	if result.Egress == nil {
		t.Fatal("expected egress metadata")
	}
	if result.Egress.Type != "TRANSIT" || len(result.Egress.IXPs) != 0 || result.Egress.LikelyCountry != "" {
		t.Fatalf("expected low-confidence CDN to avoid concrete IXP/Anycast, got %#v", result.Egress)
	}
	if !containsEvidence(result.Egress.Evidence, "低置信度 CDN") {
		t.Fatalf("expected low-confidence evidence, got %#v", result.Egress.Evidence)
	}
}

func TestServiceEgressAvoidsTransitFacilityForResidentialScene(t *testing.T) {
	restore := setReverseDNSForTest(func(addr string) ([]string, error) {
		return []string{"dsl081-032-064.lax1.dsl.speakeasy.net."}, nil
	}, time.Hour)
	defer restore()

	prefixes := store.NewPrefixIndex()
	if err := prefixes.Add("64.81.32.0/21", 3257, "caida"); err != nil {
		t.Fatal(err)
	}
	asns := store.NewASNIndex()
	asns.Upsert(store.ASNProfile{ASN: 3257, Name: "GTT Communications (AS3257)", Country: "US", Registry: "arin"})
	asns.Upsert(store.ASNProfile{ASN: 1299, Name: "Arelion (Twelve99)", Sources: []string{"peeringdb"}})
	allocations := store.NewAllocationIndex()
	if err := allocations.Add(store.AllocationRecord{Prefix: "64.81.0.0/16", Country: "US", Registry: "arin", Status: "allocated", Source: "rir:arin"}); err != nil {
		t.Fatal(err)
	}
	egress := store.NewEgressIndex()
	egress.AddFacility(store.FacilityPresence{ASN: 1299, Name: "365 Data Centers Detroit (DT1)", Country: "US", City: "Southfield"})
	snapshot := store.NewSnapshotFullWithEgress(prefixes, allocations, asns, store.NewHistoryIndex(), egress, store.Status{Version: "test"})
	svc := NewServiceWithOptions(snapshot, Options{
		Enricher: fakeEnricher{result: enrich.Result{
			TeamCymru: &enrich.CymruResult{ASN: 3257, Prefix: "64.81.32.0/21", Country: "US"},
			BGPPath: &enrich.BGPPathAnalysis{
				OriginASN:         3257,
				Prefix:            "64.81.32.0/21",
				ObservationCount:  8,
				DominantUpstream:  1299,
				DominantUpstreams: []int{1299},
			},
		}},
	})

	result := svc.Lookup("64.81.32.64")
	if result.Scene != "DYN" || result.Egress == nil {
		t.Fatalf("expected residential egress metadata, got %#v", result)
	}
	if result.Egress.Type != "TRANSIT" || len(result.Egress.Facilities) != 0 || result.Egress.LikelyCountry != "" {
		t.Fatalf("expected residential transit facility to be suppressed, got %#v", result.Egress)
	}
	if !containsEvidence(result.Egress.Evidence, "家庭宽带") {
		t.Fatalf("expected residential suppression evidence, got %#v", result.Egress.Evidence)
	}
}

func TestServiceEgressAvoidsTransitFacilityForInstitutionAndMobileScenes(t *testing.T) {
	cases := []struct {
		name      string
		ip        string
		prefix    string
		asn       int
		profile   store.ASNProfile
		rdns      string
		sceneWord string
	}{
		{
			name:      "education",
			ip:        "18.9.22.69",
			prefix:    "18.9.0.0/16",
			asn:       3,
			profile:   store.ASNProfile{ASN: 3, Name: "Massachusetts Institute of Technology", Country: "US", Registry: "arin"},
			rdns:      "bitsy.mit.edu.",
			sceneWord: "机构",
		},
		{
			name:      "mobile",
			ip:        "70.192.0.1",
			prefix:    "70.192.0.0/10",
			asn:       6167,
			profile:   store.ASNProfile{ASN: 6167, Name: "Cellco Partnership DBA Verizon Wireless", Country: "US", Registry: "arin"},
			rdns:      "1.sub-70-192-0.myvzw.com.",
			sceneWord: "移动网络",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			restore := setReverseDNSForTest(func(addr string) ([]string, error) {
				return []string{tc.rdns}, nil
			}, time.Hour)
			defer restore()

			prefixes := store.NewPrefixIndex()
			if err := prefixes.Add(tc.prefix, tc.asn, "caida"); err != nil {
				t.Fatal(err)
			}
			asns := store.NewASNIndex()
			asns.Upsert(tc.profile)
			asns.Upsert(store.ASNProfile{ASN: 3356, Name: "Lumen", Sources: []string{"peeringdb"}})
			allocations := store.NewAllocationIndex()
			if err := allocations.Add(store.AllocationRecord{Prefix: tc.prefix, Country: "US", Registry: "arin", Status: "allocated", Source: "rir:arin"}); err != nil {
				t.Fatal(err)
			}
			egress := store.NewEgressIndex()
			egress.AddFacility(store.FacilityPresence{ASN: 3356, Name: "Equinix CH1", Country: "US", City: "Chicago"})
			snapshot := store.NewSnapshotFullWithEgress(prefixes, allocations, asns, store.NewHistoryIndex(), egress, store.Status{Version: "test"})
			svc := NewServiceWithOptions(snapshot, Options{
				Enricher: fakeEnricher{result: enrich.Result{
					TeamCymru: &enrich.CymruResult{ASN: tc.asn, Prefix: tc.prefix, Country: "US"},
					BGPPath: &enrich.BGPPathAnalysis{
						OriginASN:         tc.asn,
						Prefix:            tc.prefix,
						ObservationCount:  8,
						DominantUpstream:  3356,
						DominantUpstreams: []int{3356},
					},
				}},
			})

			result := svc.Lookup(tc.ip)
			if result.Egress == nil {
				t.Fatal("expected egress metadata")
			}
			if result.Egress.Type != "TRANSIT" || len(result.Egress.Facilities) != 0 || result.Egress.LikelyCountry != "" {
				t.Fatalf("expected %s egress facility to be suppressed, got %#v", tc.name, result.Egress)
			}
			if !containsEvidence(result.Egress.Evidence, tc.sceneWord) {
				t.Fatalf("expected suppression evidence to mention %s, got %#v", tc.sceneWord, result.Egress.Evidence)
			}
		})
	}
}

func TestServiceKeepsResidentialRDNSButReferencesEnhancement(t *testing.T) {
	restore := setReverseDNSForTest(func(addr string) ([]string, error) {
		return []string{"dsl081-032-032.lax1.dsl.speakeasy.net."}, nil
	}, time.Hour)
	defer restore()

	prefixes := store.NewPrefixIndex()
	if err := prefixes.Add("64.81.32.0/21", 3257, "caida"); err != nil {
		t.Fatal(err)
	}
	asns := store.NewASNIndex()
	asns.Upsert(store.ASNProfile{ASN: 3257, Name: "GTT Communications (AS3257)", Country: "US", Registry: "arin"})
	asns.Upsert(store.ASNProfile{ASN: 1299, Name: "Arelion (Twelve99)", Sources: []string{"peeringdb"}})
	allocations := store.NewAllocationIndex()
	if err := allocations.Add(store.AllocationRecord{Prefix: "64.81.0.0/16", Country: "US", Registry: "arin", Status: "allocated", Source: "rir:arin"}); err != nil {
		t.Fatal(err)
	}
	egress := store.NewEgressIndex()
	egress.AddFacility(store.FacilityPresence{ASN: 1299, Name: "365 Data Centers Detroit (DT1)", Country: "US", City: "Southfield"})
	snapshot := store.NewSnapshotFullWithEgress(prefixes, allocations, asns, store.NewHistoryIndex(), egress, store.Status{Version: "test"})
	svc := NewServiceWithOptions(snapshot, Options{
		Enricher: fakeEnricher{result: enrich.Result{
			NetName:   "GTT",
			TeamCymru: &enrich.CymruResult{ASN: 3257, Prefix: "64.81.32.0/21", Country: "US"},
			BGPPath: &enrich.BGPPathAnalysis{
				OriginASN:         3257,
				Prefix:            "64.81.32.0/21",
				ObservationCount:  8,
				DominantUpstream:  1299,
				DominantUpstreams: []int{1299},
			},
		}},
	})

	result := svc.Lookup("64.81.32.32")
	if !result.OK {
		t.Fatalf("expected success: %s", result.Error)
	}
	if result.Scene != "DYN" || result.InferredScene != "DYN" {
		t.Fatalf("expected DSL evidence to keep DYN usage, got %#v", result)
	}
	if result.InferredSource != "主场景规则 + 在线增强参考" {
		t.Fatalf("expected enhancement-aware inferred source, got %q", result.InferredSource)
	}
	if !containsEvidence(result.Evidence, "在线增强参考") {
		t.Fatalf("expected enhancement reference evidence, got %#v", result.Evidence)
	}
}

func TestServiceUsesEgressForLowConfidenceUsage(t *testing.T) {
	prefixes := store.NewPrefixIndex()
	if err := prefixes.Add("203.0.114.0/24", 64500, "caida"); err != nil {
		t.Fatal(err)
	}
	asns := store.NewASNIndex()
	asns.Upsert(store.ASNProfile{ASN: 64500, Name: "Example Network", Country: "US", Registry: "arin"})
	asns.Upsert(store.ASNProfile{ASN: 64501, Name: "Example Transit", Sources: []string{"peeringdb"}})
	allocations := store.NewAllocationIndex()
	if err := allocations.Add(store.AllocationRecord{Prefix: "203.0.114.0/24", Country: "US", Registry: "arin", Status: "allocated", Source: "rir:arin"}); err != nil {
		t.Fatal(err)
	}
	egress := store.NewEgressIndex()
	egress.AddFacility(store.FacilityPresence{ASN: 64501, Name: "Example DC", Country: "US", City: "Los Angeles"})
	snapshot := store.NewSnapshotFullWithEgress(prefixes, allocations, asns, store.NewHistoryIndex(), egress, store.Status{Version: "test"})
	svc := NewServiceWithOptions(snapshot, Options{
		Enricher: fakeEnricher{result: enrich.Result{
			TeamCymru: &enrich.CymruResult{ASN: 64500, Prefix: "203.0.114.0/24", Country: "US"},
			BGPPath: &enrich.BGPPathAnalysis{
				OriginASN:         64500,
				Prefix:            "203.0.114.0/24",
				ObservationCount:  5,
				DominantUpstream:  64501,
				DominantUpstreams: []int{64501},
			},
		}},
	})

	result := svc.Lookup("203.0.114.10")
	if !result.OK {
		t.Fatalf("expected success: %s", result.Error)
	}
	if result.Scene != "IDC" || result.InferredScene != "IDC" {
		t.Fatalf("expected low-confidence usage to be promoted by egress, got %#v", result)
	}
	if result.InferredSource != "机房/出口推断" {
		t.Fatalf("expected egress inferred source, got %q", result.InferredSource)
	}
}

func TestServiceAddsRoutingSecurityAndDataQuality(t *testing.T) {
	prefixes := store.NewPrefixIndex()
	if err := prefixes.Add("64.81.32.0/21", 3257, "caida"); err != nil {
		t.Fatal(err)
	}
	asns := store.NewASNIndex()
	asns.Upsert(store.ASNProfile{ASN: 3257, Name: "GTT Communications", Country: "US", Registry: "arin"})
	allocations := store.NewAllocationIndex()
	if err := allocations.Add(store.AllocationRecord{Prefix: "64.81.0.0/16", Country: "US", Registry: "arin", Status: "allocated", Source: "rir:arin"}); err != nil {
		t.Fatal(err)
	}
	reliability := store.NewReliabilityIndex()
	if err := reliability.RPKI.Add(store.RPKIRecord{Prefix: "64.81.0.0/16", MaxLength: 24, ASN: 3257, Source: "routinator"}); err != nil {
		t.Fatal(err)
	}
	if err := reliability.IRR.Add(store.IRRRouteRecord{Prefix: "64.81.32.0/21", ASN: 3257, Source: "RADB", Registry: "radb"}); err != nil {
		t.Fatal(err)
	}
	if err := reliability.BGP.Add(store.BGPObservationRecord{Prefix: "64.81.32.0/21", OriginASN: 3257, Source: "routeviews", Collector: "rv2", ObservationCount: 8, DominantUpstream: 1299}); err != nil {
		t.Fatal(err)
	}
	if err := reliability.BGP.Add(store.BGPObservationRecord{Prefix: "64.81.32.0/21", OriginASN: 3257, Source: "ripe_ris", Collector: "rrc00", ObservationCount: 7, DominantUpstream: 2914}); err != nil {
		t.Fatal(err)
	}
	snapshot := store.NewSnapshotFullWithReliability(prefixes, allocations, asns, store.NewHistoryIndex(), store.NewEgressIndex(), reliability, store.Status{Version: "test"})
	svc := NewService(snapshot)

	result := svc.Lookup("64.81.32.32")
	if !result.OK {
		t.Fatalf("expected success: %s", result.Error)
	}
	if result.RoutingSecurity == nil || result.RoutingSecurity.RPKI != "valid" || !result.RoutingSecurity.IRRMatched || result.RoutingSecurity.MOAS {
		t.Fatalf("expected valid routing security, got %#v", result.RoutingSecurity)
	}
	if result.DataQuality == nil || result.DataQuality.Level != "high" || result.DataQuality.Score < 0.8 {
		t.Fatalf("expected high data quality, got %#v", result.DataQuality)
	}
	if len(result.SourceVotes) == 0 {
		t.Fatalf("expected source votes, got %#v", result.SourceVotes)
	}
	if !containsEvidence(result.Evidence, "RPKI: valid") || !containsEvidence(result.Evidence, "IRR: route object matched") {
		t.Fatalf("expected reliability evidence, got %#v", result.Evidence)
	}
}

func TestServiceFlagsRoutingReliabilityConflicts(t *testing.T) {
	prefixes := store.NewPrefixIndex()
	if err := prefixes.Add("203.0.114.0/24", 64500, "caida"); err != nil {
		t.Fatal(err)
	}
	asns := store.NewASNIndex()
	asns.Upsert(store.ASNProfile{ASN: 64500, Name: "Example Network", Country: "US", Registry: "arin"})
	reliability := store.NewReliabilityIndex()
	if err := reliability.RPKI.Add(store.RPKIRecord{Prefix: "203.0.114.0/24", MaxLength: 24, ASN: 64496, Source: "routinator"}); err != nil {
		t.Fatal(err)
	}
	if err := reliability.IRR.Add(store.IRRRouteRecord{Prefix: "203.0.114.0/24", ASN: 64496, Source: "TEST", Registry: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := reliability.BGP.Add(store.BGPObservationRecord{Prefix: "203.0.114.0/24", OriginASN: 64500, Source: "routeviews", Collector: "rv2", ObservationCount: 2}); err != nil {
		t.Fatal(err)
	}
	if err := reliability.BGP.Add(store.BGPObservationRecord{Prefix: "203.0.114.0/24", OriginASN: 64496, Source: "ripe_ris", Collector: "rrc00", ObservationCount: 8}); err != nil {
		t.Fatal(err)
	}
	snapshot := store.NewSnapshotFullWithReliability(prefixes, store.NewAllocationIndex(), asns, store.NewHistoryIndex(), store.NewEgressIndex(), reliability, store.Status{Version: "test"})
	svc := NewService(snapshot)

	result := svc.Lookup("203.0.114.10")
	if result.RoutingSecurity == nil || result.RoutingSecurity.RPKI != "invalid" || !result.RoutingSecurity.MOAS {
		t.Fatalf("expected invalid RPKI and MOAS, got %#v", result.RoutingSecurity)
	}
	if result.DataQuality == nil || result.DataQuality.Level == "high" {
		t.Fatalf("expected degraded data quality, got %#v", result.DataQuality)
	}
	if len(result.Warnings) == 0 {
		t.Fatalf("expected warnings, got %#v", result.Warnings)
	}
}

func TestServiceOmitsRoutingSecurityWithoutReliabilityData(t *testing.T) {
	prefixes := store.NewPrefixIndex()
	if err := prefixes.Add("8.8.8.0/24", 15169, "caida"); err != nil {
		t.Fatal(err)
	}
	asns := store.NewASNIndex()
	asns.Upsert(store.ASNProfile{ASN: 15169, Name: "Google LLC"})
	svc := NewService(store.NewSnapshot(prefixes, asns, store.Status{Version: "test"}))

	result := svc.Lookup("8.8.8.8")
	if result.RoutingSecurity != nil {
		t.Fatalf("expected routing security to be omitted without reliability data, got %#v", result.RoutingSecurity)
	}
	if result.DataQuality == nil {
		t.Fatal("expected data quality to remain available")
	}
}

func TestServiceOmitsGeoConsistencyWhenOnlineEvidenceIsPending(t *testing.T) {
	prefixes := store.NewPrefixIndex()
	if err := prefixes.Add("52.88.0.0/13", 16509, "caida"); err != nil {
		t.Fatal(err)
	}
	asns := store.NewASNIndex()
	asns.Upsert(store.ASNProfile{ASN: 16509, Name: "Amazon.com", Country: "US", Registry: "arin"})
	allocations := store.NewAllocationIndex()
	if err := allocations.Add(store.AllocationRecord{Prefix: "52.88.0.0/13", Country: "US", Registry: "arin", Status: "allocated", Source: "rir:arin"}); err != nil {
		t.Fatal(err)
	}
	snapshot := store.NewSnapshotFull(prefixes, allocations, asns, store.NewHistoryIndex(), store.Status{Version: "test"})
	svc := NewServiceWithOptions(snapshot, Options{
		Enricher: fakeEnricher{result: enrich.Result{
			RefreshQueued:     true,
			RefreshInProgress: true,
			Evidence:          []string{"在线增强缓存未命中，已后台刷新"},
		}},
		GeoLocator: fakeGeoLocator{ok: true, location: geo.Location{
			Country:     "美国",
			Province:    "Washington",
			City:        "Seattle",
			ISP:         "Amazon",
			CountryCode: "US",
		}},
	})

	result := svc.LookupWithOptions(context.Background(), "52.95.110.1", LookupOptions{IncludeLocation: true})
	if !result.OK {
		t.Fatalf("expected success: %s", result.Error)
	}
	if result.GeoConsistency != nil {
		t.Fatalf("expected geo consistency to wait for online evidence, got %#v", result.GeoConsistency)
	}
}

func TestLocationCountryCodeHandlesHongKongProvince(t *testing.T) {
	code := locationCountryCode(&geo.Location{Country: "中国", Province: "香港", City: "香港", CountryCode: "CN"})
	if code != "HK" {
		t.Fatalf("expected Hong Kong country code, got %q", code)
	}
}

func TestInferredUsagePrefersHighConfidenceMainScene(t *testing.T) {
	scene, name, confidence, source := inferredUsage(
		classify.Result{Scene: "DNS", SceneName: "域名解析", Confidence: 0.95},
		&enrich.Result{InferredScene: "DYN", InferredSceneName: "家庭宽带", InferredConfidence: 0.74},
		nil,
	)
	if scene != "DNS" || name != "域名解析" || confidence != 0.95 || source != "主场景规则" {
		t.Fatalf("expected high-confidence main scene, got %s %s %f %s", scene, name, confidence, source)
	}
}

func TestIPLookupPrefersAllocationCountryAndRegistry(t *testing.T) {
	prefixes := store.NewPrefixIndex()
	if err := prefixes.Add("114.114.112.0/21", 21859, "caida"); err != nil {
		t.Fatal(err)
	}
	asns := store.NewASNIndex()
	asns.Upsert(store.ASNProfile{ASN: 21859, Name: "Zenlayer Inc", Country: "US", Registry: "arin"})
	allocations := store.NewAllocationIndex()
	if err := allocations.Add(store.AllocationRecord{Prefix: "114.114.0.0/15", Country: "CN", Registry: "apnic", Status: "allocated", Source: "rir:apnic"}); err != nil {
		t.Fatal(err)
	}
	snapshot := store.NewSnapshotFull(prefixes, allocations, asns, store.NewHistoryIndex(), store.Status{Version: "test"})

	result := NewService(snapshot).Lookup("114.114.114.114")
	if !result.OK {
		t.Fatalf("expected success: %s", result.Error)
	}
	if result.Country != "CN" || result.Registry != "apnic" {
		t.Fatalf("expected IP allocation country/registry, got %s / %s", result.Country, result.Registry)
	}
}

func TestServiceLookupASN(t *testing.T) {
	prefixes := store.NewPrefixIndex()
	if err := prefixes.Add("8.8.8.0/24", 15169, "test"); err != nil {
		t.Fatal(err)
	}
	asns := store.NewASNIndex()
	asns.Upsert(store.ASNProfile{ASN: 15169, Name: "Google LLC"})
	svc := NewService(store.NewSnapshot(prefixes, asns, store.Status{Version: "test"}))

	result := svc.Lookup("AS15169")
	if !result.OK {
		t.Fatalf("expected success: %s", result.Error)
	}
	if result.QueryType != "asn" || result.ASN != 15169 {
		t.Fatalf("unexpected lookup result: %#v", result)
	}
	if len(result.Prefixes) != 1 || result.Prefixes[0] != "8.8.8.0/24" {
		t.Fatalf("unexpected prefixes: %#v", result.Prefixes)
	}
}

func TestServiceReturnsBogonBeforeDatabaseLookup(t *testing.T) {
	svc := NewService(store.NewSnapshot(store.NewPrefixIndex(), store.NewASNIndex(), store.Status{Version: "test"}))
	result := svc.Lookup("10.0.0.1")
	if !result.OK || result.Scene != "BOGON" {
		t.Fatalf("expected BOGON result, got %#v", result)
	}
}

func TestServiceFallsBackToRIRAllocationWhenNoASNIsAnnounced(t *testing.T) {
	allocations := store.NewAllocationIndex()
	if err := allocations.Add(store.AllocationRecord{Prefix: "1.1.10.0/23", Country: "CN", Registry: "apnic", Status: "allocated", Source: "rir:apnic"}); err != nil {
		t.Fatal(err)
	}
	snapshot := store.NewSnapshot(store.NewPrefixIndex(), store.NewASNIndex(), store.Status{Version: "test"})
	snapshot.Allocations = allocations

	svc := NewService(snapshot)
	result := svc.Lookup("1.1.10.23")
	if !result.OK {
		t.Fatalf("expected allocation fallback success: %s", result.Error)
	}
	if result.ASN != 0 {
		t.Fatalf("expected no ASN, got %d", result.ASN)
	}
	if result.MatchedPrefix != "1.1.10.0/23" || result.Country != "CN" || result.Registry != "apnic" {
		t.Fatalf("unexpected allocation fallback result: %#v", result)
	}
	if result.RoutingStatus != "not_announced" {
		t.Fatalf("expected not_announced routing status, got %q", result.RoutingStatus)
	}
	if len(result.Prefixes) != 1 || result.Prefixes[0] != "1.1.10.0/23" {
		t.Fatalf("expected allocation prefix as related prefix, got %#v", result.Prefixes)
	}
}

func TestServiceAppliesOfflineRuleForUnannouncedAllocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "services.json")
	body := []byte(`{"rules":[{"id":"blocklist","name":"Test Blocklist","scene":"BLOCKLIST","prefixes":["45.45.46.1/32"]}]}`)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := classify.LoadServiceRules(path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = classify.LoadServiceRules("")
	})

	allocations := store.NewAllocationIndex()
	if err := allocations.Add(store.AllocationRecord{Prefix: "45.45.46.0/24", Country: "US", Registry: "arin", Status: "allocated", Source: "rir:arin"}); err != nil {
		t.Fatal(err)
	}
	snapshot := store.NewSnapshot(store.NewPrefixIndex(), store.NewASNIndex(), store.Status{Version: "test"})
	snapshot.Allocations = allocations

	result := NewService(snapshot).Lookup("45.45.46.1")
	if !result.OK {
		t.Fatalf("expected allocation fallback success: %s", result.Error)
	}
	if result.Scene != "BLOCKLIST" || result.SceneName != "风险名单" {
		t.Fatalf("expected offline service rule to classify unannounced IP, got %#v", result)
	}
	if result.RoutingStatus != "not_announced" {
		t.Fatalf("expected not_announced routing status, got %q", result.RoutingStatus)
	}
	if !containsEvidence(result.Evidence, "Test Blocklist") {
		t.Fatalf("expected blocklist evidence, got %#v", result.Evidence)
	}
}

func TestServiceUsesEnrichmentForUnannouncedAllocation(t *testing.T) {
	allocations := store.NewAllocationIndex()
	if err := allocations.Add(store.AllocationRecord{Prefix: "1.1.10.0/23", Country: "CN", Registry: "apnic", Status: "allocated", Source: "rir:apnic"}); err != nil {
		t.Fatal(err)
	}
	snapshot := store.NewSnapshot(store.NewPrefixIndex(), store.NewASNIndex(), store.Status{Version: "test"})
	snapshot.Allocations = allocations

	svc := NewServiceWithOptions(snapshot, Options{
		Enricher: fakeEnricher{result: enrich.Result{
			PrimaryScene:       "UNROUTED",
			PrimarySceneName:   "已分配未宣告",
			InferredScene:      "DYN",
			InferredSceneName:  "家庭宽带",
			InferredConfidence: 0.74,
			Organization:       "China Telecom",
			NetName:            "CHINANET-GD",
			Evidence: []string{
				"Team Cymru 当前无 ASN",
				"RIPEstat 当前未宣告",
				"RDAP: CHINANET-GD / China Telecom",
				"WHOIS: service provider",
			},
		}},
	})
	result := svc.Lookup("1.1.10.23")
	if !result.OK {
		t.Fatalf("expected success: %s", result.Error)
	}
	if result.Scene != "UNROUTED" || result.InferredScene != "DYN" || result.Company != "China Telecom" {
		t.Fatalf("unexpected enriched result: %#v", result)
	}
	if len(result.Evidence) < 4 {
		t.Fatalf("expected merged evidence, got %#v", result.Evidence)
	}
}

func TestServiceUsesHistoricalBGPForUnannouncedAllocation(t *testing.T) {
	allocations := store.NewAllocationIndex()
	if err := allocations.Add(store.AllocationRecord{Prefix: "1.1.10.0/23", Country: "CN", Registry: "apnic", Status: "allocated", Source: "rir:apnic"}); err != nil {
		t.Fatal(err)
	}
	historyPrefixes := store.NewPrefixIndex()
	if err := historyPrefixes.Add("1.1.10.0/23", 4134, "caida_history"); err != nil {
		t.Fatal(err)
	}
	history := store.NewHistoryIndex()
	history.AddSnapshot("ipv4-routeviews-rv2-20260518-1200", historyPrefixes)

	snapshot := store.NewSnapshotFull(store.NewPrefixIndex(), allocations, store.NewASNIndex(), history, store.Status{Version: "test"})
	svc := NewService(snapshot)
	result := svc.Lookup("1.1.10.23")
	if !result.OK {
		t.Fatalf("expected success: %s", result.Error)
	}
	if len(result.History) != 1 || result.History[0].ASN != 4134 {
		t.Fatalf("expected historical BGP hit, got %#v", result.History)
	}
	if !containsEvidence(result.Evidence, "历史 BGP 样本曾命中 AS4134") {
		t.Fatalf("expected historical BGP evidence, got %#v", result.Evidence)
	}
}

func TestServiceUsesAIOnlyForLowConfidenceResult(t *testing.T) {
	prefixes := store.NewPrefixIndex()
	if err := prefixes.Add("203.0.114.0/24", 64500, "test"); err != nil {
		t.Fatal(err)
	}
	asns := store.NewASNIndex()
	asns.Upsert(store.ASNProfile{ASN: 64500, Name: "Example Holder"})
	advisor := &fakeAdvisor{decision: ai.Decision{Scene: "ORG", SceneName: "组织机构", Confidence: 0.82, Reason: "组织名显示为基金会"}}
	svc := NewServiceWithOptions(store.NewSnapshot(prefixes, asns, store.Status{Version: "test"}), Options{
		AIAdvisor:          advisor,
		AIConfidenceCutoff: 0.7,
	})

	result := svc.Lookup("203.0.114.10")
	if !result.OK {
		t.Fatalf("expected success: %s", result.Error)
	}
	if advisor.calls != 1 {
		t.Fatalf("expected one AI call, got %d", advisor.calls)
	}
	if result.Scene != "ORG" || result.AI == nil || !result.AI.Used {
		t.Fatalf("expected AI scene result, got %#v", result)
	}
}

func containsEvidence(values []string, needle string) bool {
	for _, value := range values {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func TestServiceSkipsAIForHighConfidenceResult(t *testing.T) {
	prefixes := store.NewPrefixIndex()
	if err := prefixes.Add("8.8.8.0/24", 15169, "test"); err != nil {
		t.Fatal(err)
	}
	asns := store.NewASNIndex()
	asns.Upsert(store.ASNProfile{ASN: 15169, Name: "Google LLC", InfoType: "Content"})
	advisor := &fakeAdvisor{decision: ai.Decision{Scene: "IDC", SceneName: "数据中心", Confidence: 0.8}}
	svc := NewServiceWithOptions(store.NewSnapshot(prefixes, asns, store.Status{Version: "test"}), Options{
		AIAdvisor:          advisor,
		AIConfidenceCutoff: 0.7,
	})

	result := svc.Lookup("8.8.8.8")
	if !result.OK {
		t.Fatalf("expected success: %s", result.Error)
	}
	if advisor.calls != 0 {
		t.Fatalf("expected AI to be skipped for high confidence result, got %d calls", advisor.calls)
	}
	if result.AI != nil {
		t.Fatalf("expected no AI metadata, got %#v", result.AI)
	}
}
