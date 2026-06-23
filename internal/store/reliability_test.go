package store

import (
	"path/filepath"
	"testing"
)

func TestRPKIIndexValidatesRouteOrigin(t *testing.T) {
	idx := NewRPKIIndex()
	if err := idx.Add(RPKIRecord{Prefix: "64.81.0.0/16", MaxLength: 24, ASN: 3257, Source: "routinator"}); err != nil {
		t.Fatal(err)
	}

	valid := idx.Validate("64.81.32.0/21", 3257)
	if valid.Status != "valid" || valid.MatchedPrefix != "64.81.0.0/16" || valid.MaxLength != 24 {
		t.Fatalf("expected valid RPKI result, got %#v", valid)
	}

	invalidASN := idx.Validate("64.81.32.0/21", 64500)
	if invalidASN.Status != "invalid" {
		t.Fatalf("expected invalid RPKI result for wrong ASN, got %#v", invalidASN)
	}

	invalidLength := idx.Validate("64.81.32.0/25", 3257)
	if invalidLength.Status != "invalid" {
		t.Fatalf("expected invalid RPKI result for too-specific prefix, got %#v", invalidLength)
	}

	notFound := idx.Validate("203.0.114.0/24", 64500)
	if notFound.Status != "not_found" {
		t.Fatalf("expected not_found RPKI result, got %#v", notFound)
	}
}

func TestRPKIIndexFinalizeUsesFlatEntries(t *testing.T) {
	idx := NewRPKIIndex()
	if err := idx.Add(RPKIRecord{Prefix: "64.81.0.0/16", MaxLength: 24, ASN: 3257, Source: "routinator"}); err != nil {
		t.Fatal(err)
	}

	idx.Finalize()

	if idx.buildV4[16] != nil {
		t.Fatalf("expected finalized RPKI index to release IPv4 build map")
	}
	if len(idx.v4[16]) != 1 || len(idx.v4Records[16]) != 1 {
		t.Fatalf("expected flat RPKI entry, entries=%d records=%d", len(idx.v4[16]), len(idx.v4Records[16]))
	}
	valid := idx.Validate("64.81.32.0/21", 3257)
	if valid.Status != "valid" || valid.MatchedPrefix != "64.81.0.0/16" || valid.Source != "routinator" {
		t.Fatalf("unexpected finalized RPKI validation: %#v", valid)
	}
}

func TestIRRIndexReportsMatchAndConflicts(t *testing.T) {
	idx := NewIRRIndex()
	if err := idx.Add(IRRRouteRecord{Prefix: "64.81.32.0/21", ASN: 3257, Source: "RADB", Registry: "radb"}); err != nil {
		t.Fatal(err)
	}
	if err := idx.Add(IRRRouteRecord{Prefix: "64.81.32.0/21", ASN: 64500, Source: "TEST", Registry: "test"}); err != nil {
		t.Fatal(err)
	}

	matched := idx.Validate("64.81.32.0/21", 3257)
	if !matched.Matched || !matched.Conflict || len(matched.OriginASNs) != 2 {
		t.Fatalf("expected matched route with conflict visibility, got %#v", matched)
	}

	missing := idx.Validate("203.0.114.0/24", 64500)
	if missing.Matched || missing.Conflict {
		t.Fatalf("expected missing route object, got %#v", missing)
	}
}

func TestIRRIndexFinalizeUsesFlatEntries(t *testing.T) {
	idx := NewIRRIndex()
	if err := idx.Add(IRRRouteRecord{Prefix: "64.81.32.0/21", ASN: 3257, Source: "RADB", Registry: "radb"}); err != nil {
		t.Fatal(err)
	}
	if err := idx.Add(IRRRouteRecord{Prefix: "64.81.32.0/21", ASN: 64500, Source: "TEST", Registry: "test"}); err != nil {
		t.Fatal(err)
	}

	idx.Finalize()

	if idx.buildV4[21] != nil {
		t.Fatalf("expected finalized IRR index to release IPv4 build map")
	}
	if len(idx.v4[21]) != 1 || len(idx.v4Records[21]) != 2 {
		t.Fatalf("expected flat IRR entry, entries=%d records=%d", len(idx.v4[21]), len(idx.v4Records[21]))
	}
	result := idx.Validate("64.81.32.0/21", 3257)
	if !result.Matched || !result.Conflict || result.Source != "RADB" || result.Registry != "radb" {
		t.Fatalf("unexpected finalized IRR validation: %#v", result)
	}
}

func TestBGPObservationIndexSummarizesOriginAgreement(t *testing.T) {
	idx := NewBGPObservationIndex()
	if err := idx.Add(BGPObservationRecord{Prefix: "64.81.32.0/21", OriginASN: 3257, Source: "routeviews", Collector: "rv2", ObservationCount: 8, DominantUpstream: 1299}); err != nil {
		t.Fatal(err)
	}
	if err := idx.Add(BGPObservationRecord{Prefix: "64.81.32.0/21", OriginASN: 3257, Source: "ripe_ris", Collector: "rrc00", ObservationCount: 7, DominantUpstream: 2914}); err != nil {
		t.Fatal(err)
	}
	if err := idx.Add(BGPObservationRecord{Prefix: "64.81.32.0/21", OriginASN: 64500, Source: "routeviews", Collector: "rv6", ObservationCount: 1}); err != nil {
		t.Fatal(err)
	}

	summary := idx.Summarize("64.81.32.32", 3257)
	if summary.Prefix != "64.81.32.0/21" || summary.Visibility != 16 || summary.OriginAgreement < 0.93 || !summary.MOAS {
		t.Fatalf("unexpected BGP summary: %#v", summary)
	}
	if len(summary.Origins) != 2 || summary.Origins[0].ASN != 3257 || summary.Origins[0].Count != 15 {
		t.Fatalf("unexpected origin counts: %#v", summary.Origins)
	}
}

func TestBGPObservationIndexHandlesIPv4MappedIPv6Prefix(t *testing.T) {
	idx := NewBGPObservationIndex()
	if err := idx.Add(BGPObservationRecord{Prefix: "::ffff:172.16.16.16/128", OriginASN: 16637, Source: "routeviews", Collector: "rv2", ObservationCount: 1}); err != nil {
		t.Fatal(err)
	}

	summary := idx.Summarize("172.16.16.16", 16637)
	if summary.Prefix != "172.16.16.16/32" || summary.Visibility != 1 || summary.Origins[0].ASN != 16637 {
		t.Fatalf("unexpected mapped IPv4 summary: %#v", summary)
	}
}

func TestBGPObservationIndexRoundTripsCompactFile(t *testing.T) {
	idx := NewBGPObservationIndex()
	if err := idx.Add(BGPObservationRecord{Prefix: "64.81.32.0/21", OriginASN: 3257, Source: "routeviews", Collector: "routeviews:2", ObservationCount: 8, DominantUpstream: 1299}); err != nil {
		t.Fatal(err)
	}
	if err := idx.Add(BGPObservationRecord{Prefix: "64.81.32.0/21", OriginASN: 64500, Source: "ripe_ris", Collector: "ripe_ris:1", ObservationCount: 1}); err != nil {
		t.Fatal(err)
	}
	if err := idx.Add(BGPObservationRecord{Prefix: "2001:db8::/32", OriginASN: 64496, Source: "ripe_ris", Collector: "ripe_ris:3", ObservationCount: 3, DominantUpstream: 6939}); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "bgp-index.bin")
	if err := SaveBGPObservationIndex(path, idx); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadBGPObservationIndex(path)
	if err != nil {
		t.Fatal(err)
	}

	summary := loaded.Summarize("64.81.32.32", 3257)
	if summary.Visibility != 9 || !summary.MOAS || len(summary.Origins) != 2 || summary.DominantUpstreams[0].ASN != 1299 {
		t.Fatalf("unexpected loaded IPv4 summary: %#v", summary)
	}
	v6 := loaded.Summarize("2001:db8::1", 64496)
	if v6.Visibility != 3 || v6.Prefix != "2001:db8::/32" || v6.DominantUpstreams[0].ASN != 6939 {
		t.Fatalf("unexpected loaded IPv6 summary: %#v", v6)
	}
}

func TestBGPObservationIndexFinalizeUsesFlatRecords(t *testing.T) {
	idx := NewBGPObservationIndex()
	if err := idx.Add(BGPObservationRecord{Prefix: "64.81.32.0/21", OriginASN: 3257, Source: "routeviews", Collector: "routeviews:2", ObservationCount: 8}); err != nil {
		t.Fatal(err)
	}
	if err := idx.Add(BGPObservationRecord{Prefix: "64.81.32.0/21", OriginASN: 64500, Source: "ripe_ris", Collector: "ripe_ris:1", ObservationCount: 1}); err != nil {
		t.Fatal(err)
	}

	idx.Finalize()

	if idx.buildV4[21] != nil {
		t.Fatalf("expected finalized index to release IPv4 build map")
	}
	if len(idx.v4[21]) != 1 || len(idx.v4Records[21]) != 2 {
		t.Fatalf("expected one flat IPv4 entry with two records, entries=%d records=%d", len(idx.v4[21]), len(idx.v4Records[21]))
	}
	summary := idx.Summarize("64.81.32.64", 3257)
	if summary.Visibility != 9 || !summary.MOAS {
		t.Fatalf("unexpected finalized summary: %#v", summary)
	}
}
