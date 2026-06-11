package store

import "testing"

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
