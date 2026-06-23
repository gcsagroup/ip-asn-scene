package store

import (
	"net/netip"
	"testing"
)

func TestPrefixIndexUsesLongestMatch(t *testing.T) {
	idx := NewPrefixIndex()
	if err := idx.Add("8.0.0.0/8", 100, "test"); err != nil {
		t.Fatal(err)
	}
	if err := idx.Add("8.8.8.0/24", 15169, "test"); err != nil {
		t.Fatal(err)
	}

	record, ok := idx.Lookup(netip.MustParseAddr("8.8.8.8"))
	if !ok {
		t.Fatal("expected prefix match")
	}
	if record.ASN != 15169 {
		t.Fatalf("expected longest match ASN 15169, got %d", record.ASN)
	}
	if record.Prefix != "8.8.8.0/24" {
		t.Fatalf("expected 8.8.8.0/24, got %s", record.Prefix)
	}
}

func TestPrefixIndexSupportsIPv6AndASNPrefixList(t *testing.T) {
	idx := NewPrefixIndex()
	if err := idx.Add("2001:4860::/32", 15169, "test"); err != nil {
		t.Fatal(err)
	}

	record, ok := idx.Lookup(netip.MustParseAddr("2001:4860:4860::8888"))
	if !ok {
		t.Fatal("expected IPv6 prefix match")
	}
	if record.ASN != 15169 {
		t.Fatalf("expected ASN 15169, got %d", record.ASN)
	}

	records := idx.PrefixesForASN(15169, 10)
	if len(records) != 1 || records[0].Prefix != "2001:4860::/32" {
		t.Fatalf("unexpected ASN prefix list: %#v", records)
	}
}

func TestPrefixIndexFinalizeUsesFlatEntriesAndKeepsASNList(t *testing.T) {
	idx := NewPrefixIndex()
	if err := idx.Add("8.0.0.0/8", 100, "test"); err != nil {
		t.Fatal(err)
	}
	if err := idx.Add("8.8.8.0/24", 15169, "test"); err != nil {
		t.Fatal(err)
	}
	if err := idx.Add("2001:4860::/32", 15169, "test"); err != nil {
		t.Fatal(err)
	}

	idx.Finalize()

	if idx.buildV4[8] != nil || idx.buildV4[24] != nil || idx.buildV6[32] != nil {
		t.Fatalf("expected finalized index to release build maps")
	}
	if len(idx.v4[8]) != 1 || len(idx.v4[24]) != 1 || len(idx.v6[32]) != 1 {
		t.Fatalf("expected flat prefix entries, v4/8=%d v4/24=%d v6/32=%d", len(idx.v4[8]), len(idx.v4[24]), len(idx.v6[32]))
	}
	record, ok := idx.Lookup(netip.MustParseAddr("8.8.8.8"))
	if !ok || record.Prefix != "8.8.8.0/24" || record.ASN != 15169 || record.Source != "test" {
		t.Fatalf("unexpected finalized IPv4 lookup: %#v ok=%v", record, ok)
	}
	records := idx.PrefixesForASN(15169, 10)
	if len(records) != 2 || records[0].Prefix != "2001:4860::/32" || records[1].Prefix != "8.8.8.0/24" {
		t.Fatalf("unexpected finalized ASN prefix list: %#v", records)
	}
}

func TestLookupOnlyPrefixIndexDoesNotKeepASNList(t *testing.T) {
	idx := NewLookupOnlyPrefixIndex()
	if err := idx.Add("1.1.10.0/24", 4809, "caida_history"); err != nil {
		t.Fatal(err)
	}

	idx.Finalize()

	record, ok := idx.Lookup(netip.MustParseAddr("1.1.10.23"))
	if !ok || record.ASN != 4809 || record.Prefix != "1.1.10.0/24" {
		t.Fatalf("unexpected lookup-only match: %#v ok=%v", record, ok)
	}
	if records := idx.PrefixesForASN(4809, 10); len(records) != 0 {
		t.Fatalf("lookup-only index should not retain ASN prefix list, got %#v", records)
	}
}
