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
