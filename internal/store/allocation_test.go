package store

import (
	"net/netip"
	"testing"
)

func TestAllocationIndexUsesLongestMatch(t *testing.T) {
	idx := NewAllocationIndex()
	if err := idx.Add(AllocationRecord{Prefix: "1.1.0.0/16", Country: "AU", Registry: "apnic", Status: "allocated", Source: "rir:apnic"}); err != nil {
		t.Fatal(err)
	}
	if err := idx.Add(AllocationRecord{Prefix: "1.1.10.0/23", Country: "CN", Registry: "apnic", Status: "allocated", Source: "rir:apnic"}); err != nil {
		t.Fatal(err)
	}

	record, ok := idx.Lookup(netip.MustParseAddr("1.1.10.23"))
	if !ok {
		t.Fatal("expected allocation match")
	}
	if record.Prefix != "1.1.10.0/23" || record.Country != "CN" || record.Registry != "apnic" {
		t.Fatalf("unexpected allocation record: %#v", record)
	}
}
