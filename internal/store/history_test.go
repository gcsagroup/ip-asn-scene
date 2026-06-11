package store

import (
	"net/netip"
	"testing"
)

func TestHistoryIndexLooksUpNewestSnapshotsFirst(t *testing.T) {
	oldPrefixes := NewPrefixIndex()
	if err := oldPrefixes.Add("1.1.10.0/23", 4134, "caida_history"); err != nil {
		t.Fatal(err)
	}
	newPrefixes := NewPrefixIndex()
	if err := newPrefixes.Add("1.1.10.0/24", 4809, "caida_history"); err != nil {
		t.Fatal(err)
	}

	history := NewHistoryIndex()
	history.AddSnapshot("old", oldPrefixes)
	history.AddSnapshot("new", newPrefixes)

	records := history.Lookup(netip.MustParseAddr("1.1.10.23"), 10)
	if len(records) != 2 {
		t.Fatalf("expected two historical records, got %#v", records)
	}
	if records[0].ASN != 4809 || records[0].Label != "new" {
		t.Fatalf("expected newest match first, got %#v", records[0])
	}
	if history.SnapshotCount() != 2 || history.PrefixCount() != 2 {
		t.Fatalf("unexpected history counts")
	}
}
