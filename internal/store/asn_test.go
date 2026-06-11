package store

import "testing"

func TestASNIndexMergesProfiles(t *testing.T) {
	idx := NewASNIndex()
	idx.Upsert(ASNProfile{ASN: 15169, Name: "GOOGLE", Country: "US", Registry: "arin"})
	idx.Upsert(ASNProfile{ASN: 15169, Name: "Google LLC", InfoType: "Content", Website: "https://google.com"})

	profile, ok := idx.Lookup(15169)
	if !ok {
		t.Fatal("expected profile")
	}
	if profile.Name != "Google LLC" {
		t.Fatalf("expected newer non-empty name, got %q", profile.Name)
	}
	if profile.Country != "US" {
		t.Fatalf("expected existing country to be preserved, got %q", profile.Country)
	}
	if profile.InfoType != "Content" {
		t.Fatalf("expected info type to be merged, got %q", profile.InfoType)
	}
}
