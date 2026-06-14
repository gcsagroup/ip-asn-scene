package geo

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

type staticLocator struct {
	location Location
	ok       bool
}

func (l staticLocator) Lookup(ctx context.Context, ip string) (Location, bool) {
	return l.location, l.ok
}

func TestGeofeedLocatorMatchesLongestPrefixIPv4AndIPv6(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geofeed.csv")
	body := []byte(`
# prefix,country,region,city,postal
203.0.113.0/24,US,US-CA,Los Angeles,
203.0.113.128/25,US,US-NY,New York,
2001:db8:100::/48,JP,JP-13,Tokyo,
`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}

	locator, err := NewGeofeedLocatorFromFiles(path)
	if err != nil {
		t.Fatal(err)
	}

	location, ok := locator.Lookup(context.Background(), "203.0.113.200")
	if !ok {
		t.Fatal("expected IPv4 geofeed match")
	}
	if location.CountryCode != "US" || location.Province != "US-NY" || location.City != "New York" || location.Source != "geofeed" {
		t.Fatalf("unexpected IPv4 location: %#v", location)
	}

	location, ok = locator.Lookup(context.Background(), "2001:db8:100::1")
	if !ok {
		t.Fatal("expected IPv6 geofeed match")
	}
	if location.CountryCode != "JP" || location.Province != "JP-13" || location.City != "Tokyo" {
		t.Fatalf("unexpected IPv6 location: %#v", location)
	}
}

func TestCompositeLocatorPrefersGeofeedAndFallsBack(t *testing.T) {
	primary := staticLocator{location: Location{CountryCode: "HK", City: "Hong Kong", Source: "geofeed"}, ok: true}
	fallback := staticLocator{location: Location{CountryCode: "CN", City: "Beijing", Source: "ip2region"}, ok: true}

	location, ok := NewCompositeLocator(primary, fallback).Lookup(context.Background(), "1.1.1.1")
	if !ok {
		t.Fatal("expected composite match")
	}
	if location.Source != "geofeed" || location.CountryCode != "HK" {
		t.Fatalf("expected geofeed priority, got %#v", location)
	}

	location, ok = NewCompositeLocator(staticLocator{}, fallback).Lookup(context.Background(), "1.1.1.1")
	if !ok {
		t.Fatal("expected fallback match")
	}
	if location.Source != "ip2region" || location.CountryCode != "CN" {
		t.Fatalf("expected fallback location, got %#v", location)
	}
}

func TestGeofeedLocatorIgnoresUnsupportedMappedPrefix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geofeed.csv")
	if err := os.WriteFile(path, []byte("::ffff:203.0.113.0/120,US,US-CA,Los Angeles,\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	locator, err := NewGeofeedLocatorFromFiles(path)
	if err != nil {
		t.Fatal(err)
	}
	if locator != nil {
		if _, ok := locator.Lookup(context.Background(), "203.0.113.10"); ok {
			t.Fatal("mapped IPv6 prefix should not be indexed as IPv4 with an invalid mask")
		}
	}
}
