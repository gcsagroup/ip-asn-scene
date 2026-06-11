package geo

import "testing"

func TestParseIP2RegionRegion(t *testing.T) {
	location := parseIP2RegionRegion("中国|广东省|深圳市|电信|CN", "2026-05-20")
	if location.Country != "中国" || location.Province != "广东省" || location.City != "深圳市" || location.ISP != "电信" || location.CountryCode != "CN" {
		t.Fatalf("unexpected location: %#v", location)
	}
	if location.Source != "ip2region" || location.DBVersion != "2026-05-20" {
		t.Fatalf("unexpected metadata: %#v", location)
	}
}

func TestParseIP2RegionFullRegion(t *testing.T) {
	location := parseIP2RegionRegion("北美洲|美国|California|Mountain View||谷歌|-122.083847|37.386051|||95025|America/Los_Angeles|USD|AS15169|||US", "2026-05-20")
	if location.Country != "美国" || location.Province != "California" || location.City != "Mountain View" || location.ISP != "谷歌" || location.CountryCode != "US" || location.ASN != "AS15169" {
		t.Fatalf("unexpected full location: %#v", location)
	}
}

func TestParseIP2RegionRegionSkipsZeroFields(t *testing.T) {
	location := parseIP2RegionRegion("0|0|0|0|0", "2026-05-20")
	if location.Country != "" || location.Province != "" || location.City != "" || location.ISP != "" || location.CountryCode != "" {
		t.Fatalf("expected zero fields to be blank, got %#v", location)
	}
}
