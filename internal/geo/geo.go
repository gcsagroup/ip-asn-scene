package geo

import "context"

type Location struct {
	Country     string `json:"country,omitempty"`
	Province    string `json:"province,omitempty"`
	City        string `json:"city,omitempty"`
	ISP         string `json:"isp,omitempty"`
	CountryCode string `json:"country_code,omitempty"`
	ASN         string `json:"asn,omitempty"`
	Source      string `json:"-"`
	DBVersion   string `json:"-"`
}

type Locator interface {
	Lookup(ctx context.Context, ip string) (Location, bool)
}
