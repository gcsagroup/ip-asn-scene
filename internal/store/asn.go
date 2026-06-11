package store

import "sort"

type ASNProfile struct {
	ASN      int      `json:"asn"`
	Name     string   `json:"name,omitempty"`
	AKA      string   `json:"aka,omitempty"`
	InfoType string   `json:"info_type,omitempty"`
	Website  string   `json:"website,omitempty"`
	Country  string   `json:"country,omitempty"`
	Registry string   `json:"registry,omitempty"`
	Sources  []string `json:"sources,omitempty"`
}

type ASNIndex struct {
	profiles map[int]ASNProfile
}

func NewASNIndex() *ASNIndex {
	return &ASNIndex{profiles: make(map[int]ASNProfile)}
}

func (idx *ASNIndex) Upsert(profile ASNProfile) {
	if profile.ASN <= 0 {
		return
	}

	existing := idx.profiles[profile.ASN]
	existing.ASN = profile.ASN

	if profile.Name != "" {
		existing.Name = profile.Name
	}
	if profile.AKA != "" {
		existing.AKA = profile.AKA
	}
	if profile.InfoType != "" {
		existing.InfoType = profile.InfoType
	}
	if profile.Website != "" {
		existing.Website = profile.Website
	}
	if profile.Country != "" {
		existing.Country = profile.Country
	}
	if profile.Registry != "" {
		existing.Registry = profile.Registry
	}
	existing.Sources = mergeStrings(existing.Sources, profile.Sources)

	idx.profiles[profile.ASN] = existing
}

func (idx *ASNIndex) Lookup(asn int) (ASNProfile, bool) {
	profile, ok := idx.profiles[asn]
	return profile, ok
}

func (idx *ASNIndex) Count() int {
	return len(idx.profiles)
}

func mergeStrings(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, item := range append(a, b...) {
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}
