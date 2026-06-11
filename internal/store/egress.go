package store

import "sort"

type NetworkPresence struct {
	IXPs       []IXPPresence      `json:"ixps,omitempty"`
	Facilities []FacilityPresence `json:"facilities,omitempty"`
}

type IXPPresence struct {
	ASN     int    `json:"asn,omitempty"`
	IXID    int    `json:"ix_id,omitempty"`
	Name    string `json:"name,omitempty"`
	Country string `json:"country,omitempty"`
	City    string `json:"city,omitempty"`
	IP      string `json:"ip,omitempty"`
	Speed   int    `json:"speed,omitempty"`
}

type FacilityPresence struct {
	ASN        int    `json:"asn,omitempty"`
	FacilityID int    `json:"facility_id,omitempty"`
	Name       string `json:"name,omitempty"`
	Country    string `json:"country,omitempty"`
	City       string `json:"city,omitempty"`
}

type EgressIndex struct {
	byASN map[int]NetworkPresence
}

func NewEgressIndex() *EgressIndex {
	return &EgressIndex{byASN: map[int]NetworkPresence{}}
}

func (idx *EgressIndex) AddIXP(presence IXPPresence) {
	if idx == nil || presence.ASN <= 0 || presence.Name == "" {
		return
	}
	current := idx.byASN[presence.ASN]
	for _, existing := range current.IXPs {
		if existing.Name == presence.Name && existing.IP == presence.IP {
			return
		}
	}
	current.IXPs = append(current.IXPs, presence)
	sort.SliceStable(current.IXPs, func(i, j int) bool {
		if current.IXPs[i].Speed == current.IXPs[j].Speed {
			return current.IXPs[i].Name < current.IXPs[j].Name
		}
		return current.IXPs[i].Speed > current.IXPs[j].Speed
	})
	idx.byASN[presence.ASN] = current
}

func (idx *EgressIndex) AddFacility(presence FacilityPresence) {
	if idx == nil || presence.ASN <= 0 || presence.Name == "" {
		return
	}
	current := idx.byASN[presence.ASN]
	for _, existing := range current.Facilities {
		if existing.Name == presence.Name {
			return
		}
	}
	current.Facilities = append(current.Facilities, presence)
	sort.SliceStable(current.Facilities, func(i, j int) bool {
		return current.Facilities[i].Name < current.Facilities[j].Name
	})
	idx.byASN[presence.ASN] = current
}

func (idx *EgressIndex) Lookup(asn int) (NetworkPresence, bool) {
	if idx == nil {
		return NetworkPresence{}, false
	}
	presence, ok := idx.byASN[asn]
	return presence, ok
}

func (idx *EgressIndex) Count() int {
	if idx == nil {
		return 0
	}
	return len(idx.byASN)
}
