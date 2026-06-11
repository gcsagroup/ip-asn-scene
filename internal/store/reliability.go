package store

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

type RPKIRecord struct {
	Prefix    string `json:"prefix"`
	MaxLength int    `json:"max_length,omitempty"`
	ASN       int    `json:"asn"`
	Source    string `json:"source,omitempty"`
}

type RPKIValidation struct {
	Status        string `json:"status"`
	MatchedPrefix string `json:"matched_prefix,omitempty"`
	MaxLength     int    `json:"max_length,omitempty"`
	ASN           int    `json:"asn,omitempty"`
	Source        string `json:"source,omitempty"`
	Reason        string `json:"reason,omitempty"`
}

type RPKIIndex struct {
	v4    [33]map[uint32][]RPKIRecord
	v6    [129]map[[2]uint64][]RPKIRecord
	count int
}

func NewRPKIIndex() *RPKIIndex {
	return &RPKIIndex{}
}

func (idx *RPKIIndex) Add(record RPKIRecord) error {
	prefix, err := netip.ParsePrefix(record.Prefix)
	if err != nil {
		return fmt.Errorf("parse RPKI prefix %q: %w", record.Prefix, err)
	}
	if record.ASN <= 0 {
		return fmt.Errorf("invalid RPKI ASN %d", record.ASN)
	}
	prefix = prefix.Masked()
	record.Prefix = prefix.String()
	if record.MaxLength <= 0 {
		record.MaxLength = prefix.Bits()
	}
	if record.MaxLength < prefix.Bits() {
		return fmt.Errorf("RPKI max length %d is shorter than %s", record.MaxLength, record.Prefix)
	}

	addr := prefix.Addr().Unmap()
	if addr.Is4() {
		if record.MaxLength > 32 {
			return fmt.Errorf("invalid IPv4 RPKI max length %d", record.MaxLength)
		}
		bits := prefix.Bits()
		if idx.v4[bits] == nil {
			idx.v4[bits] = map[uint32][]RPKIRecord{}
		}
		key := maskIPv4(addr, bits)
		idx.v4[bits][key] = append(idx.v4[bits][key], record)
	} else {
		if record.MaxLength > 128 {
			return fmt.Errorf("invalid IPv6 RPKI max length %d", record.MaxLength)
		}
		bits := prefix.Bits()
		if idx.v6[bits] == nil {
			idx.v6[bits] = map[[2]uint64][]RPKIRecord{}
		}
		key := maskIPv6(addr, bits)
		idx.v6[bits][key] = append(idx.v6[bits][key], record)
	}
	idx.count++
	return nil
}

func (idx *RPKIIndex) Validate(routePrefixText string, asn int) RPKIValidation {
	if idx == nil || routePrefixText == "" || asn <= 0 {
		return RPKIValidation{Status: "not_found", Reason: "no RPKI data"}
	}
	routePrefix, err := netip.ParsePrefix(routePrefixText)
	if err != nil {
		return RPKIValidation{Status: "not_found", Reason: "invalid route prefix"}
	}
	routePrefix = routePrefix.Masked()
	routeBits := routePrefix.Bits()
	records := idx.covering(routePrefix)
	if len(records) == 0 {
		return RPKIValidation{Status: "not_found", Reason: "no covering VRP"}
	}

	best := records[0]
	for _, record := range records {
		if record.ASN == asn && routeBits <= record.MaxLength {
			return RPKIValidation{
				Status:        "valid",
				MatchedPrefix: record.Prefix,
				MaxLength:     record.MaxLength,
				ASN:           record.ASN,
				Source:        record.Source,
				Reason:        "origin ASN and prefix length match VRP",
			}
		}
		if len(record.Prefix) > len(best.Prefix) {
			best = record
		}
	}
	return RPKIValidation{
		Status:        "invalid",
		MatchedPrefix: best.Prefix,
		MaxLength:     best.MaxLength,
		ASN:           best.ASN,
		Source:        best.Source,
		Reason:        "covering VRP exists but origin ASN or prefix length does not match",
	}
}

func (idx *RPKIIndex) covering(routePrefix netip.Prefix) []RPKIRecord {
	addr := routePrefix.Addr().Unmap()
	routeBits := routePrefix.Bits()
	out := []RPKIRecord{}
	if addr.Is4() {
		for bits := routeBits; bits >= 0; bits-- {
			bucket := idx.v4[bits]
			if bucket == nil {
				continue
			}
			out = append(out, bucket[maskIPv4(addr, bits)]...)
		}
		return out
	}
	if !addr.Is6() {
		return out
	}
	for bits := routeBits; bits >= 0; bits-- {
		bucket := idx.v6[bits]
		if bucket == nil {
			continue
		}
		out = append(out, bucket[maskIPv6(addr, bits)]...)
	}
	return out
}

func (idx *RPKIIndex) Count() int {
	if idx == nil {
		return 0
	}
	return idx.count
}

type IRRRouteRecord struct {
	Prefix   string `json:"prefix"`
	ASN      int    `json:"asn"`
	Source   string `json:"source,omitempty"`
	Registry string `json:"registry,omitempty"`
}

type IRRValidation struct {
	Matched    bool   `json:"matched"`
	Prefix     string `json:"prefix,omitempty"`
	ASN        int    `json:"asn,omitempty"`
	Source     string `json:"source,omitempty"`
	Registry   string `json:"registry,omitempty"`
	Conflict   bool   `json:"conflict,omitempty"`
	OriginASNs []int  `json:"origin_asns,omitempty"`
}

type IRRIndex struct {
	byPrefix map[string][]IRRRouteRecord
	count    int
}

func NewIRRIndex() *IRRIndex {
	return &IRRIndex{byPrefix: map[string][]IRRRouteRecord{}}
}

func (idx *IRRIndex) Add(record IRRRouteRecord) error {
	prefix, err := netip.ParsePrefix(record.Prefix)
	if err != nil {
		return fmt.Errorf("parse IRR prefix %q: %w", record.Prefix, err)
	}
	if record.ASN <= 0 {
		return fmt.Errorf("invalid IRR ASN %d", record.ASN)
	}
	record.Prefix = prefix.Masked().String()
	record.Source = strings.ToUpper(strings.TrimSpace(record.Source))
	record.Registry = strings.ToLower(strings.TrimSpace(record.Registry))
	key := record.Prefix
	for _, existing := range idx.byPrefix[key] {
		if existing.ASN == record.ASN && strings.EqualFold(existing.Source, record.Source) {
			return nil
		}
	}
	idx.byPrefix[key] = append(idx.byPrefix[key], record)
	idx.count++
	return nil
}

func (idx *IRRIndex) Validate(routePrefixText string, asn int) IRRValidation {
	if idx == nil || routePrefixText == "" || asn <= 0 {
		return IRRValidation{}
	}
	prefix, err := netip.ParsePrefix(routePrefixText)
	if err != nil {
		return IRRValidation{}
	}
	key := prefix.Masked().String()
	records := idx.byPrefix[key]
	if len(records) == 0 {
		return IRRValidation{Prefix: key}
	}
	origins := uniqueOriginASNs(records)
	out := IRRValidation{Prefix: key, OriginASNs: origins, Conflict: len(origins) > 1}
	for _, record := range records {
		if record.ASN == asn {
			out.Matched = true
			out.ASN = record.ASN
			out.Source = record.Source
			out.Registry = record.Registry
			return out
		}
	}
	out.Conflict = true
	return out
}

func (idx *IRRIndex) Count() int {
	if idx == nil {
		return 0
	}
	return idx.count
}

func uniqueOriginASNs(records []IRRRouteRecord) []int {
	seen := map[int]bool{}
	out := []int{}
	for _, record := range records {
		if record.ASN <= 0 || seen[record.ASN] {
			continue
		}
		seen[record.ASN] = true
		out = append(out, record.ASN)
	}
	sort.Ints(out)
	return out
}

type BGPObservationRecord struct {
	Prefix           string `json:"prefix"`
	OriginASN        int    `json:"origin_asn"`
	Source           string `json:"source,omitempty"`
	Collector        string `json:"collector,omitempty"`
	ObservationCount int    `json:"observation_count,omitempty"`
	DominantUpstream int    `json:"dominant_upstream,omitempty"`
}

type BGPOriginCount struct {
	ASN   int `json:"asn"`
	Count int `json:"count"`
}

type BGPObservationSummary struct {
	Prefix            string                 `json:"prefix,omitempty"`
	Visibility        int                    `json:"visibility,omitempty"`
	OriginAgreement   float64                `json:"origin_agreement,omitempty"`
	MOAS              bool                   `json:"moas,omitempty"`
	Origins           []BGPOriginCount       `json:"origins,omitempty"`
	DominantUpstreams []BGPOriginCount       `json:"dominant_upstreams,omitempty"`
	Records           []BGPObservationRecord `json:"records,omitempty"`
}

type BGPObservationIndex struct {
	v4    [33]map[uint32][]BGPObservationRecord
	v6    [129]map[[2]uint64][]BGPObservationRecord
	count int
}

func NewBGPObservationIndex() *BGPObservationIndex {
	return &BGPObservationIndex{}
}

func (idx *BGPObservationIndex) Add(record BGPObservationRecord) error {
	prefix, err := netip.ParsePrefix(record.Prefix)
	if err != nil {
		return fmt.Errorf("parse BGP observation prefix %q: %w", record.Prefix, err)
	}
	if record.OriginASN <= 0 {
		return fmt.Errorf("invalid BGP observation ASN %d", record.OriginASN)
	}
	if record.ObservationCount <= 0 {
		record.ObservationCount = 1
	}
	prefix = prefix.Masked()
	record.Prefix = prefix.String()
	addr := prefix.Addr().Unmap()
	if addr.Is4() {
		bits := prefix.Bits()
		if idx.v4[bits] == nil {
			idx.v4[bits] = map[uint32][]BGPObservationRecord{}
		}
		idx.v4[bits][maskIPv4(addr, bits)] = append(idx.v4[bits][maskIPv4(addr, bits)], record)
	} else {
		bits := prefix.Bits()
		if idx.v6[bits] == nil {
			idx.v6[bits] = map[[2]uint64][]BGPObservationRecord{}
		}
		idx.v6[bits][maskIPv6(addr, bits)] = append(idx.v6[bits][maskIPv6(addr, bits)], record)
	}
	idx.count++
	return nil
}

func (idx *BGPObservationIndex) Summarize(query string, asn int) BGPObservationSummary {
	records := idx.lookup(query)
	if len(records) == 0 {
		return BGPObservationSummary{}
	}
	originCounts := map[int]int{}
	upstreamCounts := map[int]int{}
	total := 0
	for _, record := range records {
		count := record.ObservationCount
		if count <= 0 {
			count = 1
		}
		originCounts[record.OriginASN] += count
		if record.DominantUpstream > 0 {
			upstreamCounts[record.DominantUpstream] += count
		}
		total += count
	}
	summary := BGPObservationSummary{
		Prefix:            records[0].Prefix,
		Visibility:        total,
		Origins:           sortedCounts(originCounts),
		DominantUpstreams: sortedCounts(upstreamCounts),
		Records:           append([]BGPObservationRecord(nil), records...),
	}
	if total > 0 {
		summary.OriginAgreement = float64(originCounts[asn]) / float64(total)
	}
	summary.MOAS = len(summary.Origins) > 1
	return summary
}

func (idx *BGPObservationIndex) lookup(query string) []BGPObservationRecord {
	if idx == nil {
		return nil
	}
	if prefix, err := netip.ParsePrefix(query); err == nil {
		return idx.lookupAddr(prefix.Addr().Unmap(), prefix.Bits())
	}
	addr, err := netip.ParseAddr(query)
	if err != nil {
		return nil
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return idx.lookupAddr(addr, 32)
	}
	if addr.Is6() {
		return idx.lookupAddr(addr, 128)
	}
	return nil
}

func (idx *BGPObservationIndex) lookupAddr(addr netip.Addr, maxBits int) []BGPObservationRecord {
	if addr.Is4() {
		for bits := minInt(maxBits, 32); bits >= 0; bits-- {
			bucket := idx.v4[bits]
			if bucket == nil {
				continue
			}
			if records := bucket[maskIPv4(addr, bits)]; len(records) > 0 {
				return append([]BGPObservationRecord(nil), records...)
			}
		}
		return nil
	}
	for bits := minInt(maxBits, 128); bits >= 0; bits-- {
		bucket := idx.v6[bits]
		if bucket == nil {
			continue
		}
		if records := bucket[maskIPv6(addr, bits)]; len(records) > 0 {
			return append([]BGPObservationRecord(nil), records...)
		}
	}
	return nil
}

func (idx *BGPObservationIndex) Count() int {
	if idx == nil {
		return 0
	}
	return idx.count
}

type ReliabilityIndex struct {
	RPKI *RPKIIndex
	IRR  *IRRIndex
	BGP  *BGPObservationIndex
}

func NewReliabilityIndex() *ReliabilityIndex {
	return &ReliabilityIndex{
		RPKI: NewRPKIIndex(),
		IRR:  NewIRRIndex(),
		BGP:  NewBGPObservationIndex(),
	}
}

func sortedCounts(values map[int]int) []BGPOriginCount {
	out := make([]BGPOriginCount, 0, len(values))
	for asn, count := range values {
		if asn <= 0 || count <= 0 {
			continue
		}
		out = append(out, BGPOriginCount{ASN: asn, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].ASN < out[j].ASN
		}
		return out[i].Count > out[j].Count
	})
	return out
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
