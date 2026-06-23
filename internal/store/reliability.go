package store

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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
	v4        [33][]rpkiV4Entry
	v4Records [33][]rpkiCompactRecord
	v6        [129][]rpkiV6Entry
	v6Records [129][]rpkiCompactRecord
	buildV4   [33]map[uint32][]rpkiCompactRecord
	buildV6   [129]map[[2]uint64][]rpkiCompactRecord
	sources   []string
	sourceIDs map[string]uint16
	count     int
	finalized bool
}

type rpkiCompactRecord struct {
	ASN       int
	MaxLength uint8
	Source    uint16
}

type rpkiV4Entry struct {
	Key   uint32
	Start uint32
	Count uint32
}

type rpkiV6Entry struct {
	Key   [2]uint64
	Start uint32
	Count uint32
}

func NewRPKIIndex() *RPKIIndex {
	return &RPKIIndex{sourceIDs: map[string]uint16{}}
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
	idx.ensureMutable()
	compact := rpkiCompactRecord{ASN: record.ASN, MaxLength: uint8(record.MaxLength), Source: idx.sourceID(record.Source)}

	addr := prefix.Addr().Unmap()
	if addr.Is4() {
		if record.MaxLength > 32 {
			return fmt.Errorf("invalid IPv4 RPKI max length %d", record.MaxLength)
		}
		bits := prefix.Bits()
		if idx.buildV4[bits] == nil {
			idx.buildV4[bits] = map[uint32][]rpkiCompactRecord{}
		}
		key := maskIPv4(addr, bits)
		idx.buildV4[bits][key] = append(idx.buildV4[bits][key], compact)
	} else {
		if record.MaxLength > 128 {
			return fmt.Errorf("invalid IPv6 RPKI max length %d", record.MaxLength)
		}
		bits := prefix.Bits()
		if idx.buildV6[bits] == nil {
			idx.buildV6[bits] = map[[2]uint64][]rpkiCompactRecord{}
		}
		key := maskIPv6(addr, bits)
		idx.buildV6[bits][key] = append(idx.buildV6[bits][key], compact)
	}
	idx.count++
	idx.finalized = false
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
			key := maskIPv4(addr, bits)
			for _, record := range idx.lookupRPKIV4(bits, key) {
				out = append(out, idx.rpkiRecordFromV4(key, bits, record))
			}
		}
		return out
	}
	if !addr.Is6() {
		return out
	}
	for bits := routeBits; bits >= 0; bits-- {
		key := maskIPv6(addr, bits)
		for _, record := range idx.lookupRPKIV6(bits, key) {
			out = append(out, idx.rpkiRecordFromV6(key, bits, record))
		}
	}
	return out
}

func (idx *RPKIIndex) Count() int {
	if idx == nil {
		return 0
	}
	return idx.count
}

func (idx *RPKIIndex) Finalize() {
	if idx == nil || idx.finalized {
		return
	}
	for bits, bucket := range idx.buildV4 {
		if len(bucket) == 0 {
			idx.buildV4[bits] = nil
			continue
		}
		keys := make([]uint32, 0, len(bucket))
		total := 0
		for key, records := range bucket {
			keys = append(keys, key)
			total += len(records)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		entries := make([]rpkiV4Entry, 0, len(keys))
		flat := make([]rpkiCompactRecord, 0, total)
		for _, key := range keys {
			records := bucket[key]
			start := len(flat)
			flat = append(flat, records...)
			entries = append(entries, rpkiV4Entry{Key: key, Start: uint32(start), Count: uint32(len(records))})
		}
		idx.v4[bits] = entries
		idx.v4Records[bits] = flat
		idx.buildV4[bits] = nil
	}
	for bits, bucket := range idx.buildV6 {
		if len(bucket) == 0 {
			idx.buildV6[bits] = nil
			continue
		}
		keys := make([][2]uint64, 0, len(bucket))
		total := 0
		for key, records := range bucket {
			keys = append(keys, key)
			total += len(records)
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i][0] == keys[j][0] {
				return keys[i][1] < keys[j][1]
			}
			return keys[i][0] < keys[j][0]
		})
		entries := make([]rpkiV6Entry, 0, len(keys))
		flat := make([]rpkiCompactRecord, 0, total)
		for _, key := range keys {
			records := bucket[key]
			start := len(flat)
			flat = append(flat, records...)
			entries = append(entries, rpkiV6Entry{Key: key, Start: uint32(start), Count: uint32(len(records))})
		}
		idx.v6[bits] = entries
		idx.v6Records[bits] = flat
		idx.buildV6[bits] = nil
	}
	idx.finalized = true
}

func (idx *RPKIIndex) ensureMutable() {
	if idx == nil || !idx.finalized {
		return
	}
	for bits, entries := range idx.v4 {
		if len(entries) == 0 {
			continue
		}
		bucket := make(map[uint32][]rpkiCompactRecord, len(entries))
		records := idx.v4Records[bits]
		for _, entry := range entries {
			bucket[entry.Key] = append([]rpkiCompactRecord(nil), records[entry.Start:entry.Start+entry.Count]...)
		}
		idx.buildV4[bits] = bucket
		idx.v4[bits] = nil
		idx.v4Records[bits] = nil
	}
	for bits, entries := range idx.v6 {
		if len(entries) == 0 {
			continue
		}
		bucket := make(map[[2]uint64][]rpkiCompactRecord, len(entries))
		records := idx.v6Records[bits]
		for _, entry := range entries {
			bucket[entry.Key] = append([]rpkiCompactRecord(nil), records[entry.Start:entry.Start+entry.Count]...)
		}
		idx.buildV6[bits] = bucket
		idx.v6[bits] = nil
		idx.v6Records[bits] = nil
	}
	idx.finalized = false
}

func (idx *RPKIIndex) lookupRPKIV4(bits int, key uint32) []rpkiCompactRecord {
	if bucket := idx.buildV4[bits]; len(bucket) > 0 {
		return bucket[key]
	}
	entries := idx.v4[bits]
	pos := sort.Search(len(entries), func(i int) bool { return entries[i].Key >= key })
	if pos >= len(entries) || entries[pos].Key != key {
		return nil
	}
	entry := entries[pos]
	return idx.v4Records[bits][entry.Start : entry.Start+entry.Count]
}

func (idx *RPKIIndex) lookupRPKIV6(bits int, key [2]uint64) []rpkiCompactRecord {
	if bucket := idx.buildV6[bits]; len(bucket) > 0 {
		return bucket[key]
	}
	entries := idx.v6[bits]
	pos := sort.Search(len(entries), func(i int) bool {
		if entries[i].Key[0] == key[0] {
			return entries[i].Key[1] >= key[1]
		}
		return entries[i].Key[0] >= key[0]
	})
	if pos >= len(entries) || entries[pos].Key != key {
		return nil
	}
	entry := entries[pos]
	return idx.v6Records[bits][entry.Start : entry.Start+entry.Count]
}

func (idx *RPKIIndex) rpkiRecordFromV4(key uint32, bits int, record rpkiCompactRecord) RPKIRecord {
	return RPKIRecord{Prefix: ipv4PrefixString(key, bits), MaxLength: int(record.MaxLength), ASN: record.ASN, Source: idx.sourceName(record.Source)}
}

func (idx *RPKIIndex) rpkiRecordFromV6(key [2]uint64, bits int, record rpkiCompactRecord) RPKIRecord {
	return RPKIRecord{Prefix: ipv6PrefixString(key, bits), MaxLength: int(record.MaxLength), ASN: record.ASN, Source: idx.sourceName(record.Source)}
}

func (idx *RPKIIndex) sourceID(source string) uint16 {
	if source == "" {
		return 0
	}
	if idx.sourceIDs == nil {
		idx.sourceIDs = map[string]uint16{}
	}
	if id, ok := idx.sourceIDs[source]; ok {
		return id
	}
	id := uint16(len(idx.sources) + 1)
	idx.sources = append(idx.sources, source)
	idx.sourceIDs[source] = id
	return id
}

func (idx *RPKIIndex) sourceName(id uint16) string {
	if idx == nil || id == 0 || int(id) > len(idx.sources) {
		return ""
	}
	return idx.sources[id-1]
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
	v4          [33][]irrV4Entry
	v4Records   [33][]irrCompactRecord
	v6          [129][]irrV6Entry
	v6Records   [129][]irrCompactRecord
	buildV4     [33]map[uint32][]irrCompactRecord
	buildV6     [129]map[[2]uint64][]irrCompactRecord
	sources     []string
	sourceIDs   map[string]uint16
	registries  []string
	registryIDs map[string]uint16
	count       int
	finalized   bool
}

type irrCompactRecord struct {
	ASN      int
	Source   uint16
	Registry uint16
}

type irrV4Entry struct {
	Key   uint32
	Start uint32
	Count uint32
}

type irrV6Entry struct {
	Key   [2]uint64
	Start uint32
	Count uint32
}

func NewIRRIndex() *IRRIndex {
	return &IRRIndex{sourceIDs: map[string]uint16{}, registryIDs: map[string]uint16{}}
}

func (idx *IRRIndex) Add(record IRRRouteRecord) error {
	prefix, err := netip.ParsePrefix(record.Prefix)
	if err != nil {
		return fmt.Errorf("parse IRR prefix %q: %w", record.Prefix, err)
	}
	if record.ASN <= 0 {
		return fmt.Errorf("invalid IRR ASN %d", record.ASN)
	}
	idx.ensureMutable()
	prefix = prefix.Masked()
	record.Source = strings.ToUpper(strings.TrimSpace(record.Source))
	record.Registry = strings.ToLower(strings.TrimSpace(record.Registry))
	compact := irrCompactRecord{ASN: record.ASN, Source: idx.sourceID(record.Source), Registry: idx.registryID(record.Registry)}
	addr := prefix.Addr().Unmap()
	if addr.Is4() {
		bits := prefix.Bits()
		if bits < 0 || bits > 32 {
			return fmt.Errorf("invalid IPv4 IRR prefix length %d", bits)
		}
		key := maskIPv4(addr, bits)
		if idx.hasIRRV4(bits, key, compact.ASN, compact.Source) {
			return nil
		}
		if idx.buildV4[bits] == nil {
			idx.buildV4[bits] = map[uint32][]irrCompactRecord{}
		}
		idx.buildV4[bits][key] = append(idx.buildV4[bits][key], compact)
	} else {
		bits := prefix.Bits()
		if bits < 0 || bits > 128 {
			return fmt.Errorf("invalid IPv6 IRR prefix length %d", bits)
		}
		key := maskIPv6(addr, bits)
		if idx.hasIRRV6(bits, key, compact.ASN, compact.Source) {
			return nil
		}
		if idx.buildV6[bits] == nil {
			idx.buildV6[bits] = map[[2]uint64][]irrCompactRecord{}
		}
		idx.buildV6[bits][key] = append(idx.buildV6[bits][key], compact)
	}
	idx.count++
	idx.finalized = false
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
	prefix = prefix.Masked()
	key := prefix.String()
	addr := prefix.Addr().Unmap()
	records := []irrCompactRecord{}
	if addr.Is4() {
		records = idx.lookupIRRV4(prefix.Bits(), maskIPv4(addr, prefix.Bits()))
	} else if addr.Is6() {
		records = idx.lookupIRRV6(prefix.Bits(), maskIPv6(addr, prefix.Bits()))
	}
	if len(records) == 0 {
		return IRRValidation{Prefix: key}
	}
	origins := uniqueIRROriginASNs(records)
	out := IRRValidation{Prefix: key, OriginASNs: origins, Conflict: len(origins) > 1}
	for _, record := range records {
		if record.ASN == asn {
			out.Matched = true
			out.ASN = record.ASN
			out.Source = idx.sourceName(record.Source)
			out.Registry = idx.registryName(record.Registry)
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

func (idx *IRRIndex) Finalize() {
	if idx == nil || idx.finalized {
		return
	}
	for bits, bucket := range idx.buildV4 {
		if len(bucket) == 0 {
			idx.buildV4[bits] = nil
			continue
		}
		keys := make([]uint32, 0, len(bucket))
		total := 0
		for key, records := range bucket {
			keys = append(keys, key)
			total += len(records)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		entries := make([]irrV4Entry, 0, len(keys))
		flat := make([]irrCompactRecord, 0, total)
		for _, key := range keys {
			records := bucket[key]
			start := len(flat)
			flat = append(flat, records...)
			entries = append(entries, irrV4Entry{Key: key, Start: uint32(start), Count: uint32(len(records))})
		}
		idx.v4[bits] = entries
		idx.v4Records[bits] = flat
		idx.buildV4[bits] = nil
	}
	for bits, bucket := range idx.buildV6 {
		if len(bucket) == 0 {
			idx.buildV6[bits] = nil
			continue
		}
		keys := make([][2]uint64, 0, len(bucket))
		total := 0
		for key, records := range bucket {
			keys = append(keys, key)
			total += len(records)
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i][0] == keys[j][0] {
				return keys[i][1] < keys[j][1]
			}
			return keys[i][0] < keys[j][0]
		})
		entries := make([]irrV6Entry, 0, len(keys))
		flat := make([]irrCompactRecord, 0, total)
		for _, key := range keys {
			records := bucket[key]
			start := len(flat)
			flat = append(flat, records...)
			entries = append(entries, irrV6Entry{Key: key, Start: uint32(start), Count: uint32(len(records))})
		}
		idx.v6[bits] = entries
		idx.v6Records[bits] = flat
		idx.buildV6[bits] = nil
	}
	idx.finalized = true
}

func (idx *IRRIndex) ensureMutable() {
	if idx == nil || !idx.finalized {
		return
	}
	for bits, entries := range idx.v4 {
		if len(entries) == 0 {
			continue
		}
		bucket := make(map[uint32][]irrCompactRecord, len(entries))
		records := idx.v4Records[bits]
		for _, entry := range entries {
			bucket[entry.Key] = append([]irrCompactRecord(nil), records[entry.Start:entry.Start+entry.Count]...)
		}
		idx.buildV4[bits] = bucket
		idx.v4[bits] = nil
		idx.v4Records[bits] = nil
	}
	for bits, entries := range idx.v6 {
		if len(entries) == 0 {
			continue
		}
		bucket := make(map[[2]uint64][]irrCompactRecord, len(entries))
		records := idx.v6Records[bits]
		for _, entry := range entries {
			bucket[entry.Key] = append([]irrCompactRecord(nil), records[entry.Start:entry.Start+entry.Count]...)
		}
		idx.buildV6[bits] = bucket
		idx.v6[bits] = nil
		idx.v6Records[bits] = nil
	}
	idx.finalized = false
}

func (idx *IRRIndex) lookupIRRV4(bits int, key uint32) []irrCompactRecord {
	if bits < 0 || bits > 32 {
		return nil
	}
	if bucket := idx.buildV4[bits]; len(bucket) > 0 {
		return bucket[key]
	}
	entries := idx.v4[bits]
	pos := sort.Search(len(entries), func(i int) bool { return entries[i].Key >= key })
	if pos >= len(entries) || entries[pos].Key != key {
		return nil
	}
	entry := entries[pos]
	return idx.v4Records[bits][entry.Start : entry.Start+entry.Count]
}

func (idx *IRRIndex) lookupIRRV6(bits int, key [2]uint64) []irrCompactRecord {
	if bits < 0 || bits > 128 {
		return nil
	}
	if bucket := idx.buildV6[bits]; len(bucket) > 0 {
		return bucket[key]
	}
	entries := idx.v6[bits]
	pos := sort.Search(len(entries), func(i int) bool {
		if entries[i].Key[0] == key[0] {
			return entries[i].Key[1] >= key[1]
		}
		return entries[i].Key[0] >= key[0]
	})
	if pos >= len(entries) || entries[pos].Key != key {
		return nil
	}
	entry := entries[pos]
	return idx.v6Records[bits][entry.Start : entry.Start+entry.Count]
}

func (idx *IRRIndex) hasIRRV4(bits int, key uint32, asn int, source uint16) bool {
	for _, record := range idx.lookupIRRV4(bits, key) {
		if record.ASN == asn && record.Source == source {
			return true
		}
	}
	return false
}

func (idx *IRRIndex) hasIRRV6(bits int, key [2]uint64, asn int, source uint16) bool {
	for _, record := range idx.lookupIRRV6(bits, key) {
		if record.ASN == asn && record.Source == source {
			return true
		}
	}
	return false
}

func (idx *IRRIndex) sourceID(source string) uint16 {
	if source == "" {
		return 0
	}
	if idx.sourceIDs == nil {
		idx.sourceIDs = map[string]uint16{}
	}
	if id, ok := idx.sourceIDs[source]; ok {
		return id
	}
	id := uint16(len(idx.sources) + 1)
	idx.sources = append(idx.sources, source)
	idx.sourceIDs[source] = id
	return id
}

func (idx *IRRIndex) sourceName(id uint16) string {
	if idx == nil || id == 0 || int(id) > len(idx.sources) {
		return ""
	}
	return idx.sources[id-1]
}

func (idx *IRRIndex) registryID(registry string) uint16 {
	if registry == "" {
		return 0
	}
	if idx.registryIDs == nil {
		idx.registryIDs = map[string]uint16{}
	}
	if id, ok := idx.registryIDs[registry]; ok {
		return id
	}
	id := uint16(len(idx.registries) + 1)
	idx.registries = append(idx.registries, registry)
	idx.registryIDs[registry] = id
	return id
}

func (idx *IRRIndex) registryName(id uint16) string {
	if idx == nil || id == 0 || int(id) > len(idx.registries) {
		return ""
	}
	return idx.registries[id-1]
}

func uniqueIRROriginASNs(records []irrCompactRecord) []int {
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
	v4        [33][]bgpObservationV4Entry
	v4Records [33][]bgpObservationCompactRecord
	v6        [129][]bgpObservationV6Entry
	v6Records [129][]bgpObservationCompactRecord
	buildV4   [33]map[uint32][]bgpObservationCompactRecord
	buildV6   [129]map[[2]uint64][]bgpObservationCompactRecord
	count     int
	finalized bool
}

type bgpObservationV4Entry struct {
	key   uint32
	start uint32
	count uint32
}

type bgpObservationV6Entry struct {
	key   [2]uint64
	start uint32
	count uint32
}

type bgpObservationCompactRecord struct {
	originASN        uint32
	observationCount uint32
	dominantUpstream uint32
	source           uint8
	collectorCount   uint16
}

var (
	bgpCompactMagicV1 = [8]byte{'I', 'P', 'A', 'S', 'B', 'G', 'P', '1'}
	bgpCompactMagicV2 = [8]byte{'I', 'P', 'A', 'S', 'B', 'G', 'P', '2'}
	bgpCompactOrder   = binary.LittleEndian
)

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
	idx.ensureMutable()
	prefix = normalizeBGPObservationPrefix(prefix)
	record.Prefix = prefix.String()
	addr := prefix.Addr()
	if addr.Is4() {
		bits := prefix.Bits()
		if idx.buildV4[bits] == nil {
			idx.buildV4[bits] = map[uint32][]bgpObservationCompactRecord{}
		}
		key := maskIPv4(addr, bits)
		idx.buildV4[bits][key] = append(idx.buildV4[bits][key], compactBGPObservationRecord(record))
	} else {
		bits := prefix.Bits()
		if idx.buildV6[bits] == nil {
			idx.buildV6[bits] = map[[2]uint64][]bgpObservationCompactRecord{}
		}
		key := maskIPv6(addr, bits)
		idx.buildV6[bits][key] = append(idx.buildV6[bits][key], compactBGPObservationRecord(record))
	}
	idx.count++
	idx.finalized = false
	return nil
}

func (idx *BGPObservationIndex) ensureMutable() {
	if idx == nil || !idx.finalized {
		return
	}
	for bits, entries := range idx.v4 {
		if len(entries) == 0 {
			continue
		}
		bucket := make(map[uint32][]bgpObservationCompactRecord, len(entries))
		records := idx.v4Records[bits]
		for _, entry := range entries {
			bucket[entry.key] = append([]bgpObservationCompactRecord(nil), records[entry.start:entry.start+entry.count]...)
		}
		idx.buildV4[bits] = bucket
		idx.v4[bits] = nil
		idx.v4Records[bits] = nil
	}
	for bits, entries := range idx.v6 {
		if len(entries) == 0 {
			continue
		}
		bucket := make(map[[2]uint64][]bgpObservationCompactRecord, len(entries))
		records := idx.v6Records[bits]
		for _, entry := range entries {
			bucket[entry.key] = append([]bgpObservationCompactRecord(nil), records[entry.start:entry.start+entry.count]...)
		}
		idx.buildV6[bits] = bucket
		idx.v6[bits] = nil
		idx.v6Records[bits] = nil
	}
	idx.finalized = false
}

func (idx *BGPObservationIndex) Finalize() {
	if idx == nil || idx.finalized {
		return
	}
	for bits, bucket := range idx.buildV4 {
		if len(bucket) == 0 {
			idx.buildV4[bits] = nil
			continue
		}
		keys := make([]uint32, 0, len(bucket))
		total := 0
		for key, records := range bucket {
			keys = append(keys, key)
			total += len(records)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		entries := make([]bgpObservationV4Entry, 0, len(keys))
		flat := make([]bgpObservationCompactRecord, 0, total)
		for _, key := range keys {
			records := bucket[key]
			start := len(flat)
			flat = append(flat, records...)
			entries = append(entries, bgpObservationV4Entry{key: key, start: uint32(start), count: uint32(len(records))})
		}
		idx.v4[bits] = entries
		idx.v4Records[bits] = flat
		idx.buildV4[bits] = nil
	}
	for bits, bucket := range idx.buildV6 {
		if len(bucket) == 0 {
			idx.buildV6[bits] = nil
			continue
		}
		keys := make([][2]uint64, 0, len(bucket))
		total := 0
		for key, records := range bucket {
			keys = append(keys, key)
			total += len(records)
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i][0] == keys[j][0] {
				return keys[i][1] < keys[j][1]
			}
			return keys[i][0] < keys[j][0]
		})
		entries := make([]bgpObservationV6Entry, 0, len(keys))
		flat := make([]bgpObservationCompactRecord, 0, total)
		for _, key := range keys {
			records := bucket[key]
			start := len(flat)
			flat = append(flat, records...)
			entries = append(entries, bgpObservationV6Entry{key: key, start: uint32(start), count: uint32(len(records))})
		}
		idx.v6[bits] = entries
		idx.v6Records[bits] = flat
		idx.buildV6[bits] = nil
	}
	idx.finalized = true
}

func (idx *BGPObservationIndex) Summarize(query string, asn int) BGPObservationSummary {
	prefix, records := idx.lookup(query)
	if len(records) == 0 {
		return BGPObservationSummary{}
	}
	originCounts := map[int]int{}
	upstreamCounts := map[int]int{}
	total := 0
	for _, record := range records {
		count := int(record.observationCount)
		if count <= 0 {
			count = 1
		}
		originCounts[int(record.originASN)] += count
		if record.dominantUpstream > 0 {
			upstreamCounts[int(record.dominantUpstream)] += count
		}
		total += count
	}
	summary := BGPObservationSummary{
		Prefix:            prefix,
		Visibility:        total,
		Origins:           sortedCounts(originCounts),
		DominantUpstreams: sortedCounts(upstreamCounts),
		Records:           expandBGPObservationRecords(prefix, records),
	}
	if total > 0 {
		summary.OriginAgreement = float64(originCounts[asn]) / float64(total)
	}
	summary.MOAS = len(summary.Origins) > 1
	return summary
}

func (idx *BGPObservationIndex) lookup(query string) (string, []bgpObservationCompactRecord) {
	if idx == nil {
		return "", nil
	}
	if prefix, err := netip.ParsePrefix(query); err == nil {
		prefix = normalizeBGPObservationPrefix(prefix)
		return idx.lookupAddr(prefix.Addr(), prefix.Bits())
	}
	addr, err := netip.ParseAddr(query)
	if err != nil {
		return "", nil
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return idx.lookupAddr(addr, 32)
	}
	if addr.Is6() {
		return idx.lookupAddr(addr, 128)
	}
	return "", nil
}

func normalizeBGPObservationPrefix(prefix netip.Prefix) netip.Prefix {
	prefix = prefix.Masked()
	addr := prefix.Addr()
	if addr.Is4In6() && prefix.Bits() >= 96 {
		return netip.PrefixFrom(addr.Unmap(), prefix.Bits()-96).Masked()
	}
	return prefix
}

func (idx *BGPObservationIndex) lookupAddr(addr netip.Addr, maxBits int) (string, []bgpObservationCompactRecord) {
	if addr.Is4() {
		for bits := minInt(maxBits, 32); bits >= 0; bits-- {
			key := maskIPv4(addr, bits)
			if bucket := idx.buildV4[bits]; len(bucket) > 0 {
				if records := bucket[key]; len(records) > 0 {
					return ipv4PrefixString(key, bits), records
				}
				continue
			}
			entries := idx.v4[bits]
			pos := sort.Search(len(entries), func(i int) bool { return entries[i].key >= key })
			if pos < len(entries) && entries[pos].key == key {
				entry := entries[pos]
				records := idx.v4Records[bits][entry.start : entry.start+entry.count]
				return ipv4PrefixString(key, bits), records
			}
		}
		return "", nil
	}
	for bits := minInt(maxBits, 128); bits >= 0; bits-- {
		key := maskIPv6(addr, bits)
		if bucket := idx.buildV6[bits]; len(bucket) > 0 {
			if records := bucket[key]; len(records) > 0 {
				return ipv6PrefixString(key, bits), records
			}
			continue
		}
		entries := idx.v6[bits]
		pos := sort.Search(len(entries), func(i int) bool {
			if entries[i].key[0] == key[0] {
				return entries[i].key[1] >= key[1]
			}
			return entries[i].key[0] >= key[0]
		})
		if pos < len(entries) && entries[pos].key == key {
			entry := entries[pos]
			records := idx.v6Records[bits][entry.start : entry.start+entry.count]
			return ipv6PrefixString(key, bits), records
		}
	}
	return "", nil
}

func (idx *BGPObservationIndex) Count() int {
	if idx == nil {
		return 0
	}
	return idx.count
}

func SaveBGPObservationIndex(path string, idx *BGPObservationIndex) error {
	if idx == nil {
		idx = NewBGPObservationIndex()
	}
	idx.Finalize()
	if err := os.MkdirAll(filepath.Dir(path), 0o775); err != nil {
		return err
	}
	tmp := path + ".tmp"
	file, err := os.Create(tmp)
	if err != nil {
		return err
	}
	writer := bufio.NewWriterSize(file, 1024*1024)
	if _, err := writer.Write(bgpCompactMagicV2[:]); err != nil {
		_ = file.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := writeBGPCompactUint64(writer, uint64(idx.count)); err != nil {
		_ = file.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := writeBGPCompactUint64(writer, uint64(idx.compactGroupCount())); err != nil {
		_ = file.Close()
		_ = os.Remove(tmp)
		return err
	}
	writeErr := idx.writeCompactRecords(writer)
	flushErr := writer.Flush()
	closeErr := file.Close()
	if writeErr != nil {
		_ = os.Remove(tmp)
		return writeErr
	}
	if flushErr != nil {
		_ = os.Remove(tmp)
		return flushErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	return os.Rename(tmp, path)
}

func LoadBGPObservationIndex(path string) (*BGPObservationIndex, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	reader := bufio.NewReaderSize(file, 1024*1024)
	var magic [8]byte
	if _, err := io.ReadFull(reader, magic[:]); err != nil {
		return nil, err
	}
	total, err := readBGPCompactUint64(reader)
	if err != nil {
		return nil, err
	}
	idx := NewBGPObservationIndex()
	switch magic {
	case bgpCompactMagicV1:
		for i := uint64(0); i < total; i++ {
			if err := idx.readCompactRecord(reader); err != nil {
				return nil, err
			}
		}
		idx.Finalize()
	case bgpCompactMagicV2:
		groups, err := readBGPCompactUint64(reader)
		if err != nil {
			return nil, err
		}
		for i := uint64(0); i < groups; i++ {
			if err := idx.readCompactGroup(reader); err != nil {
				return nil, err
			}
		}
		idx.finalized = true
		if uint64(idx.count) != total {
			return nil, fmt.Errorf("invalid BGP compact index count: got %d want %d", idx.count, total)
		}
	default:
		return nil, fmt.Errorf("invalid BGP compact index magic")
	}
	return idx, nil
}

func BGPObservationIndexVersion(path string) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	var magic [8]byte
	if _, err := io.ReadFull(file, magic[:]); err != nil {
		return 0, err
	}
	switch magic {
	case bgpCompactMagicV1:
		return 1, nil
	case bgpCompactMagicV2:
		return 2, nil
	default:
		return 0, fmt.Errorf("invalid BGP compact index magic")
	}
}

func (idx *BGPObservationIndex) compactGroupCount() int {
	if idx == nil {
		return 0
	}
	count := 0
	for _, entries := range idx.v4 {
		count += len(entries)
	}
	for _, entries := range idx.v6 {
		count += len(entries)
	}
	return count
}

func (idx *BGPObservationIndex) writeCompactRecords(w io.Writer) error {
	for bits, entries := range idx.v4 {
		flat := idx.v4Records[bits]
		for _, entry := range entries {
			records := flat[entry.start : entry.start+entry.count]
			if err := writeBGPCompactGroupHeader(w, 4, uint8(bits), entry.key, [2]uint64{}, uint32(len(records))); err != nil {
				return err
			}
			for _, record := range records {
				if err := writeBGPCompactRecordBody(w, record); err != nil {
					return err
				}
			}
		}
	}
	for bits, entries := range idx.v6 {
		flat := idx.v6Records[bits]
		for _, entry := range entries {
			records := flat[entry.start : entry.start+entry.count]
			if err := writeBGPCompactGroupHeader(w, 6, uint8(bits), 0, entry.key, uint32(len(records))); err != nil {
				return err
			}
			for _, record := range records {
				if err := writeBGPCompactRecordBody(w, record); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (idx *BGPObservationIndex) readCompactRecord(r io.Reader) error {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	family := header[0]
	bits := int(header[1])
	switch family {
	case 4:
		if bits < 0 || bits > 32 {
			return fmt.Errorf("invalid BGP compact IPv4 prefix length %d", bits)
		}
		key, err := readBGPCompactUint32(r)
		if err != nil {
			return err
		}
		record, err := readBGPCompactRecordBody(r)
		if err != nil {
			return err
		}
		if idx.buildV4[bits] == nil {
			idx.buildV4[bits] = map[uint32][]bgpObservationCompactRecord{}
		}
		idx.buildV4[bits][key] = append(idx.buildV4[bits][key], record)
	case 6:
		if bits < 0 || bits > 128 {
			return fmt.Errorf("invalid BGP compact IPv6 prefix length %d", bits)
		}
		hi, err := readBGPCompactUint64(r)
		if err != nil {
			return err
		}
		lo, err := readBGPCompactUint64(r)
		if err != nil {
			return err
		}
		record, err := readBGPCompactRecordBody(r)
		if err != nil {
			return err
		}
		key := [2]uint64{hi, lo}
		if idx.buildV6[bits] == nil {
			idx.buildV6[bits] = map[[2]uint64][]bgpObservationCompactRecord{}
		}
		idx.buildV6[bits][key] = append(idx.buildV6[bits][key], record)
	default:
		return fmt.Errorf("invalid BGP compact address family %d", family)
	}
	idx.count++
	return nil
}

func (idx *BGPObservationIndex) readCompactGroup(r io.Reader) error {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	family := header[0]
	bits := int(header[1])
	switch family {
	case 4:
		if bits < 0 || bits > 32 {
			return fmt.Errorf("invalid BGP compact IPv4 prefix length %d", bits)
		}
		key, err := readBGPCompactUint32(r)
		if err != nil {
			return err
		}
		recordCount, err := readBGPCompactUint32(r)
		if err != nil {
			return err
		}
		start := len(idx.v4Records[bits])
		for i := uint32(0); i < recordCount; i++ {
			record, err := readBGPCompactRecordBody(r)
			if err != nil {
				return err
			}
			idx.v4Records[bits] = append(idx.v4Records[bits], record)
		}
		idx.v4[bits] = append(idx.v4[bits], bgpObservationV4Entry{key: key, start: uint32(start), count: recordCount})
		idx.count += int(recordCount)
	case 6:
		if bits < 0 || bits > 128 {
			return fmt.Errorf("invalid BGP compact IPv6 prefix length %d", bits)
		}
		hi, err := readBGPCompactUint64(r)
		if err != nil {
			return err
		}
		lo, err := readBGPCompactUint64(r)
		if err != nil {
			return err
		}
		recordCount, err := readBGPCompactUint32(r)
		if err != nil {
			return err
		}
		start := len(idx.v6Records[bits])
		for i := uint32(0); i < recordCount; i++ {
			record, err := readBGPCompactRecordBody(r)
			if err != nil {
				return err
			}
			idx.v6Records[bits] = append(idx.v6Records[bits], record)
		}
		idx.v6[bits] = append(idx.v6[bits], bgpObservationV6Entry{key: [2]uint64{hi, lo}, start: uint32(start), count: recordCount})
		idx.count += int(recordCount)
	default:
		return fmt.Errorf("invalid BGP compact address family %d", family)
	}
	return nil
}

func writeBGPCompactGroupHeader(w io.Writer, family uint8, bits uint8, v4 uint32, v6 [2]uint64, recordCount uint32) error {
	if _, err := w.Write([]byte{family, bits}); err != nil {
		return err
	}
	if family == 4 {
		if err := writeBGPCompactUint32(w, v4); err != nil {
			return err
		}
	} else {
		if err := writeBGPCompactUint64(w, v6[0]); err != nil {
			return err
		}
		if err := writeBGPCompactUint64(w, v6[1]); err != nil {
			return err
		}
	}
	return writeBGPCompactUint32(w, recordCount)
}

func writeBGPCompactRecord(w io.Writer, family uint8, bits uint8, v4 uint32, v6 [2]uint64, record bgpObservationCompactRecord) error {
	if err := writeBGPCompactGroupHeader(w, family, bits, v4, v6, 1); err != nil {
		return err
	}
	return writeBGPCompactRecordBody(w, record)
}

func writeBGPCompactRecordBody(w io.Writer, record bgpObservationCompactRecord) error {
	if err := writeBGPCompactUint32(w, record.originASN); err != nil {
		return err
	}
	if err := writeBGPCompactUint32(w, record.observationCount); err != nil {
		return err
	}
	if err := writeBGPCompactUint32(w, record.dominantUpstream); err != nil {
		return err
	}
	if _, err := w.Write([]byte{record.source}); err != nil {
		return err
	}
	return writeBGPCompactUint16(w, record.collectorCount)
}

func readBGPCompactRecordBody(r io.Reader) (bgpObservationCompactRecord, error) {
	originASN, err := readBGPCompactUint32(r)
	if err != nil {
		return bgpObservationCompactRecord{}, err
	}
	observationCount, err := readBGPCompactUint32(r)
	if err != nil {
		return bgpObservationCompactRecord{}, err
	}
	dominantUpstream, err := readBGPCompactUint32(r)
	if err != nil {
		return bgpObservationCompactRecord{}, err
	}
	var source [1]byte
	if _, err := io.ReadFull(r, source[:]); err != nil {
		return bgpObservationCompactRecord{}, err
	}
	collectorCount, err := readBGPCompactUint16(r)
	if err != nil {
		return bgpObservationCompactRecord{}, err
	}
	return bgpObservationCompactRecord{
		originASN:        originASN,
		observationCount: observationCount,
		dominantUpstream: dominantUpstream,
		source:           source[0],
		collectorCount:   collectorCount,
	}, nil
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

func compactBGPObservationRecord(record BGPObservationRecord) bgpObservationCompactRecord {
	count := record.ObservationCount
	if count <= 0 {
		count = 1
	}
	return bgpObservationCompactRecord{
		originASN:        uint32(record.OriginASN),
		observationCount: uint32(count),
		dominantUpstream: uint32(maxInt(record.DominantUpstream, 0)),
		source:           bgpSourceCode(record.Source),
		collectorCount:   bgpCollectorCount(record.Collector),
	}
}

func expandBGPObservationRecords(prefix string, records []bgpObservationCompactRecord) []BGPObservationRecord {
	out := make([]BGPObservationRecord, 0, len(records))
	for _, record := range records {
		source := bgpSourceName(record.source)
		out = append(out, BGPObservationRecord{
			Prefix:           prefix,
			OriginASN:        int(record.originASN),
			Source:           source,
			Collector:        bgpCollectorName(source, record.collectorCount),
			ObservationCount: int(record.observationCount),
			DominantUpstream: int(record.dominantUpstream),
		})
	}
	return out
}

func bgpSourceCode(source string) uint8 {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "routeviews", "route_views":
		return 1
	case "ripe_ris", "ripe-ris", "ris":
		return 2
	default:
		return 0
	}
}

func bgpSourceName(code uint8) string {
	switch code {
	case 1:
		return "routeviews"
	case 2:
		return "ripe_ris"
	default:
		return ""
	}
}

func bgpCollectorCount(collector string) uint16 {
	parts := strings.Split(strings.TrimSpace(collector), ":")
	if len(parts) != 2 {
		return 0
	}
	value, err := strconv.Atoi(parts[1])
	if err != nil || value <= 0 {
		return 0
	}
	if value > int(^uint16(0)) {
		return ^uint16(0)
	}
	return uint16(value)
}

func bgpCollectorName(source string, count uint16) string {
	if source == "" || count == 0 {
		return ""
	}
	return source + ":" + strconv.Itoa(int(count))
}

func ipv4PrefixString(key uint32, bits int) string {
	addr := netip.AddrFrom4([4]byte{byte(key >> 24), byte(key >> 16), byte(key >> 8), byte(key)})
	return netip.PrefixFrom(addr, bits).Masked().String()
}

func ipv6PrefixString(key [2]uint64, bits int) string {
	var raw [16]byte
	binary.BigEndian.PutUint64(raw[0:8], key[0])
	binary.BigEndian.PutUint64(raw[8:16], key[1])
	return netip.PrefixFrom(netip.AddrFrom16(raw), bits).Masked().String()
}

func writeBGPCompactUint16(w io.Writer, value uint16) error {
	var buf [2]byte
	bgpCompactOrder.PutUint16(buf[:], value)
	_, err := w.Write(buf[:])
	return err
}

func writeBGPCompactUint32(w io.Writer, value uint32) error {
	var buf [4]byte
	bgpCompactOrder.PutUint32(buf[:], value)
	_, err := w.Write(buf[:])
	return err
}

func writeBGPCompactUint64(w io.Writer, value uint64) error {
	var buf [8]byte
	bgpCompactOrder.PutUint64(buf[:], value)
	_, err := w.Write(buf[:])
	return err
}

func readBGPCompactUint16(r io.Reader) (uint16, error) {
	var buf [2]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err
	}
	return bgpCompactOrder.Uint16(buf[:]), nil
}

func readBGPCompactUint32(r io.Reader) (uint32, error) {
	var buf [4]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err
	}
	return bgpCompactOrder.Uint32(buf[:]), nil
}

func readBGPCompactUint64(r io.Reader) (uint64, error) {
	var buf [8]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err
	}
	return bgpCompactOrder.Uint64(buf[:]), nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
