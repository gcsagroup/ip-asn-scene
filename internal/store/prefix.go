package store

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
)

type PrefixRecord struct {
	Prefix string `json:"prefix"`
	ASN    int    `json:"asn"`
	Source string `json:"source,omitempty"`
}

type PrefixIndex struct {
	v4        [33][]prefixV4Entry
	v6        [129][]prefixV6Entry
	buildV4   [33]map[uint32]prefixCompactRecord
	buildV6   [129]map[[2]uint64]prefixCompactRecord
	byASN     map[int][]prefixASNEntry
	sources   []string
	sourceIDs map[string]uint16
	keepASN   bool
	finalized bool
	count     int
}

type prefixCompactRecord struct {
	ASN    int
	Source uint16
}

type prefixV4Entry struct {
	Key    uint32
	ASN    int
	Source uint16
}

type prefixV6Entry struct {
	Key    [2]uint64
	ASN    int
	Source uint16
}

type prefixASNEntry struct {
	Family uint8
	Bits   uint8
	V4     uint32
	V6     [2]uint64
	Source uint16
}

func NewPrefixIndex() *PrefixIndex {
	return newPrefixIndex(true)
}

func NewLookupOnlyPrefixIndex() *PrefixIndex {
	return newPrefixIndex(false)
}

func newPrefixIndex(keepASN bool) *PrefixIndex {
	idx := &PrefixIndex{
		sourceIDs: map[string]uint16{},
		keepASN:   keepASN,
	}
	if keepASN {
		idx.byASN = map[int][]prefixASNEntry{}
	}
	return idx
}

func (idx *PrefixIndex) Add(prefixText string, asn int, source string) error {
	prefix, err := netip.ParsePrefix(prefixText)
	if err != nil {
		return fmt.Errorf("parse prefix %q: %w", prefixText, err)
	}
	if asn <= 0 {
		return fmt.Errorf("invalid asn %d", asn)
	}

	prefix = prefix.Masked()
	idx.ensureMutable()
	sourceID := idx.sourceID(source)
	record := prefixCompactRecord{ASN: asn, Source: sourceID}

	addr := prefix.Addr().Unmap()
	if addr.Is4() {
		bits := prefix.Bits()
		if bits < 0 || bits > 32 {
			return fmt.Errorf("invalid IPv4 prefix length %d", bits)
		}
		if idx.buildV4[bits] == nil {
			idx.buildV4[bits] = make(map[uint32]prefixCompactRecord)
		}
		key := maskIPv4(addr, bits)
		idx.buildV4[bits][key] = record
		if idx.keepASN {
			idx.byASN[asn] = append(idx.byASN[asn], prefixASNEntry{Family: 4, Bits: uint8(bits), V4: key, Source: sourceID})
		}
	} else {
		bits := prefix.Bits()
		if bits < 0 || bits > 128 {
			return fmt.Errorf("invalid IPv6 prefix length %d", bits)
		}
		if idx.buildV6[bits] == nil {
			idx.buildV6[bits] = make(map[[2]uint64]prefixCompactRecord)
		}
		key := maskIPv6(addr, bits)
		idx.buildV6[bits][key] = record
		if idx.keepASN {
			idx.byASN[asn] = append(idx.byASN[asn], prefixASNEntry{Family: 6, Bits: uint8(bits), V6: key, Source: sourceID})
		}
	}

	idx.count++
	idx.finalized = false
	return nil
}

func (idx *PrefixIndex) Lookup(addr netip.Addr) (PrefixRecord, bool) {
	if idx == nil {
		return PrefixRecord{}, false
	}
	addr = addr.Unmap()
	if addr.Is4() {
		for bits := 32; bits >= 0; bits-- {
			key := maskIPv4(addr, bits)
			if bucket := idx.buildV4[bits]; len(bucket) > 0 {
				if record, ok := bucket[key]; ok {
					return idx.prefixRecordFromV4(key, bits, record), true
				}
				continue
			}
			entries := idx.v4[bits]
			pos := sort.Search(len(entries), func(i int) bool { return entries[i].Key >= key })
			if pos < len(entries) && entries[pos].Key == key {
				entry := entries[pos]
				return idx.prefixRecordFromV4(key, bits, prefixCompactRecord{ASN: entry.ASN, Source: entry.Source}), true
			}
		}
		return PrefixRecord{}, false
	}

	if !addr.Is6() {
		return PrefixRecord{}, false
	}
	for bits := 128; bits >= 0; bits-- {
		key := maskIPv6(addr, bits)
		if bucket := idx.buildV6[bits]; len(bucket) > 0 {
			if record, ok := bucket[key]; ok {
				return idx.prefixRecordFromV6(key, bits, record), true
			}
			continue
		}
		entries := idx.v6[bits]
		pos := sort.Search(len(entries), func(i int) bool {
			if entries[i].Key[0] == key[0] {
				return entries[i].Key[1] >= key[1]
			}
			return entries[i].Key[0] >= key[0]
		})
		if pos < len(entries) && entries[pos].Key == key {
			entry := entries[pos]
			return idx.prefixRecordFromV6(key, bits, prefixCompactRecord{ASN: entry.ASN, Source: entry.Source}), true
		}
	}
	return PrefixRecord{}, false
}

func (idx *PrefixIndex) PrefixesForASN(asn int, limit int) []PrefixRecord {
	if idx == nil || len(idx.byASN) == 0 {
		return nil
	}
	entries := idx.byASN[asn]
	records := make([]PrefixRecord, 0, len(entries))
	for _, entry := range entries {
		switch entry.Family {
		case 4:
			records = append(records, PrefixRecord{
				Prefix: ipv4PrefixString(entry.V4, int(entry.Bits)),
				ASN:    asn,
				Source: idx.sourceName(entry.Source),
			})
		case 6:
			records = append(records, PrefixRecord{
				Prefix: ipv6PrefixString(entry.V6, int(entry.Bits)),
				ASN:    asn,
				Source: idx.sourceName(entry.Source),
			})
		}
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].Prefix < records[j].Prefix
	})
	if limit > 0 && len(records) > limit {
		return records[:limit]
	}
	return records
}

func (idx *PrefixIndex) Count() int {
	if idx == nil {
		return 0
	}
	return idx.count
}

func (idx *PrefixIndex) Finalize() {
	if idx == nil || idx.finalized {
		return
	}
	for bits, bucket := range idx.buildV4 {
		if len(bucket) == 0 {
			idx.buildV4[bits] = nil
			continue
		}
		keys := make([]uint32, 0, len(bucket))
		for key := range bucket {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		entries := make([]prefixV4Entry, 0, len(keys))
		for _, key := range keys {
			record := bucket[key]
			entries = append(entries, prefixV4Entry{Key: key, ASN: record.ASN, Source: record.Source})
		}
		idx.v4[bits] = entries
		idx.buildV4[bits] = nil
	}
	for bits, bucket := range idx.buildV6 {
		if len(bucket) == 0 {
			idx.buildV6[bits] = nil
			continue
		}
		keys := make([][2]uint64, 0, len(bucket))
		for key := range bucket {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i][0] == keys[j][0] {
				return keys[i][1] < keys[j][1]
			}
			return keys[i][0] < keys[j][0]
		})
		entries := make([]prefixV6Entry, 0, len(keys))
		for _, key := range keys {
			record := bucket[key]
			entries = append(entries, prefixV6Entry{Key: key, ASN: record.ASN, Source: record.Source})
		}
		idx.v6[bits] = entries
		idx.buildV6[bits] = nil
	}
	idx.finalized = true
}

func (idx *PrefixIndex) ensureMutable() {
	if idx == nil || !idx.finalized {
		return
	}
	for bits, entries := range idx.v4 {
		if len(entries) == 0 {
			continue
		}
		bucket := make(map[uint32]prefixCompactRecord, len(entries))
		for _, entry := range entries {
			bucket[entry.Key] = prefixCompactRecord{ASN: entry.ASN, Source: entry.Source}
		}
		idx.buildV4[bits] = bucket
		idx.v4[bits] = nil
	}
	for bits, entries := range idx.v6 {
		if len(entries) == 0 {
			continue
		}
		bucket := make(map[[2]uint64]prefixCompactRecord, len(entries))
		for _, entry := range entries {
			bucket[entry.Key] = prefixCompactRecord{ASN: entry.ASN, Source: entry.Source}
		}
		idx.buildV6[bits] = bucket
		idx.v6[bits] = nil
	}
	idx.finalized = false
}

func (idx *PrefixIndex) prefixRecordFromV4(key uint32, bits int, record prefixCompactRecord) PrefixRecord {
	return PrefixRecord{
		Prefix: ipv4PrefixString(key, bits),
		ASN:    record.ASN,
		Source: idx.sourceName(record.Source),
	}
}

func (idx *PrefixIndex) prefixRecordFromV6(key [2]uint64, bits int, record prefixCompactRecord) PrefixRecord {
	return PrefixRecord{
		Prefix: ipv6PrefixString(key, bits),
		ASN:    record.ASN,
		Source: idx.sourceName(record.Source),
	}
}

func (idx *PrefixIndex) sourceID(source string) uint16 {
	if source == "" {
		return 0
	}
	if id, ok := idx.sourceIDs[source]; ok {
		return id
	}
	id := uint16(len(idx.sources) + 1)
	idx.sources = append(idx.sources, source)
	idx.sourceIDs[source] = id
	return id
}

func (idx *PrefixIndex) sourceName(id uint16) string {
	if idx == nil || id == 0 || int(id) > len(idx.sources) {
		return ""
	}
	return idx.sources[id-1]
}

func maskIPv4(addr netip.Addr, bits int) uint32 {
	raw := addr.As4()
	value := binary.BigEndian.Uint32(raw[:])
	if bits == 0 {
		return 0
	}
	return value & (uint32(0xffffffff) << (32 - bits))
}

func maskIPv6(addr netip.Addr, bits int) [2]uint64 {
	raw := addr.As16()
	hi := binary.BigEndian.Uint64(raw[0:8])
	lo := binary.BigEndian.Uint64(raw[8:16])

	switch {
	case bits <= 0:
		return [2]uint64{0, 0}
	case bits < 64:
		return [2]uint64{hi & (uint64(0xffffffffffffffff) << (64 - bits)), 0}
	case bits == 64:
		return [2]uint64{hi, 0}
	case bits < 128:
		return [2]uint64{hi, lo & (uint64(0xffffffffffffffff) << (128 - bits))}
	default:
		return [2]uint64{hi, lo}
	}
}
