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
	v4    [33]map[uint32]PrefixRecord
	v6    [129]map[[2]uint64]PrefixRecord
	byASN map[int][]PrefixRecord
	count int
}

func NewPrefixIndex() *PrefixIndex {
	return &PrefixIndex{byASN: make(map[int][]PrefixRecord)}
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
	record := PrefixRecord{Prefix: prefix.String(), ASN: asn, Source: source}

	addr := prefix.Addr().Unmap()
	if addr.Is4() {
		bits := prefix.Bits()
		if bits < 0 || bits > 32 {
			return fmt.Errorf("invalid IPv4 prefix length %d", bits)
		}
		if idx.v4[bits] == nil {
			idx.v4[bits] = make(map[uint32]PrefixRecord)
		}
		idx.v4[bits][maskIPv4(addr, bits)] = record
	} else {
		bits := prefix.Bits()
		if bits < 0 || bits > 128 {
			return fmt.Errorf("invalid IPv6 prefix length %d", bits)
		}
		if idx.v6[bits] == nil {
			idx.v6[bits] = make(map[[2]uint64]PrefixRecord)
		}
		idx.v6[bits][maskIPv6(addr, bits)] = record
	}

	idx.byASN[asn] = append(idx.byASN[asn], record)
	idx.count++
	return nil
}

func (idx *PrefixIndex) Lookup(addr netip.Addr) (PrefixRecord, bool) {
	addr = addr.Unmap()
	if addr.Is4() {
		for bits := 32; bits >= 0; bits-- {
			bucket := idx.v4[bits]
			if bucket == nil {
				continue
			}
			if record, ok := bucket[maskIPv4(addr, bits)]; ok {
				return record, true
			}
		}
		return PrefixRecord{}, false
	}

	if !addr.Is6() {
		return PrefixRecord{}, false
	}
	for bits := 128; bits >= 0; bits-- {
		bucket := idx.v6[bits]
		if bucket == nil {
			continue
		}
		if record, ok := bucket[maskIPv6(addr, bits)]; ok {
			return record, true
		}
	}
	return PrefixRecord{}, false
}

func (idx *PrefixIndex) PrefixesForASN(asn int, limit int) []PrefixRecord {
	records := append([]PrefixRecord(nil), idx.byASN[asn]...)
	sort.Slice(records, func(i, j int) bool {
		return records[i].Prefix < records[j].Prefix
	})
	if limit > 0 && len(records) > limit {
		return records[:limit]
	}
	return records
}

func (idx *PrefixIndex) Count() int {
	return idx.count
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
