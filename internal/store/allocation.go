package store

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

type AllocationRecord struct {
	Prefix   string `json:"prefix"`
	Country  string `json:"country,omitempty"`
	Registry string `json:"registry,omitempty"`
	Status   string `json:"status,omitempty"`
	Source   string `json:"source,omitempty"`
}

type AllocationIndex struct {
	v4    [33]map[uint32]AllocationRecord
	v6    [129]map[[2]uint64]AllocationRecord
	count int
}

func NewAllocationIndex() *AllocationIndex {
	return &AllocationIndex{}
}

func (idx *AllocationIndex) Add(record AllocationRecord) error {
	prefix, err := netip.ParsePrefix(record.Prefix)
	if err != nil {
		return fmt.Errorf("parse allocation prefix %q: %w", record.Prefix, err)
	}

	prefix = prefix.Masked()
	record.Prefix = prefix.String()
	addr := prefix.Addr().Unmap()
	if addr.Is4() {
		bits := prefix.Bits()
		if idx.v4[bits] == nil {
			idx.v4[bits] = make(map[uint32]AllocationRecord)
		}
		idx.v4[bits][maskAllocationIPv4(addr, bits)] = record
	} else {
		bits := prefix.Bits()
		if idx.v6[bits] == nil {
			idx.v6[bits] = make(map[[2]uint64]AllocationRecord)
		}
		idx.v6[bits][maskAllocationIPv6(addr, bits)] = record
	}
	idx.count++
	return nil
}

func (idx *AllocationIndex) Lookup(addr netip.Addr) (AllocationRecord, bool) {
	addr = addr.Unmap()
	if addr.Is4() {
		for bits := 32; bits >= 0; bits-- {
			bucket := idx.v4[bits]
			if bucket == nil {
				continue
			}
			if record, ok := bucket[maskAllocationIPv4(addr, bits)]; ok {
				return record, true
			}
		}
		return AllocationRecord{}, false
	}

	if !addr.Is6() {
		return AllocationRecord{}, false
	}
	for bits := 128; bits >= 0; bits-- {
		bucket := idx.v6[bits]
		if bucket == nil {
			continue
		}
		if record, ok := bucket[maskAllocationIPv6(addr, bits)]; ok {
			return record, true
		}
	}
	return AllocationRecord{}, false
}

func (idx *AllocationIndex) Count() int {
	return idx.count
}

func maskAllocationIPv4(addr netip.Addr, bits int) uint32 {
	raw := addr.As4()
	value := binary.BigEndian.Uint32(raw[:])
	if bits == 0 {
		return 0
	}
	return value & (uint32(0xffffffff) << (32 - bits))
}

func maskAllocationIPv6(addr netip.Addr, bits int) [2]uint64 {
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
