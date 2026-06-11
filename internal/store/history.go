package store

import "net/netip"

type HistoryRecord struct {
	Label  string `json:"label,omitempty"`
	Prefix string `json:"prefix"`
	ASN    int    `json:"asn"`
	Source string `json:"source,omitempty"`
}

type HistorySnapshot struct {
	Label    string
	Prefixes *PrefixIndex
}

type HistoryIndex struct {
	snapshots   []HistorySnapshot
	prefixCount int
}

func NewHistoryIndex() *HistoryIndex {
	return &HistoryIndex{}
}

func (idx *HistoryIndex) AddSnapshot(label string, prefixes *PrefixIndex) {
	if idx == nil || prefixes == nil || prefixes.Count() == 0 {
		return
	}
	idx.snapshots = append(idx.snapshots, HistorySnapshot{Label: label, Prefixes: prefixes})
	idx.prefixCount += prefixes.Count()
}

func (idx *HistoryIndex) Lookup(addr netip.Addr, limit int) []HistoryRecord {
	if idx == nil {
		return nil
	}
	out := []HistoryRecord{}
	for i := len(idx.snapshots) - 1; i >= 0; i-- {
		snapshot := idx.snapshots[i]
		record, ok := snapshot.Prefixes.Lookup(addr)
		if !ok {
			continue
		}
		out = append(out, HistoryRecord{
			Label:  snapshot.Label,
			Prefix: record.Prefix,
			ASN:    record.ASN,
			Source: record.Source,
		})
		if limit > 0 && len(out) >= limit {
			return out
		}
	}
	return out
}

func (idx *HistoryIndex) SnapshotCount() int {
	if idx == nil {
		return 0
	}
	return len(idx.snapshots)
}

func (idx *HistoryIndex) PrefixCount() int {
	if idx == nil {
		return 0
	}
	return idx.prefixCount
}
