package store

import "time"

type Status struct {
	Version             string            `json:"version"`
	Loaded              bool              `json:"loaded"`
	Updating            bool              `json:"updating"`
	UpdateProgress      *UpdateProgress   `json:"update_progress,omitempty"`
	UpdatedAt           time.Time         `json:"updated_at,omitempty"`
	PrefixCount         int               `json:"prefix_count"`
	AllocationCount     int               `json:"allocation_count"`
	ASNCount            int               `json:"asn_count"`
	EgressASNCount      int               `json:"egress_asn_count,omitempty"`
	RPKICount           int               `json:"rpki_count,omitempty"`
	IRRRouteCount       int               `json:"irr_route_count,omitempty"`
	BGPObservationCount int               `json:"bgp_observation_count,omitempty"`
	HistorySnapshots    int               `json:"history_snapshots,omitempty"`
	HistoryPrefixCount  int               `json:"history_prefix_count,omitempty"`
	DataDir             string            `json:"data_dir,omitempty"`
	DataDirSize         string            `json:"data_dir_size,omitempty"`
	DataDirSizeBytes    int64             `json:"data_dir_size_bytes,omitempty"`
	DataDirFileCount    int               `json:"data_dir_file_count,omitempty"`
	RawFiles            map[string]string `json:"raw_files,omitempty"`
	LastError           string            `json:"last_error,omitempty"`
	LastDuration        string            `json:"last_duration,omitempty"`
}

type UpdateProgress struct {
	Active         bool                 `json:"active"`
	StartedAt      time.Time            `json:"started_at,omitempty"`
	FinishedAt     time.Time            `json:"finished_at,omitempty"`
	Duration       string               `json:"duration,omitempty"`
	CurrentStep    string               `json:"current_step,omitempty"`
	CurrentDetail  string               `json:"current_detail,omitempty"`
	LastStep       string               `json:"last_step,omitempty"`
	LastError      string               `json:"last_error,omitempty"`
	CompletedSteps int                  `json:"completed_steps"`
	TotalSteps     int                  `json:"total_steps"`
	Percent        int                  `json:"percent"`
	Steps          []UpdateStepProgress `json:"steps,omitempty"`
}

type UpdateStepProgress struct {
	Index      int       `json:"index"`
	Name       string    `json:"name"`
	Status     string    `json:"status"`
	Detail     string    `json:"detail,omitempty"`
	StartedAt  time.Time `json:"started_at,omitempty"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	Duration   string    `json:"duration,omitempty"`
}

type Snapshot struct {
	Prefixes    *PrefixIndex
	Allocations *AllocationIndex
	ASNs        *ASNIndex
	Egress      *EgressIndex
	Reliability *ReliabilityIndex
	History     *HistoryIndex
	Status      Status
}

func NewSnapshot(prefixes *PrefixIndex, asns *ASNIndex, status Status) *Snapshot {
	return NewSnapshotWithAllocations(prefixes, NewAllocationIndex(), asns, status)
}

func NewSnapshotWithAllocations(prefixes *PrefixIndex, allocations *AllocationIndex, asns *ASNIndex, status Status) *Snapshot {
	return NewSnapshotFull(prefixes, allocations, asns, nil, status)
}

func NewSnapshotFull(prefixes *PrefixIndex, allocations *AllocationIndex, asns *ASNIndex, history *HistoryIndex, status Status) *Snapshot {
	return NewSnapshotFullWithEgress(prefixes, allocations, asns, history, NewEgressIndex(), status)
}

func NewSnapshotFullWithEgress(prefixes *PrefixIndex, allocations *AllocationIndex, asns *ASNIndex, history *HistoryIndex, egress *EgressIndex, status Status) *Snapshot {
	return NewSnapshotFullWithReliability(prefixes, allocations, asns, history, egress, NewReliabilityIndex(), status)
}

func NewSnapshotFullWithReliability(prefixes *PrefixIndex, allocations *AllocationIndex, asns *ASNIndex, history *HistoryIndex, egress *EgressIndex, reliability *ReliabilityIndex, status Status) *Snapshot {
	if prefixes == nil {
		prefixes = NewPrefixIndex()
	}
	if allocations == nil {
		allocations = NewAllocationIndex()
	}
	if asns == nil {
		asns = NewASNIndex()
	}
	if history == nil {
		history = NewHistoryIndex()
	}
	if egress == nil {
		egress = NewEgressIndex()
	}
	if reliability == nil {
		reliability = NewReliabilityIndex()
	}
	if reliability.RPKI == nil {
		reliability.RPKI = NewRPKIIndex()
	}
	if reliability.IRR == nil {
		reliability.IRR = NewIRRIndex()
	}
	if reliability.BGP == nil {
		reliability.BGP = NewBGPObservationIndex()
	}
	status.Loaded = true
	status.PrefixCount = prefixes.Count()
	status.AllocationCount = allocations.Count()
	status.ASNCount = asns.Count()
	status.EgressASNCount = egress.Count()
	status.RPKICount = reliability.RPKI.Count()
	status.IRRRouteCount = reliability.IRR.Count()
	status.BGPObservationCount = reliability.BGP.Count()
	status.HistorySnapshots = history.SnapshotCount()
	status.HistoryPrefixCount = history.PrefixCount()
	return &Snapshot{Prefixes: prefixes, Allocations: allocations, ASNs: asns, Egress: egress, Reliability: reliability, History: history, Status: status}
}

func EmptySnapshot() *Snapshot {
	return NewSnapshot(NewPrefixIndex(), NewASNIndex(), Status{Version: "empty"})
}
