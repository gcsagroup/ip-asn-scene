package perf

import (
	"context"
	"sync"
	"time"
)

type contextKey struct{}

type Report struct {
	TotalMS            int64            `json:"total_ms"`
	LocalOfflineMS     int64            `json:"local_offline_ms"`
	OnlineEnrichmentMS int64            `json:"online_enrichment_ms,omitempty"`
	LocationMS         int64            `json:"location_ms,omitempty"`
	QualityMS          int64            `json:"quality_ms,omitempty"`
	AIMS               int64            `json:"ai_ms,omitempty"`
	CacheHit           bool             `json:"cache_hit,omitempty"`
	RefreshQueued      bool             `json:"refresh_queued,omitempty"`
	RefreshInProgress  bool             `json:"refresh_in_progress,omitempty"`
	ThirdParty         []ThirdPartyCall `json:"third_party,omitempty"`
}

type ThirdPartyCall struct {
	Name       string `json:"name"`
	URL        string `json:"url,omitempty"`
	DurationMS int64  `json:"duration_ms"`
	OK         bool   `json:"ok"`
	Error      string `json:"error,omitempty"`
}

type Recorder struct {
	start time.Time
	mu    sync.Mutex
	data  Report
}

func NewRecorder() *Recorder {
	return &Recorder{start: time.Now()}
}

func WithRecorder(ctx context.Context, recorder *Recorder) context.Context {
	if recorder == nil {
		return ctx
	}
	return context.WithValue(ctx, contextKey{}, recorder)
}

func FromContext(ctx context.Context) *Recorder {
	if ctx == nil {
		return nil
	}
	recorder, _ := ctx.Value(contextKey{}).(*Recorder)
	return recorder
}

func AddPhase(ctx context.Context, name string, duration time.Duration) {
	if recorder := FromContext(ctx); recorder != nil {
		recorder.AddPhase(name, duration)
	}
}

func RecordThirdParty(ctx context.Context, call ThirdPartyCall) {
	if recorder := FromContext(ctx); recorder != nil {
		recorder.AddThirdParty(call)
	}
}

func SetOnlineState(ctx context.Context, cacheHit, refreshQueued, refreshInProgress bool) {
	if recorder := FromContext(ctx); recorder != nil {
		recorder.SetOnlineState(cacheHit, refreshQueued, refreshInProgress)
	}
}

func (r *Recorder) AddPhase(name string, duration time.Duration) {
	if r == nil {
		return
	}
	ms := DurationMS(duration)
	r.mu.Lock()
	defer r.mu.Unlock()
	switch name {
	case "local_offline":
		r.data.LocalOfflineMS += ms
	case "online_enrichment":
		r.data.OnlineEnrichmentMS += ms
	case "location":
		r.data.LocationMS += ms
	case "quality":
		r.data.QualityMS += ms
	case "ai":
		r.data.AIMS += ms
	}
}

func (r *Recorder) AddThirdParty(call ThirdPartyCall) {
	if r == nil || call.Name == "" {
		return
	}
	if call.DurationMS < 0 {
		call.DurationMS = 0
	}
	r.mu.Lock()
	r.data.ThirdParty = append(r.data.ThirdParty, call)
	r.mu.Unlock()
}

func (r *Recorder) SetOnlineState(cacheHit, refreshQueued, refreshInProgress bool) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.data.CacheHit = r.data.CacheHit || cacheHit
	r.data.RefreshQueued = r.data.RefreshQueued || refreshQueued
	r.data.RefreshInProgress = r.data.RefreshInProgress || refreshInProgress
	r.mu.Unlock()
}

func (r *Recorder) Finish(includeThirdParty bool) Report {
	if r == nil {
		return Report{}
	}
	r.mu.Lock()
	report := r.data
	if !includeThirdParty {
		report.ThirdParty = nil
	} else if len(report.ThirdParty) > 0 {
		report.ThirdParty = append([]ThirdPartyCall(nil), report.ThirdParty...)
	}
	report.TotalMS = DurationMS(time.Since(r.start))
	r.mu.Unlock()
	return report
}

func DurationMS(duration time.Duration) int64 {
	if duration <= 0 {
		return 0
	}
	return duration.Milliseconds()
}
