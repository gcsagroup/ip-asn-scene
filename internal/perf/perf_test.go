package perf

import (
	"testing"
	"time"
)

func TestRecorderBuildsReport(t *testing.T) {
	recorder := NewRecorder()
	recorder.AddPhase("local_offline", 2*time.Millisecond)
	recorder.AddPhase("online_enrichment", 5*time.Millisecond)
	recorder.SetOnlineState(true, false, false)
	recorder.AddThirdParty(ThirdPartyCall{
		Name:       "ripestat_prefix",
		URL:        "https://stat.ripe.net/data/prefix-overview/data.json?resource=8.8.8.8",
		DurationMS: 3,
		OK:         true,
	})

	report := recorder.Finish(true)
	if report.TotalMS < 0 {
		t.Fatalf("expected total duration, got %#v", report)
	}
	if report.LocalOfflineMS != 2 || report.OnlineEnrichmentMS != 5 {
		t.Fatalf("unexpected phase durations: %#v", report)
	}
	if !report.CacheHit {
		t.Fatalf("expected cache hit flag: %#v", report)
	}
	if len(report.ThirdParty) != 1 || report.ThirdParty[0].Name != "ripestat_prefix" || report.ThirdParty[0].DurationMS != 3 {
		t.Fatalf("unexpected third-party timings: %#v", report.ThirdParty)
	}

	withoutThirdParty := recorder.Finish(false)
	if len(withoutThirdParty.ThirdParty) != 0 {
		t.Fatalf("expected third-party timings to be hidden: %#v", withoutThirdParty.ThirdParty)
	}
}
