package update

import (
	"testing"

	"ipasn/internal/config"
)

func TestManagerProgressTracksSteps(t *testing.T) {
	m := NewManager(config.Config{})
	m.startProgress([]string{"下载基础离线库", "加载离线索引"})
	m.setProgressStep(0, "正在下载 CAIDA / RIR / PeeringDB")

	status := m.Status()
	if status.UpdateProgress == nil {
		t.Fatal("expected update progress in status")
	}
	if !status.UpdateProgress.Active || status.UpdateProgress.TotalSteps != 2 || status.UpdateProgress.CompletedSteps != 0 {
		t.Fatalf("unexpected active progress: %#v", status.UpdateProgress)
	}
	if status.UpdateProgress.CurrentStep != "下载基础离线库" || status.UpdateProgress.CurrentDetail != "正在下载 CAIDA / RIR / PeeringDB" {
		t.Fatalf("unexpected current step: %#v", status.UpdateProgress)
	}
	if status.UpdateProgress.Percent <= 0 || status.UpdateProgress.Percent >= 100 {
		t.Fatalf("expected in-progress percent, got %#v", status.UpdateProgress)
	}

	m.completeProgressStep(0, "基础数据下载完成")
	m.setProgressStep(1, "正在加载索引")
	status = m.Status()
	if status.UpdateProgress.CompletedSteps != 1 || status.UpdateProgress.CurrentStep != "加载离线索引" {
		t.Fatalf("unexpected second step progress: %#v", status.UpdateProgress)
	}
	if status.UpdateProgress.Steps[0].Status != "done" || status.UpdateProgress.Steps[1].Status != "running" {
		t.Fatalf("unexpected step statuses: %#v", status.UpdateProgress.Steps)
	}

	m.finishProgress("")
	status = m.Status()
	if status.UpdateProgress.Active || status.UpdateProgress.Percent != 100 || status.UpdateProgress.LastError != "" {
		t.Fatalf("expected completed progress: %#v", status.UpdateProgress)
	}
}

func TestManagerProgressRecordsFailure(t *testing.T) {
	m := NewManager(config.Config{})
	m.startProgress([]string{"下载基础离线库"})
	m.setProgressStep(0, "正在下载")
	m.finishProgress("download failed")

	status := m.Status()
	if status.UpdateProgress == nil {
		t.Fatal("expected update progress in status")
	}
	if status.UpdateProgress.Active || status.UpdateProgress.LastError != "download failed" || status.UpdateProgress.Steps[0].Status != "failed" {
		t.Fatalf("expected failed progress: %#v", status.UpdateProgress)
	}
}
