package update

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"ipasn/internal/config"
	"ipasn/internal/firewall"
	"ipasn/internal/store"
)

const refreshCooldown = 10 * time.Minute

var generateFirewallLists = firewall.GenerateFromIP2Region

type Manager struct {
	mu         sync.RWMutex
	cfg        config.Config
	downloader *Downloader
	snapshot   atomic.Pointer[store.Snapshot]
	updating   atomic.Bool
	lastError  atomic.Value

	progressMu sync.RWMutex
	progress   *store.UpdateProgress

	diskMu          sync.Mutex
	diskCachedAt    time.Time
	diskCachedDir   string
	diskSizeBytes   int64
	diskFileCount   int
	diskSizeDisplay string
}

func NewManager(cfg config.Config) *Manager {
	m := &Manager{cfg: cfg, downloader: NewDownloader(cfg.HTTPTimeout)}
	if snap, err := BuildSnapshot(cfg); err == nil {
		m.snapshot.Store(snap)
	} else {
		m.snapshot.Store(store.EmptySnapshot())
		m.lastError.Store(err.Error())
	}
	return m
}

func (m *Manager) Snapshot() *store.Snapshot {
	return m.snapshot.Load()
}

func (m *Manager) Status() store.Status {
	status := m.Snapshot().Status
	status.Updating = m.updating.Load()
	status.UpdateProgress = m.progressSnapshot()
	if value := m.lastError.Load(); value != nil {
		status.LastError, _ = value.(string)
	}
	m.applyDataDirStats(&status)
	return status
}

func (m *Manager) Config() config.Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg
}

func (m *Manager) UpdateConfig(cfg config.Config) error {
	m.mu.Lock()
	path := cfg.ConfigPath
	if path == "" {
		path = m.cfg.ConfigPath
	}
	if path == "" {
		path = "config.yaml"
	}
	cfg.ConfigPath = path
	if err := config.SaveToFile(path, cfg); err != nil {
		m.mu.Unlock()
		return err
	}
	m.cfg = cfg
	m.mu.Unlock()
	return nil
}

func (m *Manager) Refresh(ctx context.Context) error {
	if !m.updating.CompareAndSwap(false, true) {
		return nil
	}
	defer m.updating.Store(false)

	start := time.Now()
	cfg := m.Config()
	steps := []string{
		"下载基础离线库",
		"生成动态服务规则",
		"更新 IP 所在地库",
		"构建全量 BGP 汇总",
		"加载离线索引",
		"生成防火墙 CIDR 列表",
	}
	m.startProgress(steps)
	fail := func(err error) error {
		m.lastError.Store(err.Error())
		m.finishProgress(err.Error())
		return err
	}

	m.setProgressStep(0, "下载 CAIDA、RIR、PeeringDB、IANA RDAP、RPKI/IRR/Geofeed 等基础公开数据")
	if _, err := m.downloader.DownloadAll(ctx, cfg); err != nil {
		return fail(err)
	}
	m.completeProgressStep(0, "基础离线库下载完成")

	m.setProgressStep(1, "更新爬虫、Tor、邮件、监控、云厂商、CDN、Proxy/VPN 等动态规则")
	if _, err := RefreshDynamicServiceRules(ctx, cfg); err != nil {
		return fail(err)
	}
	m.completeProgressStep(1, "动态服务规则生成完成")

	m.setProgressStep(2, "检查并下载 ip2region IPv4/IPv6 全载库")
	if _, err := RefreshIP2Region(ctx, cfg); err != nil {
		return fail(err)
	}
	if cfg.IP2Region.Enabled {
		m.completeProgressStep(2, "IP 所在地库检查完成")
	} else {
		m.completeProgressStep(2, "IP 所在地库未启用，已跳过")
	}

	m.setProgressStep(3, "发现 RouteViews / RIPE RIS collector，下载并解析 MRT RIB")
	if skip, detail := shouldSkipFreshBGPSummary(cfg, time.Now()); skip {
		if err := ensureBGPCompactIndex(cfg); err != nil {
			return fail(err)
		}
		m.completeProgressStep(3, detail)
	} else if _, err := RefreshFullBGP(ctx, cfg, m.downloader.client); err != nil {
		return fail(err)
	} else if cfg.BGP.Enabled && cfg.BGP.Mode == "full" {
		m.completeProgressStep(3, "全量 BGP 汇总生成完成")
	} else {
		m.completeProgressStep(3, "全量 BGP 未启用，已跳过")
	}

	m.setProgressStep(4, "解析本地 raw/generated 数据并热加载索引")
	snapshot, err := BuildSnapshot(cfg)
	if err != nil {
		return fail(err)
	}
	snapshot.Status.LastDuration = time.Since(start).String()
	m.snapshot.Store(snapshot)
	m.lastError.Store("")
	m.completeProgressStep(4, fmt.Sprintf("索引加载完成：前缀 %d，ASN %d", snapshot.Status.PrefixCount, snapshot.Status.ASNCount))

	m.setProgressStep(5, "根据 ip2region、ASN、服务规则生成防火墙 CIDR 输出")
	if summary, err := refreshFirewallLists(ctx, cfg, snapshot); err != nil {
		return fail(err)
	} else if cfg.FirewallLists.Enabled && cfg.IP2Region.Enabled {
		m.completeProgressStep(5, fmt.Sprintf("防火墙列表生成完成：文件 %d，导出记录 %d", len(summary.Files), summary.ExportedRecord))
	} else if !cfg.FirewallLists.Enabled {
		m.completeProgressStep(5, "防火墙列表未启用，已跳过")
	} else {
		m.completeProgressStep(5, "IP 所在地库未启用，防火墙列表已跳过")
	}

	m.finishProgress("")
	return nil
}

func refreshFirewallLists(ctx context.Context, cfg config.Config, snapshot *store.Snapshot) (firewall.Summary, error) {
	if !cfg.FirewallLists.Enabled || !cfg.IP2Region.Enabled {
		return firewall.Summary{}, nil
	}
	return generateFirewallLists(ctx, cfg, snapshot)
}

func (m *Manager) StartAutoUpdate(ctx context.Context) {
	cfg := m.Config()
	if cfg.UpdateInterval <= 0 {
		return
	}
	ticker := time.NewTicker(cfg.UpdateInterval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = m.Refresh(ctx)
			}
		}
	}()
}

func (m *Manager) startProgress(steps []string) {
	now := time.Now()
	progress := &store.UpdateProgress{
		Active:     true,
		StartedAt:  now,
		TotalSteps: len(steps),
		Percent:    1,
		Steps:      make([]store.UpdateStepProgress, 0, len(steps)),
	}
	for index, name := range steps {
		progress.Steps = append(progress.Steps, store.UpdateStepProgress{
			Index:  index,
			Name:   name,
			Status: "pending",
		})
	}
	m.progressMu.Lock()
	m.progress = progress
	m.progressMu.Unlock()
}

func (m *Manager) setProgressStep(index int, detail string) {
	m.progressMu.Lock()
	defer m.progressMu.Unlock()
	if m.progress == nil || index < 0 || index >= len(m.progress.Steps) {
		return
	}
	now := time.Now()
	step := &m.progress.Steps[index]
	step.Status = "running"
	step.Detail = detail
	if step.StartedAt.IsZero() {
		step.StartedAt = now
	}
	m.progress.CurrentStep = step.Name
	m.progress.CurrentDetail = detail
	m.recalculateProgressLocked()
}

func (m *Manager) completeProgressStep(index int, detail string) {
	m.progressMu.Lock()
	defer m.progressMu.Unlock()
	if m.progress == nil || index < 0 || index >= len(m.progress.Steps) {
		return
	}
	now := time.Now()
	step := &m.progress.Steps[index]
	step.Status = "done"
	step.Detail = detail
	if step.StartedAt.IsZero() {
		step.StartedAt = now
	}
	step.FinishedAt = now
	step.Duration = durationSince(step.StartedAt, now)
	m.progress.CurrentStep = step.Name
	m.progress.CurrentDetail = detail
	m.progress.LastStep = step.Name
	m.recalculateProgressLocked()
}

func (m *Manager) finishProgress(lastError string) {
	m.progressMu.Lock()
	defer m.progressMu.Unlock()
	if m.progress == nil {
		return
	}
	now := time.Now()
	m.progress.Active = false
	m.progress.FinishedAt = now
	m.progress.Duration = durationSince(m.progress.StartedAt, now)
	m.progress.LastError = lastError
	if lastError != "" {
		for index := range m.progress.Steps {
			step := &m.progress.Steps[index]
			if step.Status == "running" {
				step.Status = "failed"
				step.Detail = lastError
				step.FinishedAt = now
				step.Duration = durationSince(step.StartedAt, now)
				m.progress.CurrentStep = step.Name
				m.progress.CurrentDetail = lastError
				break
			}
		}
		m.recalculateProgressLocked()
		return
	}
	for index := range m.progress.Steps {
		step := &m.progress.Steps[index]
		if step.Status == "running" {
			step.Status = "done"
			step.FinishedAt = now
			step.Duration = durationSince(step.StartedAt, now)
		}
	}
	m.progress.CompletedSteps = m.progress.TotalSteps
	m.progress.Percent = 100
	m.progress.CurrentStep = "完成"
	m.progress.CurrentDetail = "离线库更新完成"
}

func (m *Manager) progressSnapshot() *store.UpdateProgress {
	m.progressMu.RLock()
	defer m.progressMu.RUnlock()
	if m.progress == nil {
		return nil
	}
	copyValue := *m.progress
	if len(m.progress.Steps) > 0 {
		copyValue.Steps = append([]store.UpdateStepProgress(nil), m.progress.Steps...)
	}
	return &copyValue
}

func (m *Manager) recalculateProgressLocked() {
	if m.progress == nil || m.progress.TotalSteps <= 0 {
		return
	}
	completed := 0
	running := false
	for _, step := range m.progress.Steps {
		if step.Status == "done" {
			completed++
		}
		if step.Status == "running" {
			running = true
		}
	}
	m.progress.CompletedSteps = completed
	percent := completed * 100 / m.progress.TotalSteps
	if m.progress.Active && running && percent < 99 {
		percent++
	}
	m.progress.Percent = percent
}

func durationSince(start, end time.Time) string {
	if start.IsZero() || end.IsZero() || end.Before(start) {
		return ""
	}
	return end.Sub(start).Round(time.Millisecond).String()
}

func (m *Manager) applyDataDirStats(status *store.Status) {
	dataDir := status.DataDir
	if dataDir == "" {
		dataDir = m.Config().DataDir
	}
	if dataDir == "" {
		return
	}

	now := time.Now()
	m.diskMu.Lock()
	defer m.diskMu.Unlock()
	if dataDir == m.diskCachedDir && now.Sub(m.diskCachedAt) < 3*time.Second {
		status.DataDir = dataDir
		status.DataDirSizeBytes = m.diskSizeBytes
		status.DataDirFileCount = m.diskFileCount
		status.DataDirSize = m.diskSizeDisplay
		return
	}
	sizeBytes, fileCount, err := dataDirStats(dataDir)
	if err != nil {
		status.DataDir = dataDir
		return
	}
	m.diskCachedAt = now
	m.diskCachedDir = dataDir
	m.diskSizeBytes = sizeBytes
	m.diskFileCount = fileCount
	m.diskSizeDisplay = humanBytes(sizeBytes)
	status.DataDir = dataDir
	status.DataDirSizeBytes = sizeBytes
	status.DataDirFileCount = fileCount
	status.DataDirSize = m.diskSizeDisplay
}

func dataDirStats(root string) (int64, int, error) {
	var sizeBytes int64
	var fileCount int
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return nil
		}
		sizeBytes += info.Size()
		fileCount++
		return nil
	})
	return sizeBytes, fileCount, err
}

func humanBytes(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	value := float64(size)
	for _, suffix := range []string{"KB", "MB", "GB", "TB"} {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.2f %s", value, suffix)
		}
	}
	return fmt.Sprintf("%.2f PB", value/unit)
}
