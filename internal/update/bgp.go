package update

import (
	"bufio"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/osrg/gobgp/v3/pkg/packet/mrt"
	"ipasn/internal/config"
	"ipasn/internal/store"
)

const bgpDownloadMaxAttempts = 4

var bgpDownloadRetryDelay = 2 * time.Second

type bgpRefreshState struct {
	Version       int       `json:"version"`
	SummaryFile   string    `json:"summary_file"`
	LastSuccessAt time.Time `json:"last_success_at,omitempty"`
	LastErrorAt   time.Time `json:"last_error_at,omitempty"`
	LastError     string    `json:"last_error,omitempty"`
	SourceCount   int       `json:"source_count,omitempty"`
}

type BGPRIBSource struct {
	Source    string `json:"source"`
	Collector string `json:"collector"`
	URL       string `json:"url"`
}

type BGPObservationInput struct {
	Prefix           string
	OriginASN        int
	Source           string
	Collector        string
	DominantUpstream int
}

func RefreshFullBGP(ctx context.Context, cfg config.Config, client *http.Client) (int, error) {
	if !cfg.BGP.Enabled || strings.ToLower(strings.TrimSpace(cfg.BGP.Mode)) != "full" {
		return 0, nil
	}
	if client == nil {
		client = http.DefaultClient
	}
	if skip, _ := shouldSkipFreshBGPSummary(cfg, time.Now()); skip {
		if err := ensureBGPCompactIndex(cfg); err != nil {
			recordBGPRefreshError(cfg, err)
			return 0, err
		}
		return 0, nil
	}
	sources, err := DiscoverBGPRIBSources(ctx, client, cfg.BGP)
	if err != nil {
		recordBGPRefreshError(cfg, err)
		return 0, err
	}
	rawDir := filepath.Join(cfg.DataDir, "raw", "bgp")
	downloaded, err := downloadBGPSources(ctx, client, rawDir, sources, cfg.BGP.MaxParallelDownloads, cfg.BGP.DownloadTimeout)
	if err != nil {
		recordBGPRefreshError(cfg, err)
		return 0, err
	}
	aggregator, err := parseBGPSources(ctx, downloaded, cfg.BGP.MaxParallelParse)
	if err != nil {
		recordBGPRefreshError(cfg, err)
		return 0, err
	}
	if !cfg.BGP.KeepRaw {
		for _, item := range downloaded {
			_ = os.Remove(item.Path)
		}
	}
	summaryPath := resolveDataPath(cfg.DataDir, cfg.BGP.SummaryFile)
	if err := writeBGPRecords(summaryPath, aggregator.records()); err != nil {
		recordBGPRefreshError(cfg, err)
		return 0, err
	}
	if err := ensureBGPCompactIndex(cfg); err != nil {
		recordBGPRefreshError(cfg, err)
		return 0, err
	}
	recordBGPRefreshSuccess(cfg, len(sources))
	pruneBGPRawFiles(rawDir, cfg.BGP.RawRetentionDays)
	return len(sources), nil
}

func ensureBGPCompactIndex(cfg config.Config) error {
	if !bgpCompactIndexEnabled(cfg.BGP) {
		return nil
	}
	summaryPath := resolveDataPath(cfg.DataDir, cfg.BGP.SummaryFile)
	indexPath := resolveDataPath(cfg.DataDir, cfg.BGP.IndexFile)
	if strings.TrimSpace(summaryPath) == "" || strings.TrimSpace(indexPath) == "" {
		return nil
	}
	summaryInfo, err := os.Stat(summaryPath)
	if err != nil || summaryInfo.IsDir() || summaryInfo.Size() == 0 {
		return err
	}
	if indexInfo, err := os.Stat(indexPath); err == nil && !indexInfo.IsDir() && indexInfo.Size() > 0 && !indexInfo.ModTime().Before(summaryInfo.ModTime()) {
		if version, err := store.BGPObservationIndexVersion(indexPath); err == nil && version >= 2 {
			return nil
		}
	}
	_, err = CompileBGPObservationIndex(summaryPath, indexPath)
	return err
}

func bgpCompactIndexEnabled(cfg config.BGPConfig) bool {
	mode := strings.ToLower(strings.TrimSpace(cfg.IndexMode))
	return mode != "" && mode != "jsonl" && mode != "off"
}

func shouldSkipFreshBGPSummary(cfg config.Config, now time.Time) (bool, string) {
	if !cfg.BGP.Enabled || strings.ToLower(strings.TrimSpace(cfg.BGP.Mode)) != "full" {
		return false, ""
	}
	interval := cfg.BGP.RefreshInterval
	if interval <= 0 {
		interval = 8 * time.Hour
	}
	summaryPath := resolveDataPath(cfg.DataDir, cfg.BGP.SummaryFile)
	info, err := os.Stat(summaryPath)
	if err != nil || info.IsDir() || info.Size() == 0 {
		return false, ""
	}

	state := loadBGPRefreshState(cfg.DataDir)
	if state.LastErrorAt.After(state.LastSuccessAt) {
		return false, ""
	}
	reference := state.LastSuccessAt
	if reference.IsZero() || state.SummaryFile != summaryPath {
		reference = info.ModTime()
	}
	if reference.IsZero() {
		return false, ""
	}
	elapsed := now.Sub(reference)
	if elapsed < 0 {
		elapsed = 0
	}
	if elapsed >= interval {
		return false, ""
	}
	remaining := interval - elapsed
	return true, fmt.Sprintf("BGP 汇总在 %s 前已成功更新，剩余 %s 后再刷新；失败状态会立即重试", elapsed.Round(time.Second), remaining.Round(time.Second))
}

func recordBGPRefreshSuccess(cfg config.Config, sourceCount int) {
	summaryPath := resolveDataPath(cfg.DataDir, cfg.BGP.SummaryFile)
	state := loadBGPRefreshState(cfg.DataDir)
	state.Version = 1
	state.SummaryFile = summaryPath
	state.LastSuccessAt = time.Now().UTC()
	state.LastError = ""
	state.SourceCount = sourceCount
	_ = saveBGPRefreshState(cfg.DataDir, state)
}

func recordBGPRefreshError(cfg config.Config, err error) {
	if err == nil {
		return
	}
	summaryPath := resolveDataPath(cfg.DataDir, cfg.BGP.SummaryFile)
	state := loadBGPRefreshState(cfg.DataDir)
	state.Version = 1
	state.SummaryFile = summaryPath
	state.LastErrorAt = time.Now().UTC()
	state.LastError = err.Error()
	_ = saveBGPRefreshState(cfg.DataDir, state)
}

func loadBGPRefreshState(dataDir string) bgpRefreshState {
	body, err := os.ReadFile(bgpRefreshStatePath(dataDir))
	if err != nil {
		return bgpRefreshState{Version: 1}
	}
	var state bgpRefreshState
	if err := json.Unmarshal(body, &state); err != nil {
		return bgpRefreshState{Version: 1}
	}
	if state.Version == 0 {
		state.Version = 1
	}
	return state
}

func saveBGPRefreshState(dataDir string, state bgpRefreshState) error {
	state.Version = 1
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(bgpRefreshStatePath(dataDir), body)
}

func bgpRefreshStatePath(dataDir string) string {
	if strings.TrimSpace(dataDir) == "" {
		dataDir = "data"
	}
	return filepath.Join(dataDir, "processed", "bgp-refresh-state.json")
}

type downloadedBGPRIB struct {
	Source BGPRIBSource
	Path   string
}

func downloadBGPSources(ctx context.Context, client *http.Client, rawDir string, sources []BGPRIBSource, workers int, downloadTimeout time.Duration) ([]downloadedBGPRIB, error) {
	if workers <= 0 {
		workers = 1
	}
	if workers > len(sources) && len(sources) > 0 {
		workers = len(sources)
	}
	downloadClient := bgpDownloadClient(client, downloadTimeout)
	jobs := make(chan BGPRIBSource)
	out := []downloadedBGPRIB{}
	var mu sync.Mutex
	var firstErr error
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	setErr := func(err error) {
		if err == nil {
			return
		}
		mu.Lock()
		if firstErr == nil {
			firstErr = err
			cancel()
		}
		mu.Unlock()
	}
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for source := range jobs {
				localPath := bgpRawPath(rawDir, source)
				if err := downloadBGPFile(ctx, downloadClient, source.URL, localPath); err != nil {
					setErr(err)
					continue
				}
				mu.Lock()
				out = append(out, downloadedBGPRIB{Source: source, Path: localPath})
				mu.Unlock()
			}
		}()
	}
feedDownloads:
	for _, source := range sources {
		select {
		case <-ctx.Done():
			break feedDownloads
		case jobs <- source:
		}
	}
	close(jobs)
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Source.Source == out[j].Source.Source {
			return out[i].Source.Collector < out[j].Source.Collector
		}
		return out[i].Source.Source < out[j].Source.Source
	})
	return out, nil
}

func bgpDownloadClient(base *http.Client, timeout time.Duration) *http.Client {
	if base == nil {
		base = http.DefaultClient
	}
	if timeout <= 0 {
		return base
	}
	next := *base
	next.Timeout = timeout
	return &next
}

func parseBGPSources(ctx context.Context, downloaded []downloadedBGPRIB, workers int) (*bgpSummaryAggregator, error) {
	if workers <= 0 {
		workers = 1
	}
	if workers > len(downloaded) && len(downloaded) > 0 {
		workers = len(downloaded)
	}
	jobs := make(chan downloadedBGPRIB)
	global := newBGPSummaryAggregator()
	var mu sync.Mutex
	var firstErr error
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	setErr := func(err error) {
		if err == nil {
			return
		}
		mu.Lock()
		if firstErr == nil {
			firstErr = err
			cancel()
		}
		mu.Unlock()
	}
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				local := newBGPSummaryAggregator()
				if err := parseBGPMRTFile(item.Path, item.Source.Source, item.Source.Collector, local); err != nil {
					setErr(err)
					continue
				}
				mu.Lock()
				global.merge(local)
				mu.Unlock()
			}
		}()
	}
feedParsers:
	for _, item := range downloaded {
		select {
		case <-ctx.Done():
			break feedParsers
		case jobs <- item:
		}
	}
	close(jobs)
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	return global, nil
}

func DiscoverBGPRIBSources(ctx context.Context, client *http.Client, cfg config.BGPConfig) ([]BGPRIBSource, error) {
	if client == nil {
		client = http.DefaultClient
	}
	out := []BGPRIBSource{}
	months := bgpMonthCandidates(cfg.Month)
	if cfg.RouteViewsEnabled {
		collectors, err := discoverCollectors(ctx, client, cfg.RouteViewsBaseURL, cfg.Collectors, routeViewsCollector, routeViewsCollectorFromHref, nil)
		if err != nil {
			return nil, err
		}
		for _, collector := range collectors {
			source, ok, err := discoverLatestInMonths(ctx, client, cfg.RouteViewsBaseURL, collector, months, routeViewsRIBPath, routeViewsRIBFile)
			if err != nil {
				return nil, err
			}
			if ok {
				source.Source = "routeviews"
				out = append(out, source)
			}
		}
	}
	if cfg.RIPERISEnabled {
		collectors, err := discoverCollectors(ctx, client, cfg.RIPERISBaseURL, cfg.Collectors, ripeRISCollector, ripeRISCollectorFromHref, defaultRIPERISCollectors())
		if err != nil {
			return nil, err
		}
		for _, collector := range collectors {
			source, ok, err := discoverLatestInMonths(ctx, client, cfg.RIPERISBaseURL, collector, months, ripeRISRIBPath, ripeRISRIBFile)
			if err != nil {
				return nil, err
			}
			if ok {
				source.Source = "ripe_ris"
				out = append(out, source)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Source == out[j].Source {
			return out[i].Collector < out[j].Collector
		}
		return out[i].Source < out[j].Source
	})
	return out, nil
}

func WriteBGPObservationSummary(destination string, observations []BGPObservationInput) error {
	aggregator := newBGPSummaryAggregator()
	for _, observation := range observations {
		aggregator.add(observation)
	}
	records := aggregator.records()
	return writeBGPRecords(destination, records)
}

type bgpSummaryAggregate struct {
	prefix     string
	originASN  int
	source     string
	collectors map[string]struct{}
	upstreams  map[int]int
}

type bgpSummaryAggregator struct {
	groups map[string]*bgpSummaryAggregate
}

func newBGPSummaryAggregator() *bgpSummaryAggregator {
	return &bgpSummaryAggregator{groups: map[string]*bgpSummaryAggregate{}}
}

func (a *bgpSummaryAggregator) add(observation BGPObservationInput) {
	if observation.Prefix == "" || observation.OriginASN <= 0 || observation.Source == "" {
		return
	}
	key := observation.Prefix + "\x00" + observation.Source + "\x00" + fmt.Sprint(observation.OriginASN)
	group := a.groups[key]
	if group == nil {
		group = &bgpSummaryAggregate{
			prefix:     observation.Prefix,
			originASN:  observation.OriginASN,
			source:     observation.Source,
			collectors: map[string]struct{}{},
			upstreams:  map[int]int{},
		}
		a.groups[key] = group
	}
	if observation.Collector != "" {
		group.collectors[observation.Collector] = struct{}{}
	}
	if observation.DominantUpstream > 0 {
		group.upstreams[observation.DominantUpstream]++
	}
}

func (a *bgpSummaryAggregator) records() []store.BGPObservationRecord {
	records := make([]store.BGPObservationRecord, 0, len(a.groups))
	for _, group := range a.groups {
		count := len(group.collectors)
		if count == 0 {
			count = 1
		}
		records = append(records, store.BGPObservationRecord{
			Prefix:           group.prefix,
			OriginASN:        group.originASN,
			Source:           group.source,
			Collector:        group.source + ":" + fmt.Sprint(count),
			ObservationCount: count,
			DominantUpstream: mostCommonASN(group.upstreams),
		})
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Prefix == records[j].Prefix {
			if records[i].Source == records[j].Source {
				return records[i].OriginASN < records[j].OriginASN
			}
			return records[i].Source < records[j].Source
		}
		return records[i].Prefix < records[j].Prefix
	})
	return records
}

func (a *bgpSummaryAggregator) merge(other *bgpSummaryAggregator) {
	if other == nil {
		return
	}
	for key, incoming := range other.groups {
		group := a.groups[key]
		if group == nil {
			group = &bgpSummaryAggregate{
				prefix:     incoming.prefix,
				originASN:  incoming.originASN,
				source:     incoming.source,
				collectors: map[string]struct{}{},
				upstreams:  map[int]int{},
			}
			a.groups[key] = group
		}
		for collector := range incoming.collectors {
			group.collectors[collector] = struct{}{}
		}
		for upstream, count := range incoming.upstreams {
			group.upstreams[upstream] += count
		}
	}
}

func writeBGPRecords(destination string, records []store.BGPObservationRecord) error {
	if err := os.MkdirAll(filepath.Dir(destination), 0o775); err != nil {
		return err
	}
	tmp := destination + ".tmp"
	file, err := os.Create(tmp)
	if err != nil {
		return err
	}
	var writer io.WriteCloser = file
	if strings.HasSuffix(strings.ToLower(destination), ".gz") {
		gz := gzip.NewWriter(file)
		writer = struct {
			io.Writer
			io.Closer
		}{Writer: gz, Closer: closeFunc(func() error {
			if err := gz.Close(); err != nil {
				_ = file.Close()
				return err
			}
			return file.Close()
		})}
	}
	encoder := json.NewEncoder(writer)
	for _, record := range records {
		if err := encoder.Encode(record); err != nil {
			_ = writer.Close()
			_ = os.Remove(tmp)
			return err
		}
	}
	if err := writer.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, destination)
}

type closeFunc func() error

func (fn closeFunc) Close() error { return fn() }

func mostCommonASN(counts map[int]int) int {
	bestASN := 0
	bestCount := 0
	for asn, count := range counts {
		if count > bestCount || (count == bestCount && (bestASN == 0 || asn < bestASN)) {
			bestASN = asn
			bestCount = count
		}
	}
	return bestASN
}

func parseBGPMRTFile(filePath, source, collector string, aggregator *bgpSummaryAggregator) error {
	reader, closeFn, err := openMRTFile(filePath)
	if err != nil {
		return err
	}
	defer closeFn()

	scanner := bufio.NewScanner(reader)
	scanner.Split(mrt.SplitMrt)
	scanner.Buffer(make([]byte, 64*1024), 256*1024*1024)
	for scanner.Scan() {
		token := scanner.Bytes()
		if len(token) < mrt.MRT_COMMON_HEADER_LEN {
			continue
		}
		var header mrt.MRTHeader
		if err := header.DecodeFromBytes(token[:mrt.MRT_COMMON_HEADER_LEN]); err != nil {
			return err
		}
		message, err := mrt.ParseMRTBody(&header, token[mrt.MRT_COMMON_HEADER_LEN:])
		if err != nil {
			continue
		}
		rib, ok := message.Body.(*mrt.Rib)
		if !ok || rib == nil || rib.Prefix == nil {
			continue
		}
		prefix := rib.Prefix.String()
		for _, entry := range rib.Entries {
			if entry == nil {
				continue
			}
			origin, upstream := originAndUpstream(entry.PathAttributes)
			if origin <= 0 {
				continue
			}
			aggregator.add(BGPObservationInput{
				Prefix:           prefix,
				OriginASN:        origin,
				Source:           source,
				Collector:        collector,
				DominantUpstream: upstream,
			})
		}
	}
	return scanner.Err()
}

func originAndUpstream(attrs []bgp.PathAttributeInterface) (int, int) {
	as4Path := []int{}
	asPath := []int{}
	for _, attr := range attrs {
		switch pathAttr := attr.(type) {
		case *bgp.PathAttributeAs4Path:
			for _, param := range pathAttr.Value {
				for _, asn := range param.GetAS() {
					if asn > 0 {
						as4Path = append(as4Path, int(asn))
					}
				}
			}
		case *bgp.PathAttributeAsPath:
			for _, param := range pathAttr.Value {
				for _, asn := range param.GetAS() {
					if asn > 0 {
						asPath = append(asPath, int(asn))
					}
				}
			}
		}
	}
	path := asPath
	if len(as4Path) > 0 {
		path = as4Path
	}
	if len(path) == 0 {
		return 0, 0
	}
	origin := path[len(path)-1]
	upstream := 0
	if len(path) > 1 {
		upstream = path[len(path)-2]
		if upstream == origin {
			upstream = 0
		}
	}
	return origin, upstream
}

func openMRTFile(filePath string) (io.Reader, func(), error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, func() {}, err
	}
	lower := strings.ToLower(filePath)
	switch {
	case strings.HasSuffix(lower, ".gz"):
		reader, err := gzip.NewReader(file)
		if err != nil {
			_ = file.Close()
			return nil, func() {}, err
		}
		return reader, func() {
			_ = reader.Close()
			_ = file.Close()
		}, nil
	case strings.HasSuffix(lower, ".bz2"):
		return bzip2.NewReader(file), func() { _ = file.Close() }, nil
	default:
		return file, func() { _ = file.Close() }, nil
	}
}

func downloadBGPFile(ctx context.Context, client *http.Client, sourceURL, destination string) error {
	if info, err := os.Stat(destination); err == nil && info.Size() > 0 {
		return nil
	}
	var lastErr error
	for attempt := 1; attempt <= bgpDownloadMaxAttempts; attempt++ {
		if err := downloadBGPFileOnce(ctx, client, sourceURL, destination); err != nil {
			lastErr = err
			if !isRetryableBGPDownloadError(ctx, err) || attempt == bgpDownloadMaxAttempts {
				return err
			}
			if err := sleepBGPDownloadRetry(ctx, time.Duration(attempt)*bgpDownloadRetryDelay); err != nil {
				return err
			}
			continue
		}
		return nil
	}
	return lastErr
}

func downloadBGPFileOnce(ctx context.Context, client *http.Client, sourceURL, destination string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return err
	}
	if offset := partialBGPDownloadSize(destination); offset > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return bgpHTTPStatusError{URL: sourceURL, Code: resp.StatusCode}
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o775); err != nil {
		return err
	}
	tmp := destination + ".tmp"
	flags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	if req.Header.Get("Range") != "" && resp.StatusCode == http.StatusPartialContent {
		flags = os.O_CREATE | os.O_WRONLY | os.O_APPEND
	}
	file, err := os.OpenFile(tmp, flags, 0o664)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(file, resp.Body)
	closeErr := file.Close()
	if copyErr != nil {
		return fmt.Errorf("download %s: %w", sourceURL, copyErr)
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(tmp, destination)
}

type bgpHTTPStatusError struct {
	URL  string
	Code int
}

func (e bgpHTTPStatusError) Error() string {
	return fmt.Sprintf("download %s: HTTP %d", e.URL, e.Code)
}

func partialBGPDownloadSize(destination string) int64 {
	info, err := os.Stat(destination + ".tmp")
	if err != nil || info.IsDir() {
		return 0
	}
	return info.Size()
}

func isRetryableBGPDownloadError(ctx context.Context, err error) bool {
	if err == nil || ctx.Err() != nil {
		return false
	}
	var statusErr bgpHTTPStatusError
	if errors.As(err, &statusErr) {
		return statusErr.Code == http.StatusRequestTimeout || statusErr.Code == http.StatusTooManyRequests || statusErr.Code >= 500
	}
	return true
}

func sleepBGPDownloadRetry(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func bgpRawPath(rawDir string, source BGPRIBSource) string {
	name := path.Base(strings.Split(source.URL, "?")[0])
	if name == "." || name == "/" || name == "" {
		name = sanitizeHistoryFileName(source.Collector) + ".mrt"
	}
	return filepath.Join(rawDir, sanitizeHistoryFileName(source.Source), sanitizeHistoryFileName(source.Collector), sanitizeHistoryFileName(name))
}

func resolveDataPath(dataDir, filePath string) string {
	if filepath.IsAbs(filePath) {
		return filePath
	}
	cleanData := filepath.Clean(dataDir)
	cleanPath := filepath.Clean(filePath)
	if cleanPath == cleanData || strings.HasPrefix(cleanPath, cleanData+string(os.PathSeparator)) {
		return cleanPath
	}
	return filepath.Join(dataDir, filePath)
}

func pruneBGPRawFiles(rawDir string, retentionDays int) {
	if retentionDays <= 0 {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	_ = filepath.WalkDir(rawDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry == nil || entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err == nil && info.ModTime().Before(cutoff) {
			_ = os.Remove(path)
		}
		return nil
	})
}

func discoverLatestInMonths(ctx context.Context, client *http.Client, baseURL, collector string, months []string, dirFn func(string, string) string, fileFn func(string) bool) (BGPRIBSource, bool, error) {
	for _, month := range months {
		dirURL := joinURL(baseURL, dirFn(collector, month))
		hrefs, status, err := fetchLinks(ctx, client, dirURL)
		if err != nil {
			return BGPRIBSource{}, false, err
		}
		if status == http.StatusNotFound {
			continue
		}
		if status < 200 || status >= 300 {
			return BGPRIBSource{}, false, fmt.Errorf("discover RIBs %s: HTTP %d", dirURL, status)
		}
		latest := latestMatchingHref(hrefs, fileFn)
		if latest == "" {
			continue
		}
		return BGPRIBSource{Collector: collector, URL: joinURL(dirURL, latest)}, true, nil
	}
	return BGPRIBSource{}, false, nil
}

func discoverCollectors(ctx context.Context, client *http.Client, baseURL string, wanted []string, predicate func(string) bool, normalizeHref func(string) (string, bool), fallback []string) ([]string, error) {
	if !wantsAllCollectors(wanted) {
		out := []string{}
		for _, collector := range wanted {
			collector = strings.Trim(strings.TrimSpace(collector), "/")
			if collector != "" && predicate(collector) {
				out = append(out, collector)
			}
		}
		return out, nil
	}
	hrefs, status, err := fetchLinks(ctx, client, baseURL)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("discover collectors %s: HTTP %d", baseURL, status)
	}
	out := []string{}
	seen := map[string]struct{}{}
	for _, href := range hrefs {
		collector, ok := normalizeHref(href)
		if !ok {
			continue
		}
		collector = strings.Trim(strings.TrimSpace(collector), "/")
		if collector == "" || strings.HasPrefix(collector, ".") || !predicate(collector) {
			continue
		}
		if _, ok := seen[collector]; ok {
			continue
		}
		seen[collector] = struct{}{}
		out = append(out, collector)
	}
	sort.Strings(out)
	if len(out) == 0 && len(fallback) > 0 {
		return append([]string(nil), fallback...), nil
	}
	return out, nil
}

func fetchLinks(ctx context.Context, client *http.Client, sourceURL string) ([]string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, resp.StatusCode, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return parseHREFs(string(body)), resp.StatusCode, nil
}

var hrefRE = regexp.MustCompile(`(?i)href=["']([^"']+)["']`)

func parseHREFs(body string) []string {
	matches := hrefRE.FindAllStringSubmatch(body, -1)
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) > 1 {
			out = append(out, htmlUnescape(match[1]))
		}
	}
	return out
}

func htmlUnescape(value string) string {
	replacer := strings.NewReplacer("&amp;", "&", "&#47;", "/", "&quot;", `"`, "&#34;", `"`)
	return replacer.Replace(value)
}

func latestMatchingHref(hrefs []string, match func(string) bool) string {
	candidates := []string{}
	for _, href := range hrefs {
		base := path.Base(strings.Split(href, "?")[0])
		if match(base) {
			candidates = append(candidates, base)
		}
	}
	sort.Strings(candidates)
	if len(candidates) == 0 {
		return ""
	}
	return candidates[len(candidates)-1]
}

func routeViewsCollector(value string) bool {
	value = strings.Trim(strings.TrimSpace(value), "/")
	return value != "" && !strings.Contains(value, "/")
}

func ripeRISCollector(value string) bool {
	return strings.HasPrefix(value, "rrc")
}

func routeViewsCollectorFromHref(href string) (string, bool) {
	parts := hrefPathParts(href)
	for index, part := range parts {
		if part == "bgpdata" && index > 0 {
			return parts[index-1], true
		}
	}
	if len(parts) == 1 && strings.HasPrefix(parts[0], "route-views") {
		return parts[0], true
	}
	return "", false
}

func ripeRISCollectorFromHref(href string) (string, bool) {
	for _, part := range hrefPathParts(href) {
		if ripeRISCollector(part) {
			return part, true
		}
	}
	return "", false
}

func hrefPathParts(href string) []string {
	href = strings.TrimSpace(strings.Split(href, "?")[0])
	parsed, err := url.Parse(href)
	rawPath := href
	if err == nil && parsed.Path != "" {
		rawPath = parsed.Path
	}
	rawPath = strings.Trim(rawPath, "/")
	if rawPath == "" {
		return nil
	}
	values := strings.Split(rawPath, "/")
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && value != "." && value != ".." {
			out = append(out, value)
		}
	}
	return out
}

func defaultRIPERISCollectors() []string {
	out := make([]string, 0, 27)
	for i := 0; i <= 26; i++ {
		out = append(out, fmt.Sprintf("rrc%02d", i))
	}
	return out
}

func routeViewsRIBPath(collector, month string) string {
	return collector + "/bgpdata/" + month + "/RIBS/"
}

func ripeRISRIBPath(collector, month string) string {
	return collector + "/" + month + "/"
}

func routeViewsRIBFile(name string) bool {
	return strings.HasPrefix(name, "rib.") && (strings.HasSuffix(name, ".bz2") || strings.HasSuffix(name, ".gz") || strings.HasSuffix(name, ".mrt"))
}

func ripeRISRIBFile(name string) bool {
	return strings.HasPrefix(name, "bview.") && (strings.HasSuffix(name, ".gz") || strings.HasSuffix(name, ".bz2") || strings.HasSuffix(name, ".mrt"))
}

func wantsAllCollectors(values []string) bool {
	if len(values) == 0 {
		return true
	}
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), "all") {
			return true
		}
	}
	return false
}

func bgpMonthCandidates(configured string) []string {
	if strings.TrimSpace(configured) != "" {
		return []string{strings.TrimSpace(configured)}
	}
	now := time.Now().UTC()
	return []string{now.Format("2006.01"), now.AddDate(0, -1, 0).Format("2006.01")}
}

func joinURL(baseURL string, elem string) string {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return strings.TrimRight(baseURL, "/") + "/" + strings.TrimLeft(elem, "/")
	}
	if strings.HasPrefix(elem, "http://") || strings.HasPrefix(elem, "https://") {
		return elem
	}
	if !strings.HasSuffix(parsed.Path, "/") {
		parsed.Path += "/"
	}
	joined := path.Join(parsed.Path, elem)
	if strings.HasSuffix(elem, "/") {
		joined += "/"
	}
	parsed.Path = joined
	return parsed.String()
}
