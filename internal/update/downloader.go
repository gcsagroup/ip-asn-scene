package update

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"ipasn/internal/config"
)

type Downloader struct {
	client *http.Client
}

func NewDownloader(timeout time.Duration) *Downloader {
	if timeout <= 0 {
		timeout = 90 * time.Second
	}
	return &Downloader{client: &http.Client{Timeout: timeout}}
}

func (d *Downloader) DownloadAll(ctx context.Context, cfg config.Config) (Manifest, error) {
	rawDir := filepath.Join(cfg.DataDir, "raw")
	processedDir := filepath.Join(cfg.DataDir, "processed")
	if err := os.MkdirAll(rawDir, 0o775); err != nil {
		return Manifest{}, err
	}
	if err := os.MkdirAll(processedDir, 0o775); err != nil {
		return Manifest{}, err
	}

	files := map[string]string{}
	cache := newDownloadCache(cfg.DataDir, d.client)

	historyLimit := cfg.History.Snapshots
	v4Paths, err := d.latestCAIDAURLs(ctx, cfg.Sources.CAIDAv4LogURL, cfg.Sources.CAIDAv4BaseURL, maxInt(1, historyLimit))
	if err != nil {
		return Manifest{}, err
	}
	v4Path := v4Paths[len(v4Paths)-1]
	if err := d.download(ctx, cache, v4Path, filepath.Join(rawDir, "caida-ipv4.pfx2as.gz")); err != nil {
		return Manifest{}, err
	}
	files["caida_ipv4"] = v4Path
	if historyLimit > 0 {
		if err := d.downloadCAIDAHistory(ctx, cache, rawDir, "ipv4", v4Paths, historyLimit, files); err != nil {
			return Manifest{}, err
		}
	}

	v6Paths, err := d.latestCAIDAURLs(ctx, cfg.Sources.CAIDAv6LogURL, cfg.Sources.CAIDAv6BaseURL, maxInt(1, historyLimit))
	if err != nil {
		return Manifest{}, err
	}
	v6Path := v6Paths[len(v6Paths)-1]
	if err := d.download(ctx, cache, v6Path, filepath.Join(rawDir, "caida-ipv6.pfx2as.gz")); err != nil {
		return Manifest{}, err
	}
	files["caida_ipv6"] = v6Path
	if historyLimit > 0 {
		if err := d.downloadCAIDAHistory(ctx, cache, rawDir, "ipv6", v6Paths, historyLimit, files); err != nil {
			return Manifest{}, err
		}
	}

	for name, url := range cfg.Sources.RIRURLs {
		if err := d.download(ctx, cache, url, filepath.Join(rawDir, "rir-"+name+".txt")); err != nil {
			return Manifest{}, err
		}
		files["rir_"+name] = url
	}

	if cfg.Sources.PeeringDBURL != "" {
		if err := d.download(ctx, cache, cfg.Sources.PeeringDBURL, filepath.Join(rawDir, "peeringdb-net.json")); err != nil {
			return Manifest{}, err
		}
		files["peeringdb"] = cfg.Sources.PeeringDBURL
	}
	for _, item := range []struct {
		key  string
		url  string
		file string
	}{
		{"peeringdb_ix", cfg.Sources.PeeringDBIXURL, "peeringdb-ix.json"},
		{"peeringdb_netixlan", cfg.Sources.PeeringDBNetIXLANURL, "peeringdb-netixlan.json"},
		{"peeringdb_facility", cfg.Sources.PeeringDBFacilityURL, "peeringdb-fac.json"},
		{"peeringdb_netfac", cfg.Sources.PeeringDBNetFacilityURL, "peeringdb-netfac.json"},
	} {
		if item.url == "" {
			continue
		}
		if err := d.download(ctx, cache, item.url, filepath.Join(rawDir, item.file)); err != nil {
			return Manifest{}, err
		}
		files[item.key] = item.url
	}

	for name, url := range cfg.Sources.IANARDAPURLs {
		if err := d.download(ctx, cache, url, filepath.Join(rawDir, "iana-rdap-"+name+".json")); err != nil {
			return Manifest{}, err
		}
		files["iana_rdap_"+name] = url
	}
	if err := d.downloadOptionalList(ctx, cache, cfg.Sources.RPKIVRPURLs, rawDir, "rpki-vrps", ".csv", "rpki_vrp", files); err != nil {
		return Manifest{}, err
	}
	if err := d.downloadOptionalList(ctx, cache, cfg.Sources.IRRRouteURLs, rawDir, "irr-routes", ".db", "irr_route", files); err != nil {
		return Manifest{}, err
	}
	if err := d.downloadOptionalList(ctx, cache, cfg.Sources.BGPObservationURLs, rawDir, "bgp-observations", ".jsonl", "bgp_observation", files); err != nil {
		return Manifest{}, err
	}
	if err := d.downloadOptionalList(ctx, cache, cfg.Sources.GeofeedURLs, rawDir, "geofeed", ".csv", "geofeed", files); err != nil {
		return Manifest{}, err
	}

	manifest := Manifest{
		Version:       time.Now().UTC().Format("20060102T150405Z"),
		UpdatedAt:     time.Now().UTC(),
		RawFiles:      files,
		DownloadStats: cache.Stats(),
	}
	manifestPath := filepath.Join(processedDir, "manifest.json")
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return Manifest{}, err
	}
	if err := atomicWrite(manifestPath, encoded); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func (d *Downloader) latestCAIDAURL(ctx context.Context, logURL, baseURL string) (string, error) {
	urls, err := d.latestCAIDAURLs(ctx, logURL, baseURL, 1)
	if err != nil {
		return "", err
	}
	return urls[len(urls)-1], nil
}

func (d *Downloader) latestCAIDAURLs(ctx context.Context, logURL, baseURL string, limit int) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, logURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("download %s: HTTP %d", logURL, resp.StatusCode)
	}
	paths, err := LatestNCAIDAPathsFromCreationLog(resp.Body, limit)
	if err != nil {
		return nil, err
	}
	urls := make([]string, 0, len(paths))
	for _, filePath := range paths {
		urls = append(urls, strings.TrimRight(baseURL, "/")+"/"+path.Clean(filePath))
	}
	return urls, nil
}

func (d *Downloader) downloadCAIDAHistory(ctx context.Context, cache *downloadCache, rawDir, family string, urls []string, limit int, files map[string]string) error {
	historyDir := filepath.Join(rawDir, "history")
	for i, sourceURL := range urls {
		name := "caida-" + family + "-" + sanitizeHistoryFileName(path.Base(sourceURL))
		destination := filepath.Join(historyDir, name)
		if err := d.download(ctx, cache, sourceURL, destination); err != nil {
			return err
		}
		files[fmt.Sprintf("caida_history_%s_%d", family, i)] = sourceURL
	}
	return pruneHistoryFiles(historyDir, "caida-"+family+"-*.pfx2as.gz", limit)
}

func (d *Downloader) download(ctx context.Context, cache *downloadCache, url, destination string) error {
	if cache == nil {
		cache = newDownloadCache(filepath.Dir(filepath.Dir(destination)), d.client)
	}
	return cache.DownloadFile(ctx, url, destination)
}

func (d *Downloader) downloadOptionalList(ctx context.Context, cache *downloadCache, urls []string, rawDir, prefix, defaultExt, manifestKey string, files map[string]string) error {
	for i, sourceURL := range urls {
		if strings.TrimSpace(sourceURL) == "" {
			continue
		}
		name := numberedDownloadName(prefix, i, defaultExt, sourceURL)
		if err := d.download(ctx, cache, sourceURL, filepath.Join(rawDir, name)); err != nil {
			return err
		}
		files[fmt.Sprintf("%s_%d", manifestKey, i)] = sourceURL
	}
	return nil
}

func numberedDownloadName(prefix string, index int, defaultExt string, sourceURL string) string {
	name := prefix
	if index > 0 {
		name = fmt.Sprintf("%s-%d", prefix, index)
	}
	ext := extensionFromURL(sourceURL)
	if ext == "" {
		ext = defaultExt
	}
	return name + ext
}

func extensionFromURL(sourceURL string) string {
	base := path.Base(strings.Split(sourceURL, "?")[0])
	if base == "." || base == "/" {
		return ""
	}
	ext := path.Ext(base)
	if ext == ".gz" {
		withoutGzip := strings.TrimSuffix(base, ".gz")
		inner := path.Ext(withoutGzip)
		if inner != "" {
			return inner + ".gz"
		}
	}
	return ext
}

func atomicWrite(destination string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(destination), 0o775); err != nil {
		return err
	}
	tmp := destination + ".tmp"
	if err := os.WriteFile(tmp, content, 0o664); err != nil {
		return err
	}
	return os.Rename(tmp, destination)
}

func sanitizeHistoryFileName(value string) string {
	replacer := strings.NewReplacer("/", "_", "\\", "_", "?", "_", "&", "_", "=", "_")
	return replacer.Replace(value)
}

func pruneHistoryFiles(dir, pattern string, keep int) error {
	if keep <= 0 {
		return nil
	}
	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		return err
	}
	if len(matches) <= keep {
		return nil
	}
	for _, filePath := range matches[:len(matches)-keep] {
		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
