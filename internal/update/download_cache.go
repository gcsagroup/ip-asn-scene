package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const downloadCacheNoValidatorFreshness = 30 * time.Minute

type downloadState struct {
	Version   int                           `json:"version"`
	UpdatedAt time.Time                     `json:"updated_at"`
	Entries   map[string]downloadStateEntry `json:"entries"`
}

type downloadStateEntry struct {
	URL           string    `json:"url"`
	LocalFile     string    `json:"local_file"`
	ETag          string    `json:"etag,omitempty"`
	LastModified  string    `json:"last_modified,omitempty"`
	ContentLength int64     `json:"content_length,omitempty"`
	SHA256        string    `json:"sha256,omitempty"`
	DownloadedAt  time.Time `json:"downloaded_at"`
}

type DownloadStats struct {
	Downloaded        int `json:"downloaded"`
	ReusedNotModified int `json:"reused_not_modified"`
	ReusedFresh       int `json:"reused_fresh"`
}

type downloadCache struct {
	mu        sync.Mutex
	client    *http.Client
	statePath string
	cacheDir  string
	state     downloadState
	stats     DownloadStats
}

type downloadCacheContextKey struct{}

func newDownloadCache(dataDir string, client *http.Client) *downloadCache {
	if strings.TrimSpace(dataDir) == "" {
		dataDir = "data"
	}
	if client == nil {
		client = http.DefaultClient
	}
	cache := &downloadCache{
		client:    client,
		statePath: filepath.Join(dataDir, "processed", "download-state.json"),
		cacheDir:  filepath.Join(dataDir, "processed", "download-cache"),
		state: downloadState{
			Version: 1,
			Entries: map[string]downloadStateEntry{},
		},
	}
	cache.load()
	return cache
}

func contextWithDownloadCache(ctx context.Context, cache *downloadCache) context.Context {
	if cache == nil {
		return ctx
	}
	return context.WithValue(ctx, downloadCacheContextKey{}, cache)
}

func downloadCacheFromContext(ctx context.Context) *downloadCache {
	if ctx == nil {
		return nil
	}
	cache, _ := ctx.Value(downloadCacheContextKey{}).(*downloadCache)
	return cache
}

func (c *downloadCache) DownloadFile(ctx context.Context, sourceURL, destination string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.downloadFileLocked(ctx, sourceURL, destination, true)
}

func (c *downloadCache) Stats() DownloadStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

func (c *downloadCache) Bytes(ctx context.Context, sourceURL string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bytesLocked(ctx, sourceURL, true)
}

func (c *downloadCache) load() {
	body, err := os.ReadFile(c.statePath)
	if err != nil {
		return
	}
	var state downloadState
	if err := json.Unmarshal(body, &state); err != nil {
		return
	}
	if state.Entries == nil {
		state.Entries = map[string]downloadStateEntry{}
	}
	if state.Version == 0 {
		state.Version = 1
	}
	c.state = state
}

func (c *downloadCache) saveLocked() error {
	c.state.Version = 1
	c.state.UpdatedAt = time.Now().UTC()
	encoded, err := json.MarshalIndent(c.state, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(c.statePath, encoded)
}

func (c *downloadCache) downloadFileLocked(ctx context.Context, sourceURL, destination string, conditional bool) error {
	entry := c.state.Entries[sourceURL]
	if conditional && c.canReuseWithoutRequest(entry) {
		c.stats.ReusedFresh++
		return copyCachedFile(entry.LocalFile, destination)
	}
	req, err := c.newRequest(ctx, sourceURL, entry, conditional)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		if fileExists(entry.LocalFile) {
			c.stats.ReusedNotModified++
			return copyCachedFile(entry.LocalFile, destination)
		}
		return c.downloadFileLocked(ctx, sourceURL, destination, false)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("download %s: HTTP %d", sourceURL, resp.StatusCode)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o775); err != nil {
		return err
	}
	tmp := destination + ".tmp"
	file, err := os.Create(tmp)
	if err != nil {
		return err
	}
	hasher := sha256.New()
	written, copyErr := copyAndHash(file, resp.Body, hasher)
	closeErr := file.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	if err := os.Rename(tmp, destination); err != nil {
		return err
	}
	c.stats.Downloaded++
	c.updateEntryLocked(sourceURL, destination, resp, written, hasher)
	return c.saveLocked()
}

func (c *downloadCache) bytesLocked(ctx context.Context, sourceURL string, conditional bool) ([]byte, error) {
	entry := c.state.Entries[sourceURL]
	if conditional && c.canReuseWithoutRequest(entry) {
		c.stats.ReusedFresh++
		return os.ReadFile(entry.LocalFile)
	}
	req, err := c.newRequest(ctx, sourceURL, entry, conditional)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		if fileExists(entry.LocalFile) {
			c.stats.ReusedNotModified++
			return os.ReadFile(entry.LocalFile)
		}
		return c.bytesLocked(ctx, sourceURL, false)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	localFile := c.cacheFileForURL(sourceURL)
	if err := atomicWrite(localFile, body); err != nil {
		return nil, err
	}
	hasher := sha256.New()
	_, _ = hasher.Write(body)
	c.updateEntryLocked(sourceURL, localFile, resp, int64(len(body)), hasher)
	if err := c.saveLocked(); err != nil {
		return nil, err
	}
	c.stats.Downloaded++
	return body, nil
}

func (c *downloadCache) newRequest(ctx context.Context, sourceURL string, entry downloadStateEntry, conditional bool) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sourceURL, nil)
	if err != nil {
		return nil, err
	}
	if conditional {
		if strings.TrimSpace(entry.ETag) != "" {
			req.Header.Set("If-None-Match", entry.ETag)
		}
		if strings.TrimSpace(entry.LastModified) != "" {
			req.Header.Set("If-Modified-Since", entry.LastModified)
		}
	}
	return req, nil
}

func (c *downloadCache) canReuseWithoutRequest(entry downloadStateEntry) bool {
	if entry.URL == "" || entry.ETag != "" || entry.LastModified != "" || !fileExists(entry.LocalFile) {
		return false
	}
	return time.Since(entry.DownloadedAt) >= 0 && time.Since(entry.DownloadedAt) < downloadCacheNoValidatorFreshness
}

func (c *downloadCache) updateEntryLocked(sourceURL, localFile string, resp *http.Response, size int64, hasher hash.Hash) {
	c.state.Entries[sourceURL] = downloadStateEntry{
		URL:           sourceURL,
		LocalFile:     localFile,
		ETag:          resp.Header.Get("ETag"),
		LastModified:  resp.Header.Get("Last-Modified"),
		ContentLength: size,
		SHA256:        hex.EncodeToString(hasher.Sum(nil)),
		DownloadedAt:  time.Now().UTC(),
	}
}

func (c *downloadCache) cacheFileForURL(sourceURL string) string {
	sum := sha256.Sum256([]byte(sourceURL))
	ext := extensionFromURL(sourceURL)
	if ext == "" {
		ext = ".bin"
	}
	return filepath.Join(c.cacheDir, hex.EncodeToString(sum[:])+ext)
}

func copyAndHash(dst io.Writer, src io.Reader, hasher hash.Hash) (int64, error) {
	return io.Copy(io.MultiWriter(dst, hasher), src)
}

func copyCachedFile(source, destination string) error {
	if source == destination {
		return nil
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	if err := os.MkdirAll(filepath.Dir(destination), 0o775); err != nil {
		return err
	}
	tmp := destination + ".tmp"
	output, err := os.Create(tmp)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	return os.Rename(tmp, destination)
}

func fileExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Size() > 0
}
