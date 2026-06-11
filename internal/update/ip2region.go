package update

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"ipasn/internal/config"
)

type IP2RegionRefreshStatus struct {
	Updated bool     `json:"updated"`
	Files   []string `json:"files,omitempty"`
}

func RefreshIP2Region(ctx context.Context, cfg config.Config) (IP2RegionRefreshStatus, error) {
	return RefreshIP2RegionWithClient(ctx, cfg, &http.Client{Timeout: cfg.HTTPTimeout})
}

func RefreshIP2RegionWithClient(ctx context.Context, cfg config.Config, client *http.Client) (IP2RegionRefreshStatus, error) {
	if !cfg.IP2Region.Enabled {
		return IP2RegionRefreshStatus{}, nil
	}
	if client == nil {
		client = &http.Client{Timeout: cfg.HTTPTimeout}
	}
	status := IP2RegionRefreshStatus{}
	for _, source := range []struct {
		file        string
		versionURL  string
		downloadURL string
	}{
		{file: cfg.IP2Region.V4File, versionURL: cfg.IP2Region.V4VersionURL, downloadURL: cfg.IP2Region.V4DownloadURL},
		{file: cfg.IP2Region.V6File, versionURL: cfg.IP2Region.V6VersionURL, downloadURL: cfg.IP2Region.V6DownloadURL},
	} {
		updated, err := refreshOneIP2Region(ctx, client, source.file, source.versionURL, source.downloadURL)
		if err != nil {
			return status, err
		}
		if updated {
			status.Updated = true
			status.Files = append(status.Files, source.file)
		}
	}
	return status, nil
}

func refreshOneIP2Region(ctx context.Context, client *http.Client, filePath, versionURL, downloadURL string) (bool, error) {
	if filePath == "" || versionURL == "" || downloadURL == "" {
		return false, nil
	}
	releasedAt, err := fetchIP2RegionReleasedAt(ctx, client, versionURL)
	if err != nil {
		return false, err
	}
	localCreatedAt, _ := readXDBCreatedAt(filePath)
	if normalizeIP2RegionTime(localCreatedAt) >= normalizeIP2RegionTime(releasedAt) {
		return false, nil
	}
	if err := downloadIP2RegionFile(ctx, client, downloadURL, filePath); err != nil {
		return false, err
	}
	return true, nil
}

func fetchIP2RegionReleasedAt(ctx context.Context, client *http.Client, versionURL string) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, versionURL, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("ip2region version API HTTP %d", resp.StatusCode)
	}
	var payload struct {
		Errno int    `json:"errno"`
		Err   string `json:"errstr"`
		Data  struct {
			ReleasedAt int64 `json:"released_at"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return 0, err
	}
	if payload.Errno != 0 {
		return 0, fmt.Errorf("ip2region version API: %s", payload.Err)
	}
	return payload.Data.ReleasedAt, nil
}

func readXDBCreatedAt(filePath string) (int64, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	buf := make([]byte, 8)
	if _, err := io.ReadFull(file, buf); err != nil {
		return 0, err
	}
	return int64(binary.LittleEndian.Uint32(buf[4:8])), nil
}

func normalizeIP2RegionTime(value int64) int64 {
	if value <= 0 {
		return 0
	}
	t := time.Unix(value, 0).In(time.Local)
	return time.Date(t.Year(), t.Month(), t.Day(), 13, 0, 0, 0, t.Location()).Unix()
}

func downloadIP2RegionFile(ctx context.Context, client *http.Client, downloadURL, destination string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("ip2region download API HTTP %d", resp.StatusCode)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o775); err != nil {
		return err
	}
	tmp := destination + ".tmp"
	file, err := os.Create(tmp)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(file, resp.Body)
	closeErr := file.Close()
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
