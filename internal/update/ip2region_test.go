package update

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ipasn/internal/config"
)

func TestRefreshIP2RegionDownloadsWhenRemoteIsNewer(t *testing.T) {
	xdbPath := filepath.Join(t.TempDir(), "ip2region_v4.xdb")
	if err := writeTestXDBHeader(xdbPath, time.Date(2026, 5, 1, 13, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	remoteReleasedAt := time.Date(2026, 6, 1, 13, 0, 0, 0, time.UTC)

	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(fmt.Sprintf(`{"errno":0,"errstr":"OK","data":{"released_at":%d,"released_dt":"2026-06-01 13:00:00"}}`, remoteReleasedAt.Unix())))
	})
	mux.HandleFunc("/download", func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 64)
		binary.LittleEndian.PutUint32(body[4:8], uint32(time.Date(2026, 6, 1, 13, 0, 0, 0, time.UTC).Unix()))
		_, _ = w.Write(body)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	cfg := config.Default()
	cfg.IP2Region.Enabled = true
	cfg.IP2Region.V4File = xdbPath
	cfg.IP2Region.V4VersionURL = server.URL + "/version"
	cfg.IP2Region.V4DownloadURL = server.URL + "/download"

	status, err := RefreshIP2RegionWithClient(context.Background(), cfg, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if !status.Updated {
		t.Fatalf("expected database update, got %#v", status)
	}
	body, err := os.ReadFile(xdbPath)
	if err != nil {
		t.Fatal(err)
	}
	createdAt := binary.LittleEndian.Uint32(body[4:8])
	if createdAt != uint32(time.Date(2026, 6, 1, 13, 0, 0, 0, time.UTC).Unix()) {
		t.Fatalf("expected downloaded xdb file, got created_at=%d", createdAt)
	}
}

func writeTestXDBHeader(path string, createdAt time.Time) error {
	body := make([]byte, 64)
	binary.LittleEndian.PutUint32(body[4:8], uint32(createdAt.Unix()))
	if err := os.MkdirAll(filepath.Dir(path), 0o775); err != nil {
		return err
	}
	return os.WriteFile(path, body, 0o664)
}
