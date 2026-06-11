package geo

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ipasn/internal/config"

	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
)

type IP2RegionLocator struct {
	cfg       config.IP2RegionConfig
	reloadMu  sync.Mutex
	lastCheck atomic.Int64
	v4        atomic.Value
	v6        atomic.Value
}

type ip2RegionDB struct {
	content []byte
	version *xdb.Version
	dbDate  string
	modTime time.Time
	size    int64
}

const ip2RegionReloadCheckInterval = 10 * time.Second

func NewIP2RegionLocator(cfg config.IP2RegionConfig) (*IP2RegionLocator, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	locator := &IP2RegionLocator{cfg: cfg}
	locator.lastCheck.Store(time.Now().UnixNano())
	if cfg.V4File != "" {
		db, err := loadIP2RegionDB(cfg.V4File)
		if err == nil {
			locator.v4.Store(db)
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("load ip2region v4: %w", err)
		}
	}
	if cfg.V6File != "" {
		db, err := loadIP2RegionDB(cfg.V6File)
		if err == nil {
			locator.v6.Store(db)
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("load ip2region v6: %w", err)
		}
	}
	if locator.v4.Load() == nil && locator.v6.Load() == nil {
		return nil, nil
	}
	return locator, nil
}

func (l *IP2RegionLocator) Lookup(ctx context.Context, ip string) (Location, bool) {
	_ = ctx
	l.reloadIfNeeded()
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return Location{}, false
	}
	var value any
	if addr.Unmap().Is4() {
		value = l.v4.Load()
	} else {
		value = l.v6.Load()
	}
	if value == nil {
		return Location{}, false
	}
	db := value.(*ip2RegionDB)
	searcher, err := xdb.NewWithBuffer(db.version, db.content)
	if err != nil {
		return Location{}, false
	}
	defer searcher.Close()
	region, err := searcher.Search(ip)
	if err != nil || strings.TrimSpace(region) == "" {
		return Location{}, false
	}
	location := parseIP2RegionRegion(region, db.dbDate)
	if location == (Location{Source: "ip2region", DBVersion: db.dbDate}) {
		return Location{}, false
	}
	return location, true
}

func loadIP2RegionDB(path string) (*ip2RegionDB, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	content, err := xdb.LoadContentFromFile(path)
	if err != nil {
		return nil, err
	}
	header, err := xdb.LoadHeaderFromBuff(content)
	if err != nil {
		return nil, err
	}
	version, err := xdb.VersionFromHeader(header)
	if err != nil {
		return nil, err
	}
	return &ip2RegionDB{
		content: content,
		version: version,
		dbDate:  time.Unix(int64(header.CreatedAt), 0).Format("2006-01-02"),
		modTime: info.ModTime(),
		size:    info.Size(),
	}, nil
}

func (l *IP2RegionLocator) reloadIfNeeded() {
	now := time.Now().UnixNano()
	last := l.lastCheck.Load()
	if now-last < int64(ip2RegionReloadCheckInterval) {
		return
	}
	if !l.lastCheck.CompareAndSwap(last, now) {
		return
	}
	l.reloadMu.Lock()
	defer l.reloadMu.Unlock()
	l.reloadSlot(&l.v4, l.cfg.V4File)
	l.reloadSlot(&l.v6, l.cfg.V6File)
}

func (l *IP2RegionLocator) reloadSlot(slot *atomic.Value, path string) {
	if path == "" {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	if value := slot.Load(); value != nil {
		current := value.(*ip2RegionDB)
		if current.size == info.Size() && current.modTime.Equal(info.ModTime()) {
			return
		}
	}
	db, err := loadIP2RegionDB(path)
	if err != nil {
		return
	}
	slot.Store(db)
}

func parseIP2RegionRegion(region string, dbDate string) Location {
	parts := strings.Split(region, "|")
	if len(parts) >= 17 {
		return Location{
			Country:     cleanRegionField(parts[1]),
			Province:    cleanRegionField(parts[2]),
			City:        cleanRegionField(parts[3]),
			ISP:         cleanRegionField(parts[5]),
			CountryCode: cleanRegionField(parts[len(parts)-1]),
			ASN:         cleanRegionField(parts[13]),
			Source:      "ip2region",
			DBVersion:   dbDate,
		}
	}
	for len(parts) < 5 {
		parts = append(parts, "")
	}
	return Location{
		Country:     cleanRegionField(parts[0]),
		Province:    cleanRegionField(parts[1]),
		City:        cleanRegionField(parts[2]),
		ISP:         cleanRegionField(parts[3]),
		CountryCode: cleanRegionField(parts[4]),
		Source:      "ip2region",
		DBVersion:   dbDate,
	}
}

func cleanRegionField(value string) string {
	value = strings.TrimSpace(value)
	if value == "0" {
		return ""
	}
	return value
}
