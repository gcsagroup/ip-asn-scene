package geo

import (
	"context"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

type GeofeedLocator struct {
	v4 [33]map[uint32]Location
	v6 [129]map[[2]uint64]Location
}

type CompositeLocator struct {
	locators []Locator
}

func NewGeofeedLocatorFromDir(dataDir string) (*GeofeedLocator, error) {
	matches, err := filepath.Glob(filepath.Join(dataDir, "raw", "geofeed*.csv"))
	if err != nil {
		return nil, err
	}
	if len(matches) == 0 {
		return nil, nil
	}
	return NewGeofeedLocatorFromFiles(matches...)
}

func NewGeofeedLocatorFromFiles(paths ...string) (*GeofeedLocator, error) {
	locator := &GeofeedLocator{}
	loaded := false
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		file, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		count, parseErr := locator.load(file)
		closeErr := file.Close()
		if parseErr != nil {
			return nil, fmt.Errorf("%s: %w", path, parseErr)
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if count > 0 {
			loaded = true
		}
	}
	if !loaded {
		return nil, nil
	}
	return locator, nil
}

func NewCompositeLocator(locators ...Locator) Locator {
	clean := make([]Locator, 0, len(locators))
	for _, locator := range locators {
		if locator != nil {
			clean = append(clean, locator)
		}
	}
	if len(clean) == 0 {
		return nil
	}
	if len(clean) == 1 {
		return clean[0]
	}
	return CompositeLocator{locators: clean}
}

func (l CompositeLocator) Lookup(ctx context.Context, ip string) (Location, bool) {
	for _, locator := range l.locators {
		location, ok := locator.Lookup(ctx, ip)
		if ok {
			return location, true
		}
	}
	return Location{}, false
}

func (l *GeofeedLocator) Lookup(ctx context.Context, ip string) (Location, bool) {
	_ = ctx
	if l == nil {
		return Location{}, false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return Location{}, false
	}
	addr = addr.Unmap()
	if addr.Is4() {
		for bits := 32; bits >= 0; bits-- {
			bucket := l.v4[bits]
			if bucket == nil {
				continue
			}
			if location, ok := bucket[maskGeofeedIPv4(addr, bits)]; ok {
				return location, true
			}
		}
		return Location{}, false
	}
	if !addr.Is6() {
		return Location{}, false
	}
	for bits := 128; bits >= 0; bits-- {
		bucket := l.v6[bits]
		if bucket == nil {
			continue
		}
		if location, ok := bucket[maskGeofeedIPv6(addr, bits)]; ok {
			return location, true
		}
	}
	return Location{}, false
}

func (l *GeofeedLocator) load(reader io.Reader) (int, error) {
	csvReader := csv.NewReader(reader)
	csvReader.FieldsPerRecord = -1
	count := 0
	for {
		fields, err := csvReader.Read()
		if err == io.EOF {
			return count, nil
		}
		if err != nil {
			return count, err
		}
		if len(fields) == 0 {
			continue
		}
		prefixText := strings.TrimSpace(fields[0])
		if prefixText == "" || strings.HasPrefix(prefixText, "#") {
			continue
		}
		prefix, err := netip.ParsePrefix(prefixText)
		if err != nil {
			continue
		}
		location := Location{
			CountryCode: geofeedField(fields, 1),
			Province:    geofeedField(fields, 2),
			City:        geofeedField(fields, 3),
			Source:      "geofeed",
		}
		location.Country = location.CountryCode
		if location.CountryCode == "" && location.Province == "" && location.City == "" {
			continue
		}
		l.add(prefix, location)
		count++
	}
}

func (l *GeofeedLocator) add(prefix netip.Prefix, location Location) {
	prefix = prefix.Masked()
	originalAddr := prefix.Addr()
	addr := originalAddr.Unmap()
	if addr.Is4() {
		if originalAddr.Is6() {
			return
		}
		bits := prefix.Bits()
		if bits < 0 || bits > 32 {
			return
		}
		if l.v4[bits] == nil {
			l.v4[bits] = map[uint32]Location{}
		}
		l.v4[bits][maskGeofeedIPv4(addr, bits)] = location
		return
	}
	bits := prefix.Bits()
	if bits < 0 || bits > 128 {
		return
	}
	if l.v6[bits] == nil {
		l.v6[bits] = map[[2]uint64]Location{}
	}
	l.v6[bits][maskGeofeedIPv6(addr, bits)] = location
}

func geofeedField(fields []string, index int) string {
	if index < 0 || index >= len(fields) {
		return ""
	}
	return strings.TrimSpace(fields[index])
}

func maskGeofeedIPv4(addr netip.Addr, bits int) uint32 {
	raw := addr.As4()
	value := binary.BigEndian.Uint32(raw[:])
	if bits == 0 {
		return 0
	}
	return value & (uint32(0xffffffff) << (32 - bits))
}

func maskGeofeedIPv6(addr netip.Addr, bits int) [2]uint64 {
	raw := addr.As16()
	hi := binary.BigEndian.Uint64(raw[0:8])
	lo := binary.BigEndian.Uint64(raw[8:16])
	switch {
	case bits <= 0:
		return [2]uint64{0, 0}
	case bits < 64:
		return [2]uint64{hi & (uint64(0xffffffffffffffff) << (64 - bits)), 0}
	case bits == 64:
		return [2]uint64{hi, 0}
	case bits < 128:
		return [2]uint64{hi, lo & (uint64(0xffffffffffffffff) << (128 - bits))}
	default:
		return [2]uint64{hi, lo}
	}
}
