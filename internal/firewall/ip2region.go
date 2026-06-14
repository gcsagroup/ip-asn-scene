package firewall

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"ipasn/internal/classify"
	"ipasn/internal/config"
	"ipasn/internal/store"

	"github.com/lionsoul2014/ip2region/binding/golang/xdb"
)

type ip2RegionSegment struct {
	Start       string
	End         string
	Country     string
	Province    string
	City        string
	ISP         string
	CountryCode string
	ASN         int
}

func OptionsFromConfig(cfg config.FirewallListsConfig) Options {
	return Options{
		OutputDir:     cfg.OutputDir,
		Countries:     cfg.Countries,
		Companies:     cfg.Companies,
		Scenes:        cfg.Scenes,
		MinConfidence: cfg.MinConfidence,
		IncludeIPv4:   cfg.IncludeIPv4,
		IncludeIPv6:   cfg.IncludeIPv6,
		WriteEntries:  cfg.WriteEntries,
	}
}

func GenerateFromIP2Region(ctx context.Context, cfg config.Config, snapshot *store.Snapshot) (Summary, error) {
	return Generate(ctx, IP2RegionIterator(cfg.IP2Region, snapshot), OptionsFromConfig(cfg.FirewallLists))
}

func IP2RegionIterator(cfg config.IP2RegionConfig, snapshot *store.Snapshot) RecordIterator {
	return func(ctx context.Context, emit func(Record) error) error {
		loaded := false
		if cfg.V4File != "" {
			if err := iterateIP2RegionFile(ctx, cfg.V4File, snapshot, emit); err != nil {
				if !os.IsNotExist(err) {
					return err
				}
			} else {
				loaded = true
			}
		}
		if cfg.V6File != "" {
			if err := iterateIP2RegionFile(ctx, cfg.V6File, snapshot, emit); err != nil {
				if !os.IsNotExist(err) {
					return err
				}
			} else {
				loaded = true
			}
		}
		if !loaded {
			return fmt.Errorf("no ip2region xdb files loaded")
		}
		return nil
	}
}

func iterateIP2RegionFile(ctx context.Context, path string, snapshot *store.Snapshot, emit func(Record) error) error {
	content, err := xdb.LoadContentFromFile(path)
	if err != nil {
		return err
	}
	header, err := xdb.LoadHeaderFromBuff(content)
	if err != nil {
		return err
	}
	version, err := xdb.VersionFromHeader(header)
	if err != nil {
		return err
	}
	if header.StartIndexPtr == 0 || header.EndIndexPtr == 0 {
		return nil
	}
	step := version.SegmentIndexSize
	for offset := int(header.StartIndexPtr); offset <= int(header.EndIndexPtr); offset += step {
		if err := ctx.Err(); err != nil {
			return err
		}
		if offset+step > len(content) {
			return fmt.Errorf("segment index out of range in %s at %d", path, offset)
		}
		segment, err := decodeIP2RegionSegment(content, offset, version)
		if err != nil {
			return fmt.Errorf("%s segment %d: %w", path, offset, err)
		}
		if segment.CountryCode == "" && segment.Country == "" && segment.ISP == "" && segment.ASN == 0 {
			continue
		}
		prefixes, err := rangeToPrefixes(segment.Start, segment.End)
		if err != nil {
			return err
		}
		record := recordFromSegment(segment, snapshot)
		for _, cidr := range prefixes {
			record.CIDR = cidr
			if err := emit(record); err != nil {
				return err
			}
		}
	}
	return nil
}

func decodeIP2RegionSegment(content []byte, offset int, version *xdb.Version) (ip2RegionSegment, error) {
	bytes := version.Bytes
	dBytes := bytes * 2
	dataLen := int(binary.LittleEndian.Uint16(content[offset+dBytes:]))
	dataPtr := int(binary.LittleEndian.Uint32(content[offset+dBytes+2:]))
	if dataLen <= 0 {
		return ip2RegionSegment{}, nil
	}
	if dataPtr < 0 || dataPtr+dataLen > len(content) {
		return ip2RegionSegment{}, fmt.Errorf("region data out of range ptr=%d len=%d", dataPtr, dataLen)
	}
	start, err := ipBytesToAddr(content[offset:offset+bytes], version)
	if err != nil {
		return ip2RegionSegment{}, err
	}
	end, err := ipBytesToAddr(content[offset+bytes:offset+dBytes], version)
	if err != nil {
		return ip2RegionSegment{}, err
	}
	segment := parseIP2RegionRegion(string(content[dataPtr : dataPtr+dataLen]))
	segment.Start = start.String()
	segment.End = end.String()
	return segment, nil
}

func ipBytesToAddr(raw []byte, version *xdb.Version) (netip.Addr, error) {
	if version.Id == xdb.IPv4VersionNo {
		if len(raw) != 4 {
			return netip.Addr{}, fmt.Errorf("invalid IPv4 bytes")
		}
		return netip.AddrFrom4([4]byte{raw[3], raw[2], raw[1], raw[0]}), nil
	}
	if len(raw) != 16 {
		return netip.Addr{}, fmt.Errorf("invalid IPv6 bytes")
	}
	var arr [16]byte
	copy(arr[:], raw)
	return netip.AddrFrom16(arr), nil
}

func parseIP2RegionRegion(region string) ip2RegionSegment {
	parts := strings.Split(region, "|")
	clean := func(index int) string {
		if index < 0 || index >= len(parts) {
			return ""
		}
		value := strings.TrimSpace(parts[index])
		if value == "0" {
			return ""
		}
		return value
	}
	segment := ip2RegionSegment{}
	if len(parts) >= 17 {
		segment.Country = clean(1)
		segment.Province = clean(2)
		segment.City = clean(3)
		segment.ISP = clean(5)
		segment.CountryCode = strings.ToUpper(clean(len(parts) - 1))
		segment.ASN, _ = strconv.Atoi(clean(13))
		return segment
	}
	segment.Country = clean(0)
	segment.Province = clean(1)
	segment.City = clean(2)
	segment.ISP = clean(3)
	segment.CountryCode = strings.ToUpper(clean(4))
	return segment
}

func recordFromSegment(segment ip2RegionSegment, snapshot *store.Snapshot) Record {
	addr, _ := netip.ParseAddr(segment.Start)
	asn := segment.ASN
	matchedPrefix := ""
	if snapshot != nil && snapshot.Prefixes != nil && addr.IsValid() {
		if prefix, ok := snapshot.Prefixes.Lookup(addr); ok {
			if asn == 0 {
				asn = prefix.ASN
			}
			matchedPrefix = prefix.Prefix
		}
	}
	profile := store.ASNProfile{ASN: asn, Name: segment.ISP}
	if snapshot != nil && snapshot.ASNs != nil && asn > 0 {
		if found, ok := snapshot.ASNs.Lookup(asn); ok {
			profile = found
		}
	}
	classification := classify.Classify(classify.Input{
		IP:            addr,
		MatchedPrefix: matchedPrefix,
		Profile:       profile,
	})
	confidence := classification.Confidence
	if confidence < 0.9 && (segment.CountryCode != "" || segment.Country != "") {
		confidence = 0.9
	}
	company := detectCompany(strings.Join([]string{profile.Name, profile.AKA, segment.ISP}, " "))
	if company == "" && profile.Name != "" {
		company = slug(profile.Name)
	}
	sources := []string{"ip2region"}
	if matchedPrefix != "" {
		sources = append(sources, "caida")
	}
	if classification.Scene != "" && classification.Scene != "NET" {
		sources = append(sources, "scene_rules")
	}
	return Record{
		Country:     segment.Country,
		CountryCode: segment.CountryCode,
		Province:    segment.Province,
		City:        segment.City,
		ISP:         segment.ISP,
		ASN:         asn,
		Company:     company,
		Scenes:      []string{classification.Scene},
		Confidence:  confidence,
		Sources:     sources,
		Evidence:    classification.Evidence,
	}
}
