package update

import (
	"bufio"
	"compress/gzip"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math/bits"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"ipasn/internal/store"
)

type Manifest struct {
	Version   string            `json:"version"`
	UpdatedAt time.Time         `json:"updated_at"`
	RawFiles  map[string]string `json:"raw_files"`
}

func LatestCAIDAPathFromCreationLog(r io.Reader) (string, error) {
	paths, err := LatestNCAIDAPathsFromCreationLog(r, 1)
	if err != nil {
		return "", err
	}
	return paths[len(paths)-1], nil
}

func LatestNCAIDAPathsFromCreationLog(r io.Reader, limit int) ([]string, error) {
	scanner := bufio.NewScanner(r)
	paths := []string{}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		paths = append(paths, fields[2])
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no CAIDA file path found in creation log")
	}
	if limit > 0 && len(paths) > limit {
		paths = paths[len(paths)-limit:]
	}
	return paths, nil
}

func ParseCAIDALine(line string) (string, int, bool) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return "", 0, false
	}

	bits, err := strconv.Atoi(fields[1])
	if err != nil {
		return "", 0, false
	}
	prefix := fields[0] + "/" + strconv.Itoa(bits)
	if _, err := netip.ParsePrefix(prefix); err != nil {
		return "", 0, false
	}

	asn, ok := firstASN(fields[2])
	return prefix, asn, ok
}

func ParseRIRASNLine(line string) []store.ASNProfile {
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}
	fields := strings.Split(line, "|")
	if len(fields) < 7 || strings.ToLower(fields[2]) != "asn" {
		return nil
	}

	start, err := strconv.Atoi(fields[3])
	if err != nil || start <= 0 {
		return nil
	}
	count, err := strconv.Atoi(fields[4])
	if err != nil || count <= 0 {
		return nil
	}
	if count > 100000 {
		count = 100000
	}

	registry := strings.ToLower(fields[0])
	country := strings.ToUpper(fields[1])
	profiles := make([]store.ASNProfile, 0, count)
	for i := 0; i < count; i++ {
		profiles = append(profiles, store.ASNProfile{
			ASN:      start + i,
			Country:  country,
			Registry: registry,
			Sources:  []string{"rir:" + registry},
		})
	}
	return profiles
}

func ParseRIRAllocationLine(line string) []store.AllocationRecord {
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}
	fields := strings.Split(line, "|")
	if len(fields) < 7 {
		return nil
	}

	registry := strings.ToLower(fields[0])
	country := strings.ToUpper(fields[1])
	resourceType := strings.ToLower(fields[2])
	status := strings.ToLower(fields[6])

	switch resourceType {
	case "ipv4":
		startAddr, err := netip.ParseAddr(fields[3])
		if err != nil || !startAddr.Is4() {
			return nil
		}
		count, err := strconv.ParseUint(fields[4], 10, 32)
		if err != nil || count == 0 {
			return nil
		}
		prefixes := ipv4RangeToPrefixes(startAddr, count)
		records := make([]store.AllocationRecord, 0, len(prefixes))
		for _, prefix := range prefixes {
			records = append(records, store.AllocationRecord{
				Prefix:   prefix,
				Country:  country,
				Registry: registry,
				Status:   status,
				Source:   "rir:" + registry,
			})
		}
		return records
	case "ipv6":
		startAddr, err := netip.ParseAddr(fields[3])
		if err != nil || !startAddr.Is6() {
			return nil
		}
		prefixLength, err := strconv.Atoi(fields[4])
		if err != nil || prefixLength < 0 || prefixLength > 128 {
			return nil
		}
		prefix := netip.PrefixFrom(startAddr, prefixLength).Masked().String()
		return []store.AllocationRecord{{
			Prefix:   prefix,
			Country:  country,
			Registry: registry,
			Status:   status,
			Source:   "rir:" + registry,
		}}
	default:
		return nil
	}
}

func ParseRPKIVRPLine(line string) (store.RPKIRecord, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return store.RPKIRecord{}, false
	}
	fields, err := csv.NewReader(strings.NewReader(line)).Read()
	if err != nil || len(fields) < 3 {
		return store.RPKIRecord{}, false
	}
	asnField := 0
	prefixField := 1
	maxLengthField := 2
	source := ""
	asn, ok := parseASNumber(fields[asnField])
	if !ok {
		if len(fields) < 4 {
			return store.RPKIRecord{}, false
		}
		asnField = 1
		prefixField = 2
		maxLengthField = 3
		asn, ok = parseASNumber(fields[asnField])
		if !ok {
			return store.RPKIRecord{}, false
		}
		source = "routinator"
	}
	prefix := strings.TrimSpace(fields[prefixField])
	if _, err := netip.ParsePrefix(prefix); err != nil {
		return store.RPKIRecord{}, false
	}
	maxLength, err := strconv.Atoi(strings.TrimSpace(fields[maxLengthField]))
	if err != nil {
		return store.RPKIRecord{}, false
	}
	if source == "" && len(fields) > 3 {
		source = strings.TrimSpace(fields[3])
	}
	return store.RPKIRecord{Prefix: prefix, MaxLength: maxLength, ASN: asn, Source: source}, true
}

func ParseIRRRouteObjects(r io.Reader, idx *store.IRRIndex) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024), 1024*1024)
	var prefix, source string
	var asn int
	flush := func() error {
		if prefix == "" || asn <= 0 {
			prefix, source, asn = "", "", 0
			return nil
		}
		if err := idx.Add(store.IRRRouteRecord{Prefix: prefix, ASN: asn, Source: source, Registry: source}); err != nil {
			return err
		}
		prefix, source, asn = "", "", 0
		return nil
	}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			if err := flush(); err != nil {
				return err
			}
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])
		switch key {
		case "route", "route6":
			if prefix != "" && asn > 0 {
				if err := flush(); err != nil {
					return err
				}
			}
			prefix = value
		case "origin":
			parsed, ok := parseASNumber(value)
			if ok {
				asn = parsed
			}
		case "source":
			source = value
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return flush()
}

func ParseBGPObservationLine(line string) (store.BGPObservationRecord, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return store.BGPObservationRecord{}, false
	}
	if strings.HasPrefix(line, "{") {
		var record store.BGPObservationRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			return store.BGPObservationRecord{}, false
		}
		if _, err := netip.ParsePrefix(record.Prefix); err != nil || record.OriginASN <= 0 {
			return store.BGPObservationRecord{}, false
		}
		return record, true
	}
	fields, err := csv.NewReader(strings.NewReader(line)).Read()
	if err != nil || len(fields) < 2 {
		return store.BGPObservationRecord{}, false
	}
	prefix := strings.TrimSpace(fields[0])
	if _, err := netip.ParsePrefix(prefix); err != nil {
		return store.BGPObservationRecord{}, false
	}
	asn, ok := parseASNumber(fields[1])
	if !ok {
		return store.BGPObservationRecord{}, false
	}
	record := store.BGPObservationRecord{Prefix: prefix, OriginASN: asn}
	if len(fields) > 2 {
		record.Source = strings.TrimSpace(fields[2])
	}
	if len(fields) > 3 {
		record.Collector = strings.TrimSpace(fields[3])
	}
	if len(fields) > 4 {
		record.ObservationCount, _ = strconv.Atoi(strings.TrimSpace(fields[4]))
	}
	if len(fields) > 5 {
		record.DominantUpstream, _ = strconv.Atoi(strings.TrimSpace(fields[5]))
	}
	return record, true
}

func BuildSnapshotFromRaw(dataDir string) (*store.Snapshot, error) {
	rawDir := filepath.Join(dataDir, "raw")
	prefixes := store.NewPrefixIndex()
	allocations := store.NewAllocationIndex()
	asns := store.NewASNIndex()
	egress := store.NewEgressIndex()
	reliability := store.NewReliabilityIndex()
	history := store.NewHistoryIndex()
	rawFiles := map[string]string{}

	for _, file := range []struct {
		key  string
		name string
	}{
		{"caida_ipv4", "caida-ipv4.pfx2as.gz"},
		{"caida_ipv6", "caida-ipv6.pfx2as.gz"},
	} {
		path := filepath.Join(rawDir, file.name)
		if _, err := os.Stat(path); err == nil {
			rawFiles[file.key] = path
			if err := parseCAIDAFile(path, prefixes); err != nil {
				return nil, err
			}
		}
	}

	matches, _ := filepath.Glob(filepath.Join(rawDir, "rir-*.txt"))
	for _, path := range matches {
		rawFiles[strings.TrimSuffix(filepath.Base(path), ".txt")] = path
		if err := parseRIRFile(path, asns, allocations); err != nil {
			return nil, err
		}
	}

	peeringPath := filepath.Join(rawDir, "peeringdb-net.json")
	if _, err := os.Stat(peeringPath); err == nil {
		rawFiles["peeringdb"] = peeringPath
		if err := parsePeeringDBFile(peeringPath, asns); err != nil {
			return nil, err
		}
	}
	if err := parsePeeringDBEgressFiles(rawDir, egress); err != nil {
		return nil, err
	}
	for _, name := range []string{"peeringdb-ix.json", "peeringdb-netixlan.json", "peeringdb-fac.json", "peeringdb-netfac.json"} {
		path := filepath.Join(rawDir, name)
		if _, err := os.Stat(path); err == nil {
			rawFiles[strings.TrimSuffix(name, ".json")] = path
		}
	}

	if prefixes.Count() == 0 {
		return nil, fmt.Errorf("no prefix records loaded from %s", rawDir)
	}
	if err := parseCAIDAHistory(rawDir, history, rawFiles); err != nil {
		return nil, err
	}
	if err := parseReliabilityFiles(rawDir, reliability, rawFiles); err != nil {
		return nil, err
	}

	status := store.Status{
		Version:   time.Now().UTC().Format("20060102T150405Z"),
		UpdatedAt: time.Now().UTC(),
		DataDir:   dataDir,
		RawFiles:  rawFiles,
	}
	return store.NewSnapshotFullWithReliability(prefixes, allocations, asns, history, egress, reliability, status), nil
}

func parseCAIDAFile(path string, prefixes *store.PrefixIndex) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	reader, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer reader.Close()

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024), 1024*1024)
	for scanner.Scan() {
		prefix, asn, ok := ParseCAIDALine(scanner.Text())
		if !ok {
			continue
		}
		_ = prefixes.Add(prefix, asn, "caida")
	}
	return scanner.Err()
}

func parseCAIDAHistory(rawDir string, history *store.HistoryIndex, rawFiles map[string]string) error {
	matches, _ := filepath.Glob(filepath.Join(rawDir, "history", "caida-ipv*.pfx2as.gz"))
	sort.Strings(matches)
	for _, path := range matches {
		prefixes := store.NewPrefixIndex()
		if err := parseCAIDAFile(path, prefixes); err != nil {
			return err
		}
		if prefixes.Count() == 0 {
			continue
		}
		label := historyLabel(path)
		history.AddSnapshot(label, prefixes)
		rawFiles["caida_history_"+sanitizeKey(label)] = path
	}
	return nil
}

func parseReliabilityFiles(rawDir string, reliability *store.ReliabilityIndex, rawFiles map[string]string) error {
	dirs := []string{rawDir, filepath.Join(filepath.Dir(rawDir), "generated")}
	for _, path := range reliabilityMatches(rawDir, "rpki-vrps*") {
		rawFiles["rpki_"+sanitizeKey(filepath.Base(path))] = path
		if err := parseRPKIFile(path, reliability.RPKI); err != nil {
			return err
		}
	}
	for _, path := range reliabilityMatches(rawDir, "irr-routes*") {
		rawFiles["irr_"+sanitizeKey(filepath.Base(path))] = path
		if err := parseIRRFile(path, reliability.IRR); err != nil {
			return err
		}
	}
	for _, dir := range dirs {
		for _, path := range reliabilityMatches(dir, "bgp-observations*") {
			rawFiles["bgp_observation_"+sanitizeKey(filepath.Base(path))] = path
			if err := parseBGPObservationFile(path, reliability.BGP); err != nil {
				return err
			}
		}
	}
	for _, path := range reliabilityMatches(rawDir, "geofeed*") {
		rawFiles["geofeed_"+sanitizeKey(filepath.Base(path))] = path
	}
	return nil
}

func reliabilityMatches(rawDir, pattern string) []string {
	matches, _ := filepath.Glob(filepath.Join(rawDir, pattern))
	out := []string{}
	for _, path := range matches {
		if strings.HasSuffix(path, ".tmp") {
			continue
		}
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

func parseRPKIFile(path string, idx *store.RPKIIndex) error {
	reader, closeFn, err := openMaybeGzip(path)
	if err != nil {
		return err
	}
	defer closeFn()
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024), 1024*1024)
	for scanner.Scan() {
		record, ok := ParseRPKIVRPLine(scanner.Text())
		if !ok {
			continue
		}
		if err := idx.Add(record); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func parseIRRFile(path string, idx *store.IRRIndex) error {
	reader, closeFn, err := openMaybeGzip(path)
	if err != nil {
		return err
	}
	defer closeFn()
	return ParseIRRRouteObjects(reader, idx)
}

func parseBGPObservationFile(path string, idx *store.BGPObservationIndex) error {
	reader, closeFn, err := openMaybeGzip(path)
	if err != nil {
		return err
	}
	defer closeFn()
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024), 1024*1024)
	for scanner.Scan() {
		record, ok := ParseBGPObservationLine(scanner.Text())
		if !ok {
			continue
		}
		if err := idx.Add(record); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func openMaybeGzip(path string) (io.Reader, func(), error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, func() {}, err
	}
	if !strings.HasSuffix(strings.ToLower(path), ".gz") {
		return file, func() { _ = file.Close() }, nil
	}
	reader, err := gzip.NewReader(file)
	if err != nil {
		_ = file.Close()
		return nil, func() {}, err
	}
	return reader, func() {
		_ = reader.Close()
		_ = file.Close()
	}, nil
}

func historyLabel(filePath string) string {
	base := strings.TrimSuffix(filepath.Base(filePath), ".pfx2as.gz")
	base = strings.TrimPrefix(base, "caida-")
	return base
}

func sanitizeKey(value string) string {
	replacer := strings.NewReplacer("-", "_", ".", "_", "/", "_", " ", "_")
	return replacer.Replace(strings.ToLower(value))
}

func parseRIRFile(path string, asns *store.ASNIndex, allocations *store.AllocationIndex) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		for _, profile := range ParseRIRASNLine(line) {
			asns.Upsert(profile)
		}
		for _, allocation := range ParseRIRAllocationLine(line) {
			_ = allocations.Add(allocation)
		}
	}
	return scanner.Err()
}

func ipv4RangeToPrefixes(startAddr netip.Addr, count uint64) []string {
	raw := startAddr.As4()
	start := binary.BigEndian.Uint32(raw[:])
	prefixes := []string{}
	for count > 0 {
		alignment := uint64(1) << bits.TrailingZeros32(start)
		if start == 0 {
			alignment = uint64(1) << 32
		}
		size := minUint64(alignment, highestPowerOfTwo(count))
		prefixLength := 32 - bits.TrailingZeros64(size)
		var addrBytes [4]byte
		binary.BigEndian.PutUint32(addrBytes[:], start)
		prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom4(addrBytes), prefixLength).Masked().String())
		start += uint32(size)
		count -= size
	}
	return prefixes
}

func highestPowerOfTwo(value uint64) uint64 {
	if value == 0 {
		return 0
	}
	return uint64(1) << (bits.Len64(value) - 1)
}

func minUint64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func parsePeeringDBFile(path string, asns *store.ASNIndex) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	var response struct {
		Data []struct {
			ASN      int    `json:"asn"`
			Name     string `json:"name"`
			AKA      string `json:"aka"`
			InfoType string `json:"info_type"`
			Website  string `json:"website"`
		} `json:"data"`
	}
	if err := json.NewDecoder(file).Decode(&response); err != nil {
		return err
	}
	for _, item := range response.Data {
		asns.Upsert(store.ASNProfile{
			ASN:      item.ASN,
			Name:     item.Name,
			AKA:      item.AKA,
			InfoType: item.InfoType,
			Website:  item.Website,
			Sources:  []string{"peeringdb"},
		})
	}
	return nil
}

func parsePeeringDBEgressFiles(rawDir string, egress *store.EgressIndex) error {
	ixByID := map[int]struct {
		Name    string
		Country string
		City    string
	}{}
	if err := parsePeeringDBIXFile(filepath.Join(rawDir, "peeringdb-ix.json"), ixByID); err != nil {
		return err
	}
	facByID := map[int]struct {
		Name    string
		Country string
		City    string
	}{}
	if err := parsePeeringDBFacilityFile(filepath.Join(rawDir, "peeringdb-fac.json"), facByID); err != nil {
		return err
	}
	if err := parsePeeringDBNetIXLANFile(filepath.Join(rawDir, "peeringdb-netixlan.json"), ixByID, egress); err != nil {
		return err
	}
	if err := parsePeeringDBNetFacilityFile(filepath.Join(rawDir, "peeringdb-netfac.json"), facByID, egress); err != nil {
		return err
	}
	return nil
}

func parsePeeringDBIXFile(path string, out map[int]struct {
	Name    string
	Country string
	City    string
}) error {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	var response struct {
		Data []struct {
			ID      int    `json:"id"`
			Name    string `json:"name"`
			Country string `json:"country"`
			City    string `json:"city"`
		} `json:"data"`
	}
	if err := json.NewDecoder(file).Decode(&response); err != nil {
		return err
	}
	for _, item := range response.Data {
		if item.ID <= 0 {
			continue
		}
		out[item.ID] = struct {
			Name    string
			Country string
			City    string
		}{Name: item.Name, Country: strings.ToUpper(item.Country), City: item.City}
	}
	return nil
}

func parsePeeringDBFacilityFile(path string, out map[int]struct {
	Name    string
	Country string
	City    string
}) error {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	var response struct {
		Data []struct {
			ID      int    `json:"id"`
			Name    string `json:"name"`
			Country string `json:"country"`
			City    string `json:"city"`
		} `json:"data"`
	}
	if err := json.NewDecoder(file).Decode(&response); err != nil {
		return err
	}
	for _, item := range response.Data {
		if item.ID <= 0 {
			continue
		}
		out[item.ID] = struct {
			Name    string
			Country string
			City    string
		}{Name: item.Name, Country: strings.ToUpper(item.Country), City: item.City}
	}
	return nil
}

func parsePeeringDBNetIXLANFile(path string, ixByID map[int]struct {
	Name    string
	Country string
	City    string
}, egress *store.EgressIndex) error {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	var response struct {
		Data []struct {
			ASN     int    `json:"asn"`
			IXID    int    `json:"ix_id"`
			Name    string `json:"name"`
			IPAddr4 string `json:"ipaddr4"`
			IPAddr6 string `json:"ipaddr6"`
			Speed   int    `json:"speed"`
		} `json:"data"`
	}
	if err := json.NewDecoder(file).Decode(&response); err != nil {
		return err
	}
	for _, item := range response.Data {
		ix := ixByID[item.IXID]
		name := firstNonEmpty(item.Name, ix.Name)
		egress.AddIXP(store.IXPPresence{
			ASN:     item.ASN,
			IXID:    item.IXID,
			Name:    name,
			Country: ix.Country,
			City:    ix.City,
			IP:      firstNonEmpty(item.IPAddr4, item.IPAddr6),
			Speed:   item.Speed,
		})
	}
	return nil
}

func parsePeeringDBNetFacilityFile(path string, facByID map[int]struct {
	Name    string
	Country string
	City    string
}, egress *store.EgressIndex) error {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	var response struct {
		Data []struct {
			ASN      int `json:"asn"`
			LocalASN int `json:"local_asn"`
			FacID    int `json:"fac_id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(file).Decode(&response); err != nil {
		return err
	}
	for _, item := range response.Data {
		asn := item.LocalASN
		if asn == 0 {
			asn = item.ASN
		}
		fac := facByID[item.FacID]
		egress.AddFacility(store.FacilityPresence{
			ASN:        asn,
			FacilityID: item.FacID,
			Name:       fac.Name,
			Country:    fac.Country,
			City:       fac.City,
		})
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func firstASN(value string) (int, bool) {
	value = strings.Trim(value, "{}")
	for _, sep := range []string{"_", ","} {
		if strings.Contains(value, sep) {
			value = strings.Split(value, sep)[0]
		}
	}
	asn, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || asn <= 0 {
		return 0, false
	}
	return asn, true
}

func parseASNumber(value string) (int, bool) {
	value = strings.TrimSpace(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(value)), "AS"))
	return firstASN(value)
}
