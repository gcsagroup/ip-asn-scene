package firewall

import (
	"bufio"
	"container/heap"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const sortChunkLineLimit = 200000

type Options struct {
	OutputDir     string
	Countries     []string
	Companies     []string
	Scenes        []string
	MinConfidence float64
	IncludeIPv4   bool
	IncludeIPv6   bool
	WriteEntries  bool
}

type Record struct {
	CIDR        string   `json:"cidr"`
	Country     string   `json:"country,omitempty"`
	CountryCode string   `json:"country_code,omitempty"`
	Province    string   `json:"province,omitempty"`
	City        string   `json:"city,omitempty"`
	ISP         string   `json:"isp,omitempty"`
	ASN         int      `json:"asn,omitempty"`
	Company     string   `json:"company,omitempty"`
	Scenes      []string `json:"scenes,omitempty"`
	Confidence  float64  `json:"confidence,omitempty"`
	Sources     []string `json:"sources,omitempty"`
	Evidence    []string `json:"evidence,omitempty"`
}

type Summary struct {
	GeneratedAt    time.Time            `json:"generated_at"`
	TotalRecords   int                  `json:"total_records"`
	ExportedRecord int                  `json:"exported_records"`
	Files          map[string]FileStats `json:"files"`
}

type Index = Summary

type FileStats struct {
	Count int    `json:"count"`
	Type  string `json:"type"`
	Key   string `json:"key"`
}

type RecordIterator func(context.Context, func(Record) error) error

type writerBucket struct {
	typ     string
	key     string
	rawPath string
	file    *os.File
	writer  *bufio.Writer
}

func GenerateFromRecords(ctx context.Context, records []Record, options Options) (Summary, error) {
	return Generate(ctx, func(ctx context.Context, emit func(Record) error) error {
		for _, record := range records {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := emit(record); err != nil {
				return err
			}
		}
		return nil
	}, options)
}

func Generate(ctx context.Context, iterator RecordIterator, options Options) (Summary, error) {
	options = normalizeOptions(options)
	if err := os.MkdirAll(options.OutputDir, 0o775); err != nil {
		return Summary{}, err
	}
	if err := cleanupGeneratedOutput(options.OutputDir); err != nil {
		return Summary{}, err
	}
	tempDir, err := os.MkdirTemp(options.OutputDir, ".tmp-firewall-*")
	if err != nil {
		return Summary{}, err
	}
	defer os.RemoveAll(tempDir)

	countryTargets := upperSet(options.Countries)
	companyTargets := slugSet(options.Companies)
	sceneTargets := upperSet(options.Scenes)
	buckets := map[string]*writerBucket{}
	summary := Summary{
		GeneratedAt: time.Now().UTC(),
		Files:       map[string]FileStats{},
	}

	if iterator == nil {
		return Summary{}, fmt.Errorf("record iterator is nil")
	}

	var entriesFile *os.File
	var entriesWriter *bufio.Writer
	var entriesEncoder *json.Encoder
	if options.WriteEntries {
		entriesFile, err = os.Create(filepath.Join(tempDir, "entries.jsonl"))
		if err != nil {
			return Summary{}, err
		}
		entriesWriter = bufio.NewWriter(entriesFile)
		entriesEncoder = json.NewEncoder(entriesWriter)
	}

	if err := iterator(ctx, func(record Record) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		summary.TotalRecords++
		record = normalizeRecord(record)
		if record.CIDR == "" || !familyAllowed(record.CIDR, options) {
			return nil
		}
		if record.Confidence > 0 && record.Confidence < options.MinConfidence {
			return nil
		}

		exported := false
		if record.CountryCode != "" && targetAllows(countryTargets, record.CountryCode) {
			if err := addBucket(tempDir, buckets, "country", record.CountryCode, "country-"+record.CountryCode+".cidr", record.CIDR); err != nil {
				return err
			}
			exported = true
		}
		if record.Company != "" && len(companyTargets) > 0 && targetAllows(companyTargets, record.Company) {
			if err := addBucket(tempDir, buckets, "company", record.Company, "company-"+record.Company+".cidr", record.CIDR); err != nil {
				return err
			}
			exported = true
		}
		for _, scene := range record.Scenes {
			if scene != "" && targetAllows(sceneTargets, scene) {
				if err := addBucket(tempDir, buckets, "scene", scene, "scene-"+scene+".cidr", record.CIDR); err != nil {
					return err
				}
				exported = true
			}
		}
		if exported && options.WriteEntries {
			if err := entriesEncoder.Encode(record); err != nil {
				return err
			}
		}
		if exported {
			summary.ExportedRecord++
		}
		return nil
	}); err != nil {
		closeBuckets(buckets)
		closeEntries(entriesFile, entriesWriter)
		return Summary{}, err
	}

	if err := closeBuckets(buckets); err != nil {
		closeEntries(entriesFile, entriesWriter)
		return Summary{}, err
	}
	if err := closeEntries(entriesFile, entriesWriter); err != nil {
		return Summary{}, err
	}

	for name, bucket := range buckets {
		count, err := writeUniqueSortedFile(bucket.rawPath, filepath.Join(options.OutputDir, name))
		if err != nil {
			return Summary{}, err
		}
		summary.Files[name] = FileStats{Count: count, Type: bucket.typ, Key: bucket.key}
	}
	if options.WriteEntries {
		if err := os.Rename(filepath.Join(tempDir, "entries.jsonl"), filepath.Join(options.OutputDir, "entries.jsonl")); err != nil {
			return Summary{}, err
		}
		summary.Files["entries.jsonl"] = FileStats{Count: summary.ExportedRecord, Type: "entries", Key: "all"}
	}
	body, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return Summary{}, err
	}
	if err := os.WriteFile(filepath.Join(options.OutputDir, "index.json"), append(body, '\n'), 0o664); err != nil {
		return Summary{}, err
	}
	return summary, nil
}

func normalizeOptions(options Options) Options {
	if strings.TrimSpace(options.OutputDir) == "" {
		options.OutputDir = filepath.Join("data", "generated", "firewall")
	}
	if options.MinConfidence <= 0 {
		options.MinConfidence = 0.8
	}
	if options.MinConfidence > 1 {
		options.MinConfidence = 1
	}
	if !options.IncludeIPv4 && !options.IncludeIPv6 {
		options.IncludeIPv4 = true
		options.IncludeIPv6 = true
	}
	if len(options.Scenes) == 0 {
		options.Scenes = []string{"IDC", "CDN", "TOR", "PROXY", "BLOCKLIST"}
	}
	return options
}

func normalizeRecord(record Record) Record {
	record.CountryCode = strings.ToUpper(strings.TrimSpace(record.CountryCode))
	record.Company = slug(record.Company)
	if record.Company == "" {
		record.Company = detectCompany(record.ISP)
	}
	for i := range record.Scenes {
		record.Scenes[i] = strings.ToUpper(strings.TrimSpace(record.Scenes[i]))
	}
	record.Scenes = uniqueStrings(record.Scenes)
	record.Sources = uniqueStrings(record.Sources)
	record.Evidence = uniqueStrings(record.Evidence)
	return record
}

func addBucket(tempDir string, buckets map[string]*writerBucket, typ, key, name, cidr string) error {
	bucket := buckets[name]
	if bucket == nil {
		rawPath := filepath.Join(tempDir, name+".raw")
		file, err := os.Create(rawPath)
		if err != nil {
			return err
		}
		bucket = &writerBucket{
			typ:     typ,
			key:     key,
			rawPath: rawPath,
			file:    file,
			writer:  bufio.NewWriter(file),
		}
		buckets[name] = bucket
	}
	if _, err := bucket.writer.WriteString(cidr + "\n"); err != nil {
		return err
	}
	return nil
}

func cleanupGeneratedOutput(outputDir string) error {
	patterns := []string{
		"country-*.cidr",
		"company-*.cidr",
		"scene-*.cidr",
		"entries.jsonl",
		"index.json",
	}
	for _, pattern := range patterns {
		matches, err := filepath.Glob(filepath.Join(outputDir, pattern))
		if err != nil {
			return err
		}
		for _, match := range matches {
			if err := os.Remove(match); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	return nil
}

func closeBuckets(buckets map[string]*writerBucket) error {
	var firstErr error
	for _, bucket := range buckets {
		if err := bucket.close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (bucket *writerBucket) close() error {
	var firstErr error
	if bucket.writer != nil {
		if err := bucket.writer.Flush(); err != nil {
			firstErr = err
		}
		bucket.writer = nil
	}
	if bucket.file != nil {
		if err := bucket.file.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		bucket.file = nil
	}
	return firstErr
}

func closeEntries(file *os.File, writer *bufio.Writer) error {
	var firstErr error
	if writer != nil {
		if err := writer.Flush(); err != nil {
			firstErr = err
		}
	}
	if file != nil {
		if err := file.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func writeUniqueSortedFile(rawPath string, outputPath string) (int, error) {
	input, err := os.Open(rawPath)
	if err != nil {
		return 0, err
	}
	defer input.Close()

	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	chunks := []string{}
	lines := make([]string, 0, sortChunkLineLimit)
	flushChunk := func() error {
		if len(lines) == 0 {
			return nil
		}
		sorted := sortUniqueLines(lines)
		chunkPath := filepath.Join(filepath.Dir(rawPath), fmt.Sprintf("%s.chunk-%06d", filepath.Base(rawPath), len(chunks)))
		if err := writeLines(chunkPath, sorted); err != nil {
			return err
		}
		chunks = append(chunks, chunkPath)
		lines = lines[:0]
		return nil
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lines = append(lines, line)
		if len(lines) >= sortChunkLineLimit {
			if err := flushChunk(); err != nil {
				return 0, err
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	if len(chunks) == 0 {
		sorted := sortUniqueLines(lines)
		count, err := writeCoalescedCIDRs(outputPath, sorted)
		if err != nil {
			return 0, err
		}
		return count, nil
	}
	if err := flushChunk(); err != nil {
		return 0, err
	}
	return mergeSortedChunks(chunks, outputPath)
}

type coalescingCIDRWriter struct {
	writer     *bufio.Writer
	hasRange   bool
	familyBits int
	start      big.Int
	end        big.Int
	count      int
}

func writeCoalescedCIDRs(outputPath string, sortedCIDRs []string) (int, error) {
	output, err := os.Create(outputPath)
	if err != nil {
		return 0, err
	}
	defer output.Close()
	writer := bufio.NewWriter(output)
	coalescer := coalescingCIDRWriter{writer: writer}
	for _, cidr := range sortedCIDRs {
		if err := coalescer.add(cidr); err != nil {
			return 0, err
		}
	}
	if err := coalescer.flush(); err != nil {
		return 0, err
	}
	if err := writer.Flush(); err != nil {
		return 0, err
	}
	return coalescer.count, nil
}

func (writer *coalescingCIDRWriter) add(cidr string) error {
	start, end, familyBits, err := prefixRange(cidr)
	if err != nil {
		return err
	}
	if !writer.hasRange {
		writer.setRange(start, end, familyBits)
		return nil
	}
	next := new(big.Int).Add(&writer.end, big.NewInt(1))
	if writer.familyBits == familyBits && start.Cmp(next) <= 0 {
		if end.Cmp(&writer.end) > 0 {
			writer.end.Set(end)
		}
		return nil
	}
	if err := writer.flush(); err != nil {
		return err
	}
	writer.setRange(start, end, familyBits)
	return nil
}

func (writer *coalescingCIDRWriter) setRange(start, end *big.Int, familyBits int) {
	writer.hasRange = true
	writer.familyBits = familyBits
	writer.start.Set(start)
	writer.end.Set(end)
}

func (writer *coalescingCIDRWriter) flush() error {
	if !writer.hasRange {
		return nil
	}
	startAddr, err := bigToAddr(&writer.start, writer.familyBits)
	if err != nil {
		return err
	}
	endAddr, err := bigToAddr(&writer.end, writer.familyBits)
	if err != nil {
		return err
	}
	prefixes, err := rangeToPrefixes(startAddr.String(), endAddr.String())
	if err != nil {
		return err
	}
	for _, prefix := range prefixes {
		if _, err := writer.writer.WriteString(prefix + "\n"); err != nil {
			return err
		}
		writer.count++
	}
	writer.hasRange = false
	return nil
}

func prefixRange(cidr string) (*big.Int, *big.Int, int, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, nil, 0, err
	}
	prefix = prefix.Masked()
	addr := prefix.Addr().Unmap()
	familyBits := 128
	if addr.Is4() {
		familyBits = 32
	}
	start := addrToBig(addr, familyBits)
	hostBits := familyBits - prefix.Bits()
	size := new(big.Int).Lsh(big.NewInt(1), uint(hostBits))
	end := new(big.Int).Add(start, new(big.Int).Sub(size, big.NewInt(1)))
	return start, end, familyBits, nil
}

type sortedLine struct {
	line string
	key  string
}

func sortUniqueLines(lines []string) []string {
	seen := map[string]struct{}{}
	items := make([]sortedLine, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		items = append(items, sortedLine{line: line, key: prefixSortKey(line)})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].key == items[j].key {
			return items[i].line < items[j].line
		}
		return items[i].key < items[j].key
	})
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.line)
	}
	return out
}

type chunkReader struct {
	file    *os.File
	scanner *bufio.Scanner
}

type mergeItem struct {
	line        string
	key         string
	readerIndex int
}

type mergeHeap []mergeItem

func (h mergeHeap) Len() int { return len(h) }

func (h mergeHeap) Less(i, j int) bool {
	if h[i].key == h[j].key {
		return h[i].line < h[j].line
	}
	return h[i].key < h[j].key
}

func (h mergeHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

func (h *mergeHeap) Push(value any) {
	*h = append(*h, value.(mergeItem))
}

func (h *mergeHeap) Pop() any {
	old := *h
	item := old[len(old)-1]
	*h = old[:len(old)-1]
	return item
}

func mergeSortedChunks(chunks []string, outputPath string) (int, error) {
	readers := make([]chunkReader, 0, len(chunks))
	defer func() {
		for _, reader := range readers {
			reader.file.Close()
		}
	}()

	items := mergeHeap{}
	for _, chunkPath := range chunks {
		file, err := os.Open(chunkPath)
		if err != nil {
			return 0, err
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		readers = append(readers, chunkReader{file: file, scanner: scanner})
		index := len(readers) - 1
		if scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			heap.Push(&items, mergeItem{line: line, key: prefixSortKey(line), readerIndex: index})
		}
		if err := scanner.Err(); err != nil {
			return 0, err
		}
	}
	heap.Init(&items)

	output, err := os.Create(outputPath)
	if err != nil {
		return 0, err
	}
	defer output.Close()
	writer := bufio.NewWriter(output)
	coalescer := coalescingCIDRWriter{writer: writer}

	var last string
	for items.Len() > 0 {
		item := heap.Pop(&items).(mergeItem)
		if item.line != "" && item.line != last {
			if err := coalescer.add(item.line); err != nil {
				return 0, err
			}
			last = item.line
		}
		reader := readers[item.readerIndex]
		if reader.scanner.Scan() {
			line := strings.TrimSpace(reader.scanner.Text())
			heap.Push(&items, mergeItem{line: line, key: prefixSortKey(line), readerIndex: item.readerIndex})
		}
		if err := reader.scanner.Err(); err != nil {
			return 0, err
		}
	}
	if err := coalescer.flush(); err != nil {
		return 0, err
	}
	if err := writer.Flush(); err != nil {
		return 0, err
	}
	return coalescer.count, nil
}

func writeLines(path string, lines []string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	for _, line := range lines {
		if _, err := writer.WriteString(line + "\n"); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func prefixSortKey(value string) string {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return "\xff" + value
	}
	addr := prefix.Masked().Addr().Unmap()
	if addr.Is4() {
		raw := addr.As4()
		return string([]byte{4}) + string(raw[:]) + fmt.Sprintf("/%03d", prefix.Bits())
	}
	raw := addr.As16()
	return string([]byte{6}) + string(raw[:]) + fmt.Sprintf("/%03d", prefix.Bits())
}

func upperSet(values []string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, value := range values {
		value = strings.ToUpper(strings.TrimSpace(value))
		if value != "" {
			out[value] = struct{}{}
		}
	}
	return out
}

func slugSet(values []string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, value := range values {
		value = slug(value)
		if value != "" {
			out[value] = struct{}{}
		}
	}
	return out
}

func targetAllows(targets map[string]struct{}, value string) bool {
	if len(targets) == 0 {
		return true
	}
	_, ok := targets[value]
	return ok
}

func familyAllowed(cidr string, options Options) bool {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false
	}
	if prefix.Addr().Unmap().Is4() {
		return options.IncludeIPv4
	}
	return options.IncludeIPv6
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func detectCompany(text string) string {
	text = strings.ToLower(text)
	switch {
	case strings.Contains(text, "alibaba") || strings.Contains(text, "aliyun") || strings.Contains(text, "alicdn") || strings.Contains(text, "阿里"):
		return "alibaba"
	case strings.Contains(text, "tencent") || strings.Contains(text, "腾讯"):
		return "tencent"
	case strings.Contains(text, "cloudflare"):
		return "cloudflare"
	case strings.Contains(text, "google"):
		return "google"
	case strings.Contains(text, "amazon") || strings.Contains(text, "aws"):
		return "aws"
	case strings.Contains(text, "azure") || strings.Contains(text, "microsoft"):
		return "azure"
	case strings.Contains(text, "fastly"):
		return "fastly"
	case strings.Contains(text, "akamai"):
		return "akamai"
	case strings.Contains(text, "huawei") || strings.Contains(text, "华为"):
		return "huawei"
	case strings.Contains(text, "oracle"):
		return "oracle"
	case strings.Contains(text, "ibm") || strings.Contains(text, "softlayer"):
		return "ibm"
	case strings.Contains(text, "digitalocean"):
		return "digitalocean"
	case strings.Contains(text, "linode"):
		return "linode"
	case strings.Contains(text, "ovh"):
		return "ovhcloud"
	case strings.Contains(text, "hetzner"):
		return "hetzner"
	case strings.Contains(text, "vultr"):
		return "vultr"
	case strings.Contains(text, "upcloud"):
		return "upcloud"
	case strings.Contains(text, "scaleway") || strings.Contains(text, "online sas"):
		return "scaleway"
	case strings.Contains(text, "ionos") || strings.Contains(text, "1&1"):
		return "ionos"
	case strings.Contains(text, "g-core") || strings.Contains(text, "gcore"):
		return "gcore"
	case strings.Contains(text, "leaseweb"):
		return "leaseweb"
	case strings.Contains(text, "rackspace"):
		return "rackspace"
	case strings.Contains(text, "equinix") || strings.Contains(text, "packet host"):
		return "equinix"
	case strings.Contains(text, "baidu") || strings.Contains(text, "百度"):
		return "baidu"
	case strings.Contains(text, "jdcloud") || strings.Contains(text, "jd cloud") || strings.Contains(text, "jingdong") || strings.Contains(text, "京东"):
		return "jdcloud"
	case strings.Contains(text, "volcengine") || strings.Contains(text, "byteplus") || strings.Contains(text, "bytedance") || strings.Contains(text, "火山"):
		return "volcengine"
	case strings.Contains(text, "ucloud") || strings.Contains(text, "u-cloud"):
		return "ucloud"
	case strings.Contains(text, "kingsoft") || strings.Contains(text, "金山"):
		return "kingsoft"
	case strings.Contains(text, "qiniu") || strings.Contains(text, "七牛"):
		return "qiniu"
	case strings.Contains(text, "qingcloud") || strings.Contains(text, "青云"):
		return "qingcloud"
	case strings.Contains(text, "ctyun") || strings.Contains(text, "天翼云"):
		return "ctyun"
	case strings.Contains(text, "ecloud") || strings.Contains(text, "移动云"):
		return "ecloud"
	case strings.Contains(text, "chinaunicom cloud") || strings.Contains(text, "联通云"):
		return "chinaunicom"
	case strings.Contains(text, "cdn77"):
		return "cdn77"
	case strings.Contains(text, "bunny"):
		return "bunny"
	case strings.Contains(text, "imperva") || strings.Contains(text, "incapsula"):
		return "imperva"
	case strings.Contains(text, "cachefly"):
		return "cachefly"
	case strings.Contains(text, "cdnetworks"):
		return "cdnetworks"
	case strings.Contains(text, "chinacache"):
		return "chinacache"
	case strings.Contains(text, "wangsu") || strings.Contains(text, "网宿"):
		return "wangsu"
	case strings.Contains(text, "baishan") || strings.Contains(text, "白山"):
		return "baishan"
	case strings.Contains(text, "wasabi"):
		return "wasabi"
	case strings.Contains(text, "backblaze"):
		return "backblaze"
	case strings.Contains(text, "cloudsigma"):
		return "cloudsigma"
	case strings.Contains(text, "contabo"):
		return "contabo"
	}
	return ""
}

func slug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "_", "-")
	value = strings.ReplaceAll(value, " ", "-")
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if ok {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}
