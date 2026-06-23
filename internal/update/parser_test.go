package update

import (
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ipasn/internal/config"
	"ipasn/internal/store"
)

func TestLatestCAIDAPathFromCreationLog(t *testing.T) {
	log := strings.NewReader(`# comments are ignored
1	1778861630	2026/05/routeviews-rv2-20260514-0800.pfx2as.gz
2	1779207255	2026/05/routeviews-rv2-20260518-1200.pfx2as.gz
`)
	path, err := LatestCAIDAPathFromCreationLog(log)
	if err != nil {
		t.Fatal(err)
	}
	if path != "2026/05/routeviews-rv2-20260518-1200.pfx2as.gz" {
		t.Fatalf("unexpected latest path: %s", path)
	}
}

func TestLatestNCAIDAPathsFromCreationLog(t *testing.T) {
	log := strings.NewReader(`# comments are ignored
1	1778861630	2026/05/routeviews-rv2-20260514-0800.pfx2as.gz
2	1779207255	2026/05/routeviews-rv2-20260518-1200.pfx2as.gz
3	1779293655	2026/05/routeviews-rv2-20260519-1200.pfx2as.gz
`)
	paths, err := LatestNCAIDAPathsFromCreationLog(log, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 {
		t.Fatalf("expected two paths, got %#v", paths)
	}
	if paths[0] != "2026/05/routeviews-rv2-20260518-1200.pfx2as.gz" || paths[1] != "2026/05/routeviews-rv2-20260519-1200.pfx2as.gz" {
		t.Fatalf("unexpected paths: %#v", paths)
	}
}

func TestParseCAIDALine(t *testing.T) {
	prefix, asn, ok := ParseCAIDALine("8.8.8.0\t24\t15169")
	if !ok {
		t.Fatal("expected valid line")
	}
	if prefix != "8.8.8.0/24" || asn != 15169 {
		t.Fatalf("unexpected parsed result: %s %d", prefix, asn)
	}

	_, asn, ok = ParseCAIDALine("10.0.0.0\t8\t30_10_20")
	if !ok || asn != 30 {
		t.Fatalf("expected first MOAS ASN 30, got %d ok=%v", asn, ok)
	}
}

func TestParseRIRASNLine(t *testing.T) {
	profiles := ParseRIRASNLine("arin|US|asn|15169|1|20000330|allocated|abc")
	if len(profiles) != 1 {
		t.Fatalf("expected one ASN profile, got %d", len(profiles))
	}
	if profiles[0].ASN != 15169 || profiles[0].Country != "US" || profiles[0].Registry != "arin" {
		t.Fatalf("unexpected profile: %#v", profiles[0])
	}

	profiles = ParseRIRASNLine("arin|US|asn|64500|3|20200101|allocated|abc")
	if len(profiles) != 3 || profiles[2].ASN != 64502 {
		t.Fatalf("expected ASN range expansion, got %#v", profiles)
	}
}

func TestParseRIRAllocationLine(t *testing.T) {
	records := ParseRIRAllocationLine("apnic|CN|ipv4|1.1.10.0|512|20110412|allocated|A92319D5")
	if len(records) != 1 {
		t.Fatalf("expected one allocation record, got %d", len(records))
	}
	if records[0].Prefix != "1.1.10.0/23" || records[0].Country != "CN" || records[0].Registry != "apnic" || records[0].Status != "allocated" {
		t.Fatalf("unexpected allocation: %#v", records[0])
	}

	records = ParseRIRAllocationLine("apnic|AU|ipv6|2001:db8::|32|20200101|allocated|abc")
	if len(records) != 1 || records[0].Prefix != "2001:db8::/32" {
		t.Fatalf("unexpected IPv6 allocation: %#v", records)
	}
}

func TestParsePeeringDBEgressFiles(t *testing.T) {
	rawDir := t.TempDir()
	writeTestFile(t, filepath.Join(rawDir, "peeringdb-ix.json"), `{"data":[{"id":42,"name":"HKIX","country":"HK","city":"Hong Kong"}]}`)
	writeTestFile(t, filepath.Join(rawDir, "peeringdb-netixlan.json"), `{"data":[{"asn":9744,"ix_id":42,"name":"HKIX","ipaddr4":"123.255.92.18","speed":100000}]}`)
	writeTestFile(t, filepath.Join(rawDir, "peeringdb-fac.json"), `{"data":[{"id":77,"name":"Mega-iAdvantage","country":"HK","city":"Hong Kong"}]}`)
	writeTestFile(t, filepath.Join(rawDir, "peeringdb-netfac.json"), `{"data":[{"local_asn":9744,"fac_id":77}]}`)

	egress := store.NewEgressIndex()
	if err := parsePeeringDBEgressFiles(rawDir, egress); err != nil {
		t.Fatal(err)
	}
	presence, ok := egress.Lookup(9744)
	if !ok {
		t.Fatal("expected AS9744 egress presence")
	}
	if len(presence.IXPs) != 1 || presence.IXPs[0].Name != "HKIX" || presence.IXPs[0].IP != "123.255.92.18" || presence.IXPs[0].Country != "HK" {
		t.Fatalf("unexpected IXP presence: %#v", presence.IXPs)
	}
	if len(presence.Facilities) != 1 || presence.Facilities[0].Name != "Mega-iAdvantage" || presence.Facilities[0].City != "Hong Kong" {
		t.Fatalf("unexpected facility presence: %#v", presence.Facilities)
	}
}

func TestParseRPKIVRPLine(t *testing.T) {
	record, ok := ParseRPKIVRPLine("AS3257,64.81.0.0/16,24,routinator")
	if !ok {
		t.Fatal("expected valid RPKI VRP")
	}
	if record.ASN != 3257 || record.Prefix != "64.81.0.0/16" || record.MaxLength != 24 || record.Source != "routinator" {
		t.Fatalf("unexpected VRP: %#v", record)
	}

	record, ok = ParseRPKIVRPLine("3257,2001:db8::/32,48,arin")
	if !ok || record.Prefix != "2001:db8::/32" || record.MaxLength != 48 {
		t.Fatalf("unexpected IPv6 VRP: %#v ok=%v", record, ok)
	}

	record, ok = ParseRPKIVRPLine("rsync://rpki.example/roa.cer,AS3257,64.81.0.0/16,24,2026-01-01,2026-12-31")
	if !ok || record.ASN != 3257 || record.Prefix != "64.81.0.0/16" || record.Source != "routinator" {
		t.Fatalf("unexpected Routinator extended VRP: %#v ok=%v", record, ok)
	}
}

func TestParseIRRRouteObjects(t *testing.T) {
	input := strings.NewReader(`
route: 64.81.32.0/21
origin: AS3257
source: RADB

route6: 2001:db8::/32
origin: AS64496
source: RIPE
`)
	idx := store.NewIRRIndex()
	if err := ParseIRRRouteObjects(input, idx); err != nil {
		t.Fatal(err)
	}
	if !idx.Validate("64.81.32.0/21", 3257).Matched {
		t.Fatal("expected IPv4 IRR route match")
	}
	if !idx.Validate("2001:db8::/32", 64496).Matched {
		t.Fatal("expected IPv6 IRR route match")
	}
}

func TestParseBGPObservationLine(t *testing.T) {
	record, ok := ParseBGPObservationLine(`{"prefix":"64.81.32.0/21","origin_asn":3257,"source":"routeviews","collector":"rv2","observation_count":8,"dominant_upstream":1299}`)
	if !ok {
		t.Fatal("expected JSON observation")
	}
	if record.Prefix != "64.81.32.0/21" || record.OriginASN != 3257 || record.ObservationCount != 8 || record.DominantUpstream != 1299 {
		t.Fatalf("unexpected JSON observation: %#v", record)
	}

	record, ok = ParseBGPObservationLine("64.81.32.0/21,3257,ripe_ris,rrc00,7,2914")
	if !ok || record.Source != "ripe_ris" || record.Collector != "rrc00" || record.ObservationCount != 7 {
		t.Fatalf("unexpected CSV observation: %#v ok=%v", record, ok)
	}
}

func TestBuildSnapshotLoadsGeneratedBGPObservationSummary(t *testing.T) {
	dataDir := t.TempDir()
	rawDir := filepath.Join(dataDir, "raw")
	generatedDir := filepath.Join(dataDir, "generated")
	writeGzipTestFile(t, filepath.Join(rawDir, "caida-ipv4.pfx2as.gz"), "64.81.32.0\t21\t3257\n")
	writeTestFile(t, filepath.Join(generatedDir, "bgp-observations-full.jsonl"), `{"prefix":"64.81.32.0/21","origin_asn":3257,"source":"routeviews","collector":"routeviews:2","observation_count":2,"dominant_upstream":1299}`+"\n")

	snapshot, err := BuildSnapshotFromRaw(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Status.BGPObservationCount != 1 {
		t.Fatalf("expected generated BGP observation to be loaded, got status %#v", snapshot.Status)
	}
	summary := snapshot.Reliability.BGP.Summarize("64.81.32.64", 3257)
	if summary.Visibility != 2 || summary.DominantUpstreams[0].ASN != 1299 {
		t.Fatalf("unexpected BGP summary: %#v", summary)
	}
}

func TestBuildSnapshotLoadsConfiguredBGPSummaryFile(t *testing.T) {
	dataDir := t.TempDir()
	rawDir := filepath.Join(dataDir, "raw")
	configuredSummary := filepath.Join(dataDir, "custom", "current-bgp.jsonl.gz")
	writeGzipTestFile(t, filepath.Join(rawDir, "caida-ipv4.pfx2as.gz"), "203.0.114.0\t24\t64500\n")
	if err := WriteBGPObservationSummary(configuredSummary, []BGPObservationInput{
		{Prefix: "203.0.114.0/24", OriginASN: 64500, Source: "routeviews", Collector: "rv2", DominantUpstream: 1299},
	}); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.DataDir = dataDir
	cfg.BGP.SummaryFile = configuredSummary
	snapshot, err := BuildSnapshot(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Status.BGPObservationCount != 1 {
		t.Fatalf("expected configured BGP summary file to be loaded, got status %#v", snapshot.Status)
	}
	summary := snapshot.Reliability.BGP.Summarize("203.0.114.10", 64500)
	if summary.Visibility != 1 || len(summary.DominantUpstreams) != 1 || summary.DominantUpstreams[0].ASN != 1299 {
		t.Fatalf("unexpected configured BGP summary: %#v", summary)
	}
}

func TestBuildSnapshotPrefersCompiledBGPIndex(t *testing.T) {
	dataDir := t.TempDir()
	rawDir := filepath.Join(dataDir, "raw")
	generatedDir := filepath.Join(dataDir, "generated")
	writeGzipTestFile(t, filepath.Join(rawDir, "caida-ipv4.pfx2as.gz"), "203.0.114.0\t24\t64500\n")
	writeTestFile(t, filepath.Join(generatedDir, "bgp-observations-full.jsonl"), `{"prefix":"203.0.114.0/24","origin_asn":64496,"source":"routeviews","collector":"routeviews:1","observation_count":1}`+"\n")

	idx := store.NewBGPObservationIndex()
	if err := idx.Add(store.BGPObservationRecord{Prefix: "203.0.114.0/24", OriginASN: 64500, Source: "ripe_ris", Collector: "ripe_ris:3", ObservationCount: 3, DominantUpstream: 1299}); err != nil {
		t.Fatal(err)
	}
	indexPath := filepath.Join(generatedDir, "bgp-index.bin")
	if err := store.SaveBGPObservationIndex(indexPath, idx); err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.DataDir = dataDir
	cfg.BGP.IndexFile = indexPath
	cfg.BGP.IndexMode = "compact"
	snapshot, err := BuildSnapshot(cfg)
	if err != nil {
		t.Fatal(err)
	}
	summary := snapshot.Reliability.BGP.Summarize("203.0.114.10", 64500)
	if summary.Visibility != 3 || len(summary.Origins) != 1 || summary.Origins[0].ASN != 64500 {
		t.Fatalf("expected compiled index to win over JSONL fallback, got %#v", summary)
	}
}

func writeTestFile(t *testing.T, path string, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeGzipTestFile(t *testing.T, path string, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := gzip.NewWriter(file)
	if _, err := writer.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
