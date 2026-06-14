package firewall

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateFromRecordsWritesCountryCompanySceneLists(t *testing.T) {
	outputDir := t.TempDir()
	records := []Record{
		{
			CIDR:        "47.52.0.0/16",
			Country:     "中国",
			CountryCode: "CN",
			ISP:         "Alibaba Cloud",
			ASN:         45102,
			Company:     "alibaba",
			Scenes:      []string{"IDC"},
			Confidence:  0.92,
			Sources:     []string{"ip2region", "asn_rules"},
		},
		{
			CIDR:        "1.1.1.0/24",
			Country:     "澳大利亚",
			CountryCode: "AU",
			ISP:         "Cloudflare",
			ASN:         13335,
			Company:     "cloudflare",
			Scenes:      []string{"CDN", "DNS"},
			Confidence:  0.96,
			Sources:     []string{"ip2region", "service_rules"},
		},
		{
			CIDR:        "1.1.1.0/24",
			Country:     "澳大利亚",
			CountryCode: "AU",
			ISP:         "Cloudflare",
			ASN:         13335,
			Company:     "cloudflare",
			Scenes:      []string{"CDN", "DNS"},
			Confidence:  0.96,
			Sources:     []string{"ip2region", "service_rules"},
		},
		{
			CIDR:        "2606:4700::/32",
			Country:     "美国",
			CountryCode: "US",
			ISP:         "Cloudflare",
			ASN:         13335,
			Company:     "cloudflare",
			Scenes:      []string{"CDN", "DNS"},
			Confidence:  0.96,
			Sources:     []string{"ip2region", "service_rules"},
		},
		{
			CIDR:        "185.220.101.0/24",
			Country:     "德国",
			CountryCode: "DE",
			ISP:         "Tor Exit",
			ASN:         60729,
			Scenes:      []string{"TOR", "PROXY"},
			Confidence:  0.99,
			Sources:     []string{"service_rules"},
		},
		{
			CIDR:        "203.0.113.0/24",
			CountryCode: "US",
			Scenes:      []string{"IDC"},
			Confidence:  0.4,
		},
	}

	summary, err := GenerateFromRecords(context.Background(), records, Options{
		OutputDir:     outputDir,
		Countries:     []string{"CN", "AU", "US"},
		Companies:     []string{"alibaba", "cloudflare"},
		Scenes:        []string{"IDC", "CDN", "DNS", "TOR", "PROXY"},
		MinConfidence: 0.8,
		WriteEntries:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if summary.TotalRecords != 6 {
		t.Fatalf("unexpected record count: %#v", summary)
	}

	assertFileLines(t, filepath.Join(outputDir, "country-CN.cidr"), []string{"47.52.0.0/16"})
	assertFileLines(t, filepath.Join(outputDir, "country-AU.cidr"), []string{"1.1.1.0/24"})
	assertFileLines(t, filepath.Join(outputDir, "country-US.cidr"), []string{"2606:4700::/32"})
	assertFileLines(t, filepath.Join(outputDir, "company-alibaba.cidr"), []string{"47.52.0.0/16"})
	assertFileLines(t, filepath.Join(outputDir, "company-cloudflare.cidr"), []string{"1.1.1.0/24", "2606:4700::/32"})
	assertFileLines(t, filepath.Join(outputDir, "scene-IDC.cidr"), []string{"47.52.0.0/16"})
	assertFileLines(t, filepath.Join(outputDir, "scene-CDN.cidr"), []string{"1.1.1.0/24", "2606:4700::/32"})
	assertFileLines(t, filepath.Join(outputDir, "scene-DNS.cidr"), []string{"1.1.1.0/24", "2606:4700::/32"})
	assertFileLines(t, filepath.Join(outputDir, "scene-TOR.cidr"), []string{"185.220.101.0/24"})
	assertFileLines(t, filepath.Join(outputDir, "scene-PROXY.cidr"), []string{"185.220.101.0/24"})

	entries := readFile(t, filepath.Join(outputDir, "entries.jsonl"))
	if strings.Contains(entries, "203.0.113.0/24") {
		t.Fatalf("low confidence record should not be exported: %s", entries)
	}

	var index Index
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(outputDir, "index.json"))), &index); err != nil {
		t.Fatal(err)
	}
	if index.Files["scene-IDC.cidr"].Count != 1 {
		t.Fatalf("unexpected index: %#v", index.Files["scene-IDC.cidr"])
	}
}

func TestRangeToPrefixesCoversIPv4AndIPv6(t *testing.T) {
	v4, err := rangeToPrefixes("1.1.1.0", "1.1.1.255")
	if err != nil {
		t.Fatal(err)
	}
	if got := joinPrefixes(v4); got != "1.1.1.0/24" {
		t.Fatalf("unexpected IPv4 prefixes: %s", got)
	}

	v6, err := rangeToPrefixes("2001:db8::", "2001:db8::ff")
	if err != nil {
		t.Fatal(err)
	}
	if got := joinPrefixes(v6); got != "2001:db8::/120" {
		t.Fatalf("unexpected IPv6 prefixes: %s", got)
	}
}

func TestDetectCompanyCoversMainstreamCloudVendors(t *testing.T) {
	cases := map[string]string{
		"Oracle Cloud Infrastructure": "oracle",
		"IBM SoftLayer":               "ibm",
		"DigitalOcean LLC":            "digitalocean",
		"Linode":                      "linode",
		"OVH SAS":                     "ovhcloud",
		"Hetzner Online GmbH":         "hetzner",
		"Vultr Holdings":              "vultr",
		"百度云":                         "baidu",
		"Volcengine Cloud":            "volcengine",
		"CDN77":                       "cdn77",
		"网宿科技":                        "wangsu",
	}
	for input, want := range cases {
		if got := detectCompany(input); got != want {
			t.Fatalf("detectCompany(%q) = %q, want %q", input, got, want)
		}
	}
}

func assertFileLines(t *testing.T, path string, want []string) {
	t.Helper()
	body := readFile(t, path)
	got := strings.Split(strings.TrimSpace(body), "\n")
	if strings.TrimSpace(body) == "" {
		got = nil
	}
	if len(got) != len(want) {
		t.Fatalf("%s lines = %#v, want %#v", path, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s line %d = %q, want %q", path, i, got[i], want[i])
		}
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func joinPrefixes(prefixes []string) string {
	return strings.Join(prefixes, ",")
}
