package enrich

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"ipasn/internal/store"
)

type Config struct {
	CacheDir           string
	TTL                time.Duration
	Timeout            time.Duration
	AsyncOnMiss        bool
	ForegroundTimeout  time.Duration
	RIPEStatNetworkURL string
	RIPEStatPrefixURL  string
	RIPEStatBGPPathURL string
	RDAPURLTemplate    string
	TeamCymruTXTLookup func(context.Context, string) ([]string, error)
	WhoisLookup        func(context.Context, string, string) (string, error)
	HTTPClient         *http.Client
}

type Mode string

const (
	ModeFast Mode = "fast"
	ModeWait Mode = "wait"
)

type RequestOptions struct {
	Mode Mode
}

const defaultRDAPURLTemplate = "https://rdap.{registry}.net/ip/{ip}"
const enrichmentCacheVersion = 3

type Client struct {
	cfg      Config
	client   *http.Client
	mu       sync.Mutex
	inflight map[string]*refreshState
}

type refreshState struct {
	done   chan struct{}
	result Result
	err    error
}

type Result struct {
	CacheHit           bool                    `json:"cache_hit,omitempty"`
	RefreshQueued      bool                    `json:"refresh_queued,omitempty"`
	RefreshInProgress  bool                    `json:"refresh_in_progress,omitempty"`
	PrimaryScene       string                  `json:"primary_scene,omitempty"`
	PrimarySceneName   string                  `json:"primary_scene_name,omitempty"`
	InferredScene      string                  `json:"inferred_scene,omitempty"`
	InferredSceneName  string                  `json:"inferred_scene_name,omitempty"`
	InferredConfidence float64                 `json:"inferred_confidence,omitempty"`
	Organization       string                  `json:"organization,omitempty"`
	NetName            string                  `json:"netname,omitempty"`
	Evidence           []string                `json:"evidence,omitempty"`
	Sources            []string                `json:"sources,omitempty"`
	TeamCymru          *CymruResult            `json:"team_cymru,omitempty"`
	RIPEStat           *RIPEStat               `json:"ripestat,omitempty"`
	BGPPath            *BGPPathAnalysis        `json:"bgp_path,omitempty"`
	GeoConsistency     *GeoConsistencyAnalysis `json:"geo_consistency,omitempty"`
	RDAP               *RDAPSummary            `json:"rdap,omitempty"`
	Whois              *WhoisSummary           `json:"whois,omitempty"`
}

type CymruResult struct {
	ASN       int    `json:"asn,omitempty"`
	Prefix    string `json:"prefix,omitempty"`
	Country   string `json:"country,omitempty"`
	Registry  string `json:"registry,omitempty"`
	Allocated string `json:"allocated,omitempty"`
	Name      string `json:"name,omitempty"`
}

type RIPEStat struct {
	Announced bool   `json:"announced"`
	ASNs      []int  `json:"asns,omitempty"`
	Prefix    string `json:"prefix,omitempty"`
	QueryTime string `json:"query_time,omitempty"`
}

type BGPPathAnalysis struct {
	Source             string               `json:"source,omitempty"`
	Prefix             string               `json:"prefix,omitempty"`
	OriginASN          int                  `json:"origin_asn,omitempty"`
	ObservationCount   int                  `json:"observation_count,omitempty"`
	DominantUpstream   int                  `json:"dominant_upstream,omitempty"`
	DominantUpstreams  []int                `json:"dominant_upstreams,omitempty"`
	UpstreamASNs       []BGPASNCount        `json:"upstream_asns,omitempty"`
	CollectorLocations []string             `json:"collector_locations,omitempty"`
	Paths              []BGPPathObservation `json:"paths,omitempty"`
}

type BGPASNCount struct {
	ASN   int `json:"asn"`
	Count int `json:"count"`
}

type BGPPathObservation struct {
	Source    string `json:"source,omitempty"`
	RRC       string `json:"rrc,omitempty"`
	Location  string `json:"location,omitempty"`
	Peer      string `json:"peer,omitempty"`
	Prefix    string `json:"prefix,omitempty"`
	OriginASN int    `json:"origin_asn,omitempty"`
	ASPath    []int  `json:"as_path,omitempty"`
}

type GeoConsistencyInput struct {
	RegisteredCountry string
	AnnouncedCountry  string
	LocationCountry   string
	BGP               *BGPPathAnalysis
}

type GeoConsistencyAnalysis struct {
	RegisteredCountry string   `json:"registered_country,omitempty"`
	AnnouncedCountry  string   `json:"announced_country,omitempty"`
	LocationCountry   string   `json:"location_country,omitempty"`
	BGPPathHint       string   `json:"bgp_path_hint,omitempty"`
	Conflict          bool     `json:"conflict"`
	Confidence        float64  `json:"confidence,omitempty"`
	Summary           string   `json:"summary,omitempty"`
	Evidence          []string `json:"evidence,omitempty"`
}

type RDAPSummary struct {
	Name         string   `json:"name,omitempty"`
	Type         string   `json:"type,omitempty"`
	Country      string   `json:"country,omitempty"`
	StartAddress string   `json:"start_address,omitempty"`
	EndAddress   string   `json:"end_address,omitempty"`
	Status       []string `json:"status,omitempty"`
	Descriptions []string `json:"descriptions,omitempty"`
}

type WhoisSummary struct {
	NetName      string   `json:"netname,omitempty"`
	Country      string   `json:"country,omitempty"`
	Status       string   `json:"status,omitempty"`
	Organization string   `json:"organization,omitempty"`
	Descriptions []string `json:"descriptions,omitempty"`
	Remarks      []string `json:"remarks,omitempty"`
	Source       string   `json:"source,omitempty"`
	Raw          string   `json:"raw,omitempty"`
}

type cachedResult struct {
	Version  int       `json:"version"`
	CachedAt time.Time `json:"cached_at"`
	Result   Result    `json:"result"`
}

func NewClient(cfg Config) *Client {
	if cfg.CacheDir == "" {
		cfg.CacheDir = filepath.Join("data", "cache", "enrich")
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 7 * 24 * time.Hour
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 8 * time.Second
	}
	if cfg.ForegroundTimeout == 0 {
		cfg.ForegroundTimeout = 1500 * time.Millisecond
	}
	if cfg.RIPEStatNetworkURL == "" {
		cfg.RIPEStatNetworkURL = "https://stat.ripe.net/data/network-info/data.json?resource={ip}"
	}
	if cfg.RIPEStatPrefixURL == "" {
		cfg.RIPEStatPrefixURL = "https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}"
	}
	if cfg.RIPEStatBGPPathURL == "" {
		cfg.RIPEStatBGPPathURL = "https://stat.ripe.net/data/looking-glass/data.json?resource={prefix}"
	}
	if cfg.RDAPURLTemplate == "" {
		cfg.RDAPURLTemplate = defaultRDAPURLTemplate
	}
	if cfg.TeamCymruTXTLookup == nil {
		cfg.TeamCymruTXTLookup = defaultCymruLookup
	}
	if cfg.WhoisLookup == nil {
		cfg.WhoisLookup = defaultWhoisLookup
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	}
	return &Client{cfg: cfg, client: client, inflight: map[string]*refreshState{}}
}

func (c *Client) EnrichIP(ctx context.Context, ip string, allocation store.AllocationRecord) (Result, error) {
	return c.EnrichIPWithOptions(ctx, ip, allocation, RequestOptions{})
}

func (c *Client) EnrichIPWithOptions(ctx context.Context, ip string, allocation store.AllocationRecord, options RequestOptions) (Result, error) {
	cachePath := c.cachePath(ip, allocation.Prefix)
	if cached, ok := c.readCache(cachePath); ok {
		cached.CacheHit = true
		return cached, nil
	}
	if options.Mode == ModeWait {
		return c.enrichOnline(ctx, ip, allocation, cachePath)
	}
	if c.cfg.AsyncOnMiss {
		state, queued := c.startRefresh(ip, allocation, cachePath)
		if c.cfg.ForegroundTimeout > 0 {
			if refreshed, err, ok := c.waitRefresh(ctx, state, c.cfg.ForegroundTimeout); ok {
				return refreshed, err
			}
		}
		result := c.baseResult(allocation)
		result.RefreshQueued = queued
		result.RefreshInProgress = true
		if queued {
			result.Evidence = append(result.Evidence, "在线增强缓存未命中，已后台刷新")
		} else {
			result.Evidence = append(result.Evidence, "在线增强正在后台刷新")
		}
		return result, nil
	}

	return c.enrichOnline(ctx, ip, allocation, cachePath)
}

func (c *Client) baseResult(allocation store.AllocationRecord) Result {
	result := Result{
		Evidence: []string{},
		Sources:  []string{},
	}
	if allocation.Source != "" {
		result.Sources = appendUnique(result.Sources, allocation.Source)
	}
	if allocation.Prefix != "" && strings.HasPrefix(allocation.Source, "rir:") {
		result.Evidence = append(result.Evidence, "注册局分配记录命中 "+allocation.Prefix)
	}
	return result
}

func (c *Client) startRefresh(ip string, allocation store.AllocationRecord, cachePath string) (*refreshState, bool) {
	c.mu.Lock()
	if state, ok := c.inflight[cachePath]; ok {
		c.mu.Unlock()
		return state, false
	}
	state := &refreshState{done: make(chan struct{})}
	c.inflight[cachePath] = state
	c.mu.Unlock()

	go func() {
		result, err := c.enrichOnline(context.Background(), ip, allocation, cachePath)
		c.mu.Lock()
		state.result = result
		state.err = err
		delete(c.inflight, cachePath)
		c.mu.Unlock()
		close(state.done)
	}()
	return state, true
}

func (c *Client) waitRefresh(ctx context.Context, state *refreshState, timeout time.Duration) (Result, error, bool) {
	if state == nil || timeout <= 0 {
		return Result{}, nil, false
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-state.done:
		c.mu.Lock()
		result, err := state.result, state.err
		c.mu.Unlock()
		return result, err, true
	case <-timer.C:
		return Result{}, nil, false
	case <-ctx.Done():
		return Result{}, ctx.Err(), true
	}
}

func (c *Client) enrichOnline(ctx context.Context, ip string, allocation store.AllocationRecord, cachePath string) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()

	result := c.baseResult(allocation)

	cymruCh := make(chan struct {
		value CymruResult
		ok    bool
	}, 1)
	ripeCh := make(chan struct {
		value RIPEStat
		ok    bool
	}, 1)
	bgpCh := make(chan struct {
		value BGPPathAnalysis
		ok    bool
	}, 1)
	rdapCh := make(chan struct {
		value RDAPSummary
		ok    bool
	}, 1)
	whoisCh := make(chan struct {
		value WhoisSummary
		ok    bool
	}, 1)

	go func() {
		value, ok := c.lookupCymru(ctx, ip)
		cymruCh <- struct {
			value CymruResult
			ok    bool
		}{value: value, ok: ok}
	}()
	go func() {
		value, ok := c.lookupRIPEStat(ctx, ip)
		ripeCh <- struct {
			value RIPEStat
			ok    bool
		}{value: value, ok: ok}
	}()
	go func() {
		if allocation.Registry == "" {
			rdapCh <- struct {
				value RDAPSummary
				ok    bool
			}{}
			return
		}
		value, ok := c.lookupRDAP(ctx, ip, allocation.Registry)
		rdapCh <- struct {
			value RDAPSummary
			ok    bool
		}{value: value, ok: ok}
	}()
	go func() {
		if allocation.Registry == "" {
			whoisCh <- struct {
				value WhoisSummary
				ok    bool
			}{}
			return
		}
		value, ok := c.lookupWhois(ctx, ip, allocation.Registry)
		whoisCh <- struct {
			value WhoisSummary
			ok    bool
		}{value: value, ok: ok}
	}()

	ripe := <-ripeCh
	if ripe.ok && ripe.value.Prefix != "" {
		go func(prefix string) {
			value, ok := c.lookupBGPPath(ctx, prefix)
			bgpCh <- struct {
				value BGPPathAnalysis
				ok    bool
			}{value: value, ok: ok}
		}(ripe.value.Prefix)
	} else {
		bgpCh <- struct {
			value BGPPathAnalysis
			ok    bool
		}{}
	}
	cymru := <-cymruCh
	rdap := <-rdapCh
	whois := <-whoisCh
	bgp := <-bgpCh

	if cymru.ok {
		result.TeamCymru = &cymru.value
		result.Sources = appendUnique(result.Sources, "team_cymru")
		if cymru.value.ASN > 0 {
			result.Evidence = append(result.Evidence, fmt.Sprintf("Team Cymru 当前命中 AS%d / %s", cymru.value.ASN, cymru.value.Prefix))
		} else {
			result.Evidence = append(result.Evidence, "Team Cymru 当前无 ASN")
		}
	}

	if ripe.ok {
		result.RIPEStat = &ripe.value
		result.Sources = appendUnique(result.Sources, "ripestat")
		if ripe.value.Announced && len(ripe.value.ASNs) > 0 {
			result.Evidence = append(result.Evidence, fmt.Sprintf("RIPEstat 当前宣告 AS%d / %s", ripe.value.ASNs[0], ripe.value.Prefix))
		} else {
			result.Evidence = append(result.Evidence, "RIPEstat 当前未宣告")
		}
	}

	if bgp.ok {
		result.BGPPath = &bgp.value
		result.Sources = appendUnique(result.Sources, "ripe_ris")
		if bgp.value.ObservationCount > 0 {
			result.Evidence = append(result.Evidence, fmt.Sprintf("RIPE RIS AS Path 观察点 %d 个，主上游 AS%d", bgp.value.ObservationCount, bgp.value.DominantUpstream))
		}
	}

	if rdap.ok {
		result.RDAP = &rdap.value
		result.Sources = appendUnique(result.Sources, "rdap")
		if rdap.value.Name != "" {
			result.NetName = rdap.value.Name
		}
		rdapEvidence := limitStrings(append([]string{rdap.value.Name}, rdap.value.Descriptions...), 3)
		if len(rdap.value.Descriptions) > 0 {
			result.Organization = bestOrganization(result.Organization, rdap.value.Descriptions)
		}
		if len(rdapEvidence) > 0 {
			result.Evidence = append(result.Evidence, "RDAP: "+strings.Join(rdapEvidence, " / "))
		}
	}

	if whois.ok {
		result.Whois = &whois.value
		result.Sources = appendUnique(result.Sources, "whois")
		if result.NetName == "" {
			result.NetName = whois.value.NetName
		}
		result.Organization = bestOrganization(result.Organization, append([]string{whois.value.Organization}, whois.value.Descriptions...))
		result.Evidence = append(result.Evidence, "WHOIS: "+strings.Join(limitStrings(append([]string{whois.value.NetName}, append(whois.value.Descriptions, whois.value.Remarks...)...), 3), " / "))
	}

	result.GeoConsistency = BuildGeoConsistency(GeoConsistencyInput{
		RegisteredCountry: firstNonEmptyCountry(rdap.value.Country, whois.value.Country),
		AnnouncedCountry:  cymru.value.Country,
		BGP:               result.BGPPath,
	})
	result.InferredScene, result.InferredSceneName, result.InferredConfidence = inferScene(result, allocation)
	c.writeCache(cachePath, result)
	return result, nil
}

func ParseCymruTXT(line string) (CymruResult, bool) {
	parts := splitPipe(line)
	if len(parts) == 7 {
		parts = []string{parts[0], parts[2], parts[3], parts[4], parts[5], parts[6]}
	}
	if len(parts) < 6 || strings.EqualFold(parts[0], "NA") {
		return CymruResult{}, false
	}
	asn, err := strconv.Atoi(parts[0])
	if err != nil || asn <= 0 {
		return CymruResult{}, false
	}
	return CymruResult{
		ASN:       asn,
		Prefix:    parts[1],
		Country:   parts[2],
		Registry:  strings.ToLower(parts[3]),
		Allocated: parts[4],
		Name:      parts[5],
	}, true
}

func ParseRDAPSummary(body []byte) RDAPSummary {
	var raw struct {
		Name         string   `json:"name"`
		Type         string   `json:"type"`
		Country      string   `json:"country"`
		StartAddress string   `json:"startAddress"`
		EndAddress   string   `json:"endAddress"`
		Status       []string `json:"status"`
		Remarks      []struct {
			Description []string `json:"description"`
		} `json:"remarks"`
	}
	_ = json.Unmarshal(body, &raw)
	out := RDAPSummary{
		Name:         raw.Name,
		Type:         raw.Type,
		Country:      raw.Country,
		StartAddress: raw.StartAddress,
		EndAddress:   raw.EndAddress,
		Status:       raw.Status,
	}
	for _, remark := range raw.Remarks {
		out.Descriptions = append(out.Descriptions, remark.Description...)
	}
	return out
}

func ParseWhoisSummary(raw string) WhoisSummary {
	summary := WhoisSummary{Raw: raw}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := scanner.Text()
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch key {
		case "netname":
			if summary.NetName == "" {
				summary.NetName = value
			}
		case "descr":
			summary.Descriptions = append(summary.Descriptions, value)
		case "remarks":
			summary.Remarks = append(summary.Remarks, value)
		case "country":
			if summary.Country == "" {
				summary.Country = value
			}
		case "status":
			if summary.Status == "" {
				summary.Status = value
			}
		case "org", "organisation", "organization", "owner", "person", "role":
			if summary.Organization == "" {
				summary.Organization = value
			}
		case "source":
			if summary.Source == "" {
				summary.Source = value
			}
		}
	}
	return summary
}

func (c *Client) lookupCymru(ctx context.Context, ip string) (CymruResult, bool) {
	lines, err := c.cfg.TeamCymruTXTLookup(ctx, ip)
	if err != nil {
		return CymruResult{}, false
	}
	for _, line := range lines {
		if result, ok := ParseCymruTXT(line); ok {
			return result, true
		}
		if strings.Contains(line, "|") && strings.Contains(strings.ToUpper(line), "NA") {
			return CymruResult{Country: countryFromPipe(line), Registry: registryFromPipe(line)}, true
		}
	}
	return CymruResult{}, false
}

func (c *Client) lookupRIPEStat(ctx context.Context, ip string) (RIPEStat, bool) {
	prefixURL := strings.ReplaceAll(c.cfg.RIPEStatPrefixURL, "{ip}", ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, prefixURL, nil)
	if err != nil {
		return RIPEStat{}, false
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return RIPEStat{}, false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return RIPEStat{}, false
	}
	var raw struct {
		Status string `json:"status"`
		Data   struct {
			Announced bool `json:"announced"`
			ASNs      []struct {
				ASN int `json:"asn"`
			} `json:"asns"`
			Resource  string `json:"resource"`
			QueryTime string `json:"query_time"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &raw); err != nil || raw.Status != "ok" {
		return RIPEStat{}, false
	}
	out := RIPEStat{Announced: raw.Data.Announced, Prefix: raw.Data.Resource, QueryTime: raw.Data.QueryTime}
	for _, asn := range raw.Data.ASNs {
		if asn.ASN > 0 {
			out.ASNs = append(out.ASNs, asn.ASN)
		}
	}
	if out.Prefix == ip {
		out.Prefix = ""
	}
	return out, true
}

func (c *Client) lookupBGPPath(ctx context.Context, prefix string) (BGPPathAnalysis, bool) {
	if prefix == "" {
		return BGPPathAnalysis{}, false
	}
	url := strings.ReplaceAll(c.cfg.RIPEStatBGPPathURL, "{prefix}", prefix)
	url = strings.ReplaceAll(url, "{ip}", prefix)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return BGPPathAnalysis{}, false
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return BGPPathAnalysis{}, false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return BGPPathAnalysis{}, false
	}
	return ParseRIPEStatLookingGlass(body)
}

func ParseRIPEStatLookingGlass(body []byte) (BGPPathAnalysis, bool) {
	var raw struct {
		Status string `json:"status"`
		Data   struct {
			RRCs []struct {
				RRC      string `json:"rrc"`
				Location string `json:"location"`
				Peers    []struct {
					ASNOrigin string `json:"asn_origin"`
					ASPath    string `json:"as_path"`
					Prefix    string `json:"prefix"`
					Peer      string `json:"peer"`
				} `json:"peers"`
			} `json:"rrcs"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &raw); err != nil || raw.Status != "ok" {
		return BGPPathAnalysis{}, false
	}
	out := BGPPathAnalysis{Source: "ripe_ris"}
	upstreamCounts := map[int]int{}
	locationSeen := map[string]bool{}
	for _, rrc := range raw.Data.RRCs {
		if rrc.Location != "" && !locationSeen[rrc.Location] {
			out.CollectorLocations = append(out.CollectorLocations, rrc.Location)
			locationSeen[rrc.Location] = true
		}
		for _, peer := range rrc.Peers {
			path := parseASPath(peer.ASPath)
			if len(path) == 0 {
				continue
			}
			origin := parsePositiveInt(peer.ASNOrigin)
			if origin == 0 {
				origin = path[len(path)-1]
			}
			if out.OriginASN == 0 {
				out.OriginASN = origin
			}
			if out.Prefix == "" {
				out.Prefix = peer.Prefix
			}
			upstream := upstreamBeforeOrigin(path, origin)
			if upstream > 0 {
				upstreamCounts[upstream]++
			}
			out.ObservationCount++
			if len(out.Paths) < 20 {
				out.Paths = append(out.Paths, BGPPathObservation{
					Source:    "ripe_ris",
					RRC:       rrc.RRC,
					Location:  rrc.Location,
					Peer:      peer.Peer,
					Prefix:    peer.Prefix,
					OriginASN: origin,
					ASPath:    path,
				})
			}
		}
	}
	if out.ObservationCount == 0 {
		return BGPPathAnalysis{}, false
	}
	out.UpstreamASNs = sortedASNCounts(upstreamCounts)
	for i, item := range out.UpstreamASNs {
		if i == 0 {
			out.DominantUpstream = item.ASN
		}
		if i >= 5 {
			break
		}
		out.DominantUpstreams = append(out.DominantUpstreams, item.ASN)
	}
	return out, true
}

func (c *Client) lookupRDAP(ctx context.Context, ip, registry string) (RDAPSummary, bool) {
	url := c.rdapURL(ip, registry)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return RDAPSummary{}, false
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return RDAPSummary{}, false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return RDAPSummary{}, false
	}
	summary := ParseRDAPSummary(body)
	return summary, summary.Name != "" || len(summary.Descriptions) > 0
}

func (c *Client) rdapURL(ip, registry string) string {
	if c.cfg.RDAPURLTemplate != defaultRDAPURLTemplate {
		url := strings.ReplaceAll(c.cfg.RDAPURLTemplate, "{ip}", ip)
		return strings.ReplaceAll(url, "{registry}", registry)
	}
	base := map[string]string{
		"apnic":   "https://rdap.apnic.net/ip/{ip}",
		"arin":    "https://rdap.arin.net/registry/ip/{ip}",
		"ripencc": "https://rdap.db.ripe.net/ip/{ip}",
		"ripe":    "https://rdap.db.ripe.net/ip/{ip}",
		"lacnic":  "https://rdap.lacnic.net/rdap/ip/{ip}",
		"afrinic": "https://rdap.afrinic.net/rdap/ip/{ip}",
	}[strings.ToLower(registry)]
	if base == "" {
		base = defaultRDAPURLTemplate
	}
	url := strings.ReplaceAll(base, "{ip}", ip)
	return strings.ReplaceAll(url, "{registry}", registry)
}

func (c *Client) lookupWhois(ctx context.Context, ip, registry string) (WhoisSummary, bool) {
	raw, err := c.cfg.WhoisLookup(ctx, registry, ip)
	if err != nil || strings.TrimSpace(raw) == "" {
		return WhoisSummary{}, false
	}
	summary := ParseWhoisSummary(raw)
	return summary, summary.NetName != "" || len(summary.Descriptions) > 0 || len(summary.Remarks) > 0
}

func defaultCymruLookup(ctx context.Context, ip string) ([]string, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", "whois.cymru.com:43")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	_, _ = conn.Write([]byte(" -v " + ip + "\r\n"))
	scanner := bufio.NewScanner(conn)
	lines := []string{}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "AS ") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, scanner.Err()
}

func defaultWhoisLookup(ctx context.Context, registry, ip string) (string, error) {
	host := map[string]string{
		"apnic":   "whois.apnic.net:43",
		"arin":    "whois.arin.net:43",
		"ripencc": "whois.ripe.net:43",
		"ripe":    "whois.ripe.net:43",
		"lacnic":  "whois.lacnic.net:43",
		"afrinic": "whois.afrinic.net:43",
	}[strings.ToLower(registry)]
	if host == "" {
		return "", fmt.Errorf("unknown whois registry %q", registry)
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	_, _ = conn.Write([]byte(ip + "\r\n"))
	body, err := io.ReadAll(conn)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func (c *Client) cachePath(ip, prefix string) string {
	sum := sha1.Sum([]byte(ip + "|" + prefix))
	return filepath.Join(c.cfg.CacheDir, hex.EncodeToString(sum[:])+".json")
}

func (c *Client) readCache(path string) (Result, bool) {
	body, err := os.ReadFile(path)
	if err != nil {
		return Result{}, false
	}
	var cached cachedResult
	if err := json.Unmarshal(body, &cached); err != nil {
		return Result{}, false
	}
	if cached.Version != enrichmentCacheVersion {
		return Result{}, false
	}
	if time.Since(cached.CachedAt) > c.cfg.TTL {
		return Result{}, false
	}
	return cached.Result, true
}

func (c *Client) writeCache(path string, result Result) {
	_ = os.MkdirAll(filepath.Dir(path), 0o775)
	body, err := json.MarshalIndent(cachedResult{Version: enrichmentCacheVersion, CachedAt: time.Now(), Result: result}, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, body, 0o664)
}

func inferScene(result Result, allocation store.AllocationRecord) (string, string, float64) {
	text := strings.ToLower(strings.Join([]string{
		result.Organization,
		result.NetName,
		joinRDAP(result.RDAP),
		joinWhois(result.Whois),
		allocation.Country,
		allocation.Registry,
	}, " "))
	scene := "NET"
	confidence := 0.45
	if containsAny(text,
		"amazon technologies", "amazon.com", "amazon web services", "aws.amazon.com",
		"alibaba cloud", "alicloud", "aliyun", "alibabacloud", "tencent cloud",
		"google cloud", "microsoft azure", "oracle cloud", "huawei cloud",
	) {
		scene = "IDC"
		confidence = 0.84
	}
	if containsAny(text, "broadband", "adsl", "dsl", "cable", "residential", "chinanet", "china telecom", "telecom", "service provider", "internet service provider") {
		scene = "DYN"
		confidence = 0.74
	}
	if containsAny(text, "frontiernet.net", "frontier communications", "comcast cable", "charter communications", "spectrum residential", "cox communications", "verizon fios") {
		scene = "DYN"
		confidence = 0.8
	}
	if containsAny(text, "mobile", "lte", "5g", "4g", "cellular", "t-mobile", "tmobile", "myvzw", "verizon wireless", "cellco", "wirelessdatanetwork", "at&t mobility", "att mobility") {
		scene = "MOB"
		confidence = 0.78
	}
	if containsAny(text, "hosting", "cloud", "data center", "datacenter", "server") {
		scene = "IDC"
		confidence = 0.76
	}
	if containsAny(text, "dns", "resolver") {
		scene = "DNS"
		confidence = 0.82
	}
	if containsAny(text, "tor exit", "tor relay") {
		scene = "TOR"
		confidence = 0.78
	}
	if containsAny(text, "vpn") {
		scene = "VPN"
		confidence = 0.72
	}
	if containsAny(text, "proxy", "open proxy") {
		scene = "PROXY"
		confidence = 0.7
	}
	if containsAny(text, "smtp", "mail server", "email service", "postfix", " mx ", "mailgun", "sendgrid", "amazonses") {
		scene = "MAIL"
		confidence = 0.72
	}
	if containsAny(text, "monitor", "uptime", "probe") {
		scene = "MON"
		confidence = 0.72
	}
	if containsAny(text, "iot", "internet of things") {
		scene = "IOT"
		confidence = 0.7
	}
	if containsAny(text, "university", "college", "school") {
		scene = "EDU"
		confidence = 0.82
	}
	if containsAny(text, "government", "ministry", ".gov") {
		scene = "GOV"
		confidence = 0.82
	}
	return scene, sceneName(scene), confidence
}

func sceneName(scene string) string {
	return map[string]string{
		"CDN": "内容分发", "DNS": "域名解析", "EDU": "教育机构", "GTW": "企业专线",
		"GOV": "政府机构", "DYN": "家庭宽带", "IDC": "数据中心", "MOB": "移动网络",
		"ORG": "组织机构", "NET": "基础设施", "BOGON": "保留 IP", "UNROUTED": "已分配未宣告", "STUN": "NAT 穿透",
		"VPN": "VPN 出口", "PROXY": "代理服务", "TOR": "Tor 出口", "BOT": "搜索爬虫",
		"MAIL": "邮件服务", "MON": "监控探测", "IOT": "物联网平台", "BLOCKLIST": "风险名单",
	}[scene]
}

func splitPipe(line string) []string {
	parts := strings.Split(line, "|")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		out = append(out, strings.TrimSpace(part))
	}
	return out
}

func appendUnique(values []string, next string) []string {
	for _, value := range values {
		if value == next {
			return values
		}
	}
	if next != "" {
		return append(values, next)
	}
	return values
}

func limitStrings(values []string, limit int) []string {
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		out = append(out, value)
		if len(out) >= limit {
			return out
		}
	}
	return out
}

func bestOrganization(current string, values []string) string {
	if current != "" {
		return current
	}
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func BuildGeoConsistency(input GeoConsistencyInput) *GeoConsistencyAnalysis {
	out := &GeoConsistencyAnalysis{
		RegisteredCountry: normalizeCountry(input.RegisteredCountry),
		AnnouncedCountry:  normalizeCountry(input.AnnouncedCountry),
		LocationCountry:   normalizeCountry(input.LocationCountry),
	}
	if input.BGP != nil && input.BGP.ObservationCount > 0 {
		if input.BGP.DominantUpstream > 0 {
			out.BGPPathHint = fmt.Sprintf("AS%d", input.BGP.DominantUpstream)
		}
		out.Evidence = append(out.Evidence, fmt.Sprintf("RIPE RIS 观察点 %d 个", input.BGP.ObservationCount))
		if input.BGP.DominantUpstream > 0 {
			out.Evidence = append(out.Evidence, fmt.Sprintf("主上游 AS%d", input.BGP.DominantUpstream))
		}
	}

	countries := []string{}
	signalCount := 0
	for _, country := range []string{out.RegisteredCountry, out.AnnouncedCountry, out.LocationCountry} {
		if country == "" {
			continue
		}
		signalCount++
		if !containsString(countries, country) {
			countries = append(countries, country)
		}
	}
	if signalCount < 2 {
		return nil
	}
	if len(countries) <= 1 {
		out.Summary = "注册地、宣告地和所在地一致"
		out.Confidence = 0.7
		return out
	}

	out.Conflict = true
	out.Confidence = 0.65
	if out.RegisteredCountry != "" && out.AnnouncedCountry != "" && out.RegisteredCountry != out.AnnouncedCountry {
		out.Evidence = append(out.Evidence, fmt.Sprintf("注册地 %s 与宣告地 %s 不一致", out.RegisteredCountry, out.AnnouncedCountry))
	}
	if out.RegisteredCountry != "" && out.LocationCountry != "" && out.RegisteredCountry != out.LocationCountry {
		out.Evidence = append(out.Evidence, fmt.Sprintf("注册地 %s 与所在地 %s 不一致", out.RegisteredCountry, out.LocationCountry))
	}
	if out.AnnouncedCountry != "" && out.LocationCountry != "" && out.AnnouncedCountry != out.LocationCountry {
		out.Evidence = append(out.Evidence, fmt.Sprintf("宣告地 %s 与所在地 %s 不一致", out.AnnouncedCountry, out.LocationCountry))
	}
	parts := []string{}
	if out.RegisteredCountry != "" {
		parts = append(parts, "注册地 "+out.RegisteredCountry)
	}
	if out.AnnouncedCountry != "" {
		parts = append(parts, "宣告地 "+out.AnnouncedCountry)
	}
	if out.LocationCountry != "" {
		parts = append(parts, "所在地 "+out.LocationCountry)
	}
	if out.BGPPathHint != "" {
		parts = append(parts, "BGP 主上游 "+out.BGPPathHint)
	}
	out.Summary = strings.Join(parts, "，")
	return out
}

func parseASPath(value string) []int {
	fields := strings.Fields(value)
	path := make([]int, 0, len(fields))
	for _, field := range fields {
		asn := parsePositiveInt(strings.Trim(field, "{}(),"))
		if asn > 0 {
			path = append(path, asn)
		}
	}
	return path
}

func upstreamBeforeOrigin(path []int, origin int) int {
	if len(path) < 2 {
		return 0
	}
	index := len(path) - 1
	if origin > 0 {
		for i := len(path) - 1; i >= 0; i-- {
			if path[i] == origin {
				index = i
				break
			}
		}
	}
	for i := index - 1; i >= 0; i-- {
		if path[i] > 0 && path[i] != origin {
			return path[i]
		}
	}
	return 0
}

func sortedASNCounts(counts map[int]int) []BGPASNCount {
	out := make([]BGPASNCount, 0, len(counts))
	for asn, count := range counts {
		out = append(out, BGPASNCount{ASN: asn, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].ASN < out[j].ASN
		}
		return out[i].Count > out[j].Count
	})
	return out
}

func parsePositiveInt(value string) int {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || parsed <= 0 {
		return 0
	}
	return parsed
}

func normalizeCountry(value string) string {
	return strings.ToUpper(strings.TrimSpace(value))
}

func firstNonEmptyCountry(values ...string) string {
	for _, value := range values {
		value = normalizeCountry(value)
		if value != "" && value != "ZZ" {
			return value
		}
	}
	return ""
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func countryFromPipe(line string) string {
	parts := splitPipe(line)
	if len(parts) == 7 {
		return parts[3]
	}
	if len(parts) >= 3 {
		return parts[2]
	}
	return ""
}

func registryFromPipe(line string) string {
	parts := splitPipe(line)
	if len(parts) == 7 {
		return strings.ToLower(parts[4])
	}
	if len(parts) >= 4 {
		return strings.ToLower(parts[3])
	}
	return ""
}

func joinRDAP(summary *RDAPSummary) string {
	if summary == nil {
		return ""
	}
	return strings.Join(append([]string{summary.Name, summary.Type}, summary.Descriptions...), " ")
}

func joinWhois(summary *WhoisSummary) string {
	if summary == nil {
		return ""
	}
	return strings.Join(append([]string{summary.NetName, summary.Organization}, append(summary.Descriptions, summary.Remarks...)...), " ")
}

func containsAny(text string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(text, needle) {
			return true
		}
	}
	return false
}

func ReverseIPForCymru(ip string) (string, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() {
		return "", false
	}
	parts := strings.Split(addr.String(), ".")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, ".") + ".origin.asn.cymru.com", true
}
