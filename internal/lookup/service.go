package lookup

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ipasn/internal/ai"
	"ipasn/internal/classify"
	"ipasn/internal/enrich"
	"ipasn/internal/geo"
	"ipasn/internal/store"
)

type AIInfo struct {
	Used       bool    `json:"used"`
	Model      string  `json:"model,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
	Reason     string  `json:"reason,omitempty"`
	Error      string  `json:"error,omitempty"`
}

type DataQualityInfo struct {
	Score           float64  `json:"score"`
	Level           string   `json:"level"`
	SourceAgreement string   `json:"source_agreement,omitempty"`
	Freshness       string   `json:"freshness,omitempty"`
	Signals         []string `json:"signals,omitempty"`
}

type RoutingSecurityInfo struct {
	RPKI               string                       `json:"rpki,omitempty"`
	RPKIReason         string                       `json:"rpki_reason,omitempty"`
	RPKIMatchedPrefix  string                       `json:"rpki_matched_prefix,omitempty"`
	RPKIMaxLength      int                          `json:"rpki_max_length,omitempty"`
	IRRMatched         bool                         `json:"irr_matched"`
	IRRConflict        bool                         `json:"irr_conflict,omitempty"`
	IRROriginASNs      []int                        `json:"irr_origin_asns,omitempty"`
	MOAS               bool                         `json:"moas,omitempty"`
	RouteLeakSuspected bool                         `json:"route_leak_suspected,omitempty"`
	PrefixVisibility   int                          `json:"prefix_visibility,omitempty"`
	OriginAgreement    float64                      `json:"origin_agreement,omitempty"`
	BGP                *store.BGPObservationSummary `json:"bgp,omitempty"`
	Evidence           []string                     `json:"evidence,omitempty"`
}

type SourceVote struct {
	Source     string  `json:"source"`
	Scene      string  `json:"scene"`
	SceneName  string  `json:"scene_name,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
	Detail     string  `json:"detail,omitempty"`
}

type Result struct {
	OK                 bool                           `json:"ok"`
	Query              string                         `json:"query"`
	QueryType          string                         `json:"query_type,omitempty"`
	IP                 string                         `json:"ip,omitempty"`
	ASN                int                            `json:"asn,omitempty"`
	Company            string                         `json:"company,omitempty"`
	Country            string                         `json:"country,omitempty"`
	Registry           string                         `json:"registry,omitempty"`
	MatchedPrefix      string                         `json:"matched_prefix,omitempty"`
	RoutingStatus      string                         `json:"routing_status,omitempty"`
	AllocationStatus   string                         `json:"allocation_status,omitempty"`
	Scene              string                         `json:"scene,omitempty"`
	SceneName          string                         `json:"scene_name,omitempty"`
	InferredScene      string                         `json:"inferred_scene,omitempty"`
	InferredSceneName  string                         `json:"inferred_scene_name,omitempty"`
	InferredConfidence float64                        `json:"inferred_confidence,omitempty"`
	InferredSource     string                         `json:"inferred_source,omitempty"`
	Confidence         float64                        `json:"confidence,omitempty"`
	Evidence           []string                       `json:"evidence,omitempty"`
	Sources            []string                       `json:"sources,omitempty"`
	NetName            string                         `json:"netname,omitempty"`
	Registration       *enrich.Result                 `json:"registration,omitempty"`
	GeoConsistency     *enrich.GeoConsistencyAnalysis `json:"geo_consistency,omitempty"`
	Egress             *EgressInfo                    `json:"egress,omitempty"`
	RoutingSecurity    *RoutingSecurityInfo           `json:"routing_security,omitempty"`
	DataQuality        *DataQualityInfo               `json:"data_quality,omitempty"`
	SourceVotes        []SourceVote                   `json:"source_votes,omitempty"`
	Warnings           []string                       `json:"warnings,omitempty"`
	History            []store.HistoryRecord          `json:"history,omitempty"`
	Prefixes           []string                       `json:"prefixes,omitempty"`
	Location           *geo.Location                  `json:"location,omitempty"`
	AI                 *AIInfo                        `json:"ai,omitempty"`
	DB                 store.Status                   `json:"db"`
	Error              string                         `json:"error,omitempty"`
	Extra              map[string]string              `json:"extra,omitempty"`
}

type EgressInfo struct {
	Type             string   `json:"type,omitempty"`
	Summary          string   `json:"summary,omitempty"`
	OriginASN        int      `json:"origin_asn,omitempty"`
	DominantUpstream int      `json:"dominant_upstream,omitempty"`
	UpstreamName     string   `json:"upstream_name,omitempty"`
	PresenceASN      int      `json:"presence_asn,omitempty"`
	PresenceName     string   `json:"presence_name,omitempty"`
	LikelyCountry    string   `json:"likely_country,omitempty"`
	LikelyCity       string   `json:"likely_city,omitempty"`
	IXPs             []string `json:"ixps,omitempty"`
	Facilities       []string `json:"facilities,omitempty"`
	Confidence       float64  `json:"confidence,omitempty"`
	Evidence         []string `json:"evidence,omitempty"`
}

type SnapshotProvider interface {
	Snapshot() *store.Snapshot
}

type staticProvider struct {
	snapshot atomic.Pointer[store.Snapshot]
}

type Service struct {
	provider           SnapshotProvider
	aiAdvisor          ai.Advisor
	enricher           Enricher
	geoLocator         geo.Locator
	aiConfidenceCutoff float64
}

type reverseDNSEntry struct {
	value    string
	cachedAt time.Time
}

type reverseDNSCache struct {
	ttl     time.Duration
	mu      sync.Mutex
	entries map[string]reverseDNSEntry
}

var (
	defaultReverseDNSCache = newReverseDNSCache(7 * 24 * time.Hour)
	reverseDNSLookup       = net.LookupAddr
)

type Enricher interface {
	EnrichIP(ctx context.Context, ip string, allocation store.AllocationRecord) (enrich.Result, error)
}

type optionEnricher interface {
	EnrichIPWithOptions(ctx context.Context, ip string, allocation store.AllocationRecord, options enrich.RequestOptions) (enrich.Result, error)
}

type Options struct {
	AIAdvisor          ai.Advisor
	Enricher           Enricher
	GeoLocator         geo.Locator
	AIConfidenceCutoff float64
}

type LookupOptions struct {
	IncludeLocation  bool
	OnlineEnrichment OnlineEnrichmentMode
}

type OnlineEnrichmentMode string

const (
	OnlineEnrichmentFast OnlineEnrichmentMode = "fast"
	OnlineEnrichmentWait OnlineEnrichmentMode = "wait"
	OnlineEnrichmentOff  OnlineEnrichmentMode = "off"
)

func NewService(snapshot *store.Snapshot) *Service {
	return NewServiceWithOptions(snapshot, Options{})
}

func NewServiceWithOptions(snapshot *store.Snapshot, options Options) *Service {
	p := &staticProvider{}
	p.snapshot.Store(snapshot)
	return NewServiceFromProviderWithOptions(p, options)
}

func NewServiceFromProvider(provider SnapshotProvider) *Service {
	return NewServiceFromProviderWithOptions(provider, Options{})
}

func NewServiceFromProviderWithOptions(provider SnapshotProvider, options Options) *Service {
	cutoff := options.AIConfidenceCutoff
	if cutoff <= 0 {
		cutoff = 0.7
	}
	return &Service{provider: provider, aiAdvisor: options.AIAdvisor, enricher: options.Enricher, geoLocator: options.GeoLocator, aiConfidenceCutoff: cutoff}
}

func (p *staticProvider) Snapshot() *store.Snapshot {
	return p.snapshot.Load()
}

func (s *Service) Lookup(query string) Result {
	return s.LookupContext(context.Background(), query)
}

func (s *Service) LookupContext(ctx context.Context, query string) Result {
	return s.LookupWithOptions(ctx, query, LookupOptions{})
}

func (s *Service) LookupWithOptions(ctx context.Context, query string, options LookupOptions) Result {
	query = strings.TrimSpace(query)
	snapshot := s.provider.Snapshot()
	if snapshot == nil {
		snapshot = store.EmptySnapshot()
	}

	if query == "" {
		return Result{OK: false, Query: query, DB: snapshot.Status, Error: "query is empty"}
	}

	if addr, err := netip.ParseAddr(query); err == nil {
		return s.lookupIP(ctx, snapshot, query, addr, options)
	}

	asn, ok := parseASNQuery(query)
	if ok {
		return s.lookupASN(ctx, snapshot, query, asn)
	}

	return Result{OK: false, Query: query, DB: snapshot.Status, Error: "query must be an IP or ASN"}
}

func (s *Service) lookupIP(ctx context.Context, snapshot *store.Snapshot, query string, addr netip.Addr, options LookupOptions) Result {
	classification := classify.Classify(classify.Input{IP: addr})
	if classification.Scene == "BOGON" {
		return Result{
			OK:         true,
			Query:      query,
			QueryType:  "ip",
			IP:         addr.String(),
			Scene:      classification.Scene,
			SceneName:  classification.SceneName,
			Confidence: classification.Confidence,
			Evidence:   classification.Evidence,
			DB:         snapshot.Status,
		}
	}

	prefix, ok := snapshot.Prefixes.Lookup(addr)
	if !ok {
		return s.lookupAllocationFallback(ctx, snapshot, query, addr, classification, options)
	}

	profile, _ := snapshot.ASNs.Lookup(prefix.ASN)
	rdns := reverseDNS(addr)
	classification = classify.Classify(classify.Input{
		IP:            addr,
		MatchedPrefix: prefix.Prefix,
		Profile:       profile,
		RDNS:          rdns,
	})

	evidence := append([]string{
		fmt.Sprintf("离线 Prefix2AS 命中 %s -> AS%d", prefix.Prefix, prefix.ASN),
	}, classification.Evidence...)
	if rdns != "" {
		evidence = append(evidence, "反向 DNS: "+rdns)
	}
	relatedPrefixes := relatedPrefixesForASN(snapshot, prefix.ASN, prefix.Prefix, 100)
	company := companyName(profile, prefix.ASN)
	country := profile.Country
	registry := profile.Registry
	allocationStatus := ""
	sources := mergeSources([]string{prefix.Source}, profile.Sources)
	netName := ""
	var registration *enrich.Result
	var history []store.HistoryRecord

	allocation, hasAllocation := allocationForIP(snapshot, addr, prefix, profile)
	if hasAllocation {
		country = firstNonEmpty(allocation.Country, country)
		registry = firstNonEmpty(allocation.Registry, registry)
		allocationStatus = allocation.Status
		sources = mergeSources(sources, []string{allocation.Source})
		if allocation.Source != "" {
			evidence = appendEvidenceUnique(evidence, []string{fmt.Sprintf("注册局分配记录命中 %s", allocation.Prefix)})
		}
	}

	if snapshot.History != nil && snapshot.History.SnapshotCount() > 0 {
		history = snapshot.History.Lookup(addr, 5)
		sources = mergeSources(sources, []string{"caida_history"})
		if len(history) > 0 {
			first := history[0]
			evidence = append(evidence, fmt.Sprintf("历史 BGP 样本曾命中 AS%d / %s / %s", first.ASN, first.Prefix, first.Label))
		} else {
			evidence = append(evidence, "历史 BGP 样本未找到 ASN")
		}
	}

	if s.enricher != nil && options.OnlineEnrichment != OnlineEnrichmentOff {
		enriched, err := s.enrichIP(ctx, addr.String(), allocation, options)
		if err == nil {
			registration = &enriched
			netName = enriched.NetName
			company = preferExistingCompany(company, enriched.Organization, prefix.ASN)
			evidence = appendEvidenceUnique(evidence, enriched.Evidence)
			sources = mergeSources(sources, enriched.Sources)
		} else {
			evidence = append(evidence, "多源增强失败："+err.Error())
		}
	}

	classification, aiInfo := s.maybeUseAI(ctx, ai.AdviceInput{
		Query:          query,
		QueryType:      "ip",
		IP:             addr.String(),
		ASN:            prefix.ASN,
		Company:        company,
		Country:        country,
		Registry:       registry,
		InfoType:       profile.InfoType,
		Website:        profile.Website,
		MatchedPrefix:  prefix.Prefix,
		RDNS:           rdns,
		RuleScene:      classification.Scene,
		RuleSceneName:  classification.SceneName,
		RuleConfidence: classification.Confidence,
		RuleEvidence:   evidence,
	}, classification, &evidence)
	inferredScene, inferredSceneName, inferredConfidence, inferredSource := inferredUsage(classification, registration, aiInfo)

	result := Result{
		OK:                 true,
		Query:              query,
		QueryType:          "ip",
		IP:                 addr.String(),
		ASN:                prefix.ASN,
		Company:            company,
		Country:            country,
		Registry:           registry,
		MatchedPrefix:      prefix.Prefix,
		RoutingStatus:      "announced",
		AllocationStatus:   allocationStatus,
		Scene:              classification.Scene,
		SceneName:          classification.SceneName,
		InferredScene:      inferredScene,
		InferredSceneName:  inferredSceneName,
		InferredConfidence: inferredConfidence,
		InferredSource:     inferredSource,
		Confidence:         classification.Confidence,
		Evidence:           evidence,
		Sources:            sources,
		NetName:            netName,
		Registration:       registration,
		History:            history,
		Prefixes:           relatedPrefixes,
		AI:                 aiInfo,
		DB:                 snapshot.Status,
	}
	s.attachLocation(ctx, &result, addr, options)
	s.attachGeoConsistency(&result)
	s.attachEgress(snapshot, &result)
	applyEnhancedUsage(&result)
	normalizeEgressForUsage(&result)
	appendEgressEvidence(&result)
	attachRoutingReliability(snapshot, &result)
	attachSourceVotes(&result)
	attachDataQuality(&result)
	return result
}

func (s *Service) lookupAllocationFallback(ctx context.Context, snapshot *store.Snapshot, query string, addr netip.Addr, classification classify.Result, options LookupOptions) Result {
	if snapshot.Allocations == nil {
		return Result{OK: false, Query: query, QueryType: "ip", IP: addr.String(), DB: snapshot.Status, Error: "no ASN found for IP"}
	}
	allocation, ok := snapshot.Allocations.Lookup(addr)
	if !ok {
		return Result{OK: false, Query: query, QueryType: "ip", IP: addr.String(), DB: snapshot.Status, Error: "no ASN found for IP"}
	}
	evidence := []string{
		"当前 BGP 离线库未找到 ASN",
		fmt.Sprintf("注册局分配记录命中 %s", allocation.Prefix),
	}
	scene := "UNROUTED"
	sceneName := "已分配未宣告"
	confidence := 0.9
	inferredScene := "NET"
	inferredSceneName := "基础设施"
	inferredConfidence := 0.35
	inferredSource := "注册局分配记录"
	company := ""
	netName := ""
	sources := []string{allocation.Source}
	var registration *enrich.Result
	history := []store.HistoryRecord{}
	ruleSceneApplied := classification.Scene != "" && classification.Scene != "NET" && classification.Confidence >= 0.75
	if ruleSceneApplied {
		scene = classification.Scene
		sceneName = classification.SceneName
		confidence = classification.Confidence
		inferredScene = classification.Scene
		inferredSceneName = classification.SceneName
		inferredConfidence = classification.Confidence
		inferredSource = "主场景规则"
		evidence = appendEvidenceUnique(evidence, classification.Evidence)
	}

	if snapshot.History != nil && snapshot.History.SnapshotCount() > 0 {
		history = snapshot.History.Lookup(addr, 5)
		sources = mergeSources(sources, []string{"caida_history"})
		if len(history) > 0 {
			first := history[0]
			evidence = append(evidence, fmt.Sprintf("历史 BGP 样本曾命中 AS%d / %s / %s", first.ASN, first.Prefix, first.Label))
		} else {
			evidence = append(evidence, "历史 BGP 样本未找到 ASN")
		}
	}

	if s.enricher != nil && options.OnlineEnrichment != OnlineEnrichmentOff {
		enriched, err := s.enrichIP(ctx, addr.String(), allocation, options)
		if err == nil {
			registration = &enriched
			if enriched.PrimaryScene != "" && !ruleSceneApplied {
				scene = enriched.PrimaryScene
				sceneName = enriched.PrimarySceneName
			}
			if enriched.InferredScene != "" && !ruleSceneApplied {
				inferredScene = enriched.InferredScene
				inferredSceneName = enriched.InferredSceneName
				inferredConfidence = enriched.InferredConfidence
				inferredSource = "RDAP/WHOIS 推断"
			}
			company = enriched.Organization
			netName = enriched.NetName
			evidence = appendEvidenceUnique(evidence, enriched.Evidence)
			sources = mergeSources(sources, enriched.Sources)
		} else {
			evidence = append(evidence, "多源增强失败："+err.Error())
		}
	}

	result := Result{
		OK:                 true,
		Query:              query,
		QueryType:          "ip",
		IP:                 addr.String(),
		Company:            company,
		Country:            allocation.Country,
		Registry:           allocation.Registry,
		MatchedPrefix:      allocation.Prefix,
		RoutingStatus:      "not_announced",
		AllocationStatus:   allocation.Status,
		Scene:              scene,
		SceneName:          sceneName,
		InferredScene:      inferredScene,
		InferredSceneName:  inferredSceneName,
		InferredConfidence: inferredConfidence,
		InferredSource:     inferredSource,
		Confidence:         confidence,
		Evidence:           evidence,
		Sources:            sources,
		NetName:            netName,
		Registration:       registration,
		History:            history,
		Prefixes:           []string{allocation.Prefix},
		DB:                 snapshot.Status,
	}
	s.attachLocation(ctx, &result, addr, options)
	s.attachGeoConsistency(&result)
	s.attachEgress(snapshot, &result)
	applyEnhancedUsage(&result)
	normalizeEgressForUsage(&result)
	appendEgressEvidence(&result)
	attachRoutingReliability(snapshot, &result)
	attachSourceVotes(&result)
	attachDataQuality(&result)
	return result
}

func (s *Service) enrichIP(ctx context.Context, ip string, allocation store.AllocationRecord, options LookupOptions) (enrich.Result, error) {
	if withOptions, ok := s.enricher.(optionEnricher); ok {
		return withOptions.EnrichIPWithOptions(ctx, ip, allocation, enrich.RequestOptions{Mode: enrichMode(options.OnlineEnrichment)})
	}
	return s.enricher.EnrichIP(ctx, ip, allocation)
}

func (s *Service) attachLocation(ctx context.Context, result *Result, addr netip.Addr, options LookupOptions) {
	if !options.IncludeLocation || s.geoLocator == nil || !addr.IsValid() {
		return
	}
	location, ok := s.geoLocator.Lookup(ctx, addr.String())
	if !ok {
		return
	}
	result.Location = &location
	result.Evidence = appendEvidenceUnique(result.Evidence, []string{"IP 所在地：" + formatLocationEvidence(location)})
}

func enrichMode(mode OnlineEnrichmentMode) enrich.Mode {
	switch mode {
	case OnlineEnrichmentWait:
		return enrich.ModeWait
	default:
		return enrich.ModeFast
	}
}

func (s *Service) attachGeoConsistency(result *Result) {
	if result == nil || result.Registration == nil {
		return
	}
	registeredCountry := ""
	if result.Registration.RDAP != nil {
		registeredCountry = result.Registration.RDAP.Country
	}
	if registeredCountry == "" && result.Registration.Whois != nil {
		registeredCountry = result.Registration.Whois.Country
	}
	announcedCountry := ""
	if result.Registration.TeamCymru != nil {
		announcedCountry = result.Registration.TeamCymru.Country
	}
	locationCountry := ""
	if result.Location != nil {
		locationCountry = locationCountryCode(result.Location)
	}
	analysis := enrich.BuildGeoConsistency(enrich.GeoConsistencyInput{
		RegisteredCountry: registeredCountry,
		AnnouncedCountry:  announcedCountry,
		LocationCountry:   locationCountry,
		BGP:               result.Registration.BGPPath,
	})
	if analysis == nil {
		return
	}
	result.GeoConsistency = analysis
	if analysis.Conflict && analysis.Summary != "" {
		result.Evidence = appendEvidenceUnique(result.Evidence, []string{"地理一致性：" + analysis.Summary})
	}
}

func (s *Service) attachEgress(snapshot *store.Snapshot, result *Result) {
	if snapshot == nil || snapshot.Egress == nil || result == nil || result.QueryType != "ip" {
		return
	}
	originASN := result.ASN
	upstreamASN := 0
	if result.Registration != nil && result.Registration.BGPPath != nil {
		if result.Registration.BGPPath.OriginASN > 0 {
			originASN = result.Registration.BGPPath.OriginASN
		}
		upstreamASN = result.Registration.BGPPath.DominantUpstream
	}

	candidates := []int{}
	if upstreamASN > 0 {
		candidates = append(candidates, upstreamASN)
	}
	if originASN > 0 && originASN != upstreamASN {
		candidates = append(candidates, originASN)
	}

	targetCountries := egressTargetCountries(result)
	selected, ok := selectEgressCandidate(snapshot, candidates, targetCountries)
	if !ok {
		return
	}

	info := &EgressInfo{
		Type:             "TRANSIT",
		OriginASN:        originASN,
		DominantUpstream: upstreamASN,
		PresenceASN:      selected.asn,
		Confidence:       0.55,
	}
	if upstreamASN > 0 {
		if profile, ok := snapshot.ASNs.Lookup(upstreamASN); ok {
			info.UpstreamName = companyName(profile, upstreamASN)
		}
	}
	if selected.asn > 0 {
		if profile, ok := snapshot.ASNs.Lookup(selected.asn); ok {
			info.PresenceName = companyName(profile, selected.asn)
		}
	}
	ixps := selected.ixps
	facilities := selected.facilities
	if suppressionType, suppressionEvidence := concreteEgressSuppression(result); suppressionType != "" {
		info.Type = suppressionType
		info.Confidence = 0.5
		ixps = nil
		facilities = nil
		info.Evidence = append(info.Evidence, suppressionEvidence)
	}
	if len(targetCountries) > 0 && !selected.matchedTarget {
		info.Confidence = 0.45
		info.Evidence = append(info.Evidence, "PeeringDB presence 未匹配目标国家/地区 "+strings.Join(targetCountries, "/")+"，未输出具体机房/IXP")
	}
	if len(ixps) > 0 {
		info.Type = "IXP"
		info.Confidence = 0.72
		for _, ixp := range limitIXPs(ixps, 5) {
			info.IXPs = append(info.IXPs, ixp.Name)
			if info.LikelyCountry == "" {
				info.LikelyCountry = ixp.Country
			}
			if info.LikelyCity == "" {
				info.LikelyCity = ixp.City
			}
			detail := ixp.Name
			if ixp.City != "" || ixp.Country != "" {
				detail += " " + strings.TrimSpace(strings.Join([]string{ixp.City, ixp.Country}, " "))
			}
			if ixp.IP != "" {
				detail += " " + ixp.IP
			}
			info.Evidence = append(info.Evidence, "PeeringDB IXP: "+detail)
		}
	}
	if len(facilities) > 0 {
		if info.Type == "TRANSIT" {
			info.Type = "IDC"
			info.Confidence = 0.65
		}
		for _, facility := range limitFacilities(facilities, 5) {
			info.Facilities = append(info.Facilities, facility.Name)
			if info.LikelyCountry == "" {
				info.LikelyCountry = facility.Country
			}
			if info.LikelyCity == "" {
				info.LikelyCity = facility.City
			}
			detail := strings.TrimSpace(strings.Join([]string{facility.Name, facility.City, facility.Country}, " "))
			info.Evidence = append(info.Evidence, "PeeringDB 机房: "+detail)
		}
	}
	if upstreamASN > 0 {
		info.Evidence = append([]string{fmt.Sprintf("RIPE RIS AS Path 主上游 AS%d", upstreamASN)}, info.Evidence...)
	}
	if info.UpstreamName == "" && upstreamASN > 0 {
		info.UpstreamName = fmt.Sprintf("AS%d", upstreamASN)
	}
	if info.PresenceName == "" && selected.asn > 0 {
		info.PresenceName = fmt.Sprintf("AS%d", selected.asn)
	}
	info.Summary = buildEgressSummary(info)
	result.Egress = info
}

type egressPresenceCandidate struct {
	asn           int
	ixps          []store.IXPPresence
	facilities    []store.FacilityPresence
	matchedTarget bool
}

func selectEgressCandidate(snapshot *store.Snapshot, candidates []int, targetCountries []string) (egressPresenceCandidate, bool) {
	var fallback egressPresenceCandidate
	hasFallback := false
	seen := map[int]bool{}
	for _, asn := range candidates {
		if asn <= 0 || seen[asn] {
			continue
		}
		seen[asn] = true
		presence, ok := snapshot.Egress.Lookup(asn)
		if !ok || (len(presence.IXPs) == 0 && len(presence.Facilities) == 0) {
			continue
		}
		ixps := preferredIXPs(presence.IXPs, targetCountries)
		facilities := preferredFacilities(presence.Facilities, targetCountries)
		matchedTarget := len(targetCountries) == 0 || len(ixps) > 0 || len(facilities) > 0
		candidate := egressPresenceCandidate{
			asn:           asn,
			ixps:          ixps,
			facilities:    facilities,
			matchedTarget: matchedTarget,
		}
		if matchedTarget {
			return candidate, true
		}
		if !hasFallback {
			fallback = candidate
			hasFallback = true
		}
	}
	return fallback, hasFallback
}

func normalizeEgressForUsage(result *Result) {
	if result == nil || result.Egress == nil {
		return
	}
	suppressionType, suppressionEvidence := concreteEgressSuppression(result)
	if suppressionType == "" {
		return
	}
	result.Egress.Type = suppressionType
	result.Egress.Confidence = 0.5
	result.Egress.LikelyCountry = ""
	result.Egress.LikelyCity = ""
	result.Egress.IXPs = nil
	result.Egress.Facilities = nil
	result.Egress.Evidence = appendEvidenceUnique(result.Egress.Evidence, []string{suppressionEvidence})
	result.Egress.Summary = buildEgressSummary(result.Egress)
}

func appendEgressEvidence(result *Result) {
	if result == nil || result.Egress == nil || result.Egress.Summary == "" {
		return
	}
	result.Evidence = appendEvidenceUnique(result.Evidence, []string{"机房/出口推断：" + result.Egress.Summary})
}

func concreteEgressSuppression(result *Result) (string, string) {
	if result == nil {
		return "", ""
	}
	scene := result.Scene
	confidence := result.Confidence
	if (scene == "" || scene == "NET") && result.InferredScene != "" {
		scene = result.InferredScene
		if result.InferredConfidence > 0 {
			confidence = result.InferredConfidence
		}
	}
	if (scene == "" || scene == "NET") && result.Registration != nil && result.Registration.InferredScene != "" {
		scene = result.Registration.InferredScene
		if result.Registration.InferredConfidence > 0 {
			confidence = result.Registration.InferredConfidence
		}
	}
	switch scene {
	case "DNS", "CDN":
		if scene == "CDN" && confidence < 0.8 {
			return "TRANSIT", "低置信度 CDN 场景不按主上游 PeeringDB 机房定位单点出口"
		}
		return "ANYCAST", "Anycast/公共服务场景不按主上游 PeeringDB 机房定位单点出口"
	case "DYN":
		return "TRANSIT", "家庭宽带场景不将主上游 PeeringDB 机房视为用户出口"
	case "MOB":
		return "TRANSIT", "移动网络场景不将主上游 PeeringDB 机房视为基站出口"
	case "EDU", "GOV", "ORG":
		return "TRANSIT", "机构网络场景不将主上游 PeeringDB 机房视为实际办公或校园出口"
	default:
		return "", ""
	}
}

func limitIXPs(values []store.IXPPresence, limit int) []store.IXPPresence {
	if limit <= 0 || len(values) <= limit {
		return values
	}
	return values[:limit]
}

func limitFacilities(values []store.FacilityPresence, limit int) []store.FacilityPresence {
	if limit <= 0 || len(values) <= limit {
		return values
	}
	return values[:limit]
}

func egressTargetCountries(result *Result) []string {
	countries := []string{}
	if result == nil {
		return countries
	}
	if result.Location != nil {
		countries = appendCountry(countries, locationCountryCode(result.Location))
	}
	if result.Registration != nil && result.Registration.RDAP != nil {
		countries = appendCountry(countries, result.Registration.RDAP.Country)
	}
	if result.Registration != nil && result.Registration.Whois != nil {
		countries = appendCountry(countries, result.Registration.Whois.Country)
	}
	countries = appendCountry(countries, result.Country)
	if result.Registration != nil && result.Registration.TeamCymru != nil {
		countries = appendCountry(countries, result.Registration.TeamCymru.Country)
	}
	return countries
}

func preferredIXPs(values []store.IXPPresence, countries []string) []store.IXPPresence {
	if len(values) == 0 || len(countries) == 0 {
		return values
	}
	preferred := []store.IXPPresence{}
	for _, country := range countries {
		for _, value := range values {
			if strings.EqualFold(value.Country, country) {
				preferred = append(preferred, value)
			}
		}
		if len(preferred) > 0 {
			return preferred
		}
	}
	return nil
}

func preferredFacilities(values []store.FacilityPresence, countries []string) []store.FacilityPresence {
	if len(values) == 0 || len(countries) == 0 {
		return values
	}
	preferred := []store.FacilityPresence{}
	for _, country := range countries {
		for _, value := range values {
			if strings.EqualFold(value.Country, country) {
				preferred = append(preferred, value)
			}
		}
		if len(preferred) > 0 {
			return preferred
		}
	}
	return nil
}

func appendCountry(values []string, country string) []string {
	country = strings.ToUpper(strings.TrimSpace(country))
	if country == "" {
		return values
	}
	for _, existing := range values {
		if existing == country {
			return values
		}
	}
	return append(values, country)
}

func buildEgressSummary(info *EgressInfo) string {
	if info == nil {
		return ""
	}
	parts := []string{}
	if info.LikelyCity != "" || info.LikelyCountry != "" {
		location := strings.TrimSpace(strings.Join([]string{info.LikelyCity, info.LikelyCountry}, " "))
		if location != "" {
			parts = append(parts, "疑似出口 "+location)
		}
	}
	if info.DominantUpstream > 0 {
		upstream := fmt.Sprintf("AS%d", info.DominantUpstream)
		if info.UpstreamName != "" {
			upstream += " " + info.UpstreamName
		}
		parts = append(parts, "主上游 "+upstream)
	}
	if len(info.IXPs) > 0 {
		parts = append(parts, "公开互联 "+strings.Join(info.IXPs, "/"))
	}
	if len(info.Facilities) > 0 {
		parts = append(parts, "机房 "+strings.Join(info.Facilities, "/"))
	}
	if len(info.IXPs) == 0 && len(info.Facilities) == 0 && info.Type == "TRANSIT" && info.DominantUpstream > 0 {
		parts = append(parts, "未定位目标地区机房/IXP")
	}
	if len(info.IXPs) == 0 && len(info.Facilities) == 0 && info.Type == "ANYCAST" {
		parts = append(parts, "Anycast/公共服务不定位单点机房")
	}
	return strings.Join(parts, "，")
}

type enhancedUsageCandidate struct {
	scene      string
	sceneName  string
	confidence float64
	source     string
}

func applyEnhancedUsage(result *Result) {
	if result == nil || result.QueryType != "ip" {
		return
	}
	candidate, ok := bestEnhancedUsageCandidate(result)
	if !ok {
		return
	}

	if candidate.confidence > result.Confidence && result.Confidence < 0.75 {
		result.Scene = candidate.scene
		result.SceneName = candidate.sceneName
		result.Confidence = candidate.confidence
		result.InferredScene = candidate.scene
		result.InferredSceneName = candidate.sceneName
		result.InferredConfidence = candidate.confidence
		result.InferredSource = candidate.source
		result.Evidence = appendEvidenceUnique(result.Evidence, []string{
			fmt.Sprintf("在线增强修正用途：%s -> %s %s", candidate.source, candidate.scene, candidate.sceneName),
		})
		return
	}

	if result.Confidence >= 0.75 {
		candidate, ok = egressUsageCandidate(result.Egress)
		if !ok {
			return
		}
	}
	if result.InferredSource == candidate.source || result.InferredSource == sourceWithEnhancement(result.InferredSource) {
		return
	}
	originalSource := result.InferredSource
	result.InferredSource = sourceWithEnhancement(result.InferredSource)
	result.Evidence = appendEvidenceUnique(result.Evidence, []string{
		fmt.Sprintf("在线增强参考：%s 提示 %s %s，保留%s %s %s",
			candidate.source,
			candidate.scene,
			candidate.sceneName,
			originalSource,
			result.InferredScene,
			result.InferredSceneName,
		),
	})
}

func attachRoutingReliability(snapshot *store.Snapshot, result *Result) {
	if snapshot == nil || snapshot.Reliability == nil || result == nil || result.QueryType != "ip" || result.ASN <= 0 || result.MatchedPrefix == "" {
		return
	}
	rpkiCount, irrCount, bgpCount := 0, 0, 0
	if snapshot.Reliability.RPKI != nil {
		rpkiCount = snapshot.Reliability.RPKI.Count()
	}
	if snapshot.Reliability.IRR != nil {
		irrCount = snapshot.Reliability.IRR.Count()
	}
	if snapshot.Reliability.BGP != nil {
		bgpCount = snapshot.Reliability.BGP.Count()
	}
	if rpkiCount == 0 && irrCount == 0 && bgpCount == 0 {
		return
	}
	security := &RoutingSecurityInfo{}
	evidence := []string{}
	warnings := []string{}

	if snapshot.Reliability.RPKI != nil && snapshot.Reliability.RPKI.Count() > 0 {
		rpki := snapshot.Reliability.RPKI.Validate(result.MatchedPrefix, result.ASN)
		security.RPKI = rpki.Status
		security.RPKIReason = rpki.Reason
		security.RPKIMatchedPrefix = rpki.MatchedPrefix
		security.RPKIMaxLength = rpki.MaxLength
		switch rpki.Status {
		case "valid":
			evidence = append(evidence, "RPKI: valid，ROA 授权当前 Origin ASN")
		case "invalid":
			evidence = append(evidence, "RPKI: invalid，ROA 与当前 Origin ASN 或前缀长度不一致")
			warnings = append(warnings, "RPKI Invalid：当前 ASN 宣告与 ROA 授权不一致")
		case "not_found":
			evidence = append(evidence, "RPKI: not_found，未找到覆盖当前路由的 ROA")
		}
	}

	if snapshot.Reliability.IRR != nil && snapshot.Reliability.IRR.Count() > 0 {
		irr := snapshot.Reliability.IRR.Validate(result.MatchedPrefix, result.ASN)
		security.IRRMatched = irr.Matched
		security.IRRConflict = irr.Conflict
		security.IRROriginASNs = irr.OriginASNs
		switch {
		case irr.Matched && irr.Conflict:
			evidence = append(evidence, "IRR: route object matched，但同一前缀存在多个 Origin ASN")
			warnings = append(warnings, "IRR 冲突：同一前缀存在多个 Origin ASN 记录")
		case irr.Matched:
			evidence = append(evidence, "IRR: route object matched")
		case irr.Conflict:
			evidence = append(evidence, "IRR: 当前 Origin ASN 未匹配，且存在其它 Origin ASN 记录")
			warnings = append(warnings, "IRR 未匹配：当前 ASN 与 IRR route object 不一致")
		default:
			evidence = append(evidence, "IRR: 未找到匹配 route object")
		}
	}

	if snapshot.Reliability.BGP != nil && snapshot.Reliability.BGP.Count() > 0 {
		bgp := snapshot.Reliability.BGP.Summarize(result.IP, result.ASN)
		if bgp.Visibility > 0 {
			security.PrefixVisibility = bgp.Visibility
			security.OriginAgreement = bgp.OriginAgreement
			security.MOAS = bgp.MOAS
			security.BGP = &bgp
			evidence = append(evidence, fmt.Sprintf("BGP 离线观察：%d 个观察样本，Origin 一致率 %.0f%%", bgp.Visibility, bgp.OriginAgreement*100))
			if bgp.MOAS {
				warnings = append(warnings, "BGP MOAS：同一前缀存在多个 Origin ASN")
			}
		}
	}

	security.RouteLeakSuspected = routeLeakSuspected(security)
	if security.RouteLeakSuspected {
		warnings = append(warnings, "疑似路由异常：RPKI/IRR/BGP 多源信号存在明显冲突")
	}
	security.Evidence = appendEvidenceUnique(security.Evidence, evidence)
	result.Evidence = appendEvidenceUnique(result.Evidence, evidence)
	result.Warnings = appendStringUnique(result.Warnings, warnings...)
	result.RoutingSecurity = security
}

func routeLeakSuspected(security *RoutingSecurityInfo) bool {
	if security == nil {
		return false
	}
	if security.RPKI == "invalid" {
		return true
	}
	if security.MOAS && security.OriginAgreement > 0 && security.OriginAgreement < 0.5 {
		return true
	}
	if security.IRRConflict && !security.IRRMatched {
		return true
	}
	return false
}

func attachSourceVotes(result *Result) {
	if result == nil || result.QueryType != "ip" {
		return
	}
	votes := []SourceVote{}
	if result.Scene != "" {
		votes = append(votes, SourceVote{
			Source:     "主场景规则",
			Scene:      result.Scene,
			SceneName:  result.SceneName,
			Confidence: result.Confidence,
			Detail:     result.InferredSource,
		})
	}
	if result.Registration != nil && result.Registration.InferredScene != "" {
		votes = append(votes, SourceVote{
			Source:     "RDAP/WHOIS",
			Scene:      result.Registration.InferredScene,
			SceneName:  result.Registration.InferredSceneName,
			Confidence: result.Registration.InferredConfidence,
			Detail:     result.Registration.NetName,
		})
	}
	if candidate, ok := egressUsageCandidate(result.Egress); ok {
		votes = append(votes, SourceVote{
			Source:     candidate.source,
			Scene:      candidate.scene,
			SceneName:  candidate.sceneName,
			Confidence: candidate.confidence,
			Detail:     result.Egress.Summary,
		})
	}
	if result.AI != nil && result.AI.Used && result.AI.Reason != "" {
		votes = append(votes, SourceVote{
			Source:     "AI",
			Scene:      result.InferredScene,
			SceneName:  result.InferredSceneName,
			Confidence: result.AI.Confidence,
			Detail:     result.AI.Reason,
		})
	}
	result.SourceVotes = votes
}

func attachDataQuality(result *Result) {
	if result == nil || result.QueryType != "ip" {
		return
	}
	score := 0.55
	signals := []string{}
	if result.MatchedPrefix != "" {
		score += 0.08
		signals = append(signals, "离线 Prefix2AS 命中")
	}
	if result.AllocationStatus != "" {
		score += 0.05
		signals = append(signals, "RIR 分配记录命中")
	}
	if result.Registration != nil {
		score += 0.05
		signals = append(signals, "在线注册信息可用")
	}
	if result.GeoConsistency != nil && result.GeoConsistency.Conflict {
		score -= 0.08
		signals = append(signals, "地理信息存在差异")
	}
	if result.Confidence >= 0.75 {
		score += 0.06
		signals = append(signals, "场景规则高置信度")
	}
	if result.RoutingSecurity != nil {
		score += routingSecurityScore(result.RoutingSecurity, &signals)
	}
	score = clamp(score, 0, 1)
	result.DataQuality = &DataQualityInfo{
		Score:           score,
		Level:           dataQualityLevel(score),
		SourceAgreement: sourceAgreement(result.RoutingSecurity),
		Freshness:       dataFreshness(result.DB.UpdatedAt),
		Signals:         signals,
	}
}

func routingSecurityScore(security *RoutingSecurityInfo, signals *[]string) float64 {
	if security == nil {
		return 0
	}
	score := 0.0
	switch security.RPKI {
	case "valid":
		score += 0.14
		*signals = append(*signals, "RPKI Valid")
	case "invalid":
		score -= 0.3
		*signals = append(*signals, "RPKI Invalid")
	case "not_found":
		score -= 0.03
		*signals = append(*signals, "RPKI NotFound")
	}
	if security.IRRMatched {
		score += 0.08
		*signals = append(*signals, "IRR route object 匹配")
	}
	if security.IRRConflict {
		score -= 0.08
		*signals = append(*signals, "IRR route object 冲突")
	}
	if security.PrefixVisibility > 0 {
		score += 0.08
		*signals = append(*signals, "BGP 多观察点可见")
		if security.OriginAgreement >= 0.9 {
			score += 0.08
			*signals = append(*signals, "BGP Origin 高一致")
		} else if security.OriginAgreement < 0.5 {
			score -= 0.12
			*signals = append(*signals, "BGP Origin 低一致")
		}
	}
	if security.MOAS {
		score -= 0.1
		*signals = append(*signals, "BGP MOAS")
	}
	if security.RouteLeakSuspected {
		score -= 0.15
		*signals = append(*signals, "疑似路由异常")
	}
	return score
}

func dataQualityLevel(score float64) string {
	switch {
	case score >= 0.8:
		return "high"
	case score >= 0.55:
		return "medium"
	default:
		return "low"
	}
}

func sourceAgreement(security *RoutingSecurityInfo) string {
	if security == nil {
		return "partial"
	}
	switch {
	case security.RouteLeakSuspected:
		return "routing_conflict"
	case security.RPKI == "valid" && security.IRRMatched && security.OriginAgreement >= 0.9:
		return "rpki_irr_bgp_agree"
	case security.MOAS:
		return "bgp_moas"
	case security.RPKI == "valid":
		return "rpki_valid"
	default:
		return "partial"
	}
}

func dataFreshness(updatedAt time.Time) string {
	if updatedAt.IsZero() {
		return "unknown"
	}
	age := time.Since(updatedAt)
	switch {
	case age <= 48*time.Hour:
		return "fresh"
	case age <= 7*24*time.Hour:
		return "recent"
	default:
		return "stale"
	}
}

func bestEnhancedUsageCandidate(result *Result) (enhancedUsageCandidate, bool) {
	candidates := []enhancedUsageCandidate{}
	if result.Registration != nil && result.Registration.InferredScene != "" && result.Registration.InferredConfidence >= 0.55 {
		candidates = append(candidates, enhancedUsageCandidate{
			scene:      result.Registration.InferredScene,
			sceneName:  firstNonEmpty(result.Registration.InferredSceneName, usageSceneName(result.Registration.InferredScene)),
			confidence: result.Registration.InferredConfidence,
			source:     "RDAP/WHOIS 推断",
		})
	}
	if candidate, ok := egressUsageCandidate(result.Egress); ok {
		candidates = append(candidates, candidate)
	}
	if len(candidates) == 0 {
		return enhancedUsageCandidate{}, false
	}
	best := candidates[0]
	for _, candidate := range candidates[1:] {
		if candidate.confidence > best.confidence {
			best = candidate
		}
	}
	return best, true
}

func egressUsageCandidate(info *EgressInfo) (enhancedUsageCandidate, bool) {
	if info == nil {
		return enhancedUsageCandidate{}, false
	}
	switch info.Type {
	case "IDC":
		return enhancedUsageCandidate{
			scene:      "IDC",
			sceneName:  usageSceneName("IDC"),
			confidence: maxFloat(info.Confidence, 0.65),
			source:     "机房/出口推断",
		}, true
	case "IXP":
		return enhancedUsageCandidate{
			scene:      "NET",
			sceneName:  usageSceneName("NET"),
			confidence: maxFloat(info.Confidence, 0.62),
			source:     "机房/出口推断",
		}, true
	case "TRANSIT":
		return enhancedUsageCandidate{
			scene:      "NET",
			sceneName:  usageSceneName("NET"),
			confidence: maxFloat(info.Confidence, 0.55),
			source:     "机房/出口推断",
		}, true
	default:
		return enhancedUsageCandidate{}, false
	}
}

func sourceWithEnhancement(source string) string {
	if source == "" {
		return "在线增强参考"
	}
	if strings.Contains(source, "在线增强参考") {
		return source
	}
	return source + " + 在线增强参考"
}

func usageSceneName(scene string) string {
	return map[string]string{
		"CDN":       "内容分发",
		"DNS":       "域名解析",
		"EDU":       "教育机构",
		"GTW":       "企业专线",
		"GOV":       "政府机构",
		"DYN":       "家庭宽带",
		"IDC":       "数据中心",
		"MOB":       "移动网络",
		"ORG":       "组织机构",
		"NET":       "基础设施",
		"BOGON":     "保留 IP",
		"UNROUTED":  "已分配未宣告",
		"STUN":      "NAT 穿透",
		"VPN":       "VPN 出口",
		"PROXY":     "代理服务",
		"TOR":       "Tor 出口",
		"BOT":       "搜索爬虫",
		"MAIL":      "邮件服务",
		"MON":       "监控探测",
		"IOT":       "物联网平台",
		"BLOCKLIST": "风险名单",
	}[scene]
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func locationCountryCode(location *geo.Location) string {
	if location == nil {
		return ""
	}
	text := strings.Join([]string{location.Country, location.Province, location.City}, " ")
	switch {
	case strings.Contains(text, "香港") || strings.Contains(strings.ToLower(text), "hong kong"):
		return "HK"
	case strings.Contains(text, "台湾") || strings.Contains(text, "臺灣") || strings.Contains(strings.ToLower(text), "taiwan"):
		return "TW"
	case strings.Contains(text, "澳门") || strings.Contains(text, "澳門") || strings.Contains(strings.ToLower(text), "macau") || strings.Contains(strings.ToLower(text), "macao"):
		return "MO"
	default:
		return strings.ToUpper(strings.TrimSpace(location.CountryCode))
	}
}

func formatLocationEvidence(location geo.Location) string {
	values := []string{location.Country, location.Province, location.City, location.ISP}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && value != "0" {
			out = append(out, value)
		}
	}
	if len(out) == 0 {
		return "未知"
	}
	return strings.Join(out, " ")
}

func appendEvidenceUnique(existing []string, next []string) []string {
	seen := map[string]bool{}
	for _, item := range existing {
		seen[item] = true
	}
	for _, item := range next {
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		existing = append(existing, item)
	}
	return existing
}

func appendStringUnique(existing []string, next ...string) []string {
	seen := map[string]bool{}
	for _, item := range existing {
		seen[item] = true
	}
	for _, item := range next {
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		existing = append(existing, item)
	}
	return existing
}

func clamp(value, minValue, maxValue float64) float64 {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func allocationForIP(snapshot *store.Snapshot, addr netip.Addr, prefix store.PrefixRecord, profile store.ASNProfile) (store.AllocationRecord, bool) {
	if snapshot.Allocations != nil {
		if allocation, ok := snapshot.Allocations.Lookup(addr); ok {
			return allocation, true
		}
	}
	if prefix.Prefix == "" && profile.Registry == "" {
		return store.AllocationRecord{}, false
	}
	return store.AllocationRecord{
		Prefix:   prefix.Prefix,
		Country:  profile.Country,
		Registry: profile.Registry,
	}, true
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func preferExistingCompany(current, enriched string, asn int) string {
	if current == "" || current == fmt.Sprintf("AS%d", asn) {
		return firstNonEmpty(enriched, current)
	}
	return current
}

func inferredUsage(classification classify.Result, registration *enrich.Result, aiInfo *AIInfo) (string, string, float64, string) {
	source := "主场景规则"
	if aiInfo != nil && aiInfo.Used {
		source = "AI 判断"
	}
	if classification.Confidence >= 0.75 {
		return classification.Scene, classification.SceneName, classification.Confidence, source
	}
	if registration != nil && registration.InferredScene != "" && registration.InferredConfidence >= 0.55 {
		return registration.InferredScene, registration.InferredSceneName, registration.InferredConfidence, "RDAP/WHOIS 推断"
	}
	return classification.Scene, classification.SceneName, classification.Confidence, source
}

func (s *Service) lookupASN(ctx context.Context, snapshot *store.Snapshot, query string, asn int) Result {
	profile, ok := snapshot.ASNs.Lookup(asn)
	if !ok {
		profile = store.ASNProfile{ASN: asn}
	}
	prefixRecords := snapshot.Prefixes.PrefixesForASN(asn, 100)
	prefixes := make([]string, 0, len(prefixRecords))
	for _, record := range prefixRecords {
		prefixes = append(prefixes, record.Prefix)
	}
	sort.Strings(prefixes)

	classification := classify.Classify(classify.Input{Profile: profile})
	evidence := append([]string{fmt.Sprintf("ASN 查询 AS%d", asn)}, classification.Evidence...)
	if !ok && len(prefixes) == 0 {
		return Result{OK: false, Query: query, QueryType: "asn", ASN: asn, DB: snapshot.Status, Error: "no information found for ASN"}
	}
	classification, aiInfo := s.maybeUseAI(ctx, ai.AdviceInput{
		Query:          query,
		QueryType:      "asn",
		ASN:            asn,
		Company:        companyName(profile, asn),
		Country:        profile.Country,
		Registry:       profile.Registry,
		InfoType:       profile.InfoType,
		Website:        profile.Website,
		RuleScene:      classification.Scene,
		RuleSceneName:  classification.SceneName,
		RuleConfidence: classification.Confidence,
		RuleEvidence:   evidence,
	}, classification, &evidence)

	return Result{
		OK:         true,
		Query:      query,
		QueryType:  "asn",
		ASN:        asn,
		Company:    companyName(profile, asn),
		Country:    profile.Country,
		Registry:   profile.Registry,
		Scene:      classification.Scene,
		SceneName:  classification.SceneName,
		Confidence: classification.Confidence,
		Evidence:   evidence,
		Sources:    profile.Sources,
		Prefixes:   prefixes,
		AI:         aiInfo,
		DB:         snapshot.Status,
	}
}

func (s *Service) maybeUseAI(ctx context.Context, input ai.AdviceInput, classification classify.Result, evidence *[]string) (classify.Result, *AIInfo) {
	if s.aiAdvisor == nil || classification.Confidence >= s.aiConfidenceCutoff {
		return classification, nil
	}

	decision, err := s.aiAdvisor.Advise(ctx, input)
	if err != nil {
		return classification, &AIInfo{Used: false, Error: err.Error()}
	}

	*evidence = append(*evidence, "AI 判断："+decision.Reason)
	return classify.Result{
			Scene:      decision.Scene,
			SceneName:  decision.SceneName,
			Confidence: decision.Confidence,
			Evidence:   classification.Evidence,
		}, &AIInfo{
			Used:       true,
			Model:      decision.Model,
			Confidence: decision.Confidence,
			Reason:     decision.Reason,
		}
}

func parseASNQuery(query string) (int, bool) {
	value := strings.TrimSpace(strings.ToUpper(query))
	value = strings.TrimPrefix(value, "AS")
	if value == "" {
		return 0, false
	}
	asn, err := strconv.Atoi(value)
	if err != nil || asn <= 0 {
		return 0, false
	}
	return asn, true
}

func companyName(profile store.ASNProfile, asn int) string {
	if profile.Name != "" {
		return profile.Name
	}
	if profile.AKA != "" {
		return profile.AKA
	}
	return fmt.Sprintf("AS%d", asn)
}

func reverseDNS(addr netip.Addr) string {
	return defaultReverseDNSCache.lookup(addr.String(), reverseDNSLookup)
}

func newReverseDNSCache(ttl time.Duration) *reverseDNSCache {
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	return &reverseDNSCache{ttl: ttl, entries: map[string]reverseDNSEntry{}}
}

func (c *reverseDNSCache) lookup(ip string, lookup func(string) ([]string, error)) string {
	now := time.Now()
	c.mu.Lock()
	if entry, ok := c.entries[ip]; ok && now.Sub(entry.cachedAt) <= c.ttl {
		c.mu.Unlock()
		return entry.value
	}
	c.mu.Unlock()

	names, err := lookup(ip)
	value := ""
	if err != nil || len(names) == 0 {
		c.store(ip, value)
		return value
	}
	value = strings.TrimSuffix(names[0], ".")
	c.store(ip, value)
	return value
}

func (c *reverseDNSCache) store(ip, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[ip] = reverseDNSEntry{value: value, cachedAt: time.Now()}
}

func mergeSources(values ...[]string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, list := range values {
		for _, item := range list {
			if item == "" || seen[item] {
				continue
			}
			seen[item] = true
			out = append(out, item)
		}
	}
	sort.Strings(out)
	return out
}

func relatedPrefixesForASN(snapshot *store.Snapshot, asn int, matchedPrefix string, limit int) []string {
	records := snapshot.Prefixes.PrefixesForASN(asn, limit)
	prefixes := make([]string, 0, len(records))
	seen := map[string]bool{}
	if matchedPrefix != "" {
		prefixes = append(prefixes, matchedPrefix)
		seen[matchedPrefix] = true
	}
	for _, record := range records {
		if seen[record.Prefix] {
			continue
		}
		prefixes = append(prefixes, record.Prefix)
	}
	if limit > 0 && len(prefixes) > limit {
		return prefixes[:limit]
	}
	return prefixes
}
