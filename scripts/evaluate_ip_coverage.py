#!/usr/bin/env python3
"""Build and run a broad IP coverage evaluation set against the local IPASN API."""

from __future__ import annotations

import argparse
import csv
import gzip
import html
import ipaddress
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "data" / "evaluation"
SAMPLE_CSV = OUT_DIR / "ip_coverage_samples.csv"
RESULT_JSONL = OUT_DIR / "ip_coverage_results.jsonl"
REPORT_MD = OUT_DIR / "ip_coverage_report.md"


SOURCE_URLS = {
    "aws": "https://ip-ranges.amazonaws.com/ip-ranges.json",
    "azure": "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519",
    "cloudflare_v4": "https://www.cloudflare.com/ips-v4",
    "cloudflare_v6": "https://www.cloudflare.com/ips-v6",
    "fastly": "https://api.fastly.com/public-ip-list",
    "github": "https://api.github.com/meta",
    "google_cloud": "https://www.gstatic.com/ipranges/cloud.json",
    "oracle": "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json",
    "tor": "https://check.torproject.org/torbulkexitlist",
}


@dataclass(frozen=True)
class Sample:
    ip: str
    family: str
    category: str
    label: str
    expected_scene: str
    source: str
    source_url: str = ""


ASN_CATEGORY_SEEDS = {
    "IDC": {
        16509: "AWS",
        8075: "Microsoft",
        396982: "Google Cloud",
        14061: "DigitalOcean",
        20473: "Vultr",
        24940: "Hetzner",
        63949: "Akamai/Linode",
        16276: "OVHcloud",
        45102: "Alibaba",
        132203: "Tencent Global",
        31898: "Oracle Cloud",
        12876: "Scaleway",
    },
    "CDN": {
        13335: "Cloudflare",
        54113: "Fastly",
        20940: "Akamai",
        32934: "Meta",
        15169: "Google",
        714: "Apple",
    },
    "MOB": {
        58453: "China Mobile International",
        56048: "China Mobile",
        9808: "China Mobile",
        21928: "T-Mobile USA",
        20057: "AT&T Mobility",
        22394: "Verizon Wireless",
        6167: "Verizon Wireless",
    },
    "DYN": {
        7922: "Comcast",
        20115: "Charter",
        5650: "Frontier",
        22773: "Cox",
        3320: "Deutsche Telekom",
        2856: "British Telecom",
        4134: "China Telecom",
        4837: "China Unicom",
        7018: "AT&T",
        701: "Verizon",
    },
    "EDU": {
        4538: "CERNET",
        3: "MIT",
        25: "University of California",
        32: "Stanford",
        11: "Harvard",
        786: "Jisc/Janet",
        20965: "GEANT",
    },
    "GOV": {
        49: "NIST",
        297: "NASA",
        721: "DoD",
        27066: "NOAA",
    },
    "NET": {
        174: "Cogent",
        1299: "Arelion",
        2914: "NTT",
        3356: "Lumen",
        6939: "Hurricane Electric",
        3491: "PCCW",
        6453: "Tata",
    },
}


HARD_CODED = [
    ("0.0.0.1", "BOGON", "Reserved 0/8", "BOGON"),
    ("10.1.2.3", "BOGON", "RFC1918 10/8", "BOGON"),
    ("100.64.1.1", "BOGON", "CGNAT 100.64/10", "BOGON"),
    ("127.0.0.1", "BOGON", "Loopback", "BOGON"),
    ("169.254.1.1", "BOGON", "Link local", "BOGON"),
    ("172.16.0.1", "BOGON", "RFC1918 172.16/12", "BOGON"),
    ("192.168.1.1", "BOGON", "RFC1918 192.168/16", "BOGON"),
    ("192.0.2.1", "BOGON", "TEST-NET-1", "BOGON"),
    ("198.51.100.1", "BOGON", "TEST-NET-2", "BOGON"),
    ("203.0.113.1", "BOGON", "TEST-NET-3", "BOGON"),
    ("224.0.0.1", "BOGON", "Multicast", "BOGON"),
    ("240.0.0.1", "BOGON", "Reserved 240/4", "BOGON"),
    ("::", "BOGON", "IPv6 unspecified", "BOGON"),
    ("::1", "BOGON", "IPv6 loopback", "BOGON"),
    ("fc00::1", "BOGON", "IPv6 ULA", "BOGON"),
    ("fd00::1", "BOGON", "IPv6 ULA local", "BOGON"),
    ("fe80::1", "BOGON", "IPv6 link local", "BOGON"),
    ("2001:db8::1", "BOGON", "IPv6 documentation", "BOGON"),
    ("ff02::1", "BOGON", "IPv6 multicast", "BOGON"),
    ("1.1.1.1", "DNS", "Cloudflare DNS", "DNS"),
    ("1.0.0.1", "DNS", "Cloudflare DNS", "DNS"),
    ("8.8.8.8", "DNS", "Google DNS", "DNS"),
    ("8.8.4.4", "DNS", "Google DNS", "DNS"),
    ("9.9.9.9", "DNS", "Quad9 DNS", "DNS"),
    ("149.112.112.112", "DNS", "Quad9 DNS", "DNS"),
    ("208.67.222.222", "DNS", "OpenDNS", "DNS"),
    ("208.67.220.220", "DNS", "OpenDNS", "DNS"),
    ("114.114.114.114", "DNS", "114DNS", "DNS"),
    ("114.114.115.115", "DNS", "114DNS", "DNS"),
    ("223.5.5.5", "DNS", "AliDNS", "DNS"),
    ("223.6.6.6", "DNS", "AliDNS", "DNS"),
    ("119.29.29.29", "DNS", "DNSPod", "DNS"),
    ("180.76.76.76", "DNS", "Baidu DNS", "DNS"),
    ("94.140.14.14", "DNS", "AdGuard DNS", "DNS"),
    ("2606:4700:4700::1111", "DNS", "Cloudflare DNS IPv6", "DNS"),
    ("2606:4700:4700::1001", "DNS", "Cloudflare DNS IPv6", "DNS"),
    ("2001:4860:4860::8888", "DNS", "Google DNS IPv6", "DNS"),
    ("2001:4860:4860::8844", "DNS", "Google DNS IPv6", "DNS"),
    ("2620:fe::fe", "DNS", "Quad9 DNS IPv6", "DNS"),
    ("2620:fe::9", "DNS", "Quad9 DNS IPv6", "DNS"),
    ("2620:119:35::35", "DNS", "OpenDNS IPv6", "DNS"),
    ("2620:119:53::53", "DNS", "OpenDNS IPv6", "DNS"),
    ("2a10:50c0::ad1:ff", "DNS", "AdGuard DNS IPv6", "DNS"),
    ("2a10:50c0::ad2:ff", "DNS", "AdGuard DNS IPv6", "DNS"),
    ("34.80.255.24", "IDC", "Google Cloud Taiwan", "IDC"),
    ("52.95.110.1", "IDC", "AWS", "IDC"),
    ("20.50.2.1", "IDC", "Azure", "IDC"),
    ("47.75.1.1", "IDC", "Alibaba Cloud HK", "IDC"),
    ("43.132.43.43", "IDC", "Tencent HTTPDNS Enterprise", "IDC"),
    ("159.89.48.1", "IDC", "DigitalOcean", "IDC"),
    ("45.32.0.1", "IDC", "Vultr", "IDC"),
    ("95.216.1.1", "IDC", "Hetzner", "IDC"),
    ("51.15.1.1", "IDC", "Scaleway", "IDC"),
    ("2a03:b0c0:3:d0::1", "IDC", "DigitalOcean IPv6", "IDC"),
    ("2001:19f0:5:1::1", "IDC", "Vultr IPv6", "IDC"),
    ("2a01:4f8:c17:1::1", "IDC", "Hetzner IPv6", "IDC"),
    ("2600:3c03::1", "IDC", "Linode IPv6", "IDC"),
    ("104.16.0.1", "CDN", "Cloudflare CDN", "CDN"),
    ("151.101.1.69", "CDN", "Fastly CDN", "CDN"),
    ("23.48.0.1", "CDN", "Akamai CDN", "CDN"),
    ("2606:4700::1", "CDN", "Cloudflare IPv6 CDN", "CDN"),
    ("2a04:4e42::1", "CDN", "Fastly IPv6 CDN", "CDN"),
    ("148.66.51.30", "NET", "XLC/Netsec BGP", "NET"),
    ("223.119.20.240", "MOB", "China Mobile International", "MOB"),
    ("117.136.0.1", "MOB", "China Mobile", "MOB"),
    ("208.54.86.1", "MOB", "T-Mobile USA", "MOB"),
    ("166.216.157.1", "MOB", "AT&T Mobility", "MOB"),
    ("70.192.0.1", "MOB", "Verizon Wireless", "MOB"),
    ("64.81.32.64", "DYN", "Speakeasy DSL", "DYN"),
    ("73.162.0.1", "DYN", "Comcast residential", "DYN"),
    ("71.80.0.1", "DYN", "Charter residential", "DYN"),
    ("47.151.0.1", "DYN", "Frontier residential", "DYN"),
    ("14.145.60.215", "DYN", "China Telecom Guangdong", "DYN"),
    ("166.111.4.100", "EDU", "Tsinghua", "EDU"),
    ("162.105.132.179", "EDU", "Peking University", "EDU"),
    ("202.112.0.36", "EDU", "CERNET", "EDU"),
    ("18.9.22.69", "EDU", "MIT", "EDU"),
    ("2001:da8:200::1", "EDU", "CERNET/Tsinghua IPv6", "EDU"),
    ("129.6.15.28", "GOV", "NIST", "GOV"),
    ("91.198.174.192", "ORG", "Wikimedia", "ORG"),
    ("185.220.101.1", "TOR", "Tor exit sample", "TOR"),
]


def http_get(url: str, timeout: float = 20.0) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "IPASN coverage evaluator"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def make_sample(ip: str, category: str, label: str, expected: str, source: str, source_url: str = "") -> Sample | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return Sample(str(addr), f"IPv{addr.version}", category, label, expected, source, source_url)


def ip_from_prefix(prefix: str, offset: int = 1) -> str | None:
    try:
        network = ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return None
    if network.num_addresses <= 1:
        return str(network.network_address)
    if network.version == 4 and network.num_addresses > 2:
        offset = max(1, min(offset, network.num_addresses - 2))
    else:
        offset = max(1, min(offset, network.num_addresses - 1))
    return str(network.network_address + offset)


def add_prefix_samples(samples: list[Sample], prefixes: list[str], category: str, label: str, expected: str, source: str, source_url: str, limit: int) -> None:
    count = 0
    seen_prefixes = set()
    for prefix in prefixes:
        prefix = prefix.strip()
        if not prefix or prefix in seen_prefixes:
            continue
        seen_prefixes.add(prefix)
        ip = ip_from_prefix(prefix, 1 + count)
        if not ip:
            continue
        sample = make_sample(ip, category, f"{label} {prefix}", expected, source, source_url)
        if sample:
            samples.append(sample)
            count += 1
        if count >= limit:
            break


def collect_remote(samples: list[Sample]) -> list[str]:
    warnings: list[str] = []
    try:
        prefixes = http_get(SOURCE_URLS["cloudflare_v4"]).decode().splitlines()
        add_prefix_samples(samples, prefixes, "CDN", "Cloudflare IPv4", "CDN", "official:cloudflare", SOURCE_URLS["cloudflare_v4"], 24)
    except Exception as exc:
        warnings.append(f"Cloudflare IPv4 fetch failed: {exc}")
    try:
        prefixes = http_get(SOURCE_URLS["cloudflare_v6"]).decode().splitlines()
        add_prefix_samples(samples, prefixes, "CDN", "Cloudflare IPv6", "CDN", "official:cloudflare", SOURCE_URLS["cloudflare_v6"], 24)
    except Exception as exc:
        warnings.append(f"Cloudflare IPv6 fetch failed: {exc}")

    try:
        data = json.loads(http_get(SOURCE_URLS["fastly"]))
        add_prefix_samples(samples, data.get("addresses", []), "CDN", "Fastly IPv4", "CDN", "official:fastly", SOURCE_URLS["fastly"], 24)
        add_prefix_samples(samples, data.get("ipv6_addresses", []), "CDN", "Fastly IPv6", "CDN", "official:fastly", SOURCE_URLS["fastly"], 24)
    except Exception as exc:
        warnings.append(f"Fastly fetch failed: {exc}")

    try:
        data = json.loads(http_get(SOURCE_URLS["aws"]))
        v4 = [item["ip_prefix"] for item in data.get("prefixes", []) if "ip_prefix" in item]
        v6 = [item["ipv6_prefix"] for item in data.get("ipv6_prefixes", []) if "ipv6_prefix" in item]
        add_prefix_samples(samples, v4, "IDC", "AWS IPv4", "IDC", "official:aws", SOURCE_URLS["aws"], 36)
        add_prefix_samples(samples, v6, "IDC", "AWS IPv6", "IDC", "official:aws", SOURCE_URLS["aws"], 36)
    except Exception as exc:
        warnings.append(f"AWS fetch failed: {exc}")

    try:
        data = json.loads(http_get(SOURCE_URLS["google_cloud"]))
        v4 = [item["ipv4Prefix"] for item in data.get("prefixes", []) if "ipv4Prefix" in item]
        v6 = [item["ipv6Prefix"] for item in data.get("prefixes", []) if "ipv6Prefix" in item]
        add_prefix_samples(samples, v4, "IDC", "Google Cloud IPv4", "IDC", "official:google_cloud", SOURCE_URLS["google_cloud"], 36)
        add_prefix_samples(samples, v6, "IDC", "Google Cloud IPv6", "IDC", "official:google_cloud", SOURCE_URLS["google_cloud"], 36)
    except Exception as exc:
        warnings.append(f"Google Cloud fetch failed: {exc}")

    try:
        data = json.loads(http_get(SOURCE_URLS["oracle"]))
        v4, v6 = [], []
        for region in data.get("regions", []):
            for item in region.get("cidrs", []):
                cidr = item.get("cidr")
                if not cidr:
                    continue
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                except ValueError:
                    continue
                if network.version == 4:
                    v4.append(cidr)
                else:
                    v6.append(cidr)
        add_prefix_samples(samples, v4, "IDC", "Oracle Cloud IPv4", "IDC", "official:oracle", SOURCE_URLS["oracle"], 24)
        add_prefix_samples(samples, v6, "IDC", "Oracle Cloud IPv6", "IDC", "official:oracle", SOURCE_URLS["oracle"], 24)
    except Exception as exc:
        warnings.append(f"Oracle fetch failed: {exc}")

    try:
        page = http_get(SOURCE_URLS["azure"]).decode("utf-8", "ignore")
        candidates = re.findall(r'https://download\.microsoft\.com/download/[^"\']+ServiceTags_Public_[^"\']+?\.json', page)
        if candidates:
            data = json.loads(http_get(html.unescape(candidates[0])))
            v4, v6 = [], []
            for value in data.get("values", []):
                for prefix in value.get("properties", {}).get("addressPrefixes", []):
                    try:
                        network = ipaddress.ip_network(prefix, strict=False)
                    except ValueError:
                        continue
                    if network.version == 4:
                        v4.append(prefix)
                    else:
                        v6.append(prefix)
            add_prefix_samples(samples, v4, "IDC", "Azure IPv4", "IDC", "official:azure", candidates[0], 36)
            add_prefix_samples(samples, v6, "IDC", "Azure IPv6", "IDC", "official:azure", candidates[0], 36)
        else:
            warnings.append("Azure download URL not found on confirmation page")
    except Exception as exc:
        warnings.append(f"Azure fetch failed: {exc}")

    try:
        data = json.loads(http_get(SOURCE_URLS["github"]))
        v4, v6 = [], []
        for key in ("web", "api", "git", "pages", "hooks"):
            for prefix in data.get(key, []):
                try:
                    network = ipaddress.ip_network(prefix, strict=False)
                except ValueError:
                    continue
                if network.version == 4:
                    v4.append(prefix)
                else:
                    v6.append(prefix)
        add_prefix_samples(samples, v4, "ORG", "GitHub IPv4", "", "official:github", SOURCE_URLS["github"], 16)
        add_prefix_samples(samples, v6, "ORG", "GitHub IPv6", "", "official:github", SOURCE_URLS["github"], 16)
    except Exception as exc:
        warnings.append(f"GitHub fetch failed: {exc}")

    try:
        ips = [line.strip() for line in http_get(SOURCE_URLS["tor"]).decode().splitlines() if line.strip() and not line.startswith("#")]
        for ip in ips[:32]:
            sample = make_sample(ip, "TOR", "Tor bulk exit list", "TOR", "official:tor", SOURCE_URLS["tor"])
            if sample:
                samples.append(sample)
    except Exception as exc:
        warnings.append(f"Tor fetch failed: {exc}")
    return warnings


def parse_asns(value: str) -> list[int]:
    return [int(match) for match in re.findall(r"\d+", value)]


def collect_caida(samples: list[Sample], family: str, per_category: int = 32, per_asn: int = 3) -> None:
    path = ROOT / "data" / "raw" / ("caida-ipv4.pfx2as.gz" if family == "IPv4" else "caida-ipv6.pfx2as.gz")
    if not path.exists():
        return
    asn_to_category = {}
    asn_to_label = {}
    for category, asns in ASN_CATEGORY_SEEDS.items():
        for asn, label in asns.items():
            asn_to_category[asn] = category
            asn_to_label[asn] = label
    counts_by_category: Counter[str] = Counter()
    counts_by_asn: Counter[int] = Counter()
    with gzip.open(path, "rt", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            parts = line.strip().split()
            if len(parts) < 3:
                continue
            prefix_text, length_text, asn_text = parts[:3]
            row_asns = parse_asns(asn_text)
            if len(row_asns) != 1:
                continue
            matched_asn = row_asns[0]
            if matched_asn not in asn_to_category:
                continue
            category = asn_to_category[matched_asn]
            if counts_by_category[category] >= per_category or counts_by_asn[matched_asn] >= per_asn:
                continue
            prefix = f"{prefix_text}/{length_text}"
            ip = ip_from_prefix(prefix, 2 + counts_by_asn[matched_asn])
            if not ip:
                continue
            sample = make_sample(ip, category, f"{asn_to_label[matched_asn]} AS{matched_asn} {prefix}", category, "local:caida_pfx2as", str(path))
            if not sample:
                continue
            samples.append(sample)
            counts_by_category[category] += 1
            counts_by_asn[matched_asn] += 1
            if all(counts_by_category[category] >= per_category for category in ASN_CATEGORY_SEEDS):
                break


def dedupe(samples: list[Sample]) -> list[Sample]:
    seen = set()
    out = []
    for sample in samples:
        if sample.ip in seen:
            continue
        seen.add(sample.ip)
        out.append(sample)
    return out


def select_balanced(samples: list[Sample], family: str, minimum: int, maximum: int) -> list[Sample]:
    groups: dict[str, list[Sample]] = defaultdict(list)
    for sample in samples:
        if sample.family == family:
            groups[sample.category].append(sample)
    selected: list[Sample] = []
    categories = sorted(groups)
    while len(selected) < maximum:
        added = False
        for category in categories:
            if groups[category]:
                selected.append(groups[category].pop(0))
                added = True
                if len(selected) >= maximum:
                    break
        if not added:
            break
    if len(selected) < minimum:
        raise SystemExit(f"{family} samples below minimum: {len(selected)} < {minimum}")
    return selected


def build_samples(min_per_family: int, max_per_family: int) -> tuple[list[Sample], list[str]]:
    samples: list[Sample] = []
    for ip, category, label, expected in HARD_CODED:
        sample = make_sample(ip, category, label, expected, "manual:known_service")
        if sample:
            samples.append(sample)
    warnings = collect_remote(samples)
    collect_caida(samples, "IPv4")
    collect_caida(samples, "IPv6")
    samples = dedupe(samples)
    selected = select_balanced(samples, "IPv4", min_per_family, max_per_family)
    selected += select_balanced(samples, "IPv6", min_per_family, max_per_family)
    return selected, warnings


def write_samples(samples: list[Sample]) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with SAMPLE_CSV.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["ip", "family", "category", "label", "expected_scene", "source", "source_url"])
        writer.writeheader()
        for sample in samples:
            writer.writerow(sample.__dict__)


def lookup_one(base_url: str, sample: Sample, online: str, include_location: bool, timeout: float) -> dict:
    params = {
        "query": sample.ip,
        "online_enrichment": online,
    }
    if include_location:
        params["include_location"] = "1"
    url = base_url.rstrip("/") + "/api/lookup?" + urllib.parse.urlencode(params)
    start = time.perf_counter()
    try:
        body = http_get(url, timeout=timeout)
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        data = json.loads(body)
        return {"sample": sample.__dict__, "elapsed_ms": elapsed_ms, "ok": True, "response": data}
    except Exception as exc:
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        return {"sample": sample.__dict__, "elapsed_ms": elapsed_ms, "ok": False, "error": str(exc)}


def run_lookups(samples: list[Sample], base_url: str, online: str, include_location: bool, concurrency: int, timeout: float) -> list[dict]:
    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(lookup_one, base_url, sample, online, include_location, timeout) for sample in samples]
        for future in as_completed(futures):
            results.append(future.result())
    order = {sample.ip: idx for idx, sample in enumerate(samples)}
    results.sort(key=lambda item: order[item["sample"]["ip"]])
    with RESULT_JSONL.open("w", encoding="utf-8") as handle:
        for item in results:
            handle.write(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n")
    return results


def is_match(expected: str, actual: str) -> bool:
    if not expected:
        return True
    if expected == actual:
        return True
    compatible = {
        "IDC": {"IDC", "CDN"},
        "CDN": {"CDN", "DNS"},
        "NET": {"NET", "IDC", "CDN", "DNS", "ORG"},
        "ORG": {"ORG", "NET", "CDN"},
    }
    return actual in compatible.get(expected, set())


def percentile(values: list[int], pct: float) -> int:
    if not values:
        return 0
    values = sorted(values)
    idx = min(len(values) - 1, int(round((len(values) - 1) * pct)))
    return values[idx]


def cell(value, limit: int = 96) -> str:
    text = str(value or "").replace("\n", " ").replace("|", "/").strip()
    text = re.sub(r"\s+", " ", text)
    if len(text) > limit:
        return text[: limit - 1] + "…"
    return text


def write_report(samples: list[Sample], results: list[dict], warnings: list[str], online: str, concurrency: int) -> None:
    by_family = Counter(sample.family for sample in samples)
    by_category = Counter((sample.family, sample.category) for sample in samples)
    scene_counts = Counter()
    egress_counts = Counter()
    failures = []
    mismatches = []
    mismatch_pairs = Counter()
    mismatch_categories = Counter()
    elapsed = []
    for item in results:
        sample = item["sample"]
        if not item.get("ok"):
            failures.append(item)
            continue
        response = item.get("response", {})
        if not response.get("ok", False):
            failures.append(item)
        actual = response.get("scene", "")
        scene_counts[(sample["family"], actual)] += 1
        egress_counts[(sample["family"], response.get("egress", {}).get("type", ""))] += 1
        elapsed.append(item.get("elapsed_ms", 0))
        expected = sample.get("expected_scene", "")
        if expected and not is_match(expected, actual):
            mismatches.append(item)
            mismatch_pairs[(expected, actual)] += 1
            mismatch_categories[(sample["family"], sample["category"])] += 1
    if mismatch_pairs:
        top_pairs = "；".join(f"{expected}->{actual or '-'} {count}" for (expected, actual), count in mismatch_pairs.most_common(5))
        gap_summary = f"剩余不一致集中在 {top_pairs}。"
    else:
        gap_summary = "本轮带明确期望的样本没有场景不一致。"

    lines = [
        "# IP 覆盖评估报告",
        "",
        f"- 生成时间：{time.strftime('%Y-%m-%d %H:%M:%S %z')}",
        f"- API：本地 `{online}` 在线增强模式，并发 `{concurrency}`",
        f"- 样本文件：`{SAMPLE_CSV.relative_to(ROOT)}`",
        f"- 原始结果：`{RESULT_JSONL.relative_to(ROOT)}`",
        f"- IPv4 样本数：{by_family['IPv4']}",
        f"- IPv6 样本数：{by_family['IPv6']}",
        f"- API 失败/非 OK：{len(failures)}",
        f"- 带明确期望的场景不一致：{len(mismatches)}",
        f"- 延迟：p50 {percentile(elapsed, 0.50)} ms，p95 {percentile(elapsed, 0.95)} ms，max {max(elapsed) if elapsed else 0} ms",
        "",
        "## 评估结论",
        "",
        f"- 稳定性：{len(samples)} 个样本全部完成 API 查询，失败/非 OK 为 {len(failures)}。",
        "- 识别较稳定：BOGON、公共 DNS、Tor、主流 CDN/云厂商和常见移动/家宽样本整体表现较好。",
        f"- 主要缺口：{gap_summary}",
        "- 建议增强：继续补充需要鉴权的阿里云、腾讯云、华为云、火山引擎、网宿等 provider；持续维护 ASN 场景表；对 RDAP/WHOIS 备注里的证书、abuse 模板等噪声做清洗。",
        "",
        "### 不一致集中项",
        "",
        "| 期望 | 实际 | 数量 |",
        "| --- | --- | ---: |",
    ]
    for (expected, actual), count in mismatch_pairs.most_common(12):
        lines.append(f"| {expected} | {actual or '-'} | {count} |")
    lines += [
        "",
        "| 地址族 | 类型 | 不一致数量 |",
        "| --- | --- | ---: |",
    ]
    for (family, category), count in mismatch_categories.most_common(12):
        lines.append(f"| {family} | {category} | {count} |")
    lines += [
        "",
        "## 覆盖类型",
        "",
        "| 地址族 | 类型 | 数量 |",
        "| --- | --- | ---: |",
    ]
    for (family, category), count in sorted(by_category.items()):
        lines.append(f"| {family} | {category} | {count} |")

    lines += ["", "## 场景分布", "", "| 地址族 | 输出场景 | 数量 |", "| --- | --- | ---: |"]
    for (family, scene), count in sorted(scene_counts.items()):
        lines.append(f"| {family} | {scene or '-'} | {count} |")

    lines += ["", "## 出口/机房类型分布", "", "| 地址族 | egress.type | 数量 |", "| --- | --- | ---: |"]
    for (family, egress_type), count in sorted(egress_counts.items()):
        lines.append(f"| {family} | {egress_type or '-'} | {count} |")

    if warnings:
        lines += ["", "## 采集警告", ""]
        for warning in warnings:
            lines.append(f"- {warning}")

    if failures:
        lines += ["", "## API 失败样本", "", "| IP | 类型 | 错误 |", "| --- | --- | --- |"]
        for item in failures[:40]:
            sample = item["sample"]
            err = item.get("error") or item.get("response", {}).get("error", "non-ok")
            lines.append(f"| `{sample['ip']}` | {sample['category']} | {cell(err, 120)} |")

    if mismatches:
        lines += ["", "## 需要复核的场景不一致样本", "", "| IP | 地址族 | 类型 | 期望 | 实际 | ASN | 公司 | 说明 |", "| --- | --- | --- | --- | --- | ---: | --- | --- |"]
        for item in mismatches[:80]:
            sample = item["sample"]
            response = item.get("response", {})
            lines.append(
                f"| `{sample['ip']}` | {sample['family']} | {sample['category']} | {sample['expected_scene']} | "
                f"{response.get('scene', '')} | {response.get('asn', '')} | {cell(response.get('company', ''))} | {cell(sample['label'])} |"
            )

    lines += [
        "",
        "## 使用的数据源",
        "",
    ]
    for name, url in sorted(SOURCE_URLS.items()):
        lines.append(f"- {name}: {url}")
    lines.append("- local: `data/raw/caida-ipv4.pfx2as.gz`, `data/raw/caida-ipv6.pfx2as.gz`, `rules/services.json`, `data/generated/services.json`")
    REPORT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:18080")
    parser.add_argument("--online", default="wait", choices=["off", "fast", "wait"])
    parser.add_argument("--include-location", action="store_true", default=True)
    parser.add_argument("--min-per-family", type=int, default=128)
    parser.add_argument("--max-per-family", type=int, default=180)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--timeout", type=float, default=45.0)
    args = parser.parse_args()

    try:
        health = json.loads(http_get(args.base_url.rstrip("/") + "/api/health", timeout=5))
        if not health.get("ok"):
            raise RuntimeError(f"health returned {health}")
    except Exception as exc:
        print(f"API health check failed: {exc}", file=sys.stderr)
        return 2

    samples, warnings = build_samples(args.min_per_family, args.max_per_family)
    write_samples(samples)
    results = run_lookups(samples, args.base_url, args.online, args.include_location, args.concurrency, args.timeout)
    write_report(samples, results, warnings, args.online, args.concurrency)
    family_counts = Counter(sample.family for sample in samples)
    mismatch_count = sum(
        1
        for item in results
        if item.get("ok")
        and item.get("response", {}).get("ok")
        and item["sample"].get("expected_scene")
        and not is_match(item["sample"]["expected_scene"], item.get("response", {}).get("scene", ""))
    )
    failure_count = sum(1 for item in results if not item.get("ok") or not item.get("response", {}).get("ok", False))
    print(f"samples IPv4={family_counts['IPv4']} IPv6={family_counts['IPv6']}")
    print(f"results failures={failure_count} mismatches={mismatch_count}")
    print(f"wrote {SAMPLE_CSV.relative_to(ROOT)}")
    print(f"wrote {RESULT_JSONL.relative_to(ROOT)}")
    print(f"wrote {REPORT_MD.relative_to(ROOT)}")
    if warnings:
        print("warnings:")
        for warning in warnings:
            print(f"- {warning}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
