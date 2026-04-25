#!/usr/bin/env python3
"""
Daily dump builder for country CIDR, open threat-intel feeds, DNS/URL feeds,
and advisory context.

Generated outputs:
  output/source-manifest.json
  output/scored-indicators.json
  output/scored-indicators.jsonl
  output/feed-reputation.json
  output/country-blocklist-ipv4.txt
  output/country-blocklist-ipv6.txt
  output/threatfeed-ips.txt
  output/threat-domains.txt
  output/threat-urls.txt
  output/privacy-domains.txt
  output/dns-blocklist.txt
  output/high-confidence-ipv4.txt
  output/high-confidence-ipv6.txt
  output/high-confidence-domains.txt
  output/high-confidence-urls.txt
  output/advisory-context.json
  output/combined-ipv4.txt
  output/combined-ipv6.txt
  output/ipset.restore
  output/nftables-blocklist.nft
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
OUT.mkdir(exist_ok=True)

CONFIG = json.loads((ROOT / "config.json").read_text())
HIGH_CONFIDENCE_THRESHOLD = int(CONFIG.get("high_confidence_threshold", 75))

SOURCE_CATALOG = [
    {
        "match": "spamhaus.org/drop",
        "name": "Spamhaus DROP",
        "kind": "abuse",
        "reputation_score": 0.95,
        "confidence": 95,
        "ttl_hours": 24,
        "cadence": "daily",
        "justification": "Spamhaus advisory drop-all-traffic netblocks for highly dangerous networks.",
    },
    {
        "match": "feodotracker.abuse.ch",
        "name": "abuse.ch Feodo Tracker",
        "kind": "abuse",
        "reputation_score": 0.90,
        "confidence": 90,
        "ttl_hours": 24,
        "cadence": "fast",
        "justification": "Botnet C2 infrastructure observed by abuse.ch Feodo Tracker.",
    },
    {
        "match": "urlhaus.abuse.ch",
        "name": "abuse.ch URLhaus",
        "kind": "abuse",
        "reputation_score": 0.88,
        "confidence": 88,
        "ttl_hours": 24,
        "cadence": "daily",
        "justification": "Malware distribution URLs and hosts from abuse.ch URLhaus.",
    },
    {
        "match": "threathive.net",
        "name": "ThreatHive",
        "kind": "abuse",
        "reputation_score": 0.78,
        "confidence": 78,
        "ttl_hours": 24,
        "cadence": "fast",
        "justification": "Open-source intelligence and honeypot telemetry malicious IP blocklist.",
    },
    {
        "match": "dshield.org",
        "name": "DShield",
        "kind": "abuse",
        "reputation_score": 0.75,
        "confidence": 75,
        "ttl_hours": 24,
        "cadence": "hourly",
        "justification": "Internet Storm Center/DShield attack telemetry.",
    },
    {
        "match": "rules.emergingthreats.net",
        "name": "Emerging Threats compromised IPs",
        "kind": "abuse",
        "reputation_score": 0.72,
        "confidence": 72,
        "ttl_hours": 48,
        "cadence": "daily",
        "justification": "Compromised IP feed used for network threat detection and blocking.",
    },
    {
        "match": "lists.blocklist.de",
        "name": "Blocklist.de",
        "kind": "abuse",
        "reputation_score": 0.60,
        "confidence": 60,
        "ttl_hours": 48,
        "cadence": "community",
        "justification": "Community attack reports from servers and fail2ban-style telemetry.",
    },
    {
        "match": "easyprivacy.txt",
        "name": "EasyPrivacy",
        "kind": "privacy",
        "reputation_score": 0.70,
        "confidence": 70,
        "ttl_hours": 168,
        "cadence": "weekly",
        "justification": "Tracking, web bug, and information-collector domain filtering.",
    },
    {
        "match": "StevenBlack/hosts",
        "name": "StevenBlack hosts",
        "kind": "privacy",
        "reputation_score": 0.68,
        "confidence": 68,
        "ttl_hours": 168,
        "cadence": "weekly",
        "justification": "Curated hosts aggregation for adware, malware, and tracking domains.",
    },
    {
        "match": "HostlistsRegistry/assets/filter_1.txt",
        "name": "AdGuard DNS filter",
        "kind": "privacy",
        "reputation_score": 0.68,
        "confidence": 68,
        "ttl_hours": 168,
        "cadence": "weekly",
        "justification": "DNS-level privacy and ad/tracker blocking filter.",
    },
    {
        "match": "cisa.gov",
        "name": "CISA advisory context",
        "kind": "context",
        "reputation_score": 0.80,
        "confidence": 0,
        "ttl_hours": 24,
        "cadence": "daily",
        "justification": "Official vulnerability and advisory context; never direct block evidence.",
    },
]

DEFAULT_SOURCE = {
    "name": "Uncataloged feed",
    "kind": "abuse",
    "reputation_score": 0.50,
    "confidence": 50,
    "ttl_hours": 24,
    "cadence": "daily",
    "justification": "Uncataloged open-source feed; use only with corroboration or manual review.",
}


def fetch(url: str, timeout: int) -> str:
    parsed = urlparse(url)
    if parsed.scheme in {"", "file"}:
        if parsed.scheme == "file":
            local_path = Path(parsed.path)
        else:
            local_path = ROOT / url
        return local_path.read_text(encoding="utf-8", errors="replace")
    req = urllib.request.Request(url, headers={"User-Agent": "custom-threatfeed-daily-dump/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def strip_comment(line: str) -> str:
    stripped = line.strip()
    if not stripped or stripped.startswith(("!", "[", "//")):
        return ""
    return re.split(r"\s*[;#]\s*", stripped, maxsplit=1)[0].strip()


def parse_ip_or_networks(text: str):
    v4, v6 = set(), set()
    for raw in text.splitlines():
        line = strip_comment(raw)
        if not line:
            continue
        m = re.search(r"([0-9a-fA-F:.]+(?:/\d{1,3})?)", line)
        if not m:
            continue
        token = m.group(1)
        try:
            if "/" in token:
                net = ipaddress.ip_network(token, strict=False)
            else:
                ip = ipaddress.ip_address(token)
                net = ipaddress.ip_network(f"{ip}/32" if ip.version == 4 else f"{ip}/128", strict=False)
            (v4 if net.version == 4 else v6).add(net)
        except ValueError:
            continue
    return v4, v6


DOMAIN_RE = re.compile(
    r"(?<![A-Za-z0-9-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![A-Za-z0-9-])"
)
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
YARA_STRING_RE = re.compile(r'"((?:\\.|[^"\\])*)"|\'((?:\\.|[^\'\\])*)\'')


def refang(text: str) -> str:
    return (
        text.replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
        .replace("[.]", ".")
        .replace("(.)", ".")
        .replace("[:]", ":")
    )


def is_domain_candidate(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return False
    except ValueError:
        return "." in value and not value.startswith(".") and not value.endswith(".")


def parse_domains_and_urls(text: str):
    domains, urls = set(), set()
    for raw in text.splitlines():
        line = refang(strip_comment(raw))
        if not line:
            continue
        if line.startswith(("@@", "127.0.0.1", "0.0.0.0", "::1")):
            parts = line.split()
            if len(parts) >= 2:
                line = " ".join(parts[1:])
        url_matches = list(URL_RE.finditer(line))
        for m in url_matches:
            u = m.group(0).strip().rstrip(").,;")
            parsed = urlparse(u)
            if parsed.scheme in {"http", "https"} and parsed.netloc:
                urls.add(u)
                host = parsed.hostname.lower() if parsed.hostname else None
                if host and is_domain_candidate(host):
                    domains.add(host)
        domain_scan = URL_RE.sub(" ", line)
        for m in DOMAIN_RE.finditer(domain_scan):
            d = m.group(0).lower()
            if is_domain_candidate(d):
                domains.add(d)
    return domains, urls


def parse_yara_network_iocs(text: str):
    quoted = []
    for match in YARA_STRING_RE.finditer(text):
        value = match.group(1) if match.group(1) is not None else match.group(2)
        if value:
            quoted.append(value.encode("utf-8", errors="ignore").decode("unicode_escape", errors="ignore"))
    corpus = "\n".join(quoted)
    v4, v6 = parse_ip_or_networks(corpus)
    domains, urls = parse_domains_and_urls(corpus)
    return v4, v6, domains, urls


def collapse(nets: Iterable[ipaddress._BaseNetwork]):
    return list(ipaddress.collapse_addresses(nets))


def write_list(path: Path, nets: Iterable[ipaddress._BaseNetwork]) -> None:
    collapsed = collapse(nets)
    path.write_text("\n".join(str(n) for n in collapsed) + ("\n" if collapsed else ""))


def write_mixed_ip_list(path: Path, nets: Iterable[ipaddress._BaseNetwork]) -> None:
    v4 = [n for n in nets if n.version == 4]
    v6 = [n for n in nets if n.version == 6]
    collapsed = collapse(v4) + collapse(v6)
    path.write_text("\n".join(str(n) for n in collapsed) + ("\n" if collapsed else ""))


def write_lines(path: Path, values: Iterable[str]) -> None:
    lines = sorted(set(values))
    path.write_text("\n".join(lines) + ("\n" if lines else ""))


def read_urls(path: Path) -> list[str]:
    if not path.exists():
        return []
    urls = []
    for line in path.read_text().splitlines():
        line = strip_comment(line)
        if line:
            urls.append(line)
    return urls


def source_meta(url: str, category: str, override: dict[str, Any] | None = None) -> dict[str, Any]:
    meta = dict(DEFAULT_SOURCE)
    for candidate in SOURCE_CATALOG:
        if candidate["match"] in url:
            meta.update(candidate)
            break
    if override:
        meta.update(override)
    meta["url"] = url
    meta["category"] = category
    return meta


def country_meta(url: str, category: str, country: str) -> dict[str, Any]:
    return {
        "url": url,
        "category": category,
        "name": f"IPdeny {country}",
        "kind": "policy_country",
        "reputation_score": 0.55,
        "confidence": 55,
        "ttl_hours": 24,
        "cadence": "daily",
        "justification": f"Policy geo-block CIDR range for {country}; this is not standalone abuse evidence.",
    }


def add_indicator(
    records: dict[str, dict[str, Any]],
    indicator: str,
    indicator_type: str,
    meta: dict[str, Any],
    generated_at: str,
) -> None:
    record = records.setdefault(
        f"{indicator_type}:{indicator}",
        {
            "indicator": indicator,
            "type": indicator_type,
            "first_seen": generated_at,
            "last_seen": generated_at,
            "sources": [],
            "source_urls": [],
            "categories": [],
            "source_confidences": [],
            "reputation_scores": [],
            "ttl_hours": [],
            "kinds": [],
            "justifications": [],
        },
    )
    record["last_seen"] = generated_at
    if meta["name"] not in record["sources"]:
        record["sources"].append(meta["name"])
    if meta["url"] not in record["source_urls"]:
        record["source_urls"].append(meta["url"])
    if meta["category"] not in record["categories"]:
        record["categories"].append(meta["category"])
    if meta["kind"] not in record["kinds"]:
        record["kinds"].append(meta["kind"])
    if meta["justification"] not in record["justifications"]:
        record["justifications"].append(meta["justification"])
    record["source_confidences"].append(int(meta["confidence"]))
    record["reputation_scores"].append(float(meta["reputation_score"]))
    record["ttl_hours"].append(int(meta["ttl_hours"]))


def finalize_records(records: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    finalized = []
    for record in records.values():
        source_count = len(record["sources"])
        base_confidence = max(record["source_confidences"]) if record["source_confidences"] else 0
        corroboration_bonus = min(15, max(0, source_count - 1) * 5)
        confidence_score = min(100, base_confidence + corroboration_bonus)
        reputation_score = max(record["reputation_scores"]) if record["reputation_scores"] else 0.0
        enforcement = "abuse" if "abuse" in record["kinds"] else record["kinds"][0]
        ttl_hours = min(record["ttl_hours"]) if record["ttl_hours"] else 24
        finalized.append(
            {
                "indicator": record["indicator"],
                "type": record["type"],
                "sources": sorted(record["sources"]),
                "source_urls": sorted(record["source_urls"]),
                "categories": sorted(record["categories"]),
                "first_seen": record["first_seen"],
                "last_seen": record["last_seen"],
                "confidence_score": confidence_score,
                "reputation_score": round(reputation_score, 2),
                "source_count": source_count,
                "ttl_hours": ttl_hours,
                "enforcement": enforcement,
                "justification": " | ".join(sorted(record["justifications"])),
            }
        )
    return sorted(finalized, key=lambda r: (r["type"], r["indicator"]))


def write_scored_outputs(scored: list[dict[str, Any]]) -> None:
    publishable = [record for record in scored if record["enforcement"] != "privacy"]

    def compact(record: dict[str, Any]) -> dict[str, Any]:
        return {
            "indicator": record["indicator"],
            "type": record["type"],
            "confidence_score": record["confidence_score"],
            "reputation_score": record["reputation_score"],
            "source_count": record["source_count"],
            "sources": record["sources"],
            "ttl_hours": record["ttl_hours"],
            "enforcement": record["enforcement"],
        }

    compact_records = [compact(record) for record in publishable]
    (OUT / "scored-indicators.json").write_text(json.dumps(compact_records, separators=(",", ":")) + "\n")
    (OUT / "scored-indicators.jsonl").write_text(
        "".join(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n" for record in compact_records)
    )

    high = [
        record
        for record in scored
        if record["enforcement"] == "abuse" and record["confidence_score"] >= HIGH_CONFIDENCE_THRESHOLD
    ]
    high_v4 = [ipaddress.ip_network(r["indicator"], strict=False) for r in high if r["type"] == "ipv4"]
    high_v6 = [ipaddress.ip_network(r["indicator"], strict=False) for r in high if r["type"] == "ipv6"]
    write_list(OUT / "high-confidence-ipv4.txt", high_v4)
    write_list(OUT / "high-confidence-ipv6.txt", high_v6)
    write_lines(OUT / "high-confidence-domains.txt", (r["indicator"] for r in high if r["type"] == "domain"))
    write_lines(OUT / "high-confidence-urls.txt", (r["indicator"] for r in high if r["type"] == "url"))


def parse_advisory_payload(url: str, text: str) -> list[dict[str, Any]]:
    items = []
    if url.endswith(".json"):
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return items
        for vuln in payload.get("vulnerabilities", [])[:50]:
            summary = " ".join(
                str(vuln.get(k, "")) for k in ("cveID", "vendorProject", "product", "vulnerabilityName", "shortDescription")
            )
            domains, urls = parse_domains_and_urls(summary)
            items.append(
                {
                    "source_url": url,
                    "title": summary.strip(),
                    "link": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    "published": vuln.get("dateAdded"),
                    "domains": sorted(domains),
                    "urls": sorted(urls),
                    "blocking_policy": "context_only",
                }
            )
        return items

    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return items

    for item in root.findall(".//item")[:50]:
        title = item.findtext("title") or ""
        link = item.findtext("link") or ""
        published = item.findtext("pubDate") or item.findtext("published") or ""
        description = item.findtext("description") or ""
        domains, urls = parse_domains_and_urls(f"{title}\n{description}")
        items.append(
            {
                "source_url": url,
                "title": title.strip(),
                "link": link.strip(),
                "published": published.strip(),
                "domains": sorted(domains),
                "urls": sorted(urls),
                "blocking_policy": "context_only",
            }
        )
    return items


def country_urls():
    v4_t = CONFIG["ipv4_country_url_template"]
    v6_t = CONFIG["ipv6_country_url_template"]
    codes = list(CONFIG["countries"].keys())
    no_ipv6 = set(CONFIG.get("countries_without_ipv6", []))
    return [(cc, v4_t.format(cc=cc)) for cc in codes], [
        (cc, v6_t.format(cc=cc)) for cc in codes if cc not in no_ipv6
    ]


def build(timeout: int = 90) -> int:
    generated_at = dt.datetime.now(dt.timezone.utc).isoformat()
    manifest = {
        "generated_at_utc": generated_at,
        "mode": CONFIG.get("mode", "dump_everything"),
        "countries": CONFIG["countries"],
        "sources": [],
        "high_confidence_threshold": HIGH_CONFIDENCE_THRESHOLD,
        "stats": {},
    }

    records: dict[str, dict[str, Any]] = {}
    country_v4, country_v6 = set(), set()
    cv4_urls, cv6_urls = country_urls()
    for category, urls in [("country_ipv4", cv4_urls), ("country_ipv6", cv6_urls)]:
        for item in urls:
            if isinstance(item, tuple):
                cc, url = item
            else:
                cc, url = "custom", item
            country = CONFIG["countries"].get(cc, "custom country feed")
            meta = country_meta(url, category, country)
            print(f"Fetching {category}: {url}", file=sys.stderr)
            entry = {**meta, "ok": False, "ipv4": 0, "ipv6": 0, "domains": 0, "urls": 0}
            try:
                text = fetch(url, timeout=timeout)
                a, b = parse_ip_or_networks(text)
                country_v4 |= a
                country_v6 |= b
                for net in a:
                    add_indicator(records, str(net), "ipv4", meta, generated_at)
                for net in b:
                    add_indicator(records, str(net), "ipv6", meta, generated_at)
                entry.update({"ok": True, "ipv4": len(a), "ipv6": len(b)})
            except Exception as e:
                entry["error"] = str(e)
                print(f"WARN failed {url}: {e}", file=sys.stderr)
            manifest["sources"].append(entry)

    threat_v4, threat_v6 = set(), set()
    threat_domains, threat_urls = set(), set()
    privacy_domains = set()

    feed_files = [
        ("threat_ip", ROOT / "feeds" / "threat-ip-feeds.txt", False, False),
        ("threat_domain", ROOT / "feeds" / "threat-domain-feeds.txt", False, False),
        ("threat_url", ROOT / "feeds" / "threat-url-feeds.txt", False, False),
        ("privacy_domain", ROOT / "feeds" / "privacy-domain-feeds.txt", True, False),
        ("yara_network_ioc", ROOT / "feeds" / "yara-ioc-feeds.txt", False, True),
    ]
    for category, path, privacy_only, yara_only in feed_files:
        for url in read_urls(path):
            meta = source_meta(url, category)
            print(f"Fetching {category}: {url}", file=sys.stderr)
            entry = {**meta, "ok": False, "ipv4": 0, "ipv6": 0, "domains": 0, "urls": 0}
            try:
                text = fetch(url, timeout=timeout)
                if yara_only:
                    a, b, d, u = parse_yara_network_iocs(text)
                else:
                    a, b = parse_ip_or_networks(text)
                    d, u = parse_domains_and_urls(text)

                if privacy_only:
                    privacy_domains |= d
                else:
                    threat_v4 |= a
                    threat_v6 |= b
                    threat_domains |= d
                    threat_urls |= u

                for net in a:
                    add_indicator(records, str(net), "ipv4", meta, generated_at)
                for net in b:
                    add_indicator(records, str(net), "ipv6", meta, generated_at)
                for domain in d:
                    add_indicator(records, domain, "domain", meta, generated_at)
                for threat_url in u:
                    add_indicator(records, threat_url, "url", meta, generated_at)

                entry.update({"ok": True, "ipv4": len(a), "ipv6": len(b), "domains": len(d), "urls": len(u)})
            except Exception as e:
                entry["error"] = str(e)
                print(f"WARN failed {url}: {e}", file=sys.stderr)
            manifest["sources"].append(entry)

    advisory_items = []
    for url in read_urls(ROOT / "feeds" / "advisory-context-feeds.txt"):
        meta = source_meta(url, "advisory_context", {"kind": "context", "confidence": 0, "reputation_score": 0.75})
        print(f"Fetching advisory context: {url}", file=sys.stderr)
        entry = {**meta, "ok": False, "ipv4": 0, "ipv6": 0, "domains": 0, "urls": 0, "items": 0}
        try:
            text = fetch(url, timeout=timeout)
            parsed_items = parse_advisory_payload(url, text)
            advisory_items.extend(parsed_items)
            entry.update({"ok": True, "items": len(parsed_items)})
        except Exception as e:
            entry["error"] = str(e)
            print(f"WARN failed {url}: {e}", file=sys.stderr)
        manifest["sources"].append(entry)

    combined_v4 = country_v4 | threat_v4
    combined_v6 = country_v6 | threat_v6
    combined_domains = threat_domains | privacy_domains

    write_list(OUT / "country-blocklist-ipv4.txt", country_v4)
    write_list(OUT / "country-blocklist-ipv6.txt", country_v6)
    write_mixed_ip_list(OUT / "threatfeed-ips.txt", list(threat_v4) + list(threat_v6))
    write_lines(OUT / "threat-domains.txt", threat_domains)
    write_lines(OUT / "threat-urls.txt", threat_urls)
    write_lines(OUT / "privacy-domains.txt", privacy_domains)
    write_lines(OUT / "dns-blocklist.txt", combined_domains)
    write_list(OUT / "combined-ipv4.txt", combined_v4)
    write_list(OUT / "combined-ipv6.txt", combined_v6)

    v4c = collapse(combined_v4)
    v6c = collapse(combined_v6)
    scored = finalize_records(records)
    write_scored_outputs(scored)
    (OUT / "feed-reputation.json").write_text(json.dumps(SOURCE_CATALOG, indent=2) + "\n")
    (OUT / "advisory-context.json").write_text(json.dumps(advisory_items, indent=2) + "\n")

    ipset_lines = [
        "create custom_blocklist_v4 hash:net family inet hashsize 4096 maxelem 4000000 -exist",
        "flush custom_blocklist_v4",
    ]
    ipset_lines += [f"add custom_blocklist_v4 {n} -exist" for n in v4c]
    ipset_lines += [
        "create custom_blocklist_v6 hash:net family inet6 hashsize 4096 maxelem 4000000 -exist",
        "flush custom_blocklist_v6",
    ]
    ipset_lines += [f"add custom_blocklist_v6 {n} -exist" for n in v6c]
    (OUT / "ipset.restore").write_text("\n".join(ipset_lines) + "\n")

    nft_lines = [
        "table inet custom_blocklist {",
        "  set blocked_v4 {",
        "    type ipv4_addr;",
        "    flags interval;",
        "    elements = {",
        "      " + ",\n      ".join(str(n) for n in v4c),
        "    }",
        "  }",
        "  set blocked_v6 {",
        "    type ipv6_addr;",
        "    flags interval;",
        "    elements = {",
        "      " + ",\n      ".join(str(n) for n in v6c),
        "    }",
        "  }",
        "}",
    ]
    (OUT / "nftables-blocklist.nft").write_text("\n".join(nft_lines) + "\n")

    manifest["stats"] = {
        "country_ipv4_raw": len(country_v4),
        "country_ipv6_raw": len(country_v6),
        "threat_ipv4_raw": len(threat_v4),
        "threat_ipv6_raw": len(threat_v6),
        "threat_domains_raw": len(threat_domains),
        "threat_urls_raw": len(threat_urls),
        "privacy_domains_raw": len(privacy_domains),
        "dns_blocklist_raw": len(combined_domains),
        "scored_indicators": sum(1 for r in scored if r["enforcement"] != "privacy"),
        "privacy_indicators_unscored": sum(1 for r in scored if r["enforcement"] == "privacy"),
        "high_confidence_indicators": sum(
            1
            for r in scored
            if r["enforcement"] == "abuse" and r["confidence_score"] >= HIGH_CONFIDENCE_THRESHOLD
        ),
        "advisory_context_items": len(advisory_items),
        "combined_ipv4_collapsed": len(v4c),
        "combined_ipv6_collapsed": len(v6c),
        "sources_total": len(manifest["sources"]),
        "sources_ok": sum(1 for s in manifest["sources"] if s["ok"]),
        "sources_failed": sum(1 for s in manifest["sources"] if not s["ok"]),
    }
    (OUT / "source-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    print(json.dumps(manifest["stats"], indent=2))
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build AbuseBlacklist outputs")
    parser.add_argument("--timeout", type=int, default=90, help="per-source fetch timeout in seconds")
    args = parser.parse_args()
    raise SystemExit(build(timeout=args.timeout))
