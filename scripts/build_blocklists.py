#!/usr/bin/env python3
"""
Daily dump builder for country CIDR + open threat-intel IP feeds.

Generated outputs:
  output/source-manifest.json
  output/country-blocklist-ipv4.txt
  output/country-blocklist-ipv6.txt
  output/threatfeed-ips.txt
  output/threat-domains.txt
  output/threat-urls.txt
  output/combined-ipv4.txt
  output/combined-ipv6.txt
  output/ipset.restore
  output/nftables-blocklist.nft
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
import re
import sys
import urllib.request
from urllib.parse import urlparse
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output"
OUT.mkdir(exist_ok=True)

CONFIG = json.loads((ROOT / "config.json").read_text())


def fetch(url: str, timeout: int) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "custom-threatfeed-daily-dump/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")


def strip_comment(line: str) -> str:
    return re.split(r"\s*[;#]\s*", line.strip(), maxsplit=1)[0].strip()


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


def parse_domains_and_urls(text: str):
    domains, urls = set(), set()
    for raw in text.splitlines():
        line = strip_comment(raw)
        if not line:
            continue
        for m in URL_RE.finditer(line):
            u = m.group(0).strip().rstrip(").,;")
            parsed = urlparse(u)
            if parsed.scheme in {"http", "https"} and parsed.netloc:
                urls.add(u)
                host = parsed.hostname.lower() if parsed.hostname else None
                if host and not host.replace(".", "").isdigit():
                    domains.add(host)
        for m in DOMAIN_RE.finditer(line):
            d = m.group(0).lower()
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", d):
                continue
            domains.add(d)
    return domains, urls


def collapse(nets: Iterable[ipaddress._BaseNetwork]):
    return list(ipaddress.collapse_addresses(nets))


def write_list(path: Path, nets: Iterable[ipaddress._BaseNetwork]) -> None:
    collapsed = collapse(nets)
    path.write_text("\n".join(str(n) for n in collapsed) + ("\n" if collapsed else ""))


def read_urls(path: Path) -> list[str]:
    urls = []
    for line in path.read_text().splitlines():
        line = strip_comment(line)
        if line.startswith("http"):
            urls.append(line)
    return urls


def country_urls():
    v4_t = CONFIG["ipv4_country_url_template"]
    v6_t = CONFIG["ipv6_country_url_template"]
    codes = list(CONFIG["countries"].keys())
    return [v4_t.format(cc=cc) for cc in codes], [v6_t.format(cc=cc) for cc in codes]


def build(timeout: int = 90) -> int:
    manifest = {
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "mode": CONFIG.get("mode", "dump_everything"),
        "countries": CONFIG["countries"],
        "sources": [],
        "stats": {},
    }

    country_v4, country_v6 = set(), set()
    cv4_urls, cv6_urls = country_urls()
    for category, urls in [("country_ipv4", cv4_urls), ("country_ipv6", cv6_urls)]:
        for url in urls:
            print(f"Fetching {category}: {url}", file=sys.stderr)
            entry = {"category": category, "url": url, "ok": False, "ipv4": 0, "ipv6": 0}
            try:
                text = fetch(url, timeout=timeout)
                a, b = parse_ip_or_networks(text)
                country_v4 |= a
                country_v6 |= b
                entry.update({"ok": True, "ipv4": len(a), "ipv6": len(b)})
            except Exception as e:
                entry["error"] = str(e)
                print(f"WARN failed {url}: {e}", file=sys.stderr)
            manifest["sources"].append(entry)

    threat_v4, threat_v6 = set(), set()
    threat_domains, threat_urls = set(), set()
    for url in read_urls(ROOT / "feeds" / "threat-ip-feeds.txt"):
        print(f"Fetching threat: {url}", file=sys.stderr)
        entry = {"category": "threat_ip", "url": url, "ok": False, "ipv4": 0, "ipv6": 0, "domains": 0, "urls": 0}
        try:
            text = fetch(url, timeout=timeout)
            a, b = parse_ip_or_networks(text)
            d, u = parse_domains_and_urls(text)
            threat_v4 |= a
            threat_v6 |= b
            threat_domains |= d
            threat_urls |= u
            entry.update({"ok": True, "ipv4": len(a), "ipv6": len(b), "domains": len(d), "urls": len(u)})
        except Exception as e:
            entry["error"] = str(e)
            print(f"WARN failed {url}: {e}", file=sys.stderr)
        manifest["sources"].append(entry)

    for url in read_urls(ROOT / "feeds" / "threat-domain-feeds.txt"):
        print(f"Fetching threat-domain: {url}", file=sys.stderr)
        entry = {"category": "threat_domain", "url": url, "ok": False, "ipv4": 0, "ipv6": 0, "domains": 0, "urls": 0}
        try:
            text = fetch(url, timeout=timeout)
            a, b = parse_ip_or_networks(text)
            d, u = parse_domains_and_urls(text)
            threat_v4 |= a
            threat_v6 |= b
            threat_domains |= d
            threat_urls |= u
            entry.update({"ok": True, "ipv4": len(a), "ipv6": len(b), "domains": len(d), "urls": len(u)})
        except Exception as e:
            entry["error"] = str(e)
            print(f"WARN failed {url}: {e}", file=sys.stderr)
        manifest["sources"].append(entry)

    for url in read_urls(ROOT / "feeds" / "threat-url-feeds.txt"):
        print(f"Fetching threat-url: {url}", file=sys.stderr)
        entry = {"category": "threat_url", "url": url, "ok": False, "ipv4": 0, "ipv6": 0, "domains": 0, "urls": 0}
        try:
            text = fetch(url, timeout=timeout)
            a, b = parse_ip_or_networks(text)
            d, u = parse_domains_and_urls(text)
            threat_v4 |= a
            threat_v6 |= b
            threat_domains |= d
            threat_urls |= u
            entry.update({"ok": True, "ipv4": len(a), "ipv6": len(b), "domains": len(d), "urls": len(u)})
        except Exception as e:
            entry["error"] = str(e)
            print(f"WARN failed {url}: {e}", file=sys.stderr)
        manifest["sources"].append(entry)

    combined_v4 = country_v4 | threat_v4
    combined_v6 = country_v6 | threat_v6

    write_list(OUT / "country-blocklist-ipv4.txt", country_v4)
    write_list(OUT / "country-blocklist-ipv6.txt", country_v6)
    write_list(OUT / "threatfeed-ips.txt", list(threat_v4) + list(threat_v6))
    (OUT / "threat-domains.txt").write_text("\n".join(sorted(threat_domains)) + ("\n" if threat_domains else ""))
    (OUT / "threat-urls.txt").write_text("\n".join(sorted(threat_urls)) + ("\n" if threat_urls else ""))
    write_list(OUT / "combined-ipv4.txt", combined_v4)
    write_list(OUT / "combined-ipv6.txt", combined_v6)

    v4c = collapse(combined_v4)
    v6c = collapse(combined_v6)

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
    timeout = 90
    if len(sys.argv) == 3 and sys.argv[1] == "--timeout":
        timeout = int(sys.argv[2])
    raise SystemExit(build(timeout=timeout))
