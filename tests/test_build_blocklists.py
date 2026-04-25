import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from scripts import build_blocklists
from scripts.build_blocklists import parse_domains_and_urls, parse_ip_or_networks, parse_yara_network_iocs


class BuildBlocklistsParsingTests(unittest.TestCase):
    def test_parse_ip_or_networks_supports_ipv4_ipv6_and_host_ips(self):
        sample = "\n".join(
            [
                "1.2.3.4",
                "2.2.2.0/24",
                "2001:db8::1",
                "2001:db8:abcd::/48",
                "# comment line",
            ]
        )
        v4, v6 = parse_ip_or_networks(sample)
        self.assertIn("1.2.3.4/32", {str(n) for n in v4})
        self.assertIn("2.2.2.0/24", {str(n) for n in v4})
        self.assertIn("2001:db8::1/128", {str(n) for n in v6})
        self.assertIn("2001:db8:abcd::/48", {str(n) for n in v6})

    def test_parse_domains_and_urls_extracts_hosts_and_urls(self):
        sample = "\n".join(
            [
                "https://evil.example/path?x=1",
                "https://downloads.bad.example/payloads/000.exe",
                "domain-only.bad",
                "some text about cdn.good.example and junk",
                "127.0.0.1 should-not-be-domain",
            ]
        )
        domains, urls = parse_domains_and_urls(sample)
        self.assertIn("evil.example", domains)
        self.assertIn("domain-only.bad", domains)
        self.assertIn("cdn.good.example", domains)
        self.assertIn("downloads.bad.example", domains)
        self.assertNotIn("000.exe", domains)
        self.assertIn("https://evil.example/path?x=1", urls)

    def test_build_emits_domain_and_url_outputs_with_manifest_stats(self):
        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td) / "output"
            out_dir.mkdir(parents=True, exist_ok=True)

            feed_payloads = {
                "https://country-v4.example": "10.0.0.0/24\n",
                "https://country-v6.example": "2001:db8::/32\n",
                "https://threat-ip.example": "8.8.8.8\nhttps://c2.bad.example/path\n",
                "https://threat-domain.example": "domain-only.bad\n",
                "https://threat-url.example": "https://malware.bad/payload\n",
            }

            def fake_read_urls(path: Path):
                p = str(path)
                if p.endswith("threat-ip-feeds.txt"):
                    return ["https://threat-ip.example"]
                if p.endswith("threat-domain-feeds.txt"):
                    return ["https://threat-domain.example"]
                if p.endswith("threat-url-feeds.txt"):
                    return ["https://threat-url.example"]
                return []

            with patch.object(build_blocklists, "OUT", out_dir), patch.object(
                build_blocklists, "country_urls", return_value=(["https://country-v4.example"], ["https://country-v6.example"])
            ), patch.object(build_blocklists, "read_urls", side_effect=fake_read_urls), patch.object(
                build_blocklists, "fetch", side_effect=lambda url, timeout: feed_payloads[url]
            ):
                rc = build_blocklists.build(timeout=3)

            self.assertEqual(rc, 0)
            domains = (out_dir / "threat-domains.txt").read_text().splitlines()
            urls = (out_dir / "threat-urls.txt").read_text().splitlines()
            manifest = (out_dir / "source-manifest.json").read_text()

            self.assertIn("c2.bad.example", domains)
            self.assertIn("domain-only.bad", domains)
            self.assertIn("malware.bad", domains)
            self.assertIn("https://c2.bad.example/path", urls)
            self.assertIn("https://malware.bad/payload", urls)
            self.assertIn('"threat_domains_raw": 3', manifest)
            self.assertIn('"threat_urls_raw": 2', manifest)

    def test_yara_parser_extracts_only_network_iocs_from_quoted_strings(self):
        sample = r'''
rule sample {
  strings:
    $url = "hxxps://stage.bad.example/payload.bin"
    $ip = "203.0.113.44"
    $mutex = "Global\\UpdaterMutex"
    $hash = "0123456789abcdef0123456789abcdef"
  condition:
    any of them
}
'''
        v4, v6, domains, urls = parse_yara_network_iocs(sample)
        self.assertIn("203.0.113.44/32", {str(n) for n in v4})
        self.assertIn("stage.bad.example", domains)
        self.assertIn("https://stage.bad.example/payload.bin", urls)
        self.assertNotIn("payload.bin", domains)
        self.assertFalse(v6)


if __name__ == "__main__":
    unittest.main()
