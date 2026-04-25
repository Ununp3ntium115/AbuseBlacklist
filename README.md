# AbuseBlacklist

Daily threatfeed dump for country CIDR blocking and open threat-intel IP feeds.

This repo performs a daily GitHub Actions dump of:

- Country CIDR ranges from IPdeny for requested and high-risk/export-watchlist countries.
- Open threat IP feeds from ThreatHive, abuse.ch Feodo Tracker, Spamhaus DROP/DROPv6, DShield, Emerging Threats, and Blocklist.de.
- Open threat DNS/URL feeds from abuse.ch URLhaus for domain and URL distillation.

## Distillation deliverables (evidence gate)

This repository now publishes distilled indicators across all requested network types:

- IPv4 CIDR/IP outputs
- IPv6 CIDR/IP outputs
- DNS/domain outputs
- URL outputs

Primary output files:

```text
output/combined-ipv4.txt
output/combined-ipv6.txt
output/threatfeed-ips.txt
output/threat-domains.txt
output/threat-urls.txt
output/source-manifest.json
```

## Architecture graph (current implementation)

```mermaid
flowchart LR
  subgraph upstream["Upstream feeds"]
    ipdeny["IPdeny country CIDRs"]
    feodo["abuse.ch Feodo (base + recommended)"]
    spamhaus["Spamhaus DROP + DROPv6"]
    threathive["ThreatHive"]
    dshield["DShield"]
    et["Emerging Threats"]
    blde["Blocklist.de (all + service lists)"]
  end

  subgraph build["scripts/build_blocklists.py"]
    fetch["Fetch source payloads"]
    parse["Parse + normalize records"]
    split["Split by type (country vs threat)"]
    dedupe["Dedupe + validate CIDRs/IPs"]
    emit["Emit text + firewall + manifest outputs"]
  end

  subgraph outputs["Published artifacts"]
    geo4["country-blocklist-ipv4.txt"]
    geo6["country-blocklist-ipv6.txt"]
    tfeed["threatfeed-ips.txt"]
    c4["combined-ipv4.txt"]
    c6["combined-ipv6.txt"]
    ipset["ipset.restore"]
    nft["nftables-blocklist.nft"]
    manifest["source-manifest.json"]
  end

  ipdeny --> fetch
  feodo --> fetch
  spamhaus --> fetch
  threathive --> fetch
  dshield --> fetch
  et --> fetch
  blde --> fetch

  fetch --> parse --> split --> dedupe --> emit
  emit --> geo4
  emit --> geo6
  emit --> tfeed
  emit --> c4
  emit --> c6
  emit --> ipset
  emit --> nft
  emit --> manifest
```

## Workflow graph (current GitHub Actions jobs)

```mermaid
flowchart TD
  schedule["schedule: 17 3 * * *"] --> gha["daily-dump.yml"]
  manual["workflow_dispatch"] --> gha
  gha --> checkout["Checkout repository"]
  checkout --> setup["Set up Python runtime"]
  setup --> runbuild["Run scripts/build_blocklists.py"]
  runbuild --> stage["git add output/* blacklist.txt"]
  stage --> commit{"Changes detected?"}
  commit -- yes --> push["Commit + push to main"]
  commit -- no --> noop["Exit without commit"]
```

```mermaid
flowchart LR
  fast["fast-feed-health.yml\n7,22,37,52 * * * *"] --> monitor["Availability probes only"]
  community["community-feed-health.yml\n9,39 * * * *"] --> monitor
  hourly["hourly-feed-health.yml\n13 * * * *"] --> monitor
  monitor --> daily["daily-dump.yml\n17 3 * * *\nfull build + publish"]
```

## Target staged workflow (recommended next step)

```mermaid
flowchart LR
  fast["fast-feeds.yml\nFeodo + ThreatHive\n(15m cadence)"] --> merge["daily-snapshot.yml"]
  community["community-feeds.yml\nBlocklist.de\n(30m cadence)"] --> merge
  hourly["hourly-feeds.yml\nDShield\n(hourly)"] --> merge
  daily["daily-authoritative.yml\nSpamhaus + geo sources\n(daily)"] --> merge
  merge --> publish["Publish output/ + feed/\n(generated branch or Pages)"]
  publish --> consumers["Routers, firewalls, SIEM,\nexternal consumers"]
```

## Rollout timeline graph (recommended)

```mermaid
flowchart LR
  w1["Week 1: stabilize publication"] --> w2["Week 2: add metadata governance"]
  w2 --> w3["Week 3: add Atom/RSS + snapshots"]
  w3 --> w4["Week 4: add provenance attestations + signed tags"]
  w4 --> w5["Week 5: RIR/NRO country derivation primary"]
  w5 --> w6["Week 6: optional derived IOC enrichment (feature-flagged)"]
```

## Daily Action

The workflow runs daily at **03:17 UTC**:

```yaml
on:
  schedule:
    - cron: "17 3 * * *"
  workflow_dispatch: {}
```

It rebuilds and commits:

```text
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
```

## Raw pull URLs

```text
https://raw.githubusercontent.com/Ununp3ntium115/AbuseBlacklist/main/output/combined-ipv4.txt
https://raw.githubusercontent.com/Ununp3ntium115/AbuseBlacklist/main/output/combined-ipv6.txt
https://raw.githubusercontent.com/Ununp3ntium115/AbuseBlacklist/main/output/country-blocklist-ipv4.txt
https://raw.githubusercontent.com/Ununp3ntium115/AbuseBlacklist/main/output/country-blocklist-ipv6.txt
https://raw.githubusercontent.com/Ununp3ntium115/AbuseBlacklist/main/output/threatfeed-ips.txt
https://raw.githubusercontent.com/Ununp3ntium115/AbuseBlacklist/main/output/threat-domains.txt
https://raw.githubusercontent.com/Ununp3ntium115/AbuseBlacklist/main/output/threat-urls.txt
https://raw.githubusercontent.com/Ununp3ntium115/AbuseBlacklist/main/output/ipset.restore
https://raw.githubusercontent.com/Ununp3ntium115/AbuseBlacklist/main/output/nftables-blocklist.nft
https://raw.githubusercontent.com/Ununp3ntium115/AbuseBlacklist/main/output/source-manifest.json
```

## Run manually

Use GitHub Actions > Daily threatfeed dump > Run workflow.

Or run locally:

```bash
python3 scripts/build_blocklists.py
```

## Firewall examples

ipset:

```bash
python3 scripts/build_blocklists.py
sudo ipset restore < output/ipset.restore
```

nftables:

```bash
python3 scripts/build_blocklists.py
sudo nft -f output/nftables-blocklist.nft
```

## Current country dump list

- Russia
- China
- North Korea
- Iran
- Israel
- Cuba
- Syria
- Belarus
- Myanmar/Burma
- Afghanistan
- Iraq
- Lebanon
- Libya
- Venezuela
- Sudan
- South Sudan
- Somalia
- Yemen
- Zimbabwe
- Democratic Republic of the Congo

## Notes

- This is intentionally broad and may block legitimate users, VPNs, cloud providers, CDNs, and partners.
- Review each upstream source's license, terms, and rate limits.
- Geo-blocking is not a complete sanctions/export-control solution.
- DNS/URL outputs are intended for abuse and malware blocking contexts; do not use them to target safety tooling, researchers, or lawful monitoring systems.
