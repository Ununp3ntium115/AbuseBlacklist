# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Offline unit tests (stdlib unittest; run from the repo root — tests import `scripts.build_blocklists`)
python3 -m unittest discover -s tests -v
python3 -m unittest tests.test_build_blocklists.BuildBlocklistsParsingTests.test_parse_ip_or_networks_supports_ipv4_ipv6_and_host_ips

# Full build: fetches every upstream feed over the network and rewrites output/
python3 scripts/build_blocklists.py               # default 90s per-source timeout
python3 scripts/build_blocklists.py --timeout 45
```

There is no linter, formatter, package manifest, or virtualenv. The builder uses only the Python stdlib, and the nightly job runs on whatever system `python3` it finds, so don't add third-party dependencies. `build()` prints its stats JSON to stdout even under test, so a passing test run is noisy. Look for the final `OK`.

`orca.yaml` runs the offline tests as the Orca worktree setup hook. Never put the full build there, because it would hit every upstream provider on each worktree create.

## Architecture

The whole system is one file, `scripts/build_blocklists.py`. Everything else is input (`config.json`, `feeds/*.txt`) or committed output (`output/`). The outputs are the product: they're served as raw GitHub URLs and as release assets for routers, ipset, nftables, and DNS filters.

### Pipeline (`build()`)

1. **Country CIDRs.** `country_urls()` expands `config.json`'s IPdeny URL templates for each country code, skipping IPv6 for codes in `countries_without_ipv6`. Their metadata comes from `country_meta()` (`kind: policy_country`, confidence 55), not from `SOURCE_CATALOG`.
2. **Feed lists.** Each `feeds/*-feeds.txt` file lists one source per line. A source can be an HTTP(S) URL, a `file://` URL, or a repo-relative path like `feeds/manual-threat-ips.txt`, which `fetch()` reads from disk. `strip_comment()` drops lines starting with `!`, `[` or `//`, and cuts each line at the first `#` or `;`.
3. **Parsing.** The feeds file sets the category label and whether results route to privacy. It does not choose the parser: every non-YARA feed goes through both `parse_ip_or_networks()` and `parse_domains_and_urls()`, so a URL inside an IP feed still yields a domain and a URL. `parse_domains_and_urls()` refangs `hxxp(s)://`, `[.]`, `(.)` and `[:]`, and strips hosts-file sentinels (`0.0.0.0`, `127.0.0.1`, `::1`) and `@@` exception markers. `parse_yara_network_iocs()` only looks inside quoted string literals.
4. **Accumulation.** `add_indicator()` keys every indicator as `type:indicator` and appends each source's metadata. `finalize_records()` then reduces it:
   - `confidence_score = min(100, max(source confidences) + min(15, (source_count - 1) * 5))`
   - `reputation_score` is the max across sources. `ttl_hours` is the min.
   - `enforcement` is `abuse` if any source says abuse. Otherwise it's the first kind seen.
5. **Outputs.**
   - `combined-*` is country ∪ threat IPs, collapsed with `ipaddress.collapse_addresses()`.
   - `dns-blocklist.txt` is threat domains ∪ privacy domains.
   - `high-confidence-*` requires `enforcement == "abuse"` **and** `confidence_score >= high_confidence_threshold` (75, set in `config.json`).
   - `scored-indicators.json[l]` excludes privacy records.
   - `ipset.restore` and `nftables-blocklist.nft` are generated from the collapsed combined sets.
   - `feed-reputation.json` is a static dump of `SOURCE_CATALOG`, not per-run data.

### Indicator classes are the central design rule

The `kind` values in `SOURCE_CATALOG` are `abuse`, `policy_country`, `privacy`, and `context`. Country and privacy data must never reach the `high-confidence-*` files: those mean "abuse evidence", while `combined-*` means "abuse plus geo-policy". `context` sources (CISA RSS and the KEV JSON in `feeds/advisory-context-feeds.txt`) only populate `advisory-context.json` and never create blocks.

When adding a feed, also add a `SOURCE_CATALOG` entry whose `match` substring appears in the URL. Without one, `source_meta()` falls back to `DEFAULT_SOURCE` (abuse, confidence 50). A feed like that can never reach high-confidence on its own.

### Failure semantics

Every fetch is wrapped in `try/except Exception`. A failing source logs `WARN` to stderr and is recorded with `"ok": false` and an `error` in `output/source-manifest.json`. `build()` always returns 0. A dead upstream (or a 404 for a country with no IPv6 zone) therefore never fails the build. It silently shrinks the outputs, which CI then commits. Check `stats.sources_failed` in the manifest when output counts drop.

### Module import side effects

Importing `build_blocklists` reads `config.json` and creates `output/` at module level. Tests isolate themselves by patching the module-level names `OUT`, `country_urls`, `read_urls` and `fetch` with `unittest.mock.patch.object`. Follow that pattern rather than hitting the network.

## Changing things

- **`output/` is generated.** Don't hand-edit it or code-review its diffs. Resolve merge conflicts there by regenerating. The root `blacklist.txt` is a static TEST-NET bootstrap file that nothing regenerates.
- **Adding a new output file:** write it in `build()`. The nightly release attaches `output/*` automatically, but nothing reads `config.json` `outputs` (it's documentation only), so update that list and the README's artifact list by hand.
- **Adding a country:** add the code to `config.json` `countries`. If IPdeny publishes no IPv6 aggregate for it, also add it to `countries_without_ipv6`. The country set is a documented policy list in the README, so keep the two in sync.
- **Emergency IOCs:** append validated IPs/CIDRs to `feeds/manual-threat-ips.txt`. `threat-ip-feeds.txt` references it as a local-path source, so it gets ingested as an uncataloged abuse feed.
- **Scope boundary:** privacy outputs are for public tracker/adware lists only. Per the README, enumerating law-enforcement, honeypot, or surveillance infrastructure is out of scope by policy, not a missing feature.

## Nightly automation (no GitHub Actions)

Automation runs from a maintainer machine by choice; the GitHub workflows were removed on 2026-10-13. Don't reintroduce `.github/workflows/` without asking. `scripts/run_daily_update.sh` is the entire pipeline, run nightly from a dedicated clean clone of `main`:

1. Refuse to run if the clone isn't on `main`, or has changes outside `output/`. Leftover `output/` changes are discarded first.
2. `git pull --rebase` while the tree is still clean. Pulling after the build would fail on the regenerated `output/`.
3. Build, then run `scripts/publish_guard.py`. Because `build()` always exits 0, the guard reads the manifest and refuses to publish in two cases: more than `MAX_FAILED_SOURCE_RATIO` of the sources failed, or there are zero high-confidence abuse indicators. The second case exists because the 39 country zones alone can pass the ratio.
4. Commit `output/` as `Daily threatfeed dump YYYY-MM-DD`, then push (retrying once with a rebase).
5. Run `gh release create rulesets-<UTC timestamp>` with `output/*` attached. Set `PUBLISH_RELEASE=0` to skip this.

On macOS, `scripts/install_launchd_job.sh` installs it as LaunchAgent `com.ununp3ntium115.abuseblacklist.daily` (03:17 local, logging to `~/Library/Logs/abuseblacklist/daily.log`). It uses a `gui/` LaunchAgent rather than cron so that `git push`/`gh` can reach the keychain. On Linux, use `cron/abuseblacklist.crontab`, and append it to the crontab rather than replacing it.

## Environment note

Orca worktrees of this repo live under the Orca app's own checkout directory, so Claude Code may also load that parent's `CLAUDE.md`/`AGENTS.md`. Those rules (pnpm, STYLEGUIDE, Electron) do not apply to this repo.
