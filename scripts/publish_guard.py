#!/usr/bin/env python3
"""Refuse to publish a build whose upstream fetches mostly failed.

build_blocklists.build() always exits 0, so without this check a run with no network
would commit near-empty blocklists to the public feed that routers pull.

Usage: publish_guard.py output/source-manifest.json   (exit 0 = publish, 1 = refuse)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

# Refuse when more than this fraction of sources failed (country zones are ~2/3 of all sources).
MAX_FAILED_SOURCE_RATIO = 0.5


def degraded_reason(stats: dict[str, Any]) -> str | None:
    """Return why the build must not be published, or None when it is publishable."""
    total = int(stats.get("sources_total", 0))
    ok = int(stats.get("sources_ok", 0))
    if total == 0 or ok == 0:
        return f"no upstream source fetched successfully ({ok}/{total})"
    failed_ratio = (total - ok) / total
    if failed_ratio > MAX_FAILED_SOURCE_RATIO:
        return f"{total - ok}/{total} sources failed (limit {MAX_FAILED_SOURCE_RATIO:.0%})"
    # Country zones can pass the ratio alone; routers import high-confidence-*.txt, which needs abuse feeds.
    if int(stats.get("high_confidence_indicators", 0)) == 0:
        return "no high-confidence abuse indicators (every abuse feed failed or returned nothing)"
    return None


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    stats = json.loads(Path(argv[1]).read_text())["stats"]
    reason = degraded_reason(stats)
    if reason:
        print(f"publish_guard: refusing to publish: {reason}", file=sys.stderr)
        return 1
    print(f"publish_guard: ok ({stats['sources_ok']}/{stats['sources_total']} sources)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
