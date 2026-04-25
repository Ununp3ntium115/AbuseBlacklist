#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="${REPO_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$REPO_DIR"

python3 scripts/build_blocklists.py

git add output/
if ! git diff --cached --quiet; then
  git commit -m "Daily threatfeed dump $(date -u +'%Y-%m-%d')"
  git push
fi
