#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="${REPO_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$REPO_DIR"

python3 scripts/build_blocklists.py

# Keep local cron clone in sync to avoid non-fast-forward push failures.
git pull --rebase origin main

# Ensure commit identity exists for unattended cron execution.
git config user.name >/dev/null 2>&1 || git config user.name "abuseblacklist-bot"
git config user.email >/dev/null 2>&1 || git config user.email "abuseblacklist-bot@users.noreply.github.com"

git add output/
if ! git diff --cached --quiet; then
  git commit -m "Daily threatfeed dump $(date -u +'%Y-%m-%d')"
  git push
fi
