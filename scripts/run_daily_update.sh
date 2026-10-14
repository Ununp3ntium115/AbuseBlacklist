#!/usr/bin/env bash
# Nightly build + publish. Run it from a dedicated clean clone checked out on main
# (scheduled by scripts/install_launchd_job.sh on macOS, or cron/abuseblacklist.crontab on Linux).
set -euo pipefail

# launchd and cron start with a bare PATH; python3 and gh usually live in /usr/local/bin or /opt/homebrew/bin.
export PATH="/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin${PATH:+:$PATH}"

REPO_DIR="${REPO_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
BRANCH="${BRANCH:-main}"
PUBLISH_RELEASE="${PUBLISH_RELEASE:-1}"
FETCH_TIMEOUT="${FETCH_TIMEOUT:-90}"
cd "$REPO_DIR"

# Dump commits (and their rebases) use a bot noreply identity, as CI did; a clone without a repo-level
# email would otherwise fall back to a private global one, which GitHub rejects on push (GH007).
export GIT_AUTHOR_NAME="${DUMP_GIT_NAME:-abuseblacklist-bot}"
export GIT_AUTHOR_EMAIL="${DUMP_GIT_EMAIL:-abuseblacklist-bot@users.noreply.github.com}"
export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"

log() { echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] $*"; }

current_branch="$(git symbolic-ref --short -q HEAD || true)"
if [[ "$current_branch" != "$BRANCH" ]]; then
  log "ERROR: $REPO_DIR is on '${current_branch:-detached HEAD}', expected '$BRANCH'"
  exit 1
fi

# output/ is fully regenerated, so leftovers from an interrupted run are safe to discard; nothing else is.
git checkout -- output/
if [[ -n "$(git status --porcelain -- . ':!output')" ]]; then
  log "ERROR: uncommitted changes outside output/; refusing to run"
  git status --short -- . ':!output'
  exit 1
fi

# Sync while the tree is clean: pulling after the build fails on the regenerated output/.
git pull --rebase --quiet origin "$BRANCH"

log "building blocklists (timeout ${FETCH_TIMEOUT}s per source)"
python3 scripts/build_blocklists.py --timeout "$FETCH_TIMEOUT"

# build() exits 0 even when every upstream fails; never publish a gutted feed that routers would load.
if ! python3 scripts/publish_guard.py output/source-manifest.json; then
  git checkout -- output/
  exit 1
fi

git add output/
if git diff --cached --quiet; then
  log "no output changes; nothing to publish"
  exit 0
fi

git commit --quiet -m "Daily threatfeed dump $(date -u +'%Y-%m-%d')"
if ! git push --quiet origin "$BRANCH"; then
  log "push rejected; rebasing once and retrying"
  git pull --rebase --quiet origin "$BRANCH"
  git push --quiet origin "$BRANCH"
fi
log "pushed $(git rev-parse --short HEAD) to $BRANCH"

[[ "$PUBLISH_RELEASE" == "1" ]] || exit 0

timestamp="$(date -u +'%Y-%m-%dT%H%M%SZ')"
counts="$(for f in output/*.txt; do printf -- '- %s: %s\n' "$(basename "$f")" "$(wc -l < "$f" | tr -d ' ')"; done)"
gh release create "rulesets-${timestamp}" output/* \
  --target "$(git rev-parse HEAD)" \
  --title "AbuseBlacklist Rulesets ${timestamp}" \
  --notes "$(printf 'AbuseBlacklist immutable ruleset snapshot for %s.\n\nRule counts:\n%s\n' "$timestamp" "$counts")" \
  --latest
log "published release rulesets-${timestamp}"
