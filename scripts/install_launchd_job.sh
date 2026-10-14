#!/usr/bin/env bash
# Install the macOS LaunchAgent that runs scripts/run_daily_update.sh nightly from THIS clone.
#   scripts/install_launchd_job.sh             install (or reinstall) and load it
#   scripts/install_launchd_job.sh --print     print the plist without installing
#   scripts/install_launchd_job.sh --uninstall unload and remove it
set -euo pipefail

LABEL="com.ununp3ntium115.abuseblacklist.daily"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
LOG_DIR="$HOME/Library/Logs/abuseblacklist"
DOMAIN="gui/$(id -u)"

# launchd does not expand ~ or $VARS inside a plist, so every path is written out absolute.
# A gui/ LaunchAgent runs in the login session, which is what lets git push and gh read the keychain.
render_plist() {
  cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>$REPO_DIR/scripts/run_daily_update.sh</string>
  </array>
  <key>WorkingDirectory</key>
  <string>$REPO_DIR</string>
  <key>StartCalendarInterval</key>
  <dict>
    <key>Hour</key>
    <integer>3</integer>
    <key>Minute</key>
    <integer>17</integer>
  </dict>
  <key>StandardOutPath</key>
  <string>$LOG_DIR/daily.log</string>
  <key>StandardErrorPath</key>
  <string>$LOG_DIR/daily.log</string>
</dict>
</plist>
EOF
}

case "${1:-}" in
  --print)
    render_plist
    exit 0
    ;;
  --uninstall)
    launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
    rm -f "$PLIST"
    echo "removed $LABEL"
    exit 0
    ;;
  "") ;;
  *)
    echo "usage: $0 [--print|--uninstall]" >&2
    exit 2
    ;;
esac

if [[ "$(git -C "$REPO_DIR" symbolic-ref --short -q HEAD || true)" != "main" ]]; then
  echo "refusing: $REPO_DIR is not on main; install from a dedicated clean clone of main" >&2
  exit 1
fi

mkdir -p "$LOG_DIR" "$(dirname "$PLIST")"
render_plist > "$PLIST"
plutil -lint "$PLIST" >/dev/null
launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || true
launchctl bootstrap "$DOMAIN" "$PLIST"
echo "installed $LABEL: runs $REPO_DIR/scripts/run_daily_update.sh daily at 03:17 local time"
echo "log: $LOG_DIR/daily.log    run now: launchctl kickstart -k $DOMAIN/$LABEL"
