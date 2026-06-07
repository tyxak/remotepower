#!/usr/bin/env bash
# RemotePower — macOS client installer (launchd).
# Run with sudo on each Mac you want in the fleet. Enrolls the agent and starts
# it as a LaunchDaemon so it runs at boot regardless of login.
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
die()     { echo -e "${RED}[✗]${NC} $*"; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run as root: sudo bash client/install-macos.sh"
[ "$(uname -s)" = "Darwin" ] || die "This installer is for macOS. Use install-client.sh (Linux) or install-windows.ps1 (Windows)."
command -v python3 >/dev/null || die "python3 not found — install it (e.g. 'xcode-select --install' or Homebrew)."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$SCRIPT_DIR/remotepower-agent-mac.py"
[ -f "$SRC" ] || SRC="$SCRIPT_DIR/client/remotepower-agent-mac.py"
[ -f "$SRC" ] || die "cannot find remotepower-agent-mac.py"

SERVER="${1:-}"; PIN="${2:-}"
if [ -z "$SERVER" ]; then read -r -p "Server URL (https://…): " SERVER; fi
if [ -z "$PIN" ];    then read -r -p "Enrollment PIN (from the dashboard): " PIN; fi
[ -n "$SERVER" ] && [ -n "$PIN" ] || die "server URL and PIN required"

info "Installing agent to /usr/local/bin/remotepower-agent-mac"
install -d -m 0755 /usr/local/bin
install -m 0755 "$SRC" /usr/local/bin/remotepower-agent-mac

info "Enrolling…"
/usr/bin/env python3 /usr/local/bin/remotepower-agent-mac --enroll --server "$SERVER" --pin "$PIN"

PLIST=/Library/LaunchDaemons/com.remotepower.agent.plist
info "Installing LaunchDaemon $PLIST"
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.remotepower.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/bin/python3</string>
    <string>/usr/local/bin/remotepower-agent-mac</string>
    <string>--run</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>/var/log/remotepower-agent.log</string>
  <key>StandardOutPath</key><string>/var/log/remotepower-agent.log</string>
</dict>
</plist>
EOF
chmod 644 "$PLIST"

info "Loading the daemon…"
launchctl unload "$PLIST" 2>/dev/null || true
launchctl load -w "$PLIST"

sleep 2
if launchctl list | grep -q com.remotepower.agent; then
  success "RemotePower agent is running (launchd). It appears in the dashboard within ~60s."
else
  warn "Daemon may not have started — check /var/log/remotepower-agent.log"
fi
echo "  Logs:      tail -f /var/log/remotepower-agent.log"
echo "  Stop:      sudo launchctl unload $PLIST"
echo "  Re-enroll: sudo python3 /usr/local/bin/remotepower-agent-mac --enroll --server <url> --pin <pin>"
