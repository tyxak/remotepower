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

# Positional SERVER / PIN for back-compat; flags add the self-signed CA story.
SERVER=""; PIN=""; CA_FP=""; CA_SRC=""
while [ $# -gt 0 ]; do
  case "$1" in
    --ca-fingerprint) CA_FP="$2"; shift 2 ;;
    --ca)             CA_SRC="$2"; shift 2 ;;
    --server)         SERVER="$2"; shift 2 ;;
    --pin)            PIN="$2"; shift 2 ;;
    *) if [ -z "$SERVER" ]; then SERVER="$1"; elif [ -z "$PIN" ]; then PIN="$1"; fi; shift ;;
  esac
done
if [ -z "$SERVER" ]; then read -r -p "Server URL (https://…): " SERVER; fi
if [ -z "$PIN" ];    then read -r -p "Enrollment PIN (from the dashboard): " PIN; fi
[ -n "$SERVER" ] && [ -n "$PIN" ] || die "server URL and PIN required"

# ── Self-signed CA trust (optional) ───────────────────────────────────────────
norm_fp() { echo "$1" | tr 'a-f' 'A-F' | sed -E 's/.*=//; s/[^0-9A-F]//g'; }
if [ -n "$CA_FP" ] || [ -n "$CA_SRC" ]; then
  command -v openssl >/dev/null 2>&1 || die "openssl required to verify the CA"
  TMPCA="$(mktemp)"; trap 'rm -f "$TMPCA"' EXIT
  if [ -z "$CA_SRC" ]; then
    host="${SERVER#*://}"; host="${host%%/*}"; host="${host%%:*}"
    CA_SRC="http://${host}/ca.crt"
  fi
  info "Fetching CA from ${CA_SRC} …"
  case "$CA_SRC" in
    http://*|https://*) curl -fsSL "$CA_SRC" -o "$TMPCA" || die "could not fetch CA from $CA_SRC" ;;
    *)                  [ -f "$CA_SRC" ] || die "CA file not found: $CA_SRC"; cp "$CA_SRC" "$TMPCA" ;;
  esac
  openssl x509 -in "$TMPCA" -noout >/dev/null 2>&1 || die "fetched file is not a valid certificate"
  if [ -n "$CA_FP" ]; then
    got="$(norm_fp "$(openssl x509 -in "$TMPCA" -noout -fingerprint -sha256)")"
    want="$(norm_fp "$CA_FP")"
    [ "$got" = "$want" ] || die "CA FINGERPRINT MISMATCH — refusing to trust (expected $want, got $got)"
    success "CA fingerprint verified ($got)"
  else
    warn "No --ca-fingerprint — trusting fetched CA WITHOUT verification (TOFU)."
  fi
  install -d -m 0755 /etc/remotepower
  install -m 0644 "$TMPCA" /etc/remotepower/ca.crt
  success "CA installed → /etc/remotepower/ca.crt"
fi

info "Installing agent to /usr/local/bin/remotepower-agent-mac"
install -d -m 0755 /usr/local/bin
install -m 0755 "$SRC" /usr/local/bin/remotepower-agent-mac

info "Enrolling…"
RP_CA_BUNDLE=/etc/remotepower/ca.crt /usr/bin/env python3 /usr/local/bin/remotepower-agent-mac --enroll --server "$SERVER" --pin "$PIN"

# Point the daemon at the CA via the launchd EnvironmentVariables dict when set.
PLIST_ENV=""
if [ -f /etc/remotepower/ca.crt ]; then
  PLIST_ENV='  <key>EnvironmentVariables</key>
  <dict><key>RP_CA_BUNDLE</key><string>/etc/remotepower/ca.crt</string></dict>'
fi

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
$PLIST_ENV
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
