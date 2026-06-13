#!/usr/bin/env bash
# RemotePower — Client installer
# Run as root on each machine you want to be able to control remotely
#
# Self-signed-CA deployments (v4.5.0): pass --ca-fingerprint so the agent trusts
# your internal CA. The CA's public cert is fetched over HTTP and verified
# against the SHA-256 fingerprint you printed from tools/gen-ca.sh, so a MITM on
# first contact can't substitute its own CA.
#
#   sudo bash install-client.sh --server https://rp.internal \
#        --ca-fingerprint AA:BB:CC:...   [--pin 123456]
#
# Options:
#   --server URL          Server base URL (https://...). Skips the interactive prompt.
#   --ca-fingerprint FP   SHA-256 fingerprint of the CA (from gen-ca.sh). Fetches
#                         http://<host>/ca.crt, verifies it, installs it, and points
#                         the agent at it via RP_CA_BUNDLE.
#   --ca PATH|URL         Use this CA cert instead of <host>/ca.crt (still verified
#                         against --ca-fingerprint if given).
#   --pin PIN             Enrollment PIN (non-interactive enroll with --server).
#   (no args)             Interactive enrollment, system trust store (real cert).
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
die()     { echo -e "${RED}[✗]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && die "Run as root: sudo bash install-client.sh"

SERVER_URL=""; CA_FP=""; CA_SRC=""; PIN=""
while [ $# -gt 0 ]; do
  case "$1" in
    --server)         SERVER_URL="$2"; shift 2 ;;
    --ca-fingerprint) CA_FP="$2"; shift 2 ;;
    --ca)             CA_SRC="$2"; shift 2 ;;
    --pin)            PIN="$2"; shift 2 ;;
    -h|--help)        sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)                die "unknown option: $1 (try --help)" ;;
  esac
done

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   RemotePower Client Installer               ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Install agent ────────────────────────────────────────────────────────────────
info "Installing agent..."
install -m 755 "$SCRIPT_DIR/client/remotepower-agent" /usr/local/bin/remotepower-agent
install -m 644 "$SCRIPT_DIR/client/remotepower-agent.service" /etc/systemd/system/remotepower-agent.service
mkdir -p /etc/remotepower
success "Agent installed"

# ── Self-signed CA trust (optional) ──────────────────────────────────────────────
# Normalise a fingerprint to bare uppercase hex (drop "sha256 Fingerprint=", colons).
norm_fp() { echo "$1" | tr 'a-f' 'A-F' | sed -E 's/.*=//; s/[^0-9A-F]//g'; }

if [ -n "$CA_FP" ] || [ -n "$CA_SRC" ]; then
  command -v openssl >/dev/null 2>&1 || die "openssl required to verify the CA"
  TMPCA="$(mktemp)"; trap 'rm -f "$TMPCA"' EXIT

  # Resolve where to get the CA from.
  if [ -z "$CA_SRC" ]; then
    [ -n "$SERVER_URL" ] || die "--ca-fingerprint needs --server (to locate http://<host>/ca.crt)"
    host="${SERVER_URL#*://}"; host="${host%%/*}"; host="${host%%:*}"
    CA_SRC="http://${host}/ca.crt"
  fi

  info "Fetching CA from ${CA_SRC} ..."
  case "$CA_SRC" in
    http://*|https://*) curl -fsSL "$CA_SRC" -o "$TMPCA" || die "could not fetch CA from $CA_SRC" ;;
    *)                  [ -f "$CA_SRC" ] || die "CA file not found: $CA_SRC"; cp "$CA_SRC" "$TMPCA" ;;
  esac
  openssl x509 -in "$TMPCA" -noout >/dev/null 2>&1 || die "fetched file is not a valid certificate"

  if [ -n "$CA_FP" ]; then
    got="$(norm_fp "$(openssl x509 -in "$TMPCA" -noout -fingerprint -sha256)")"
    want="$(norm_fp "$CA_FP")"
    [ -n "$want" ] || die "could not parse --ca-fingerprint"
    if [ "$got" != "$want" ]; then
      die "CA FINGERPRINT MISMATCH — refusing to trust. expected $want, got $got"
    fi
    success "CA fingerprint verified ($got)"
  else
    warn "No --ca-fingerprint given — trusting fetched CA WITHOUT verification (TOFU)."
  fi

  install -m 644 "$TMPCA" /etc/remotepower/ca.crt
  printf 'RP_CA_BUNDLE=/etc/remotepower/ca.crt\n' > /etc/remotepower/agent.env
  chmod 644 /etc/remotepower/agent.env
  success "CA installed → /etc/remotepower/ca.crt (agent will trust it via RP_CA_BUNDLE)"
fi

# ── Enrollment ──────────────────────────────────────────────────────────────────
info "Starting enrollment..."
echo ""
if [ -n "$SERVER_URL" ] && [ -n "$PIN" ]; then
  RP_CA_BUNDLE=/etc/remotepower/ca.crt /usr/local/bin/remotepower-agent enroll --server "$SERVER_URL" --pin "$PIN"
elif [ -n "$SERVER_URL" ]; then
  RP_CA_BUNDLE=/etc/remotepower/ca.crt /usr/local/bin/remotepower-agent enroll --server "$SERVER_URL"
else
  /usr/local/bin/remotepower-agent enroll
fi
echo ""

# ── Enable service ───────────────────────────────────────────────────────────────
info "Enabling systemd service..."
systemctl daemon-reload
systemctl enable --now remotepower-agent
success "Service enabled and started"

# ── Verify ───────────────────────────────────────────────────────────────────────
sleep 2
if systemctl is-active --quiet remotepower-agent; then
    success "Agent is running"
else
    warn "Agent may not have started — check: journalctl -u remotepower-agent -f"
fi

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   Client installed!                          ║"
echo "╚══════════════════════════════════════════════╝"
echo ""
echo "  Status:    systemctl status remotepower-agent"
echo "  Logs:      journalctl -u remotepower-agent -f"
echo "  Re-enroll: remotepower-agent enroll"
echo "  Update:    remotepower-agent update"
echo ""
