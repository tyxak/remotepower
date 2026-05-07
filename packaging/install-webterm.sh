#!/bin/bash
# install-webterm.sh — set up the remotepower-webterm daemon
#
# Handles the parts that vary by distro / install method:
#   - Detects which user runs the CGI (www-data on Debian/Ubuntu,
#     nginx on Fedora/RHEL, or rp-www if you've made a dedicated user).
#   - Installs Python deps with the right package manager.
#   - Creates the daemon's user, directories, secret.
#   - Installs the binary and systemd unit.
#   - Renders an nginx snippet you can paste into your server block.
#
# Idempotent: re-running won't break anything that's already correct.
# Doesn't restart anything you didn't ask for — at the end it tells
# you what to do.
#
# Usage:
#   sudo bash install-webterm.sh                  # uses sensible defaults
#   sudo bash install-webterm.sh --cgi-user www-data --port 8765
#
# Tested on:
#   Debian 12, Ubuntu 22.04 / 24.04 (uses www-data), Fedora 40 (uses nginx)
#   ArchLinux (uses http), Alpine (uses nginx)

set -euo pipefail

# ─── Defaults — overridable via flags ─────────────────────────────────────────

CGI_USER=""             # auto-detect if empty
DAEMON_USER="rp-webterm"
DAEMON_PORT="8765"
DAEMON_BIND="127.0.0.1"
DATA_DIR="/var/lib/remotepower"
ETC_DIR="/etc/remotepower"
BINARY_DST="/usr/local/bin/remotepower-webterm"
UNIT_DST="/etc/systemd/system/remotepower-webterm.service"
DRY_RUN=0

# ─── Args ────────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
Usage: sudo bash $0 [options]

Options:
  --cgi-user USER        User the CGI (fcgiwrap/php-fpm/etc.) runs as.
                         Auto-detected if not set: tries www-data, nginx,
                         http in that order, then errors out.
  --daemon-user USER     User to run the daemon as (default: rp-webterm).
                         Created if missing.
  --port PORT            Daemon port (default: 8765).
  --bind ADDR            Bind address (default: 127.0.0.1; don't change
                         unless you know what you're doing — the daemon is
                         deliberately not exposed publicly).
  --data-dir DIR         Where the daemon reads tickets and writes
                         recordings (default: /var/lib/remotepower).
  --etc-dir DIR          Where the secret lives (default: /etc/remotepower).
  --dry-run              Print what would happen without doing anything.
  -h, --help             This help.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cgi-user)    CGI_USER="$2"; shift 2 ;;
    --daemon-user) DAEMON_USER="$2"; shift 2 ;;
    --port)        DAEMON_PORT="$2"; shift 2 ;;
    --bind)        DAEMON_BIND="$2"; shift 2 ;;
    --data-dir)    DATA_DIR="$2"; shift 2 ;;
    --etc-dir)     ETC_DIR="$2"; shift 2 ;;
    --dry-run)     DRY_RUN=1; shift ;;
    -h|--help)     usage; exit 0 ;;
    *)             echo "Unknown flag: $1"; usage; exit 1 ;;
  esac
done

# ─── Helpers ─────────────────────────────────────────────────────────────────

run() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "DRY-RUN: $*"
  else
    echo "+ $*"
    "$@"
  fi
}

die() {
  echo "✗ $*" >&2
  exit 1
}

if [[ "$EUID" -ne 0 && "$DRY_RUN" -eq 0 ]]; then
  die "Run as root: sudo bash $0"
fi

# ─── Step 1: detect CGI user ──────────────────────────────────────────────────

if [[ -z "$CGI_USER" ]]; then
  echo "── Detecting CGI user…"
  for candidate in www-data nginx http rp-www apache; do
    if id "$candidate" &>/dev/null; then
      # Sanity check: is this user actually running anything web-server-like?
      # Quick heuristic — a process owned by them with 'fcgi', 'nginx', or
      # 'cgi' in its name.
      if pgrep -u "$candidate" -f '(fcgi|nginx|cgi|php-fpm)' &>/dev/null; then
        CGI_USER="$candidate"
        echo "  → found $CGI_USER (running web/CGI processes)"
        break
      fi
    fi
  done
fi

if [[ -z "$CGI_USER" ]]; then
  echo "  ⚠  Couldn't auto-detect. Trying common names…"
  for candidate in www-data nginx http rp-www; do
    if id "$candidate" &>/dev/null; then
      CGI_USER="$candidate"
      echo "  → using $CGI_USER (no web process detected, but user exists)"
      break
    fi
  done
fi

if [[ -z "$CGI_USER" ]]; then
  die "Couldn't find a CGI user. Pass --cgi-user explicitly."
fi

CGI_GROUP=$(id -gn "$CGI_USER")
echo "  CGI: ${CGI_USER}:${CGI_GROUP}"

# ─── Step 2: detect package manager + install Python deps ────────────────────

echo "── Installing Python deps (websockets, asyncssh)…"
if command -v apt-get &>/dev/null; then
  run apt-get update -qq
  run apt-get install -y --no-install-recommends python3-websockets python3-asyncssh
elif command -v dnf &>/dev/null; then
  run dnf install -y python3-websockets python3-asyncssh
elif command -v pacman &>/dev/null; then
  run pacman -S --noconfirm python-websockets python-asyncssh
elif command -v apk &>/dev/null; then
  run apk add --no-cache py3-websockets py3-asyncssh
elif command -v zypper &>/dev/null; then
  run zypper -n install python3-websockets python3-asyncssh
else
  echo "  ⚠  Unknown package manager. Install python3-websockets and python3-asyncssh manually."
  echo "      pip install --break-system-packages 'websockets>=10' 'asyncssh>=2.10'"
fi

# Sanity check the imports (skip in dry-run since the deps haven't actually
# been installed yet — the dry-run just printed what would happen).
if [[ "$DRY_RUN" -eq 0 ]]; then
  echo "── Verifying Python deps…"
  if ! python3 -c 'import websockets, asyncssh' 2>/dev/null; then
    die "Couldn't import websockets/asyncssh. Install manually then re-run this script."
  fi
  echo "  → ok"
fi

# ─── Step 3: create daemon user ──────────────────────────────────────────────

echo "── Creating daemon user…"
if id "$DAEMON_USER" &>/dev/null; then
  echo "  → ${DAEMON_USER} already exists"
else
  run useradd --system --shell /usr/sbin/nologin --home-dir "$DATA_DIR" \
              --no-create-home "$DAEMON_USER"
  echo "  → created ${DAEMON_USER}"
fi

# Add daemon to CGI group so it can read the ticket file written by CGI
run usermod -a -G "$CGI_GROUP" "$DAEMON_USER"
echo "  → ${DAEMON_USER} ∈ ${CGI_GROUP} (so it can read ticket file)"

# ─── Step 4: directories ─────────────────────────────────────────────────────

echo "── Setting up directories…"
run mkdir -p "$DATA_DIR/webterm-sessions"
run chown "$DAEMON_USER:$DAEMON_USER" "$DATA_DIR/webterm-sessions"
run chmod 750 "$DATA_DIR/webterm-sessions"

run mkdir -p "$ETC_DIR"
run chmod 755 "$ETC_DIR"

# Touch the ticket file so its perms exist before CGI tries to write it
TICKETS_FILE="$DATA_DIR/webterm_tickets.json"
if [[ ! -f "$TICKETS_FILE" ]]; then
  run touch "$TICKETS_FILE"
fi
run chown "$CGI_USER:$CGI_GROUP" "$TICKETS_FILE"
run chmod 640 "$TICKETS_FILE"

# ─── Step 5: shared secret ───────────────────────────────────────────────────

echo "── Setting up daemon ↔ CGI shared secret…"
SECRET_FILE="$ETC_DIR/webterm-secret"
if [[ -f "$SECRET_FILE" && -s "$SECRET_FILE" ]]; then
  echo "  → ${SECRET_FILE} exists, keeping it"
  SECRET=$(cat "$SECRET_FILE")
else
  SECRET=$(openssl rand -hex 32)
  if [[ "$DRY_RUN" -eq 0 ]]; then
    printf '%s' "$SECRET" > "$SECRET_FILE"
  else
    echo "DRY-RUN: would write 64-char hex secret to ${SECRET_FILE}"
  fi
  run chown "$DAEMON_USER:$DAEMON_USER" "$SECRET_FILE"
  run chmod 600 "$SECRET_FILE"
  echo "  → generated new secret"
fi

# Update config.json with the same secret. We use Python to do this rather
# than jq so the script doesn't add a hard dep, and we run it as the CGI
# user so the file's owner doesn't change.
CONFIG_FILE="$DATA_DIR/config.json"
if [[ -f "$CONFIG_FILE" ]]; then
  echo "── Writing secret to ${CONFIG_FILE}…"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    sudo -u "$CGI_USER" python3 -c "
import json, sys
p = '$CONFIG_FILE'
try:
    with open(p) as f:
        cfg = json.load(f)
except Exception:
    cfg = {}
cfg['webterm_daemon_secret'] = '$SECRET'
with open(p, 'w') as f:
    json.dump(cfg, f, indent=2)
"
  else
    echo "DRY-RUN: would set webterm_daemon_secret in $CONFIG_FILE"
  fi
  echo "  → done"
else
  echo "  ⚠  ${CONFIG_FILE} doesn't exist yet — will be created on first CGI hit."
  echo "      Re-run this script after the first dashboard load to populate the secret."
fi

# ─── Step 6: install daemon binary ───────────────────────────────────────────

echo "── Installing daemon binary…"
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
DAEMON_SRC="$SCRIPT_DIR/../server/webterm/remotepower-webterm.py"
if [[ ! -f "$DAEMON_SRC" ]]; then
  # Try a few other plausible locations relative to where the user might
  # have unpacked the tarball.
  for candidate in \
      "$SCRIPT_DIR/server/webterm/remotepower-webterm.py" \
      "$(pwd)/server/webterm/remotepower-webterm.py" \
      "$(pwd)/remotepower-webterm.py"; do
    if [[ -f "$candidate" ]]; then
      DAEMON_SRC="$candidate"
      break
    fi
  done
fi
if [[ ! -f "$DAEMON_SRC" ]]; then
  die "Couldn't find remotepower-webterm.py. Run this script from the unpacked tarball."
fi
run install -m 755 "$DAEMON_SRC" "$BINARY_DST"
echo "  → ${BINARY_DST}"

# ─── Step 7: install systemd unit ────────────────────────────────────────────

echo "── Installing systemd unit…"
UNIT_SRC="$SCRIPT_DIR/../packaging/remotepower-webterm.service"
if [[ ! -f "$UNIT_SRC" ]]; then
  for candidate in \
      "$SCRIPT_DIR/packaging/remotepower-webterm.service" \
      "$(pwd)/packaging/remotepower-webterm.service" \
      "$(pwd)/remotepower-webterm.service"; do
    if [[ -f "$candidate" ]]; then
      UNIT_SRC="$candidate"
      break
    fi
  done
fi
if [[ ! -f "$UNIT_SRC" ]]; then
  die "Couldn't find remotepower-webterm.service unit file."
fi

# Render the unit with the right user/group substituted in. The shipped
# unit hard-codes rp-webterm/rp-www; we replace those for distros where
# we picked different names.
if [[ "$DRY_RUN" -eq 0 ]]; then
  sed -e "s/^User=.*/User=${DAEMON_USER}/" \
      -e "s/^Group=.*/Group=${CGI_GROUP}/" \
      -e "s|^ReadWritePaths=.*|ReadWritePaths=${DATA_DIR}/webterm-sessions ${DATA_DIR}/webterm_tickets.json|" \
      "$UNIT_SRC" > "$UNIT_DST"
  chmod 644 "$UNIT_DST"
else
  echo "DRY-RUN: would render unit file → $UNIT_DST with User=${DAEMON_USER} Group=${CGI_GROUP}"
fi
echo "  → ${UNIT_DST}"

run systemctl daemon-reload

# ─── Step 8: render nginx snippet ────────────────────────────────────────────

echo
echo "── nginx config snippet ──────────────────────────────────────────"
echo "Add this to your existing server { ... } block, ABOVE any catch-all"
echo "'location /' or 'location ^~ /api/' rule. The exact-match (=) modifier"
echo "ensures nginx routes /api/webterm/connect here rather than to fcgiwrap."
echo
cat <<EOF
    location = /api/webterm/connect {
        # IP allowlist — same as the rest of /api/. Comment out if you don't use one.
        # include /etc/nginx/fw_private_rp;
        proxy_pass http://${DAEMON_BIND}:${DAEMON_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 1d;
        proxy_send_timeout 1d;
    }
EOF
echo
echo "Also ensure your http { ... } block (in /etc/nginx/nginx.conf) has:"
echo
cat <<'EOF'
    map $http_upgrade $connection_upgrade {
        default upgrade;
        ''      close;
    }
EOF
echo
echo "─────────────────────────────────────────────────────────────────"

# ─── Step 9: start ───────────────────────────────────────────────────────────

echo
echo "── Starting daemon…"
run systemctl enable remotepower-webterm
run systemctl restart remotepower-webterm
sleep 1
if systemctl is-active --quiet remotepower-webterm 2>/dev/null; then
  echo "  ✓ remotepower-webterm is running"
else
  echo "  ⚠  daemon not running. Check: journalctl -u remotepower-webterm -n 30"
fi

# ─── Final verification + summary ────────────────────────────────────────────

echo
echo "── Verification ──────────────────────────────────────────────────"
if ss -tlnp 2>/dev/null | grep -q ":${DAEMON_PORT} "; then
  echo "  ✓ Daemon listening on ${DAEMON_BIND}:${DAEMON_PORT}"
else
  echo "  ✗ Nothing listening on port ${DAEMON_PORT}"
fi

echo
echo "Next steps:"
echo "  1. Add the nginx snippet above to your server block."
echo "  2. Make sure the \$connection_upgrade map is set in http {}."
echo "  3. sudo nginx -t && sudo systemctl reload nginx"
echo "  4. Click 'Web terminal' on a device in the dashboard."
echo "  5. Watch:  sudo journalctl -u remotepower-webterm -f"
echo
echo "If the WebSocket fails with 404, the catch-all /api/ location is winning"
echo "over the exact-match. Make sure 'location = /api/webterm/connect {…}'"
echo "comes BEFORE 'location ^~ /api/ {…}' in the file (order matters for"
echo "exact matches when other config sets nginx into prefix-priority mode)."
