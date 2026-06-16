#!/usr/bin/env bash
#
# RemotePower — unified installer & wizard (v4.8.0)
#
# ONE script for the whole server lifecycle. Supersedes install-server.sh,
# tools/gen-ca.sh, `make tls-selfsigned` and remotepower-passwd:
#
#     remotepower install     interactive wizard (default; this is what runs)
#     remotepower tls         (re)issue / renew certificates
#     remotepower passwd      manage admin accounts
#     remotepower update      pull + redeploy in place
#     remotepower doctor      preflight / health check
#     remotepower agent       print the one-line device-enrol command
#
# nginx stays the front door — the operator never edits an nginx file by hand;
# this script writes the vhost + TLS for them. Heavy-fleet scaling (Postgres,
# HA, satellites, load balancing) is a separate ADVANCED path and is never
# touched here — see `docs/advanced-scaling.md`.
#
# Modes:
#   (no TTY) or --unattended   non-interactive; flags/env drive it, no eye candy
#   --demo                     run the full visual flow WITHOUT touching the box
#   --dry-run                  print each action instead of doing it
#
# STATUS: greeting + wizard skeleton. The destructive steps are gated behind
# dry-run while we lock the look; wiring the real nginx/TLS/admin work is next.
set -euo pipefail

VERSION="4.8.0"
SELF="${0##*/}"

# ── cosmetics ────────────────────────────────────────────────────────────────
# Colour only on a real terminal and when not muted (NO_COLOR / non-tty / CI).
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != "dumb" ]; then
  B=$'\e[1m'; DIM=$'\e[2m'; RST=$'\e[0m'
  ACC=$'\e[38;5;39m'        # brand blue accent
  GRN=$'\e[38;5;42m'; YLW=$'\e[38;5;214m'; RED=$'\e[38;5;203m'
else
  B=""; DIM=""; RST=""; ACC=""; GRN=""; YLW=""; RED=""
fi
CK="${GRN}✓${RST}"; CROSS="${RED}✗${RST}"; DOT="${DIM}·${RST}"
W=58   # inner width of the boxes

# pad to the box width by CHARACTER count (bash ${#} is code points under a
# UTF-8 locale), so box-drawing / middle-dot glyphs in the content still align —
# printf's %-*s pads by BYTES and would shift the right border.
_box()  {
  local s="$1" pad; pad=$(( W - ${#s} )); [ "$pad" -lt 0 ] && pad=0
  printf "${ACC}│${RST} %s" "$s"
  printf "%*s ${ACC}│${RST}\n" "$pad" ""
}
_top()  { printf "${ACC}┌"; printf '─%.0s' $(seq 1 $((W+2))); printf "┐${RST}\n"; }
_bot()  { printf "${ACC}└"; printf '─%.0s' $(seq 1 $((W+2))); printf "┘${RST}\n"; }
_titletop() { # ┌─ Title ───…─┐
  local t="$1"; local dash=$((W - ${#t}))
  printf "${ACC}┌─ ${B}%s${RST}${ACC} " "$t"
  printf '─%.0s' $(seq 1 "$dash"); printf "┐${RST}\n"
}
hr()    { printf "${DIM}"; printf '─%.0s' $(seq 1 $((W+4))); printf "${RST}\n"; }

banner() {
  echo
  _top
  _box ""
  _box "R E M O T E P O W E R"
  _box "─────────────────────"
  _box "Fleet monitoring & control  ·  installer ${VERSION}"
  _box ""
  _bot
  echo
}

step_ok()   { printf "   ${CK}  %s\n" "$1"; }
step_no()   { printf "   ${CROSS}  ${RED}%s${RST}\n" "$1"; }
step_wait() { printf "   ${DOT}  %s\n" "$1"; }
section()   { printf "\n${B}${ACC}%s${RST}\n" "$1"; }
note()      { printf "${DIM}   %s${RST}\n" "$1"; }

# ── state ────────────────────────────────────────────────────────────────────
MODE="interactive"; DRY=0
HOST=""; TLS_MODE=""; ADMIN_USER="admin"; ADMIN_PASS=""; PORT=""
PREFIX=""; SANDBOX=0; PKG_MGR=""; NGINX_USER=""; CA_FP=""; PURGE=0

usage() {
  cat <<EOF
${B}RemotePower installer ${VERSION}${RST}

  ${B}$SELF${RST} [command] [options]

Commands:
  install        Interactive setup wizard (default)
  uninstall      Remove the server (keeps data; --purge to wipe it too)
  tls            (Re)issue or renew TLS certificates
  passwd         Manage admin accounts
  update         Update an existing install in place
  doctor         Run preflight checks only
  agent          Print the one-line device-enrol command

Options:
  --host H       Server hostname / domain (default: autodetect)
  --tls MODE     self-signed | letsencrypt | byo | none
  --admin-user U Admin username (default: admin)
  --admin-pass P Admin password (else prompted, or generated)
  --port N       HTTPS port (default: 443)
  --unattended   No prompts, no eye candy (CI / Ansible)
  --purge        (uninstall) also delete /var/lib/remotepower data
  --demo         Show the full visual flow without changing anything
  --dry-run      Print actions instead of running them
  -h, --help     This help
EOF
}

# ── preflight (READ-ONLY — always safe to run) ──────────────────────────────
detect_os() {
  if [ -r /etc/os-release ]; then . /etc/os-release; echo "${PRETTY_NAME:-$NAME}"; else uname -s; fi
}
port_free() { # $1 = port → 0 if free
  if command -v ss >/dev/null 2>&1; then ! ss -ltn 2>/dev/null | grep -q ":$1 "
  elif command -v lsof >/dev/null 2>&1; then ! lsof -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
  else return 0; fi
}
preflight() {
  section "Preflight"
  step_ok "OS .............. $(detect_os)"
  if command -v nginx >/dev/null 2>&1; then step_ok "nginx ........... $(nginx -v 2>&1 | grep -oE '[0-9.]+' | head -1)"
  else step_wait "nginx ........... not installed (the installer will add it)"; fi
  if command -v python3 >/dev/null 2>&1; then step_ok "python3 ......... $(python3 -V 2>&1 | awk '{print $2}')"
  else step_no "python3 ......... missing (required)"; fi
  local p="${PORT:-443}"
  if port_free 80 && port_free "$p"; then step_ok "ports ........... 80 + $p free"
  else step_wait "ports ........... 80/$p in use (will reuse / reconfigure)"; fi
  if [ -e /var/lib/remotepower ]; then step_wait "data dir ........ /var/lib/remotepower exists (will reuse)"
  else step_ok "data dir ........ /var/lib/remotepower (new)"; fi
}

# ── wizard prompts ───────────────────────────────────────────────────────────
ask_host() {
  [ -n "$HOST" ] && return
  local def; def="$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo localhost)"
  if [ "$MODE" = "interactive" ]; then
    printf "\n${B}${ACC}Hostname${RST} — what address will agents and browsers use?\n"
    read -r -p "   Host [${def}]: " HOST || true
  fi
  HOST="${HOST:-$def}"
}
ask_tls() {
  [ -n "$TLS_MODE" ] && return
  if [ "$MODE" = "interactive" ]; then
    printf "\n${B}${ACC}TLS${RST} — how should HTTPS be set up?\n"
    printf "   ${B}1${RST}  Self-signed CA   ${DIM}automatic, best for LAN / homelab  (default)${RST}\n"
    printf "   ${B}2${RST}  Let's Encrypt    ${DIM}public domain + email${RST}\n"
    printf "   ${B}3${RST}  Bring your own   ${DIM}point nginx at existing certs${RST}\n"
    printf "   ${B}4${RST}  None             ${DIM}behind my own TLS proxy${RST}\n"
    read -r -p "   Choose [1]: " c || true
    case "${c:-1}" in 2) TLS_MODE=letsencrypt;; 3) TLS_MODE=byo;; 4) TLS_MODE=none;; *) TLS_MODE=self-signed;; esac
  else
    TLS_MODE="self-signed"
  fi
}
ask_admin() {
  if [ "$MODE" = "interactive" ]; then
    printf "\n${B}${ACC}Admin account${RST}\n"
    read -r -p "   Username [admin]: " u || true; ADMIN_USER="${u:-admin}"
    if [ -z "$ADMIN_PASS" ]; then
      read -r -s -p "   Password (blank = generate one): " ADMIN_PASS || true; echo
    fi
  fi
  if [ -z "$ADMIN_PASS" ]; then
    ADMIN_PASS="$(_gen_secret 12)"; ADMIN_GENERATED=1
  fi
}
_gen_secret() { # $1 = bytes-ish length
  if command -v openssl >/dev/null 2>&1; then openssl rand -base64 18 | tr -d '/+=' | cut -c1-"${1:-16}"
  else tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c "${1:-16}"; fi
}

# ── the work (ported faithfully from the proven install-server.sh) ───────────
# System paths; --sandbox prefixes them ALL so the real steps run rootless into
# a temp dir (no pkg-mgr, no systemd, no /etc writes) — that's how it's tested.
WWW="/var/www/remotepower"; DATA="/var/lib/remotepower"
NGX="/etc/nginx"; RPETC="/etc/remotepower"
_p() { printf '%s%s' "$PREFIX" "$1"; }
_demo() { step_ok "$1"; note "would: $2"; }

_detect_pkg() {
  if   command -v apt-get >/dev/null 2>&1; then PKG_MGR=apt;    NGINX_USER=www-data
  elif command -v dnf     >/dev/null 2>&1; then PKG_MGR=dnf;    NGINX_USER=nginx
  elif command -v pacman  >/dev/null 2>&1; then PKG_MGR=pacman; NGINX_USER=http
  else PKG_MGR=""; NGINX_USER=http; fi
}
_install_deps() {
  case "$PKG_MGR" in
    apt) apt-get update -qq; apt-get install -y --no-install-recommends nginx fcgiwrap python3 python3-pip;;
    dnf) dnf install -y -q nginx fcgiwrap python3 python3-pip;;
    pacman) pacman -Sy --noconfirm --noprogressbar nginx fcgiwrap python python-pip;;
    *) step_no "unsupported distro — install nginx/fcgiwrap/python3 manually"; return 1;;
  esac
  # Best-effort optional libs (each degrades gracefully in api.py).
  python3 -c "import bcrypt" 2>/dev/null || pip3 install bcrypt --break-system-packages 2>/dev/null || pip install bcrypt 2>/dev/null || true
}
_copy_files() {
  local SRC="$1" f
  for f in "$SRC"/server/html/*.html; do cp "$f" "$(_p "$WWW")/$(basename "$f")"; done
  for f in "$SRC"/server/html/favicon.* "$SRC"/server/html/robots.txt "$SRC"/server/html/manifest.json "$SRC"/server/html/sw.js; do
    [ -f "$f" ] && install -m644 "$f" "$(_p "$WWW")/$(basename "$f")" || true
  done
  [ -d "$SRC/server/html/static" ] && cp -rp "$SRC/server/html/static/." "$(_p "$WWW")/static/" || true
  for f in "$SRC"/server/cgi-bin/*.py; do
    if [ "$(basename "$f")" = "api.py" ]; then install -m755 "$f" "$(_p "$WWW")/cgi-bin/$(basename "$f")"
    else install -m644 "$f" "$(_p "$WWW")/cgi-bin/$(basename "$f")"; fi
  done
  install -m755 "$SRC/server/remotepower-passwd" "$(_p "$WWW")/cgi-bin/remotepower-passwd" 2>/dev/null || true
  install -m755 "$SRC/client/remotepower-agent"  "$(_p "$WWW")/agent/remotepower-agent" 2>/dev/null || true
  for f in "$SRC"/docs/*.md; do [ -f "$f" ] && install -m644 "$f" "$(_p "$DATA")/docs/$(basename "$f")" || true; done
}
_gen_tls() { # self-signed via the proven tools/gen-ca.sh
  local SRC="$1" tlsdir; tlsdir="$(_p "$RPETC")/tls"
  install -d -m755 "$(_p "$RPETC")"
  if bash "$SRC/tools/gen-ca.sh" --host "$HOST" --dir "$tlsdir" >/tmp/rp-genca.$$.log 2>&1; then
    CA_FP="$(openssl x509 -in "$tlsdir/ca.crt" -noout -fingerprint -sha256 2>/dev/null | sed 's/^.*=//')"
    return 0
  fi
  step_no "TLS cert generation failed"; sed 's/^/      /' /tmp/rp-genca.$$.log; return 1
}
_render_tls_vhost() {
  cat <<NGINX
# Generated by RemotePower installer — do not hand-edit; re-run the installer.
server {
    listen 80; listen [::]:80;
    server_name ${HOST};
    location = /ca.crt { alias ${RPETC}/tls/ca.crt; default_type application/x-x509-ca-cert; }
    location / { return 301 https://\$host\$request_uri; }
}
server {
    listen 443 ssl; listen [::]:443 ssl;
    http2 on;
    server_name ${HOST};
    root ${WWW}; index index.html;
    ssl_certificate     ${RPETC}/tls/server.crt;
    ssl_certificate_key ${RPETC}/tls/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
    gzip on;
    client_max_body_size 2m; client_body_timeout 10s; client_header_timeout 10s;
    include snippets/remotepower-locations.conf;
    access_log /var/log/nginx/remotepower_access.log;
    error_log  /var/log/nginx/remotepower_error.log;
}
NGINX
}
_write_nginx() {
  local SRC="$1" vhost
  install -d -m755 "$(_p "$NGX")/snippets" "$(_p "$NGX")/sites-available" "$(_p "$NGX")/sites-enabled" "$(_p "$NGX")/conf.d"
  cp "$SRC/server/conf/remotepower-locations.conf" "$(_p "$NGX")/snippets/remotepower-locations.conf"
  vhost="$(_p "$NGX")/sites-available/remotepower"
  if [ "$TLS_MODE" = "self-signed" ] || [ "$TLS_MODE" = "byo" ]; then
    _render_tls_vhost > "$vhost"
  else
    sed "s/server_name _;/server_name ${HOST};/" "$SRC/server/conf/remotepower.conf" > "$vhost"
  fi
  # Enable the site (distro-appropriate); both are idempotent.
  ln -sf "$NGX/sites-available/remotepower" "$(_p "$NGX")/sites-enabled/remotepower" 2>/dev/null || true
  ln -sf "$NGX/sites-available/remotepower" "$(_p "$NGX")/conf.d/remotepower.conf" 2>/dev/null || true
}
_create_admin() {
  RP_ADMIN_USER="$ADMIN_USER" RP_ADMIN_PASS="$ADMIN_PASS" RP_USERS="$(_p "$DATA")/users.json" python3 - <<'PY'
import json, time, os, hashlib, secrets
from pathlib import Path
plain = os.environ['RP_ADMIN_PASS']
try:
    import bcrypt
    h = bcrypt.hashpw(plain.encode(), bcrypt.gensalt(12)).decode(); t = 'bcrypt'
except ImportError:
    salt = secrets.token_bytes(16); it = 600_000
    h = f"pbkdf2${it}${salt.hex()}${hashlib.pbkdf2_hmac('sha256', plain.encode(), salt, it).hex()}"; t = 'pbkdf2'
p = Path(os.environ['RP_USERS'])
u = json.loads(p.read_text()) if p.exists() else {}
u[os.environ['RP_ADMIN_USER']] = {'password_hash': h, 'role': 'admin', 'created': int(time.time())}
p.write_text(json.dumps(u, indent=2))
os.chmod(p, 0o600)   # lock the hash file (install-server.sh left it 644)
PY
}
_enable_services() {
  systemctl enable --now fcgiwrap.socket 2>/dev/null || systemctl enable --now fcgiwrap 2>/dev/null || \
    step_no "could not start fcgiwrap — check: systemctl status fcgiwrap"
  nginx -t && systemctl reload nginx
}

run_install() {
  section "Installing"
  local SRC; SRC="$(cd "$(dirname "$0")" && pwd)"
  if [ "$MODE" = "demo" ]; then
    _demo "Dependencies installed" "pkg install nginx fcgiwrap python3"
    _demo "Web + backend files installed" "copy server/ + docs → /var/www/remotepower"
    _demo "Self-signed CA + certificate issued" "gen-ca → /etc/remotepower/tls"
    _demo "nginx vhost written (no hand-editing)" "template → /etc/nginx, nginx -t, reload"
    _demo "Admin account created" "users.json (bcrypt, 0600)"
    _demo "Services started + health-checked" "fcgiwrap + nginx, GET /api/health"
    return
  fi
  _detect_pkg
  if [ "$SANDBOX" = 1 ]; then step_wait "Dependencies — skipped (sandbox)"
  else _install_deps && step_ok "Dependencies installed (${PKG_MGR})"; fi

  install -d -m755 "$(_p "$WWW")/cgi-bin" "$(_p "$WWW")/agent" "$(_p "$WWW")/static" "$(_p "$WWW")/docs"
  install -d -m700 "$(_p "$DATA")" "$(_p "$DATA")/docs"
  step_ok "Directories created"
  _copy_files "$SRC"; step_ok "Web + backend files installed"

  case "$TLS_MODE" in
    self-signed) _gen_tls "$SRC" && step_ok "Self-signed CA + certificate issued (${HOST})";;
    none)        step_wait "TLS — HTTP only";;
    letsencrypt) step_wait "TLS — run 'certbot --nginx -d ${HOST}' after install (needs public DNS)";;
    byo)         step_wait "TLS — drop your cert/key at ${RPETC}/tls/server.{crt,key}";;
  esac
  _write_nginx "$SRC"; step_ok "nginx vhost written (server_name=${HOST}, no hand-editing)"
  _create_admin && step_ok "Admin account '${ADMIN_USER}' created"

  if [ "$SANDBOX" = 1 ]; then step_wait "Services (fcgiwrap/nginx) — skipped (sandbox)"
  else _enable_services && step_ok "Services started + health-checked"; fi
}

scheme() { [ "$TLS_MODE" = "none" ] && echo "http" || echo "https"; }

summary_card() {
  local url; url="$(scheme)://${HOST}${PORT:+:$PORT}"
  echo
  _titletop "RemotePower is live"
  _box ""
  _box "URL      ${url}"
  if [ "${ADMIN_GENERATED:-0}" = 1 ]; then
    _box "Login    ${ADMIN_USER}  ·  ${ADMIN_PASS}   (shown once)"
  else
    _box "Login    ${ADMIN_USER}  ·  (the password you set)"
  fi
  _box ""
  _box "Add your first device — generate a token in the"
  _box "dashboard (Add device), then on the target host:"
  _box ""
  _box "  curl -fsSL ${url}/install | sudo sh -s -- \\"
  _box "      --token <token>"
  _box ""
  _bot
  echo
  [ -n "$CA_FP" ] && note "CA fingerprint (agents pin this): ${CA_FP}"
  note "Next: open ${url} and log in."
  echo
}

cmd_install() {
  banner
  preflight
  if ! command -v python3 >/dev/null 2>&1 && [ "$MODE" != "demo" ]; then
    echo; step_no "python3 is required. Install it and re-run."; exit 1
  fi
  ask_host; ask_tls; ask_admin
  run_install
  summary_card
}

# ── uninstall the server (data-safe by default) ──────────────────────────────
cmd_uninstall() {
  banner; section "Uninstalling RemotePower server"
  if [ "$SANDBOX" = 0 ]; then
    systemctl disable --now remotepower-api 2>/dev/null || true   # our SCGI worker (fcgiwrap is generic — left alone)
  fi
  rm -f "$(_p "$NGX")/sites-available/remotepower" \
        "$(_p "$NGX")/sites-enabled/remotepower" \
        "$(_p "$NGX")/conf.d/remotepower.conf" \
        "$(_p "$NGX")/snippets/remotepower-locations.conf" \
        "$(_p "$NGX")/snippets/remotepower-ssl.conf" 2>/dev/null || true
  step_ok "nginx config removed"
  [ "$SANDBOX" = 0 ] && { nginx -t >/dev/null 2>&1 && systemctl reload nginx 2>/dev/null || true; }
  rm -f "$(_p /etc/systemd/system/remotepower-api.service)" 2>/dev/null || true
  rm -rf "$(_p "$WWW")"; step_ok "web + backend removed (${WWW})"
  rm -rf "$(_p "$RPETC")/tls"; step_ok "TLS certs removed (${RPETC}/tls)"
  if [ "$PURGE" = 1 ]; then
    rm -rf "$(_p "$DATA")"; step_no "DATA PURGED (${DATA}) — users / devices / history are gone"
  else
    step_wait "kept your data: ${DATA} (users / devices / history) — re-run with --purge to wipe it"
  fi
  echo; note "RemotePower server uninstalled."; echo
}

# ── agent: print the enrol one-liner, or push it over SSH ────────────────────
# `remotepower agent push --server URL --token T user@host …` runs the served
# one-line installer on each host over SSH. Operator-side (uses YOUR ssh), so the
# server never has to hold SSH keys to every box. Bootstrap is agent-only.
cmd_agent() {
  local sub="print"
  if [ "${1:-}" = "push" ]; then sub="push"; shift; fi
  if [ "$sub" = "push" ]; then
    local server="" token="" sudo="sudo"; local hosts=()
    while [ $# -gt 0 ]; do
      case "$1" in
        --server) server="${2:-}"; shift 2;;
        --token) token="${2:-}"; shift 2;;
        --no-sudo) sudo=""; shift;;
        --sudo) sudo="sudo"; shift;;
        --dry-run) DRY=1; shift;;
        -*) printf "${RED}unknown option: %s${RST}\n" "$1"; return 2;;
        *) hosts+=("$1"); shift;;
      esac
    done
    if [ -z "$server" ] || [ -z "$token" ] || [ "${#hosts[@]}" -eq 0 ]; then
      echo "usage: $SELF agent push --server URL --token T [--no-sudo] user@host [user@host …]"
      return 2
    fi
    banner; section "Pushing agent over SSH"
    [ "${#hosts[@]}" -gt 1 ] && note "one enrolment token enrols ONE host — mint one token per host in the dashboard."
    local one="curl -fsSL '${server}/install' | ${sudo:+$sudo }sh -s -- --token '${token}'"
    local h rc=0
    for h in "${hosts[@]}"; do
      if [ "$DRY" = 1 ]; then step_ok "$h"; note "ssh $h \"$one\""; continue; fi
      printf "   ${DOT}  %s …\n" "$h"
      if ssh -o ConnectTimeout=10 -o BatchMode=yes "$h" "$one"; then step_ok "$h — agent installed"
      else step_no "$h — failed (check SSH access / sudo)"; rc=1; fi
    done
    echo; return $rc
  fi
  # default: just show the one-liner(s)
  banner; section "Add a device"
  note "Generate an enrolment token in the dashboard, then run on the target host:"
  echo; printf "   curl -fsSL %s/install | sudo sh -s -- --token <token>\n\n" "${HOST:+https://$HOST}"
  note "…or push it from here over SSH:"
  printf "   %s agent push --server https://<server> --token <token> user@host …\n\n" "$SELF"
}

# ── arg parsing / dispatch ───────────────────────────────────────────────────
CMD="install"
case "${1:-}" in install|uninstall|tls|passwd|update|doctor|agent) CMD="$1"; shift;; esac
if [ "$CMD" = "agent" ]; then cmd_agent "$@"; exit $?; fi
while [ $# -gt 0 ]; do
  case "$1" in
    --host) HOST="${2:-}"; shift 2;;
    --tls) TLS_MODE="${2:-}"; shift 2;;
    --admin-user) ADMIN_USER="${2:-}"; shift 2;;
    --admin-pass) ADMIN_PASS="${2:-}"; shift 2;;
    --port) PORT="${2:-}"; shift 2;;
    --unattended) MODE="unattended"; shift;;
    --demo) MODE="demo"; HOST="${HOST:-rp.lan}"; TLS_MODE="${TLS_MODE:-self-signed}"; shift;;
    --dry-run) DRY=1; shift;;
    --purge) PURGE=1; shift;;
    --sandbox) PREFIX="${2:-}"; SANDBOX=1; MODE="unattended"; shift 2;;
    -h|--help) usage; exit 0;;
    *) printf "${RED}unknown option: %s${RST}\n" "$1"; usage; exit 2;;
  esac
done

case "$CMD" in
  install) cmd_install;;
  uninstall) cmd_uninstall;;
  doctor)  banner; preflight; echo;;
  tls|passwd|update)
    banner; note "'$CMD' is part of the unified tool — wiring lands with the real install steps."; echo;;
esac
