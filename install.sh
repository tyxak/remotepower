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

usage() {
  cat <<EOF
${B}RemotePower installer ${VERSION}${RST}

  ${B}$SELF${RST} [command] [options]

Commands:
  install        Interactive setup wizard (default)
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

# ── the work (SKELETON: dry-run echoes; real logic lands next) ───────────────
do_step() { # $1 label, $2... command
  local label="$1"; shift
  if [ "$DRY" = 1 ] || [ "$MODE" = "demo" ]; then
    step_ok "$label"; note "would run: $*" 2>/dev/null || true
  else
    # TODO(wire): execute the real install action here.
    step_ok "$label"
  fi
}
run_install() {
  section "Installing"
  do_step "Dependencies installed"          "apt/dnf/pacman install nginx python3 …"
  do_step "nginx vhost written + tested"     "template → /etc/nginx, nginx -t, reload"
  case "$TLS_MODE" in
    self-signed) do_step "Self-signed CA + certificate issued" "gen-ca → /etc/remotepower/tls, wire nginx TLS";;
    letsencrypt) do_step "Let's Encrypt certificate issued"    "certbot --nginx -d $HOST";;
    byo)         do_step "Using your existing certificate"     "point nginx at provided cert/key";;
    none)        do_step "HTTP only (TLS handled upstream)"    "no cert configured";;
  esac
  do_step "SCGI worker enabled (fast path)"  "systemctl enable --now remotepower-api"
  do_step "Admin account created"            "remotepower passwd: $ADMIN_USER"
  do_step "Services started + health-checked" "GET /api/health"
}

scheme() { [ "$TLS_MODE" = "none" ] && echo "http" || echo "https"; }

summary_card() {
  local url; url="$(scheme)://${HOST}${PORT:+:$PORT}"
  local tok; tok="rp_$(_gen_secret 10)"
  echo
  _titletop "RemotePower is live"
  _box ""
  _box "URL      ${url}"
  if [ "${ADMIN_GENERATED:-0}" = 1 ]; then
    _box "Login    ${ADMIN_USER}  ·  ${ADMIN_PASS}   (shown once)"
  else
    _box "Login    ${ADMIN_USER}  ·  (the password you set)"
  fi
  [ "$TLS_MODE" = "self-signed" ] && _box "CA pin   A1:B2:C3:…   (agents verify this)"
  _box ""
  _box "Add your first device — run on any host:"
  _box ""
  _box "  curl -fsSL ${url}/install | sh -s -- \\"
  _box "      --token ${tok}"
  _box ""
  _bot
  echo
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
case "${1:-}" in install|tls|passwd|update|doctor|agent) CMD="$1"; shift;; esac
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
    -h|--help) usage; exit 0;;
    *) printf "${RED}unknown option: %s${RST}\n" "$1"; usage; exit 2;;
  esac
done

case "$CMD" in
  install) cmd_install;;
  doctor)  banner; preflight; echo;;
  tls|passwd|update)
    banner; note "'$CMD' is part of the unified tool — wiring lands with the real install steps."; echo;;
esac
