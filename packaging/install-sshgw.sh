#!/usr/bin/env bash
# RemotePower — add the SSH gateway to a server that was installed another way
# (a distribution or AUR package, a hand-built install).
#
#   sudo ./install-sshgw.sh                 # from an unpacked release or a checkout
#   sudo ./install-sshgw.sh --port 22 --public-host gw.example.com
#
# install-server.sh --with-sshgw does the same for a server it installed itself.
# This script is for the rest: the server package ships the application and the
# nginx snippet, not the gateway daemon. It is safe to run again; the shared
# secret is created once, and an upgrade just replaces the daemon and the unit.
#
# What it does:
#   1. checks the server has the gateway API (RemotePower 7.1.0 or newer)
#   2. makes sure asyncssh and websockets are importable
#   3. installs the daemon (/usr/local/bin/remotepower-sshgw) and its systemd unit
#   4. creates the secret the daemon and the API share, and gives it to both
#   5. restarts the app server and starts the gateway
# It does not open a firewall port and does not edit your nginx configuration;
# it tells you what is left. See docs/sshgw.md.
set -euo pipefail

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
die()     { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

usage() {
    cat <<'USAGE'
Usage: install-sshgw.sh [options]

  --src DIR            where server/sshgw and server/conf are (default: this
                       script's release or checkout)
  --web DIR            the RemotePower web root (default /var/www/remotepower)
  --port N             SSH port the gateway listens on (default 2222)
  --public-host NAME   host name people connect to, for the config block they copy
  --no-start           install everything but do not start or restart anything
  -h, --help           this text

Environment: DESTDIR=/some/dir installs under that prefix and touches no service
(for packaging and tests).
USAGE
}

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEB=/var/www/remotepower
SSH_PORT=""
PUBLIC_HOST=""
START=1
while [[ $# -gt 0 ]]; do
    case "$1" in
        --src)         [[ $# -ge 2 ]] || die "--src needs a directory"; SRC="$2"; shift ;;
        --web)         [[ $# -ge 2 ]] || die "--web needs a directory"; WEB="$2"; shift ;;
        --port)        [[ $# -ge 2 ]] || die "--port needs a number"; SSH_PORT="$2"; shift ;;
        --public-host) [[ $# -ge 2 ]] || die "--public-host needs a name"; PUBLIC_HOST="$2"; shift ;;
        --no-start)    START=0 ;;
        -h|--help)     usage; exit 0 ;;
        *)             usage >&2; die "unknown option: $1" ;;
    esac
    shift
done

D="${DESTDIR:-}"
if [[ -n "$D" ]]; then START=0; fi
if [[ -z "$D" && $EUID -ne 0 ]]; then
    die "run as root (sudo $0)"
fi

if [[ -n "$SSH_PORT" ]]; then
    [[ "$SSH_PORT" =~ ^[0-9]{1,5}$ ]] && (( SSH_PORT >= 1 && SSH_PORT <= 65535 )) \
        || die "--port must be a number from 1 to 65535"
fi
if [[ -n "$PUBLIC_HOST" ]]; then
    [[ "$PUBLIC_HOST" =~ ^[A-Za-z0-9._:-]{1,253}$ ]] \
        || die "--public-host may only contain letters, digits, dots, colons and hyphens"
fi

DAEMON_SRC="$SRC/server/sshgw/remotepower-sshgw.py"
UNIT_SRC="$SRC/server/conf/remotepower-sshgw.service"
[[ -f "$DAEMON_SRC" ]] || die "$DAEMON_SRC not found — run this from an unpacked RemotePower 7.1.0 release, or pass --src"
[[ -f "$UNIT_SRC" ]]   || die "$UNIT_SRC not found — run this from an unpacked RemotePower 7.1.0 release, or pass --src"

# ── 1. the server must know about the gateway ─────────────────────────────────
CGI="$D$WEB/cgi-bin"
[[ -f "$CGI/api.py" ]] || die "no RemotePower server found at $WEB (cgi-bin/api.py missing). Pass --web if it lives elsewhere."
[[ -f "$CGI/sshgw_handlers.py" ]] \
    || die "the installed server has no SSH gateway support. Update RemotePower to 7.1.0 or newer first, then run this again."

# ── 2. python dependencies ────────────────────────────────────────────────────
deps_ok() {
    python3 - <<'PY' 2>/dev/null
import sys
import websockets  # noqa: F401
import asyncssh
v = tuple(int(p) for p in asyncssh.__version__.split('.')[:2])
sys.exit(0 if v >= (2, 14) else 1)
PY
}
if [[ -z "$D" ]] && ! deps_ok; then
    info "Installing asyncssh and websockets..."
    if   command -v pacman  &>/dev/null; then pacman -S --needed --noconfirm python-asyncssh python-websockets || true
    elif command -v apt-get &>/dev/null; then apt-get install -y python3-asyncssh python3-websockets || true
    elif command -v dnf     &>/dev/null; then dnf install -y python3-asyncssh python3-websockets || true
    fi
    if ! deps_ok; then
        # The distribution's package can be older than the 2.14 the gateway needs.
        pip3 install 'asyncssh>=2.14.2' 'websockets>=10' --break-system-packages 2>/dev/null \
            || pip3 install 'asyncssh>=2.14.2' 'websockets>=10' || true
    fi
    deps_ok || die "asyncssh (2.14 or newer) and websockets are not importable. Install them and run this again: pip3 install 'asyncssh>=2.14.2' websockets"
fi

# ── 3. the daemon and its unit ────────────────────────────────────────────────
install -d -m 755 "$D/usr/local/bin" "$D/etc/systemd/system" "$D/etc/remotepower"
install -m 0755 "$DAEMON_SRC" "$D/usr/local/bin/remotepower-sshgw"
# The unit points the daemon at the app's cgi-bin; follow a non-default web root.
sed "s#^Environment=RP_CGI_BIN=.*#Environment=RP_CGI_BIN=$WEB/cgi-bin#" "$UNIT_SRC" \
    > "$D/etc/systemd/system/remotepower-sshgw.service"
chmod 644 "$D/etc/systemd/system/remotepower-sshgw.service"
success "Installed the daemon and the remotepower-sshgw unit"

# ── 4. the shared secret ──────────────────────────────────────────────────────
SECRET_FILE="$D/etc/remotepower/sshgw-secret"
API_ENV="$D/etc/remotepower/api.env"
if [[ ! -s "$SECRET_FILE" ]]; then
    ( umask 077; openssl rand -hex 32 > "$SECRET_FILE" )
    info "Created the shared secret"
fi
chmod 600 "$SECRET_FILE"
SECRET="$(tr -d '[:space:]' < "$SECRET_FILE")"
[[ -n "$SECRET" ]] || die "$SECRET_FILE is empty"

# set_env FILE KEY VALUE — one KEY= line, everything else in the file untouched.
set_env() {
    local file="$1" key="$2" value="$3" tmp
    ( umask 077; touch "$file" )
    chmod 600 "$file"
    tmp="$(mktemp "$file.XXXXXX")"
    grep -v "^${key}=" "$file" > "$tmp" || true
    printf '%s=%s\n' "$key" "$value" >> "$tmp"
    chmod 600 "$tmp"
    mv "$tmp" "$file"
}
set_env "$API_ENV" RP_SSHGW_SECRET "$SECRET"

# The app server only sees api.env if its unit reads it. The shipped unit does;
# a unit from elsewhere may not, so add a drop-in rather than edit someone's unit.
WSGI_UNITS=("$D/etc/systemd/system/remotepower-wsgi.service" "$D/usr/lib/systemd/system/remotepower-wsgi.service")
FOUND_UNIT=0; READS_ENV=0
for u in "${WSGI_UNITS[@]}"; do
    if [[ -f "$u" ]]; then
        FOUND_UNIT=1
        grep -q 'EnvironmentFile=.*api\.env' "$u" && READS_ENV=1
    fi
done
DROPIN_DIR="$D/etc/systemd/system/remotepower-wsgi.service.d"
if (( FOUND_UNIT )) && (( ! READS_ENV )) && ! grep -qs 'api\.env' "$DROPIN_DIR"/*.conf 2>/dev/null; then
    install -d -m 755 "$DROPIN_DIR"
    printf '[Service]\nEnvironmentFile=-/etc/remotepower/api.env\n' > "$DROPIN_DIR/sshgw.conf"
    info "remotepower-wsgi did not read api.env; added a drop-in so it picks up the secret"
elif (( ! FOUND_UNIT )); then
    warn "Could not find remotepower-wsgi.service. Make sure your app server reads /etc/remotepower/api.env (it holds RP_SSHGW_SECRET)."
fi

# ── optional daemon settings ──────────────────────────────────────────────────
if [[ -n "$SSH_PORT" ]]; then
    set_env "$D/etc/remotepower/sshgw.env" SSHGW_SSH_PORT "$SSH_PORT"
fi
if [[ -n "$PUBLIC_HOST" ]]; then
    set_env "$D/etc/remotepower/sshgw.env" SSHGW_PUBLIC_HOST "$PUBLIC_HOST"
fi
PORT="${SSH_PORT:-2222}"
if [[ -z "$SSH_PORT" && -f "$D/etc/remotepower/sshgw.env" ]]; then
    p="$(sed -n 's/^SSHGW_SSH_PORT=//p' "$D/etc/remotepower/sshgw.env" | tail -n1)"
    [[ "$p" =~ ^[0-9]+$ ]] && PORT="$p"
fi

# ── nginx: the agents' tunnel route lives in the shared snippet ───────────────
NGINX_OK=1
if [[ -z "$D" ]]; then
    grep -rqs 'location = /api/sshgw/tunnel' /etc/nginx 2>/dev/null || NGINX_OK=0
fi

# ── 5. start it ───────────────────────────────────────────────────────────────
if (( START )); then
    systemctl daemon-reload
    systemctl restart remotepower-wsgi 2>/dev/null || warn "Could not restart remotepower-wsgi — restart your app server so it reads RP_SSHGW_SECRET."
    if systemctl enable remotepower-sshgw && systemctl restart remotepower-sshgw; then
        success "remotepower-sshgw is running (SSH on :$PORT)"
        sleep 2
        fp="$(journalctl -u remotepower-sshgw --no-pager -n 100 2>/dev/null | grep 'host key fingerprint' | tail -n1 || true)"
        [[ -n "$fp" ]] && info "$fp"
    else
        die "Could not start remotepower-sshgw — check: systemctl status remotepower-sshgw"
    fi
else
    info "Not starting anything (--no-start or DESTDIR). To finish: systemctl daemon-reload && systemctl restart remotepower-wsgi && systemctl enable --now remotepower-sshgw"
fi

echo
echo "Still to do:"
n=1
if (( ! NGINX_OK )); then
    echo "  $n. nginx has no route for the agents' tunnel. Install the 7.1.0 snippet and reload:"
    echo "       cp $SRC/server/conf/remotepower-locations.conf /etc/nginx/snippets/remotepower-locations.conf"
    echo "       nginx -t && systemctl reload nginx"
    n=$((n + 1))
fi
echo "  $n. Open TCP $PORT in this server's firewall (the only new port, and it is on this server, not on your fleet)."
n=$((n + 1))
echo "  $n. Settings → Advanced → turn on the SSH gateway module."
n=$((n + 1))
echo "  $n. SSH gateway page: set the public host name, opt hosts in, add your key. See docs/sshgw.md."
