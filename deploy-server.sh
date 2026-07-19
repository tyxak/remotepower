#!/usr/bin/env bash
# RemotePower — quick redeploy after git pull
# Does NOT touch Nginx config, users.json, or config.json
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[*]${NC} $*"; }
success() { echo -e "${GREEN}[✓]${NC} $*"; }
die()     { echo -e "${RED}[✗]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && die "Run as root: sudo bash deploy-server.sh"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEB_ROOT="/var/www/remotepower"
BACKUP_DIR="/var/backups/remotepower-deploys"

# ── v4.3.0: pre-deploy backup + rollback ─────────────────────────────────────
# Every deploy first snapshots the currently-deployed tree (code only — the
# data dir is untouched by this script) and keeps the last 3.
#   sudo bash deploy-server.sh --rollback     restores the newest snapshot.
# NOTE: rollback restores CODE only. If the newer version migrated the
# database schema, also restore the matching data backup — the server logs a
# loud schema-newer-than-code warning on every request in that state.
if [[ "${1:-}" == "--rollback" ]]; then
    latest="$(ls -1t "$BACKUP_DIR"/deploy_*.tar.gz 2>/dev/null | head -1 || true)"
    [[ -z "$latest" ]] && die "No deploy backups found in $BACKUP_DIR"
    info "Rolling back to $(basename "$latest") ..."
    tar -xzf "$latest" -C "$(dirname "$WEB_ROOT")"
    success "Rolled back. If the database was migrated by the newer version,"
    success "restore the matching data backup too (watch the nginx error log"
    success "for a 'schema is NEWER than this server' warning)."
    exit 0
fi

if [[ -d "$WEB_ROOT" ]]; then
    mkdir -p -m 700 "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"   # also tighten a pre-existing dir
    stamp="$(date +%Y%m%d-%H%M%S)"
    info "Backing up current deployment → $BACKUP_DIR/deploy_$stamp.tar.gz"
    tar -czf "$BACKUP_DIR/deploy_$stamp.tar.gz" \
        -C "$(dirname "$WEB_ROOT")" "$(basename "$WEB_ROOT")"
    # keep the 3 newest snapshots
    ls -1t "$BACKUP_DIR"/deploy_*.tar.gz 2>/dev/null | tail -n +4 | xargs -r rm -f
fi

info "Deploying all cgi-bin Python modules..."
# Auto-discovers api.py plus all sibling modules (cve_scanner.py, prometheus_export.py,
# and any future ones) — no need to edit this script when adding a new module.
for f in "$SCRIPT_DIR"/server/cgi-bin/*.py; do
    name="$(basename "$f")"
    # wsgi.py (the gunicorn entry point) + api.py need +x; others are pure imports
    if [[ "$name" == "api.py" || "$name" == "wsgi.py" ]]; then
        install -m 755 "$f" /var/www/remotepower/cgi-bin/"$name"
    else
        install -m 644 "$f" /var/www/remotepower/cgi-bin/"$name"
    fi
    echo "      → cgi-bin/$name"
done
# Precompile so gunicorn loads cached bytecode instead of recompiling the
# ~50k-line module on first request. cgi-bin/ is root-owned (the http user
# can't write __pycache__ itself), so build it now. Re-run on every deploy so a
# replaced api.py is recompiled rather than recompiled-per-request.
python3 -m compileall -q /var/www/remotepower/cgi-bin/ || true

# v1.11.0: extension-less helper scripts (remotepower-tls-check is the cron
# runner for the TLS expiry probe). Same directory as api.py because they
# need to import the sibling modules with the same sys.path layout.
info "Deploying cgi-bin helper scripts..."
for helper in remotepower-tls-check; do
    src="$SCRIPT_DIR/server/cgi-bin/$helper"
    if [[ -f "$src" ]]; then
        install -m 755 "$src" /var/www/remotepower/cgi-bin/"$helper"
        echo "      → cgi-bin/$helper"
    fi
done

# v5.2.0: WG Access privileged helper + scoped sudoers. The road-warrior
# WireGuard feature drives kernel WireGuard (or wireguard-go) + nft via this
# root-owned helper, invoked ONLY through a single-script NOPASSWD sudoers rule
# (the CGI stays unprivileged) — the deploy-remote-site.sh precedent. Detect the
# web user (http on Arch, www-data on Debian). The feature stays "unavailable"
# in the UI until the WireGuard CLI is also installed (apt install wireguard
# wireguard-tools / pacman -S wireguard-tools).
if [[ -f "$SCRIPT_DIR/packaging/remotepower-wg-apply" ]]; then
    info "Deploying WG Access helper + scoped sudoers..."
    if getent passwd http >/dev/null 2>&1; then WEB_USER=http; else WEB_USER=www-data; fi
    install -d -m 755 -o root -g root /usr/local/sbin
    install -m 755 -o root -g root "$SCRIPT_DIR/packaging/remotepower-wg-apply" \
        /usr/local/sbin/remotepower-wg-apply
    _wg_sudoers="$(mktemp)"
    printf '%s ALL=(root) NOPASSWD: /usr/local/sbin/remotepower-wg-apply\n' "$WEB_USER" > "$_wg_sudoers"
    if visudo -cf "$_wg_sudoers" >/dev/null 2>&1; then
        install -m 440 -o root -g root "$_wg_sudoers" /etc/sudoers.d/remotepower-wg
        echo "      → /usr/local/sbin/remotepower-wg-apply (+ sudoers for $WEB_USER)"
    else
        echo "      ! WG Access sudoers validation failed — skipped"
    fi
    rm -f "$_wg_sudoers"
fi

# v6.1.2: "Restart server" scoped helper + sudoers. Same single-script NOPASSWD
# model as the WG helper above — the API user may run ONLY this one script as
# root, and the script re-execs itself under `sudo -n` to `systemctl restart` the
# app-server unit. Grants no privilege an admin doesn't already have via
# self-update. The button stays hidden in the UI until this is present.
if [[ -f "$SCRIPT_DIR/packaging/remotepower-server-restart.sh" ]]; then
    info "Deploying server-restart helper + scoped sudoers..."
    if getent passwd http >/dev/null 2>&1; then WEB_USER=http; else WEB_USER=www-data; fi
    install -d -m 755 -o root -g root /usr/local/sbin
    install -m 755 -o root -g root "$SCRIPT_DIR/packaging/remotepower-server-restart.sh" \
        /usr/local/sbin/remotepower-server-restart
    _rst_sudoers="$(mktemp)"
    printf '%s ALL=(root) NOPASSWD: /usr/local/sbin/remotepower-server-restart\n' "$WEB_USER" > "$_rst_sudoers"
    if visudo -cf "$_rst_sudoers" >/dev/null 2>&1; then
        install -m 440 -o root -g root "$_rst_sudoers" /etc/sudoers.d/remotepower-self-restart
        echo "      → /usr/local/sbin/remotepower-server-restart (+ sudoers for $WEB_USER)"
    else
        echo "      ! server-restart sudoers validation failed — skipped"
    fi
    rm -f "$_rst_sudoers"
fi

info "Deploying static HTML files..."
# Auto-discovers index.html plus any sibling pages (swagger.html in v1.10.0,
# whatever future pages get added) — no need to edit this script when adding
# a new HTML file.
for f in "$SCRIPT_DIR"/server/html/*.html; do
    name="$(basename "$f")"
    install -m 644 "$f" /var/www/remotepower/"$name"
    echo "      → $name"
done

# v2.2.5: deploy root-level non-HTML assets (favicon.png, robots.txt, etc).
# The HTML loop above only catches *.html; before 2.2.5 favicon.png at the
# document root never got published, so /favicon.png returned 404 in the
# browser. The favicon MUST stay at the root — not under /static/ — so
# browsers find it via the conventional /favicon.png URL without a
# <link rel="icon"> tag detour.
for f in "$SCRIPT_DIR"/server/html/favicon.* \
         "$SCRIPT_DIR"/server/html/robots.txt \
         "$SCRIPT_DIR"/server/html/manifest.json \
         "$SCRIPT_DIR"/server/html/sw.js; do
    [[ -f "$f" ]] || continue
    name="$(basename "$f")"
    install -m 644 "$f" /var/www/remotepower/"$name"
    echo "      → $name"
done

# v3.4.0: deploy product Markdown docs into the DATA dir so the RAG indexer can
# read them at runtime — RAG_DOCS_DIR defaults to /var/lib/remotepower/docs.
RP_DATA_DIR_DEPLOY="${RP_DATA_DIR:-/var/lib/remotepower}"
if compgen -G "$SCRIPT_DIR/docs/*.md" > /dev/null; then
    info "Deploying product docs for RAG indexing..."
    mkdir -p "$RP_DATA_DIR_DEPLOY/docs"
    install -m 644 "$SCRIPT_DIR"/docs/*.md "$RP_DATA_DIR_DEPLOY/docs/"
    # Match ownership of the data dir so the CGI user can read them.
    if [[ -d "$RP_DATA_DIR_DEPLOY" ]]; then
        chown --reference="$RP_DATA_DIR_DEPLOY" -R "$RP_DATA_DIR_DEPLOY/docs" 2>/dev/null || true
    fi
    echo "      → $RP_DATA_DIR_DEPLOY/docs/ ($(compgen -G "$SCRIPT_DIR/docs/*.md" | wc -l) files)"
fi

# Also publish the docs under the web root so the in-app "Documentation" links
# (href="docs/<name>.md") resolve instead of 404ing. nginx serves them as plain
# text — they're public product docs, safe to expose. Ship the .html docs too.
if compgen -G "$SCRIPT_DIR/docs/*.md" > /dev/null || compgen -G "$SCRIPT_DIR/docs/*.html" > /dev/null; then
    info "Publishing docs to the web root..."
    mkdir -p /var/www/remotepower/docs
    install -m 644 "$SCRIPT_DIR"/docs/*.md   /var/www/remotepower/docs/ 2>/dev/null || true
    install -m 644 "$SCRIPT_DIR"/docs/*.html /var/www/remotepower/docs/ 2>/dev/null || true
    echo "      → /var/www/remotepower/docs/"
fi

# v2.0: deploy /static/ tree (logos, future CSS/JS extraction targets).
# rsync rather than cp -r so re-runs don't fail on existing-dir.
if [[ -d "$SCRIPT_DIR/server/html/static" ]]; then
    info "Deploying static assets (logos, etc.)..."
    mkdir -p /var/www/remotepower/static
    rsync -a --delete "$SCRIPT_DIR/server/html/static/" /var/www/remotepower/static/
    chown -R root:root /var/www/remotepower/static
    find /var/www/remotepower/static -type f -exec chmod 644 {} \;
    find /var/www/remotepower/static -type d -exec chmod 755 {} \;
    echo "      → static/ ($(find /var/www/remotepower/static -type f | wc -l) files)"
fi

info "Deploying remotepower-passwd..."
install -m 755 "$SCRIPT_DIR/server/remotepower-passwd" /var/www/remotepower/cgi-bin/remotepower-passwd

# `rp` — omd/checkmk-style node control (rp status|tui|start|stop|restart|doctor).
info "Deploying rp (node-control CLI)..."
install -m 755 "$SCRIPT_DIR/server/rp" /usr/local/bin/rp
# Record the source checkout (so `rp install/deploy/repair` finds these scripts)
# and the storage backend NAME (so a non-root `rp status`/`rp tui` can show it
# without reading the 0700 data dir — only the harmless name, never the DSN).
install -d -m 755 /etc/remotepower 2>/dev/null || true
{ printf 'RP_SRC=%s\n' "$SCRIPT_DIR"
  _rpbe=$(python3 -c "import json;print(json.load(open('/var/lib/remotepower/storage_backend.json')).get('backend','json'))" 2>/dev/null)
  [ -n "$_rpbe" ] && printf 'RP_BACKEND=%s\n' "$_rpbe"
} > /etc/remotepower/rp.env 2>/dev/null || true
echo "      → /usr/local/bin/rp"

# Agent push (wake-nudge) daemon binary — keep the INSTALLED copy current on
# every deploy. Deploying only a running binary and not this canonical one is
# exactly what silently reverts a daemon fix; deploy owns the source of truth.
if [[ -f /usr/local/bin/remotepower-push ]] \
        || systemctl list-unit-files 2>/dev/null | grep -q '^remotepower-push\.service'; then
    info "Deploying the agent push daemon binary..."
    install -m 755 "$SCRIPT_DIR/server/push/remotepower-push.py" /usr/local/bin/remotepower-push
    echo "      → /usr/local/bin/remotepower-push"
fi

# Refresh the shipped nginx locations snippet (push/webterm routes) IF this box
# uses it — a hand-maintained vhost that doesn't include the snippet is left
# untouched. Add the $connection_upgrade map to conf.d only if none exists.
if [[ -f /etc/nginx/snippets/remotepower-locations.conf ]]; then
    install -m 644 "$SCRIPT_DIR/server/conf/remotepower-locations.conf" \
        /etc/nginx/snippets/remotepower-locations.conf
    if command -v nginx >/dev/null 2>&1 \
            && ! nginx -T 2>/dev/null | grep -q 'map \$http_upgrade \$connection_upgrade'; then
        mkdir -p /etc/nginx/conf.d
        install -m 644 "$SCRIPT_DIR/server/conf/remotepower-ws-map.conf" \
            /etc/nginx/conf.d/remotepower-ws-map.conf
    fi
    command -v nginx >/dev/null 2>&1 && nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null || true
    echo "      → nginx locations snippet refreshed"
fi

# The unit loads operator secrets from /etc/remotepower/api.env (EnvironmentFile=,
# e.g. RP_BACKUP_PASSPHRASE). Ensure the dir exists across redeploys so that file
# — which deploy never touches, so the passphrase survives updates — has a home.
[[ -d /etc/remotepower ]] || install -d -m 755 -o root -g root /etc/remotepower 2>/dev/null || true

# ── Flask/gunicorn present before we (re)start the app server ────────────────
# Found live on a real upgrade: a pre-v6.1.0 "experimental" opt-in WSGI
# bridge used the SAME remotepower-wsgi.service unit name without needing
# Flask. This script only ever redeploys CODE (never installs packages, by
# design — see the header), so restarting remotepower-wsgi after deploying
# this session's Flask-based wsgi.py onto such a box crash-looped every
# worker on ModuleNotFoundError. Installing a genuinely missing hard
# dependency isn't optional anymore the way it was pre-6.1.0 — check and
# install it here rather than let the restart below discover it by crashing.
if systemctl list-unit-files 2>/dev/null | grep -q '^remotepower-wsgi\.service' \
        && ! python3 -c "import flask" 2>/dev/null; then
    info "Flask not found but remotepower-wsgi is installed — installing it now..."
    if   command -v apt-get >/dev/null 2>&1; then _pm=apt
    elif command -v dnf     >/dev/null 2>&1; then _pm=dnf
    elif command -v pacman  >/dev/null 2>&1; then _pm=pacman
    else _pm=""; fi
    case "$_pm" in
      apt)    apt-get install -y --no-install-recommends python3-flask 2>/dev/null \
                || pip3 install flask --break-system-packages 2>/dev/null \
                || pip3 install flask ;;
      dnf)    dnf install -y -q python3-flask 2>/dev/null || pip3 install flask ;;
      pacman) pacman -S --noconfirm python-flask 2>/dev/null || pip install flask ;;
      *)      pip3 install flask --break-system-packages 2>/dev/null || pip3 install flask ;;
    esac
    python3 -c "import flask" 2>/dev/null \
        && success "flask installed" \
        || echo "      → WARNING: flask install failed — remotepower-wsgi will fail to start. Run install-server.sh instead." >&2
    command -v gunicorn >/dev/null 2>&1 || {
        case "$_pm" in
          apt)    apt-get install -y --no-install-recommends gunicorn 2>/dev/null || pip3 install gunicorn --break-system-packages 2>/dev/null || pip3 install gunicorn ;;
          dnf)    dnf install -y -q python3-gunicorn 2>/dev/null || pip3 install gunicorn ;;
          pacman) pacman -S --noconfirm gunicorn 2>/dev/null || pip install gunicorn ;;
          *)      pip3 install gunicorn --break-system-packages 2>/dev/null || pip3 install gunicorn ;;
        esac
        [[ -x /usr/bin/gunicorn ]] || ln -sf "$(command -v gunicorn)" /usr/bin/gunicorn 2>/dev/null || true
    }
fi

# ── App server (gunicorn) + out-of-band scheduler — keep current + restart ───
# wsgi.py / scheduler.py already deploy via the *.py glob above (644, importable).
# The units themselves were installed by install-server.sh; refresh them here and
# — because a persistent process won't pick up the freshly-deployed code on its
# own — restart any that are running so the redeploy actually takes effect.
# remotepower-push is included: its binary was just redeployed above, so a
# running daemon must restart to pick it up (and its unit refreshes too).
for _svc in remotepower-wsgi remotepower-scheduler remotepower-push; do
    _src="$SCRIPT_DIR/server/conf/${_svc}.service"
    _dst="/etc/systemd/system/${_svc}.service"
    if [[ -f "$_src" && -f "$_dst" ]]; then
        install -m 644 "$_src" "$_dst"
        systemctl daemon-reload
        if systemctl is-active --quiet "$_svc"; then
            systemctl restart "$_svc"
            info "${_svc} restarted (service was active)"
        fi
    fi
done

# ── Optional sidecar daemons installed as COPIES outside the deploy tree ─────
# The webterm daemon (/usr/local/bin, via packaging/install-webterm.sh) and the
# scanner satellite (/opt/remotepower, via packaging/scanner-setup.sh) run from
# file COPIES the deploy glob above never touches — so after a redeploy they
# keep running (and keep restarting into) OLD code. Refresh the copy and
# restart the unit when active. (The v6.2.3 webterm deprecation-warning fix sat
# dead on live hosts exactly this way.) A webterm restart drops live terminal
# sessions — acceptable during a deploy, which restarts the app server anyway.
if [[ -f /usr/local/bin/remotepower-webterm ]]; then
    install -m 755 "$SCRIPT_DIR/server/webterm/remotepower-webterm.py" \
        /usr/local/bin/remotepower-webterm
    # ⛔ NEVER copy packaging/remotepower-webterm.service over the installed
    # unit: install-webterm.sh RENDERS it per host (sed's in the chosen
    # --daemon-user and CGI group). The raw template hardcodes rp-webterm/
    # rp-www — overwriting a rendered unit bricks the service with 217/USER
    # on any host that picked different names (bit tviweb01, 2026-07-19).
    # Unit changes ship via install-webterm.sh re-runs only.
    if systemctl is-active --quiet remotepower-webterm 2>/dev/null; then
        systemctl restart remotepower-webterm
        info "remotepower-webterm refreshed + restarted (service was active)"
    else
        info "remotepower-webterm binary refreshed"
    fi
fi
# Scanner unit is GENERATED by scanner-setup.sh (embeds per-install env) — only
# the code copy is refreshed here, never the unit.
if [[ -f /opt/remotepower/remotepower-scanner.py ]]; then
    install -m 755 "$SCRIPT_DIR/client/remotepower-scanner.py" \
        /opt/remotepower/remotepower-scanner.py
    if systemctl is-active --quiet remotepower-scanner 2>/dev/null; then
        systemctl restart remotepower-scanner
        info "remotepower-scanner refreshed + restarted (service was active)"
    fi
fi

# The public read-only demo (packaging/install-demo.sh) runs its OWN gunicorn
# instance, remotepower-wsgi-demo, off the SAME shared code but a separate data
# dir + port. Its unit is generated by install-demo.sh (not shipped in
# server/conf/), so the loop above skips it — but as a persistent worker pool it
# keeps serving the OLD code (and the OLD version banner) until restarted. Restart
# it whenever it's present so a deploy doesn't leave the demo stuck a version
# behind. No-op on installs without a demo.
if systemctl is-active --quiet remotepower-wsgi-demo 2>/dev/null; then
    systemctl restart remotepower-wsgi-demo
    info "remotepower-wsgi-demo restarted (demo instance was active)"
fi

info "Publishing agent binary..."
install -m 755 "$SCRIPT_DIR/client/remotepower-agent" /var/www/remotepower/agent/remotepower-agent

# v6.2.0: also publish the Windows + macOS agents. The server serves these at
# /api/agent/{win,mac}/download and bakes the Windows one-liner (/install.ps1)
# and self-update around them. Publishing ONLY the Linux agent (as this script
# did until v6.2.0) left those endpoints 404-ing and the Windows install
# one-liner dead on every deployed server — the served installer downloads the
# agent from /api/agent/win/download, which needs this file present.
for _rp_os_agent in remotepower-agent-win.py remotepower-agent-mac.py; do
    if [[ -f "$SCRIPT_DIR/client/$_rp_os_agent" ]]; then
        install -m 644 "$SCRIPT_DIR/client/$_rp_os_agent" "/var/www/remotepower/agent/$_rp_os_agent"
    fi
done

# Re-sign the freshly-published binary if a server signing key exists. Publishing
# a new binary leaves the previous detached signature stale, which the Release
# Signing page (correctly) flags as "signed but INVALID" after every deploy. If
# the operator set up server-side signing, keep it valid automatically: re-sign
# the new binary with the held key and re-sync the public key + fingerprint into
# config so the self-check passes. (CI/off-server signing is unaffected — there's
# no server key, so this is a no-op and the operator re-signs in their pipeline.)
SIGNING_HOME="$RP_DATA_DIR_DEPLOY/signing-gpg"
AGENT_PUB="/var/www/remotepower/agent/remotepower-agent"
if command -v gpg >/dev/null 2>&1 && [[ -d "$SIGNING_HOME" ]]; then
    FPR="$(GNUPGHOME="$SIGNING_HOME" gpg --batch --list-secret-keys --with-colons 2>/dev/null \
           | awk -F: '/^fpr:/{print $10; exit}')"
    if [[ -n "$FPR" ]]; then
        info "Re-signing published agent with server key ${FPR:0:16}…"
        if GNUPGHOME="$SIGNING_HOME" gpg --batch --yes --armor --detach-sign \
               -u "$FPR" -o "${AGENT_PUB}.asc" "$AGENT_PUB" 2>/dev/null; then
            # Re-sync release_pubkey + fingerprint into config so the server
            # self-check verifies against the key we just signed with.
            PUB="$(GNUPGHOME="$SIGNING_HOME" gpg --batch --armor --export "$FPR" 2>/dev/null)" \
            FPR="$FPR" CFG="$RP_DATA_DIR_DEPLOY/config.json" python3 - << 'PYEOF'
import json, os
from pathlib import Path
p = Path(os.environ['CFG'])
c = json.loads(p.read_text()) if p.exists() else {}
c['release_pubkey'] = os.environ.get('PUB', '') or c.get('release_pubkey', '')
c['release_key_fingerprint'] = os.environ.get('FPR', '').upper()
p.write_text(json.dumps(c, indent=2))
PYEOF
            echo "      → agent re-signed; release signature valid"
        else
            echo "      → WARNING: re-sign failed; Release Signing will show INVALID until you re-sign in the UI" >&2
        fi
    fi
fi

info "Updating versions in config.json..."
python3 - << 'PYEOF'
import json, re
from pathlib import Path

p = Path('/var/lib/remotepower/config.json')
c = json.loads(p.read_text()) if p.exists() else {}

# Agent version — read from deployed binary
agent = Path('/var/www/remotepower/agent/remotepower-agent').read_text()
m = re.search(r"VERSION\s*=\s*['\"]([^'\"]+)['\"]", agent)
agent_v = m.group(1) if m else 'unknown'
c['agent_version'] = agent_v

# Server version — read from deployed api.py
api = Path('/var/www/remotepower/cgi-bin/api.py').read_text()
m = re.search(r"SERVER_VERSION\s*=\s*['\"]([^'\"]+)['\"]", api)
server_v = m.group(1) if m else agent_v
c['server_version'] = server_v

p.write_text(json.dumps(c, indent=2))
print(f"  Agent version  → {agent_v}")
print(f"  Server version → {server_v}")
PYEOF

# v3.0.5: per-file content-hash cache-busting for the linked /static/
# assets in index.html. Without this, every JS/CSS change between
# releases requires operators to manually clear browser cache or
# unregister the service worker — the ?v=<server_version> query string
# only bumps when SERVER_VERSION bumps, not when code changes.
#
# Each `<script src="static/X.js?v=...">` and `<link href="static/X.css?v=...">`
# reference in the *deployed* index.html gets rewritten to carry the
# first 12 chars of the SHA-256 of that file's content. The repo's
# index.html is left untouched (tests assert ?v=<SERVER_VERSION> there).
info "Rewriting ?v= query strings to per-file content hashes..."
python3 - << 'PYEOF'
import hashlib, re
from pathlib import Path

WEB_ROOT = Path('/var/www/remotepower')
INDEX    = WEB_ROOT / 'index.html'
if not INDEX.is_file():
    raise SystemExit('  index.html missing — skipping cache-bust step')

html = INDEX.read_text()
edits = 0

def _hash(rel_path: str) -> str:
    p = WEB_ROOT / rel_path.lstrip('/')
    if not p.is_file():
        return ''
    return hashlib.sha256(p.read_bytes()).hexdigest()[:12]

def _replace(match: re.Match) -> str:
    global edits
    tag, rel = match.group(1), match.group(2)
    h = _hash(rel)
    if not h:
        return match.group(0)  # file missing — leave alone
    edits += 1
    return f'{tag}"{rel}?v={h}"'

# <script src="static/…?v=…">
html = re.sub(r'(<script\s+src=)"((?:static|/static)/[^"?]+)\?v=[^"]+"', _replace, html)
# <link  href="static/…?v=…">
html = re.sub(r'(<link [^>]*href=)"((?:static|/static)/[^"?]+)\?v=[^"]+"', _replace, html)

INDEX.write_text(html)
print(f"  Rewrote {edits} ?v= reference(s) in deployed index.html to content hashes")
PYEOF

success "Done. gunicorn (remotepower-wsgi) and the scheduler, if active, were"
echo "  already restarted above to pick up the new code."
echo ""
echo "  Enrolled agents will self-update within ~1 hour."
echo "  To trigger immediately on a client: remotepower-agent update"
echo ""
echo "  TLS / DNS expiry probes are scheduled by the server itself (~6h per"
echo "  target) — no cron needed. The optional standalone runner remains at:"
echo "    /var/www/remotepower/cgi-bin/remotepower-tls-check"
echo ""
echo "  If remotepower-wsgi/remotepower-scheduler weren't active (not yet"
echo "  installed as systemd units), start them once via:"
echo "    sudo bash install-server.sh   (or: sudo bash install.sh update)"
echo ""
