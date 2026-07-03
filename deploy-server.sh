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
    # CGI entry points (api_cgi.py shim + api.py) need +x; others are pure imports
    if [[ "$name" == "api.py" || "$name" == "api_cgi.py" ]]; then
        install -m 755 "$f" /var/www/remotepower/cgi-bin/"$name"
    else
        install -m 644 "$f" /var/www/remotepower/cgi-bin/"$name"
    fi
    echo "      → cgi-bin/$name"
done
# Precompile so the CGI user loads cached bytecode: api_cgi.py imports api, and a
# CGI *main script* never uses the .pyc cache, so without this the ~50k-line
# module is recompiled on every request. cgi-bin/ is root-owned (the http user
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

# ── SCGI prefork API worker — update service unit if installed ────────────────
# The shippable unit ships in server/conf/remotepower-api.service. On first
# install it is copied by install-server.sh (as disabled). Here we keep it
# current on every redeploy: if the unit file already exists in systemd, update
# it and reload the daemon; if the service was active, restart it so it picks up
# the new api_worker.py.
SVC_SRC="$SCRIPT_DIR/server/conf/remotepower-api.service"
SVC_DST="/etc/systemd/system/remotepower-api.service"
# The unit loads operator secrets from /etc/remotepower/api.env (EnvironmentFile=,
# e.g. RP_BACKUP_PASSPHRASE). Ensure the dir exists across redeploys so that file
# — which deploy never touches, so the passphrase survives updates — has a home.
[[ -d /etc/remotepower ]] || install -d -m 755 -o root -g root /etc/remotepower 2>/dev/null || true
if [[ -f "$SVC_SRC" ]]; then
    if [[ -f "$SVC_DST" ]]; then
        install -m 644 "$SVC_SRC" "$SVC_DST"
        systemctl daemon-reload
        if systemctl is-active --quiet remotepower-api; then
            systemctl restart remotepower-api
            info "SCGI worker restarted (service was active)"
        else
            info "SCGI worker unit updated (service is not running)"
        fi
    else
        # Not yet installed — copy it so the operator can enable it later
        install -m 644 "$SVC_SRC" "$SVC_DST"
        systemctl daemon-reload
        info "SCGI worker unit installed (not started — enable with: systemctl enable --now remotepower-api)"
    fi
fi

# ── Optional WSGI tier + out-of-band scheduler — keep current + restart ───────
# wsgi.py / scheduler.py already deploy via the *.py glob above (644, importable).
# If the operator has the optional units installed, refresh them and — because a
# persistent process won't pick up the freshly-deployed code on its own — restart
# any that are running (same reason the SCGI worker is restarted above). No-op
# when neither unit is installed (the default CGI deployment).
for _svc in remotepower-wsgi remotepower-scheduler; do
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

info "Publishing agent binary..."
install -m 755 "$SCRIPT_DIR/client/remotepower-agent" /var/www/remotepower/agent/remotepower-agent

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

success "Done. Changes are live immediately (CGI — no restart needed)."
echo ""
echo "  Enrolled agents will self-update within ~1 hour."
echo "  To trigger immediately on a client: remotepower-agent update"
echo ""
echo "  TLS / DNS expiry probes are scheduled by the server itself (~6h per"
echo "  target) — no cron needed. The optional standalone runner remains at:"
echo "    /var/www/remotepower/cgi-bin/remotepower-tls-check"
echo ""
echo "  If you run the optional WSGI tier or out-of-band scheduler, the deploy"
echo "  restarted them automatically; otherwise restart manually to load new code:"
echo "    systemctl restart remotepower-wsgi remotepower-scheduler"
echo ""
