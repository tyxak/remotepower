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

info "Deploying all cgi-bin Python modules..."
# Auto-discovers api.py plus all sibling modules (cve_scanner.py, prometheus_export.py,
# and any future ones) — no need to edit this script when adding a new module.
for f in "$SCRIPT_DIR"/server/cgi-bin/*.py; do
    name="$(basename "$f")"
    # api.py needs +x for CGI; others are pure imports
    if [[ "$name" == "api.py" ]]; then
        install -m 755 "$f" /var/www/remotepower/cgi-bin/"$name"
    else
        install -m 644 "$f" /var/www/remotepower/cgi-bin/"$name"
    fi
    echo "      → cgi-bin/$name"
done

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

info "Deploying static HTML files..."
# Auto-discovers index.html plus any sibling pages (swagger.html in v1.10.0,
# whatever future pages get added) — no need to edit this script when adding
# a new HTML file.
for f in "$SCRIPT_DIR"/server/html/*.html; do
    name="$(basename "$f")"
    install -m 644 "$f" /var/www/remotepower/"$name"
    echo "      → $name"
done

info "Deploying remotepower-passwd..."
install -m 755 "$SCRIPT_DIR/server/remotepower-passwd" /var/www/remotepower/cgi-bin/remotepower-passwd

info "Publishing agent binary..."
install -m 755 "$SCRIPT_DIR/client/remotepower-agent" /var/www/remotepower/agent/remotepower-agent

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

success "Done. Changes are live immediately (CGI — no restart needed)."
echo ""
echo "  Enrolled agents will self-update within ~1 hour."
echo "  To trigger immediately on a client: remotepower-agent update"
echo ""
echo "  v1.11.0: TLS / DNS expiry probe is at:"
echo "    /var/www/remotepower/cgi-bin/remotepower-tls-check"
echo "  To run it on a schedule, add a systemd timer or cron entry, e.g.:"
echo "    0 */6 * * * www-data /var/www/remotepower/cgi-bin/remotepower-tls-check"
echo ""
