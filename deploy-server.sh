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

info "Deploying api.py..."
install -m 755 "$SCRIPT_DIR/server/cgi-bin/api.py" /var/www/remotepower/cgi-bin/api.py

info "Deploying index.html..."
cp "$SCRIPT_DIR/server/html/index.html" /var/www/remotepower/index.html

info "Deploying remotepower-passwd..."
install -m 755 "$SCRIPT_DIR/server/remotepower-passwd" /var/www/remotepower/cgi-bin/remotepower-passwd

info "Publishing agent binary..."
install -m 755 "$SCRIPT_DIR/client/remotepower-agent" /var/www/remotepower/agent/remotepower-agent

info "Updating agent version in config.json..."
python3 - << 'PYEOF'
import json, re
from pathlib import Path
agent = Path('/var/www/remotepower/agent/remotepower-agent').read_text()
m = re.search(r"VERSION\s*=\s*['\"]([^'\"]+)['\"]", agent)
v = m.group(1) if m else 'unknown'
p = Path('/var/lib/remotepower/config.json')
c = json.loads(p.read_text()) if p.exists() else {}
c['agent_version'] = v
p.write_text(json.dumps(c, indent=2))
print(f"  Agent version → {v}")
PYEOF

success "Done. Changes are live immediately (CGI — no restart needed)."
echo ""
echo "  Enrolled agents will self-update within ~1 hour."
echo "  To trigger immediately on a client: remotepower-agent update"
echo ""
