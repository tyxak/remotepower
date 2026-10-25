#!/bin/bash
# Entrypoint for the `scanner` compose service (Dockerfile.scanner). Waits for
# the `remotepower` service's entrypoint.sh to mint a local scanner token into
# the shared data volume (docker/entrypoint.sh's "Co-located scanner satellite
# token" step), then execs the scanner worker.
set -euo pipefail

DATA_DIR="${RP_DATA_DIR:-/var/lib/remotepower}"
TOKEN_FILE="$DATA_DIR/.scanner-token"

echo "[scanner] waiting for the local scanner token minted by the server container..."
for _ in $(seq 1 60); do
    [ -s "$TOKEN_FILE" ] && break
    sleep 2
done
if [ ! -s "$TOKEN_FILE" ]; then
    echo "[scanner] no token appeared at $TOKEN_FILE after 120s" >&2
    echo "[scanner] is the remotepower service up with RP_WITH_SCANNER=1 (default)?" >&2
    exit 1
fi

# Wait for the server itself. The token above is minted by the server's
# entrypoint before nginx and gunicorn are up, so a scanner that starts at once
# polls an address nobody is listening on yet and logs "connection refused"
# (issue #33). The in-network HTTP port answers /api/health on both nginx
# servers. This is a courtesy and not a gate: if the server never answers the
# worker starts anyway, retries every RP_SCAN_POLL_SECS, and the log says why.
# (docker-compose.yml does not use `depends_on: condition: service_healthy` for
# this: the app's probe runs every 60 s, which would make `docker compose up -d`
# wait that long.)
HEALTH_URL="${RP_HEALTH_URL:-http://remotepower:8080/api/health}"
WAIT_SECS="${RP_SERVER_WAIT_SECS:-120}"
echo "[scanner] waiting for the server at ${HEALTH_URL} ..."
answered=""
for _ in $(seq 1 "$WAIT_SECS"); do
    if python3 -c 'import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=3)' \
            "$HEALTH_URL" 2>/dev/null; then
        answered=1
        break
    fi
    sleep 1
done
if [ -z "$answered" ]; then
    echo "[scanner] the server did not answer at ${HEALTH_URL} within ${WAIT_SECS}s; starting anyway, the worker keeps retrying" >&2
fi

export RP_SATELLITE_TOKEN
RP_SATELLITE_TOKEN="$(cat "$TOKEN_FILE")"
export RP_SERVER_URL="${RP_SERVER_URL:-https://remotepower:8443}"
export RP_CA_BUNDLE="${RP_CA_BUNDLE:-$DATA_DIR/tls/ca.crt}"
export RP_SCAN_RUNNER="${RP_SCAN_RUNNER:-nuclei}"

echo "[scanner] starting — upstream=${RP_SERVER_URL} runner=${RP_SCAN_RUNNER}"
exec python3 "${RP_SCANNER_BIN:-/opt/remotepower/remotepower-scanner.py}"
