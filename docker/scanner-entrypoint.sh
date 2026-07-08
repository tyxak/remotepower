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

export RP_SATELLITE_TOKEN
RP_SATELLITE_TOKEN="$(cat "$TOKEN_FILE")"
export RP_SERVER_URL="${RP_SERVER_URL:-https://remotepower:8443}"
export RP_CA_BUNDLE="${RP_CA_BUNDLE:-$DATA_DIR/tls/ca.crt}"
export RP_SCAN_RUNNER="${RP_SCAN_RUNNER:-nuclei}"

echo "[scanner] starting — upstream=${RP_SERVER_URL} runner=${RP_SCAN_RUNNER}"
exec python3 /opt/remotepower/remotepower-scanner.py
