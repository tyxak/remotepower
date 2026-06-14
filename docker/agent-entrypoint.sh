#!/bin/sh
# RemotePower containerized agent entrypoint (v4.7.0).
#
# Makes binding a Docker host to the server trivial: set RP_SERVER + RP_ENROLL_TOKEN
# and start the container. On first boot it enrolls (naming the device after the
# HOST, not the container id) and persists credentials to /etc/remotepower
# (a mounted volume); every later start reuses them and just runs.
set -eu

CREDS=/etc/remotepower/credentials
AGENT=/usr/local/bin/remotepower-agent
HOST_ROOT="${HOST_ROOT:-/host}"

log() { echo "[entrypoint] $*"; }

# Accept either RP_ENROLL_TOKEN (preferred, matches RP_SERVER) or the agent's
# native REMOTEPOWER_ENROLL_TOKEN.
RP_ENROLL_TOKEN="${RP_ENROLL_TOKEN:-${REMOTEPOWER_ENROLL_TOKEN:-}}"

already_enrolled() {
    [ -s "$CREDS" ] && grep -q '"token"' "$CREDS" 2>/dev/null
}

# Optional fingerprint-pinned CA fetch, for servers using the self-signed CA
# (RP_CA_FINGERPRINT). Mirrors install-client.sh: fetch the CA over plain HTTP
# and refuse to trust it unless its SHA-256 fingerprint matches — so a MITM on
# that first, pre-TLS fetch cannot substitute its own CA.
install_ca() {
    [ -n "${RP_CA_FINGERPRINT:-}" ] || return 0
    [ -f /etc/remotepower/ca.crt ] && return 0
    host=$(printf '%s' "$RP_SERVER" | sed -E 's#^https?://##; s#/.*$##')
    log "Fetching CA from http://$host/ca.crt for fingerprint pinning…"
    if ! curl -fsS "http://$host/ca.crt" -o /tmp/ca.crt; then
        log "ERROR: could not fetch CA from http://$host/ca.crt"; return 1
    fi
    got=$(openssl x509 -in /tmp/ca.crt -noout -fingerprint -sha256 2>/dev/null \
          | sed 's/^.*=//; s/://g' | tr 'A-F' 'a-f')
    want=$(printf '%s' "$RP_CA_FINGERPRINT" | sed 's/://g' | tr 'A-F' 'a-f')
    if [ -z "$got" ] || [ "$got" != "$want" ]; then
        log "ERROR: CA fingerprint mismatch (got '$got', want '$want') — refusing to trust"
        return 1
    fi
    mv /tmp/ca.crt /etc/remotepower/ca.crt
    log "CA verified + installed at /etc/remotepower/ca.crt"
}

host_name() {
    # The HOST's hostname (so the device isn't named after the container id).
    if [ -n "${RP_DEVICE_NAME:-}" ]; then
        printf '%s' "$RP_DEVICE_NAME"; return
    fi
    if [ -r "$HOST_ROOT/etc/hostname" ]; then
        head -n1 "$HOST_ROOT/etc/hostname" | tr -d '[:space:]'; return
    fi
    hostname
}

if already_enrolled; then
    log "Already enrolled — reusing $CREDS"
else
    : "${RP_SERVER:?RP_SERVER is required for first-time enrollment (e.g. https://remote.example.com)}"
    : "${RP_ENROLL_TOKEN:?RP_ENROLL_TOKEN (or REMOTEPOWER_ENROLL_TOKEN) is required for first-time enrollment}"
    install_ca
    [ -f /etc/remotepower/ca.crt ] && export RP_CA_BUNDLE="${RP_CA_BUNDLE:-/etc/remotepower/ca.crt}"
    name=$(host_name)
    log "Enrolling '$name' with $RP_SERVER …"
    "$AGENT" enroll-token --server "$RP_SERVER" --token "$RP_ENROLL_TOKEN" --name "$name"
fi

# Self-signed CA also needed by the run loop.
[ -f /etc/remotepower/ca.crt ] && export RP_CA_BUNDLE="${RP_CA_BUNDLE:-/etc/remotepower/ca.crt}"

log "Starting agent (HOST_ROOT=$HOST_ROOT, interval=${RP_INTERVAL:-60}s)…"
exec "$AGENT" run --interval "${RP_INTERVAL:-60}"
