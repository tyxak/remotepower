#!/usr/bin/env bash
# RemotePower — self-signed CA + server-leaf generator (v4.5.0 "TrustMatters").
#
# Generates a small PRIVATE CA and a server LEAF certificate signed by it, for
# RemotePower instances that cannot use a real (Let's Encrypt) cert — airgapped
# / internal-only / no-public-DNS deployments.
#
# WHY a CA and not a bare self-signed cert: agents trust the CA (ca.crt), not the
# leaf — so you can renew/re-issue the server cert (`--renew`) without touching a
# single client. The agent already consumes the CA via RP_CA_BUNDLE, keeping full
# verification (CERT_REQUIRED + hostname check + TLS 1.2 floor).
#
# PREFER A REAL CERT. See docs/tls-selfsigned.md for the decision tree and the
# self-signed -> real migration (which is a server-only nginx change).
#
# Usage (minimal):
#   sudo tools/gen-ca.sh --host rp.internal
#
# Common:
#   sudo tools/gen-ca.sh --host rp.internal --host 10.0.0.5 --nginx --reload
#   sudo tools/gen-ca.sh --renew                 # re-issue the leaf from the same CA
#   tools/gen-ca.sh --host rp.lan --dir ./tls    # unprivileged, custom dir (testing)
#
# Options:
#   --host NAME        DNS name or IP for the server cert. Repeatable. The first
#                      DNS host is the cert CN. An entry that parses as an IP is
#                      added as an IP SAN instead of a DNS SAN. (required unless --renew)
#   --dir DIR          Output dir for ca.crt/ca.key/server.crt/server.key
#                      (default: /etc/remotepower/tls)
#   --renew            Re-issue ONLY the leaf from the existing CA (clients keep trust).
#   --rsa              Use RSA-3072 instead of ECDSA P-256 (only for old clients).
#   --days-ca N        CA validity in days (default 3650 ≈ 10y).
#   --days-leaf N      Leaf validity in days (default 397 — CA/Browser max; renew yearly).
#   --nginx            Write the nginx TLS snippets (ssl directives + /ca.crt) to
#                      /etc/nginx/snippets/ and print how to enable HTTPS.
#   --reload           After --nginx, run `nginx -t && nginx -s reload`.
#   --cn NAME          Override the cert CN (default: first --host).
#   -h | --help        This help.
#
# Output (default dir):
#   ca.crt      the CA public cert  — distribute to agents as RP_CA_BUNDLE
#   ca.key      the CA private key  — 0600, keep safe / move off-box after issuing
#   server.crt  the leaf cert       — nginx ssl_certificate
#   server.key  the leaf private key — nginx ssl_certificate_key (0600)
#
# The CA's SHA-256 fingerprint is printed at the end — give it to operators so
# they can pin it with `install-client.sh --ca-fingerprint <sha256>`.
set -euo pipefail

DIR=/etc/remotepower/tls
HOSTS=()
CN=""
RENEW=0
USE_RSA=0
DAYS_CA=3650
DAYS_LEAF=397
DO_NGINX=0
DO_RELOAD=0
NGINX_SNIPPET_DIR=/etc/nginx/snippets

die() { echo "gen-ca: $*" >&2; exit 1; }
log() { echo "  → $*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --host)      HOSTS+=("$2"); shift 2 ;;
    --dir)       DIR="$2"; shift 2 ;;
    --cn)        CN="$2"; shift 2 ;;
    --renew)     RENEW=1; shift ;;
    --rsa)       USE_RSA=1; shift ;;
    --days-ca)   DAYS_CA="$2"; shift 2 ;;
    --days-leaf) DAYS_LEAF="$2"; shift 2 ;;
    --nginx)     DO_NGINX=1; shift ;;
    --reload)    DO_RELOAD=1; shift ;;
    -h|--help)   sed -n '2,60p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)           die "unknown option: $1 (try --help)" ;;
  esac
done

command -v openssl >/dev/null 2>&1 || die "openssl not found — install it first"

CA_CRT="$DIR/ca.crt"; CA_KEY="$DIR/ca.key"
LEAF_CRT="$DIR/server.crt"; LEAF_KEY="$DIR/server.key"

is_ip() { [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ "$1" == *:*:* ]]; }

# ── derive the SAN list + CN ────────────────────────────────────────────────
if [ "$RENEW" -eq 0 ]; then
  [ "${#HOSTS[@]}" -gt 0 ] || die "no --host given (try --host rp.internal, or --renew)"
fi

mkdir -p "$DIR"; chmod 0750 "$DIR" 2>/dev/null || true

# On --renew, reuse the SANs recorded next to the CA so the leaf still matches.
SAN_FILE="$DIR/.san"
if [ "$RENEW" -eq 1 ]; then
  [ -f "$CA_CRT" ] && [ -f "$CA_KEY" ] || die "--renew needs an existing CA in $DIR"
  if [ "${#HOSTS[@]}" -eq 0 ]; then
    [ -f "$SAN_FILE" ] || die "no --host given and no recorded SANs ($SAN_FILE) — pass --host"
    mapfile -t HOSTS < "$SAN_FILE"
  fi
fi

SAN=""; dns_n=0; ip_n=0; first_dns=""
for h in "${HOSTS[@]}"; do
  [ -n "$h" ] || continue
  if is_ip "$h"; then
    ip_n=$((ip_n+1)); SAN="${SAN:+$SAN,}IP:$h"
  else
    dns_n=$((dns_n+1)); SAN="${SAN:+$SAN,}DNS:$h"
    [ -n "$first_dns" ] || first_dns="$h"
  fi
done
[ -n "$SAN" ] || die "no usable SAN entries"
[ -n "$CN" ] || CN="${first_dns:-${HOSTS[0]}}"
printf '%s\n' "${HOSTS[@]}" > "$SAN_FILE"; chmod 0640 "$SAN_FILE" 2>/dev/null || true

# ── key algorithm ───────────────────────────────────────────────────────────
genkey() {  # $1=outfile
  if [ "$USE_RSA" -eq 1 ]; then
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$1" 2>/dev/null
  else
    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null
  fi
  chmod 0600 "$1"
}

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# ── CA (created once; reused on --renew so clients keep trust) ───────────────
if [ "$RENEW" -eq 1 ] || { [ -f "$CA_CRT" ] && [ -f "$CA_KEY" ]; }; then
  log "Reusing existing CA: $CA_CRT (clients keep trust)"
else
  log "Generating CA key + cert (valid ${DAYS_CA}d)"
  genkey "$CA_KEY"
  cat > "$TMP/ca.cnf" <<EOF
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no
[dn]
CN = RemotePower Internal CA
O  = RemotePower
[v3_ca]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF
  openssl req -x509 -new -key "$CA_KEY" -sha256 -days "$DAYS_CA" \
    -config "$TMP/ca.cnf" -out "$CA_CRT"
  chmod 0644 "$CA_CRT"
fi

# ── leaf (always (re)issued) ────────────────────────────────────────────────
log "Issuing server leaf for CN=$CN  SAN=[$SAN]  (valid ${DAYS_LEAF}d)"
genkey "$LEAF_KEY"
cat > "$TMP/leaf.cnf" <<EOF
[req]
distinguished_name = dn
req_extensions = v3_req
prompt = no
[dn]
CN = $CN
O  = RemotePower
[v3_req]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = $SAN
EOF
openssl req -new -key "$LEAF_KEY" -config "$TMP/leaf.cnf" -out "$TMP/leaf.csr"
openssl x509 -req -in "$TMP/leaf.csr" -CA "$CA_CRT" -CAkey "$CA_KEY" \
  -CAcreateserial -days "$DAYS_LEAF" -sha256 \
  -extfile "$TMP/leaf.cnf" -extensions v3_req -out "$LEAF_CRT" 2>/dev/null
chmod 0644 "$LEAF_CRT"

# verify the chain we just built
openssl verify -CAfile "$CA_CRT" "$LEAF_CRT" >/dev/null \
  || die "internal error: generated leaf does not verify against the CA"

# ── optional nginx wiring ───────────────────────────────────────────────────
if [ "$DO_NGINX" -eq 1 ]; then
  mkdir -p "$NGINX_SNIPPET_DIR"
  cat > "$NGINX_SNIPPET_DIR/remotepower-ssl.conf" <<EOF
# Managed by tools/gen-ca.sh — RemotePower self-signed TLS.
ssl_certificate     $LEAF_CRT;
ssl_certificate_key $LEAF_KEY;
ssl_protocols       TLSv1.2 TLSv1.3;
ssl_ciphers         ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
ssl_session_cache   shared:RPTLS:10m;
ssl_session_tickets off;
EOF
  cat > "$NGINX_SNIPPET_DIR/remotepower-cacrt.conf" <<EOF
# Managed by tools/gen-ca.sh — serve the CA public cert for agent bootstrap.
# Safe to expose over plain HTTP: clients pin it by SHA-256 fingerprint.
location = /ca.crt {
    alias $CA_CRT;
    default_type application/x-x509-ca-cert;
    add_header Content-Disposition 'attachment; filename="ca.crt"';
}
EOF
  log "Wrote $NGINX_SNIPPET_DIR/remotepower-ssl.conf and remotepower-cacrt.conf"
  if [ "$DO_RELOAD" -eq 1 ]; then
    if command -v nginx >/dev/null 2>&1; then
      nginx -t && nginx -s reload && log "nginx reloaded"
    else
      echo "  ! nginx not found — skipped reload" >&2
    fi
  fi
fi

FP="$(openssl x509 -in "$CA_CRT" -noout -fingerprint -sha256 | sed 's/^.*=//')"

cat <<EOF

────────────────────────────────────────────────────────────────────────────
 RemotePower self-signed CA ready in $DIR
────────────────────────────────────────────────────────────────────────────
  ca.crt      $CA_CRT   (distribute to agents)
  server.crt  $LEAF_CRT   (nginx ssl_certificate)
  server.key  $LEAF_KEY   (nginx ssl_certificate_key, 0600)

 CA SHA-256 fingerprint (pin this on agents):
   $FP

 Enroll agents so they trust this CA (over HTTP — verified by fingerprint):
   sudo ./install-client.sh --server https://$CN \\
        --ca-fingerprint $FP

 nginx: add to your HTTPS server block (or run with --nginx):
   include snippets/remotepower-ssl.conf;     # ssl_certificate + protocols
   include snippets/remotepower-cacrt.conf;   # serves /ca.crt for bootstrap

 Renew the server cert later (clients are NOT affected):
   sudo tools/gen-ca.sh --renew --reload

 NB: a self-signed CA means browsers warn until you import ca.crt into your OS
 trust store. Prefer a real cert — see docs/tls-selfsigned.md.
────────────────────────────────────────────────────────────────────────────
EOF
