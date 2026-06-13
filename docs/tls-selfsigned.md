# TLS for RemotePower — real certs, and the self-signed CA path

RemotePower requires HTTPS to enrol a real agent: the device token and command
output must never travel in cleartext, and all three agents enforce a TLS 1.2
floor and full certificate verification. This page covers how to get a cert onto
the server and trusted by the agents.

## Which path? (decision tree)

| Your situation | Use | Guide |
|---|---|---|
| Public hostname, port 80 reachable | **Let's Encrypt HTTP-01** — `certbot --nginx` | [install.md](install.md) |
| Public hostname, no inbound 80/443 | **Let's Encrypt DNS-01** — acme.sh | [acme.md](acme.md) |
| Internal-only / airgapped / no public DNS | **Self-signed CA** (this page) | below |

**Prefer a real cert.** A public cert is trusted by every browser and every
agent's system store out of the box, auto-renews, and needs no key distribution.
The self-signed CA below exists for networks where a public cert is impossible —
a lab, an airgapped site, an internal hostname like `rp.internal`.

---

## Self-signed CA — quick start

A self-signed *CA* (not a bare self-signed cert) is the right tool: agents trust
the **CA**, so you can renew the server cert later without touching any client.

### 1. Generate the CA + server cert (on the server)

```bash
sudo make tls-selfsigned HOST=rp.internal NGINX=1
# or, directly, with more control:
sudo tools/gen-ca.sh --host rp.internal --host 10.0.0.5 --nginx --reload
```

This writes `/etc/remotepower/tls/{ca,server}.{crt,key}`, drops nginx snippets,
and prints the **CA SHA-256 fingerprint** — copy it, you'll pin it on agents:

```
 CA SHA-256 fingerprint (pin this on agents):
   F3:E2:20:7D:…:40:7A
```

### 2. Enable HTTPS in nginx

Uncomment the HTTPS `server { … }` block in
`/etc/nginx/sites-available/remotepower` and, for the self-signed path, use the
generated snippet for the cert lines:

```nginx
include snippets/remotepower-ssl.conf;       # ssl_certificate + protocols (from gen-ca.sh)
include snippets/remotepower-locations.conf; # the routing (shared with HTTP, incl. /ca.crt)
```

`sudo nginx -t && sudo systemctl reload nginx`. The location blocks (and the
`/ca.crt` download) are the *same* shared snippet the HTTP server uses, so the two
never drift.

### 3. Enrol agents so they trust the CA

```bash
sudo ./install-client.sh --server https://rp.internal \
     --ca-fingerprint F3:E2:20:7D:…:40:7A
```

The installer fetches `http://rp.internal/ca.crt`, **verifies it against the
fingerprint** (refusing to trust on a mismatch — so a MITM on that first, pre-TLS
fetch can't slip in its own CA), installs it to `/etc/remotepower/ca.crt`, and
points the agent at it via `RP_CA_BUNDLE`. macOS and Windows are the same:

```bash
sudo bash client/install-macos.sh --server https://rp.internal --pin 123456 \
     --ca-fingerprint F3:E2:…
```
```powershell
.\install-windows.ps1 -Server https://rp.internal -Pin 123456 -CaFingerprint F3:E2:…
```

> Verification is on by default. Omitting `--ca-fingerprint` falls back to
> trust-on-first-use (a warning is printed) — only acceptable on a trusted LAN.

### 4. The browser

A self-signed CA isn't in your browser's trust store, so you'll get a warning
until you **import `ca.crt`** into your OS / browser trust store (download it from
`http://rp.internal/ca.crt`). This per-admin step is the main reason to prefer a
real cert.

---

## Renewing the server cert (clients unaffected)

The leaf is valid 397 days. Re-issue it from the same CA at any time:

```bash
sudo make tls-renew NGINX=1        # or: sudo tools/gen-ca.sh --renew --reload
```

Because agents trust the **CA** (which is unchanged), nothing needs to be touched
on any client. Only re-distribute `ca.crt` if you ever regenerate the CA itself
(e.g. it expired after ~10 years).

---

## Switching from self-signed → a real cert

This is deliberately painless. The agent trusts the **system root store *and*
your CA at the same time** (`RP_CA_BUNDLE` *adds* to the public roots, it doesn't
replace them). So moving to a real cert is a **server-only** change:

1. Obtain a real cert: `sudo certbot --nginx -d your.domain` (or acme.sh DNS-01).
2. Point nginx at the real cert + key (replace the `include
   snippets/remotepower-ssl.conf;` with the real `ssl_certificate` lines, or let
   certbot edit the block), then `sudo systemctl reload nginx`.
3. **Done.** Browsers trust it immediately. Agents already trust public roots, so
   they keep verifying with no change — the now-unused `RP_CA_BUNDLE` is
   harmless. You can remove it from agents later at your leisure (delete
   `/etc/remotepower/agent.env` + `ca.crt` and restart the agent), but there's no
   rush and no outage window.

No overlap dance, no agent redeploy — that property is exactly why this release
uses a CA the agent trusts additively, rather than pinning a single leaf.

---

## Docker

Set `RP_TLS_SELFSIGNED=1` and `RP_TLS_HOST=<name>` and map host `443:8443`:

```yaml
ports:
  - "443:8443"
environment:
  - RP_TLS_SELFSIGNED=1
  - RP_TLS_HOST=rp.internal
```

On first boot the container generates a CA+leaf into the data volume (so it
persists) and serves HTTPS on :8443, printing the CA fingerprint to
`docker logs remotepower`. Enrol agents with that fingerprint as above. For
production, terminating TLS at a real reverse proxy (Caddy/Traefik/nginx with a
real cert) is still the recommended setup.

---

## How it works (security notes)

- **CA, not bare leaf.** `gen-ca.sh` builds a CA (`basicConstraints CA:TRUE,
  pathlen:0`, `keyCertSign`) and a leaf (`CA:FALSE`, EKU `serverAuth`, SAN). Keys
  are ECDSA P-256 (use `--rsa` for very old clients). CA key is `0600`.
- **No weakening of verification.** The agent uses
  `ssl.create_default_context()` (which keeps `CERT_REQUIRED`, hostname checking,
  and the system roots) and merely *adds* the CA with `load_verify_locations()`.
  A wrong hostname or an untrusted issuer is still rejected.
- **Bootstrap over HTTP is safe** because the CA is pinned by SHA-256 fingerprint
  at install time; the fingerprint is the out-of-band root of trust.
- **`/ca.crt`** is a public cert (no private material) — safe to serve openly.
