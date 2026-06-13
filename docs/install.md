# Installation

The fastest path. Three commands on the server, two on the client.

### Server

```bash
git clone https://github.com/tyxak/remotepower
cd remotepower
sudo bash install-server.sh        # nginx + fcgiwrap + Python deps; prompts for admin credentials
```

The installer asks for an admin username and password, then prints the URL. Open it in a browser and log in.

### TLS — strongly recommended before enrolling any agent

> **Without TLS, session tokens and agent credentials travel in cleartext.**
> Do not expose the server on a network you don't fully control without HTTPS.

The fastest path is certbot with the nginx plugin:

```bash
# 1. Install certbot
sudo apt install certbot python3-certbot-nginx   # Debian/Ubuntu
# sudo dnf install certbot python3-certbot-nginx  # RHEL/Fedora
# sudo pacman -S certbot certbot-nginx             # Arch

# 2. Obtain a certificate and let certbot rewrite the nginx config
sudo certbot --nginx -d your.domain.com

# Certbot adds the SSL server block and sets up auto-renewal via a systemd
# timer or cron. Verify with:
sudo certbot renew --dry-run
```

After certbot runs, enable the two commented-out lines in
`/etc/nginx/sites-available/remotepower`:

```nginx
# Uncomment these after certbot has added the SSL block:
return 301 https://$host$request_uri;          # HTTP → HTTPS redirect
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
```

Then reload nginx: `sudo nginx -t && sudo systemctl reload nginx`.

**Using acme.sh / DNS-01 instead?** RemotePower has built-in ACME support
(Settings → ACME / Let's Encrypt) that can issue and renew certificates
for your devices using Cloudflare, Hetzner, Route 53, and others — no
certbot needed once the server itself has a cert.

**Internal-only / airgapped / no public DNS?** Use the built-in self-signed
**CA**: `sudo make tls-selfsigned HOST=rp.internal NGINX=1` generates a CA + a
server leaf and prints the CA fingerprint; enrol agents with
`install-client.sh --ca-fingerprint <sha256>` so they trust it. Renewing the
server cert never touches the clients, and switching to a real cert later is a
server-only change. Full guide and decision tree:
[`docs/tls-selfsigned.md`](tls-selfsigned.md).

For a hardened production nginx config (TLS 1.2+, OCSP, rate-limiting,
IP allowlist), see [`deploy/nginx/remotepower.conf`](../deploy/nginx/remotepower.conf).

### Client (on the host you want to manage)

```bash
sudo bash install-client.sh                                   # Linux
powershell -ExecutionPolicy Bypass -File client\install-windows.ps1   # Windows
sudo bash client/install-macos.sh https://your-server 123456  # macOS
# Paste the server URL and the 6-digit PIN from the dashboard. Done.
```

The device shows up in the dashboard within ~60 seconds.

> **Bigger / segmented / HA deployment?** See **[deployment.md](deployment.md)**
> for the full map (satellites, app nodes, load balancer, PostgreSQL + HA,
> PgBouncer) and **[scaling.md](scaling.md)** for 1000+ agents.

### Optional but recommended

```bash
sudo bash packaging/install-webterm.sh    # browser-based SSH terminal (separate daemon)
```

Auto-detects your nginx user (`www-data` / `nginx` / `http` / etc.) and wires everything up. Run with `--dry-run` first if you want to see what it'll do.

#### User management

```bash
python3 /var/www/remotepower/cgi-bin/remotepower-passwd
```

Interactive CLI for adding users, changing passwords, deleting accounts, and listing all users.  Supports bcrypt (preferred) and salted PBKDF2-HMAC-SHA256 (fallback when bcrypt is absent) — the same hash formats the server verifies.

#### High-performance API worker (SCGI prefork — optional)

By default the API runs as a classic CGI process (one Python startup per request).  For busier deployments, switch to the persistent SCGI prefork worker installed at `/etc/systemd/system/remotepower-api.service`:

```bash
systemctl enable --now remotepower-api          # start the worker
# then switch the /api/ location in nginx to the scgi_pass block
# (commented alternative in server/conf/remotepower.conf) and reload nginx
nginx -t && systemctl reload nginx
```

Roll back at any time by reverting the nginx block to `fastcgi_pass` — the worker and fcgiwrap can coexist.

### Public demo / sandbox

If you want to host a read-only demo at e.g. `demoremote.example.com` alongside your production install:

```bash
sudo bash packaging/install-demo.sh demoremote.example.com
sudo certbot --nginx -d demoremote.example.com
```

This creates a SEPARATE vhost — different data dir (`/var/lib/remotepower-demo/`), shared CGI code, `RP_READ_ONLY=1` set per-vhost. Visitors log in as `demo` / `demo`, browse everything, but mutations get a friendly 403 toast. Your production install at `remote.<domain>` is untouched. The vhost auto-seeds 16 fake homelab devices using the unallocated `.lab` TLD.

### Docker (one-liner alternative)

**Pull the prebuilt image** (published to the GitHub Container Registry on every release; multi-arch — `amd64` and `arm64`, so it runs on x86 servers and ARM SBCs alike):

```bash
docker pull ghcr.io/tyxak/remotepower:latest      # or pin a version, e.g. :4.6.0
docker run -d --name remotepower -p 8085:8080 -v remotepower-data:/var/lib/remotepower \
  ghcr.io/tyxak/remotepower:latest
```

**Or build from source** with compose:

```bash
git clone https://github.com/tyxak/remotepower && cd remotepower
docker compose up -d
```

(To run the published image via compose instead of building, uncomment the `image:` line in `docker-compose.yml` and drop `build:`.)

Dashboard at `http://localhost:8085` (host port default; container listens on 8080). Override with `RP_HOST_PORT=8080 docker compose up -d`. Put a TLS-terminating reverse proxy (Caddy, Traefik, nginx) in front for production — or set `RP_TLS_SELFSIGNED=1` to serve HTTPS directly (see [tls-selfsigned.md](tls-selfsigned.md)).

---

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
