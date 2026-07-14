# Installation

> **Already have RemotePower installed and just want to update it?** See
> [upgrading.md](upgrading.md) — `sudo bash install.sh update` is the one
> command for both "pick up new code" and "convert a pre-6.1.0 CGI/SCGI
> install to gunicorn+Flask," self-detected.

## Quickest path

**Server — Docker (recommended):**

```bash
docker compose up -d        # self-signed HTTPS on first boot; admin password printed to `docker logs remotepower`
```

**Server — bare-metal wizard:**

```bash
git clone https://github.com/tyxak/remotepower && cd remotepower
sudo bash install.sh        # one wizard: nginx + app + TLS + admin — you never edit an nginx file
```

HTTPS is automatic: a self-signed CA by default (agents pin it), or a real
Let's Encrypt cert when you give a public domain. Open the printed URL and log in.

**Add a device — one line, nothing to configure.** In the dashboard,
*Add device → Quick install command*, then on the target host:

```bash
# Linux / macOS (run as root)
wget -qO- "https://your-server/install?t=<token>" | sudo sh
```

```powershell
# Windows — in an elevated PowerShell (installs Python automatically if missing)
powershell -ExecutionPolicy Bypass -Command "iwr 'https://your-server/install.ps1?t=<token>' -UseBasicParsing | iex"
```

Either downloads the **signed** agent, verifies its checksum, enrols with the
baked one-time token, and the host appears **by its hostname** within ~60 seconds.
The dashboard's *Add device → Quick install command* hands you both lines with a
fresh token. (Windows details, service control, and the offline
`install-windows.ps1` script: [windows-client.md](windows-client.md).)

**Push to many hosts over SSH at once.** From the server checkout, name the hosts
to enrol:

```bash
sudo bash install.sh agent push --server https://your-server --token <token> user@host1 [user@host2 ...]
```

Each invocation enrols exactly the hosts you name (using the `--token` you pass),
SSHing in to install and start the agent on each.

**Uninstall:** `sudo bash install.sh uninstall` (keeps your data; `--purge` to
wipe it) · agent: `wget -qO- https://your-server/install | sudo sh -s -- --uninstall`.

---

## Detailed paths

The sections below cover the individual scripts, the Arch/AUR package, Windows /
macOS clients, advanced TLS and Ansible — reach for them when the quick path
above isn't enough.

### Server (script)

```bash
git clone https://github.com/tyxak/remotepower
cd remotepower
sudo bash install-server.sh        # nginx + gunicorn/Flask + Postgres + Python deps; prompts for admin credentials
```

**Arch Linux (AUR):** `yay -S remotepower-server` installs the code + deps; then
finish setup as the package prints (enable `remotepower-wsgi.service`, drop the
sample vhost from `/usr/share/doc/remotepower-server/` into `/etc/nginx/conf.d/`
with your `server_name`/TLS, and `remotepower-passwd` to create the admin). Or
use the Docker image (below).

The installer asks for an admin username and password, then prints the URL. Open it in a browser and log in.

Then run **`sudo rp doctor`** to confirm the whole stack came up healthy (app
server, scheduler, scanner, push, nginx, storage backend), or **`rp tui`** for a
live dashboard. `rp` is the omd/checkmk-style node-control command the installer
sets up — see **[cli.md](cli.md)**.

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

**Arch Linux (AUR):** `yay -S remotepower-agent`, then enrol + start:

```bash
remotepower-agent enroll --server https://your-server --pin 123456
sudo systemctl enable --now remotepower-agent
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

#### The app server + out-of-band scheduler (default since v6.1.0)

`install-server.sh` defaults to a fully-persistent single-node tier — `api.py`
served by **gunicorn** through a real Flask app (`server/cgi-bin/wsgi.py`,
thread-local request isolation, no fork) — paired with a dedicated,
leader-elected maintenance scheduler that runs the cadence off the request
path (measured ~25× lower request latency on a networked Postgres backend),
plus a co-located scanner satellite for Security → Pentest. This is the
**only** server (the earlier CGI/fcgiwrap and SCGI-worker paths are retired);
`--no-scheduler`/`--no-postgres`/`--no-scanner` opt back down to a lighter
single-file/no-scanner install. Tune worker/thread counts in
`server/conf/remotepower-wsgi.service`, then `systemctl daemon-reload &&
systemctl restart remotepower-wsgi` — see **[wsgi.md](wsgi.md)** and
**[scaling.md](scaling.md)**.

### Public demo / sandbox

If you want to host a read-only demo at e.g. `demoremote.example.com` alongside your production install:

```bash
sudo bash packaging/install-demo.sh demoremote.example.com
sudo certbot --nginx -d demoremote.example.com
```

This creates a SEPARATE vhost — different data dir (`/var/lib/remotepower-demo/`), its own dedicated `remotepower-wsgi-demo` gunicorn process on a second port (shared app code), `RP_READ_ONLY=1` set per-vhost. Visitors log in as `demo` / `demo`, browse everything, but mutations get a friendly 403 toast. Your production install at `remote.<domain>` is untouched. The vhost auto-seeds 16 fake homelab devices using the unallocated `.lab` TLD.

### Docker (one-liner alternative)

**Pull the prebuilt image** (published to the GitHub Container Registry on every release; multi-arch — `amd64` and `arm64`, so it runs on x86 servers and ARM SBCs alike):

```bash
docker pull ghcr.io/tyxak/remotepower:latest      # or pin a version, e.g. :6.2.0
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
