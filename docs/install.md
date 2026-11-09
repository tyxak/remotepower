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

**Add a host — one line, nothing to configure.** In the dashboard, open
**Hosts → Enroll host → Quick install command**, then on the target host:

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
**Quick install command** hands you both lines with a fresh token that works for 24
hours. The **Enroll host** window also shows a 6-digit PIN that expires after 10 minutes,
for installers that ask for one. (Windows details, service control, and the offline
`install-windows.ps1` script: [windows-client.md](windows-client.md).)

**Guide me.** The **Enroll host** window has a **Guide me** button that asks one thing at a time: the type of host, then a group, tags and the
networks the install may come from, then the command, and it tells you when the host has checked in and what it got. See
[wizards.md](wizards.md).

**A server with its own certificate authority** (the Docker default) has a
certificate no host trusts on its own, and `wget -q` fails without a word. When
the server has its own CA, **Quick install command** adds a second line for Linux
and macOS, labelled *self-signed certificate*. It fetches the CA, refuses to go on unless the CA matches the
fingerprint the dashboard shows, and only then fetches the installer. If you
already have the installer on the host, give it the fingerprint yourself:

```bash
sh install --token <token> --ca-fingerprint <sha256 of the CA>
```

It keeps the CA only if the fingerprint matches, and trusts that CA, and nothing
else, for the rest of the install. It works on whatever port the server is
published on. Running the line again on a host that is already enrolled enrols it
again and restarts its agent.

**Push to many hosts over SSH at once.** From the server checkout, name the hosts
to enrol:

```bash
sudo bash install.sh agent push --server https://your-server --token <token> user@host1 [user@host2 ...]
```

Each invocation enrols exactly the hosts you name, signing in to each over SSH to install and
start the agent. One enrollment token enrols **one** host, so mint a token per host in the
dashboard and run the command once for each. Add `--no-sudo` if you connect as root.

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
(**Security → TLS / DNS → ACME certificates**, see [acme.md](acme.md)) that can issue and renew
certificates for your hosts using Cloudflare, Hetzner, Route 53 and others, with no
certbot needed once the server itself has a certificate.

**Internal-only / airgapped / no public DNS?** Use the built-in self-signed
**CA**: `sudo make tls-selfsigned HOST=rp.internal NGINX=1` generates a CA + a
server leaf and prints the CA fingerprint; enrol agents with
`install-client.sh --ca-fingerprint <sha256>` so they trust it. Renewing the
server cert never touches the clients, and switching to a real cert later is a
server-only change. Full guide and decision tree:
[`docs/tls-selfsigned.md`](tls-selfsigned.md).

For a hardened production nginx config (TLS 1.2+, OCSP, rate-limiting,
IP allowlist), see [`deploy/nginx/remotepower.conf`](https://github.com/tyxak/remotepower/blob/main/deploy/nginx/remotepower.conf)
in the repository. (`deploy/` is not part of the release tarball, so a relative link here would work for
someone reading the source and dangle for everyone reading the shipped docs or the wiki.)

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

The host shows up in the dashboard within ~60 seconds.

> **Bigger / segmented / HA deployment?** See **[deployment.md](deployment.md)**
> for the full map (satellites, app nodes, load balancer, PostgreSQL + HA,
> PgBouncer) and **[scaling.md](scaling.md)** for 1000+ agents.

### Optional but recommended

```bash
sudo bash packaging/install-webterm.sh    # browser-based SSH terminal (separate daemon)
```

Auto-detects your nginx user (`www-data` / `nginx` / `http` / etc.) and wires everything up. Run with `--dry-run` first if you want to see what it'll do.

#### User management

Add, edit and remove users on the **Users** page (Admin group in the sidebar). See
[admin-guide.md](admin-guide.md) for roles and custom roles.

There is also a command-line tool:

```bash
python3 /var/www/remotepower/cgi-bin/remotepower-passwd
```

It adds users, changes passwords, deletes accounts and lists them, with bcrypt hashes (or salted
PBKDF2-HMAC-SHA256 when bcrypt is missing). **It edits `users.json` directly, so it only works on the
JSON storage backend.** On SQLite and Postgres the users live in the database, the file does not
exist, and the tool stops with "users file not found". Use the Users page there, and keep a second
admin account so you can reset the first.

#### The app server and the out-of-band scheduler

`install-server.sh` sets up a persistent single-node tier by default. `api.py` is served by
**gunicorn** through a Flask app (`server/cgi-bin/wsgi.py`), next to a dedicated, leader-elected
maintenance scheduler that runs the periodic sweeps off the request path (a large drop in request
latency on a networked Postgres backend; [wsgi.md](wsgi.md) says what that figure is and is not).
A scanner satellite for Security → Pentest is installed on the same node. This is the **only**
app server; the older CGI and SCGI paths are gone. `--no-scheduler`, `--no-postgres` and
`--no-scanner` opt back down to a lighter single-file install without a scanner. An install that
predates this setup converts with `sudo bash install.sh update` ([upgrading.md](upgrading.md)). Tune worker/thread counts in
`server/conf/remotepower-wsgi.service`, then `systemctl daemon-reload &&
systemctl restart remotepower-wsgi` — see **[wsgi.md](wsgi.md)** and
**[scaling.md](scaling.md)**.

### Public demo / sandbox

If you want to host a read-only demo at e.g. `demoremote.example.com` alongside your production install:

```bash
sudo bash packaging/install-demo.sh demoremote.example.com
sudo certbot --nginx -d demoremote.example.com
```

This creates a separate vhost with its own data directory (`/var/lib/remotepower-demo/`) and its own `remotepower-wsgi-demo` gunicorn process on a second port, sharing the app code. `RP_READ_ONLY=1` is set per vhost. Visitors log in as `demo` / `demo` and can browse everything, but changes get a friendly 403 message. Your production install is untouched. The vhost seeds a set of fake homelab hosts that use the unallocated `.lab` TLD, and refreshes them on a timer. Add `--postgres` to give the demo its own PostgreSQL database; without it the demo uses flat JSON. With `--postgres` the refresh timer has nothing to write to, so the hosts are seeded once and read as offline about half an hour later.

The demo opens in the Pilot look with the B612 typeface, so a visitor sees the newer interface first, on the sign-in page too. Visitors can still pick Classic and the system font in My Account, but the demo is read-only, so a choice lasts only until the page is reloaded. Add `--classic` to leave both defaults off.

The refresh timer sets the two defaults each time it runs. It runs `packaging/seed-demo-data.py` from the checkout you installed from, and for `/var/lib/remotepower-demo/` that script picks Pilot and B612 when the unit passes no `--look` or `--typeface`. A demo installed before these defaults changes at its next refresh once that checkout is updated (`git pull`, and the code update you already run); you do not need to run the installer again. Run it again only to change what the unit passes, for example to add `--classic`. An nginx vhost that is already there is kept as it is when you run the installer again, so the 443 block that certbot added stays; add `--rewrite-vhost` to write it again.

Check that the unit exists with `systemctl cat remotepower-demo-seed.service`. A demo installed before the unit was added has none, and nothing re-seeds it. Run the seeder by hand from a whole checkout, as the user the demo's service runs as, for example `sudo -u www-data python3 packaging/seed-demo-data.py --data-dir /var/lib/remotepower-demo --apply --quiet`. The seeder reads `server/cgi-bin/traffic.py` beside it, so it needs the checkout and not a copy of the one file, and that user has to be able to read the checkout. Running the installer once adds the unit too.

### Docker (one-liner alternative)

**Pull the prebuilt image** (published to the GitHub Container Registry on every release; multi-arch — `amd64` and `arm64`, so it runs on x86 servers and ARM SBCs alike):

```bash
docker pull ghcr.io/tyxak/remotepower:latest      # or pin a version: ghcr.io/tyxak/remotepower:<version>
docker run -d --name remotepower -p 443:8443 -p 80:8080 \
  -e RP_TLS_SELFSIGNED=1 -e RP_TLS_HOST=your.host.example \
  -v remotepower-data:/var/lib/remotepower \
  ghcr.io/tyxak/remotepower:latest
```

**Verify it before you run it.** The images are cosign-signed
(keyless, bound to the release workflow's identity):

```bash
cosign verify ghcr.io/tyxak/remotepower:latest \
  --certificate-identity-regexp '^https://github.com/tyxak/remotepower/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Both flags are required to make it a check: a bare `cosign verify` accepts a
signature from any identity. See [security.md](security.md#threat-model) for why
the signing is keyless.

The container serves **self-signed HTTPS on 8443** and plain HTTP on 8080
(health, `/ca.crt`, and a redirect to HTTPS). Set `RP_TLS_HOST` to the address
agents and browsers actually use, or the certificate won't match.

**Or build from source** with compose:

```bash
git clone https://github.com/tyxak/remotepower && cd remotepower
docker compose up -d
```

(To run the published image via compose instead of building, replace `build:.` with `image: ghcr.io/tyxak/remotepower:latest` in `docker-compose.yml`.)

Dashboard at **`https://localhost/`**. Compose publishes host `443` → container `8443` (self-signed HTTPS, on by default) and host `80` → `8080`; remap either with `RP_HTTPS_PORT=8443 RP_HTTP_PORT=8080 docker compose up -d`, and set `RP_TLS_HOST` to the address you actually reach it on (see [tls-selfsigned.md](tls-selfsigned.md)). The port you open the dashboard on is the port the agent installer, the passkey and single sign-on addresses and the HTTP to HTTPS redirect use, so a remapped port needs no other setting. Put a TLS-terminating reverse proxy (Caddy, Traefik, nginx) in front instead if you'd rather it hold the certificate.

**Browser terminal and file manager in Docker.** The terminal and the SFTP file
manager are one daemon that connects to your hosts over SSH. The image has it, but
it stays off until you ask: set `RP_WITH_WEBTERM=1` (uncomment the line in
`docker-compose.yml`, or add `-e RP_WITH_WEBTERM=1`) and restart. It listens inside
the container only, so you publish no port; the browser reaches it through the HTTPS
port. Without it the Files page says "WebSocket error". It is off by default because
it is an SSH client that an admin can point at any address the container can reach.
The secret it shares with the app is created in the data volume on first start, or
taken from `RP_WEBTERM_SECRET`.

### Troubleshooting an install

| Problem | What to check |
| --- | --- |
| Nothing responds after the install | `sudo rp doctor` checks the app server, scheduler, scanner, push, nginx and the storage backend. `sudo bash install.sh doctor` runs the preflight checks only. |
| The one-line install fails with a certificate error | The server uses its own CA, so the host does not trust it yet. Use the **self-signed certificate** line from **Quick install command**, or pass `--ca-fingerprint`. |
| `no enrolment token` | The link has no `?t=` part, or you ran the plain `/install` URL. Copy the line from **Quick install command**, or add `--token`. |
| The PIN is refused | A PIN works once and expires after 10 minutes. Open **Enroll host** again for a new one. |
| The host does not appear within a minute or two | Check that the host can reach the server on its HTTPS port, and read the agent log with `journalctl -u remotepower-agent`. |
| I forgot the admin password | Another admin can reset it on the **Users** page. On the JSON backend you can also use `remotepower-passwd` (see *User management*). It does not work on SQLite or Postgres. |
| An agent needs to be removed from a host | `wget -qO- https://your-server/install \| sudo sh -s -- --uninstall`, then delete the host in the dashboard. |

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
