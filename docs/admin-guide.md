# RemotePower — Install &amp; Admin Guide

A complete operator's guide: installing RemotePower, securing it,
running it day to day, backing it up, and upgrading it. For a quick
two-command install see [install.md](install.md); this document is
the longer, operational companion.

---

## 1. What you are installing

RemotePower has three parts:

- **The server** — nginx in front of Python CGI. It serves the
  dashboard and API, ingests agent heartbeats, runs CVE and monitor
  checks, and stores everything in flat JSON files by default — or, on
  larger fleets, an optional embedded SQLite backend (stdlib only, no
  external database server) you can switch to in place. See
  [security.md](security.md) for the on-disk data layout and the
  storage backends.
- **The agent** — a small Python script (`remotepower-agent`) on
  each managed host. It heartbeats out to the server every 60
  seconds. The agent reaches the server; the server never needs
  inbound access to a host.
- **The web terminal daemon** *(optional)* — a hardened daemon that
  proxies browser SSH sessions.

The server needs Python 3 (standard library only — no pip packages),
nginx, and a CGI runner (`fcgiwrap`). The agent needs only Python 3.

---

## 2. Installing the server

### 2.1 Quick path (recommended): the unified wizard

On the host that will run the dashboard, the turnkey wizard provisions
everything — nginx, the app, TLS and the admin account — in one run, with
**HTTPS on by default** and **no insecure default password**:

```
git clone https://github.com/tyxak/remotepower && cd remotepower
sudo bash install.sh
```

Prefer containers? One command brings the server up over self-signed HTTPS and
prints the generated admin password to the container log:

```
docker compose up -d
```

Open the printed URL and log in. To add hosts, use the self-hosted one-line agent
installer (`wget -qO- "https://your-server/install?t=<token>" | sudo sh`) or push
agents over SSH with
`sudo bash install.sh agent push --server https://your-server --token <token> user@host1 [user@host2 ...]`.
Tear any of it down with `sudo bash install.sh uninstall` (server, agent or demo;
add `--purge` to also remove data). See [install.md](install.md) for the full
quick-start.

**Advanced — the individual scripts.** The component scripts still exist for
bigger / segmented / HA deployments (the explicit heavy-fleet track) or when you
want to wire each piece yourself. On the host that will run the dashboard:

```
sudo bash install-server.sh
```

The installer provisions nginx, fcgiwrap and the Python pieces,
lays out the data directory, and prints the dashboard URL plus an
auto-generated admin password. Use that password for the first
login.

### 2.2 What the installer lays down

- The application under the web root (the `server/` tree).
- A data directory for the JSON state files, created mode `0700`.
- An nginx vhost with the security headers and the `/api/` CGI
  location.
- The state files themselves, written mode `0600`.

### 2.3 First login

Open the printed URL and log in as `admin` with the printed
password. RemotePower shows a **default-password warning banner**
until you change it — do that immediately (see §4.1).

---

## 3. Installing agents

On each host you want to manage:

```
sudo bash install-client.sh
```

It asks for the server URL and a 6-digit enrolment PIN. Generate the
PIN from the dashboard (Devices → enrol). The agent installs as a
systemd service (`remotepower-agent.service`), enabled and started.

Check it afterwards:

```
systemctl status remotepower-agent.service
journalctl -u remotepower-agent.service -n 50
```

A healthy agent logs a startup line with its version and the server
URL, then `Config updated:` lines as the server pushes it watch
lists.

For fleet enrolment (cloud-init, Ansible) use a long-lived enrolment
token instead of a one-time PIN — see [install.md](install.md).

---

## 4. Post-install hardening

RemotePower ships with sensible defaults, but a few steps are worth
taking before it manages anything important.

### 4.1 Change the admin password

Settings → Security. Passwords are stored with salted PBKDF2. The
default-password banner clears once the seeded password is replaced.

### 4.2 Enable two-factor authentication

Settings → Security → "Enable two-factor". Scan the QR with any
authenticator app. Disabling 2FA later requires a current code —
so a stolen session cookie alone cannot remove it.

### 4.3 Put the dashboard behind TLS

Do not run the dashboard over plain HTTP outside localhost. Agents
verify the server's certificate, and the login form and API tokens
must not cross the network in the clear. Terminate TLS at nginx —
see [https.md](https.md).

### 4.4 Restrict the command allow-list

Per device, the command allow-list bounds what can be executed. Keep
it as narrow as the device's role needs.

### 4.5 Secrets via environment variables

Sensitive config — the Proxmox API token secret, for instance — can
be supplied through an environment variable (`RP_PROXMOX_TOKEN_SECRET`)
rather than living in `config.json`. The backup export redacts
secret fields. Set these in the nginx/fcgiwrap service environment.

---

## 5. Day-to-day operation

### 5.1 The dashboard

The Home page is the daily view: fleet status tiles (devices online,
pending updates, drift events, CVE findings, and — if a device is
promoted — unread mail), a "needs attention" column, and recent
fleet activity. Drill into any device for sysinfo, journals, CVEs,
drift, services and command output.

### 5.2 Running commands

Devices page → a device's action menu: shutdown, reboot,
Wake-on-LAN, package upgrade, arbitrary commands, scheduled jobs.
Batch actions run across multiple selected devices. Everything is
recorded in the fleet event log and the per-device command history.

### 5.3 Monitoring

- **CVE scanning** — automatic, OSV-backed. Use "Scan packages now"
  on a device to refresh its inventory immediately after patching.
- **Drift detection** — watched config files are hashed every heartbeat;
  review and accept baselines on the device detail.
- **External monitors** — ping/TCP/HTTP probes, TLS/DNS expiry.
- **Mailbox monitor** — Settings → Mailbox monitor.
- **Alerts** — state changes fire webhooks (Settings → Notifications).

### 5.4 Proxmox

Settings → Proxmox connects one Proxmox VE node. The Virtualization
and Containers pages then manage QEMU VMs and LXC containers,
including snapshots. Use a scoped Proxmox API token.

---

## 6. Backup &amp; restore

All state lives in the data directory — flat JSON by default, or a
single `remotepower.db` SQLite file if you switched backends — so
backing RemotePower up is backing up that directory.

### 6.1 Built-in export

Settings → Backup &amp; export produces a single archive of the state
files with secret fields redacted. Schedule it, or pull it before an
upgrade.

### 6.2 Filesystem backup

Equivalently, snapshot the data directory directly:

```
tar czf remotepower-backup-$(date +%F).tar.gz -C /path/to/datadir .
```

Do this with the server briefly quiesced, or accept that a file
written mid-backup is captured atomically (saves are atomic, so a
backup never catches a half-written file — but it may catch a mix of
old and new files across a multi-file update).

### 6.3 Restore

Stop the server, replace the data directory contents from the
archive, restore ownership (`0700` on the directory, `0600` on the
files), and start the server.

---

## 7. Upgrading

### 7.1 Check for updates

RemotePower checks the project's GitHub repository and shows an
in-app notice when the running version is behind. The notice
includes the update commands. RemotePower never modifies its own
code — upgrading is always a deliberate operator action.

### 7.2 Upgrade procedure

1. **Back up** the data directory (§6).
2. Pull the new release.
3. Re-deploy the `server/` tree to the web root.
4. Reload nginx.
5. Update agents (the dashboard can push an agent update, or
   re-run `install-client.sh`). Keep agent and server versions
   aligned — a feature that spans both needs both updated.

Releases are drop-in unless a release note says otherwise; state
files are forward-compatible. Read the relevant `docs/vX.Y.Z.md`
notes before a multi-version jump.

### 7.3 Rolling back

Re-deploy the previous release and restore the data directory backup
taken in step 1. Because state files only ever gain optional fields,
an older version simply ignores fields it does not recognise.

---

## 8. Troubleshooting

| Symptom | First thing to check |
|---|---|
| A device shows offline | `systemctl status remotepower-agent` on the host; then `journalctl -u remotepower-agent` |
| Agent can't reach the server | TLS trust, the server URL, firewalling on the path agent → server |
| 403 on the dashboard | Session expired — log in again; check the system clock if TOTP fails |
| A pushed config (drift, mailbox) doesn't take effect | Agent version — a config push only works on an agent new enough to know the field |
| CVE severities look wrong | Trigger a scan; pre-2.3.4 cache entries re-classify on next scan |

More in [troubleshooting.md](troubleshooting.md).

---

## 9. Where things live

| Item | Location |
|---|---|
| Application | the nginx web root (`server/` tree) |
| State (JSON) | the data directory — mode `0700`, files `0600` |
| Agent | `/usr/local/bin/remotepower-agent` + systemd unit |
| nginx vhost | your nginx `sites-available` / `conf.d` |
| Release notes | `docs/vX.Y.Z.md` |

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
