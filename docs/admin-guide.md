# RemotePower: install and admin guide

A complete operator's guide: installing RemotePower, securing it, running it day to
day, backing it up, and upgrading it. For a quick two-command install see
[install.md](install.md). This document is the longer, operational companion.

---

## 1. What you are installing

RemotePower has three parts:

- **The server.** nginx in front of a persistent gunicorn/Flask app server. It serves
  the dashboard and API, ingests agent heartbeats, and runs CVE and monitor checks.
  State lives in Postgres (the default for Docker and for `install-server.sh`) or in
  flat JSON or SQLite files for a lightweight install. See [security.md](security.md)
  for the data layout and [scaling.md](scaling.md) for the storage backends.
- **The agent.** A small Python script (`remotepower-agent`) on each managed host. It
  heartbeats out to the server every 60 seconds by default. The agent reaches the
  server, and the server never needs inbound access to a host. There are agents for
  Linux, macOS and Windows.
- **Optional daemons.** An out-of-band scheduler that runs the maintenance sweeps, a
  scanner for the Pentest page, a push daemon that nudges agents, and a web terminal
  daemon that proxies browser SSH sessions. `install-server.sh` installs the first
  three by default.

The server needs Python 3, nginx, and gunicorn with Flask. The agent needs only
Python 3.

---

## 2. Installing the server

### 2.1 Quick path: the wizard

On the host that will run the dashboard, the wizard sets up nginx, the app, TLS and
the admin account in one run, with HTTPS on by default and no fixed default password:

```
git clone https://github.com/tyxak/remotepower && cd remotepower
sudo bash install.sh
```

The wizard offers a self-signed certificate, Let's Encrypt, a certificate you bring, or
none (`--tls self-signed|letsencrypt|byo|none`). It stores state in files. Add
`--with-postgres` to provision Postgres, and `--with-scheduler` to run the maintenance
sweeps out of band. `sudo bash install.sh doctor` checks the host first without
changing anything, and `--dry-run` prints each step instead of running it.

Prefer containers? One command brings the server up over self-signed HTTPS and prints
the generated admin password to the container log:

```
docker compose up -d
```

Open the printed URL and sign in. To add hosts, use the one-line installer that the
dashboard hands you under **Hosts → Enroll host → Quick install command**
(`wget -qO- "https://your-server/install?t=<token>" | sudo sh`), or push the agent
over SSH:

```
sudo bash install.sh agent push --server https://your-server --token <token> user@host
```

One enrollment token enrolls one host, so mint one token per host. Tear an install
down with `sudo bash install.sh uninstall` (add `--purge` to remove the data too). See
[install.md](install.md) for the full quick-start.

**Advanced: the individual scripts.** For larger or segmented deployments you can run
the component scripts yourself. On the host that will run the dashboard:

```
sudo bash install-server.sh
```

This is the full single-node topology: nginx, gunicorn and Flask, Postgres, the
out-of-band scheduler, a scanner for the Pentest page and the push daemon. It lays out
the data directory and prints the dashboard URL plus a generated admin password. Opt
out of parts with `--no-postgres`, `--no-scheduler`, `--no-scanner` or `--no-push`.
Optional pieces such as the SSH gateway, the syslog and NetFlow receivers and the KMIP
key server are off unless you pass `--with-sshgw`, `--with-syslogd`, `--with-flowd` or
`--with-kmip`, because each opens a network port.

### 2.2 What the installer lays down

- The application under the web root (the `server/` tree).
- A data directory for local state, created with mode `0700`. The JSON and SQLite
  backends keep their state here, and it holds the files that stay on disk even under
  Postgres, such as certificates and backup archives.
- An nginx vhost with the security headers and the `/api/` `proxy_pass` location.
- The state files themselves, written with mode `0600`.
- The [`rp`](cli.md) command in `/usr/local/bin` (with `install-server.sh` and
  `deploy-server.sh`).

### 2.3 First login

Open the printed URL and sign in as `admin` with the password the installer printed.
The password is shown once. If RemotePower shows a banner asking you to change a
default password, do it straight away (see section 4.1).

---

## 3. Installing agents

On each host you want to manage, the easiest route is **Hosts → Enroll host** in the
dashboard. It gives you a one-line installer for Linux and macOS, one for Windows, and
a ready-made `docker compose` file to run the agent as a container. To install by
hand instead:

```
sudo bash install-client.sh
```

The script asks for the server URL and the 6-digit enrollment PIN, which you create
under **Hosts → Enroll host**. The PIN expires after 10 minutes. You can also pass
`--server URL --pin PIN` to skip the prompts. For a server with its own certificate
authority, add `--ca-fingerprint <sha256>` so the agent fetches and trusts that CA
only if the fingerprint matches. The agent installs as a systemd service
(`remotepower-agent.service`), enabled and started.

Running the installer again on an enrolled host is an upgrade: the binary and unit are
refreshed, enrollment and credentials are kept, and the agent restarts. Add
`--re-enroll` to enroll from scratch.

Check the result:

```
systemctl status remotepower-agent.service
journalctl -u remotepower-agent.service -n 50
```

A healthy agent logs a startup line with its version and the server URL, then
`Config updated:` lines as the server pushes it watch lists. Windows and macOS hosts
have their own installers: see [windows-client.md](windows-client.md).

### Agent logs and rotation

Every agent rotates its own log. There is no logrotate or newsyslog file to install.

| Platform | Log file | Rotation |
|---|---|---|
| Linux | `/var/log/remotepower-agent.log` | 5 MB × 5 backups (about 25 MB) |
| Windows | `%ProgramData%\RemotePower\agent.log` | 1 MB × 3 backups (about 4 MB) |
| macOS | `/var/log/remotepower-agent.log` | 5 MB × 5 backups (about 25 MB) |

On Linux the agent also logs to the journal (`journalctl -u remotepower-agent.service`),
so the file is a convenience copy. A file well under its cap has not reached the
rotation threshold yet. That is normal, not a missing rotation.

On macOS, launchd's own crash output goes to a separate
`/var/log/remotepower-agent-boot.log`. The rotating handler renames the file on
rollover while launchd keeps an open descriptor to the old one, so sharing one path
would send launchd's output somewhere nothing reads. The boot file normally stays
empty. It only catches a traceback that escapes Python logging, and the agent
truncates it if it ever passes 1 MB.

For fleet enrollment from cloud-init or Ansible, mint one-time enrollment tokens with
`POST /api/enrollment-tokens` instead of using a PIN. A token lasts 24 hours by default
(7 days at most), enrolls one host, and can carry a default group and tags. See
[install.md](install.md).

**Limit a token to a network** *(7.4.9)*. A token that leaks from a build log or a chat is good from anywhere until it
expires or is used. Add `allowed_cidrs` when you mint it, a list of addresses or networks (or one string separated by
commas, spaces or new lines), and it works from those only:

```json
{"label": "build network", "expires_in": 3600, "allowed_cidrs": ["10.20.0.0/16", "192.0.2.17"]}
```

A host that tries to enrol from another address gets a 403 and the attempt is written to the audit log
(`enrollment_token_refused_source`). The refusal does not use the token up, so a copy used from the wrong place does not
cost you the one meant for the right place. At most 10 entries, and a network that matches every address (`0.0.0.0/0`,
`::/0`) is refused, because a limit everything passes is not a limit. The address is the one the server sees: behind
your own reverse proxy, set `trust_proxy` so it reads the forwarded address (the local nginx the installer sets up is
handled already). **Enrollment tokens** in the list shows each token's networks.

---

## 4. Post-install hardening

RemotePower ships with sensible defaults, but a few steps are worth taking before it
manages anything important. [security.md](security.md) has the full list.

### 4.1 Change the admin password

Open **My Account** from the avatar menu in the top-right corner, then **Security →
Password**. You need your current password, and every other session signed in as you
is signed out. Passwords are stored with bcrypt (cost 12), or with salted PBKDF2 where
bcrypt is not installed. A default-password banner stays until the account's
"must change password" flag is cleared.

### 4.2 Turn on two-factor authentication

On **My Account → Security → Two-factor authentication**, scan the QR code with any
authenticator app and confirm one code. Store the recovery codes somewhere safe; they
are shown once. Turning 2FA off again needs your account password, so a stolen session
cookie alone cannot remove it. You can also register a passkey on the same page.

To make it mandatory, tick **Require MFA for admin accounts** (and list any other
roles) under **Settings → Security → Account guardrails**. That section also sets a
default expiry for API keys, a per-user session cap, and the webhook SSRF guard.

### 4.3 Put the dashboard behind TLS

Do not run the dashboard over plain HTTP outside localhost. Agents verify the server's
certificate, and the sign-in form and API tokens must not cross the network in the
clear. Terminate TLS at nginx. See [https.md](https.md), or [tls-selfsigned.md](tls-selfsigned.md)
for a private CA.

### 4.4 Restrict what a host will run

Each host can carry a **command allowlist**: open the host, go to **Actions &
settings**, and fill in **Command allowlist**. When the list has entries, only those exact commands can be
run on the host through exec, one per line (up to 50). Leave it empty to allow any
command except a short built-in denylist (`rm -rf /`, `mkfs`, writes to `/dev/sd*`,
`dd if=` and a fork bomb). Keep it as narrow as the host's role needs. Roles and their
permissions are managed on the **Users** page.

### 4.5 Secrets via environment variables

Sensitive configuration can come from the server's environment instead of being kept
in `config.json`:

- `RP_PROXMOX_TOKEN_SECRET` supplies the Proxmox API token secret.
- `RP_BACKUP_PASSPHRASE` turns on encrypted backups (see section 6).
- `RP_BACKUP_S3_SECRET_KEY` is the secret access key for copying backups to an S3-compatible bucket (`RP_BACKUP_S3_SECRET_KEY_CMD` prints it from a command). The rest of that setting is under **Settings → Backups**.
- `RP_CONFIG_KEY` encrypts secret fields in the stored configuration.

Put them in `/etc/remotepower/api.env`, which the `remotepower-wsgi` service loads with
`EnvironmentFile=`. Make the file root-owned with mode `0600`. Do not put them inline
in the unit file, which the update scripts overwrite. The redacted export on
Settings → Backups strips secret fields.

---

## 5. Day-to-day operation

### 5.0 Managing the server itself: `rp`

On the server, the [`rp`](cli.md) command controls the RemotePower stack in the style
of omd and checkmk. **`rp status`** (or the live **`rp tui`**) shows every component,
**`sudo rp restart`** bounces the stack (or one part, `sudo rp restart push`),
**`sudo rp doctor`** health-checks everything and suggests fixes, `rp logs <component>`
follows a unit, and `rp deploy` and `rp repair` update or restore the install. See
[cli.md](cli.md) for the full guide and troubleshooting table.

### 5.1 The dashboard

The Dashboard is the daily view. By default it shows fleet tiles (hosts online,
pending updates, drift events, critical CVEs), upcoming events, open alerts, the fleet
health score, a heat map, a "needs attention" column and recent activity. You can add,
remove and resize widgets. See [dashboard.md](dashboard.md). Click any host for
sysinfo, journals, CVEs, drift, services and command output.

### 5.2 Running commands

Open the **Hosts** page. The **⋯** menu on a host offers shutdown, reboot, Wake-on-LAN,
package upgrade, **Scan packages now**, **Update agent**, a custom command, the web
terminal and more. **Bulk actions** (or `Ctrl/Cmd-K` and "Bulk actions") runs an action
across many hosts at once. Every action is recorded in the activity feed and in the
per-host command history. See [fleet-management.md](fleet-management.md).

### 5.3 Monitoring

- **CVE scanning** is automatic and uses OSV. After patching a host, use **Scan
  packages now** on it to refresh its inventory straight away.
- **Drift detection** hashes watched config files on every heartbeat. Review and
  accept baselines on the host.
- **External monitors** run ping, TCP and HTTP probes. **TLS / DNS** tracks certificate
  and domain expiry.
- **Mailbox monitor** is under Settings → Mailbox monitor.
- **Alerts.** State changes fire webhooks, email and push. Configure destinations
  under Settings → Notifications and thresholds under Settings → Alert parameters.
  See [alerts.md](alerts.md).

### 5.4 Virtualization

**Settings → Virtualization** connects your hypervisors. **Proxmox VE** uses a scoped
API token for one node. The Virtualization and Containers pages then list QEMU VMs and
LXC containers. Start, stop, reboot, snapshot, clone and migrate are off until you
tick **Allow VM/CT lifecycle actions**, because they change running guests.

**VMware vSphere, ESXi and vCenter, VMware Cloud Director and OpenShift
Virtualization** are added on the same tab as platforms. On the Virtualization page a
platform picker lists guests and offers **power** actions (start, shutdown, reboot,
suspend, filtered to each platform) and **snapshot** actions (create, revert, delete).
Any signed-in user can read; power and snapshot actions are admin-only and audited. See
[virtualization.md](virtualization.md).

### 5.5 Settings and controls worth knowing

- **Login banner** (Settings → General) is an optional notice shown above the sign-in
  form, for example "Authorized use only."
- **Per-API-key rate limits** (Admin → API Keys) give a key its own requests-per-minute
  budget. `0` means unlimited.
- **Two-person break-glass** protects the most sensitive vault credentials. One admin
  requests a reveal, a second approves, the whole exchange is audit-logged, and a
  `vault_break_glass` alert fires.
- **Agent mutual TLS** (Settings → Security → Agent mutual TLS) pins a per-host client
  certificate and can enforce it fleet-wide, so the server only accepts heartbeats from
  a known agent.
- **Maintenance mode** (Settings → Security → Maintenance mode) pauses new command
  dispatch during a server upgrade. Heartbeats and read-only browsing keep working, so
  hosts do not flip offline. Planned work on the hosts themselves belongs in
  [maintenance.md](maintenance.md).
- **Guided self-update** (Settings → Install) takes an absolute path to an update
  script and adds a **Run update now** button. See [upgrading.md](upgrading.md).
- **Backup encryption.** Set `RP_BACKUP_PASSPHRASE` and archives are written as
  AES-256-GCM. **Server Status → Encrypt existing backups** converts archives already on
  disk. See [backups.md](backups.md).
- **Status Board** and **Network Metrics** give glanceable fleet-wide views for large
  estates.

---

## 6. Backup and restore

What holds your data depends on the storage backend. The JSON backend keeps files in
the data directory. SQLite adds a single `remotepower.db` there. Postgres keeps state
in the database and leaves only certificates, backup archives and similar files in the
data directory.

### 6.1 Built-in backup (recommended)

**Settings → Backups** has a daily **Scheduled backup** (on by default, 14 days of
retention) and three buttons:

- **Full backup (tar.gz)** downloads an archive that can rebuild the server, including
  the encrypted credentials vault and integration secrets. Keep it private.
- **Export (redacted ZIP)** strips API keys and integration secrets, so it is safe to
  store or share. It is for reference, not for a restore.
- **Restore…** loads an archive back, on any storage backend.

The archive carries your data whichever backend you run, because the database backends
export their documents into it. **Test restore (latest backup)** checks that the newest
archive opens, and a scheduled drill does the same every week. Set
`RP_BACKUP_PASSPHRASE` to encrypt archives, and set an off-host copy path so a lost
server does not take its backups with it. All of that is in [backups.md](backups.md).

### 6.2 Filesystem backup

On the JSON or SQLite backend you can also copy the data directory:

```
tar czf remotepower-backup-$(date +%F).tar.gz -C /path/to/datadir .
```

Saves are atomic, so a backup never catches a half-written file. It can catch a mix of
old and new files across a multi-file update, so stop the server briefly if you need a
consistent copy. On Postgres, back up the database with your usual tooling as well.

### 6.3 Restore

The easiest route is **Settings → Backups → Restore…** with the archive. RemotePower
takes a safety snapshot of the current state first. To restore by hand on the JSON or
SQLite backend, stop the server, replace the data directory contents from the archive,
restore ownership (`0700` on the directory, `0600` on the files) and start the server.

---

## 7. Upgrading

### 7.1 Check for updates

**Settings → Install → Check for updates** compares the running version with the latest
published release. When a newer one exists, a banner appears with the release notes
link and the update steps. **Snooze 30d** hides the banner for that version.
RemotePower never changes its own code by itself. You run the update, or you set up the
optional guided self-update script.

### 7.2 Upgrade procedure

1. **Back up** (section 6).
2. Pull the new release.
3. `sudo bash install.sh update` detects whether this is a plain code deploy or a
   pre-6.1.0 CGI conversion, redeploys the `server/` tree and reloads nginx. `rp deploy`
   does the code deploy too. Full detail: [upgrading.md](upgrading.md).
4. Update agents. The host menu has **Update agent**, and you can also run
   `install-client.sh` again. Keep agent and server versions aligned, because a feature
   that spans both needs both updated.

Releases are drop-in unless a release note says otherwise, and state files are
forward-compatible. Read the release notes for each version before a multi-version
jump.

### 7.3 Rolling back

Each deploy first saves a snapshot of the code, and the three newest are kept.
`sudo bash deploy-server.sh --rollback` restores the newest one. That restores code
only. If the newer version changed the database schema, also restore the data backup you
took in step 1; the server logs a loud warning on every request while the schema is
newer than the code. State files only gain optional fields, so an older version ignores
fields it does not recognise.

---

## 8. Troubleshooting

| Symptom | First thing to check |
|---|---|
| A host shows offline | `systemctl status remotepower-agent` on the host, then `journalctl -u remotepower-agent` |
| Agent cannot reach the server | TLS trust, the server URL, and firewalling between agent and server |
| 403 on the dashboard | The session expired, so sign in again. If a TOTP code fails, check the system clock |
| A pushed config (drift, mailbox) does not take effect | The agent version: a push only works on an agent new enough to know the field |
| Pages load but nothing updates | `sudo rp doctor`, then `rp logs wsgi` |
| The server will not start after an upgrade | `rp logs wsgi`, then `rp repair` |

More in [troubleshooting.md](troubleshooting.md).

---

## 9. Where things live

| Item | Location |
|---|---|
| Application | The nginx web root (`server/` tree) |
| State | The data directory (mode `0700`, files `0600`), plus the database on Postgres |
| Server settings that come from the environment | `/etc/remotepower/api.env` |
| Agent | `/usr/local/bin/remotepower-agent` plus a systemd unit |
| nginx vhost | Your nginx `sites-available` or `conf.d` |
| Release notes | `docs/vX.Y.Z.md` and `CHANGELOG.md` |

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
