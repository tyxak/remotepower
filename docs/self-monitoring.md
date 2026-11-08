# Server Status — RemotePower watching itself

> **On the machine itself**, the [`rp`](cli.md) command is the terminal
> counterpart of this page: `rp status` (or the live `rp tui`) shows every stack
> component, and `rp doctor` checks the whole stack and exits non-zero on a
> failure. This page is the in-browser view of the same picture.

**Admin → Server Status** closes the "who monitors the monitor" gap. Without it
you only know the fleet is healthy because RemotePower says so. If the server
itself starts misbehaving, you would find out the slow way.

Any signed-in user can open the page and read the status. Running a backup, the
diagnostics, the maintenance-sweep list, the browser-error list and the
detection self-test need an admin.

## The toolbar

| Button | What it does |
|---|---|
| **Refresh** | Reloads every card. |
| **Run backup now** | Takes a snapshot backup of the data directory immediately (see [Backup scheduling](#backup-scheduling)). |
| **Diagnostics bundle** | Downloads one JSON support file: versions, storage backend, fleet counts, recurring-job staleness, audit chain status and which optional libraries are installed. Secrets are removed. Attach it to a support request. |
| **Run diagnostics** | A quick green/red check of storage, config, disk headroom, the audit chain, agent reachability, the AI key (informational), the observed uptime and the maintenance scheduler. |
| **Clear backup archives** | Deletes every backup archive (encrypted or not) and resets the backup state. It cannot be undone. |

## What the page shows

Top to bottom:

**Control-plane readiness.** One row per part of RemotePower itself that can fail
without paging anyone: storage, the request tier, the maintenance scheduler, the
maintenance sweeps, the recurring jobs, backup and disaster recovery, and each
optional sidecar. Rows with a problem sort first, and the header counts them:
*"N subsystems · N degraded · N needing a look"*. See [Readiness and muting a
row](#readiness-and-muting-a-row).

**Serving & runtime.** What is really serving this install: the storage backend
(PostgreSQL, SQLite or JSON files), the request tier (WSGI with gunicorn), the
out-of-band scheduler (running, configured but silent, or off) and whether
maintenance runs inside each request or in the scheduler. See
[scaling.md](scaling.md) to change any of it.

**Distributed subsystems.** Relay satellites and scan workers (online of total),
the agent push daemon, the SSH gateway, the web terminal, and the syslog, flow and
KMIP sidecars. The same rows as in the readiness table. The web terminal is
optional and may run on another host, so a daemon that does not answer on this
server reads as *Not detected locally* and is never a fault.

**Restart the stack.** The exact `systemctl restart` command, with a copy button:
the app workers and the scheduler, and each sidecar in use on this server, so a
copy leaves no daemon on old code. That is the scan worker, the push daemon, the SSH
gateway and the web terminal while they are set up here, and the syslog, flow and
KMIP daemons while their unit is active on this server (a unit that runs on another
host is not named, because `systemctl` would refuse the whole command). The sentence
above the command names the same units. RemotePower runs as an unprivileged
service, so a restart needs root on the host. Installs that set up the
privileged helper can also restart from **Settings → Install → Restart server**,
and the card says why when that is unavailable. That button restarts the app
workers and the scheduler only.

**Site health.** A **healthy** pill, or the number of warnings with a **View N
reasons** link. It shows the server version and when it last
changed (with the last few upgrades), load average, memory, the worker's memory
use, active sessions, the share of hosts online and the process ID. A warning is
raised for:

- load: the 5-minute load average above the core count times a ratio (default 2),
- memory use above 90%,
- fewer than 80% of hosts online,
- a webhook success rate under 90% in the last 24 hours.

You can change the first three under **Settings → Alert parameters →
RemotePower self-health**.

**Hosts.** Monitored count, hosts offline now, the freshest and oldest
heartbeat, and the configured online TTL.

**Webhook delivery — outbound.** Success rate over 24 hours and 7 days, and the
number of log entries kept (up to 500). Skipped events (disabled, suppressed by a
maintenance window or filtered) do not count as failures. A rate under 95% usually
means a destination is rejecting your payloads (rate limit, bad format, dead
URL). The failed deliveries are under **Settings → Notifications**, see
[webhooks.md](webhooks.md).

**Inbound webhooks & syslog.** The same rates for what arrives, split by kind.

**Disk.** The data directory's size, how full its filesystem is, and the largest
files over 100 KB (collapsed). When a runaway log fills the disk, this shows which
file grew. A **disk watchdog** raises `server_disk_low` when the filesystem
reaches a used-space threshold, before writes start failing. It checks every 30
minutes and clears with `server_disk_ok` once usage is 3 points below the
threshold. The threshold is **Settings → Alert parameters → Hardware & power →
Server disk (used %)**, default 85, and 0 turns it off.

**Audit log.** Active entries, the retention in days and the archive size if
entries have been moved out.

**Backup.** Whether archives are encrypted, how many are encrypted or plaintext,
and when the last run was, with the file, size, what the archive carries,
retention and the last prune. If you set targets under **Settings → Backups**,
you also see the RPO (maximum time between backups) as met or breached, and the
RTO (restore-time target) with the result of the last test restore. Buttons:
**Encrypt existing backups** (appears when plaintext archives exist) and
**Verify restorability now**. The page shows the setup steps for encryption if it
is off. See [Backup scheduling](#backup-scheduling) and [backups.md](backups.md).

**Recurring jobs.** KEV and EPSS refresh, monitors and scheduled scans, each
with its last run. A job is *stale* when it last ran more than three times its
interval ago, which usually means it is wedged.

**Slow requests.** The newest requests slower than the threshold (default 1500 ms),
so you can see which endpoint is slow on your real fleet. The card is hidden
until there is one. Set `slow_handler_ms` through `POST /api/config` to change
the threshold.

**Fleet events.** Size of the event log and its archive.

**Internal health — maintenance sweeps.** Every background sweep (offline
detection, monitors, integrations, DMARC and ticket mailboxes, ticket SLA,
backups, rollouts and more) with its last good run, error count and last error. The
sweeps run behind a catch-all so one failing sweep cannot stop the rest, which
used to make a sweep that quietly stopped invisible. A red **FAILING** row means
its last run ended in an error. Recent internal errors are listed underneath.
(`GET /api/self/observability`, admin only.)

**Client-side JS errors.** Uncaught errors from operators' browser sessions,
grouped by message, source file and line, with a count, the page they fired on
and the reporting address. The list keeps the newest 200. It is admin only, and
**Clear** empties it. After a fix ships, an empty list is the proof.

**Detection self-test.** A read-only check that every alertable event type
reaches a person: it flags types muted on every channel, test mode left on,
webhook-only types with no destination, and recover events that can never close
their alert. It sends nothing. See [detection-selftest.md](detection-selftest.md).

## Optional sidecars

The ingest and key-custody daemons get a row only when they are in use. A
receiver you do not run is not a fault.

| Row | What it tells you |
|---|---|
| **Agent push daemon** | Whether the channel is on, its port, and whether it answers on loopback. See [push.md](push.md). |
| **SSH Gateway** | Whether the module is on, its ports, and how many opted-in hosts are connected. See [sshgw.md](sshgw.md). |
| **Syslog receiver** | Mapped sources, last intake and the unit state. See [syslog.md](syslog.md). |
| **Flow receiver** | Exporters, last export and the unit state. See [flow.md](flow.md). |
| **KMIP key server** | Clients, stored keys, the unit state and the **soonest certificate expiry** across the CA and every live client certificate. See [kmip.md](kmip.md). |

A row names what it is talking about. A flow receiver with three exporters where
one has gone quiet reports that exporter by label and how long it has been silent.
Both receivers match a packet to its token by the **sender's source IP** against
the IP of the enrolled host, so a token whose host has no IP, or is gone, can never
receive anything. The row says so instead of blaming the router. The name list is
capped, with a `+N more` tail. The receiver rows link to **Settings →
Integrations → Inbound webhooks & syslog → Tokens**.

## Alerts about RemotePower itself

Most of this page is information. These conditions also raise alerts:

| Event | When |
|---|---|
| `server_disk_low`, `server_disk_ok` | The data directory's filesystem is fuller than the watchdog threshold, and the recovery. |
| `sidecar_down`, `sidecar_recovered` | A sidecar you enabled (syslog, flow, KMIP) has stopped. It is checked every 5 minutes, and only when systemd is present and reports a definite `inactive` or `failed`. A sidecar running on another host stays silent. |
| `ingest_source_unmappable`, `ingest_source_mapped` | A syslog or flow token is wired to a host that has no IP, or no longer exists. A token you disabled yourself is not reported. |
| `kmip_cert_expiring`, `kmip_cert_renewed` | The KMIP CA or a live client certificate expires within the window in **Settings → Alert parameters → Certificates → Cert-file expiring** (default 21 days). Checked every 6 hours. Revoked clients are ignored. |
| `restore_drill_failed`, `restore_drill_ok` | The scheduled restore drill failed, and the next pass. See [backups.md](backups.md). |

A KMIP outage matters more than most. When the key server stops, every
appliance that stores its volume keys there fails to unlock at its next reboot,
and an expired client certificate ends that appliance's key access the same way.

## Readiness and muting a row

An amber row you have already decided about, such as an optional receiver you have
not wired up, can be muted from the row itself. A muted row turns grey, keeps
showing what it would have said, and stops counting toward *needing a look*. The
header reports it separately as `N muted`, and **Unmute** puts it back.

Mutes are an admin setting. They are stored in the server config, so they are the
same for every operator. A mute for a row that no longer exists does nothing, so
renaming a subsystem un-mutes it instead of silencing the wrong one.

The reason: a tally that permanently reads "1 needing a look" for something nobody
means to act on teaches people to ignore the number, which is when the row that
does matter goes unread.

## External monitoring

`GET /api/self/status` returns JSON for any signed-in session or API key. Use it
from Uptime Kuma, Grafana or Homepage for "is RemotePower healthy" checks. Useful
fields:

- `devices.offline` should be 0 (or the number you tolerate),
- `webhooks.last_24h.rate` should be above 0.95,
- `backup.last_run` should be within about 30 hours,
- `data_dir.fs_free_bytes` should not fall below a threshold you pick,
- `performance.health` is `ok` or `warn`, with the reasons in `performance.health_flags`.

The **status token** under **Settings → Integrations → Status endpoint** does not
work here. It opens a different payload, the fleet summary at
`GET /api/status?token=...`. Use that one if your monitoring tool cannot hold a
session. See [status-board.md](status-board.md).

## Backup scheduling

The daily backup runs from the server's maintenance cadence. It checks the time of
the last run on each tick and runs when more than 24 hours have passed. With the
out-of-band `remotepower-scheduler` (the single-node default) that tick is the
scheduler's. Otherwise it is checked on incoming requests. A marker file stops two
runs from overlapping, and a marker older than one hour is treated as a crashed run
and cleared.

**Run backup now** starts the same job at once and skips the 24-hour wait.

An archive is a gzipped tar of the whole data directory under a top-level
`remotepower/` folder. It leaves out:

- the backups folder itself,
- the restore safety snapshots and the KMIP master key (which only travels in the
  passphrase-protected KMIP recovery bundle),
- in-flight temporary files and existing `.gz` archives,
- on SQLite, the live database files. A consistent snapshot of the database goes
  in instead.

On SQLite and PostgreSQL the archive also carries an export of every stored
document, so one archive restores onto any backend. Owner and group are stripped, so
restoring on another host does not fail with "missing uid". A file the server cannot
read is skipped instead of failing the whole backup.

Set the output folder, retention (default 14 days, older archives are pruned on each
run), an off-host copy and the RPO and RTO targets under **Settings → Backups →
Scheduled backup**. **Test restore (latest backup)** there, and **Verify
restorability now** on this page, decrypt and unpack the newest archive and report
how much state it carries. Nothing is written.

To encrypt archives, set `RP_BACKUP_PASSPHRASE` in the server's environment. Put it
in `/etc/remotepower/api.env` (owned by root, mode 0600), which the
`remotepower-wsgi` unit loads. Do not add it as an `Environment=` line in the unit:
the deploy and update scripts overwrite the unit file. `RP_BACKUP_PASSPHRASE_CMD`
runs a command that prints the passphrase instead, for use with Vault or a KMS.
**Encrypt existing backups** converts plaintext archives on disk with a passphrase
you type for that run. It is never stored.

## Restoring from a backup

**Settings → Backups → Backup & restore → Restore…** takes a backup file directly.
It works on a freshly installed host, which is the point: pick the archive off a USB
stick and the server unpacks it in place, after taking a safety snapshot of whatever
data is already there. Restore is admin only and overwrites current data. On
PostgreSQL and SQLite it imports the archive's stored documents instead of just
unpacking files.

An **encrypted** archive (`*.tar.gz.enc`) is offered by the file picker and asks for
its passphrase: the one that was in `RP_BACKUP_PASSPHRASE` on the server that
*wrote* it. Leave the prompt blank to use the passphrase already configured on this
server.

If you cannot log in, the archives are ordinary tarballs you can unpack yourself:

```bash
# Stop the app server and nginx (no writes during the restore)
systemctl stop remotepower-wsgi nginx

# Keep the existing data directory
mv /var/lib/remotepower /var/lib/remotepower.before-restore

# Extract the snapshot. An encrypted archive (.enc) is NOT an openssl-format
# file: it is AES-256-GCM with a PBKDF2 header written by backup_crypto.py.
# Decrypt it first with the module that wrote it (see the next section).
mkdir -p /var/lib/remotepower
cd /var/lib/remotepower
tar -xzf /var/lib/remotepower.before-restore/backups/remotepower_data_YYYYMMDD_HHMMSS.tar.gz
mv remotepower/* .  # the tarball has a `remotepower/` top-level folder
rmdir remotepower

# Reapply ownership to the service user (www-data on Debian and Ubuntu)
chown -R www-data:www-data /var/lib/remotepower

# Start again
systemctl start remotepower-wsgi nginx
```

On a PostgreSQL install the state lives in the database, so unpacking files is not
enough. Use the in-app **Restore…** instead.

### Decrypting a `.enc` archive by hand

`*.tar.gz.enc` is **not** an `openssl enc` file. It is AES-256-GCM in a custom
container (`RPBKENC1` magic, PBKDF2-SHA256 at 600,000 iterations, streamed in 64 KiB
chunks so a multi-GB archive never loads whole). There is no `openssl` one-liner.
Use the module that wrote it, which ships with the server:

```bash
cd /var/www/remotepower/cgi-bin
python3 -c "
import backup_crypto, pathlib
backup_crypto.decrypt_file(pathlib.Path('/path/to/backup.tar.gz.enc'),
                           pathlib.Path('/path/to/backup.tar.gz'),
                           'YOUR-PASSPHRASE')"
```

A wrong passphrase or a tampered file fails the GCM tag check and raises an error
instead of producing garbage. The in-app restore does exactly this for you.

If the backup came from a host with a different `RP_PROXMOX_TOKEN_SECRET`
environment variable, set the token secret again under **Settings →
Virtualization**. The same goes for SMTP and LDAP bind passwords if they were
redacted, which they always are in `config.json` exports.

## Troubleshooting

- **"Configured — no heartbeat" for the scheduler.** The flag is set but no
  scheduler process is reporting. Start it with `sudo systemctl enable --now
  remotepower-scheduler`. Until then the maintenance sweeps may not run.
- **A sweep shows FAILING.** Read its last error in **Internal health**. A failing
  sweep takes its feature down without an alert, which is why the readiness table
  counts it.
- **"Last archive is hollow" on PostgreSQL.** The archive opened but carried no
  stored documents, so a restore would give an empty install. Check the backup sweep
  under Internal health for the export error, then run a backup again.
- **A receiver says "Running — no sources mapped".** The daemon is up but its token
  map is empty, so every packet is dropped. Enroll the host with a syslog or flow
  token under **Settings → Integrations → Inbound webhooks & syslog**.
- **The status token returns 401 on this page.** Use a session or an API key for
  `/api/self/status`, see [External monitoring](#external-monitoring).
- **Restart is not offered in the app.** The card says why: a hardened unit that
  cannot gain privileges, or no helper installed. Use the command it shows, and see
  [upgrading.md](upgrading.md).

See also: [cli.md](cli.md), [scaling.md](scaling.md), [backups.md](backups.md),
[webhooks.md](webhooks.md), [alert-parameters.md](alert-parameters.md).

## With multi-tenancy

The self-test, the security posture, the setup checklist and the diagnostics bundle describe the installation. With tenant isolation on, only users of the default tenant can open them.
