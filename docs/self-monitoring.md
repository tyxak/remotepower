# Server status — RemotePower watching itself

> **On the box itself**, the [`rp`](cli.md) command is the terminal counterpart of
> this page: `rp status` (or the live `rp tui`) shows every stack component, and
> `rp doctor` runs a full health check with fixes. The page below is the in-browser
> view of the same picture.

The Server status page (`/api/self/status`) closes the "who monitors the monitor" gap. Without it, you only know the fleet is healthy because RemotePower says so — but if the RemotePower server itself starts misbehaving, you find out the slow way.

## What's reported

**Process** — server version, PID, resident memory (RSS).

**Devices** — monitored count, current offline count, freshest and oldest heartbeat ages, configured online TTL.

**Webhook delivery** — success rate over the last 24h and 7d, total entries logged. Drops below 95% usually mean a destination is rejecting your payloads (rate limit, invalid format, dead URL) and the operator needs to investigate.

**Disk** — RemotePower's data dir total bytes, filesystem-level used/free, and the top 20 files >100KB (collapsible). Useful when a runaway log fills disk; the page tells you which file grew. A **disk watchdog** (v5.0.0) also raises a `server_disk_low` alert when the controller's free space crosses a configurable threshold, before flock writes start failing, and clears it with `server_disk_ok`.

**Audit log** — active entry count, configured retention in days, archive size if any entries have been evicted.

**Backup** — last run timestamp + age, file path, size, retention setting, last-prune count. Empty section until the first backup runs. v5.0.0 adds an **encryption** row (AES-256-GCM armed or plaintext, whether the crypto library is present) and **archive counts** (encrypted vs plaintext), plus an **"Encrypt existing backups"** button that converts the plaintext archives on disk with a passphrase you supply for that run only (it's never stored). For ongoing scheduled backups, set `RP_BACKUP_PASSPHRASE` in the server environment — put it in `/etc/remotepower/api.env` (root-owned `0600`), which the `remotepower-wsgi` app-server unit loads via `EnvironmentFile=`. Don't add it as an inline `Environment=` line in the unit: the deploy/update scripts overwrite the unit file, so an inline edit is wiped on the next redeploy.

**Maintenance mode** (v5.0.0) — when on, new command dispatch is paused (heartbeats and browsing keep working). Surfaced as a banner; toggled under Settings → Advanced.

**Webhook dead-letter queue** (v5.0.0) — permanently-failed webhook deliveries are parked here for retry/replay (Settings → Notifications → Webhook log). See [webhooks.md](webhooks.md).

**Fleet events** — current rolling file size, archive size.

**Client-side JS errors** (v6.4.0) — the browser error beacon
(`window.onerror` / `unhandledrejection`, collected since v5.4.1) is rendered
as a card on this page: uncaught frontend errors from operators' sessions,
deduped-by-occurrence in a capped ring, newest first, with source file/line,
the page they fired on and the reporting IP. Admin-only (`GET
/api/client-error`), with a **Clear** action (`DELETE /api/client-error`) —
after a fix ships, the list staying empty is the verification.

**Detection self-test** (v6.3.1) — a read-only card verifying the
detection → routing → delivery chain is intact for every alertable event type
(muted-everywhere kinds, test mode left on, webhook-routed kinds with no
destination, recover events that can never close their alert). It fires
nothing; see [detection-selftest.md](detection-selftest.md).

**Optional sidecars** — informational rows for the ingest and key-custody
daemons, each reported **only when that sidecar is enabled** and deliberately
never a health input on its own (a receiver you don't run is not a fault):

| Row | What it tells you |
|---|---|
| **Agent push** | Whether the channel is on, its port, and whether the daemon actually answers on loopback — see [push.md](push.md) |
| **Syslog** | Mapped sources, last ingest time, and the `remotepower-syslogd` unit state — see [syslog.md](syslog.md) |
| **Flow** | Reporting exporters, last ingest time, and the `remotepower-flowd` unit state — see [flow.md](flow.md) |
| **KMIP** | Live clients, stored keys, last sidecar check-in, the `remotepower-kmipd` unit state, and the **soonest PKI expiry** across the CA and every live client certificate — see [kmip.md](kmip.md) |

The KMIP expiry number is there because an expired client certificate silently
ends that appliance's key access, and encrypted volumes then fail to mount
after its next reboot. It also **alerts** — `kmip_cert_expiring` (and its
`kmip_cert_renewed` recovery) fires from a six-hourly sweep, routed through the
existing certificate-files channel. These certificates are server-side, with no
agent to report them, so they needed their own sweep rather than riding the
agent's cert-file check. Revoked clients are ignored: they cannot fetch keys
anyway.

## Where the data lives

| Section | Source |
|---|---|
| Process | `os.getpid()`, `/proc/self/status` for RSS |
| Devices | `devices.json` |
| Webhook delivery | `webhook_log.json` (last `MAX_WEBHOOK_LOG` entries, default 500) |
| Disk | `DATA_DIR.iterdir()` + `os.statvfs()` |
| Audit log | `audit_log.json`, `audit_log_archive.jsonl.gz` |
| Backup | `self_backup_state.json` |
| Fleet events | `fleet_events.json`, `fleet_events_archive.jsonl.gz` |

All reads. No writes happen from this endpoint.

## External monitoring

`GET /api/self/status` returns JSON. Auth: any logged-in user. Use it from Uptime Kuma / Grafana / Homepage for "is RemotePower healthy" checks. The shape is documented inline — fields are stable across patch releases. Suggested checks:

- `devices.offline` should equal 0 (or your tolerated count)
- `webhooks.last_24h.rate` should be >0.95
- `backup.last_run` should be within ~30 hours (allow slack for the 24h schedule + drift)
- `data_dir.fs_free_bytes` shouldn't fall below a sensible threshold

`/api/self/status` needs a normal session or API key — the **Settings → Advanced status token does not work here**; it authenticates a different, fleet-summary payload. If your monitoring system can't hold a session, point it at `GET /api/status?token=…` instead (a read-only fleet summary, not this self-status payload).

## Backup scheduling

The daily backup runs from the server's maintenance cadence: the `self_backup_state.last_run` timestamp is checked on each tick and the backup runs if >24 h has elapsed. When the out-of-band `remotepower-scheduler` owns the cadence — the single-node default — that tick is the scheduler's; otherwise it is checked on each incoming request. (Before v6.1.2 this hung off the heartbeat handler and ran unconditionally on every beat.) A sentinel file (`.backup_in_progress`) prevents two concurrent runs; if it is >1 h old it's assumed crashed and gets cleared.

The "Run backup now" button on the page triggers `POST /api/self/backup-now` manually. Same code path as the scheduled run; bypasses the 24h gate.

What's in the tarball: a gzipped tar of the entire `DATA_DIR`, excluding:
- The backups directory itself (`backups/`)
- In-flight `.tmp.*.<pid>.<nonce>` files from in-progress writes
- Existing `.gz` archives (already compressed; re-compressing wastes time)

Owner/group are stripped (`uid=gid=0`, empty names) so restoring on a different host doesn't fail with "missing uid".

Retention defaults to 14 days. Older tarballs are pruned on each run. Change the path or retention in Settings → Advanced → Scheduled backup.

## Restoring from a backup

**Settings → Advanced → Backup & restore → Restore** takes a backup file
directly. It works on a freshly-installed host, which is the point: pick the
archive off a USB stick and the server unpacks it in place, after taking a
safety snapshot of whatever data is already there.

An **encrypted** archive (`*.tar.gz.enc`) is offered by the file picker and
prompts for its passphrase — the one that was in `RP_BACKUP_PASSPHRASE` on the
server that *wrote* it. Leave the prompt blank to use the passphrase already
configured on this server instead. (Before v6.4.2 the picker did not offer
`.enc` at all and the passphrase never reached the server, so an encrypted
archive could only be restored by hand.)

If you would rather do it by hand — or you cannot log in — the archives are
ordinary tarballs:

```bash
# Stop the app server + nginx (we don't want writes during restore)
systemctl stop remotepower-wsgi nginx

# Back up the existing data dir (paranoid)
mv /var/lib/remotepower /var/lib/remotepower.before-restore

# Extract the snapshot. An encrypted archive (.enc) is NOT an openssl-format
# file — it is AES-256-GCM with a PBKDF2 header written by backup_crypto.py.
# Decrypt it with the module that wrote it (see the note below this block).
mkdir -p /var/lib/remotepower
cd /var/lib/remotepower
tar -xzf /var/lib/remotepower.before-restore/backups/remotepower_data_YYYYMMDD_HHMMSS.tar.gz
mv remotepower/* .  # tarball has a `remotepower/` top-level dir
rmdir remotepower

# Reapply ownership
chown -R www-data:www-data /var/lib/remotepower

# Start back up
systemctl start remotepower-wsgi nginx
```

### Decrypting a `.enc` archive by hand

`*.tar.gz.enc` is **not** an `openssl enc` file — it is AES-256-GCM in a custom
container (`RPBKENC1` magic, PBKDF2-SHA256 at 600k iterations, streamed in 64 KiB
chunks so a multi-GB archive never loads whole). There is no `openssl` one-liner.
Use the module that wrote it, which ships with the server:

```bash
cd /var/www/remotepower/server/cgi-bin
python3 -c "
import backup_crypto, pathlib
backup_crypto.decrypt_file(pathlib.Path('/path/to/backup.tar.gz.enc'),
                           pathlib.Path('/path/to/backup.tar.gz'),
                           'YOUR-PASSPHRASE')"
```

A wrong passphrase or a tampered file fails the GCM tag check and raises rather
than producing garbage. The in-app restore does exactly this for you.

If the backup was created on a host with a different `RP_PROXMOX_TOKEN_SECRET` environment variable, re-set Settings → Virtualization → token secret. Same for SMTP / LDAP bind passwords if they were redacted (they always are in `config.json` exports).

## Internal health — maintenance sweeps

The Server-status page shows an **Internal health** card: every background
maintenance sweep (offline detection, monitors, integrations, DMARC/IMAP,
ticket SLA, backups, rollouts, …) with its **last successful run**, error count,
and last error. The sweeps run inside a swallow-all wrapper so a single failing
one can never take down the cadence — but that also meant a sweep that silently
stopped, or started failing, used to be invisible until someone noticed a stale
feature. Now a red **FAILING** row (its last outcome was an error) or a sweep
that hasn't run OK in a long time is visible immediately, with a rolling list of
recent internal errors underneath. Served by `GET /api/self/observability`
(admin).
