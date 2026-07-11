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

**Backup** — last run timestamp + age, file path, size, retention setting, last-prune count. Empty section until the first backup runs. v5.0.0 adds an **encryption** row (AES-256-GCM armed or plaintext, whether the crypto library is present) and **archive counts** (encrypted vs plaintext), plus an **"Encrypt existing backups"** button that converts the plaintext archives on disk with a passphrase you supply for that run only (it's never stored). For ongoing scheduled backups, set `RP_BACKUP_PASSPHRASE` in the server environment — put it in `/etc/remotepower/api.env` (root-owned `0600`), which the `remotepower-api` worker unit loads via `EnvironmentFile=`. Don't add it as an inline `Environment=` line in the unit: the deploy/update scripts overwrite the unit file, so an inline edit is wiped on the next redeploy.

**Maintenance mode** (v5.0.0) — when on, new command dispatch is paused (heartbeats and browsing keep working). Surfaced as a banner; toggled under Settings → Advanced.

**Webhook dead-letter queue** (v5.0.0) — permanently-failed webhook deliveries are parked here for retry/replay (Settings → Notifications → Webhook log). See [webhooks.md](webhooks.md).

**Fleet events** — current rolling file size, archive size.

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

If your monitoring system can't auth, generate a status token in Settings → Advanced → Status endpoint (a separate read-only token, not your session).

## Backup scheduling

The daily backup runs via the heartbeat hook — every incoming heartbeat checks the `self_backup_state.last_run` timestamp and runs the backup if >24h has elapsed. A sentinel file (`.backup_in_progress`) prevents two simultaneous heartbeats from both triggering. Stale-lock recovery: if the sentinel is >1h old it's assumed crashed and gets cleared.

The "Run backup now" button on the page triggers `POST /api/self/backup-now` manually. Same code path as the scheduled run; bypasses the 24h gate.

What's in the tarball: a gzipped tar of the entire `DATA_DIR`, excluding:
- The backups directory itself (`backups/`)
- In-flight `.tmp.*.<pid>.<nonce>` files from in-progress writes
- Existing `.gz` archives (already compressed; re-compressing wastes time)

Owner/group are stripped (`uid=gid=0`, empty names) so restoring on a different host doesn't fail with "missing uid".

Retention defaults to 14 days. Older tarballs are pruned on each run. Change the path or retention in Settings → Advanced → Scheduled backup.

## Restoring from a backup

There's no in-UI restore — backup files are tarballs you can extract yourself. Procedure:

```bash
# Stop the app server + nginx (we don't want writes during restore)
systemctl stop remotepower-wsgi nginx

# Back up the existing data dir (paranoid)
mv /var/lib/remotepower /var/lib/remotepower.before-restore

# Extract the snapshot
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

If the backup was created on a host with a different `RP_PROXMOX_TOKEN_SECRET` environment variable, re-set Settings → Proxmox → token secret. Same for SMTP / LDAP bind passwords if they were redacted (they always are in `config.json` exports).
