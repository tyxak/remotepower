# Backups & disaster recovery

RemotePower covers backups at three levels: **scheduled backup jobs** it runs on
your hosts, **freshness + integrity monitoring** of backups you already run, and
**disaster recovery of the control plane itself**.

## Backup jobs

**Backups** (sidebar) lists scheduled jobs — Name, Device, Schedule, Last run,
Enabled, Actions. A job is a backup command (restic / borg / rsync / tar, auto
-detected) plus a cron schedule, queued to a host through the audited command
pipeline.

- `GET/POST /api/backup-jobs`, `PUT/DELETE /api/backup-jobs/{id}`, and
  **Run now** (`POST /api/backup-jobs/{id}/run`).
- Cron expressions are validated; up to 100 jobs per fleet.

## Backup freshness & integrity

For backups you run yourself (any tool), point the agent at the resulting files:

- **Freshness** — `collect_backup_status` checks each monitored path's mtime
  against `max_age_hours`. Too old raises **`backup_stale`**; a refreshed backup
  raises **`backup_recovered`**.
- **Integrity** — `collect_backup_verify` runs the tool's own check (`restic
  check`, `borg check`, `tar -t`) on a weekly-ish rate gate, bounded to ~30s per
  check. A bad archive raises **`backup_verify_failed`** (high); a passing one
  raises **`backup_verified`**. Verification needs the repo passphrase in the
  agent's environment (e.g. `RESTIC_PASSWORD_FILE`, `BORG_PASSPHRASE`).

All four events are edge-triggered (fire on transition, not every heartbeat).

**Proxmox guest backups** get a dedicated card: per-guest vzdump archive age vs a
`proxmox_backup_warn_days` threshold (default 7), surfaced on the dashboard
attention card.

## Control-plane disaster recovery

RemotePower can back up **itself** (its whole data directory) so you can rebuild
the server after a loss:

- **Encrypted DR backups** (`backup_crypto.py`) — AES-256-GCM with PBKDF2-SHA256
  (600k iterations). The passphrase comes **only** from the `RP_BACKUP_PASSPHRASE`
  environment variable and is never persisted. Archives (`.tar.gz.enc`) are
  written and read in 64 KiB chunks for bounded memory.
- `GET /api/backup/download` streams the data dir; `POST /api/backup/restore`
  restores from an uploaded archive (admin, with a safety confirmation);
  `POST /api/backup/test-restore` verifies the latest backup actually restores.
- A **scheduled self-backup** runs off the heartbeat path, gated to once every
  24h (`backup.enabled`, state in `self_backup_state.json`, guarded by a
  `.backup_in_progress` sentinel). The gate uses the storage-aware
  `backend_exists()` so it behaves correctly on the SQLite/Postgres backends.
- An optional **WORM audit sink** (`audit_worm_path`) appends the hash-chained
  audit log to a tamper-resistant location (an append-only mount or S3 Object
  Lock), so the audit trail survives even a full compromise.

## Permissions

- Creating/editing/deleting backup jobs, the Proxmox threshold, restore and
  test-restore are **admin-only**; **Run now** is available to any non-viewer.
- Every job edit and DR operation is audit-logged. Backup commands ride the same
  quarantine / 4-eyes controls as any other host command.
