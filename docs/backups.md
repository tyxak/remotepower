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
- **Apply one job to many devices (a baseline).** Pick one or more devices when
  you create the job — the same backup runs on every one, on demand or on the
  schedule. (Cross-tenant / out-of-scope devices are filtered out for you.)
- **On-demand feedback.** For a single-device job, **Run now** waits for the
  agent's output and shows it in a progress dialog (including rsync's progress
  lines); a backup that outlasts the wait window keeps running and its output
  lands in the device's command history. A multi-device run queues on all and
  reports the count.
- **Last-run status.** The jobs table shows each job's last **outcome** — ✓
  succeeded / ✗ failed (with the exit code) / running / never — not just a
  timestamp, so a job that silently errors every night is obvious at a glance.
  For a multi-device job the badge summarises per-host results.
- **Restore browser.** For tar jobs, **Restore** lists the archives at the
  destination (newest first, the latest pre-selected) so you pick one instead of
  typing the filename; for a multi-device job you first choose which host to
  restore to. `POST /api/backup-jobs/{id}/archives`.

### File backup (structured — no shell required)

Instead of typing a command, pick **File backup** as the job type and fill in a
form: the **source paths** to back up (one per line), a **method** (rsync for
incremental, or a single tar.gz archive), and a **destination**:

- **SSH** — rsync/tar over ssh to `user@host:/path`. Uses **key authentication**
  (the host needs an ssh key for the target; no password is ever stored or typed).
- **NFS** — the export is mounted, the files copied, then unmounted.
- **SMB/CIFS** — the share is mounted (optionally with a **host-side credentials
  file**, the same posture as an ssh key), copied, then unmounted.

The server **generates the command** from those fields and validates every value
against a strict allowlist (absolute paths only, no shell metacharacters, no
traversal) — the operator never supplies shell text, and **no credential ever
appears in the generated command** (it runs as root on the host, so this matters).
rsync progress is captured in the command output, visible in the device's command
history.

**Restore on demand** — a file-backup job has a **Restore** action that pulls the
backup back to a directory you choose on the host. It's destructive (it overwrites
the restore path), so it is admin-only, requires typing `RESTORE` to confirm, and
is audited. `POST /api/backup-jobs/{id}/restore`.

### Proxmox Backup Server

Configure a **Proxmox Backup Server** instance under **Settings → Integrations**
(a PBS API token) and its datastores appear on the Backups page — fill %, dedup
factor, free/total space and estimated-full date per datastore. A full or
unreachable datastore raises the standard `integration_down` / `integration_recovered`
alerts.

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
- A **scheduled restore drill** *(v6.3.0)* runs the same
  decrypt→decompress→structure-check as the manual test-restore against the
  latest archive, weekly by default (`backup.drill_days`, 0 disables, max 90 —
  settable via `POST /api/config` `{"backup": {"drill_days": N}}`). A failing
  drill fires `restore_drill_failed` (path `self:dr-archive`) into the alert
  inbox and notification channels; the next passing drill auto-resolves it via
  `restore_drill_ok`. So "the backup is restorable" is continuously proven,
  not assumed — if the passphrase changes, the cryptography library breaks, or
  archives corrupt, you hear about it within a week instead of during a
  disaster.
- An optional **WORM audit sink** (`audit_worm_path`) appends the hash-chained
  audit log to a tamper-resistant location (an append-only mount or S3 Object
  Lock), so the audit trail survives even a full compromise.
- Optional **off-host mirroring** (`backup.offsite_dir`) copies each finished
  archive to a second, typically off-host, location (an NFS/SMB/sshfs mount)
  so a host loss doesn't take the backups with it — best-effort; a copy
  failure never fails the backup itself, and the result is graded on the
  Security posture page.
- Optional **RPO/RTO targets** (`backup.rpo_hours`, `backup.rto_hours`,
  Settings → Maintenance): RPO is graded automatically on
  `GET /api/self/status` against hours-since-last-successful-run (a target
  with no successful run to compare against reads as breached, not silently
  "fine"). RTO is a declared target only — `POST /api/backup/test-restore`
  surfaces the closest real signal available (its own decrypt+decompress+
  structure-check timing), labelled explicitly as a lower bound, not a full
  service-restore measurement.

### Key escrow / break-glass

`RP_BACKUP_PASSPHRASE` is deliberately **never persisted anywhere RemotePower
controls** — it lives only in the process environment of whatever runs the
server (systemd unit, Docker Compose, etc.). That's the right posture for the
passphrase itself, but it means **RemotePower cannot help you if you lose it**:
a lost or forgotten passphrase makes every existing encrypted archive
permanently unrecoverable, with no reset/recovery path. Treat it like a
root disk-encryption key, not an application password:

- Store it in your organisation's actual secret-escrow system (a password
  manager's shared vault, HashiCorp Vault, a sealed physical envelope in a
  safe — whatever your org already uses for "if this person is unreachable,
  can someone else still get in") **before** you rely on encrypted backups in
  production, not after the first incident.
- Write down (outside RemotePower) *where* it's escrowed and *who* can reach
  it — the passphrase being safe is only half the plan; someone needs to be
  able to find it during an actual incident, possibly without the person who
  originally set it.
- Rotating the passphrase does **not** re-encrypt existing archives — plan
  for a rotation to mean "new archives use the new passphrase; keep the old
  one escrowed too, for as long as you keep archives it encrypted."
- If backup encryption is off (no `RP_BACKUP_PASSPHRASE` set), none of the
  above applies — archives are plaintext and there is nothing to escrow, but
  see the Security posture page for that trade-off.

## Permissions

- Creating/editing/deleting backup jobs, the Proxmox threshold, restore and
  test-restore are **admin-only**; **Run now** is available to any non-viewer.
- Every job edit and DR operation is audit-logged. Backup commands ride the same
  quarantine / 4-eyes controls as any other host command.
