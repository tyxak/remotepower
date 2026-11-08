# Backups & disaster recovery

RemotePower covers backups at three levels: **scheduled backup jobs** it runs on
your hosts, **freshness and integrity monitoring** of backups you already run, and
**disaster recovery of the control plane itself**.

## Backup jobs

**Backups** (sidebar) lists scheduled jobs: Name, Host, Schedule, Last run, Enabled
and Actions. A job is a backup command (restic, borg, rsync or tar, detected
automatically) plus a cron schedule, queued to a host through the audited command
pipeline.

- **API.** `GET/POST /api/backup-jobs`, `PUT/DELETE /api/backup-jobs/{id}`, and
  **Run now** (`POST /api/backup-jobs/{id}/run`).
- **Limits.** Cron expressions are validated. A fleet can hold up to 200 jobs.
- **Linux hosts only.** Backup jobs run on Linux hosts. A Windows or macOS host in a
  job is skipped: a scheduled run logs the skip in the command history, and **Run
  now** lists the skipped hosts in its reply. Use a native tool on those hosts and
  watch it with the freshness monitor below.
- **Apply one job to many hosts.** Pick one or more hosts when you create the job.
  The same backup runs on every one, on demand or on the schedule. Hosts you cannot
  manage (another tenant, outside your role's scope) are filtered out.
- **On-demand feedback.** For a single-host job, **Run now** waits for the agent's
  output and shows it in a progress dialog, including rsync's progress lines. A
  backup that outlasts the wait keeps running, and its output lands in the host's
  command history. A multi-host run queues on all hosts and reports the count.
- **Last-run status.** The jobs table shows each job's last outcome (succeeded,
  failed with the exit code, running or never), not only a timestamp, so a job that
  fails every night is easy to spot. For a multi-host job the badge summarises the
  per-host results.
- **Restore browser.** For file-backup jobs, **Restore** lists the archives at the
  destination (newest first, the latest pre-selected) so you pick one instead of
  typing a file name. For a multi-host job you first choose which host to restore to.
  `POST /api/backup-jobs/{id}/archives`.

### File backup (no shell required)

Instead of typing a command, pick **File backup** as the job type and fill in a form:
the **source paths** to back up (one per line, up to 20), a **method** (rsync for
incremental, or a single tar.gz archive) and a **destination**:

- **SSH.** rsync or tar over SSH to `user@host:/path`. It uses key authentication: the
  host needs an SSH key for the target, and no password is ever stored or typed.
- **NFS.** The export is mounted, the files copied, then unmounted.
- **SMB/CIFS.** The share is mounted (optionally with a credentials file that lives on
  the host, the same posture as an SSH key), copied, then unmounted.

The server builds the command from those fields and checks every value against a
strict allowlist: absolute paths only, no shell metacharacters, no `..`. You never
supply shell text, and no credential ever appears in the generated command. That
matters because it runs as root on the host. rsync progress is captured in the
command output, visible in the host's command history.

**Restore on demand.** A file-backup job has a **Restore** action that pulls the
backup back to a directory you choose on the host. It overwrites the restore path, so
it is admin-only, asks you to type `RESTORE`, and is audited.
`POST /api/backup-jobs/{id}/restore`.

### Proxmox Backup Server

Add a **Proxmox Backup Server** instance under **Settings → Integrations** (a PBS API
token). Its datastores then appear on the Backups page with fill percentage, dedup
factor, free and total space, and the estimated date it fills (only a date to come:
PBS says an estimate in the past means that usage is declining or not changing). A full
or unreachable datastore raises the standard `integration_down` and `integration_recovered`
alerts.

The connector also reads what PBS says is wrong, and the datastore's row says it under
the name:

- **An error.** PBS answers an error text for a datastore it cannot look up (and an
  available size of -1). The status is critical and the Backups page shows PBS's own words.
  Before 8.0.0 such a datastore read as one with nothing used in it.
- **Not mounted.** A removable datastore that is not mounted turns the status to a
  warning: backups cannot land on it, but the server is not at fault.
- **Bad chunks.** Chunks still marked bad after garbage collection mean a snapshot still
  refers to data that verification found damaged: a warning with the count.
- **Failed tasks.** The number of tasks that ended in an error in the last 24 hours, by
  kind (backup, verification, prune, garbage collection, sync), is a **Failed 24h**
  metric, and any failed task makes a healthy poll a warning. PBS shows a token only
  the tasks of its own user unless that user has **Sys.Audit** on `/system/tasks`: without
  it the count leaves out the scheduled jobs, so give the token's user that privilege
  if you want the number to mean "every task". A token that cannot list tasks at all
  leaves the figure out rather than reporting a zero.

These are read from the API schema PBS publishes (`/docs/api-viewer`). They were checked
against fixtures built from it, not against a running PBS.

## Backup freshness and integrity

For backups you run yourself with any tool, point the agent at the resulting files.
Add them under **Settings → Alerting → Backup file monitoring**: a file path, a label,
the maximum age in hours, and optional integrity and restore-drill checks. The host
drawer then shows each path with its age, threshold, status, verify result and
restore-drill result: open the drawer's **Audit** tab and expand **System → Backups**.

- **Freshness.** The agent checks each path's modification time on every heartbeat
  against the maximum age. Too old raises **`backup_stale`**; a refreshed backup
  raises **`backup_recovered`**.
- **Size drop.** Set **Shrink alert threshold** to a percentage and a fresh backup that
  falls below that share of its recent median size raises **`backup_size_anomaly`**.
  This catches a truncated or half-written file that is still recent. `0` turns it
  off, which is the default.
- **Integrity.** With **Verify integrity** on, the agent runs the tool's own check
  (`restic check`, `borg check`, `tar -t`) at most about once a week, with a time
  limit of 30 seconds per check. A bad archive raises **`backup_verify_failed`**; a
  passing one raises **`backup_verified`**. `restic` and `borg` need their passphrase
  in the agent's environment, for example `RESTIC_PASSWORD_FILE` or `BORG_PASSPHRASE`.
- **Restore drill.** With **Restore drill** on, the agent restores a sample path from
  the backup into a sandbox and checks it. A failure raises **`restore_drill_failed`**
  and the next pass raises **`restore_drill_ok`**. The host drawer's backup table shows how
  long ago the last integrity check and the last drill ran, next to their results *(7.5.0)*.
- **3-2-1 rule.** The same section scores each host against the 3-2-1 rule (three fresh
  copies, two kinds of target, one off-site) from what the monitors report. The score
  is a guide, not an alert. "Targets" and "off-site" are inferred from each monitor's
  target, so a monitor that names no target counts by its top-level folder.

**Tool** *(8.0.0)*. The form's **Tool** says which program checks the backup: `restic`, `borg` or `tar`, or **Guess from the path name**. The guess finds a tool only when
the name of the path says so (`restic` or `borg` in it, or a tar file name) and silently leaves a path with any other name unchecked, so choose the tool when the name
says nothing. Before 8.0.0 the form had no such field and every monitor it made was a guess.

The form has no field for how often the integrity check and the restore drill run. `verify_max_age_hours` and `restore_drill_max_age_hours` are in hours and weekly (168)
when unset. Set them on a monitor with `POST /api/config` under `backup_monitors`. Editing a monitor in the form keeps them *(8.0.0; an edit used to put both back to
weekly)*.

Backup events fire on a change of state, not on every heartbeat.

**Proxmox guest backups** have their own card on the Backups page. It compares each
guest's newest vzdump archive to a threshold (`proxmox_backup_warn_days`, 7 days by
default) and shows stale guests on the dashboard's attention card. Change the
threshold with **Save threshold** on that card.

## Control-plane disaster recovery

RemotePower can back up **itself** so you can rebuild the server after a loss.

- **Where.** **Settings → Backups** holds the schedule, and the **Server Status** page
  shows the last run and has a **Run now** button. A scheduled backup runs about once
  every 24 hours as one of the maintenance sweeps (out of band when the scheduler
  service is installed) and is on by default (`backup.enabled`). Archives go to
  `<data dir>/backups` unless you set an output path, and **Retain (days)** prunes old
  ones.
- **Two kinds of export.** On **Settings → Backups** you can download a **redacted
  export** (a ZIP with API keys and integration secrets stripped, safe to share) or a
  **full backup** (`.tar.gz`). The full backup can rebuild the controller, including
  the encrypted credentials vault and integration secrets, so keep it private.
  `GET /api/export` and `GET /api/backup/download`.
- **Encrypted archives.** Set `RP_BACKUP_PASSPHRASE` in the server's environment and
  archives are written as `.tar.gz.enc`: AES-256-GCM with a PBKDF2-SHA256 key
  (600,000 iterations), read and written in 64 KiB chunks. The passphrase comes only
  from the environment and is never stored. **Server Status → Encrypt existing
  backups** converts plaintext archives already on disk.
- **Every storage backend.** A backup archive carries your data whichever backend you
  run. On the JSON backend it is the data directory. On SQLite it adds a consistent
  database snapshot. On Postgres, which keeps nothing in the data directory, the
  archive holds an export of every logical document under the same file names the
  JSON backend uses. One archive shape therefore restores onto any backend. The
  backup result and Server Status report how many stores were written (`stores`).
- **Restore.** **Settings → Backups → Restore…** (or `POST /api/backup/restore`)
  accepts both archive shapes: the download stream, and the scheduled archive whose
  members sit under a `remotepower/` folder. It is admin-only, and it asks you to
  confirm your password or a one-time code first (a "step-up"), because a restore
  replaces the users and the settings. An API key cannot step up, so it cannot
  restore. For an encrypted
  archive the page asks for the passphrase, which reaches the server as the
  `X-RP-Backup-Passphrase` header; leave it blank to use the server's own. A restore:
  - saves a snapshot of the current state first, in the data directory's
    `restore-snapshots` folder, encrypted when a passphrase is set;
  - refuses unsafe archive members (absolute paths, `..`, links, special files) and archives
    that unpack past 2 GB or 50,000 members;
  - on SQLite and Postgres, imports the archive into the database instead of only
    unpacking files, because reads go to the database. The response reports
    `stores_imported`.
- **Test restore.** **Test restore (latest backup)** on Settings → Backups, or
  `POST /api/backup/test-restore`, decrypts and unpacks the newest archive and checks
  its structure, without touching live data.
- **Restore drill.** A scheduled drill runs the same decrypt, unpack and structure
  check against the latest archive and, when an off-host copy is configured, against
  that copy too. If either fails, the drill fails, because a pass should mean the
  backup you would restore from works. The drill counts the restorable state in the
  archive and fails when there is none, so an archive that opens but holds nothing
  cannot report green. It runs weekly by default. `backup.drill_days` sets the
  interval (`0` disables it, the maximum is 90) and you change it through
  `POST /api/config` with `{"backup": {"drill_days": N}}`. A failing drill raises
  `restore_drill_failed` (path `self:dr-archive`) in the alert inbox and notification
  channels, and the next passing drill resolves it with `restore_drill_ok`.
- **WORM audit sink.** `audit_worm_path` appends the hash-chained audit log to a
  tamper-resistant location (an append-only mount or S3 Object Lock), so the trail
  survives a full compromise.
- **Off-host copy.** Set **Off-host copy** (`backup.offsite_dir`) to a mounted path
  (NFS, SMB or sshfs) and each finished archive is copied there as well. The copy is
  best-effort and never fails the backup. The Security posture card on the Audit page grades it.
- **S3-compatible bucket.** Under **Settings → Backups → Scheduled backup**, tick *Also copy each backup to an S3-compatible
  bucket* and fill in the endpoint, the bucket, the region, a folder if you want one, and the access key id. AWS S3, MinIO,
  Backblaze B2, Wasabi, Cloudflare R2 and any other store that speaks S3 work. The secret access key is not a setting: put
  `RP_BACKUP_S3_SECRET_KEY` in the server's environment (or `RP_BACKUP_S3_SECRET_KEY_CMD`, a command that prints it), next to
  `RP_BACKUP_PASSPHRASE`, so it never lands in the data directory or in an archive. **Test S3 connection** writes, reads, lists and
  deletes a small object and tells you which step failed. With tenant isolation on, only the platform operator can use it, since the
  server connects to the address in the request.
  - Only an **encrypted** archive is sent. An unencrypted one holds every secret of the installation, so with no
    `RP_BACKUP_PASSPHRASE` the copy is skipped and Server Status says why.
  - Use an `https://` endpoint. A plain `http://` one is accepted for a private or loopback address only, such as a MinIO on your
    LAN. Link-local and cloud metadata addresses are refused when you save and again when the server connects, and a redirect is
    not followed. For a store with a self-signed certificate, untick *Verify the TLS certificate*.
  - An archive up to 5 GiB goes up in one request. A larger one goes up in parts of at least 64 MiB (up to 1 TiB), each part tried
    three times, and the upload is cancelled in the store when a part cannot be sent, so no half-finished upload is left behind.
    The SHA-256 is stored beside the archive either way. Run the copy from the scheduler, which is the default install. On a server
    installed with `--no-scheduler` a backup runs inside a web request, and a large upload can outlast the web worker's time limit
    (120 seconds), and the worker is stopped in the middle of it.
    Copies older than **Retain (days)** are deleted, never the newest and never more than 50 in one run, and only files named
    like the archives in your folder.
  - The restore drill reads the newest copy back, compares it with the digest stored at upload, and runs the same decrypt, unpack
    and structure check as for the local archive. A copy that changed in the store fails the drill.
  - **Restore from S3…** (Settings → Backups → Backup & restore) lists the archives in the bucket, newest first. It uses the settings
    in the form as they stand, saved or not, so it works on a rebuilt server that has none yet; the secret key still has to be in the
    server's environment. Pick **Restore**, confirm, and give the backup passphrase (leave it empty to use the server's own). The
    server reads the archive into a private scratch directory, compares it with the digest stored at upload, decrypts it, takes a
    safety snapshot of the current data and restores it the way an uploaded archive is restored. Only encrypted archives made by the
    copy are listed, and one over 1 GiB is not taken from the bucket: download it and restore the file. With tenant isolation on, only
    the platform operator can list or restore.
  - The Security posture row (Audit page) *Backups mirrored off-host* counts the bucket, and every destination you set has to have worked on
    the last run. A failed copy never fails the backup: Server Status shows the reason.
- **RPO and RTO targets.** `backup.rpo_hours` and `backup.rto_hours` (Settings →
  Backups, `0` is off). RPO is graded on Server Status against the hours since the last
  successful run, and a target with no successful run reads as breached. RTO is a
  declared target only. Test restore reports its own timing as a lower bound, not a
  measure of a full service restore.

### Key escrow and break-glass

`RP_BACKUP_PASSPHRASE` is **never persisted anywhere RemotePower controls**. It lives
only in the environment of whatever runs the server (a systemd unit, Docker Compose
and so on). That is the right place for the passphrase itself, but it means
**RemotePower cannot help you if you lose it**: a lost passphrase makes every existing
encrypted archive permanently unrecoverable, with no reset. Treat it like a root disk
encryption key, not an application password.

- Store it in your organisation's real secret-escrow system (a shared password
  manager vault, HashiCorp Vault, a sealed envelope in a safe) **before** you rely on
  encrypted backups in production.
- Write down, outside RemotePower, where it is escrowed and who can reach it. Someone
  needs to find it during an incident, possibly without the person who set it.
- Rotating the passphrase does **not** re-encrypt existing archives. New archives use
  the new passphrase, so keep the old one escrowed for as long as you keep archives it
  encrypted.
- If backup encryption is off (no `RP_BACKUP_PASSPHRASE`), archives are plaintext and
  there is nothing to escrow. The Security posture card on the Audit page flags that trade-off.

## Permissions

- Creating, editing and deleting backup jobs, the Proxmox threshold, restore and test
  restore are **admin-only**.
- **Run now** needs the `command` permission on the target hosts.
- Every job edit and recovery operation is audit-logged. Backup commands pass through
  the same quarantine and four-eyes controls as any other host command.

## Troubleshooting

- **A job skips a host.** The host is Windows or macOS, or it is quarantined. Backup
  jobs run on Linux hosts and not on quarantined ones.
- **The host's Backups section is empty.** Nothing is watching a path on that host yet.
  Add one under **Settings → Alerting → Backup file monitoring**.
- **`backup_verify_failed` for restic or borg.** The agent has no passphrase. Set
  `RESTIC_PASSWORD_FILE` or `BORG_PASSPHRASE` in the agent's environment.
- **Restore says the backup is encrypted.** Supply the passphrase in the restore
  dialog, or set `RP_BACKUP_PASSPHRASE` on the server.

See also: [self-monitoring.md](self-monitoring.md) for the Server Status page,
[data-retention.md](data-retention.md) for how long records are kept,
[upgrading.md](upgrading.md) for the pre-upgrade backup, and
[incident-response.md](incident-response.md) for using these in a recovery.
