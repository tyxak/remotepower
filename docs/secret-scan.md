# Exposed secrets on disk & canary files

Two tripwires that run on the host, both **off by default**:

- the **secrets-on-disk scan**: the agent sweeps the paths you choose for
  credentials that should not be lying around in files (private keys, API
  tokens, passwords) and reports *redacted* findings;
- **canary files**: the agent plants decoy credential files and raises a
  critical alert the moment anything modifies, deletes or (where the
  filesystem records access times) reads one. Linux, Windows and macOS.

## What is reported, and what never leaves the host

The scanner redacts by construction. For each finding the agent sends only:

- the **rule** that matched (for example `aws_access_key` or `private_key`),
- the **file path** and **line number**,
- a **masked preview**: the first few characters plus the length
  (`AKIA********…(20)`), never the full value,
- a **fingerprint**: the first 16 hex characters of the value's SHA-256, so the
  server can dedupe and mute a finding without ever seeing the secret.

The secret itself is never sent. The server cleans the fields again when it
stores them, so neither the network nor the server's data holds the value. The
sibling [PII scan](pii-scan.md) goes one step further and drops even the
fingerprint, because personal data is easy enough to guess that a hash would
give it away. API keys are not.

The rules cover private keys (PEM headers), AWS access keys, GitHub tokens and
personal access tokens, Slack tokens and webhook URLs, Google API keys, Stripe
live keys, JWTs, and a lower-confidence generic `password`, `secret`,
`api_key` or `token` assignment. The generic rule is the usual source of false
positives. Mute those.

## Enabling and cadence

Open **Settings → Security → Secrets-on-disk scanning**, tick **Enable
secrets-on-disk scanning**, and optionally fill in **Scan paths** (one per
line, up to 50). Leave the paths blank to use the agent's defaults:

- Linux: `/etc /root /home /opt /srv /var/www`
- macOS: `/etc /Users /opt /usr/local /srv`
- Windows: `C:\Users C:\ProgramData C:\inetpub`

The server hands the switch and the paths to every agent in the heartbeat
response. Nothing is installed or changed on the host. The scan runs about
every 6 hours. The agent keeps the time of the last run on disk on all three
platforms, so a restart does not reset the clock.

The scan is capped so it cannot hog a host: at most 200 findings, 5,000 files
visited, 1 MiB read per file and about 12 seconds per run. Binary files,
symlinks and noise folders (`.git`, `node_modules`, `venv` and similar) are
skipped.

### Scan now

On the **Exposure** page, **Scan now** queues a one-shot scan on every agent
host. The agents run it on their next heartbeat. It needs an admin or an
operator role (viewer, auditor, finance and MCP roles get a 403), and the scan
must be enabled in Settings first, otherwise the server answers 400.

## Findings, alerts and mutes

Findings appear on the **Exposure** page (Security group) under **Exposed
secrets on disk**. You can filter by host, type, path or preview. Everyone who
can see a host can see its findings, and tenants only see their own hosts. The
**Security posture** card on the **Audit** page also shows whether the scan is
switched on.

Alerting is edge-triggered per fingerprint. A `secret_exposed` event (severity
**high**) fires only when a *new*, un-muted fingerprint appears on a host, and
only **one summary event per ingest** (the first finding plus a count). Turning
the scan on for a host that already holds 50 findings produces one alert, not
fifty. When a rescan finds nothing left on a host, `secret_cleared` closes the
open alert. You can silence either event under **Settings → Notifications →
Per-event toggles**.

Two mute levels, both admin-only and both written to the audit log:

- **Mute** on a row silences one finding fleet-wide, by fingerprint. The row
  stays listed, marked muted, and stops alerting and counting. With
  multi-tenancy on, only the platform operator can do this, because the list
  is shared by every tenant.
- **Mute host** silences a host whose findings you have accepted as a whole.
  None of its findings alert or count, its open `secret_exposed` alerts are
  closed, and its rows stay visible marked muted. A tenant admin can only do
  this for hosts in their own tenant.

**Unmute** and **Unmute host** reverse both.

## Canary files (honeytokens)

Open **Settings → Security → Canary files (honeytokens)** and enter one
absolute path per line (blank turns canaries off). At each path the agent
plants a decoy file (mode 0600) with realistic but fake AWS credentials, then
watches it on every heartbeat:

- **read**: the access time moved past the time of planting,
- **modified**: the modification time or the size changed,
- **deleted**: the file is gone.

Any of the three is reported with the path and the reason, and the server fires
a **`canary_accessed`** event with severity **critical**. Nothing legitimate
touches a decoy, so this is close to a zero-false-positive intrusion tripwire.
A backup job or indexer that walks the path is the one benign trigger, so pick
locations they skip.

The settings page saves paths only. To give a decoy its own contents, send
`content` for that entry through `POST /api/config` (see the table below).

### Where a decoy can live

A canary is a file written as root (or SYSTEM) with content you supply, so the
server and the agent both refuse places where the system runs what it finds:

- folders such as `/etc/cron.d/`, `/etc/systemd/`, `/etc/sudoers.d/`,
  `/usr/bin/`, `/usr/local/bin/`, `/etc/profile.d/`, and the Windows startup
  and `System32` folders;
- files such as `~/.ssh/authorized_keys`, `~/.bashrc`, `/etc/crontab` and
  `/etc/sudoers`;
- executable and script types, for example `.sh`, `.py`, `.ps1`, `.exe`,
  `.service` and `.timer`.

Saving one of these returns 400 with the reason. Use a name a thief would open
instead, such as `/root/.aws/credentials.bak`. Paths may be POSIX
(`/root/.aws/credentials.bak`), drive-letter (`C:\Users\Public\payroll.xlsx`)
or UNC (`\\server\share\decoy.docx`). Traversal (`..`) is rejected under either
separator, and you can set up to 50 canaries.

### Checking that a decoy is really in place

The agent reports the outcome of every planting, and the host drawer shows it
in the **Canary files** row, worst first:

| Status | Meaning |
|--------|---------|
| `NOT PLANTED` | The agent could not create the decoy. The reason is shown, for example a read-only filesystem, permission denied, or a folder that does not exist. |
| `watching a real file (not a decoy)` | A real file was already at the path. The agent never overwrites it, so the path is a change-watch on real data, not a honeytoken. |
| `not yet planted` | Configured, but the agent has not processed it yet. |
| `armed` | The agent created the decoy and is watching it. |

A host with a failed planting also gets a **Canary not armed** reason in its
risk score. You can change its weight under **Settings → Alert parameters →
Risk score weights**.

### Behaviour worth knowing

- The agent **never overwrites an existing file**, and it does not create
  missing folders. On uninstall it removes only decoys it created itself.
- In **audit mode** (the read-only agent flag) the agent plants nothing and
  marks every path `NOT PLANTED` with the reason `audit mode (read-only)`.
- Each access is reported **once per agent run**. A restart baselines the file
  again and re-arms detection.
- Detecting a plain *read* depends on the filesystem updating access times.
  The Linux default `relatime` catches the first read. On a `noatime` mount
  only changes and deletions are detected. **On Windows this is the usual
  case**: NTFS last-access updates are off by default
  (`NtfsDisableLastAccessUpdate`), so treat read detection there as
  best-effort. Changes and deletions, which is what ransomware does, are caught
  on every platform. macOS keeps access times, so reads are detected there.
- Uninstall cleanup covers Linux and Windows. The macOS agent has no uninstall
  command, so a Mac agent you remove by hand leaves its decoys on disk. Delete
  them yourself.

## Troubleshooting

- **No findings, and you expect some.** Check that the scan is enabled and that
  the host runs an agent (agentless hosts cannot scan). Paths outside your list
  are not visited, and a run stops after 5,000 files or about 12 seconds, so
  point **Scan paths** at the folders that matter instead of `/`.
- **"Scan now" says scanning is off.** Enable it under **Settings → Security**
  first.
- **A finding is still listed after you removed the secret.** The list only
  changes when the agent rescans, which happens every 6 hours. Use **Scan now**
  to check sooner. If the same value is still in another file, it is still
  reported there.
- **A canary shows `NOT PLANTED`.** Read the reason in the drawer. Fix the path
  (the parent folder has to exist) or pick a writable location.
- **A canary fired and you are sure nobody opened it.** Look for a backup,
  indexer or antivirus scanner that walks the folder, and move the decoy.

## API

| Method | Path | Auth | Notes |
|--------|------|------|-------|
| GET  | `/api/fleet/secrets` | any signed-in user | Redacted findings per host, the active count and the enabled flag. Scoped to the hosts the caller can see. |
| POST | `/api/secrets-scan/scan` | admin or an operator role | `{device_id?}`. Queues a one-shot scan (all agent hosts when omitted). Needs the scan enabled. |
| POST | `/api/secrets/mute` | admin (platform operator under multi-tenancy) | `{fingerprint, unmute?}`. Mutes one finding. |
| POST | `/api/secrets/host-mute` | admin | `{device_id, unmute?}`. Mutes a whole host and closes its open alerts. |
| POST | `/api/config` | admin | `secrets_scan_enabled`, `secrets_scan_paths`, `canary_files` (a list of `{path, content?}`, up to 50), and the stored mute lists `secrets_mutes` and `secrets_host_mutes`. |

See also: [pii-scan.md](pii-scan.md) for the sibling scan for regulated data,
[exposure.md](exposure.md) for the page the findings live on,
[alerts.md](alerts.md) for acknowledging and resolving the fired events, and
[security.md](security.md) for the wider trust boundaries.
