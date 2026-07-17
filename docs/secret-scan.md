# Exposed secrets on disk & canary files

*Secrets-on-disk scan in v3.14.0; per-fingerprint mutes in v3.14.0, whole-host
mutes in v4.1.0; canary (honeytoken) files in v6.0.0; "Scan now" in v6.1.2.*

Two related tripwires, both agent-side and both **off by default**:

- the **secrets-on-disk scan** — agents periodically sweep configured paths
  for credentials that shouldn't be lying around in files (private keys, API
  tokens, passwords) and report *redacted* findings;
- **canary files** — agents plant decoy credential files and raise a critical
  alert the moment anything reads, modifies or deletes one.

## What is reported — and what never leaves the host

The scanner is **redacting by construction**. For each finding the agent
sends only:

- the **rule** that matched (e.g. `aws_access_key`, `private_key`),
- the **file path** and **line number**,
- a **masked preview** — the first few characters plus the length
  (`AKIA********…(20)`), never the full value,
- a **fingerprint** — the first 16 hex chars of the value's SHA-256, so the
  server can dedupe and mute a finding without ever seeing the secret.

The secret's value itself is never transmitted, and the server re-sanitizes
defensively on ingest before persisting to `secret_findings.json` — so
neither the wire nor the control plane's datastore ever holds it. (The
sibling [PII scan](pii-scan.md) goes one step further and drops even the
fingerprint, because PII is low-entropy enough to reverse a hash; API keys
are not.)

Detection rules: private keys (PEM headers), AWS access keys, GitHub tokens
and PATs, Slack tokens and webhook URLs, Google API keys, Stripe live keys,
JWTs, plus a lower-confidence generic `password/secret/api_key/token = …`
assignment catch-all (the usual false-positive source — mute those).

## Enabling and cadence

**Settings → Security → Secrets-on-disk scanning**: tick **Enable
secrets-on-disk scanning** (config `secrets_scan_enabled`) and optionally set
**Scan paths** (one per line, config `secrets_scan_paths`; blank = the
agent's per-OS defaults):

- Linux: `/etc /root /home /opt /srv /var/www`
- macOS: `/etc /Users /opt /usr/local /srv`
- Windows: `C:\Users C:\ProgramData C:\inetpub`

The server pushes the flag and paths to every agent in the heartbeat
response; nothing is installed or changed host-side. The scan runs on a
**~6-hour cadence** — on Linux and macOS as a persisted wall-clock interval
(it survives agent restarts), on Windows shortly after agent start and every
~360 polls.

It is bounded hard so it can never hog a host: at most 200 findings, 5,000
files visited, 1 MiB read per file, ~12 s wall clock per run; binaries,
symlinks and noise directories (`.git`, `node_modules`, `venv`, …) are
skipped.

### Scan now

`POST /api/secrets-scan/scan` with `{"device_id": "..."}` for one host or
`{}` for every agent host (requires the `exec` write permission, and the scan
must be enabled). It sets a one-shot `force_secrets_scan` flag the agent
honours on its next heartbeat. Linux and macOS agents honour it; the Windows
agent runs only on its own cadence. There is currently no UI button for this
— it's API-only.

## Findings, alerts and mutes

Findings appear on the **Exposure** page under **"Exposed secrets on disk"**
(filterable by device / type / path / preview), backed by
`GET /api/fleet/secrets` — scope- and tenant-filtered, values never present.
The Security posture page also shows whether the scan is enabled.

Alerting is edge-triggered per fingerprint: a `secret_exposed` event
(severity **high**) fires only when a *new*, un-muted fingerprint appears on
a host — and only **one summary event per ingest** (first finding + count),
so enabling the scan on a host with 50 pre-existing findings produces one
alert, not fifty.

Two mute levels, both admin-only and audit-logged:

- **Per finding** — `POST /api/secrets/mute` `{fingerprint, unmute?}` (the
  Mute button on the Exposure row). The finding stays listed, flagged muted,
  and stops alerting/counting. The fingerprint is a hash prefix, never the
  secret.
- **Per host** — `POST /api/secrets/host-mute` `{device_id, unmute?}` for a
  host whose findings you've accepted wholesale: none of its findings alert
  or count, open `secret_exposed` alerts for it are auto-resolved, and its
  rows stay visible flagged muted.

## Canary files (honeytokens)

**Settings → Security → Canary files (honeytokens)**: one absolute path per
line (config `canary_files`; blank = off). At each path the agent plants a
decoy file (mode 0600) containing realistic-but-fake AWS credentials — a
custom `content` per entry can be set via `POST /api/config` — and then
watches it every heartbeat:

- **read** — atime advancing past plant time,
- **modified** — mtime or size changed,
- **deleted** — file gone.

Any of the three is reported to the server (`canary_events` in the
heartbeat), which fires a **`canary_accessed`** event — severity
**critical** — carrying the path and the reason. Nothing legitimate ever
touches a decoy, so this is as close to a zero-false-positive intrusion
tripwire as monitoring gets (a backup job or indexer that walks the path is
the one benign trigger to think about when choosing locations).

Behaviour worth knowing:

- The agent **never overwrites an existing file**: a path that already
  exists is baselined and watched, but its content is untouched — and on
  uninstall the agent removes only decoys it created itself.
- Each access is reported **once per agent run** (edge-triggered in memory);
  an agent restart re-baselines the file and re-arms detection.
- Detecting pure *reads* depends on the filesystem updating atime: the Linux
  default `relatime` catches the first read; on a `noatime` mount only
  modification and deletion are detected.
- Canaries are implemented in the **Linux agent only** — Windows and macOS
  agents ignore the `canary_files` key.

## API

| Method | Path | Auth | Notes |
|--------|------|------|-------|
| GET  | `/api/fleet/secrets` | any | Redacted findings per device + active count + enabled flag. |
| POST | `/api/secrets-scan/scan` | `exec` write role | `{device_id?}` — queue a one-shot scan (all agent hosts when omitted). |
| POST | `/api/secrets/mute` | admin | `{fingerprint, unmute?}` — mute one finding. |
| POST | `/api/secrets/host-mute` | admin | `{device_id, unmute?}` — mute a whole host; auto-resolves its open alerts. |
| POST | `/api/config` | admin | `secrets_scan_enabled`, `secrets_scan_paths`, `canary_files` (list of `{path, content?}`), plus the stored mute lists `secrets_mutes` / `secrets_host_mutes`. |

Implementation: `collect_secret_findings` / `_plant_canaries` /
`_check_canaries` in `client/remotepower-agent.py` (siblings in the Windows
and macOS agents for the scan); `_ingest_secret_findings`, the
`canary_events` ingest and `handle_fleet_secrets` / `handle_secrets_*` in
`server/cgi-bin/api.py`.

Related: [pii-scan.md](pii-scan.md) — the sibling scan for regulated data,
[exposure.md](exposure.md) — the page the findings live on,
[security.md](security.md) — the wider trust-boundary story,
[alerts.md](alerts.md) — acknowledge/resolve for the fired events.
