# Data retention — what RemotePower keeps, for how long, and where

RemotePower's compliance mapping treats retention as your responsibility. This page is the
other half of that sentence: every store, the setting that trims it, and what the shipped
default really does.

The short version:

- Every log is bounded two ways: an optional **age limit** in days, and a **row cap** that is
  always on.
- Only the audit log has an age limit out of the box (90 days). The other age limits are off
  until you set them.
- On a busy fleet the row cap trims first. A policy that says "we keep command history for
  N days" is not true of a default install, because the log only holds its last 200 rows.

So set the numbers you need, and check the row caps in the table below against them.

---

## What bounds each store

| Store | Row cap (always on) | Age setting | Default age |
|---|---|---|---|
| Audit log, live part | newest 500 entries; older ones go to the archive | `audit_log_retention_days` | **90** days. 0 means no age limit. |
| Command history | 200 rows, fleet-wide (`command_history_max`, 50 to 20,000) | `history_retention_days` | off |
| Fleet events | 1,000 rows | `fleet_events_retention_days` | off |
| Webhook delivery log | 500 rows | `webhook_log_retention_days` | off |
| Monitor history | 300 results per monitor (`monitor_history_max`, 10 to 5,000) | `monitor_history_retention_days` | off |
| Alerts | 5,000 rows | `alerts_retention_days` (resolved alerts only) | off |
| Metric samples (host trend charts) | JSON backend: 1,440 samples per host, about a day. SQLite and Postgres: none | `metric_samples_retention_days` | off |
| Ingested log lines | optional byte cap per unit (`log_buffer_max_bytes_per_unit`) | `log_buffer_retention_hours` | **6** hours |

"Off" means 0 or unset: nothing is trimmed by age. The age settings count whole days (0 to 3,650).

Where the settings live:

- **Settings → Advanced → Data retention & maintenance** has the day settings and the two
  log-line settings. Leave a box empty to keep its current value. **Save retention** stores them
  and **Run maintenance now** applies them at once. Without that button the sweep runs once a day.
- **Settings → Advanced → Audit log retention** has the audit-log setting.
- **Settings → Alert parameters → Reliability tuning** has **Command history rows kept** and
  **Monitor checks kept**.
- `GET /api/security/diag` (admin only) returns the seven day settings, so you can evidence them
  without a screenshot.

Things to know before you write a number:

- **The alerts store evicts the oldest *resolved* alerts first** when it passes 5,000 rows. It
  reaches open alerts only if all 5,000 are open. The cap is a memory bound, not a retention
  policy. The age sweep never touches open alerts.
- **`monitor_history_retention_days` trims the data your uptime percentages are computed from.**
  Setting it to 30 makes a 90-day SLO report unanswerable. Decide the reporting window first.
  The row cap matters here too: at a 60-second check interval, 300 results is about five hours.
  Raise **Monitor checks kept** if the windows you report on are longer.
- **Rows past a cap are archived where the data is evidence.** The audit log, the fleet events
  and, on the JSON backend, the command history each append what they evict to a gzipped file in
  the data directory (`audit_log_archive.jsonl.gz`, `fleet_events_archive.jsonl.gz`,
  `command_history_archive.jsonl.gz`). On SQLite and Postgres the command history rows are dropped,
  and the same actions remain in the audit log and the archived `command_queued` fleet events.
- **Metric samples on the JSON backend are a rolling window only.** A time series longer than a day
  needs the SQLite or Postgres backend (see [storage.md](storage.md)), and then
  `metric_samples_retention_days` is the knob.

---

## Audit log: trimming is not deletion

The audit log is hash-chained, which is what makes it evidence rather than a list. Deleting from the
middle breaks the chain, so retention does not delete. When an entry is older than
`audit_log_retention_days`, or falls past the newest 500, it is **appended to
`audit_log_archive.jsonl.gz`** in the data directory and removed from the live store. The archive
is gzipped JSONL in chain order.

To get it, open **Audit** (Compliance group) and click **Archive**. Admins and auditors can
download it. The download carries an `X-RP-Signature` header (an HMAC over the file) and is itself
written to the audit log. The Audit page also shows **Verify integrity** for the live chain and
**Rotate signing key**.

Consequences for your policy:

- The live log is never longer than 500 entries, whatever you set. The age setting decides when an
  entry leaves earlier than that. For a longer view, use the archive.
- The archive **grows without bound**. Rotating or shipping it elsewhere (object storage, a WORM
  sink) is your job. Nothing in RemotePower deletes it.
- `audit_log_retention_days` below **30** fails the `audit_retention` posture check, which several
  frameworks read as a control failure. The default of 90 is above that line.
- **Settings → Security → Audit log forwarding** can mirror every entry to a SIEM (HTTP or syslog)
  and can append each entry to an **append-only (WORM) file** that RemotePower never rotates or
  prunes. If you use a SIEM, its retention is the one your auditor will ask about, and the local
  window can be shorter.
- **Clear** on the Audit page asks for your admin password and writes the whole live log to a
  `audit_log_prewipe_<timestamp>.jsonl.gz` file first. If that file cannot be written, the log is
  not cleared.

---

## Litigation hold — suspending all of it at once

**Settings → Advanced → Litigation hold** (or `POST /api/litigation-hold {enabled, reason}`)
stops **every** age-based purge in one switch: the audit trim, the age limits above, and the
cleanup of long-expired API keys. Both the daily sweep and **Run maintenance now** go through the
same gate, so neither can bypass it.

- You must give a reason to start a hold. Starting or lifting one asks you to confirm again with
  your password (step-up).
- With multi-tenancy on, only the platform operator can change the hold.
- The hold records `started_at`, `started_by` and the reason. Starting and lifting are each
  written to the audit log, so a disputed end date can be answered from the log.

It is all-or-nothing, never per store. A per-record hold sounds more precise, but it risks the one
failure a hold exists to prevent: something that should have been kept being purged because it was
missed.

What the hold does **not** stop:

- **Row caps.** The caps in the table above are not age purges. Command history past 200 rows,
  fleet events past 1,000 and so on still roll off, and the archive described above is what keeps
  the audit and fleet-event rows. If a matter needs a store kept in full, raise its row cap or
  export it first.
- **Operator deletions** such as deleting a host, a ticket or a user. Those are actions,
  not automated purging, and a hold that blocked them would be a surprise in the other direction.
  If a hold requires that nobody deletes anything, pair it with a role change.

---

## Stores with no retention setting

These are bounded by shape rather than age, and no setting trims them. In a retention policy they
read as "kept for the life of the record":

| Store | Bound |
|---|---|
| Hosts, groups, tags, sites | Until the host is deleted. Deleting a host removes its telemetry with it. |
| CMDB assets and the credential vault | Until an operator deletes them. The vault is separately encrypted. |
| Tickets, KB articles | Until deleted. At 5,000 of either, new ones are refused. |
| Contacts, runbooks, saved scripts | Until deleted. |
| Users and API keys | Until deleted or deprovisioned. API keys that expired more than 30 days ago are removed by the daily sweep. Deleting a user does **not** rewrite the audit entries that name them. That is on purpose: it is what keeps the log evidence. |
| Host trend rings (thermal, SMART, GPU, disk I/O, container stats, custom metrics) | A fixed number of samples per series, for example 288 GPU samples (about a day) and 720 samples per custom metric. |
| Service history | The last 100 state changes per host and unit. |
| DR backups | Whatever your backup destination keeps. RemotePower does not prune them. |

---

## Personal data and the right to erasure

For GDPR Article 15 and 17 requests, use **Compliance → Data subject requests**.

1. Type the person's username, display name or email and click **Run subject-access report**. Admins
   and auditors can run it. It lists every record on the instance that names them and marks each one
   **erasable** or **retained**.
2. If an admin approves, click **Erase what can be erased** and type the subject to confirm. It
   removes the account, its avatar, its sessions and its contact record, and nothing else.

The same two steps are `GET /api/privacy/subject?who=&email=` and `POST /api/privacy/erase`.

The audit log is **not** rewritten. Editing an entry destroys the hash chain that makes it evidence,
so retention is the lawful position there. Ticket authorship and time entries stay too, as business
records. Retention settings are the background policy; the subject request is the per-person
action. See [compliance.md](compliance.md).

---

## Suggested starting point

For an organisation that has to answer "what is your retention period":

```
audit_log_retention_days        365    # archive holds what the live 500 cannot
metric_samples_retention_days    90    # matches a quarterly capacity review (SQLite or Postgres)
monitor_history_retention_days  400    # longer than any annual SLO report window
history_retention_days          180
fleet_events_retention_days      90
webhook_log_retention_days       30    # delivery debugging, not evidence
alerts_retention_days           365    # resolved only; open alerts are untouched
```

These only decide what you keep if the row cap does not trim first. On a busy fleet, also raise
**Command history rows kept** and **Monitor checks kept**, or the age settings never come into play.

Record the numbers in your policy and check them again after upgrades. `GET /api/security/diag`
returns the seven day settings, so a scheduled check can assert that they still match what you
published.

---

← [Back to docs index](README.md) · [Compliance mapping](compliance.md) ·
[Security controls](security.md)
