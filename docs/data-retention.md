# Data retention — what RemotePower keeps, for how long, and where

RemotePower's compliance mapping claims retention as an operator responsibility.
This page is the missing half of that sentence: an inventory of every store, the
knob that trims it, and — the part that matters for a retention policy — **what
the shipped default actually does.**

The short version: **most stores default to keeping everything forever.** That is
a choice (silently deleting an operator's history is worse than
growth), but it means a retention policy that says "we keep operational data for
N days" is not true of a default install until you set these.

---

## The knobs

All of these live under **Settings → Advanced → Data retention & maintenance**
(audit-log retention has its own box in the same pane), are read on the
maintenance sweep, and are returned by `GET /api/security/diag` so you can
evidence them without a screenshot.

| Setting key | Default | 0 means | What it trims |
|---|---|---|---|
| `audit_log_retention_days` | **90** | keep forever | Audit-log entries. Trimmed entries are appended to the archive first, so the hash chain stays verifiable and nothing is destroyed — see below. |
| `metric_samples_retention_days` | **30** | keep forever | Per-device metric samples (CPU/memory/disk/network time series). |
| `history_retention_days` | 0 | keep forever | Per-device history: thermal, SMART, GPU, custom metrics. |
| `fleet_events_retention_days` | 0 | keep forever | The dashboard activity feed. |
| `webhook_log_retention_days` | 0 | keep forever | Webhook delivery log (payloads + response codes). |
| `monitor_history_retention_days` | 0 | keep forever | Uptime-monitor check results, which back the SLO/uptime figures. |
| `alerts_retention_days` | 0 | keep forever | **Resolved** alerts only. Open alerts are never trimmed by age. |
| `log_buffer_retention_hours` | **6** | — | The rolling buffer for ingested syslog. |

Two behaviours worth knowing before you write a number into any of them:

- **The alerts store also has a hard cap of 5,000 rows**, independent of age.
  It evicts the oldest **resolved** alerts first and only reaches open ones in the
  pathological case where all 5,000 are open — the cap is ultimately a memory
  bound, not a retention policy. On a fleet that turns over more than that between
  sweeps, the cap, not `alerts_retention_days`, is what actually trims.
- **`monitor_history_retention_days` trims the data your uptime percentages are
  computed from.** Setting it to 30 does not just shrink a table; it makes a
  90-day SLO report unanswerable. Decide the reporting window first.

---

## Audit log: trimming is not deletion

The audit log is hash-chained, which is what makes it evidence rather than a
list. Deleting from the middle breaks the chain and destroys that property, so
retention does not delete — entries older than `audit_log_retention_days` are
**appended to `audit_log_archive.jsonl.gz`** in the data directory and removed
from the live store. The archive is gzipped JSONL, still in chain order, and is
what you hand an auditor for a period outside the live window — **Settings →
Security → Audit log** downloads it as a signed export.

Consequences for your policy:

- The archive **grows without bound by design**. Rotating or shipping it
  elsewhere (your WORM sink, object storage) is an operator job; nothing in
  RemotePower deletes it.
- `audit_log_retention_days` below **30** fails the `audit_retention` posture
  check, which several frameworks read as a control failure. The default of 90 is
  above that line.
- If you have configured **audit forwarding** to a SIEM, the SIEM's retention is
  the one your auditor will ask about. RemotePower's window is then a local cache,
  and can reasonably be shorter.

---

## Litigation hold — suspending all of it at once

**Settings → Advanced → Litigation hold** (or `POST /api/litigation-hold
{enabled, reason}`) stops **every** age-based purge in one switch: the audit
trim, `_purge_old_data`, and each of the knobs above. Both the daily sweep and
the manual *Run maintenance now* button route through the same gate, so neither
can bypass it.

It is coarse — all-or-nothing, never per-entity. A per-record hold
sounds more precise but risks the one failure a hold exists to prevent: something
that should have been preserved being purged because it was missed. The hold
records `started_at`, `started_by` and `reason`, and **enabling and lifting are
each independently audit-logged** — lifting a hold is as consequential as
starting one, and a disputed end date is answered from the log.

What it does *not* stop: considered operator deletions (deleting a device, a
ticket, a user). Those are actions, not automated purging, and a hold that
silently blocked them would be a surprise in the other direction. If a hold
requires that no one delete anything, pair it with read-only mode or a role
change.

---

## Stores with no retention knob

These are bounded by *shape* rather than age, and no setting trims them. They
belong in a retention policy as "retained for the life of the record":

| Store | Bound |
|---|---|
| Devices, groups, tags, sites | Until the device is deleted. Deleting a device removes its telemetry with it. |
| CMDB assets + the credential vault | Until deleted by an operator. The vault is separately encrypted. |
| Tickets, KB articles | Until deleted, then a hard cap of 5,000 rows each. |
| Contacts, runbooks, saved scripts | Until deleted. |
| Users and API keys | Until deleted or deprovisioned. Deleting a user does **not** rewrite the audit entries naming them — that is on purpose, and is what makes the log evidence. |
| Command history | Capped by row count (`command_history_max`), not by age. On the JSON backend the overflow is archived; on SQLite/Postgres it is dropped, and the same actions remain in the audit log and the archived `command_queued` fleet events. |
| DR backups | Whatever your backup destination retains. RemotePower does not prune them. |

---

## Personal data and the right to erasure

If you are handling GDPR Article 15 / 17 requests, the relevant surface is
`GET /api/privacy/subject?who=&email=` and `POST /api/privacy/erase` (v6.4.2) —
API-only, there is no page for them. The first enumerates every record naming a
person and marks each erasable or retained; the second removes what can go and
reports what it did not touch. The audit log is **not** rewritten:
editing an entry destroys the hash chain that makes it evidence, so retention is
the lawful position there. Retention settings are the background policy; those
endpoints are the per-subject action. See [compliance.md](compliance.md).

---

## Suggested starting point

For an organisation that has to answer "what is your retention period":

```
audit_log_retention_days        365    # keep a year live; archive holds the rest
metric_samples_retention_days    90    # matches a quarterly capacity review
monitor_history_retention_days  400    # > any annual SLO report window
history_retention_days          180
fleet_events_retention_days      90
webhook_log_retention_days       30    # delivery debugging, not evidence
alerts_retention_days           365    # resolved only; open alerts are untouched
```

Then record the numbers in your policy, and re-check them after upgrades —
`GET /api/security/diag` returns all seven, so a scheduled check can assert they
still match what you published.

---

← [Back to docs index](README.md) · [Compliance mapping](compliance.md) ·
[Security controls](security.md)
