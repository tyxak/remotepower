# Alerts inbox

**Alerts** is the operational inbox: every fired event that carries a
severity lands here, grouped by host, until it is acknowledged, resolved, or
auto-resolved by its matching recover event (`device_online`,
`service_recover`, `custom_script_recover`, …). An alert also resolves when the
condition behind it is removed rather than recovered: **deleting a device**
resolves all of its open alerts, **deleting a custom check or script** resolves
its alerts fleet-wide, and **accepting or disabling** a protect/baseline check
fires `custom_check_recovered` so its alert closes — so nothing lingers pointing
at something that no longer exists.

**The contract (v6.4.0): every alert that records an ongoing condition
auto-resolves when the condition clears** — including CVEs (patched →
`cve_cleared`), pending updates (`patch_ok`), expiring watched certificates
(`tls_renewed`), ECC error bursts (`ecc_stable` after 24 quiet hours) and
exposed secrets (`secret_cleared`). Point-in-time alerts (something
*happened* — a login, a config change) can't self-heal by definition; those
rows carry a **confirm** badge so you know to resolve them yourself after
looking.

## Working the inbox

- **Acknowledge** — takes ownership; optionally prompts for a comment
  (Settings → Alerts inbox) that is stored on the alert and included in the
  acknowledgement webhook.
- **Resolve / Clear resolved / Clear all** — housekeeping; history is kept.
- **Resolve with a note** *(v6.4.2)* — the pencil button next to Resolve asks
  what actually fixed it and stores the answer on the alert (`resolve_note`,
  max 256 characters). The note shows on the resolved row and in the
  **Resolution timeline**, so the next person who hits the same alert can see
  what worked last time instead of starting from scratch. Plain Resolve still
  works with no note; reopening an alert (**unresolve**) clears the note along
  with the resolution.
- **Age, not last occurrence** *(v6.4.2)* — a repeating alert is one row: each
  new firing bumps its `count` and its `ts`. Every row therefore also carries
  **`first_seen`**, the timestamp of the *first* observation, which is never
  rewritten. The inbox shows "age" from `first_seen` (and "open for" once
  resolved), so an alert that says "2 minutes ago" can no longer hide the fact
  that it has been firing for a week. MTTA/MTTR are measured from `first_seen`
  for the same reason. Rows written before the field existed adopt their
  current `ts` as their first observation, so ages stay truthful across the
  upgrade.
- **Group by host** — folds symptom alerts under their probable root cause
  (a `device_offline` folds the service/port alerts it likely caused).
- **Filters** — state dropdown + free-text filter by device, event or title.
- **Open a ticket** — with the [ticket system](ticket-system.md), an alert
  row can spawn a linked ticket; opening one auto-acknowledges the alert.
- **Triage** *(v6.4.0)* — runs a bounded agentic investigation on the alert:
  the model gathers evidence through read-only, device-scoped tools and stores
  a root-cause verdict with its evidence trail on the row. Optionally automatic
  for new alerts (off by default, with a severity floor and a daily cap). See
  [ai.md](ai.md).

## Getting fewer of them

Recurring noise is silenced at the source on the [Tuning](alert-tuning.md)
page (per host + alert type), suppressed during
[maintenance windows](maintenance.md), or routed per event kind under
Settings → Notifications. The **Resolution timeline (MTTR)** card at the
bottom tracks how quickly alerts get resolved.

## Watching RemotePower itself *(v6.4.2)*

RemotePower has always told you when somebody gained sudo on a monitored host
(`priv_group_added`) and said nothing when somebody became an admin of the
server that can run root commands across the whole fleet. The
**`control_plane_security_change`** event closes that: privilege and
security-control changes to RemotePower itself now fire on the same
alert/webhook/activity channels as everything else, instead of only landing in
an audit log nobody watches.

It fires (severity **high**, kind `accounts`) when:

| Change value | Meaning |
|---|---|
| `admin_user_created` | a new admin account was created |
| `user_promoted_to_admin` | an existing account was promoted to admin |
| `admin_apikey_created` | an admin-role API key was minted |
| `mfa_enforcement_disabled` | MFA is no longer required for any role |
| `change_approval_disabled` | four-eyes change approval was switched off |
| `audit_log_cleared` | the audit log was cleared |

The payload carries `change`, `actor`, `target_user` and a human-readable
`detail`. It is a **point-in-time** event with no recover event and it does not
auto-resolve — a privilege change is something that *happened*, and a row that
disappeared as soon as the visible half was undone would be worse than no row.
Resolve it yourself once you have confirmed the change was intentional.

Like every event it can be routed per channel under Settings → Notifications,
and muted per host/type on the [Tuning](alert-tuning.md) page — though muting
this one deserves a moment's thought.

## Reading the inbox over the API

`GET /api/alerts` answers with `{alerts, total, offset, limit, summary,
ack_comment_enabled}`. All parameters are optional:

| Parameter | Default | Notes |
|---|---|---|
| `status` | `open` | `open` \| `ack` \| `resolved` \| `all` |
| `limit` | 200 | clamped to 1–1000 |
| `offset` | 0 | *(v6.4.2)* clamped ≥ 0 — before this, row 201 was simply unreachable |
| `q` | — | *(v6.4.2)* case-insensitive substring over device name, event and title |
| `severity` | — | *(v6.4.2)* `critical`/`high`/`medium`/`low`; repeat the parameter or comma-separate for several |
| `device_id` | — | *(v6.4.2)* exact match |
| `mine` | — | only alerts *you* acknowledged |

Rows come back newest first. Filtering runs **after** the visibility filter, so
`total` counts only rows you are allowed to see — page through it with `offset`
until `offset + len(alerts) >= total`. RBAC scope and tenant isolation apply
throughout: an alert for a device outside your scope or tenant is not returned,
and addressing it by id returns 404 rather than 403.

## Turning the inbox off

Alerts are an optional module (**Settings → Advanced → Modules**). Switched off,
the whole `/api/alerts` surface 404s and the nav entry hides — alerts stop being
**recorded**.

What keeps working is the part people usually assume goes with it: webhooks and
email are separate delivery channels, and the Recent Activity / fleet-event
history is a separate store, so both carry on. That makes notification-only a
supported setup — your phone still pings, there is just no inbox to triage.

## Ignored items — and keeping them from piling up *(v6.4.0)*

Hiding a Needs-Attention card (the × on the card) sends it to **Settings →
Ignored items**, alongside hidden stale containers, devices, ignored CVEs and
cleared log lines. On a large fleet that list used to grow without bound —
so it now maintains itself:

- **Self-pruning.** An ignore is garbage-collected once its underlying condition
  has been gone past a short grace window (the drift resolved, the disk
  recovered, the point-in-time event aged out). You only keep the ignores you
  still need.
- **Device cleanup.** Deleting or decommissioning a host drops every ignore
  scoped to it — no tombstones from fleet churn.
- **Last active.** Each ignore shows when its condition was last actually seen,
  so a stale one is obvious, and every category has a bulk **Restore all**.
- **Class-level suppression.** When the same benign signal fires on many hosts,
  add one **suppression rule** (Settings → Ignored items) that silences a whole
  *kind* across the fleet, a group, a tag or a device — one entry instead of
  one ignore per host.

You should also need to ignore *less*, because more alerts now clear themselves:
open `patch_alert` and `cve_found` alerts are periodically re-checked against
current state and **auto-resolve** when the condition clears (pending drops under
threshold; no CVE findings left), so they leave the inbox on their own.
