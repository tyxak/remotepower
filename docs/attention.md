# Needs Attention

**Monitoring → Needs Attention** is the live list of everything the fleet is
raising right now. The Home dashboard summarises it in a card; this page is the
whole list.

## Needs Attention vs Recent Activity

Two surfaces with very different semantics.

- **Needs Attention** = "fix this NOW". Only items whose underlying state is
  currently broken.
- **Recent Activity** = event log. Things that happened — transitions,
  dispatches, acknowledged alerts.

A service that went down at 14:30 and came back at 14:35 shows in **Recent
Activity** (two events: `service_down` then `service_up`) but disappears from
**Needs Attention** the moment it is healthy again.

This split exists because reading a "today's events" feed to work out current
state is exhausting and error-prone. NA only ever shows live conditions, so an
empty NA list genuinely means "nothing is broken right now".

| Surface | Source | What it shows |
|---|---|---|
| Needs Attention | `_compute_attention()` walks current state files | Things that are currently broken |
| Recent Activity | `/api/fleet/events` reads `fleet_events.json` | The last N events fired by webhooks |

`fleet_events.json` is append-only (bounded at `MAX_FLEET_EVENTS = 1000`). Every
`fire_webhook(...)` call records into it whether or not a webhook URL is
configured.

## The page

The card on the dashboard shows the **first ten** items and, below them, how many
more there are with a link through to the full list. Everything else is here.

- **One row per item** — severity, kind, the host it belongs to, and the
  one-line detail. Columns sort; the ordering for severity is by rank
  (critical > warning > info), not alphabetically, because alphabetical would
  read critical < info < warning.
- **Filters** for severity, kind and device, plus a free-text box over host,
  kind and detail. The per-severity totals above the table double as one-click
  filters. The kind and device pickers are rebuilt from the loaded rows on each
  refresh, so they only ever offer values that actually occur — and they keep
  your current selection if it still exists, because a kind can vanish between
  refreshes precisely *because* you just fixed it.
- **Refresh** re-runs the digest server-side, which is how you confirm something
  you just fixed has really cleared.
- **The same per-item actions as the card**: jump to the page the item is about,
  **Investigate** (diagnostic + AI suggestion, when the kind has a mitigation
  playbook and the item has a device), **Snooze** for 24 hours, **×** to ignore
  permanently, and for `log_alert` items an "open Logs filtered to this device
  and unit" shortcut plus a clear-this-line control.
- **Nothing is queued.** The list is recomputed from current fleet state on every
  load, so an item disappears the moment its cause clears — there is no "resolve"
  button because there is nothing stored to resolve.
- The list is **scoped to what you can see**. A role- or tenant-scoped operator
  gets only items for their own devices; fleet-level items (TLS expiry and
  friends, which have no device to attribute) are kept for everyone.

`GET /api/attention` returns `{items, counts, total}` — `counts` is the
per-severity tally, `total` the number of items after scoping.

## How an item relates to alerts, mutes and health

An item is `{severity, kind, device, device_id, summary}` plus a stable
`_ignore_key`, and `mitigation_kind` / `mitigation_target` when a mitigation
playbook exists for that kind.

**Kinds are not events.** A `kind` is a UI grouping (`av_posture`, `hardware`);
a webhook `event` is what actually fires (`av_infected`, `smart_failure`). They
are separate namespaces that only sometimes share a name, so `_NA_MUTE_EVENTS`
maps `(kind, severity)` → the event(s) that item represents. Severity is
load-bearing in that map: muting `av_warning` must not also hide an
`av_infected` item of the same kind.

**Health is derived from these items, and only from these items.** Every
monitored device starts at 100 and loses points per item by severity (25 for a
critical, 8 for a warning, 2 for an info by default — tunable under Settings →
Alert parameters); the fleet score is the mean over monitored devices. That is
why silencing an item *lifts the score*: there is exactly one source of truth for
"what is wrong", and the score cannot disagree with the list. It is also why an
item you have no way to silence permanently depresses a host's score — see the
`_NA_MUTE_EVENTS` warning under [Adding new kinds](#adding-new-kinds).

The per-asset **risk** score is a separate lens (security posture) and does not
blend into health. See [health-score.md](health-score.md) and [risk.md](risk.md).

### Four ways to quiet an item

| Mechanism | Scope | Where |
|---|---|---|
| Channel routing | a whole kind, fleet-wide, per channel | Settings → Notifications — untick *Needs Attention* for that kind |
| Ignore / snooze | one item | the × (permanent, reviewable under Settings → Ignored items) or the bell (24 h) on the row |
| Suppression rule | a kind across the fleet, a group, a tag or one device | Settings → Ignored items → *Suppression rules* (`/api/na-suppress`) — one managed entry instead of 500 per-item ignores |
| Alert mute | one `(host, event)` pair | [Alert tuning](alert-tuning.md) — also silences the inbox, webhooks, e-mail and push |

They are applied in that order at the end of `_compute_attention()`, and each
one also removes the item's deduction from the health score.

Maintenance windows are **not** in that list. A window suppresses outbound
notification (webhook and e-mail delivery); it does not remove an item from this
page. See [maintenance.md](maintenance.md).

## All attention kinds

These produce a Needs Attention item when the underlying condition is currently
active. Anything else in `fleet_events` is past-tense only.

| Kind | Source | Severity range |
|---|---|---|
| `offline` | `last_seen` outside TTL | critical |
| `patches` | `upgradable > 0` on device record | info / warning |
| `cve` | findings in `cve_findings.json`, ignoring `cve_ignore.json` | warning / critical |
| `drift` | `drift_detected` set on device | warning |
| `mailbox` | mailbox count exceeds threshold | warning |
| `brute_force` | active state in `brute_force.json` | critical |
| `snapshot` | snapshot age > threshold | warning |
| `backup` | backup state stale | critical |
| `disk` | metric overrides per mount | warning / critical |
| `tls` | TLS expiry watchlist | warning / critical |
| `reboot` | `/run/reboot-required` exists in sysinfo | warning |
| `agent_version` | agent version ≠ server version | info |
| `service_down` | systemd unit in `services.json` not active | warning / critical |
| `failed_units` | systemd `failed` units reported in the device's sysinfo | warning |
| `monitor_down` | last monitor probe `ok: false` | critical |
| `custom_script_fail` | custom script reports non-zero rc in latest result | warning |
| `custom_check` | a custom check's latest result is warning/critical | warning / critical |
| `mount` | a watched mount is missing or **stalled** (not responding) | warning / critical |
| `hardware` | SMART failure and other hardware findings on the device record | warning / critical |
| `reliability` | the reliability scorer rates the host likely to fail | warning / critical |
| `av_posture` | ClamAV infected files, or AV/real-time protection off | warning / critical |
| `agent_integrity` | running agent binary hash ≠ the published build | critical |
| `ssh_key` | a new authorized SSH key appeared for a user | critical |
| `new_port` | a new listening port appeared since the baseline | warning |
| `log_alert` | a log-watch rule matched (severity comes from the rule) | rule-defined |
| `container` | container data stale — the host stopped reporting containers | warning |
| `acme` | an ACME certificate is not `ok`; `failed`/`expired` escalate | warning / critical |
| `os_eol` | the host's OS is approaching or past end-of-life | info / warning |
| `proxmox_backup` | a Proxmox guest has no backup, or its newest is too old | warning |
| `after_hours` | events fired outside configured business hours (fleet-level) | warning |
| `cred_rotation` | a vault credential is older than its rotation policy | info |
| `apikey_rotation_due` | an API key is older than its `rotate_after_days` | info |

## Adding new kinds

To make a new state-derived condition show in NA:

1. Append to `_compute_attention()` in `server/cgi-bin/api.py` with `severity`,
   `kind`, `device` (device name string), `summary`, and optionally `target` for
   parameterised mitigation.
2. Add a `PAGE_FOR` entry in `app.js` so clicking the row lands on the page the
   item is about. The Home card and the full page share that one table.
3. If the kind should also support the Investigate button, add a playbook entry
   to `_MITIGATE_PLAYBOOKS` and a default AI prompt in `ai_provider.py`.
4. Add a regression test that seeds the relevant state file and asserts the item
   appears.
5. **Add a `_NA_MUTE_EVENTS` row** mapping `(kind, severity)` → the webhook
   event(s) that produce it. A kind with no row is **unmuteable** — muting the
   corresponding alert will never clear its card, and because the health score is
   derived purely from these items, it will never lift the host's score either.
   This is the step that silently ships a defect if skipped.

The decorator step at the end of `_compute_attention` automatically:

- adds `device_id` (looked up from the device-name reverse map),
- adds `mitigation_kind` / `mitigation_target` if the kind is in
  `_MITIGATE_PLAYBOOKS`,
- filters items through the channel-routing matrix, the global Ignored list,
  the class-level suppression rules in `attention_handlers.py`, and
  `_na_item_muted()`.

## History

`service_down`, `monitor_down` and `custom_script_fail` were added in v3.0.1.
These conditions previously fired webhooks (so Recent Activity showed them on
the transition) but never produced an NA item — meaning a service that was
already down when the operator opened the dashboard was effectively invisible.
