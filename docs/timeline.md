# Timeline

**Monitoring → Timeline** merges fleet events, command runs, current CVE
posture and — for admins and auditors — operator-side changes into one
chronological stream. The "what happened around 03:40" view. Scope it to the
whole fleet or a single device.

- Every entry links to its source (alert, command output, drift diff, …).
- **Point it at the incident.** Pick a moment in **Around** and a window
  (± 15 minutes through ± 2 days) and the page returns what surrounded that
  moment, not the newest 300 rows. Any alert row has a clock button that opens
  the Timeline already centred on that alert's own timestamp and narrowed to its
  host. **Clear window** goes back to newest-first.
- Filters by kind (events / commands / CVE posture / audit).
- Useful for incident reconstruction: agent went offline, what commands ran
  before, which alerts fired after, when it recovered.

## What is merged

| Source | Rows |
|---|---|
| Fleet events | every fired event whose payload names the device |
| Command runs | operator and scheduled command output, including server-queued package upgrades |
| CVE findings | one current-posture row per device (state, not an event — a re-scan of already-known CVEs fires nothing, so an event-sourced view would never show them) |
| Audit log | **admins and auditors only** — the change-shaped entries: config saves, maintenance windows, rule and threshold edits, mitigations, device and firewall changes |

The audit rows answer "what changed right before this broke", which the event
stream alone cannot. They are shown only to callers who can already read
`GET /api/audit-log`; that gate is on purpose, so the Timeline does not become a
way around it. Read-only login/read entries are excluded — folding the whole
audit log in would bury the events under noise.

## API

`GET /api/fleet/timeline` and `GET /api/devices/{id}/timeline` take:

| Parameter | Meaning |
|---|---|
| `limit` | rows returned, default 100, max 500 |
| `kinds` | CSV filter on kind |
| `since` / `until` | explicit epoch-second bounds, either may be omitted |
| `around` + `window` | centre on an epoch second, ± `window` seconds (default 1800, max 30 days) |
| `device` | fleet endpoint only — restrict to one host |
| `severity` | fleet endpoint only — CSV |

Timestamps in milliseconds are accepted and coerced. Responses echo the
resolved `since` / `until` so a client can show the window it actually got.

The same data feeds the dashboard activity feed (recent slice) and the
per-device history in the drawer; the Timeline is the full merged view.
