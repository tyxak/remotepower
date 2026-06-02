# Needs Attention vs Recent Activity

Two distinct surfaces on the Home dashboard, with very different semantics.

## The distinction

- **Needs Attention** = "fix this NOW". Only items whose underlying state is currently broken.
- **Recent Activity** = event log. Things that happened in the past — transitions, dispatches, ACK'd alerts.

A service that went down at 14:30 and came back up at 14:35 shows in **Recent Activity** (two events: `service_down` then `service_up`) but disappears from **Needs Attention** once it's healthy again.

This split exists because looking at a "today's events" feed and trying to determine current state is exhausting and error-prone. NA only ever shows live conditions, so an empty NA list genuinely means "nothing is broken right now".

## Where each surface gets its data

| Surface | Source | What it shows |
|---|---|---|
| Needs Attention | `_compute_attention()` walks current state files | Things that are currently broken |
| Recent Activity | `/api/fleet/events` reads `fleet_events.json` | The last N events fired by webhooks |

`fleet_events.json` is append-only (bounded at `MAX_FLEET_EVENTS = 200`). Every `fire_webhook(...)` call records into it whether or not a webhook URL is configured.

## All attention kinds

These produce a Needs Attention item when the underlying condition is currently active. Anything else in `fleet_events` is past-tense only.

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

## Adding new kinds

To make a new state-derived condition show in NA:

1. Append to `_compute_attention()` in `server/cgi-bin/api.py` with `severity`, `kind`, `device` (device name string), `summary`, and optionally `target` for parameterised mitigation.
2. If the kind should also support the 🩺 Investigate button, add a playbook entry to `_MITIGATE_PLAYBOOKS` and a default AI prompt in `ai_provider.py`.
3. Add a regression test that seeds the relevant state file and asserts the item appears.

The decorator step at the end of `_compute_attention` automatically:
- Adds `device_id` (looked up from device-name reverse map)
- Adds `mitigation_kind` and `mitigation_target` if the kind is in `_MITIGATE_PLAYBOOKS`
- Filters items through the global Ignored list

## v3.0.1 audit additions

`service_down`, `monitor_down`, `custom_script_fail` were added in v3.0.1. These conditions previously fired webhooks (so Recent Activity showed them on the transition) but never produced an NA item — meaning a service that was already down when the operator opened the dashboard was effectively invisible. Now they show until the underlying state recovers.
