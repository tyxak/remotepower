# Uptime & SLA

RemotePower tracks each device's up/down history and turns it into uptime
percentages, a 7-day status stripe on the Home roster, and per-device /
per-group SLA figures on the Reports page.

## Where the data comes from

Uptime is reconstructed from a log of **state transitions** (`uptime.json`), not
from polling samples. Each time a device flips online↔offline an event is
recorded; the percentage is the integral of "up" time over the window. This is
cheap to store and exact between transitions.

- **Agent devices** record a transition whenever a heartbeat is missed long
  enough to mark them offline, and again when they return.
- **Agentless / SNMP devices** are probed by the reachability sweep. As of
  v3.4.2 the sweep records the current state on *every* probe (de-duplicated, so
  it only writes on a real change). Before that it recorded only on a change, so
  a device that had been continuously reachable since it was added never got a
  baseline event and showed as all-"unknown" in the roster stripe.

## "No data" is unknown, never downtime

If RemotePower has **no record** covering part of the window — most commonly the
time *before a device was enrolled* — that period is reported as **unknown** and
excluded from the calculation. It is never counted as downtime.

Unmonitored and **decommissioned** (v5.0.0) devices are skipped entirely:
decommissioning a host forces `monitored: false`, so it drops out of SLA
computation rather than dragging the number down.

This matters for fresh deployments: a host enrolled 8 days ago, evaluated over a
30-day window, is scored over the ~8 days actually covered — not reported as "22
days down / 27% uptime". The Reports table shows `unknown` for a device with no
usable history yet, and the SLA is computed only over the covered period.

## Maintenance windows don't burn the SLA

One-shot maintenance windows (a scheduled start/end, scoped to the device, its
group, or fleet-wide) are **excluded** from both downtime and the covered window
when computing uptime. Planned work therefore doesn't count against a device's
SLA. (Recurring/cron windows are not subtracted from historical SLA — only
explicitly-scheduled one-shot windows are.)

## SLA targets (per device / tag / group / default)

You can set a target uptime % and have each device measured against it. Targets
resolve **most-specific-first**:

1. a target set for the **device** id, else
2. a target for any of the device's **tags**, else
3. a target for the device's **group**, else
4. the fleet **default**.

Set them from the **Uptime (SLA)** card on the Reports page — the "SLA targets"
button opens an editor with a default field plus per-group / per-tag / per-device
overrides. Each row in the table then shows its target and whether it is **met**
or **breached**.

## API

- `GET /api/fleet/sla?days=N` — per-device and per-group uptime % over an N-day
  window (1–365, default 30). Each device row carries `uptime_pct`,
  `downtime_seconds`, `covered` (false = unknown), `sla_target`, and `sla_met`.
- `GET /api/fleet/uptime7d` — the 7-day daily up/down stripe per device.
- `GET /api/fleet/sla-targets` / `PUT /api/fleet/sla-targets` — read / set the
  targets (`default`, `groups`, `tags`, `devices`). Setting targets is admin-only;
  each percentage is validated to the range (0, 100].
