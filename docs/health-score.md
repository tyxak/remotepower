# Fleet health score

The health score is a single 0–100 number per device (and a fleet average),
shown on the Home dashboard and the heat map. It is derived from the **same
Needs Attention signals** as everything else, so the score can never disagree
with the Needs Attention list.

## How it's computed

Each monitored device starts at **100** and loses points for every current Needs
Attention item it has, weighted by severity:

| Severity | Points lost |
|---|---|
| critical | 25 |
| warning  | 8 |
| info     | 2 |

The score floors at 0. The fleet score is the mean of the per-device scores.
Unmonitored devices (`monitored: false`) are excluded — scoring a silenced host
a perfect 100 would inflate the fleet average.

Grades: **good** ≥ 90, **fair** ≥ 70, **poor** ≥ 40, **critical** below 40.

## What lowers a score

Anything that appears in Needs Attention, including:

- a device **offline** (critical),
- **critical / high CVEs** (the item also notes how many are *fixable* — i.e.
  carry a known fixed version a package upgrade would clear),
- **pending package updates** — `info` below 20 pending, `warning` at 20 or more.
  (Pending updates are read from the agent's `sysinfo.packages.upgradable`
  count; a host with updates waiting does drop below 100.)
- failed systemd units, config **drift**, expiring **TLS** certs, SMART / kernel
  hardware findings, agent-integrity mismatch, after-hours activity, and so on.

Because the score is just the Needs Attention digest scored by severity, "why is
this device at N?" is always answerable: look at its Needs Attention items.

## Heat map

The Home heat map is the same per-device score rendered as a grid of cells
coloured green (healthy) → red (needs attention), so problem hosts stand out
visually even on a large fleet where a table wouldn't.

## API

- `GET /api/fleet/health` — `{score, grade, devices: [{device_id, device_name,
  score, critical, warning, info}], total_devices}`. Scoped roles see only their
  in-scope devices, with the headline score recomputed over those.
- A `health_degraded` event fires (and `health_recovered` clears it) when the
  score crosses the configured alert threshold.
