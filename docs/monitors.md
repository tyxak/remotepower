# Active monitors & probes

Beyond the metrics each agent reports about *itself*, RemotePower runs
**server-side synthetic checks** against targets you name, plus receivers for
telemetry hosts push to it. These live under **Monitoring → Remote Checks** (and
a few sibling pages), and every failure/recovery is a first-class event.

## Remote Checks

**Monitoring → Remote Checks** lists your synthetic checks — Label, Type, Target,
Status, Detail and last-checked time — with **Check now**, **Reset alerts** and
**Add target**. The server runs them on a cadence (`monitor_interval`, default
300s) and stores results in `monitor_history.json`.

| Type | Target | Checks |
| --- | --- | --- |
| `ping` / `icmp` | host or IP | ICMP reachability (icmp adds loss/latency stats) |
| `tcp` | `host:port` | TCP connect |
| `http` / `https` | full URL | HTTP request + expected status/latency, body contains/regex, JSON dot-path assertions |
| `http_flow` | first step's URL | multi-step HTTP transaction — up to 5 ordered steps sharing a cookie jar, per-step expect-status/contains and `extract` → `${var}` reuse |
| `dns` | name (+ optional expected record) | resolves to an answer |
| `db` | `host:port` | database liveness (PostgreSQL / MySQL / Redis protocol probe, credential-less) |
| `path` | host or IP | network path (traceroute) — fires `path_changed` when the route's hop set moves vs the baseline |

Targets are validated server-side (`_sanitize_monitor_target`) so a check can't
be pointed at a private/rebound address. Each check raises **`monitor_down`** when
it fails and **`monitor_up`** when it recovers. The `/api/monitor` endpoint can
also be pinged by an external scheduler to force a run.

Everyday controls on each row: **Pause** stops probing a target without
deleting it — config, history and uptime % survive, no alerts fire, and the
row stays visible (badged *PAUSED*) until you Resume. **Clone** prefills the
create form from an existing monitor. **Export** downloads the definitions as
JSON the **Import** box accepts (which also takes Nagios/Icinga configs,
Uptime Kuma backups and Zabbix XML exports). A monitor can be probed **from a
relay satellite** instead of the server (`via_satellite` — reaches
segmented/private space the server can't; the row shows a *via satellite*
badge). Every probe is timed, so the History modal shows **response-time
percentiles** (p50/p95/p99 over the window, successful checks only).

## SLA / SLO objects

Named availability targets that remote probes attach to. Define an object —
name, target % (say 99.9), rolling window in days — under **Monitoring → SLA /
SLO objects**, then tick it on each probe whose checks should count toward it
(checkboxes in the probe editor; any type, and a tag/group probe's fanned-out
per-device checks all count). The panel shows each object's check-weighted
**availability**, **error budget remaining** and **burn rate** over its own
window — filterable by name/probe and by compliance (breached / meeting / no
data), sortable on every column. An object with no measured checks reads *no
data*, never a fake breach; deleting one detaches its probes and keeps their
history.

Availability is a ratio of stored checks, so a window of N checks can only
resolve steps of 100/N percentage points. When that step is coarser than the
error budget itself — a 99.9% target leaves 0.1 pp, so it needs at least 1,000
checks in the window — the budget could only ever read 100% or 0%, and one
failed check would report a blown budget for a probe that was up 99.7%. The
budget column shows *too few checks* in that case instead. Raise
`monitor_history_max` (Settings) so the window holds more checks, or set a
target the window can actually measure.

`GET /api/slo` returns the objects alongside the per-monitor availability
list, and the same numbers export as Prometheus gauges
(`remotepower_slo_object_target_percent`, `…_availability_percent`,
`…_budget_remaining_percent`) for Grafana SLO dashboards. The budget and
burn-rate gauges are omitted while the window is too coarse to resolve the
target, so a Grafana panel never reads an unmeasurable budget as a real
breach; `availability` is always exported.

## Service monitoring

Watch specific systemd units per host (`watched_services`). The agent reports
each unit's state in its heartbeat; a stopped unit raises **`service_down`** and
a recovered one **`service_up`**. Service baselines let you snapshot the expected
running set and alert on deviation.

## Log-tail alerts

Two layers, both firing **`log_alert`**:

- **Per-device** log-watch rules (`log_watch`): `{unit, pattern, threshold,
  severity}` — the agent tails the unit's journal and reports matches.
- **Fleet-wide** rules (**`/api/logs/rules/global`**): a pattern + threshold +
  optional `exclude_pattern` and a `file:/path/to/log` synthetic unit for tailing
  a plain file. Managed on the Logs page.

## Inbound receivers (syslog & SNMP traps)

Devices and appliances can push to tokenised, admin-created endpoints (tokens
start with `rpwi_`, managed as inbound webhooks):

- **Syslog** — `POST /api/syslog/in/{token}` accepts `{lines:[…]}`, a bare JSON
  array, or plain newline-separated text. Lines are parsed for severity and run
  through the syslog rules (fires `log_alert`).
- **Alerts** — `POST /api/webhook/in/{token}` lands an external system's alert
  in the inbox. The sender's own payload shape is **adapted**: Prometheus
  Alertmanager, Grafana (legacy and unified), Authentik, or RemotePower's own
  `{severity, title, body, device}`. Detected automatically, or pinned on the
  token. A **resolved** notification closes the alert it opened, and a repeat
  firing updates that alert with a repeat count rather than adding a row — so
  a re-notifying source does not fill the inbox.
- **SNMP traps** — `POST /api/snmp/trap/{token}` accepts `{traps:[{oid,value,…}]}`
  or a single trap; a decoding trapd feeds it. New traps raise
  **`snmp_trap_received`**. Well-known OIDs are resolved to their MIB name on
  ingest, so the alert reads `upsOnBattery` rather than a bare dotted string.

### Trap rules

Settings → Integrations → **SNMP trap rules** decides what a trap *means*. A
rule matches an **OID prefix** — and optionally a regex against the value — and
sets the alert severity, or `ignore` to drop the trap without alerting at all.

- **Longest prefix wins.** A rule on `1.3.6.1.4.1.318.0.5` (upsOnBattery) beats
  a broad `1.3.6.1.4.1.318` rule added later, so you never have to reorder.
- **Traps matching different rules stay in different alerts.** The matched rule
  name is part of the alert's identity, so a UPS on battery and a chatty
  linkDown from the same switch no longer fold into one row where acknowledging
  the noise buries the outage.
- A rule can be scoped to a single device, or left fleet-wide.
- Traps matching no rule keep the old behaviour: one coalesced `medium` alert
  per host.
- **Test before you wait for 3am.** `POST /api/snmp/trap-rules/test` with
  `{oid, value}` (or the Test box on the settings pane) reports which rule would
  match and what it would do — a mistyped OID prefix otherwise looks exactly
  like a correct one until the device happens to emit.

`GET/POST /api/snmp/trap-rules`, `PATCH/DELETE /api/snmp/trap-rules/{id}`.
- **SNMP polling** is separate: per device, `POST …/snmp/poll` and a deep
  inspection at `GET …/snmp/deep`.

## Resolver health & watchdog

- **Resolver health** monitor (`resolver_health.py`): names you register are
  resolved at several vetted public resolvers on a cadence; latency, NXDOMAIN and
  failure counts are tracked, and a name that stops resolving raises
  **`resolver_unhealthy`** (and `resolver_recovered` when it comes back). See
  [dns.md](dns.md).
- **Healthchecks.io watchdog** — set `healthchecks_url` and RemotePower pings it
  every `healthchecks_interval_seconds`, so an external dead-man's-switch alerts
  *you* if the control plane itself goes dark.
- **Server disk watchdog** — `disk_watchdog_pct` (default 85, 0 = off) raises
  `server_disk_low` when the data volume fills (recovers with `server_disk_ok`).

## Prometheus exposition

`GET /api/metrics` renders everything above — and most of what the rest of the
product measures — as Prometheus text exposition, for Grafana or an external
alertmanager. Authenticate with an operator token or the dedicated **status
token** (Settings → Advanced), which is the usual choice for a scrape config.
[`prometheus-metrics-sample.txt`](prometheus-metrics-sample.txt) is real output
from a small seeded fleet; ready-made dashboards live in
[`contrib/grafana/`](../contrib/grafana/).

Every per-device family carries `device`, `name` and `group` labels, so a
dashboard can slice by host or by group without a join.

| Family | What it exposes |
| --- | --- |
| `remotepower_info`, `remotepower_devices_total`, `remotepower_devices_online`, `remotepower_device_online`, `remotepower_device_last_seen_timestamp_seconds` | Build version and fleet reachability |
| `remotepower_device_cpu_percent`, `…_mem_percent`, `…_disk_percent` | Per-host resource utilisation |
| `remotepower_device_upgradable_packages`, `remotepower_device_cve_findings`, `remotepower_cve_fixable_total` | Patch backlog and vulnerability findings (by `severity`) |
| `remotepower_monitor_up`, `remotepower_monitor_last_check_timestamp_seconds`, `remotepower_monitor_availability_percent` | The remote checks above |
| `remotepower_slo_target_percent`, `remotepower_monitor_slo_budget_remaining_percent`, `remotepower_monitor_slo_burn_rate`, `remotepower_slo_object_*` | SLO targets, error budgets and burn rate |
| `remotepower_service_active`, `remotepower_services_down_total` | Watched systemd units |
| `remotepower_fleet_health_score`, `remotepower_device_health_score`, `remotepower_attention_items` | Fleet health and the Needs-Attention digest behind it |
| `remotepower_maintenance_windows_active`, `remotepower_commands_pending_total`, `remotepower_scheduled_jobs_total`, `remotepower_webhook_deliveries_total`, `remotepower_webhook_log_size`, `remotepower_control_plane_uptime_percent`, `remotepower_timeline_events_24h` | Control-plane state |

### Hardware, backup and posture families *(v6.4.2)*

These signals already drove RemotePower's own alerts, drawers and scores, but
none of them reached the exporter — so a Grafana user could not alert on a
failing drive, a UPS on battery or a stale backup from RemotePower's own
metrics. Each block is emitted only when the underlying store has data.

| Family | Extra labels | Notes |
| --- | --- | --- |
| `remotepower_device_temperature_celsius` | `sensor` | One series per reading. `sensor` is the board sensor label, `disk:<dev>` for a SMART drive, or `gpu:<name>` |
| `remotepower_device_temperature_max_celsius` | — | Hottest reading on the host, across all three sources |
| `remotepower_device_smart_disk_healthy` | `disk`, `model` | 1/0 from the **server-side** SMART verdict — the same one the alert, the digest and the badge use, not a second copy of the rule |
| `remotepower_device_smart_disks_failed` | — | Drives currently failing that verdict, per host |
| `remotepower_device_smart_reallocated_sectors`, `…_pending_sectors` | `disk` | The pre-fail counters behind the verdict |
| `remotepower_device_smart_power_on_seconds` | `disk` | Power-on time in **seconds** (the store keeps hours) |
| `remotepower_device_smart_wear_ratio`, `…_spare_ratio` | `disk` | SSD/NVMe endurance consumed and remap reserve left, as **0–1 ratios** (the store keeps percentages) |
| `remotepower_ups_on_battery` | `ups` | 1 when running on battery, using the same `OB`/`BATT` test as the `ups_on_battery` alert, so a dashboard and an alert cannot disagree |
| `remotepower_ups_battery_charge_ratio`, `remotepower_ups_load_ratio` | `ups` | 0–1 ratios |
| `remotepower_ups_runtime_seconds`, `remotepower_ups_input_volts`, `remotepower_ups_power_watts` | `ups` | Runtime left, line voltage, output draw |
| `remotepower_backup_ok`, `remotepower_backup_age_seconds` | `path` | Freshness of each watched backup path — see [backups.md](backups.md) |
| `remotepower_backup_max_age_seconds` | `path` | The configured threshold, emitted **only** where a monitor names that path, so a rule comparing age against it never compares to an invented default |
| `remotepower_device_disk_fill_eta_seconds` | — | Predicted time to a full filesystem, emitted only for hosts already trending full — see [forecast.md](forecast.md) |
| `remotepower_device_risk_score`, `remotepower_risk_devices` | `level` on the rollup | Security-posture risk, 0–100, higher is worse — see [risk.md](risk.md) |
| `remotepower_device_reliability_score`, `remotepower_reliability_devices` | `level` on the rollup | Predicted hardware failure — see [disk-health.md](disk-health.md) |
| `remotepower_compliance_pass_ratio`, `remotepower_compliance_devices_evaluated` | — | Fleet baseline compliance, severity-weighted, as a 0–1 ratio |
| `remotepower_device_compliance_pass_ratio` | — | Per-host, omitted when no check applied (a 0 would read as total failure) |
| `remotepower_compliance_check_devices` | `check`, `severity`, `result` | Device counts per outcome for one baseline control, so a panel can name the failing check — see [compliance.md](compliance.md) |

Health, risk and reliability are three separate families, not one
number: health is the Needs-Attention rollup, risk is security posture, and
reliability is predicted hardware failure. Folding them together would lose the
distinction the product makes everywhere else.

## Permissions

- Viewing check status needs normal authentication.
- Adding/editing checks, log rules, inbound tokens and resolver-health targets is
  **admin-only**; inbound receiver endpoints authenticate by their `rpwi_` token,
  not a session.
- All targets/URLs are SSRF-guarded (loopback, link-local and cloud-metadata
  addresses are refused), and inbound endpoints are rate-limited.
