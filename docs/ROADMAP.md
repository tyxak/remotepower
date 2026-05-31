# RemotePower — Roadmap

> Feature backlog grouped by build effort. Effort reflects how much net-new
> surface is needed vs. extending existing infrastructure (event registry,
> channels, scheduler, package inventory, exporters, netmap).

**Shipped in v3.4.1** ("bind it together"): Fleet health score, Reporting
(fleet-posture) + scheduled email, Per-device timeline, and Command palette
extensions. Those are struck from the backlog below.

---

## 📊 Overview

| Feature | Effort | Status | Builds On |
|---|:---:|:---:|---|
| Cross-link CVEs ↔ patches | 🟢 Small | ✅ v3.4.1 | Patches + CVE pages |
| Software inventory search | 🟢 Small | ✅ v3.4.1 | Package inventory |
| End-of-life OS detection | 🟢 Small | ✅ v3.4.1 | Compliance + health |
| [Richer Grafana/Prometheus exporters](#richer-grafanaprometheus-exporters) | 🟢 Small | — | `prometheus_export.py` |
| [iCal feed of scheduled jobs](#ical-feed-of-scheduled-jobs) | 🟢 Small | — | Scheduler |
| [Quiet hours / notification schedules](#quiet-hours--notification-schedules) | 🟢 Small | — | Channels |
| Command palette extensions | 🟢 Small | ✅ v3.4.1 | Existing palette |
| Fleet health score | 🟡 Medium | ✅ v3.4.1 | `_compute_attention()` |
| [Health-score history](#health-score-history) | 🟡 Medium | — | Forecast regression chart |
| [Health-score thresholds → alerts](#health-score-thresholds--alerts) | 🟡 Medium | — | Event registries |
| Reporting (fleet-posture) | 🟡 Medium | ✅ v3.4.1 | patch-report + scheduler + SMTP |
| [SLA / uptime reporting](#sla--uptime-reporting) | 🟡 Medium | — | `uptime.json` / `offline_since` |
| [Webhook → ticketing](#webhook--ticketing) | 🟡 Medium | — | Existing channels |
| [Capacity dashboard](#capacity-dashboard) | 🟡 Medium | — | Per-device forecast |
| [Read-only public status page](#read-only-public-status-page) | 🟡 Medium | — | Report / health data |
| Per-device timeline | 🔴 Large | ✅ v3.4.1 | New merge endpoint + UI |
| Fleet-wide timeline | 🔴 Large | ✅ v3.4.1 | Per-device merge logic |
| [Automation rules engine](#automation-rules-engine) | 🔴 Large | — | Event registry + channels + scripts |
| [Device dependency map](#device-dependency-map) | 🔴 Large | — | Netmap |
| [Anomaly baselining](#anomaly-baselining) | 🔴 Large | — | AI anomaly scan |
| [Agent integrity / signed binaries](#agent-integrity--signed-binaries) | 🔴 Large | — | Agent packaging |

---

## 🟢 Small

Extensions to existing surfaces; mostly additive logic, little or no new UI scaffolding.

*(Cross-link CVEs ↔ patches, software inventory search, and end-of-life OS detection shipped in v3.4.1.)*

### Richer Grafana/Prometheus exporters
Add health score and timeline counts to the existing `/metrics` endpoint. New gauges/counters in `prometheus_export.py` — no new infra.

### iCal feed of scheduled jobs
Expose scheduled jobs + maintenance windows as a tokened `.ics` feed. Serialize `process_schedule` entries to VEVENTs behind a read-only token.

### Quiet hours / notification schedules
Suppress non-critical channel sends overnight, fleet- or device-scoped. A time-window gate in the channel-send path with a priority threshold.

---

## 🟡 Medium

Reuse a core engine or dataset but require a new rollup, report, or modest surface.

### Health-score history
Sample the fleet/per-device score (now produced by `_fleet_health()`) into a `metrics_history.json`-style series and chart the trend. Reuses the forecast regression chart for rendering — mostly a sampling job + storage.

### Health-score thresholds → alerts
Fire a `health_degraded` event when a device drops below N or falls sharply. New event type wired through all 6 registries; threshold + slope detection on the score series.

### SLA / uptime reporting
Per-device and per-group uptime % over a window, exportable in the report. Computed from `uptime.json` / `offline_since`; integrate into the v3.4.1 reporting pipeline.

### Webhook → ticketing
Outbound adapters for Jira / Linear / PagerDuty / Opsgenie alongside existing channels. Each is a channel-shaped adapter following the `_webhook_message/_webhook_priority/_webhook_tags` helper pattern.

### Capacity dashboard
Fleet-wide CPU / mem / disk aggregates, not just per-device forecast. Roll up existing per-device metrics into fleet totals + a dashboard view.

### Read-only public status page
A tokened external page showing fleet health score + monitor status, served from the same report/health data. New public route + minimal template, no auth beyond the token.

---

## 🔴 Large

Net-new surfaces, new data models, or cross-cutting engines.

### Automation rules engine
"When event X on devices matching Y → run script / notify channel / open ticket." Composes the existing event registry, channels, and saved scripts into a rule model + evaluation loop + a rule-builder UI.

### Device dependency map
Declare "web depends on db"; suppress downstream alerts when an upstream is down, drawn on the netmap. New dependency model + alert-suppression logic + netmap rendering.

### Anomaly baselining
Extend the existing AI anomaly scan to per-metric statistical baselines (per-host, per-metric rolling stats with deviation detection). New baseline store + scoring on top of the current scan.

### Agent integrity / signed binaries
Sign agent binaries and verify integrity on the server side. Touches the agent packaging/release pipeline + a verification step — security-sensitive, largest blast radius.
