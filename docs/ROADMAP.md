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
| Richer Grafana/Prometheus exporters | 🟢 Small | ✅ v3.4.1 | `prometheus_export.py` |
| iCal feed of scheduled jobs | 🟢 Small | ✅ v3.4.1 | Scheduler |
| Quiet hours / notification schedules | 🟢 Small | ✅ v3.4.1 | Channels |
| Command palette extensions | 🟢 Small | ✅ v3.4.1 | Existing palette |
| Fleet health score | 🟡 Medium | ✅ v3.4.1 | `_compute_attention()` |
| Health-score history | 🟡 Medium | ✅ v3.4.1 | Forecast regression chart |
| Health-score thresholds → alerts | 🟡 Medium | ✅ v3.4.1 | Event registries |
| Reporting (fleet-posture) | 🟡 Medium | ✅ v3.4.1 | patch-report + scheduler + SMTP |
| SLA / uptime reporting | 🟡 Medium | ✅ v3.4.1 | `uptime.json` / `offline_since` |
| Webhook → ticketing | 🟡 Medium | ✅ v3.4.1 | Existing channels |
| Capacity dashboard | 🟡 Medium | ✅ v3.4.1 | Per-device forecast |
| Read-only public status page | 🟡 Medium | ✅ v3.4.1 | Report / health data |
| Per-device timeline | 🔴 Large | ✅ v3.4.1 | New merge endpoint + UI |
| Fleet-wide timeline | 🔴 Large | ✅ v3.4.1 | Per-device merge logic |
| Automation rules engine | 🔴 Large | ✅ v3.4.2 | Event registry + channels + scripts |
| Device dependency map | 🔴 Large | ✅ v3.4.2 | Netmap |
| [Anomaly baselining](#anomaly-baselining) | 🔴 Large | — | AI anomaly scan |
| [Agent integrity / signed binaries](#agent-integrity--signed-binaries) | 🔴 Large | — | Agent packaging |

---

## 🟢 Small

Extensions to existing surfaces; mostly additive logic, little or no new UI scaffolding.

*All six 🟢 Small items shipped in v3.4.1 (CVE↔patch cross-link, software
inventory search, end-of-life OS detection, richer Prometheus exporters, iCal
feed, quiet hours).*

---

## 🟡 Medium

*All 🟡 Medium items shipped in v3.4.1 (fleet health score + history + threshold
alerts, fleet-posture reporting, SLA/uptime, capacity dashboard, public status
page, webhook→ticketing via PagerDuty/Opsgenie). Jira/Linear ticketing adapters
remain a possible follow-up.*

---

## 🔴 Large

Net-new surfaces, new data models, or cross-cutting engines.

*(Automation rules engine shipped in v3.4.2.)*

### Device dependency map
Declare "web depends on db"; suppress downstream alerts when an upstream is down, drawn on the netmap. New dependency model + alert-suppression logic + netmap rendering.

### Anomaly baselining
Extend the existing AI anomaly scan to per-metric statistical baselines (per-host, per-metric rolling stats with deviation detection). New baseline store + scoring on top of the current scan.

### Agent integrity / signed binaries
Sign agent binaries and verify integrity on the server side. Touches the agent packaging/release pipeline + a verification step — security-sensitive, largest blast radius.
