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
| Anomaly baselining | 🔴 Large | ✅ v3.4.2 | AI anomaly scan |
| Agent integrity / signed binaries | 🔴 Large | ✅ v3.4.2 | Agent packaging |

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

*All 🔴 Large items shipped in v3.4.2 (automation rules engine, device dependency
map, anomaly baselining, agent integrity attestation).*

**Ticketing:** PagerDuty + Opsgenie (on-call paging) shipped in v3.4.1. For
*ticketing/help-desk*, the recommended path is the email channel → a self-hosted
help-desk (osTicket, Zammad, Request Tracker, FreeScout) — zero code, documented
in `docs/webhooks.md`. This keeps RemotePower self-hosted end to end; preferred
over SaaS Jira/Linear adapters. A native osTicket REST adapter could follow if a
structured-field integration is wanted. *(Cryptographic release signing shipped
in v3.4.2.)*

---

## 🔜 Planned — next test release

Two bind-it-together follow-ups identified during the v3.13.0 sweep. Both are
low-risk and operate over data the system **already collects and caches** — no
agent change, no new storage.

| Feature | Effort | Builds On |
|---|:---:|---|
| Per-container stale-image badge | 🟢 Small | image-update digest cache + `/devices/<id>/containers` |
| Fleet thermal roll-up ("hottest hosts") | 🟡 Medium | `hardware.json` temps/SMART + Storage-health page pattern |
| Per-account sidebar favorites | 🟡 Medium | sidebar favorites (localStorage) + My Account / `/api/me` |

- **Per-container stale-image badge.** Surface the registry-staleness the fleet
  **Image Updates** page already computes (`_image_update_view` produces a
  per-`(device, container)` `stale` flag) directly on each row of the
  device-drawer Containers table — right next to the new Restarts column. Minimal
  change: stamp `update_available` onto each item in `handle_device_containers`
  by joining the container's `repo_digest` against the cached registry digest in
  `image_updates.json` (same logic as the fleet page, so the two never disagree),
  then render a badge. No agent change, no new storage.
- **Fleet thermal roll-up.** A "Hottest hosts" page mirroring the Storage / RAID
  health page: one row per host with its max temperature and hottest sensor, so
  thermals are answerable fleet-wide instead of only inside one device's drawer.
  The data already persists per-device in `hardware.json`
  (`hardware.temps[].current_c` and `smart[].temperature_c`); add a read-only
  `GET /api/fleet/thermal` aggregation modelled on `handle_storage_overview`,
  plus a sortable table page (with the mandatory `tableCtl.wireSortOnly` /
  `sortRows` / `data-col` wiring). No agent or schema change.
- **Per-account sidebar favorites.** Sidebar favorites currently persist in
  `localStorage` (`rp_favorites`) — per *browser*, so they don't follow a user
  across devices and are shared if two users share a browser profile (same model
  as theme / sidebar-collapse / group state). Optional upgrade: persist them on
  the user record and hydrate on login through the existing My Account `/api/me`
  plumbing, so favorites become true per-account and sync across devices. Needs a
  user-record field + a small read/write endpoint + a load-on-login hydrate that
  seeds `_renderFavorites`; keep localStorage as the offline/anonymous fallback.
  No agent change.

---

## ✅ Earlier roadmap — shipped

Every item in the Overview table landed across v3.4.1 and v3.4.2. New ideas get
appended above.
