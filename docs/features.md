# Features

Version tags (e.g. *v3.4.1*) mark when a feature landed. Complete history is in [`CHANGELOG.md`](../CHANGELOG.md).

## Fleet visibility & inventory

| Feature | Notes |
|---|---|
| Live status | Green/red per device, auto-refresh 60s, configurable per device (10–3600s) |
| OS icons | Auto-detected SVG glyphs — Linux, Windows, macOS *(v4.0.0)*, fallback |
| Uptime tracking | Online/offline state changes stored per device |
| Container awareness | Auto-detected Docker / Podman / Kubernetes pods — image, status, restart count, ports, namespace; read-only |
| Network map | Manual topology from per-device `connected_to`; agentless switches/APs; site/group/tag scope picker *(v5.0.0)* |
| Network metrics page | Per-device RX/TX from interface samples; fleet/group/tag/site scope, top-talkers, roll-ups *(v5.0.0)* |
| Pending-reboot indicator | Amber ⟳ **Pending Reboot** badge on Patches when `/run/reboot-required` exists *(v2.4.14)* |
| Timeline (fleet or device) | Merged fleet events + command runs, newest-first, filterable, scoped *(v3.4.1)* |
| Fleet health score | 0–100 per device and fleet from Needs-Attention signals; history sparkline + `health_degraded`/`health_recovered` *(v3.4.1)* |
| Fleet heat map | Home grid of device cells coloured by health score *(v3.4.2)* |
| Risk scoring | Per-asset 0–100 from CVEs, exposure, policy, lifecycle, mount health, with per-point breakdown |
| NOC Status Board | Fleet rolled into group/site/tag tiles + problem-host strip *(v5.0.0)* |
| Tasks | Operational checklist page for tracking fleet work items |
| Needs-Attention digest | Single ranked list merging every fleet signal *(v2.4.7)* |
| Software inventory search | "Which hosts run openssl < X" over collected inventory *(v3.4.1)* |
| Software center | Every installed package across the fleet, versions + host counts *(v3.13.0)* |
| End-of-life OS detection | Vendor-EOL table flags out-of-support hosts *(v3.4.1)* |
| Ad-hoc fleet query | Filter by group/tag/OS/online/pending/CVE/integrity/version/pkg-manager/has-package/failed-units/disk-mem%/offline-days; saved queries *(v3.4.2)* |
| Boot reason | Why a host last restarted, stored + shown *(v3.8.0)* |
| Failed systemd units + logged-in users | Persisted, shown in System Info tab *(v3.8.0)* |
| Unmonitored devices | Shown in telemetry/inventory views (thermal/power/storage/exposure/SMART/patches/ports/processes/GPU), flagged; only alerting suppressed *(v4.7.0)* |
| Decommissioned assets | Greyed across lists + CMDB with *DECOMMED* badge; fully silenced (no monitoring/alerts/health/SLA) *(v5.0.0)* |
| Tags & groups | Tag devices, namespace by group (`dc1/prod`); filter and batch by either |
| Device notes | Free-text per device, shown as tooltip |
| Sites & teams | First-class fleet grouping above groups (location/team/customer); super-admins see all *(v3.5.0)* |
| Geographic site map | Sites gain optional latitude/longitude; a self-contained NOC world map (no external tiles/CSP-safe) plots them, colored by rolled-up device health (all-online / some-offline / all-offline). Click a dot to filter the site list. `GET /api/sites/map` *(v6.0.0)* |
| Rack elevation view | Model racks (name, site, height in U); place assets via their CMDB record (rack, bottom U, height in U); a front elevation view renders occupancy and flags overlapping U spans. `GET/POST /api/racks`, `GET /api/racks/{id}/elevation` *(v6.0.0)* |
| IPAM | Define subnets (CIDR/site/VLAN/notes + static reservations); per-subnet occupancy is derived from known device addresses (device IP + CMDB interfaces incl. NAT) — used/reserved/free counts + a per-address inventory. A duplicate IP across two devices raises an edge-triggered `ip_conflict` alert. `GET/POST /api/ipam/subnets`, `GET /api/ipam/subnets/{id}/occupancy` *(v6.0.0)* |
| Device profiles | Named bundle of per-device settings (poll interval, watched units, log watches, drift-watched files, metric thresholds); **apply** stamps them onto selected devices as a one-shot copy (devices stay editable). `GET/POST /api/device-profiles`, `POST /api/device-profiles/{id}/apply` *(v6.0.0)* |
| Smart groups | Saved fleet-query predicate (group/tag/site/OS/agent-version/monitored/agentless/drift/reboot + mem/disk/cpu/swap % thresholds) whose membership is re-materialized every ~60s; reference it as a `smart:<name>` targeting scope in alert-routing, auto-patch, report and service-baseline scopes (doesn't change a device's real group). `GET/POST /api/smart-groups` *(v6.0.0)* |

## Device drawer signals

| Feature | Notes |
|---|---|
| System Info | Top processes by CPU, per-mount fs type, reboot-required+reason, 1-min loadavg, container age *(v3.4.0)* |
| Hardware pills | CPU model, kernel, total RAM, total disk beside live usage *(v4.6.0)* |
| Access — recent logins | Who logged in + distinct source IPs *(v3.13.0)*, with Last-seen timestamp *(v4.4.0)* |
| Scheduled jobs / timers | Failed-first table of every systemd timer — unit, target, state *(v3.13.0)* |
| Per-host storage / RAID | This host's ZFS / mdadm / btrfs pools (state, capacity, scrub) *(v3.13.0)* |
| Port bind + scope | Each socket's bind address + world / LAN / local badge *(v3.13.0)* |
| Firewall fingerprint | Active backend, rule count, drift baseline fingerprint *(v3.13.0)* |
| Pressure pills | Brute-force lockout badge; disk/swap pressure pills *(v3.13.0)* |
| Per-interface MAC | MAC per interface *(v3.10.0)* |
| Backups | Each watched backup path's age + fresh/stale state *(v3.4.2)*; **3-2-1-rule score** (3 fresh copies / 2 distinct targets / 1 off-site — informational) *(v6.0.0)* |

## Metrics, history & forecasting

| Feature | Notes |
|---|---|
| Metrics history | CPU/RAM/disk/swap/loadavg sparklines per device, full chart on click; up to 1440 snapshots (`metrics.json`) |
| Live metrics (Monitor page) | All-fleet current sysinfo, colour-coded by alert level *(v1.12.0)* |
| Live high-res device view | Drawer **Live view** button arms a bounded (~30 s) burst — the agent posts 1-second CPU/mem/disk/swap samples that the drawer streams; auto-stops on close, re-arms while open. `POST /api/devices/{id}/live`, `GET …/live-samples` *(v6.0.0)* |
| Metric trend modal | Time-series per device, one click from the fleet view *(v2.0)* |
| Per-mount disk | Each non-pseudo mount tracked individually *(v1.11.10)* |
| Network-mount trends | NFS/SMB/CIFS shares flow into daily history + disk-fill forecast *(v3.13.0)* |
| Resource forecasting | Per-mount least-squares trend → days-to-full + projected fill date; **Monitoring → Forecast** page *(v3.4.0)* |
| Statistical anomalies | Per-host mean/stdev baselines flag ≥2.5σ memory/swap/disk deviations *(v3.4.2)*; optional **seasonal** mode scores each host against its matching day-of-week × 4-hour-block baseline (falls back to the flat baseline until ~2 weeks of data), so a recurring Monday-morning spike isn't a false alarm — `GET /api/fleet/anomalies?seasonal=1` *(v6.0.0)* |
| What changed (drift over time) | Diff oldest vs latest snapshot — package/port/unit/reboot/disk deltas *(v3.4.0)* |
| Trends charts | Zero-dep multi-series SVG — fleet health, compliance %, per-device resources, CPU-load saturation % *(v3.4.2)* |
| Long-term metric roll-ups | Hourly cadence folds raw per-device CPU/mem/swap/disk samples into hourly (kept 30 days) and daily (kept ~2 years) min/avg/max buckets; the Trends "Device resources" chart gains a range selector (Recent → 30d hourly → 2y daily). Additive read path — raw store untouched. `GET /api/devices/{id}/metrics/rollup?tier=hourly|daily` *(v6.0.0)* |
| Prometheus metrics | `/api/metrics` exposition (Grafana); status-token auth; health/needs-attention/CVE gauges *(v3.4.1)*; metrics push *(v4.0.0)* |
| Availability SLO + error budgets | Per-monitor availability vs a `slo_target_percent` target → error-budget remaining + burn rate; `GET /api/slo` + Prometheus gauges *(v5.5.0)* |
| Control-plane uptime | RemotePower's own observed availability (hourly "served a request" buckets) over 24h/7d/30d at `GET /api/self-test` + a Prometheus gauge; denominator starts at first tracked hour *(v5.5.0)* |
| Capacity dashboard | Fleet-wide CPU/mem/disk rollup, top consumers, on Reports *(v3.4.1)* |

## Checks & custom checks *(v4.1.0)*

| Feature | Notes |
|---|---|
| Per-host Checks | Every monitored signal as OK/WARN/CRIT/UNKNOWN — reachability, CPU/mem/swap, per-mount disk + inode, fd/conntrack, failed units, timers, drift, exposed ports, updates, CVEs, SMART/UPS/temperature, clock, gateway, OOM, mail-queue, RO filesystems, disk-fill ETA, storage/RAID. Sortable, filterable, per-check muteable |
| Check catalog | Server-evaluated process/port-open/port-closed; host-evaluated **systemd unit active** *(v5.6.0)*, file present/absent, job freshness, log error rate; **~70 ready-made templates** that pre-fill the form (incl. a RemotePower self-infra set — API/WSGI/scheduler/satellite units); host target is a device-search typeahead; a unit check can also be added to the device's Services watch-list; editable *(catalog v5.6.0)* |
| Custom monitoring scripts | Admin bash health checks, assigned per device, run every ~5 min; binary exit; fleet results page; `custom_script_fail`/`custom_script_recover`; AI generation in create modal; full guide [custom-scripts.md](custom-scripts.md) *(v2.5.0)* |
| Custom metric ingestion | Agent reads a Prometheus-textfile-collector dir (`/etc/remotepower/metrics.d/*.prom`, `name value` lines) → numeric metrics (≤32, name-validated) with rolling history; per-metric thresholds (`custom_metric_thresholds`) → `custom_metric_alert`/`_recover`; shown in the device drawer. `GET /api/devices/{id}/custom-metrics` *(v6.0.0)* |
| Monitoring profiles | Named bundles of custom scripts applied to omnisearch-selected assets in one action; `/api/monitoring-profiles` + `/apply` |

## Active monitors & probes

| Feature | Notes |
|---|---|
| Ping / TCP / HTTP probes | ICMP, TCP, HTTP HEAD from the server; runs when dashboard closed *(v1.11.8)*; HTTP SSRF-guarded with connect-time recheck |
| Network path monitoring | `path` monitor type — server runs traceroute/tracepath on cadence, stores the hop list, and fires `path_changed` when the route's hop set differs from the baseline (auto re-baselines); graceful when no traceroute binary is present *(v6.0.0)* |
| DNS / ICMP / HTTP / DB monitors | DNS resolution with expected-address; ICMP latency + loss; HTTP status + latency-SLA; credential-less DB-liveness (PostgreSQL/MySQL/Redis); tag/group fan-out *(v4.1.0)* |
| HTTP content assertions | Body contains / not-contains *(v3.12.0)*, regex match, and JSON dot-path field assertions (`status.healthy` = expected value, or just "must exist") — catches a 200 OK that's actually an error page *(regex/JSON v5.8.0)* |
| Multi-step HTTP monitors | `http_flow` type — up to 5 ordered steps sharing a cookie jar, with per-step expect-status/contains and `extract`→`${var}` for later steps (e.g. login → CSRF token → fetch page); each step SSRF-guarded, no-redirect *(v6.0.0)* |
| Mail round-trip monitor | Sends a token-stamped email through outbound SMTP, then polls a mailbox over IMAP for it — measuring true end-to-end delivery latency and firing `mailflow_delayed` when a probe doesn't arrive within the max-latency threshold, `mailflow_ok` on recovery. `GET/POST /api/mailflow` *(v6.0.0)* |
| Monitor history | Uptime %, sparkline, last 50 results per target |
| Probe from a satellite | A monitor can be probed by a relay satellite (`via_satellite`) instead of the server, so it reaches segmented/private networks the server can't. The satellite fetches its assigned monitors (`GET /api/satellite/monitor-work`), runs the probes on its side, and reports back (`POST /api/satellite/monitor-results`, satellite-token auth, results accepted only for its own monitors); the monitor list shows a "via satellite" origin badge. Admin-gated. *(v6.0.0)* |
| Import from Nagios / Kuma / Zabbix | Paste a Nagios/Icinga object config, Uptime Kuma backup JSON, or Zabbix XML export → preview the mapped monitors (dry-run) then apply; unmappable entries listed, duplicates skipped. `POST /api/import/monitors` *(v6.0.0)* |
| Service monitoring | Agent watches systemd units; matrix view; webhooks on transitions; shows resolved alias *(v3.9.0)* |
| Service baselines | Fleet-wide default sets of watched units (e.g. `sshd.service`, `remotepower-agent.service`) scoped by all/group/tag/site and merged into each covered device's watch list — set once, no per-host editing. `GET/POST /api/service-baselines` *(v5.5.0)* |
| Failed-unit alerting | A systemd unit entering the failed state raises a first-class `failed_unit` alert/webhook (edge-triggered, coalesced per host) *(v5.5.0)* |
| Log tail + alerts | journalctl per watched unit; rolling 6-hour buffer; regex search; pattern-match alerts; per-rule template / exclude / snooze; matched line shown in NA card / inbox / webhook + Open-in-Logs deep link *(v3.3.0)* |
| Inbound syslog | HTTP receiver — point rsyslog `omhttp`/fluent-bit/`curl` at `POST /api/syslog/in/<token>`; parses RFC 3164/5424 into the device log buffer for `log_alert` rules *(v3.2.0)* |
| SNMP trap receiver | HTTP receiver — an `snmptrapd` handler POSTs decoded traps as JSON to `POST /api/snmp/trap/<token>`; traps attach to the pinned device's SNMP view and raise a coalesced `snmp_trap_received` alert |
| Inbound alert webhook | Generic receiver — external systems (Grafana, Alertmanager, Authentik, n8n, Home Assistant, …) POST JSON `{severity, title, …}` to `POST /api/webhook/in/<token>`; lands in the Alerts inbox *(v3.2.0)* |
| TLS / DNS expiry | Server-side probes against a watchlist; warn 14d / crit 3d; auto re-probed ~6h by the built-in schedule — no cron needed; a certificate crossing the window raises a coalesced one-per-host **alert** by default (not just needs-attention) *(alert v6.0.1)* |
| CT watch | Certificate-Transparency monitoring via crt.sh — watched domains baseline on first check, then any certificate you didn't know about raises `ct_new_certificate` (compromised DNS/ACME, rogue issuance); circuit-broken when crt.sh is down *(v6.0.0)* |
| Resolver health monitor | Re-resolves a name across public resolvers; tracks latency + NXDOMAIN; `resolver_unhealthy`/`resolver_recovered` *(v4.9.0)* |
| Healthchecks.io watchdog | Server pings a URL on a cadence so an external monitor flips red if RemotePower stops |

## Alerts, events & routing

| Feature | Notes |
|---|---|
| Metric alerts | Disk/memory/swap/CPU-load thresholds with hysteresis *(v1.11.10)*; per-device + per-mount overrides *(v1.12.0)* |
| Webhook event registry | 124 event types (incl. ticket lifecycle: opened/resolved/SLA-breached), per-event toggles, test-event button; payloads carry a `schema_version` so consumers can guard against shape drift *(v5.5.0)* |
| Notification sandbox mode | `notifications_test_mode` (or per-destination `dry_run`) logs webhook + email deliveries without sending — validate event routing on a staging instance without spamming recipients *(v5.5.0)* |
| Notification digest window | Per-destination `digest_minutes` batches non-critical events into one periodic summary delivery; critical/urgent always page immediately *(v6.0.0)* |
| Channel routing matrix | Per event-kind, which surfaces it reaches — Needs Attention / Recent Activity / Alerts inbox / Webhook *(v3.3.0)* |
| Per-user notifications | Each operator subscribes their **own** webhook + email with personal filters (min urgency, event allowlist, group/tag/site scope) in My Account — additive to the org channels (never suppresses them); only fires for devices the user's role can see. `GET/POST /api/my/notify-prefs` *(v6.0.0)* |
| Host-grouped alert inbox | Open alerts stacked per host (worst first), Ack-all/Resolve-all, symptoms folded under `device_offline` root cause *(v4.1.0)* |
| Fix from the Alerts page | An alert whose event maps to a remediation playbook shows a **Fix** button that opens the guided diagnostic → AI → remediation runner directly from the inbox *(v6.0.0)* |
| Alert correlation | Tags `_root_cause` / `_symptom_of` for the grouped inbox |
| Duplicate-alert coalescing | Repeat firings fold into the open alert (count bump) *(v5.0.1)* |
| Recovery auto-resolve | A recover event closes the matching open alert when the condition clears — service/metric/mount/integration/resolver/IP/SNMP/disk, plus **container** (`container_recovered`) and **backup** (`backup_recovered`), matched per-identity *(container/backup v5.6.0)* |
| Alert-resolution timeline (MTTR) | Time-to-resolve / ack mean+median 7/30/90d, per-host, close-classification *(v4.9.0)* |
| Quiet hours | Hold non-critical delivery during a daily window; critical always pages *(v3.4.1)* |
| Maintenance windows | Suppress alerts and/or gate command execution; per-device/group/fleet; one-shot or recurring cron+duration; audit trail *(v3.4.2)* |
| After-hours detection | Flag selected events firing outside business hours *(v3.4.2)* |
| On-call & escalation | Escalation tiers re-notify unacked alerts; on-call rotation names the contact *(v3.4.2)*; **per-tier target** routes a tier to one webhook destination *(v5.5.0)*; **calendar rotation** — anchored "who's on call this week" schedule + dated overrides/handoffs + upcoming-handoffs view *(v6.0.0)* |
| Automation rules engine | Event (at severity) on matching devices → run saved script, notify, **open a ticket**, **add a tag** or **mute the alert** *(actions extended v5.6.0)*; per-rule cooldown, admin-only, audited *(v3.4.2)* |
| Device dependency map | Declare device→upstream deps; downstream alerts held while upstream offline *(v3.4.2)* |
| Dependency auto-suggestion | Agent samples established outbound peers (private IPs only); server correlates them to known device IPs → suggested `depends_on` edges with evidence on the Network map — accept adds the link, dismiss hides it. `GET/POST /api/dependency-suggestions` *(v6.0.0)* |
| LLDP topology discovery | Agent parses `lldpctl` neighbors (peer sysname, port, mgmt-IP) where lldpd is installed; server correlates them to known devices → suggested physical `connected_to` links on the Network map — accept sets the (manual-wins) edge, dismiss hides it. `GET/POST /api/lldp-suggestions` *(v6.0.0)* |
| Patch alerts | Webhook when pending updates exceed a threshold |
| Patch-compliance SLA | Per group/tag/fleet max-age (days) for security and/or all pending updates; first-seen aging → `patch_sla_violation`/`patch_sla_ok`, a breach list on the Patches page and a count in the posture report. `GET /api/patch-sla` *(v6.0.0)* |
| Admin-only alert mutation | Optionally require admin role to ack / unack / resolve (`viewers_can_ack_alerts`) *(v3.3.0)* |
| One-click ack from email | Opt-in signed **Acknowledge / Resolve** links in alert emails (`alert_email_ack_links`) — HMAC-signed, no login, IP-allowlist-exempt; acts on the alert straight from your inbox. `GET /api/alerts/act` *(v6.0.0)* |
| Ticket system | Opt-in built-in helpdesk (Advanced → `tickets_enabled`, default off): tickets typed Incident / Request / Change (alerts → Incident, reusing the alert id as `#RP000042`), statuses ongoing/pending-customer/pending-internal/resolved/closed; **priority P1 Major / P2 Critical / P3 Warning / P4 Low** (alert-derived tickets inherit the alert severity, Major manual-only); per-priority SLA response-time targets (`ticket_sla`) with breach events; **assignee + take-ownership**; **multiple affected devices**; **master/sub parent-child links**; sortable list defaulting to unhandled → your own → ongoing; attach to alerts + devices; search; outbound email (existing SMTP) + dedicated-IMAP reply ingestion with a mail-loop guard; recipient parsed from CMDB contacts/notes; per-device + CMDB ticket indicators |
| Ticket attachments | Inbound email attachments stored + downloadable/previewable; attach files to an outbound reply (≤15 MB each, ≤10/msg); access bound to the ticket, served `nosniff`. `GET …/tickets/{id}/attachments/{aid}[?inline=1]` *(v5.5.0)* |
| Ticket auto-reply | Opt-in one-time acknowledgement on inbound-created tickets; loop-safe (`Auto-Submitted`, once per ticket, skips no-reply/mailer-daemon). `…/tickets/autoreply` *(v5.5.0)* |
| Canned ticket replies | Reusable reply snippets with insert-time `{ticket_id}`/`{customer}`/`{assignee}` placeholders — admin-managed, one-click insert in the composer. `GET/POST /api/tickets/templates` *(v6.0.0)* |
| Recurring scheduled tickets | Cron-scheduled auto-created tickets for recurring chores (restore drills, cert reviews) — subject/body/priority/device/assignee, deduped per matching minute. `GET/POST /api/tickets/schedules` *(v6.0.0)* |
| Ticket satisfaction survey (CSAT) | Opt-in one-click Good/Okay/Bad rating link emailed on resolve — signed + single-use (no login); rating shown on the ticket. `GET /api/tickets/csat` *(v6.0.0)* |
| Business-hours SLA calendar | Optional `ticket_business_hours` (weekday windows + holidays + UTC offset) counts ticket SLA targets in business time only — the clock pauses overnight/weekends/holidays; off = 24/7 wall-clock *(v6.0.0)* |
| Email thread view | One-click printable window of a ticket's full correspondence *(v5.5.0)* |
| Posture digest | Opt-in daily/weekly email summary over SMTP *(v3.11.0)* |
| Branded email | Alert / digest / test emails send a branded HTML alternative (white-label name + accent) + plain-text fallback *(v5.5.0)* |
| Digest endpoint | `/api/digest` for cron-driven email summaries |
| Flap cap | Server-wide cap stops a flapping monitor flooding channels |
| Alert mute & tuning | Per-(host, event) **mute** silences one exact alert from one asset (inbox + webhook + needs-attention) while history keeps recording; the Alerts/dashboard Ack button is an **X mute**; Monitoring → Tuning ranks the noisiest alerts/sources from the timeline. `GET/POST /api/alert-mutes`, `GET /api/alert-tuning` *(v5.6.0)* |

## Notification destinations

| Feature | Notes |
|---|---|
| Webhooks | Generic JSON, Discord, ntfy, Slack, Gotify, Microsoft Teams, Pushover, Telegram, Matrix *(Telegram/Matrix v5.3.0)*; auto-format detection |
| Signed webhook deliveries | Optional per-destination HMAC secret → `X-RemotePower-Signature` (HMAC-SHA256 over the raw body) + timestamp header on generic-format deliveries, so receivers verify authenticity; secret write-only *(v5.3.0)* |
| Browser push | Web Push (VAPID) notifications straight to subscribed browsers / the PWA — no third-party service; admin-enabled, per-browser opt-in *(v4.0.0)* |
| GitHub issues | `github` destination opens an issue with labels *(v3.3.0)* |
| PagerDuty / Opsgenie | PagerDuty Events v2 (trigger + auto-resolve), Opsgenie Alerts v2 *(v3.4.1)* |
| ITSM (Jira / ServiceNow / Zendesk) | Ready-made ticket formats; "fire on ACK" opens a ticket, link shown on the alert *(v5.0.0)* |
| Ack → ticket webhook | Any destination can also fire on alert acknowledgement *(v3.12.0)* |
| Audit-log forwarding | Audit entries to a SIEM (HTTP) or syslog *(v3.7.0)* |

## Commands, actions & automation

| Feature | Notes |
|---|---|
| Reboot / shutdown | Queue actions, reported on next heartbeat |
| Suspend to RAM | Schedule (one-shot/cron) or queue `systemctl suspend`; warns if no MAC for WoL resume *(v4.0.0)* |
| Wake-on-LAN | Magic packet, unicast over routed networks/VPN |
| Custom commands | Arbitrary shell as root; output via heartbeat; 64 KB cap |
| Command library | Saved named snippets |
| Per-device allowlist | Whitelist of allowed exec commands per device |
| Scheduled commands | One-shot (datetime) or recurring (cron) |
| Per-command timeouts | Override default command timeout on a single run *(v5.0.0)* |
| Long-poll exec | `/api/exec/wait` holds the connection until output arrives |
| Update history | Rolling 10-run buffer of apt/dnf/pacman output per device |
| Command queue | View + cancel every device's pending queued commands; ACME actions logged; clear-all/clear-log *(v3.4.2)* |
| Bulk delete & re-tag | Select many devices, remove or tag in one action *(v5.0.0)* |
| Maker-checker approval | A second admin signs off risky actions; re-checks device state at approval *(v3.7.0)*; **configurable gated-kind set** — pick which command kinds require approval (reboot/shutdown/upgrade/uninstall/container by default; can add Run-command/Compose/Service/Kill) *(v6.0.0)* |
| Quarantine | Per-device admin switch disabling every action, enforced at dispatch, audited *(v3.4.0)* |
| Audit (read-only) mode | `/etc/remotepower/audit-mode` makes the agent refuse every command (exec/scripts/reboot/config/self-update); operator-owned; AUDIT badge *(v4.10.0)* |
| Uninstall agent | Queues uninstall; agent removes unit/creds/state/binary *(v3.3.0)* |
| Ansible playbook runner | Run playbooks against group/tag/site/fleet, server as control node; lives under the Provisioning page *(v3.7.0)* |
| Provisioning blueprints | Folder-tree catalog of Terraform / cloud-init / Ansible / iPXE templates; fill variables → render (copy/download), or run Terraform **plan/apply/destroy** server-side (opt-in `iac_execute_enabled`, secrets via env, per-blueprint state + run lock). `GET/POST /api/provisioning/blueprints`, `…/{id}/render`, `…/{id}/run` *(v5.6.0)* |
| App catalog | One-click deploy curated self-contained apps via Docker Compose; admin custom catalog entries *(v5.1.0)* |
| Cron & timer management | View/manage crontabs + systemd timers; audited, no-shell install *(v5.1.0)* |
| On-demand diagnostics | Network speed test + LAN discovery (ARP/nmap), flags unmanaged hosts *(v3.4.0)* |
| Diagnostics bundle | One downloadable scrubbed support bundle (no secrets) *(v4.3.0)* |

## Remote access

| Feature | Notes |
|---|---|
| Web terminal | Real xterm.js SSH in the browser via a hardened daemon; asciinema v2 recordings (output-only default, opt-in keystroke) *(v1.11.11)* |
| Graphical remote desktop | noVNC over the web-terminal daemon's SSH tunnel to loopback VNC; never network-exposed; Linux only *(v3.5.0)* |
| RDP tunnel (Windows) | Opt-in (`rdp_enabled`): the drawer's RDP action mints an admin-reauth'd session that tunnels the host's loopback 3389 over the same SSH plumbing; an operator-side bridge exposes it as `localhost:PORT` for mstsc/Remmina (no in-browser RDP client — deliberate). RDP port stays loopback-only on the host *(v6.0.0)* |
| Remote file manager | Browse/view/edit files through the agent — no SSH/SFTP; allowlisted roots, exec-gated, audited; reads survive quarantine; opt-in per server *(v3.6.0)*; **binary-safe download + upload** (base64, ≤8 MB, no-overwrite unless forced) *(v6.0.0)* |
| Host user/key/firewall mgmt | Add/lock/unlock/delete users, add/revoke SSH keys, allow/deny ufw/firewalld ports from the drawer; exec-gated *(v3.6.0)* |
| SSH links | Per-credential `ssh://user@host:port` + copy button; default SSH username *(v2.4.2)* |

## Patching & packages

| Feature | Notes |
|---|---|
| Install software | Install repo packages on a host or tag/group (apt/dnf/yum/zypper/pacman/apk) *(v3.4.2)* |
| Hold / unhold packages | Pin packages at current version (`apt-mark hold`, dnf/yum `versionlock`, `zypper addlock`); names only, no shell *(v4.0.0)* |
| Patch catalog | Pending updates aggregated by package across hosts; third-party (flatpak/snap/pip/npm) *(v3.4.2)* |
| Post-deploy verification | Confirm the pending count actually dropped (ok/stalled/pending) *(v3.4.2)* |
| Auto-patch | Cron-scheduled updates across a single device / group / tag / site / whole fleet, respecting maintenance windows; optional staged rings *(v3.6.0, single-device v6.0.1)* |
| Patch report | Fleet-wide per-device pending-update detail, filterable by group/device, with a per-device drill-down and re-check; export the filtered report as CSV / XML / browser-PDF. `GET /api/patch-report`, `…/csv`, `…/xml`, `…/device/{id}` *(PDF v6.0.1)* |
| On-demand package scan | One-shot **Scan packages** now — fresh inventory + patch count *(v2.4.5)* |
| Software metering | Named-software install counts vs allowance, over-deployment flagged; aliases + reclamation *(v3.4.2)* |
| Fleet software policy | `banned` / `required` / `min_version` rules (tag-scoped) → `software_policy_violation` *(v3.11.0)* |
| Update-available notice | Checks GitHub for newer RemotePower releases; detection only *(v2.4.6)* |

## Vulnerabilities (CVE) & risk

| Feature | Notes |
|---|---|
| CVE scanner | Installed packages vs [OSV.dev](https://osv.dev) on a schedule; severity-ranked per device with fixed-version hints; per-CVE ignore list; Ubuntu-derivative mapping |
| KEV / EPSS prioritization | Re-ranked by CISA KEV (known-exploited) + FIRST EPSS (exploit-probability) *(v4.0.0)* |
| Distro security flag | Counts vendor-flagged security updates (apt `-security`, dnf/yum `--security`, `arch-audit`) as a "N sec" badge *(v5.0.0)* |
| CVE ↔ patch cross-link | Per device, how many critical/high CVEs a pending patch fixes *(v3.4.1)* |
| Container image CVEs | Opt-in: the agent runs `trivy` against the images of running containers on a ~24h cadence (feature-invisible without trivy), ships a capped severity summary; the CVE page shows them grouped by image across the fleet. `GET /api/image-cves` *(v6.0.0)* |
| Windows / macOS patch execution | Detection existed; now execution too — Windows installs pending updates via PSWindowsUpdate (`Install-WindowsUpdate`), else the built-in Microsoft.Update COM API (never auto-reboots); macOS reports outdated Homebrew formulae to the Patches page and upgrades via `brew upgrade --formula` (casks left alone, never `--greedy`). Both ride the existing audited, maker-checker-gated `upgrade` command. `upgrade` / `upgrade:<name>` *(v6.0.0)* |
| CVE remediation campaigns | Group CVEs (by severity/KEV or explicit ids) into an owned, deadlined effort; server tracks the affected-host burn-down (daily sample) and fires `campaign_completed` at zero. `GET/POST /api/cve/campaigns` *(v6.0.0)* |
| OSV circuit breaker | Scanner backs off when the OSV feed is unhealthy *(v5.0.0)* |
| SBOM export | CycloneDX 1.5 + SPDX 2.3 per host/fleet, with purls + VEX vulnerabilities; deterministic *(v3.5.0)* |

## Security scanning & pentest *(v4.2.0)*

| Feature | Notes |
|---|---|
| Authorized vuln scanning | *Pentest* page — scan hosts/websites you own with industry tools, orchestrated/scheduled/collected |
| Authorization-gated targets | Enrolled hosts (target derived server-side) or domains you prove you own via DNS TXT / `.well-known`; private/loopback refused |
| Passive profile | nuclei, nikto, nmap |
| Active profile | OWASP ZAP, wapiti — gated behind an authorization attestation + (enrolled) a maintenance window; audited |
| On-host audit | lynis hardening audit via the agent (read-only) |
| Scanner satellites | Toolchain runs on a hardened relay node; pin a scan to a satellite. `install-server.sh`/`docker-compose.yml` install a co-located scanner by default *(v6.1.0)* — `--no-scanner` opts down to a separate dedicated machine |
| Scheduled scans | Cron cadence; recurring findings notify a channel; quick/full intensity + vhost |

## Host security & hardening

| Feature | Notes |
|---|---|
| Exposure (attack surface) | Listening sockets classified local/lan/world; `port_exposed_world`; Exposure page *(v3.11.0)* |
| Secrets-on-disk scanning | Opt-in agent scan (~6h, configurable paths) for keys/cloud-keys/tokens; masked findings + dedup fingerprint on the Exposure page; `secret_exposed`; off by default *(v4.0.0)* |
| Canary files (honeytokens) | Agent plants decoy files (fake credentials) at configured paths — never over an existing file — and watches them; any read/change/deletion raises a critical `canary_accessed` alert; removed on agent uninstall *(v6.0.0)* |
| Firewall + fail2ban | Fleet page to view + edit host firewalls (nftables/iptables/ufw/firewalld) and fail2ban jails/bans; edits via the audited command queue, server-validated *(v4.10.0)* |
| Host firewall drift | Stable ruleset fingerprint → `firewall_changed` *(v3.11.0)* |
| Host configuration | Declare desired state per device — repos, netplan, nmcli, resolv.conf, /etc/hosts, enabled services, users + SSH keys, groups, sudoers, MOTD; agent applies on heartbeat (~60s), reports current state every 15 min; audit-only, never auto-remediates *(v2.6.0)* |
| Configuration drift | Hash a watch-list of config files (sshd_config/sudoers/…), diff vs baseline; `config_drift` edge-triggered *(v2.2.0)*; named reusable profiles *(v3.13.0)*; **near-real-time** — a cheap per-poll mtime scan forces an immediate re-hash on change, so drift surfaces within ~one heartbeat instead of the hourly cadence *(v6.0.0)* |
| Desired-state enforcement | Correct-on-drift mode *(v3.7.0)* |
| Host-config collect & export | Drift page: collect all host configs fleet-wide + export one JSON bundle of desired/current/drift *(v3.13.0)* |
| SSH-key audit | Fleet-wide authorized_keys audit — fingerprints, weak-type flags, reuse counts *(v4.0.0)* |
| Endpoint AV posture | ClamAV / rkhunter status + on-demand scan; last-scan time *(v3.6.0)*; `av_infected` on rising infection *(v5.1.0)*; `av_warning` on rising rkhunter-warning / stale-DB count *(v5.5.0)* |
| OpenSCAP scans | `oscap xccdf eval` — CIS/STIG/PCI-DSS, USG, ANSSI; score + failing rules; HTML report; by host/tag/group *(v3.4.2)* |
| CIS-style compliance baseline | Pass/fail checks, severity-weighted score + daily trend *(v3.4.2)* |
| Guided CIS remediation | One-click fix for a failed baseline check (pending updates / reboot / clear failed units / patch CVEs) queued through the audited command channel — per-host opt-in (`remediation_enabled`), quarantine + audit-mode enforced, and **maker-checker required** when change-approval is on. `POST /api/compliance/remediate` *(v3.14.0; 4-eyes-required v5.8.0)* |
| Compliance frameworks | PCI DSS / HIPAA / SOC 2 controls mapped to collected data with evidence + remediation *(v3.4.0)* |
| Access watch | First-seen login source → `login_new_source`; brute force → `brute_force_detected` *(v3.11.0)* |
| GeoIP enrichment | Point RemotePower at an operator-supplied offline GeoLite2 Country/ASN `.mmdb` file (pure-python reader, no external dependency, no egress) — login sources get country/ASN; optional impossible-travel detection fires `login_geo_anomaly` when one account logs in from two countries within a window. Degrades to no-op with no DB configured. *(v6.0.0)* |
| Sudo audit trail | Agent tails sudo invocations (journal / `auth.log`) → a per-device privileged-command log (who/tty/pwd/command, secrets redacted); drawer table + fleet search `GET /api/sudo-search`; admin/auditor-only *(v6.0.0)* |
| Lifecycle expiry | Warranty / license / support end dates per asset → attention items *(v3.5.0)* |
| Warranty auto-lookup | Opt-in: a cadence job maps each device's inventoried serial → a vendor warranty API (**Lenovo** via ClientID; Dell behind TechDirect creds) → auto-fills the CMDB warranty-expiry field — only when it's empty or was previously auto-filled (never clobbers an operator-set date). Cached ~30 days/serial; credential write-only; no-op without a key. *(v6.0.0)* |
| Container restart tracking | Real restart count/age via batched `docker inspect`, fleet-wide *(v3.10.0)* |

## Containers & virtualization

| Feature | Notes |
|---|---|
| Container detail | Per-device list — health badge, live CPU%/mem, published ports, stale pill *(v3.4.2)* |
| Container alerts | `container_stopped`, `container_restarting`, `containers_stale` *(v1.11.4)* |
| Image updates | Pulled-digest vs registry digest → stale flag on Image Updates page; one-click compose pull + up -d *(v3.3.4 / v3.9.0)*; **standalone-container Update** (pull image + recreate with the same config; compose-managed refused) *(v6.0.0)* |
| Patch rings | An auto-patch policy can patch in **staged rings** (canary → wave → rest) — spawns a health-gated rollout that verifies each ring before the next and auto-halts on a health drop; optional per-ring reboot *(v6.0.0)* |
| Proxmox VE | Connect one node (scoped API token); QEMU VM + LXC start/shutdown, server-to-API *(v2.3.0)* |
| Proxmox snapshots | Create/list/roll-back/delete per guest; type-to-confirm rollback *(v2.4.0)* |
| Proxmox create / delete | LXC create wizard + delete *(v3.5.0)*; QEMU VM create wizard *(v3.7.0)* |
| Proxmox backup recency | Per-guest vzdump staleness check *(v3.6.0)* |
| VMware / OpenShift lifecycle | vSphere/vCenter, Cloud Director and OpenShift Virtualization (KubeVirt) get Proxmox-level control on the Virtualization page — list guests, power on/off/reboot/suspend, and create/revert/delete snapshots; configured under Settings → Virtualization, driven through the SSRF-guarded integrations client. `GET /api/virt/{id}/vms`, `POST /api/virt/{id}/power`, `GET|POST /api/virt/{id}/snapshot(s)` *(v5.6.0)* |
| Helm release status | Surfaces release status where Helm + kubeconfig present (visibility only) *(v3.4.0)* |

## Networking, DNS & email posture

| Feature | Notes |
|---|---|
| DNS dashboard | **Admin → DNS** read/write A/AAAA/CNAME/TXT/MX/NS/SRV/CAA via provider API (Cloudflare/DigitalOcean/Hetzner/deSEC/Porkbun); reuses ACME tokens / vault / agent import; admin-only, audited, SSRF-guarded *(v4.9.0)* |
| Live resolve / dig + propagation | Authoritative-NS vs public-resolver answers; per-record propagation check *(v4.9.0)* |
| Central ACME DNS-01 creds | Server-stored provider tokens injected into `acme.sh --issue`; redacted in audit/UI *(v3.3.0)* |
| RouterOS integration | MikroTik via REST (SSRF-guarded) — DHCP lease table, firewall filter/NAT counts, routes, interfaces, wireless clients; read-only *(v4.7.0)* |
| OPNsense integration | View / add / enable-disable / delete filter + outbound-NAT rules over the OPNsense REST API from an agentless device's drawer; API secret write-only; full guide [opnsense.md](opnsense.md) *(v3.4.0)* |
| IP reputation (DNSBL) | Mail-sending IPs vs Spamhaus/SpamCop/Barracuda/SORBS/UCEPROTECT/PSBL; `ip_blacklisted`/`ip_blacklist_cleared`; partial state on unreachable *(v4.8.0)* |
| DMARC / SPF / DKIM | Published-record grading + aggregate (RUA) report ingestion over IMAP; per-source pass/fail tallies + mailbox health *(v4.8.0)* |

## Storage & hardware

| Feature | Notes |
|---|---|
| SMART / inventory | smartctl health + pre-fail attributes → `smart_failure`; DIMMs, serials, temperatures, RAID state *(v3.4.0)* |
| Storage / RAID page | ZFS/mdadm/btrfs pool state, capacity, last-scrub; `storage_degraded`/`storage_recovered`, `scrub_overdue` *(v3.11.0)* |
| One-click maintenance | Per-pool scrub/trim/error-clear/balance/status/snapshot from a fixed server-side template; audited *(v5.0.0)* |
| GPU monitoring | **Monitoring → GPUs** NVIDIA + AMD — util/VRAM/temp/power/fan, trend sparklines, fleet summary; amdgpu sysfs fallback; thermal alerting reuses temp_high *(v4.7.0)* |
| Thermal | Hottest hosts, per-sensor expand, ~24h trend sparkline, per-host warning/critical thresholds *(v4.0.0)* |
| Power / UPS | NUT (`upsc`) / apcupsd (`apcaccess`) — status, battery %, load %, runtime, input V, watts; Power page + energy cost; `ups_on_battery`/`ups_on_line` *(v4.0.0)* |
| Disk endurance + predictive health | SSD/NVMe endurance + predictive disk health *(v4.0.0)* |
| Certificate-file + account audit | Local certificate-file inventory + local-account audit; an expiring local service cert raises a coalesced one-per-host `cert_file_expiring` alert by default *(v4.0.0, alert on by default v6.0.1)* |
| Read-only remount alert | A local filesystem the kernel flips read-only (a silent I/O-error / data-loss outage) raises a coalesced `readonly_fs` alert + webhook; `readonly_fs_cleared` on recovery *(v6.0.1)* |
| Mail-queue backlog alert | A host mail queue (postfix / exim / sendmail) crossing its per-host `mailq_warn_count` / `mailq_crit_count` raises `mailq_high`; `mailq_normal` on drain *(v6.0.1)* |

## Backups & disaster recovery

| Feature | Notes |
|---|---|
| Per-device backups | Watched-path age + fresh/stale state in the drawer *(v3.4.2)* |
| Backup orchestration | Define a backup command per device (restic/borg/rsync); on-demand or cron *(v3.6.0)* |
| Backup integrity verification | Agent runs the tool's own check (`tar -tf` / `restic check` / `borg check`); `backup_verify_failed` *(v4.10.0)* |
| Scheduled restore drills | Opt-in per backup monitor: the agent actually restores a configured sample path from the latest archive (`restic`/`borg`/`tar`) into a throwaway sandbox (never over live paths), verifies it's non-empty + hashes it, then deletes it. Rate-gated + time-bounded; a failure fires `restore_drill_failed` (`restore_drill_ok` on recovery). Result shown in the device drawer *(v6.0.0)* |
| Backup size trending | Agent reports each watched backup's size; server keeps a rolling history and fires `backup_size_anomaly` when a fresh backup drops below a configurable % of its trailing median — catches a truncated/half-written backup that's still recent *(v6.0.0)* |
| Controller backup & restore | Full DR tar.gz of the data dir (incl. encrypted vault) + restore with pre-restore safety snapshot *(v3.13.0)* |
| Encrypted DR backups | AES-256-GCM at rest, key from `RP_BACKUP_PASSPHRASE` (never on disk); web-UI "Encrypt existing backups" *(v5.0.0)* |
| Encrypted config secrets | Opt-in `RP_CONFIG_KEY` → AES-256-GCM at rest for every secret-bearing config value at any depth (SMTP/OIDC/LDAP/SIEM, ACME DNS credentials, webhook tokens/URL, AI api_key, integration secrets) *(v5.6.x: full-tree coverage)*; transparent at load/save, fail-graceful *(v5.5.0)* |
| External key sourcing | `RP_CONFIG_KEY` / `RP_BACKUP_PASSPHRASE` can be fetched from an external command (`<NAME>_CMD`, e.g. Vault/KMS/`pass`) instead of the process environment; cached per worker *(v5.5.0)* |
| WORM audit sink | `audit_worm_path` appends every hash-chained audit entry to an operator-immutable file (`chattr +a` / WORM mount) — tamper-resistant copy *(v5.5.0)* |
| Off-host backups + restore-verify | Mirror the DR backup to an off-host destination (`backup.offsite_dir`, an NFS/SMB/sshfs mount); **Test restore** decrypts + decompresses + structure-checks the latest archive *(v5.5.0)*. Optional declared RPO/RTO targets (`backup.rpo_hours`/`rto_hours`), graded on `GET /api/self/status` |
| Backup export | One-click redacted ZIP of all data JSON |
| Config as code | One versioned, secret-redacted JSON document of all operator-authored config (monitors, checks, rules, integrations, webhooks, windows, targets, …) — git-safe, for review / diffing / off-box backup; `GET/POST /api/config/declarative` (import is dry-run-first, secret-rehydrating) *(v6.0.0)* |

## CMDB, credentials & documentation

| Feature | Notes |
|---|---|
| Asset metadata | Asset ID, server function, hypervisor URL, SSH port |
| Network interfaces + NAT | Multiple NICs each with optional NAT/public IP, one primary (★), live preview tree *(v5.0.0)* |
| Multi-doc attachments | Multiple titled Markdown documents per asset (≤64 KB) *(v2.0)* |
| Credentials vault | AES-GCM 256 + PBKDF2-SHA256, shared admin passphrase, audit-logged reveals; key never persisted |
| Site/group/tag-scoped credentials | Shared login at a scope, inherited by member devices; same vault; admin-only, audited *(v4.10.0)* |
| Break-glass reveals | Two-person rule for sensitive secrets; `vault_break_glass` *(v5.0.0)* |
| Credential rotation reminders | Vault entries flagged for rotation *(v3.7.0)* |
| Agentless devices | Switches/APs/printers/IPMI/cameras — same CMDB/vault/SSH-link *(v1.11.0)* |
| Cloud inventory import | Pull running instances into the fleet as agentless devices (`POST /api/cloud/import`); **AWS EC2** (stdlib SigV4, no SDK), plus **Hetzner Cloud** and **DigitalOcean** (read API token) *(providers v5.8.0)*; read-only, credentials write-only. Optional scheduled auto re-sync marks vanished instances decommissioned (never deleted) *(v6.0.0)* |
| In-app docs | Curated documentation page with substring search *(v2.0)* |
| Knowledge base | Operator-authored markdown articles (SOPs / how-tos / runbooks) in a category folder tree; searchable; opt-in `kb_enabled`; fed to the AI as a RAG source. `GET/POST /api/kb`, `…/{id}` *(v5.6.0)* |
| Runbook links on alerts | Map an alert type (or a custom check) to a KB article (`alert_runbooks`) → a one-click **Runbook** link on the matching alert in the inbox; resolved at read time so it always shows the current article *(v6.0.0)* |

## Authentication & access

| Feature | Notes |
|---|---|
| bcrypt + PBKDF2 | Password hashing with transparent upgrade on login; legacy unsalted hashes rejected |
| TOTP 2FA | Per-user QR setup; recovery codes *(v3.7.0)* |
| Passkeys / WebAuthn | Phishing-resistant passwordless sign-in; refuses cloned authenticator; satisfies MFA policy *(v4.2.0)* |
| OIDC SSO | External IdP; group→role mapping; first-login provisioning |
| SAML 2.0 SSO | Okta/Entra/OneLogin/Ping/ADFS; signed assertions + replay protection; attribute→role *(v4.2.0)* |
| LDAP / AD + SCIM 2.0 | Bind-mode auth; IdP-driven create/deactivate so offboarding revokes access + sessions; **SCIM Groups** map to roles (IdP group membership → role) + discovery endpoints (ServiceProviderConfig / ResourceTypes / Schemas) *(v6.0.0)* |
| MFA enforcement | Require MFA (TOTP or passkey) per role; forced before any other action *(v4.2.0)* |
| Password policy | Opt-in min length + 3-of-4 character classes + HaveIBeenPwned breach check (k-anonymity, fails open); enforced on new users + changes *(v5.5.0)* |
| SSO-only | Refuse local-password logins when an IdP is configured; per-account `local_login` break-glass *(v5.5.0)* |
| SSO group→role matrix | `sso_group_roles` maps an OIDC/SAML group to any builtin/custom role (not just admin-or-viewer); admin wins, legacy admin-group still works, viewer promoted on login, never auto-demotes *(v5.5.0)* |
| Roles | Admin, Viewer, Auditor (read-only + audit/compliance, reveals nothing) *(v4.10.0)*, plus custom scoped roles *(v3.4.2)* |
| Granular RBAC | Custom roles granting exec/reboot/upgrade scoped to groups/tags; roster filtered to scope *(v3.4.2)* |
| API keys | Named keys (`X-Token`); default expiry window *(v4.2.0)*; per-key rate limits *(v5.0.0)*; editable, secret immutable *(v5.0.1)*; **hashed at rest** (SHA-256, shown once) *(v5.5.0)*; optional **per-key device scope** (scoped service account — confines visibility+actions to groups/tags/sites, binds even an admin key) + **source-IP allowlist** (`ip_allow` CIDRs — key rejected from any other IP) *(v5.5.0)* |
| Device tokens hashed | Agent auth tokens stored as SHA-256 `token_hash` (not plaintext); agent unchanged; legacy tokens migrate on next heartbeat *(v5.5.0)* |
| Enrolment tokens | One-time tokens for Ansible/cloud-init/golden images; default group+tags at enrolment *(v1.11.10)*; **hashed at rest** (keyed by SHA-256, display prefix kept) *(v5.5.0)* |
| Enrolment auto-placement | Rules (Settings → Sites & teams) stamp group / site / tags on a **new** device by hostname regex or source-IP CIDR — first match wins, token defaults still win over a rule; never touches already-enrolled devices *(v6.0.0)* |
| PIN enrolment | 6-digit, single-use, 10-min expiry |
| Session caps | Limit concurrent sessions per user; oldest evicted *(v4.2.0)* |
| Idle session timeout | Opt-in sliding-window expiry — a session unused for N minutes dies before its absolute TTL *(v5.5.0)* |
| Active session management | Review/revoke live sessions *(v4.0.0)* |
| Config-change audit | Every Settings save logs a `config_changed` entry (changed key names; values never logged) *(v5.5.0)* |
| Rate limiting | Per-IP login throttle + per-username lockout; enroll/register throttle |
| IP allowlist | Per-IP/CIDR allowlist; loopback always allowed; agent paths exempt; can't lock yourself out *(v3.3.0)* |
| Login banner | Optional security notice above the sign-in form *(v5.0.0)* |
| Read-only demo mode | Rejects all mutations for public sandboxes; `install-demo.sh` runs it on its own dedicated gunicorn process, with an optional separate PostgreSQL database via `--postgres` matching the main install's backend *(v2.0; own process + `--postgres` since v6.1.0)* |

## Audit & governance

| Feature | Notes |
|---|---|
| Audit log | Every admin action with actor, IP, timestamp |
| Tamper-evident audit log | Hash-chained entries; *Verify integrity*; clear requires re-prompt + immutable pre-wipe archive *(v4.2.0)* |
| Archived audit download | Gzipped archive of evicted entries *(v4.3.0)* |
| Security-posture self-check | Graded hardening checklist, each warning links to its fix *(v4.2.0)* |
| Maintenance mode | Runtime switch pauses command dispatch during upgrades without taking the dashboard offline *(v5.0.0)* |
| Disk-space watchdog | Server monitors its own free space → `server_disk_low`/`server_disk_ok` *(v5.0.0)* |
| Webhook dead-letter queue | Exhausted deliveries land in a DLQ you can inspect + replay *(v5.0.0)* |

## Staged rollouts & posture reporting

| Feature | Notes |
|---|---|
| Staged / ring rollouts | Canary → pilot → broad upgrade/script push, verified per ring, auto/manual promote *(v3.4.2)* |
| Health-gated rollouts | Auto-halt + `rollout_halted` if a host's health drops during verify; pauses, never auto-rolls-back *(v4.10.0)* |
| Rollout rollback | One-click rollback for a staged script rollout *(v5.0.0)* |
| Rolling reboot orchestrator | Reboot a scope in dependency-ordered waves (leaves first, upstreams last, from each device's `depends_on`; cycle-safe), health-gated + verified per wave via the rollout engine. `POST /api/rollouts/reboot-plan` + `action: reboot` *(v6.0.0)* |
| Fleet posture reports | One report binding patches/CVEs/health/compliance; JSON/CSV or scheduled email *(v3.4.1)* |
| Custom report builder | Pick sections (devices/health/attention/patches/CVE/SLA/compliance), JSON/CSV, download or schedule *(v4.0.0)* |
| Per-site (customer) reports | Same report scoped to one site; RBAC-scoped *(v4.10.0)* |
| SLA / uptime reporting | Per-device + per-group uptime % over 7/30/90d *(v3.4.1)* |
| Print / Save as PDF | Self-contained posture report for native print/PDF *(v3.4.2)* |
| Public status page | Standalone `status.html` (no login) via status token *(v3.4.1)*; **operator-posted incidents** (title / impact / status with a running update log, above the component list) + optional subscriber emails on open/resolve. `GET/POST /api/incidents` *(v6.0.0)* |
| Status endpoint | `/api/status` machine-readable fleet summary (status token) *(v2.4.7)* |
| iCal feed | `/api/schedule.ics` — scheduled jobs + maintenance windows, recurring as RRULEs *(v3.4.1)* |

## WG Access (WireGuard VPN) *(v5.2.0)*

| Feature | Notes |
|---|---|
| Built-in road-warrior VPN | **Admin → WG Access** — userspace wireguard-go on the server host; no kernel module |
| Tunnel | Reach scope (dashboard-only / fleet / site / group / tag, RBAC-enforced via nftables), allow-internet toggle, optional pushed DNS, optional expiry; disabled = torn down |
| Client | Browser-generated keypair (private key never sent), `.conf` + QR once; live endpoint / last-handshake / transfer; tunnel pool + throughput rollups |
| Events + AI | `vpn_client_connected` / `vpn_client_disconnected` / `vpn_handshake_stale`; feeds RAG + a Remote-access-review AI advisor |

## Time-tracking & billing *(v5.4.0)*

| Feature | Notes |
|---|---|
| Unified time ledger | One entry per logged block: hours (0.25 steps), date, billable flag, customer (site) / device / ticket link, note or internal category. `GET/POST /api/time-entries` |
| Hours on tickets | **Log hours** on any ticket; billable hours attach to the ticket's customer (site, derived from device); running total on the ticket. `…/tickets/{id}/hours` |
| Weekly timesheet | Personal **Timesheet** page (Planning, + linked from My Account) — week navigator, per-day/weekly totals, ad-hoc internal time; ticket hours roll in. `GET /api/timesheet?week=` |
| Billing page (opt-in) | The Billing surface (worksheet / invoices / rates & fees) is gated under Advanced → `billing_enabled` (default off); logging hours + the Timesheet stay on regardless *(v5.5.0)* |
| Billing worksheet | Per-customer per-month: billable hours × rate + recurring fees → subtotal / VAT / total. `GET /api/billing/worksheet` |
| Invoices | draft → sent → paid (+ void); issuing **locks** the billed hours (frozen amounts), voiding frees them to re-bill. `GET/POST /api/invoices`, `PATCH /api/invoices/{id}` |
| Invoice email + reminders | Email an invoice to the customer's billing contact over existing SMTP (branded HTML + plain text; draft→sent); opt-in overdue-reminder sweep sends one reminder after N days unpaid. `POST /api/invoices/{id}/send` *(v6.0.0)* |
| Rates & fees | Named rate card + global default rate / currency / VAT / invoice prefix; per-customer rate / VAT / billing address / recurring license-operation-service fees. `GET/POST /api/billing/config` |
| Finance role | Read-only role that views/exports billing without admin; issuing/voiding + rate edits stay admin-only; everyone logs their own hours |
| Export | CSV (`?format=csv`) on ledger / worksheet / invoice, JSON API on every list, browser-print PDF for invoices |
| Timesheet watchers | Let specific non-finance users view another user's timesheet (read-only, hours only, never rates) by user or whole team; "Watch for" omnisearch on the Timesheet page. `GET/POST /api/timesheet/watchers`, `GET /api/timesheet/watchable` *(v5.6.0)* |

## AI assistant & RAG *(v2.1.3)*

| Feature | Notes |
|---|---|
| LLM integration | Optional — Ollama, LocalAI, Anthropic, OpenAI, DeepSeek, plus local **opencode** (REST session server) &amp; **openclaw** (WebSocket-RPC gateway) *(v6.0.0)*; pure stdlib HTTP/WS; disabled by default; full reference [ai.md](ai.md) |
| Context-aware actions | Investigate device, explain output, find the problem (journal), diagnose service, triage CVE/TLS, prioritise patches, explain/generate/audit scripts, explain events |
| AI Investigate / mitigate | Diagnose + suggested-fix on ~21 Needs-Attention kinds; requires `exec` *(v3.4.2 / v3.8.0)* |
| On-demand AI insights | Fleet anomaly scan, cron builder, runbook + CMDB doc drafts (RAG-aware) *(v3.4.0)* |
| AI Insights hub | One-click reports/advisors — proactive briefing, RCA, NL→config, planning, advisors (firewall/DNS/email/SBOM/host one-pager) *(v4.10.0)*; TLS/CVE/top-alert *(v5.0.1)*; remote-access *(v5.2.0)*; helpdesk triage *(v5.3.0)*; **automation-rule suggestions**, plus **virtualization-hygiene, IaC/provisioning review, drift triage, access &amp; credential review, network-dependency review and billing review** advisors *(v5.6.0)* |
| Inline AI buttons | Context "AI review" buttons on the Virtualization, Provisioning, Drift, Network-map, CVE, Backups, Users and Billing pages that launch the matching advisor in place *(v5.6.0)* |
| Secret redaction | Regex pre-flight strips tokens/keys/hex; privacy toggles for hostnames/IPs/journal |
| Rate limiting | Per-user daily cap + per-response token cap |
| Free-form chat | Multi-turn chat page with model picker + local history |
| Local-model support | Ollama/LocalAI — no egress, no API key; shows loaded models + VRAM |
| RAG over your fleet | Cited `<retrieved_context>` from device state, services, CVEs, containers, firewall/fail2ban, integrations, backups, DNS/email, security posture, CMDB, runbooks, commands, alerts, tickets, knowledge base, **provisioning blueprints, rollouts and network topology** *(v5.6.0)*, product docs; BM25 lexical + optional semantic (RRF); vault never indexed *(v3.4.0)* |

## MCP server *(v2.2.1)*

| Feature | Notes |
|---|---|
| MCP server | 18 tools — 14 read (`list_devices`, `get_device`, `search_devices`, `search_fleet`, `get_journal`, `get_services`, `get_containers`, `get_cves`, `get_drift`, `get_recent_commands`, `get_runbook`, `get_patches`, `get_tls`, `get_snmp_data`) |
| Guarded write tools | `reboot_device`, `run_saved_script`, `force_package_scan`, `force_acme_rescan` — per-token allow-list + roles; arbitrary `run_command` intentionally absent |

## Homelab software integrations *(v4.7.0)*

| Feature | Notes |
|---|---|
| Integration subsystem | Read-only server-side polling, folded into Alerts + dashboard; `integration_down` (auto-resolved); SSRF-guarded; admin-only URLs; **Show Homelab software** kill switch |
| 40 connectors (+ Custom HTTP) | Pi-hole v6, AdGuard Home, TrueNAS, Unraid, Kubernetes/k3s, **VMware vSphere/ESXi/vCenter**, **Red Hat OpenShift** *(v5.6.0)*, **VMware Cloud Director** *(v5.6.0)*, Proxmox Backup Server, UniFi, Traefik, Nginx Proxy Manager, Caddy, Netdata, Grafana, Uptime Kuma, Jellyfin, Plex, Home Assistant, Nextcloud, GitHub Issues, Immich, Paperless-ngx, Vaultwarden, Gitea/Forgejo, Syncthing, Frigate, OctoPrint, ESPHome, Homebridge, RemotePower (peer instance) *(all v5.8.0)*, qBittorrent, Transmission, Deluge, SABnzbd, NZBGet, Servarr (Sonarr/Radarr/Prowlarr/Lidarr), Bazarr, Overseerr/Jellyseerr |
| Custom HTTP probe plugin | Declarative — turn an endpoint's status/body/JSON field into a health signal; SSRF-guarded *(v5.1.0)* |
| Connector plugins | Drop a `*.py` in `connectors.d/` to add your own integration connector via the same `@_register` decorator — root-owned, filesystem-only, load-fail-safe; full guide in [writing-a-connector.md](writing-a-connector.md) *(v6.0.0)* |
| GitHub issue monitor | Watch repos (`owner/repo`, multiple per instance) for newly opened issues → `github_new_issue` alert in the Alerts inbox (PRs ignored, first poll baselines; webhook/paging off by default) *(v6.0.0)* |

## Agents

| Feature | Notes |
|---|---|
| Platforms | Linux, Windows, macOS *(v4.0.0)*; macOS loadavg + fd% + Windows NVIDIA GPU parity *(v4.8.0)* |
| Self-update | SHA-256-verified, atomic replace, no SSH; hash-driven decision *(v3.3.0)* |
| Signed updates | Detached GPG signature; pinned-key agents refuse unsigned/invalid; opt-in fail-closed `require-signed-updates`; Admin → Release Signing server-side key gen/sign + distribution + refused-agent list *(v3.4.2 / v3.8.0)* |
| App-self SBOM + SLSA | `make sbom-self` → CycloneDX of the control plane's own Python deps; release images carry SLSA build provenance *(v5.5.0)* |
| Integrity attestation | Reports running-binary hash each heartbeat; mismatch flagged; `integrity` subcommand; signed-agent badge *(v3.4.2)* |
| mTLS agent authentication | Agents present a CA-verified client certificate per connection, pinned per device; optional/additive, fleet-wide enforceable *(v5.0.0)* |
| Version-compatibility checks | Server flags agents whose version is too far out of step before they cause surprises *(v5.0.0)* |
| Containerized agent | Run as a container monitoring its Docker host; shared PID/net ns, host rootfs read-only; multi-arch `ghcr.io/tyxak/remotepower-agent` *(v4.7.0)* |
| Re-enrolment | Preserves history, tags, group, notes |
| Store-and-forward | Agent spools metric samples locally when the server is unreachable (bounded ring) and backfills the gap into the sparklines on reconnect; backfilled history never triggers retro-alerts *(v6.0.0)* |
| Adjustable poll interval | Per-device cadence (10–3600s), applied on next heartbeat |
| Mailbox monitor | Counts files in configured directories (Maildir unread); `mailbox_threshold` *(v2.4.3)* |
| SNMP polling | Periodic SNMP read — sysDescr/uptime/contact/processors/storage + vendor (Mikrotik/Synology); `snmp_unreachable`/`snmp_recover`; **SNMPv2c or SNMPv3/USM** (noAuth/auth/authPriv — MD5/SHA-1/SHA-2 auth, AES-128 privacy) *(v3: v5.8.0)* |

## Platform, scale & storage backend

| Feature | Notes |
|---|---|
| Architecture | nginx + gunicorn/Flask (the only app server) + stdlib Python; one HTML + CSS + vanilla-JS modules; no build step *(v6.1.0)* |
| SQLite backend | Optional, WAL, stdlib; row-per-entity hot data; reversible migration *(v3.12.0)* |
| PostgreSQL backend | Default single-node backend via `install-server.sh`/`docker-compose.yml`; automatic failover + read replicas *(v4.0.0; default since v6.1.0)* |
| Persistent app server | gunicorn/Flask (`remotepower-wsgi.service`) — pre-warmed threaded workers with thread-local request isolation, the only server; installed and enabled by default *(v5.5.0; only server since v6.1.0)* |
| Out-of-band scheduler | Default dedicated maintenance process (`remotepower-scheduler.service`, `RP_EXTERNAL_SCHEDULER=1`) — leader-elected (host file-lock + Postgres `pg_advisory_lock`) so one node runs the cadence; runs sweeps without request traffic and cuts per-request latency *(v5.5.0; default since v6.1.0)* |
| Serving & runtime panel | Server-status page shows what's ACTUALLY serving — storage backend (JSON/SQLite/PostgreSQL), request tier (`WSGI · gunicorn`) and out-of-band scheduler state (running + heartbeat age, configured-but-dead, or off) with a per-request-cadence indicator; verify tiers at a glance, links to `scaling.md` *(v5.6.x)* |
| Hard multi-tenancy | Optional tenant entity + `tenancy_enforced` (Settings → Security) — tenant admins confined to their own devices; a default-tenant admin is the cross-tenant superadmin *(v5.5.0)* |
| Postgres row-level security | Optional DB-enforced tenant isolation (`tenancy_rls`) on the devices table — `FORCE` RLS + per-request `app.rp_tenant` GUC, fail-closed; defense-in-depth beneath the app-layer tenancy; schema applied live *(v5.5.0)* |
| Relay satellites | For segmented networks; agent→satellite over HTTPS; internal-CA trust *(v4.0.0)* |
| Load-balanced multi-node | Horizontal scale *(v4.0.0)* |
| Self-signed CA onboarding | `make tls-selfsigned` CA + leaf; agents trust the CA (client-free renew/migration); `--ca-fingerprint` installers *(v4.5.0)* |
| Hardened persistence | flock-serialised writes, per-process tmp, fsync, rolling `.bak` fallback + recovery *(v1.12.1)* |
| GitOps | Config-from-Git *(v4.0.0)*; Terraform via REST; Ansible runner |
| Swagger / OpenAPI | OpenAPI 3.1 at `/api/openapi.json`, interactive UI at `/swagger.html` with auto-injected token; **route-table-driven so every endpoint is covered** (~290 paths), advertises the `/api/v1` base *(v5.5.0)* |
| API versioning | Every route is also reachable under `/api/v1/...` (permanent alias of the unversioned path) *(v5.5.0)* |
| Postman collection | `make postman` → a Postman v2.1 collection from the OpenAPI spec (foldered by tag, auth + baseUrl pre-wired) *(v5.5.0)* |
| Correlation IDs | `X-Request-Id` on every JSON response (honours an inbound proxy id); `RP_LOG_LEVEL`-gated `log_json` + slow-handler ring carry it *(v5.5.0)* |
| Distributed trace-context | Inbound W3C `traceparent` is honoured → carried in structured logs (`trace_id`) and propagated as a child span on outbound webhooks *(v5.5.0)* |
| Frontend error beacon | Uncaught client errors POST to `/api/client-error` (throttled, scrubbed, capped); admin-visible *(v5.5.0)* |
| List API convention | Optional `?q` filter, `?sort`/`?order`, `?limit`/`?offset`, `?meta=1` envelope on list endpoints; bare list unchanged when omitted *(v5.5.0)* |
| Signed exports | Evidence pack carries an HMAC-SHA256 `signature`; audit-archive download emits `X-RP-Signature` (per-install `export_sign.key`) *(v5.5.0)* |
| Export-key rotation | Admin can rotate the export-signing key (Settings → Security); posture page grades password-policy / idle-timeout / SSO-only / signed-exports *(v5.5.0)* |
| Turnkey install | Unified `install.sh` wizard; one-command Docker (HTTPS, no default password); served `/install` quick-install agent; `install.sh agent push` SSH bootstrap; `install.sh uninstall` *(v4.8.0)* |
| Install update | **Settings → Install** version check + guided self-update via a server-side update script *(v5.0.0)* |
| Setup checklist | Settings → Install live getting-started checklist *(v3.4.2)* |
| Guided tour | First-run coach-mark walkthrough (Dashboard/Devices/Alerts/Search/Settings); once per account, re-runnable via "Take a tour" *(v5.5.0)* |

## UX, interface & accessibility

| Feature | Notes |
|---|---|
| ClarityMatters interface | Flat, calm v6 UI — `--surface` panels with hairline borders, system font stack, accent-soft active states; a 12-domain sidebar accordion and a left-nav Settings *(v6.0.0)* |
| Themes | 13 palettes + Follow system + accent presets, persisted per browser |
| Composable dashboard | Resizable widget grid, 67-widget catalog, size/reorder/show-hide/reset, import/export layout *(v4.1.0)* |
| Command palette | `/` or `Ctrl/Cmd-K` fuzzy launcher — pages, devices, open alerts, vulnerable hosts, scripts, bulk actions, command history *(v3.0.2)* |
| Filter & sort everywhere | Substring filter + multi-key clickable headers; sort persists |
| Density modes | Minimal / Compact / Comfortable / Spacious, synced per user |
| Multi-select | Batch actions on cards or minimal table; selection survives density switch *(v1.12.1)* |
| Post-it widget | A per-account freeform sticky note on the dashboard (composable widget, persists in `ui_prefs`) |
| Scoped notes | Free-text notes at device (tooltip), **site** (on the site record) and **fleet-wide** (shown as a dashboard card) scope |
| Contacts directory | Internal team phonebook (name/role/company/email/phone/notes) — searchable, sortable, admin-maintained; separate from the ticket system; a contact can be given a **site** + **portal access** for the customer portal *(v6.0.0)* |
| Customer portal | Opt-in (`portal_enabled`, default off): a separate `/portal` page where a site's contacts sign in by **magic link** (no password, no operator account, HttpOnly session cookie scoped to `/api/portal`) to view & submit tickets for **their own site only**. Closed `/api/portal/*` allowlist; every handler resolves the cookie → contact → site and filters server-side; operator/portal tokens never interchange; per-IP+email rate limits; internal notes never cross to the portal; separate CSP report bucket. `POST /api/portal/magic-link`, `/session`, `GET/POST /api/portal/tickets` *(v6.0.0)* |
| Saved Devices views | Save + share named fleet filter views via URL *(v4.0.0)* |
| Edit everywhere | Edit on every operator-managed list — alert rules, monitors, TLS/backup targets, snippets, scheduled jobs, inbound tokens, users, ignore patterns *(v3.3.0)* |
| Did-you-know tips | About page surfaces lesser-known features |
| Collapsible sidebar | Main / Security / Planning / Admin / Help groups, alphabetised; state persists |
| My Account | Account menu + page — avatar, role/permissions, 2FA, default SSH user, acknowledged alerts *(v3.12.0)* |
| Box-overflow caps | Every variable panel caps ~15 rows and scrolls internally *(v3.13.0)* |
| Branding | Favicon + header logo, full-size logo on login *(v2.0)* |
| Interface language | 7 languages (en/zh/hi/es/ar/de/fr); German + French added *(v6.0.0)*; Arabic right-to-left layout *(v4.0.0 / v5.1.0)* |
| Accessibility | Modal accessible names, styled accessible confirm/prompt *(v4.8.0)*; `scope="col"` headers, icon-button `aria-label` *(v5.0.0)*; **every form control has an accessible name** (label / wrapping label / `aria-label`), ratchet-tested *(v6.0.0)* |
| Mobile UX | ≤720/≤480px touch targets, full-viewport modals, scrollable tables |

---

← [Back to docs index](README.md) · [Back to main README](../README.md)
