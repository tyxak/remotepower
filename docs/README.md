# RemotePower documentation

The main `README.md` at the repo root is the place to start. This folder
holds long-form docs that don't fit there.

## Getting started

- **[install.md](install.md)** — Server install (Linux + Docker), client
 enrolment, optional webterm, demo vhost.
- **[admin-guide.md](admin-guide.md)** — Full install & operations guide:
 hardening, daily ops, backup/restore, upgrades, troubleshooting.
- **[features.md](features.md)** — Full feature inventory and the
 per-feature guide.
- **[writing-a-connector.md](writing-a-connector.md)** — Write your own
 integration connector plugin (drop-in `connectors.d/*.py`).
- **[cookbook.md](cookbook.md)** — Task-shaped recipes: "I want to do X — here
 are the steps" (monitor a host, 3-2-1 backups, tame alert noise, roll out
 safely, …).
- **[architecture.md](architecture.md)** — How the pieces fit together,
 the heartbeat → command → response cycle, file layout on disk.
- **[deployment.md](deployment.md)** — Install-everything map: server, agents
 (Linux/Windows/macOS), satellites, app nodes, load balancer, Postgres/HA —
 which script installs each and when you need it.
- **[scaling.md](scaling.md)** — Running large fleets (1000+ agents): the
 PostgreSQL backend, poll-interval tuning, FastCGI worker pool, load-balanced
 multi-node, relay satellites, PgBouncer, retention, and the encryption matrix.
- **[satellites.md](satellites.md)** — Relay satellites for segmented networks:
 add one, encrypt the agent→satellite hop, point agents at it, revoke.
- **[upgrading.md](upgrading.md)** — Migration steps between versions.
- **[troubleshooting.md](troubleshooting.md)** — Common issues and
 diagnostics.

## Reference

- **[api.md](api.md)** — REST endpoints + auth model. Interactive at
 `/swagger.html`; spec at `/api/openapi.json`.
- **[agent-commands.md](agent-commands.md)** — CLI for the Linux agent.
- **[fleet-management.md](fleet-management.md)** — operating the fleet from the
 dashboard: agent updates, release signing, the command queue, install/uninstall,
 reboot/WoL, quarantine, SLA targets, OpenSCAP, and AI Investigate.
- **[windows-client.md](windows-client.md)** — Windows-specific notes,
 install path, service control.
- **[https.md](https.md)** — TLS termination at nginx with acme.sh or
 Let's Encrypt.
- **[security.md](security.md)** — Threat model and on-disk data layout.
- **[security-review-5.8.0.md](security-review-5.8.0.md)** — Latest review:
 the v5.8.0 "WatchMatters" line plus a whole-project, eight-stream manual audit,
 the full SAST stack (CodeQL 0, Bandit/gitleaks clean) and a live authenticated
 penetration test — no Critical/High/Medium ships; two Medium read-only-role write
 gates plus Low/defense-in-depth fixes (agent no-redirect, file-manager resolved
 path, `javascript:` link scheme, scrub/arg-terminator hardening).
- **[security-review-5.6.0.md](security-review-5.6.0.md)** — A prior review:
 the v5.6.0 "HeapMatters" line (knowledge base, automation actions, check
 catalog + `systemd_unit`, recover events) plus a 5-dimension manual pentest and
 the full SAST stack (CodeQL 0, Bandit/gitleaks/njsscan/pip-audit clean) — no
 Critical/High/Medium ships; seven Low fixes (two secret-URL leaks, a read-only-role
 write gate, `systemctl`/`useradd` arg-injection guards, RouterOS/OPNsense
 connect-time SSRF).
- **[security-review-5.5.0.md](security-review-5.5.0.md)** — A prior review:
 the v5.5.0 "ScaleMatters" release (persistent WSGI app tier, out-of-band scheduler,
 hard multi-tenancy + Postgres RLS) plus a whole-project server + agent audit, SAST
 (CodeQL + Bandit + semgrep + gitleaks, all clean) and a live authenticated
 penetration test — no Critical/High/Medium ships; a High drift-authz fix, two Medium
 fixes (DMARC entity-guard window, AI-provider HTTP SSRF) and a Low secret-URL fix.

## Release notes

The full release history — every version, newest first — lives in
[`CHANGELOG.md`](../CHANGELOG.md) at the repository root.

The five most recent per-release notes are kept here:

- **[v5.8.0.md](v5.8.0.md)** — unreleased (test): TLS/DANE expiry probing now
 runs on the server's own ~6h schedule (it was silently cron-only, and blind
 under the SQLite/Postgres backends); **SNMPv3/USM** polling for agentless
 devices (MD5/SHA-1/SHA-2 auth + AES-128 privacy, engine discovery and
 time-window resync automatic, write-only passwords); and a new **GitHub
 Issues** connector that raises `github_new_issue` alerts when a new issue is
 opened on watched repositories (PRs ignored, first poll baselines, paging
 off by default). No breaking changes.
- **[v5.7.0.md](v5.7.0.md)** — "F4ct0rMatters": a refactor-and-fix release.
 Fixes five New-UI theming/accent/light-mode bugs (device delete, profile menu,
 accent picker, themes, chamfered buttons) reported by @AndiBSE and a mobile
 pass; adds ticket lifecycle events, full-tree config-secret encryption and
 multi-table Postgres RLS (both opt-in); and is faster to start (lazy pages,
 parallel fonts) on a much slimmer, modular server. No breaking changes.
- **[v5.6.0.md](v5.6.0.md)** — "HeapMatters": the IaC / automation +
 alert-tuning release. An opt-in **Provisioning** blueprint catalog (Terraform /
 cloud-init / Ansible / iPXE) that renders to copy/download or **runs Terraform
 server-side** (Plan / Apply / Destroy, behind a separate execute gate); an
 **alert Tuning** page that surfaces the noisiest alerts with per-host **mute**
 (the Ack button becomes an X mute); and **timesheet watchers** (view another
 user's hours, by user or team). All opt-in, default-off. No breaking changes.
- **[v5.5.0.md](v5.5.0.md)** — "ScaleMatters": the persistent-tier + enterprise
 release — the **keystone** (opt-in **gunicorn WSGI app server** + leader-elected
 **out-of-band scheduler**) that lifts the fork-per-request scale ceiling, **hard
 multi-tenancy** with optional **Postgres row-level security**, a large opt-in
 **enterprise-hardening** program, plus helpdesk-signal + billing polish (AV
 **`av_warning`** alerts, ticket **attachments**, **auto-reply**, **"View email
 thread"**, opt-in **Billing**). All opt-in, default-off. No breaking changes.
- **[v5.4.0.md](v5.4.0.md)** — "RackMatters": a lightweight **time-tracking +
 billing** layer on one shared time-entry ledger — log billable (debtable) or
 internal hours on tickets and a weekly **timesheet**, then turn them plus
 recurring fees into per-customer **invoices** (worksheet → draft/sent/paid, with
 issue-time hour locking). New read-only **finance** role; CSV / JSON-API /
 browser-PDF export. No breaking changes.

Older release notes (v5.0.1 and earlier) live in
[CHANGELOG.md](../CHANGELOG.md).

## Feature guides

- **[cmdb.md](cmdb.md)** — Per-asset metadata, Markdown documentation,
 and the encrypted credential vault (AES-GCM + PBKDF2). Threat model,
 API reference, backup story, disaster recovery.
- **[drift.md](drift.md)** — Configuration drift detection: what's
 watched, customising the list, re-baselining, the compliance angle.
- **[firewall.md](firewall.md)** — Fleet firewall + fail2ban: view posture and
 drift, edit nftables/iptables/ufw/firewalld rules, ban/unban IPs and start/stop jails.
- **[compliance.md](compliance.md)** — Host-security compliance: PCI/HIPAA/SOC2
 profiles, OpenSCAP + CIS baseline scoring, remediation.
- **[dmarc.md](dmarc.md)** — DMARC/SPF/DKIM email-posture monitor + IP reputation
 (DNSBL) checks.
- **[time-billing.md](time-billing.md)** — Time-tracking &amp; billing: billable
 hours, weekly timesheet, per-customer invoices, rate card / VAT, the finance role.
- **[wsgi.md](wsgi.md)** — The persistent WSGI app server + out-of-band scheduler
 (the v5.5.0 keystone) — when and how to run them.
- **[mcp.md](mcp.md)** — MCP server setup, Claude Desktop config, the
 14 read + 4 guarded write tools, security model, troubleshooting.
- **[scripts.md](scripts.md)** — Multi-line script library, dry-run
 linting, batch execution.
- **[compose.md](compose.md)** — docker compose dropdown on device cards.
- **[docker-agent.md](docker-agent.md)** — run the agent as a container to
 monitor a Docker host (no host install; one-click compose from the UI).
- **[containers.md](containers.md)** — Docker / Podman / Kubernetes pod
 listings.
- **[network-map.md](network-map.md)** — Manual topology graph from
 `connected_to` links, with a site/group/tag scope filter for big fleets.
- **[network-metrics.md](network-metrics.md)** — Per-device RX/TX throughput,
 rolled up fleet-wide or by group / tag / site.
- **[agentless-devices.md](agentless-devices.md)** — Manual records for
 switches, APs, printers, IPMI cards.
- **[tls-monitor.md](tls-monitor.md)** — Server-side TLS / DNS expiry
 probes.
- **[monitors.md](monitors.md)** — Active synthetic checks (ping/tcp/http/dns/db),
 service + log-tail alerts, inbound syslog / SNMP-trap receivers, resolver health,
 the healthchecks watchdog.
- **[cve.md](cve.md)** — Vulnerability scanning: the OSV.dev scanner, KEV + EPSS
 prioritisation, ignores/re-alert, SBOM (CycloneDX / SPDX).
- **[dns.md](dns.md)** — The Admin → DNS dashboard: read/write records via provider
 APIs, live resolve + propagation, the resolver-health monitor.
- **[backups.md](backups.md)** — Backup jobs, freshness + integrity monitoring,
 and encrypted control-plane disaster recovery.
- **[remote-access.md](remote-access.md)** — Browser web terminal, remote file
 manager, and host user / SSH-key / firewall management from the drawer.
- **[storage.md](storage.md)** — Storage-RAID health (ZFS/mdadm/btrfs), SMART +
 predictive disk health, GPUs, thermal, and power / UPS.
- **[tls-selfsigned.md](tls-selfsigned.md)** — Built-in self-signed CA +
 fingerprint-verified agent TLS (generate a cert from the UI).
- **[update-history.md](update-history.md)** — Captured `apt` / `dnf` /
 `pacman` upgrade output.
- **[swagger.md](swagger.md)** — OpenAPI / Swagger UI details.
- **[ai.md](ai.md)** — Optional AI assistant (Anthropic / OpenAI /
 DeepSeek / Ollama / LocalAI), button inventory, privacy redaction,
 rate limiting, nginx config for slow local models.
- **[rag.md](rag.md)** — How the AI assistant retrieves your runbooks,
 CMDB docs and live state to ground its answers.
- **[ticket-system.md](ticket-system.md)** — The built-in opt-in helpdesk:
 ticket types/priorities/SLA, ownership/teams/groups, master & sub-tickets,
 alert↔ticket linkage, and email in/out.
- **[contacts.md](contacts.md)** — The internal team contact directory.
- **[knowledge-base.md](knowledge-base.md)** — Opt-in operator-authored IT
 documentation (SOPs / how-tos / runbooks) in a category tree; searchable and
 fed to the AI as a RAG source.
- **[automations.md](automations.md)** — The event-driven automation rules
 engine: when an event fires, run a script / notify / open a ticket / add a
 tag / mute the alert.
- **[provisioning.md](provisioning.md)** — The Provisioning page: a catalog of
 infrastructure blueprints (Terraform, cloud-init, Ansible, iPXE) you render or
 run server-side (Terraform Plan/Apply/Destroy behind the execute gate).
- **[alert-tuning.md](alert-tuning.md)** — The Tuning page: surface the noisiest
 alerts and sources, and per-(host, event) mute to silence exactly one alert.
- **[virtualization.md](virtualization.md)** — Virtualization lifecycle across
 Proxmox, VMware (vSphere/vCenter, Cloud Director) and OpenShift: list guests,
 power actions and snapshots.
- **[security-scans.md](security-scans.md)** — Authorized vulnerability
 scanning (the Pentest page): tools, profiles, target ownership
 verification, scheduling, the scanner satellite.
- **[webhooks.md](webhooks.md)** — Outbound webhook destinations, the
 event catalog, channel routing, inbound webhooks.
- **[wg-access.md](wg-access.md)** — WG Access: a built-in WireGuard
 road-warrior VPN (tunnels → clients, reach scopes, browser keygen + QR).
- **[acme.md](acme.md)** — ACME / Let's Encrypt certificate tracking
 across the fleet.
- **[attention.md](attention.md)** — The "Needs attention" roll-up: what
 feeds it and how items clear.
- **[bulk-operations.md](bulk-operations.md)** — Multi-device commands,
 tag/group targeting, batch patching.
- **[custom-scripts.md](custom-scripts.md)** — Custom monitoring scripts:
 server-defined bash health checks with fleet-wide results.
- **[forecast.md](forecast.md)** — Disk-fill forecasting and predictive
 disk health.
- **[health-score.md](health-score.md)** — How the fleet health score is
 computed.
- **[host-config.md](host-config.md)** — Declarative per-host desired
 state (repos, DNS, users, services) with drift reporting.
- **[keyboard-shortcuts.md](keyboard-shortcuts.md)** — Command palette and
 keyboard navigation.
- **[mitigation.md](mitigation.md)** — One-click mitigation runners for
 common findings.
- **[opnsense.md](opnsense.md)** — OPNsense firewall integration (and the
 RouterOS sibling).
- **[integrations.md](integrations.md)** — Homelab software integrations: poll
 Pi-hole, TrueNAS, Home Assistant, the *arr suite, download clients and more for
 health → Alerts (read-only, SSRF-guarded).
- **[self-monitoring.md](self-monitoring.md)** — The server watching
 itself: status page, DB maintenance, CSP reports.
- **[sla.md](sla.md)** — Uptime SLA targets and reporting.
- **[terraform-api.md](terraform-api.md)** — Using the REST API from
 Terraform / IaC pipelines.
- **[maintaining-docs.md](maintaining-docs.md)** — How these docs are kept
 in sync with the product (for contributors).
- **[prometheus-metrics-sample.txt](prometheus-metrics-sample.txt)** —
 Example `/api/metrics` output for Grafana scrape config.
- **screenshots/** — UI screenshots referenced from the main README.
