# RemotePower documentation

The main `README.md` at the repo root is the place to start. This folder
holds long-form docs that don't fit there.

## Getting started

- **[install.md](install.md)** — Server install (Linux + Docker), client
 enrolment, optional webterm, demo vhost.
- **[requirements.md](requirements.md)** — Minimum/recommended server
 hardware (cores, RAM, disk) by fleet size, plus agent/client footprint.
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
- **[internals.md](internals.md)** — Under the hood: the engineering tour of
 *how it's built* — the table-driven router, the one-API/three-backend storage
 layer, the maintenance sweeps, request validation, the no-build frontend, and
 the defensive-security posture. For the curious and for contributors.
- **[deployment.md](deployment.md)** — Install-everything map: server, agents
 (Linux/Windows/macOS), satellites, app nodes, load balancer, Postgres/HA —
 which script installs each and when you need it.
- **[scaling.md](scaling.md)** — Running large fleets (1000+ agents): the
 PostgreSQL backend, poll-interval tuning, the gunicorn worker pool, load-balanced
 multi-node, relay satellites, PgBouncer, retention, and the encryption matrix.
- **[satellites.md](satellites.md)** — Relay satellites for segmented networks:
 add one, encrypt the agent→satellite hop, point agents at it, revoke.
- **[push.md](push.md)** — Experimental opt-in agent push channel: near-
 instant command dispatch via a companion WebSocket daemon, off by default.
- **[upgrading.md](upgrading.md)** — One command (`install.sh update`) for
 every upgrade, self-detecting whether that's a plain code update or a
 pre-6.1.0 CGI/SCGI-to-gunicorn/Flask conversion.
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
- **[security.md](security.md)** — Security controls and on-disk data layout.
- **[threat-model.md](threat-model.md)** — Structured STRIDE threat/mitigation
 matrix, organized by attacker goal rather than by feature.
- **[security-review-6.2.3.md](security-review-6.2.3.md)** — Latest review: the
 v6.2.3 "Un1fyMatters" pass — full SAST stack (CodeQL 0 results, Bandit 0 new,
 gitleaks clean, Semgrep triaged) plus an exhaustive six-dimension adversarial
 audit prompted by the release's shared-helper refactors. Confirmed the config-
 secret, HTML-escaping and request-validation refactors are behaviour-preserving
 (a 20k-config property test on the secret redactors), and fixed a set of
 pre-existing multi-tenant isolation gaps (cross-tenant device targeting and
 fleet-aggregate read leaks) plus a drift between the off-box export surfaces'
 secret-redaction lists; no Critical/High/Medium ships.
- **[security-review-6.2.2.md](security-review-6.2.2.md)** — the
 v6.2.2 "Pu1seMatters" pass — full SAST stack (Bandit 0 new, gitleaks clean,
 agents F821-clean) plus a Semgrep pass with every finding triaged in the open, a
 trust-boundary review of the new delta-heartbeat protocol (per-device,
 whitelisted, capability-negotiated — no stale or cross-device exposure) and the
 reused HTTPS transport (same cert/mTLS verification, redirects still refused), and
 a live header/auth-boundary check of production. One agent-side hardening (a
 billion-laughs guard on the OpenSCAP XML parse) was made from the scan; no
 Critical/High/Medium ships.
- **[security-review-6.2.0.md](security-review-6.2.0.md)** — the v6.2.0
 "Daem0nMatters" pass — full SAST stack (CodeQL 0 results, Bandit 0 High,
 gitleaks clean) plus an authorization audit of the new attack surface (the
 supervised-service installers, governed AI executor, PII scan, EDR coverage,
 DNS-blocker control, JIT vault checkout) and a prompt-injection analysis of the AI
 executor (which cannot author commands — it may only pick a saved catalog action
 by exact id); no Critical/High/Medium ships.
## Release notes

The full release history — every version, newest first — lives in
[`CHANGELOG.md`](../CHANGELOG.md) at the repository root.

The three most recent per-release notes are kept here:

- **[v6.2.3.md](v6.2.3.md)** — "Un1fyMatters": a consolidation and tidy-up pass —
 an optional listen port on Create tunnel, an ACME page that loads on navigation,
 clearer empty-snapshot feedback, and a removed duplicate dampening setting; plus
 a project-wide sweep that collapsed repeated code idioms, deleted dead code and
 de-duplicated the docs.
- **[v6.2.2.md](v6.2.2.md)** — "Pu1seMatters": performance and polish around
 the heartbeat — delta sysinfo (agents skip re-sending unchanged inventory),
 agent HTTP keep-alive, streamed large-fleet tables and a leaner first load;
 an always-on kernel-module visibility check that flags the v6.2.1 failure
 class before patch day; an upgrade-in-place installer; keyboard-driven alert
 inbox, device hover cards and tab-level device deep links.
- **[v6.2.1.md](v6.2.1.md)** — "In1tMatters": a critical fix for Linux hosts
 booting via initramfs (Debian/Ubuntu) — agent-unit sandboxing could make
 upgrades run through RemotePower rebuild the initramfs without kernel modules
 (unbootable at next reboot). Unit fixed; the upgrade command now refuses to
 run in that situation; patch-window reboots verify the initrd first.
Older release notes (v6.1.2 and earlier) live in
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
 hours, weekly timesheet, per-customer invoices, **quotes** *(v6.2.0)*, rate card /
 VAT, the finance role.
- **[ai-executor.md](ai-executor.md)** — The governed AI executor *(v6.2.0)*: it
 proposes a remediation from a catalog of your own scripts, a human approves, and
 what you approve is what runs. Off by default.
- **[pii-scan.md](pii-scan.md)** — Regulated-data (PII) scan *(v6.2.0)*: where your
 emails / card numbers / national IDs live, reported by file — never the values.
- **[secret-scan.md](secret-scan.md)** — Exposed-secrets-on-disk scan (redacted
 findings — keys/tokens/passwords by rule, path and fingerprint, never the value)
 and canary (honeytoken) decoy files with the critical `canary_accessed` tripwire.
- **[edr-coverage.md](edr-coverage.md)** — EDR coverage *(v6.2.0)*: Wazuh /
 CrowdStrike / SentinelOne connectors cross-referenced to name the hosts with no
 EDR at all.
- **[dns-control.md](dns-control.md)** — DNS-blocker control *(v6.2.0)*: pause
 Pi-hole / AdGuard blocking for a bounded, self-restoring window.
- **[wsgi.md](wsgi.md)** — The gunicorn/Flask app server + out-of-band scheduler:
 the only server since v6.1.0, installed and enabled by default. Tuning workers,
 threads and the scheduler.
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
- **[ipam.md](ipam.md)** — Racks (elevation view, asset placement) and IPAM
 (subnets, derived occupancy, reservations, duplicate-IP/MAC conflict alerts).
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
- **[sso.md](sso.md)** — Single sign-on & directory integration: OIDC, SAML 2.0
 and LDAP/LDAPS sign-in, the shared IdP group→role mapping, SCIM provisioning /
 deactivation, and SSO-only mode with break-glass local login.
- **[storage.md](storage.md)** — Storage-RAID health (ZFS/mdadm/btrfs) + SMART;
 umbrella page linking the focused disk-health, GPU, thermal and power guides.
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
- **[ticket-system.md](ticket-system.md)** — The built-in helpdesk (on by default):
 ticket types/priorities/SLA, ownership/teams/groups, master & sub-tickets,
 alert↔ticket linkage, and email in/out.
- **[contacts.md](contacts.md)** — The internal team contact directory.
- **[customer-portal.md](customer-portal.md)** — The opt-in, self-service portal
 where customers raise and follow their own tickets by magic-link (tickets only;
 closed `/api/portal/*` surface).
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
- **[oncall.md](oncall.md)** — On-call rotation (anchored calendar schedule,
 overrides) and tiered escalation of unacknowledged alerts, with per-tier
 webhook targets.
- **[alert-parameters.md](alert-parameters.md)** — Settings → Alert parameters:
 the one home for every numeric alert-firing threshold, the health-grade /
 risk / reliability cutoffs, and the per-factor score weights (with a filter box).
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
 itself: status page, distributed-subsystem health, DB maintenance, CSP reports.
- **[settings.md](settings.md)** — The complete Settings guide: every tab
 (Setup / Monitoring / Connections / System), the key knobs, and links to the
 deeper per-topic docs.
- **[cli.md](cli.md)** — The `rp` node-control command (omd/checkmk style):
 `rp status`, `rp start/stop/restart`, `rp logs`, and a `rp doctor` health check.
- **[sla.md](sla.md)** — Uptime SLA targets and reporting.
- **[terraform-api.md](terraform-api.md)** — Using the REST API from
 Terraform / IaC pipelines.
- **[maintaining-docs.md](maintaining-docs.md)** — How these docs are kept
 in sync with the product (for contributors).
- **[prometheus-metrics-sample.txt](prometheus-metrics-sample.txt)** —
 Example `/api/metrics` output for Grafana scrape config.
- **[../contrib/grafana/](../contrib/grafana/)** — Ready-made Grafana
 dashboard JSON for the `/api/metrics` exposition (import → pick your
 Prometheus datasource).
- **screenshots/** — UI screenshots referenced from the main README.

## Page guides

One page of the UI, one guide. (These existed but were never linked from this
index — a doc nobody can find is a doc nobody reads.)

### Fleet & inventory
- **[dashboard.md](dashboard.md)** — The home dashboard: widgets, what each one
 counts, and how to customise the layout.
- **[sites.md](sites.md)** — Sites and the fleet world map.
- **[links.md](links.md)** — Per-device quick links to your other tools.
- **[timeline.md](timeline.md)** — The fleet activity timeline.
- **[status-board.md](status-board.md)** — The public/NOC status board.

### Monitoring & health
- **[checks.md](checks.md)** — The per-host Checks engine: every monitored signal
 as OK / WARN / CRIT, custom checks, and muting.
- **[alerts.md](alerts.md)** — The Alerts inbox: severities, acknowledge/resolve,
 correlation (root cause vs symptom), mutes.
- **[trends.md](trends.md)** — Metric history and trend charts.
- **[thermal.md](thermal.md)** — Temperatures and thermal health.
- **[power.md](power.md)** — Power draw, energy, and UPS status.
- **[gpus.md](gpus.md)** — GPU inventory and utilisation.
- **[disk-health.md](disk-health.md)** — SMART disk health, wear, NVMe spare
 reserve and failure prediction.
- **[services.md](services.md)** — Watched systemd services and baselines.
- **[log-watch.md](log-watch.md)** — The rolling log buffer and log alert rules.
- **[reports.md](reports.md)** — Scheduled and on-demand fleet reports.

### Security & compliance
- **[risk.md](risk.md)** — The fleet risk score and what moves it.
- **[exposure.md](exposure.md)** — World-exposed listening ports.
- **[patches.md](patches.md)** — Pending patches, per-package pinning, patch SLA.
- **[auto-patch.md](auto-patch.md)** — Automatic patching policies and staged
 (canary → wave → rest) patch rings.
- **[patch-snapshots.md](patch-snapshots.md)** — Freeze the fleet's package versions
 into a named snapshot, diff two, promote one as a tag's reference state, and see
 which hosts have drifted from it.
- **[software-policy.md](software-policy.md)** — Allowed/forbidden software policy.

### Automation & operations
- **[schedule.md](schedule.md)** — Scheduled jobs.
- **[cron.md](cron.md)** — Managing host crontabs and systemd timers.
- **[tasks.md](tasks.md)** — The task list.
- **[calendar.md](calendar.md)** — The shared team events calendar (a memory
 aid — it doesn't run anything; on-call lives in [oncall.md](oncall.md)).
- **[maintenance.md](maintenance.md)** — Maintenance windows and alert suppression.
- **[rollouts.md](rollouts.md)** — Health-gated staged rollouts.
- **[command-library.md](command-library.md)** — Saved commands and scripts.
- **[app-catalog.md](app-catalog.md)** — One-click app deployment.
- **[fleet-query.md](fleet-query.md)** — Fleet Query (device-only ANDed conditions)
 and the Data explorer (nested AND/OR across devices, CVEs and drift); saved query
 templates.

### For contributors
- **[testing-deep.md](testing-deep.md)** — Property-based and fuzz testing
 (Hypothesis), and how to run the deeper suite.
