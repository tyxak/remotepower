# RemotePower documentation

The main `README.md` at the repo root is the place to start. This folder
holds long-form docs that don't fit there.

## Getting started

- **[install.md](install.md)** — Server install (Linux + Docker), client
 enrolment, optional webterm, demo vhost.
- **[wizards.md](wizards.md)** — The Add a host and Add a notification
 destination wizards, and the Step by step switch of the long forms.
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
- **[ha.md](ha.md)** — High availability: the active/passive reference topology
 (Postgres streaming replication, keepalived floating IP, the scheduler-singleton
 rule), the promote runbook, and the capacity target + load-test recipe *(v6.4.0)*.
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
- **[release-checklist.md](release-checklist.md)** — how a release goes from
 the test branch to production: version bump, the pre-release gate, tagging,
 packages, and what to verify afterwards.
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
- **[security-review-7.5.0.md](security-review-7.5.0.md)** — the v7.5.0 review, a second read of the whole product for rules the
  code applied in most places and missed in one or two: four-eyes approval on every command, a step-up on the restores, playbook
  content for the roles that may edit it, flaws in the agents, and the server code added since 7.4.0. Fifteen medium, twenty-one
  low and three informational findings, all fixed, the scans and the mutation checks behind them, and what is still open.
- **[security-review-7.4.9.md](security-review-7.4.9.md)** — the v7.4.9 review, of the whole project and not only of what
  changed: an authorization check on every route as 26 kinds of caller, hostile input on every route, the three agents
  and their installers, the web client and the web server headers, the interface, and the documents. Five high, seventeen
  medium and twelve low findings, all fixed, the scans and the mutation checks behind them, and what is still open.
- **[security-review-7.4.8.md](security-review-7.4.8.md)** — the v7.4.8 review: what a host can make the server and
  its own agent do through the sensor limits and labels it reports and the text `apt-get` prints, what a stored row
  of the wrong kind does to the Thermal page and the risk score, and one low issue, a stored reading or limit too big
  for a float that answered 500 to everyone. Caught before release, with the scans and the mutation checks behind it.
- **[v8.0.0.md](v8.0.0.md)** — "Pil0tMatters": the text size from 80% to 300%, tabs and named layouts, ten wizards, the apps
  the agent finds on a host, three connectors and four monitor types, a read-only MCP endpoint, automatic image updates and a Traffic view of what each host talks to.
- **[v7.5.0.md](v7.5.0.md)** — "Wh0leMatters": the release that carries 7.4.1 to 7.4.9 to production, with four-eyes approval on every
  command, a sign-in before a restore, the agents' data in every page that can use it, and fifteen medium findings fixed.
- **[v7.4.9.md](v7.4.9.md)** — "Ch0iceMatters": a host runs its upgrades in a Standard or an Extended mode, a
  hard disk and a SATA SSD behind the same controllers keep their own temperature lines, and an update Ubuntu is
  still phasing in is not counted as pending.
- **[cmdb.md](cmdb.md)** — Per-asset metadata, Markdown documentation,
 and the encrypted credential vault (AES-GCM + PBKDF2). Threat model,
 API reference, backup story, disaster recovery.
- **[drift.md](drift.md)** — Configuration drift detection: what's
 watched, customising the list, re-baselining, the compliance angle.
- **[security-advisory.md](security-advisory.md)** — Security Advisory
 (Security → Advisory): what to fix first across application/exposure/OS/
 identity/integrity, at any scope, plus the redacted AI option.
- **[integrity-guard.md](integrity-guard.md)** — Integrity Guard (Security →
 Protect): file-integrity and egress check types, auto-quarantine and the
 on-host vault, restore/delete, the maintenance + mass-change safety rails,
 the hardening template catalog, and troubleshooting.
- **[firewall.md](firewall.md)** — Fleet firewall + fail2ban: view posture and
 drift, edit nftables/iptables/ufw/firewalld rules, ban/unban IPs and start/stop jails.
- **[compliance.md](compliance.md)** — Host-security compliance: PCI/HIPAA/SOC2
 profiles, OpenSCAP + CIS baseline scoring, remediation.
- **[data-retention.md](data-retention.md)** — What each store keeps and for how
 long: the seven retention knobs and their real defaults (most keep everything
 forever), what the audit archive does instead of deleting, and litigation hold.
- **[access-review.md](access-review.md)** — Quarterly access recertification:
 which fields answer which question, what to check on API keys and live sessions,
 and what RemotePower will not decide for you.
- **[incident-response.md](incident-response.md)** — The RemotePower half of an IR
 plan: containing a compromised host without losing telemetry, what to do when the
 control plane itself is suspect, and telling a real incident from a noisy rule.
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
 16 read + 5 guarded write tools, security model, troubleshooting.
- **[scripts.md](scripts.md)** — Multi-line script library, dry-run
 linting, batch execution.
- **[compose.md](compose.md)** — docker compose dropdown on host cards.
- **[app-discovery.md](app-discovery.md)** — The apps an agent finds on a Linux host (from its sockets, containers and services), and the monitor and connector each one offers: **Discovered on this host** in the drawer and **Found on your hosts** on Integrations *(8.0.0)*.
- **[traffic.md](traffic.md)** — Which addresses your Linux hosts talk to and how much each connection moved: the **Traffic** tab on the Network page, the host drawer's section, the watch list and its alert, the Data Explorer `traffic` entity and Fleet Query **Talks to**; off until you switch it on *(8.0.0)*.
- **[docker-agent.md](docker-agent.md)** — run the agent as a container to
 monitor a Docker host (no host install; one-click compose from the UI).
- **[containers.md](containers.md)** — Docker / Podman / Kubernetes pod
 listings.
- **[network-map.md](network-map.md)** — Manual topology graph from
 `connected_to` links, with a site/group/tag scope filter for big fleets.
- **[network-metrics.md](network-metrics.md)** — Per-host RX/TX throughput,
 rolled up fleet-wide or by group / tag / site.
- **[ipam.md](ipam.md)** — Racks (elevation view, asset placement) and IPAM
 (subnets, derived occupancy, reservations, duplicate-IP/MAC conflict alerts).
- **[agentless-devices.md](agentless-devices.md)** — Manual records for
 switches, APs, printers, IPMI cards.
- **[inbound-tokens.md](inbound-tokens.md)** — Inbound tokens: the five kinds,
 which senders get a URL and which never hold a token (syslog and NetFlow from a
 firewall arrive as UDP), and what to check when nothing arrives.
- **[syslog.md](syslog.md)** — Syslog ingestion from agentless appliances: the
 HTTP receiver and the native `remotepower-syslogd` UDP listener.
- **[flow.md](flow.md)** — Agentless network flow visibility: the
 `remotepower-flowd` NetFlow/IPFIX receiver, exporter setup, and the per-host
 top-talkers/conversations view *(v6.4.0)*.
- **[kmip.md](kmip.md)** — The built-in KMIP key server: keep Synology DSM /
 TrueNAS / vSphere encryption keys off the appliance that holds the encrypted
 data. Sidecar install, the client wizard, the security model and the encrypted
 recovery bundle *(v6.4.1)*.
- **[tls-monitor.md](tls-monitor.md)** — Server-side TLS / DNS expiry
 probes.
- **[monitors.md](monitors.md)** — Active synthetic checks (ping/tcp/http/dns/db),
 service + log-tail alerts, inbound syslog / SNMP-trap receivers, resolver health,
 the healthchecks watchdog, and the `/api/metrics` Prometheus exposition.
- **[cve.md](cve.md)** — Vulnerability scanning: the OSV.dev scanner, KEV + EPSS
 prioritisation, ignores/re-alert, SBOM (CycloneDX / SPDX).
- **[dns.md](dns.md)** — The Admin → DNS dashboard: read/write records via provider
 APIs, live resolve + propagation, the resolver-health monitor.
- **[backups.md](backups.md)** — Backup jobs, freshness + integrity monitoring,
 and encrypted control-plane disaster recovery.
- **[remote-access.md](remote-access.md)** — Browser web terminal, remote file
 manager, and host user / SSH-key / firewall management from the drawer.
- **[ip-intel.md](ip-intel.md)** — Threat Intel: look up, report and block
 brute-force sources with AbuseIPDB and SniffCat.
- **[edge-sources.md](edge-sources.md)** — Edge sources: set up the Cloudflare
 token and feeds that let Threat Intel read what Cloudflare refused, step by
 step, with troubleshooting.
- **[firewall-sources.md](firewall-sources.md)** — Firewall sources: let Threat
 intel read the syslog of an OPNsense or MikroTik, for port scans, a decoy port,
 Suricata and CrowdSec alerts and failed sign-ins, step by step.
- **[honeypot-worker.md](honeypot-worker.md)** — Run a honeypot Worker on
 Cloudflare: one script and one config file that answer decoy paths and write
 the log Threat Intel reads, step by step.
- **[honeypot-traps.md](honeypot-traps.md)** — More traps for the honeypot
 Worker: a robots.txt decoy, a fake git repository and backup directory, WordPress
 probes, a planted password and decoy hosts, in one replacement script.
- **[sshgw.md](sshgw.md)** — SSH Gateway: reach hosts with your own SSH client
 through one gateway, with no inbound port on the host, public-key login and a
 per-session audit trail.
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
- **[attention.md](attention.md)** — The "Needs attention" roll-up and its
 full page: what feeds it, how items clear, and the four ways to quiet one.
- **[bulk-operations.md](bulk-operations.md)** — Multi-host commands,
 tag/group targeting, batch patching.
- **[custom-scripts.md](custom-scripts.md)** — Custom monitoring scripts:
 server-defined bash health checks with fleet-wide results.
- **[forecast.md](forecast.md)** — Capacity forecasting: disk-fill, memory /
 swap / CPU-load headroom, and predictive disk health.
- **[health-score.md](health-score.md)** — How the fleet health score is
 computed.
- **[host-config.md](host-config.md)** — Declarative per-host desired
 state (repos, DNS, users, services) with drift reporting.
- **[keyboard-shortcuts.md](keyboard-shortcuts.md)** — Command palette and
 keyboard navigation.
- **[ux.md](ux.md)** — Working the interface: undo instead of confirm,
 the notification center, drafts, tables, selection, deep links, charts
 and the posture radar (the v6.3.0 UX program in one guide).
- **[accessibility.md](accessibility.md)** — Accessibility conformance
 statement: what is supported against WCAG 2.1 AA, what is partially
 supported, and the known limitations — for procurement reviews.
- **[mitigation.md](mitigation.md)** — One-click mitigation runners for
 common findings.
- **[opnsense.md](opnsense.md)** — OPNsense: send its logs and NetFlow to
 RemotePower, and manage its rules over the API (and the RouterOS sibling).
- **[integrations.md](integrations.md)** — Homelab software integrations: poll
 Pi-hole, TrueNAS, Home Assistant, the *arr suite, download clients and more for
 health → Alerts (read-only, SSRF-guarded).
- **[self-monitoring.md](self-monitoring.md)** — The server watching
 itself: status page, distributed-subsystem health, DB maintenance, CSP reports.
- **[settings.md](settings.md)** — The complete Settings guide: every tab
 (Setup / Monitoring / Connections / System), the key knobs, and links to the
 deeper per-topic docs.
- **[my-account.md](my-account.md)** — Your own account page: profile, team,
 email signature, password, 2FA and passkeys, personal notification routing,
 theme and display units, active sessions.
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
- **[links.md](links.md)** — Per-host quick links to your other tools.
- **[timeline.md](timeline.md)** — The fleet activity timeline.
- **[status-board.md](status-board.md)** — The public/NOC status board.

### Monitoring & health
- **[checks.md](checks.md)** — The per-host Checks engine: every monitored signal
 as OK / WARN / CRIT, custom checks, and muting.
- **[alerts.md](alerts.md)** — The Alerts inbox: severities, acknowledge/resolve,
 correlation (root cause vs symptom), mutes.
- **[problems.md](problems.md)** — The Problems page: alerts, Needs Attention and checks
 joined into one list, each problem once, with whether the host still reports it.
- **[trends.md](trends.md)** — Metric history and trend charts.
- **[thermal.md](thermal.md)** — Temperatures and thermal health, plus the
 per-host temperature timeline (24 hours to 2 years) and time-pinpointing.
- **[power.md](power.md)** — Power draw, energy, and UPS status.
- **[gpus.md](gpus.md)** — GPU inventory and utilisation.
- **[disk-health.md](disk-health.md)** — SMART disk health, wear, NVMe spare
 reserve and failure prediction.
- **[services.md](services.md)** — Watched systemd services and baselines.
- **[business-services.md](business-services.md)** — Business services: hosts, monitors, units, containers and scripts
  grouped under a name, with a rule for how the parts add up, a state, and alerts when it goes down.
- **[log-watch.md](log-watch.md)** — The rolling log buffer and log alert rules.
- **[detection-selftest.md](detection-selftest.md)** — Verify the alert
  detection → routing → delivery chain is intact — silence isn't clearance.
- **[config-history.md](config-history.md)** — Configuration snapshots and
  one-click rollback (last 10 saved states, every restore reversible).
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
- **[time-periods.md](time-periods.md)** — Named sets of hours that quiet hours, after-hours detection, the ticket SLA clock and maintenance windows share.
- **[rollouts.md](rollouts.md)** — Health-gated staged rollouts.
- **[command-library.md](command-library.md)** — Saved commands and scripts.
- **[app-catalog.md](app-catalog.md)** — One-click app deployment.
- **[navigation.md](navigation.md)** — Finding your way around: the All-pages
 map, the sidebar, the command palette and the search box, and which to use
 when.
- **[fleet-query.md](fleet-query.md)** — Fleet Query: the quick host-only
 filter in the toolbar.
- **[data-explorer.md](data-explorer.md)** — Data Explorer: nested AND/OR
 conditions across hosts, CVEs, drift, packages, listening ports, services,
 containers and alerts; the 45 host fields you can query (posture, telemetry,
 inventory) and why the posture booleans are tri-state. Saved query
 templates.

### For contributors
- **[testing-deep.md](testing-deep.md)** — Property-based and fuzz testing
 (Hypothesis), and how to run the deeper suite.
- [Autonomous remediation](autonomy.md) — the loop that can fix recurring problems on its own, and the safety envelope around it
