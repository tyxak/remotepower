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
- **[security-review-5.2.0.md](security-review-5.2.0.md)** — Latest review:
 the new WG Access (WireGuard VPN) feature plus a whole-project server + agent
 audit and a live authenticated penetration test, with CodeQL + Bandit + gitleaks
 all clean (no Critical/High/Medium ships) — the privileged-helper boundary,
 browser keygen, and two Low-severity tunnel-confinement/teardown fixes.
- **[security-review-5.1.1.md](security-review-5.1.1.md)** — A prior review:
 a whole-project server + agent audit and a live authenticated penetration test,
 with CodeQL + Bandit + gitleaks all clean (no Critical/High/Medium ships) — the
 community-contribution surface (Proxmox cluster, hash routing, LocalAI keys, the
 separate embedding service) plus Low-severity escaping and request-body hardening.
- **[security-review-5.1.0.md](security-review-5.1.0.md)** — A prior review:
 the first-class `fail2ban_ban` event (no new sink, post-lock fire, per-host
 coalescing), Arabic RTL CSS and the i18n batch, with SAST (Bandit/gitleaks)
 held to the bar (no Critical/High/Medium ships).

## Release notes

The full release history — every version, newest first — lives in
[`CHANGELOG.md`](../CHANGELOG.md) at the repository root.

The five most recent per-release notes are kept here:

- **[v5.2.0.md](v5.2.0.md)** — "AccessMatters": **WG Access**, a built-in light
 WireGuard road-warrior VPN (Admin → WG Access). Reach the dashboard and fleet
 over an encrypted tunnel: tunnels carry a reach scope (dashboard-only / fleet /
 site / group / tag), full- or split-tunnel egress and optional auto-expiry;
 per-client `.conf` + QR configs are issued with keys generated in your browser.
 No breaking changes.
- **[v5.1.1.md](v5.1.1.md)** — "ClusterMatters": the Proxmox integration lists
 guests across the whole cluster (not just one node), resolving each guest's
 owning node for actions/snapshots/lifecycle, with hostname-validated node names;
 plus the test/polish gaps from that feature. Contributed by @tbouquet (#9). No
 breaking changes.
- **[v5.1.0.md](v5.1.0.md)** — "UnityMatters": security-signal + localisation —
 fail2ban bans and active malware/rootkit detections are now first-class alert
 events, an admin App Catalog (add your own one-click Docker Compose apps), an
 opt-in host file manager, host cron/timer management, a code-free custom HTTP
 probe plugin, full Arabic right-to-left layout, and a whole-project finalize
 sweep. No breaking changes.
- **[v5.0.1.md](v5.0.1.md)** — "TemperMatters": a stability + polish release —
 fixes a class of bugs that silently broke features on the SQLite/PostgreSQL
 backend (SSH-key drift audit, Proxmox snapshot alerts, host-config view),
 coalesces duplicate alerts, makes agent stop/start quiet by default, and adds
 Edit buttons for API keys and custom checks. No breaking changes.
- **[v5.0.0.md](v5.0.0.md)** — "CTRLMatters": control-plane hardening — opt-in
 mutual TLS for agents, AES-256-GCM encrypted DR backups, break-glass vault
 reveals and per-API-key rate limits, a webhook dead-letter queue, runtime
 maintenance mode, bulk fleet ops, one-click rollout rollback, and cross-device
 OSV batching. Every new control is opt-in; no breaking changes.

Older release notes (v4.10.0 and earlier) live in
[CHANGELOG.md](../CHANGELOG.md).

## Feature guides

- **[cmdb.md](cmdb.md)** — Per-asset metadata, Markdown documentation,
 and the encrypted credential vault (AES-GCM + PBKDF2). Threat model,
 API reference, backup story, disaster recovery.
- **[drift.md](drift.md)** — Configuration drift detection: what's
 watched, customising the list, re-baselining, the compliance angle.
- **[firewall.md](firewall.md)** — Fleet firewall + fail2ban: view posture and
 drift, edit nftables/iptables/ufw/firewalld rules, ban/unban IPs and start/stop jails.
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
