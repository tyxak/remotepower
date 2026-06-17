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
- **[security-review-4.6.0.md](security-review-4.6.0.md)** — Latest review:
 a full server + agent re-audit (independently pentested clean) — SSRF parity on
 the OPNsense/Proxmox/AI/TLS-monitor targets, resolved-role checks on two read
 endpoints, and agent credential-storage hardening on Windows/macOS/Linux.
- **[security-review-4.4.1.md](security-review-4.4.1.md)** — Triage of the open
 CodeQL code-scanning alerts (XSS/SSRF/weak-hash/clear-text); all confirmed
 false positives, with the feature/function that covers each.
- **[security-review-4.4.0.md](security-review-4.4.0.md)** — A full server +
 agent audit (independently pentested clean) — a critical admin-gate escalation,
 mitigation-route scope guards, shell-quoting the drift/ACME command builders,
 the RouterOS SSRF guard, metrics-scrape resilience, and Windows/macOS agent
 transport parity.

## Release notes

The full release history — every version, newest first — lives in
[`CHANGELOG.md`](../CHANGELOG.md) at the repository root.

The five most recent per-release notes are kept here:

- **[v4.8.0.md](v4.8.0.md)** — "OnboardingMatters": turnkey onboarding (unified
 `install.sh` wizard, one-command Docker with HTTPS-by-default, a self-hosted
 one-line agent installer, SSH agent-push, clean uninstall) + a Reputation/DMARC
 monitor (IP reputation against DNS blocklists, plus SPF / DKIM / DMARC posture
 with IMAP aggregate-report ingestion), accessibility work, and macOS/Windows
 agent parity. No breaking changes.
- **[v4.7.0.md](v4.7.0.md)** — homelab/fleet software integrations (26 read-only
 connectors → Alerts + dashboard, SSRF-guarded) + a containerized agent that
 monitors a Docker host with no install. No breaking changes.
- **[v4.6.1.md](v4.6.1.md)** — a stability + hardening patch on v4.6.0: SCGI-worker
 fixes (CAP_NET_RAW for agentless ICMP ping, Postgres connection fork-safety), a
 ReDoS fix in `_valid_tls_host`, a defence-in-depth XSS coercion, and a subtitle
 reload-flash fix. No breaking changes.
- **[v4.6.0.md](v4.6.0.md)** — "RepellantMatters": a visual-identity release — the
 new Industrial "New UI" (graphite/steel + blue accent) as default, with a
 CSP-safe New UI / Old UI toggle. No markup/nav/functional changes.
- **[v4.5.0.md](v4.5.0.md)** — "TrustMatters": TLS onboarding — a one-command
 self-signed CA, fingerprint-verified rollout to agents, Docker opt-in TLS, and a
 server-only self-signed → real migration. No breaking changes.

Older release notes (v4.4.1 and earlier) live in
[CHANGELOG.md](../CHANGELOG.md).

## Feature guides

- **[cmdb.md](cmdb.md)** — Per-asset metadata, Markdown documentation,
 and the encrypted credential vault (AES-GCM + PBKDF2). Threat model,
 API reference, backup story, disaster recovery.
- **[drift.md](drift.md)** — Configuration drift detection: what's
 watched, customising the list, re-baselining, the compliance angle.
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
 `connected_to` links.
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
