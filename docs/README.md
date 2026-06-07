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
- **[security-review-3.13.0.md](security-review-3.13.0.md)** — Latest security
 review (sandboxed SCAP reports, OIDC id_token claim checks, syslog-forward
 DNS-rebinding fix) plus the external-scan summary.
- **[security-review-3.10.0.md](security-review-3.10.0.md)** — Image-registry
 SSRF / credential-exfiltration fix and the `/api/config` secret-scrub backstop.
- **[security-review-3.9.0.md](security-review-3.9.0.md)** — HTTP / TCP uptime
 monitor SSRF closure.
- **[Manual.html](Manual.html)** — Single-page reference manual.

## Release notes

The full release history — every version, newest first — lives in
[`CHANGELOG.md`](../CHANGELOG.md) at the repository root.

The five most recent per-release notes are kept here:

- **[v3.14.0.md](v3.14.0.md)** — per-account sidebar favorites; per-container
 stale-image badge; fleet thermal roll-up ("hottest hosts").
- **[v3.13.0.md](v3.13.0.md)** — bind-it-together round four; every panel caps
 at ~15 rows and scrolls; SCAP / OIDC / syslog hardening.
- **[v3.12.0.md](v3.12.0.md)** — optional SQLite storage backend with a live,
 in-place, reversible migration.
- **[v3.11.0.md](v3.11.0.md)** — fleet posture batch (exposure map, software
 policy, storage/RAID health, access watch, firewall drift).
- **[v3.10.0.md](v3.10.0.md)** — fleet-wide container restart tracking;
 image-registry SSRF hardening.

## Feature guides

- **[cmdb.md](cmdb.md)** — Per-asset metadata, Markdown documentation,
 and the encrypted credential vault (AES-GCM + PBKDF2). Threat model,
 API reference, backup story, disaster recovery.
- **[drift.md](drift.md)** — Configuration drift detection: what's
 watched, customising the list, re-baselining, the compliance angle.
- **[mcp.md](mcp.md)** — MCP server setup, Claude Desktop config, the
 read-only tools, security model, troubleshooting.
- **[scripts.md](scripts.md)** — Multi-line script library, dry-run
 linting, batch execution.
- **[compose.md](compose.md)** — docker compose dropdown on device cards.
- **[containers.md](containers.md)** — Docker / Podman / Kubernetes pod
 listings.
- **[network-map.md](network-map.md)** — Manual topology graph from
 `connected_to` links.
- **[agentless-devices.md](agentless-devices.md)** — Manual records for
 switches, APs, printers, IPMI cards.
- **[tls-monitor.md](tls-monitor.md)** — Server-side TLS / DNS expiry
 probes.
- **[update-history.md](update-history.md)** — Captured `apt` / `dnf` /
 `pacman` upgrade output.
- **[swagger.md](swagger.md)** — OpenAPI / Swagger UI details.
- **[ai.md](ai.md)** — Optional AI assistant (Anthropic / OpenAI /
 DeepSeek / Ollama / LocalAI), button inventory, privacy redaction,
 rate limiting, nginx config for slow local models.
- **[prometheus-metrics-sample.txt](prometheus-metrics-sample.txt)** —
 Example `/api/metrics` output for Grafana scrape config.
- **screenshots/** — UI screenshots referenced from the main README.
