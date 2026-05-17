# RemotePower documentation

The main `README.md` at the repo root is the place to start. This folder
holds long-form docs that don't fit there.

## Getting started

- **[install.md](install.md)** — Server install (Linux + Docker), client
  enrolment, optional webterm, demo vhost.
- **[features.md](features.md)** — Full feature inventory and the
  per-feature guide.
- **[architecture.md](architecture.md)** — How the pieces fit together,
  the heartbeat → command → response cycle, file layout on disk.
- **[upgrading.md](upgrading.md)** — Migration steps between versions.
- **[troubleshooting.md](troubleshooting.md)** — Common issues and
  diagnostics.

## Reference

- **[api.md](api.md)** — REST endpoints + auth model. Interactive at
  `/swagger.html`; spec at `/api/openapi.json`.
- **[agent-commands.md](agent-commands.md)** — CLI for the Linux agent.
- **[windows-client.md](windows-client.md)** — Windows-specific notes,
  install path, service control.
- **[https.md](https.md)** — TLS termination at nginx with acme.sh or
  Let's Encrypt.
- **[security.md](security.md)** — Threat model and on-disk data layout.

## v2.2 features and release notes

- **[v2.4.4.md](v2.4.4.md)** — 2.4.4 (fixes the mailbox monitor heartbeat bug; favicon.ico restored; config moved to Settings).
- **[v2.4.3.md](v2.4.3.md)** — 2.4.3 (lightweight mailbox-count monitor: agent counts Maildir files, dashboard widget).
- **[v2.4.2.md](v2.4.2.md)** — 2.4.2 (default SSH username, quick SSH link on Devices, Proxmox/snapshot documentation).
- **[v2.4.1.md](v2.4.1.md)** — 2.4.1 (bugfix: stale CVE cache re-served pre-2.3.4 severities; cache-version invalidation).
- **[v2.4.0.md](v2.4.0.md)** — 2.4.0 (Proxmox VM/LXC snapshots; CVE Debian-urgency severity fix).
- **[v2.3.4.md](v2.3.4.md)** — 2.3.4 (CVE severity fix, unmonitored devices excluded from activity, drift ignore, nav move).
- **[v2.3.3.md](v2.3.3.md)** — 2.3.3 (bugfix: Virtualization nav entry always visible).
- **[v2.3.2.md](v2.3.2.md)** — 2.3.2 (security release: PBKDF2 password hashing, default-password warning) — see also [security-review-2.3.2.md](security-review-2.3.2.md).
- **[v2.3.1.md](v2.3.1.md)** — 2.3.1 (security: Proxmox token via env var, backup export redacts secrets).
- **[v2.3.0.md](v2.3.0.md)** — 2.3.0 (Proxmox VE integration: Virtualization page for QEMU VMs, LXC on the Containers page, server-to-API).
- **[v2.2.7.md](v2.2.7.md)** — 2.2.7 (mobile drawer hotfix).
- **[v2.2.6.md](v2.2.6.md)** — 2.2.6 (CVE scanner false-positive
  fix, Docker hardening, mobile modal stacking, drift dormant
  handling + expanded watch list, agent host-health telemetry,
  container CPU/mem).
- **[v2.2.5.md](v2.2.5.md)** — 2.2.5 (container width 1300 px,
  >20-row table scroll wrap, clickable activity items, favicon
  deploy fix, hover-affordance strip removed).
- **[v2.2.4.md](v2.2.4.md)** — 2.2.4 fix (dedicated fleet event log
  so events show on Home regardless of webhook/email config;
  unmonitored devices excluded from "Needs attention").
- **[v2.2.3.md](v2.2.3.md)** — 2.2.3 hotfix (Home dashboard
  activity panel filters out operator SMTP / webhook test entries).
- **[v2.2.2.md](v2.2.2.md)** — 2.2.2 hotfix (hover-action focus
  ring clipping; webhook log endpoint mismatch in Home dashboard;
  pre-existing `handle_webhook_log` 500 on bare-list file shape).
- **[v2.2.1.md](v2.2.1.md)** — 2.2.1 release notes (design polish:
  distro logos, sparklines, refined palette, skeleton loaders,
  Home dashboard, ✨ identity extended, typography upgrade, hover
  affordances, mobile layout, drift diff visualisation).
- **[v2.2.0.md](v2.2.0.md)** — 2.2.0 release notes (configuration
  drift detection + MCP server for natural-language fleet queries).
- **[drift.md](drift.md)** — configuration drift detection: how
  it works, what's watched, customising the list, re-baselining,
  compliance angle.
- **[mcp.md](mcp.md)** — MCP server setup, Claude Desktop config,
  the 12 read-only tools, security model, troubleshooting.

## v2.1 features and release notes

- **[v2.1.9.md](v2.1.9.md)** — 2.1.9 hotfix (runbook hallucination
  on smaller local models: num_ctx wiring, prompt rewrite, snapshot
  trimming; demo URL correction).
- **[v2.1.8.md](v2.1.8.md)** — 2.1.8 hotfix (AI fleet context was
  reporting every device offline; fixed to compute online status
  canonically from last_seen + TTL).
- **[v2.1.7.md](v2.1.7.md)** — 2.1.7 release notes (AI-generated
  device runbooks, Level-1 RAG context awareness, README polish,
  Documentation page expansion).
- **[v2.1.6.md](v2.1.6.md)** — 2.1.6 hotfix (Patches page Detail
  button + the long-missing modal element).
- **[v2.1.5.md](v2.1.5.md)** — 2.1.5 release notes (Investigate
  fix, Markdown rendering, heartbeat silence, grouped dropdown,
  four new ✨ surfaces, ai.md documentation).
- **[v2.1.4.md](v2.1.4.md)** — 2.1.4 release notes (JSON.parse fix for
  slow local Ollama models; standalone AI Assistant page).
- **[v2.1.3.md](v2.1.3.md)** — 2.1.3 release notes (optional AI assistant
  with five providers, About-page version fix).
- **[v2.1.2.md](v2.1.2.md)** — 2.1.2 release notes (critical fix for the
  lost-update race in heartbeats; new `_locked_update` primitive).
- **[v2.1.1.md](v2.1.1.md)** — 2.1.1 release notes (offline regression
  fix, real logging, 5-minute default TTL, log_alert matched-line,
  per-container actions).
- **[v2.1.0.md](v2.1.0.md)** — 2.1.0 release notes (flock fluctuation
  fix, auto-refresh stability, script library, batch exec, compose
  dropdown).
- **[scripts.md](scripts.md)** — Multi-line script library, dry-run
  linting, batch execution.
- **[compose.md](compose.md)** — docker compose dropdown on device cards.

## Inherited topical docs

- **[cmdb.md](cmdb.md)** — Per-asset metadata, Markdown documentation,
  and the encrypted credential vault (AES-GCM + PBKDF2). Threat model,
  API reference, backup story, disaster recovery. *(v1.9.0)*
- **[swagger.md](swagger.md)** — OpenAPI / Swagger UI details. *(v1.10.0)*
- **[update-history.md](update-history.md)** — Captured `apt`/`dnf`/
  `pacman` upgrade output. *(v1.10.0)*
- **[containers.md](containers.md)** — Docker / Podman / Kubernetes pod
  listings. *(v1.11.0)*
- **[network-map.md](network-map.md)** — Manual topology graph from
  `connected_to` links. *(v1.11.0)*
- **[agentless-devices.md](agentless-devices.md)** — Manual records for
  switches, APs, printers, IPMI cards. *(v1.11.0)*
- **[tls-monitor.md](tls-monitor.md)** — Server-side TLS / DNS expiry
  probes. *(v1.11.0)*
- **[ai.md](ai.md)** — Optional AI assistant (Anthropic / OpenAI /
  DeepSeek / Ollama / LocalAI), ✨ button inventory, privacy
  redaction, rate limiting, nginx config for slow local models.
  *(v2.1.3+)*
- **[prometheus-metrics-sample.txt](prometheus-metrics-sample.txt)** —
  Example `/api/metrics` output for Grafana scrape config.
- **screenshots/** — UI screenshots referenced from the main README.
