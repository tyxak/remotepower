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

## v2.1 features and release notes

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
- **[prometheus-metrics-sample.txt](prometheus-metrics-sample.txt)** —
  Example `/api/metrics` output for Grafana scrape config.
- **screenshots/** — UI screenshots referenced from the main README.
