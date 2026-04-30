# RemotePower documentation

Long-form docs for individual features. The main `README.md` at the
repo root is the place to start; this folder is for the things that
need more than a paragraph.

## Index

- **[CMDB & credential vault](cmdb.md)** — per-asset metadata,
  Markdown documentation, and the encrypted credential vault
  (AES-GCM + PBKDF2). Threat model, API reference, backup story,
  and the disaster-recovery section you'll wish you'd read sooner.
  *(v1.9.0)*
- **[Swagger / OpenAPI](swagger.md)** — interactive API docs at
  `/swagger.html`, the spec at `/api/openapi.json`, and notes on
  air-gapped deployment + client-SDK generation. *(v1.10.0)*
- **[Update history](update-history.md)** — capture and review
  output from `apt`/`dnf`/`pacman` upgrades. Why it works the way
  it does, what's captured, and the API for scripting. *(v1.10.0)*
- **[Container awareness](containers.md)** — Docker / Podman /
  Kubernetes pod listings reported by agents. Detection logic,
  caps, what's not captured, troubleshooting. *(v1.11.0)*
- **[Network map](network-map.md)** — manual topology graph from
  `connected_to` links. Why manual, what the layout looks like,
  why agentless devices matter for it. *(v1.11.0)*
- **[Agentless devices](agentless-devices.md)** — manual records
  for switches, APs, printers, IPMI cards, cameras. What works
  and what doesn't (no probing in v1.11.0). *(v1.11.0)*
- **[TLS / DNS expiry](tls-monitor.md)** — server-side probes
  with cron schedule, status thresholds, internal-vs-external
  considerations. *(v1.11.0)*
- **[Prometheus metrics sample](prometheus-metrics-sample.txt)** —
  example output of `/api/metrics` for Grafana scrape config
  reference.
- **screenshots/** — UI screenshots referenced from the main README.
