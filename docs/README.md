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
- **[Prometheus metrics sample](prometheus-metrics-sample.txt)** —
  example output of `/api/metrics` for Grafana scrape config
  reference.
- **screenshots/** — UI screenshots referenced from the main README.
