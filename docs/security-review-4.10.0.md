# Security review — v4.10.0 "PerimeterMatters"

RemotePower is reviewed for security on every release. This document summarises
the v4.10.0 pass. The bar we hold ourselves to is simple and explicit:

> **No Critical, High, or Medium severity finding ships.** Anything that could be
> exploited is fixed before release, on both the server and the agent.

## Scope

A whole-project review — not just the new code — covering:

- **Server** (`api.py` and its sibling modules: integrations, DNS zones/resolve,
  resolver health, IP reputation, DMARC monitor, TLS monitor, AI/RAG, CVE
  scanner, storage backends).
- **Agent** (Linux/Windows/macOS collectors, command execution, self-update,
  containerized mode).
- **Frontend** (Content-Security-Policy compliance, output escaping / XSS,
  event dispatch).

The new attack surface this release — the **Security → Firewall** page, which can
view and edit nftables/iptables/ufw/firewalld rules and fail2ban jails — received
focused attention.

## Method

The code was audited by hand across seven axes — authentication / RBAC, command
and argument injection, SSRF, alert/lock integrity, secret handling, and the
containerized-agent host boundary — and exercised with the static and dynamic
tooling we use every cycle: **bandit, semgrep, gitleaks, njsscan, nuclei and
wapiti**, plus manual probing (auth/RBAC, SSRF, path traversal, injection,
brute-force) against a live instance.

## Result

**No Critical or High findings.** The release bar is met.

The headline new feature is safe by construction: **every firewall and fail2ban
edit is server-validated against a strict character allowlist, permission-gated
(`command` permission), written to the audited command queue, and skipped on
quarantined hosts** — there is no path from the UI to an arbitrary shell command
that the operator could not already run with that permission.

A small number of **Medium/Low** hardening items were found and **fixed in this
release**:

| Sev | Area | Fix |
|-----|------|-----|
| Medium | Containerized agent — file-integrity (drift) monitoring | The drift hasher now reads the Docker **host's** files through the host-path mapping, so a containerized agent can't be blind to host-side tampering. |
| Low | firewalld rule delete | The port/service value is now validated to its exact firewalld shape, so no extra command argument can be appended. |
| Low | TLS monitor SSRF guard | IPv6-encoded forms of the cloud-metadata address (IPv4-mapped, 6to4, NAT64) are now unwrapped and blocked, and multicast is blocked. |
| Low | Containerized agent — host reads | `authorized_keys` and mailbox-count collectors now use the host-path mapping. |
| Low | 2FA setup | The provisioning secret is HTML-escaped on render (defense-in-depth; the value is a fixed-alphabet base32 string with no injection surface). |

## Standing posture (unchanged, verified this cycle)

- **CSP is fully migrated** — production serves `script-src 'self'; style-src
  'self'` with no `unsafe-inline`; there are zero inline event handlers or inline
  styles in the HTML or the rendered markup. Output is escaped at every
  data-controlled sink.
- **SSRF-safe outbound** — every outbound integration (webhooks, homelab
  connectors, DNS providers, AI providers, web-push, monitors) goes through a
  pre-flight that blocks link-local/metadata targets, re-checks the peer at
  connect time, and refuses redirects.
- **Alert integrity** — webhook/alert recorders are never called while a storage
  lock is held, and every recover/clear event resolves its alert.
- **Secrets** — at rest, secrets are redacted from config reads by name; session
  tokens are stored hashed; the data file is `0600`.
- **Transport** — full HSTS (preload), frame-deny, nosniff, a strict
  permissions-policy, and TLS 1.2+ with the agent pinning the server's CA.

## Transparency

We publish this review because we think security posture should be legible, not
asserted. If you find something, we want to hear about it — see
[security.md](security.md) for how the project handles disclosure and the
durable list of controls.
