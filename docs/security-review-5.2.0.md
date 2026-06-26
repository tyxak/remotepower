# Security review — v5.2.0 "AccessMatters"

Status: released with v5.2.0 (2026-06-26). No breaking changes.

## Scope

v5.2.0 adds **WG Access**, a built-in light WireGuard road-warrior VPN whose hub
is the RemotePower server host itself (userspace `wireguard-go`). Because the hub
is the server — not an enrolled device — the feature follows the *integrations*
pattern: configuration is applied through a small, root-owned privileged helper
(`remotepower-wg-apply`) that the unprivileged CGI invokes with a structured,
argv-only JSON spec, mirroring the existing site-deploy precedent. This review
covers that new code (the `wg_access.py` module, the WG Access API handlers, the
root helper, and the browser keygen/QR UI) and the whole-project finalize sweep
that accompanied it.

## Tooling

A clean run of all three static-analysis tools was required, plus a live
authenticated penetration test of the production deployment.

- **CodeQL** (the GitHub default `python` + `javascript` security suites, run
  locally via `tools/codeql-local.sh`, honouring the committed
  `.github/codeql/codeql-config.yml`): **0 results** across both languages.
- **bandit** (`-r server/cgi-bin client -b .bandit-baseline.json`): **0 new
  findings** beyond the triaged baseline; no HIGH introduced. The root helper
  (`remotepower-wg-apply`) is argv-only with no `shell=True`.
- **gitleaks** (`-c .gitleaks.toml`, current tree + full history, and
  `--no-git`): **no leaks**.
- **Live pentest** (authenticated, against the production site): a full
  Content-Security-Policy with **no `unsafe-inline`** (`script-src 'self'`,
  `style-src 'self'`, `frame-ancestors 'none'`), HSTS with `preload`,
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
  `Cross-Origin-Opener-Policy`/`Cross-Origin-Resource-Policy`, and a
  referrer/permissions policy. Unauthenticated and bad-token API calls return
  `401` (not `500`); a top-level JSON-array body returns `400` (not `500`);
  unknown routes return a clean JSON `404` with no stack trace; a traversal
  attempt returns `404`. The `GET /api/config` response withholds all secrets
  (webhook URL and AI key reduced to a boolean indicator).
- **Unit gate**: the full suite passes on **both** the JSON and SQLite storage
  backends (`make test` and `make test-sqlite`).

## WG Access security model

The new feature was audited against the project's recurring vulnerability
classes. All were clean:

- **Privilege boundary.** The CGI worker stays unprivileged. The single
  root-owned helper validates every attacker-influenceable field a second time
  (interface name, UDP port, public key, CIDR, booleans) with strict regex/range
  checks before any `ip`/`wg`/`nft` call, and runs them as argv lists — never a
  shell. The sudoers grant is scoped to that one script.
- **Key handling.** Client keypairs are generated **in the browser** (X25519,
  verified against the RFC 7748 test vector); the private key is never sent to
  the server. The persisted store holds only public data (public keys, addresses,
  connection state) — no private keys.
- **Authorization.** Every mutating endpoint is admin-only; reads are
  admin/auditor. Tunnel and client identifiers are validated and used only to
  match store entries, never as filesystem paths.
- **Lock discipline / events.** The three new events
  (`vpn_client_connected` / `vpn_client_disconnected` / `vpn_handshake_stale`)
  are registered through every server- and client-side registry, and all
  self-locking calls (audit log, webhooks) fire outside the store lock.
- **XSS / CSP.** The WG Access UI builds its QR and `.conf` download with DOM
  APIs and escapes all server data; there are no inline event handlers or styles.

## Findings fixed

No Critical, High or Medium findings. The items below are Low-severity
robustness and defence-in-depth fixes addressed during the sweep so that
automated code scanning stays clean and there is nothing exploitable.

### Disabling a tunnel now tears it down (Low — correctness/expectation)
Setting a tunnel to *disabled* re-synced it, which silently brought the WireGuard
interface back up and re-installed every client — so an administrator who
disabled a tunnel to cut off access did not actually do so. A disabled tunnel is
now brought **down** (and back up only on re-enable). A regression test covers
both directions.

### Dashboard-only tunnel confinement (Low — defence in depth)
A "dashboard-only" tunnel (no internet, empty reach scope) deliberately installs
no forwarding rules, so its peers can reach only the hub. Confinement previously
relied on the host's global `ip_forward` state and baseline forward policy. The
helper now installs an explicit per-interface nftables drop chain for
non-forwarding tunnels, so isolation holds regardless of any other tunnel having
enabled forwarding globally.

## Whole-project sweep

Beyond WG Access, the finalize sweep ran the data-binding, bug, UI/box-overflow,
typography, i18n/CSP and documentation audits across the entire project. The
flagship-feature data is now bound where it belongs: WG Access posture feeds the
fleet-knowledge (RAG) index and a new Remote-access review AI advisor, and the
previously-collected tunnel rollup statistics (pool utilisation, throughput) and
each client's source endpoint are now shown in the UI. A duplicate byte-formatter
was removed and the WG Access table strings localised.

## Reporting

Security contact and disclosure policy are in [security.md](security.md). We aim
to ship nothing exploitable: no Critical, High or Medium finding ships.
