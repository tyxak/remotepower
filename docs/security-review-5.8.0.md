# Security review — v5.8.0 "WatchMatters"

*Date: 2026-07-04. Authorized review of the maintainer's own codebase and
infrastructure.*

This cycle ran a whole-project security pass over the product — not just the
release's new code. It combined the full committed SAST stack, an eight-stream
parallel manual audit (server auth/RBAC, SSRF, injection, XSS/CSP, secrets/crypto,
the agent root channel, data-binding, and dependencies), and a live authenticated
pentest of the maintainer's own running instance. Every reported finding was
hand-verified before fixing.

**No Critical or High issues were found.** Two Medium findings (both the same
root cause — an incomplete migration to permission-checked writes) and a set of
Low/defense-in-depth items were fixed before promotion. **Nothing Critical, High,
or Medium ships.**

## Tooling

| Tool | Result |
| --- | --- |
| **CodeQL** (GitHub default suites, python + javascript) | **0 results** |
| **bandit** (`-b .bandit-baseline.json`) | 0 new — 0 High |
| **gitleaks** (git history + working tree) | no leaks |
| **Live header/TLS review** (production instance) | strict CSP (no `unsafe-inline`), HSTS preload, `X-Frame-Options: DENY`, `nosniff`, COOP/CORP `same-origin`, `Permissions-Policy`, CSP reporting — all present |

The public "Code scanning" surface on GitHub is clean: CodeQL reports zero open
alerts across both languages.

## Live pentest (authorized, maintainer's own instance)

A one-time admin token was used against the maintainer's production instance to
confirm the deployed posture matches the code. All checks passed:

- **Authentication gating** — every sensitive read and every mutation
  (`POST`/`PATCH`/`PUT`/`DELETE`) returns `401` unauthenticated; the app sits
  behind an SSO proxy.
- **Secret redaction** — `GET /api/config` returns every secret-bearing field
  (webhook tokens, SMTP/LDAP/OIDC/SCIM/status secrets, Proxmox token secret) as a
  `*_set` boolean; no credential is echoed back, even to an admin.
- **Error handling** — malformed and array-typed request bodies return `4xx`, not
  `500`; malformed JSON is rejected by the front proxy with no stack trace.
- **Traversal / method hygiene** — path-traversal attempts return `404`;
  `OPTIONS` is refused; the CSP report endpoint accepts reports.

## Findings fixed

### Medium — read-only roles could mutate shared state (2 handler groups)

RemotePower has purely read-only roles (`viewer`, `mcp`, `auditor`, `finance`).
Two handler groups still gated on bare authentication instead of a write-capable
role, so a read-only principal could change state it shouldn't:

1. **Ticket create / update / log-hours.** A read-only token could open or edit a
   ticket (status, assignee, priority, messages, re-parenting) and — more
   importantly — append billable time entries that feed invoices. Now gated on a
   write-capable role, matching the ticket-email and ticket-delete handlers.
2. **Runbook generation.** A read-only token could overwrite a device's stored
   operational runbook and spend AI/cost budget (each call is a paid LLM request).
   Now gated on a write-capable role, matching runbook delete.

Both are one-line completions of an already-established pattern
(`require_write_role` — admin **or** a role with at least one action permission;
permission-based, not a role-string denylist).

### Low / defense-in-depth

3. **Agent HTTP now refuses redirects.** The agent posts its device token and full
   host telemetry to the server. It followed HTTP redirects, so a `307`/`308` could
   in principle replay the credential-bearing body to a redirect target, or an
   `https→http` hop could send the token in cleartext. The agent (Linux, Windows,
   macOS) now installs a no-redirect opener and refuses every `3xx` — mirroring the
   no-redirect hardening the server already applies to its own outbound calls.

4. **File-manager writes now act on the resolved path.** The agent's file-manager
   write/mkdir/delete operated on the pre-resolution path, leaving a narrow
   parent-directory symlink race on world-writable roots. They now operate on the
   already-resolved, already-allowlisted target — matching the read-path hardening
   from the previous cycle.

5. **`javascript:` scheme neutralized in operator-authored link sinks.** Several
   places render an operator-supplied URL into an `href` (CMDB hypervisor link,
   network-map links, alert ticket links, release-notes links). HTML-escaping
   stopped attribute breakout but not a `javascript:`/`data:` scheme. A shared
   helper now allowlists `http(s)` only. The production CSP already blocks such
   navigation, so this is belt-and-braces.

6. **Config secret-scrub backstop widened.** The recursive secret-key scrubber
   used a narrower name set than the encryption walk; it now matches the same set
   (adding `passphrase`, `community`, `bearer`) so a future global config key
   ending in one of those cannot slip past the scrub.

7. **Argument-terminator hardening.** The CVE version comparison (`dpkg
   --compare-versions`) and the fail2ban jail-name validator were tightened so a
   value beginning with `-` cannot be read as an option / a trailing newline cannot
   satisfy the pattern (integrity-only, argv not shell).

## Release-artifact hygiene

The release tarball packs the working tree, so its exclude list is the last line
of defense for local files. It was extended to exclude `*.env` / `.env` /
`*.pem` / `*.key` / `*.enc` / `.ssh` / scan bundles, and the build's leak gate now
fails loudly if any of those are present — the same class of guard added for the
session-tooling directory in the previous cycle.

## Verified clean (no change needed)

The eight recurring bug classes tracked in this codebase were each re-audited and
found clean, with guardrail tests in place: the permission-checked role model (no
role-string denylist regressions), SSRF (pre-flight DNS classification +
connect-time peer-IP recheck + no-redirect, with IPv4-mapped/6to4/NAT64 and
non-link-local metadata literals blocked), command/argument injection (argv-only,
allowlisted), XSS/CSP (escape-first rendering, no inline handlers or styles),
secret handling (read-time redaction to booleans, substring-matched secret
filtering into the AI corpus), IDOR/authorization, lock-nesting, and the
storage-backend-aware existence checks. SAML uses a vetted library with signed
responses/assertions; login enforces MFA with dual rate-limiting and timing-oracle
defense.

## Transparency

RemotePower is built to be run on infrastructure people care about, so security is
treated as a release gate, not an afterthought. Every release runs this process;
the bar is simple — **nothing Critical, High, or Medium ships, and nothing
exploitable ships.** Findings and their fixes are recorded here in the open. If you
find something we missed, please open a report on the repository.
