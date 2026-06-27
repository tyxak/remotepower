# Security review — v5.3.0 "ResolveMatters"

Status: released with v5.3.0 (2026-06-27). No breaking changes.

## Scope

v5.3.0 adds a built-in, opt-in **ticket system** (helpdesk) and an internal
**Contacts** directory, and was accompanied by a whole-project finalize sweep.
The new attack surface reviewed here is: the ticket and contact API handlers; the
inbound-email parser and dedicated-IMAP poller (which ingests attacker-influenced
mail and can auto-create tickets); outbound email (operator-supplied recipients,
subjects and a per-user HTML signature); the ticket↔alert linkage (auto-ack on
open, auto-resolve on close); and the new `tickets` AI/RAG source. The review also
re-covered the whole project, not just the new code.

## Tooling

A clean run of all static-analysis tools was required, plus a live authenticated
penetration test of the production deployment.

- **CodeQL** (the GitHub default `python` + `javascript` security suites, run
  locally via `tools/codeql-local.sh`, honouring the committed
  `.github/codeql/codeql-config.yml`): **0 results** across both languages.
- **bandit** (`-r server/cgi-bin client -b .bandit-baseline.json`): **0 new**
  findings beyond the triaged baseline; no HIGH introduced.
- **semgrep** (`--config auto`): no real findings — every hit maps to a previously
  triaged, by-design class (SSRF-guarded outbound fetches, the agent's by-design
  root command channel, deliberate 0600/0700 secret files, legacy-TLS probe
  ciphers, size-capped/DOCTYPE-rejecting XML parsing, a hardcoded `PRAGMA` literal).
- **gitleaks** (`-c .gitleaks.toml`, current tree + full history, and `--no-git`):
  **no leaks**.
- **Live pentest** (authorized, against the production site): a full
  Content-Security-Policy with **no `unsafe-inline`** (`script-src 'self'`,
  `style-src 'self'`), HSTS with `preload`, `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, and COOP/CORP. Unauthenticated and bad-token
  API calls return `401` (not `500`); a top-level JSON-array body to the ticket /
  contact endpoints returns `400` (not `500`); unknown routes return a clean JSON
  `404` with no stack trace. `GET /api/config` withholds all secrets — the ticket
  IMAP and SMTP passwords are reduced to a boolean indicator and never echoed.
- **Unit gate**: the full suite passes on both the JSON and SQLite storage backends.

## Ticket / helpdesk security model

The new code was audited against the project's recurring vulnerability classes:

- **Cross-site scripting:** every value the ticket and contact UIs render — subjects,
  conversation messages (including inbound email bodies and the attacker-controlled
  `From`/`Subject`), assignees, groups, device names, contact fields — is escaped
  (`escHtml`/`escAttr`); `mailto:`/`tel:` schemes are hardcoded. The per-user HTML
  signature is only ever emitted into an outbound email body (the recipient's mail
  client) and read back into a `<textarea>` value — never into the app DOM — so it
  is not stored XSS. CodeQL's XSS queries report 0.
- **Authorization & IDOR:** ticket delete, SLA-target save, contact writes and the
  IMAP get/save/test endpoints all require admin; admin gating resolves the role
  record rather than a string denylist. The IMAP password is returned only as a
  `password_set` boolean.
- **Email-header injection:** the outbound mailer now strips CR/LF from
  operator-supplied recipients and subjects before they enter mail headers
  (defence-in-depth).
- **Mail loop / injection via inbound mail:** the IMAP poller skips auto-submitted,
  bulk and the system's own (`X-RP-Ticket`) messages; auto-created tickets use a
  reserved number band so they cannot collide with alert-derived numbers.
- **Lock safety:** the ticket and contact handlers fire `audit_log()` and the
  cross-store alert-resolve **outside** their data-store lock (collect-then-fire),
  so there are no nested locks that could silently drop an audit row under SQLite.
- **SSRF:** the ticket system's only outbound connections are to the
  admin-configured SMTP and IMAP servers — the same trust model as the existing
  notification SMTP — not a user-supplied URL sink.

## Findings fixed before release

Two issues were found and fixed; neither is exploitable in a default deployment.

- **Medium — strict-mode alert-permission bypass via the ticket path.** When a
  deployment opts into least-privilege by setting `viewers_can_ack_alerts=false`,
  direct alert ack/resolve correctly requires admin. The ticket path did not apply
  the same gate, so a viewer could acknowledge an alert (by opening a ticket from
  it) or resolve it (by closing a linked ticket). Fixed: the ticket operation still
  succeeds, but its alert side-effect is now suppressed for non-admins in strict
  mode. (No effect under the default `viewers_can_ack_alerts=true`.)
- **Low — email-header CRLF (defence-in-depth).** Header values are now stripped of
  CR/LF, as above.

## Posture

No Critical, High or Medium issues remain. There is nothing in this release we
consider exploitable. Static analysis (CodeQL, bandit, semgrep, gitleaks) is clean,
the live deployment presents a strong header and authentication posture, and the
test suite is green on both storage backends.
