# Security review — v6.3.0 "Fl0wMatters"

RemotePower is a defensive fleet-management product. Every release goes through a
security pass before it ships; this note is the public record for v6.3.0. The bar
is simple and non-negotiable: **no Critical, High or Medium finding — and nothing
exploitable — ships, on the server or the agent.**

v6.3.0 is a UX and quality release, but its security pass was run as a full,
whole-codebase audit rather than a changes-only one — the multi-tenant isolation
surface in particular is reviewed exhaustively every release, because that class
of bug hides in handlers untouched by the release itself.

## What was reviewed

- **Static analysis (SAST).** CodeQL (Python + JavaScript security suites, run
  through the same configuration the production scan uses), Bandit and Gitleaks
  all report **clean**: Bandit **zero new issues** against its reviewed baseline;
  Gitleaks reports no leaks across the full git history and the working tree.
  CodeQL surfaced a single new result — the new agentless syslog receiver
  (`remotepower-syslogd`) binds its UDP listener to all interfaces. That is the
  receiver's entire purpose (it must accept syslog from switches, firewalls and
  printers across the network); it is opt-in and disabled by default, validates
  every datagram's source address against the enrolled-device set, holds no
  secrets, forwards only over loopback, and its bind address is operator-
  overridable. It is the same by-design pattern Bandit already baselines, and is
  documented as a reviewed, individually-triaged exclusion — no injection, SSRF,
  XSS or authentication rule is ever suppressed.

- **Live black-box pass.** The production edge was probed unauthenticated (the
  surface any remote attacker actually sees). It sits behind a single sign-on
  gateway; the application serves a strict Content-Security-Policy
  (`script-src 'self'`, no `unsafe-inline`), HSTS with preload, `nosniff`,
  `frame-ancestors 'none'`, and a locked-down permissions policy; TLS verifies;
  malformed, array-typed and wrong-method request bodies return correct 4xx
  responses rather than 500s.

- **Adversarial review across the recurring dimensions.** Independent deep passes
  over authentication, RBAC and multi-tenant isolation; server-side request
  forgery; injection (command, SQL, path, XML, header); frontend cross-site
  scripting and CSP integrity; the agents' HTTP and host-fact handling; and
  secrets, cryptography and token handling. Findings were confirmed by driving
  the real code paths, not by reading alone.

## Findings fixed before release

The audit surfaced a set of **pre-existing** issues (not v6.3.0 regressions),
concentrated as usual in the multi-tenant isolation surface. All were fixed and
covered with regression tests before this release. Each fix is a **no-op on a
single-tenant, unscoped install** — it only changes behaviour where tenant
isolation or role scoping is actually in use.

- **Cross-tenant certificate control (ACME).** The ACME write endpoints — issue,
  force-renew, revoke and cancel a certificate — sit under a path prefix that the
  pre-dispatch device-scope enforcement does not cover, and gated on the admin
  role only. On a multi-tenant install a tenant administrator could therefore
  queue a certificate operation on another tenant's host. All four now enforce
  the tenant-and-scope check at the shared command funnel, matching their
  already-correct read siblings.
- **Cross-tenant alert data.** Three read surfaces — the dashboard Tickets card,
  the alert resolution-statistics (MTTR/MTTA) endpoint, and the alert-tuning
  endpoint — filtered by role scope alone. Because a tenant administrator has no
  *role* scope, that check was skipped for them and each surface returned alert
  data (hostnames, titles, timelines, who-acknowledged) across every tenant. All
  three now apply the shared visibility filter that combines role scope **and**
  the tenant gate, the same filter the alerts list and summary already use.
- **Cross-tenant credential metadata.** The inherited-credentials endpoint
  (`GET /api/cmdb/{id}/inherited-credentials`) confirmed the existence of another
  tenant's device and returned the metadata of the scoped credentials that apply
  to it. It now goes through the canonical device tenant-and-scope block. (Secret
  *values* were never exposed here — reveal is a separate, separately-gated
  endpoint — but the metadata leak and existence oracle are closed.)
- **Stored cross-site scripting via SNMP.** A polled device's `sysUpTime` value
  was rendered into the device drawer and CMDB view without HTML-escaping, while
  every neighbouring SNMP field was escaped. SNMP v1/v2c is unauthenticated UDP,
  so a hostile or spoofed responder could return that field as text containing
  markup, which was then stored and re-rendered in an administrator's session. It
  is now escaped at both UI sinks and coerced to an integer on ingest (it is a
  numeric counter), so attacker-controlled text can neither be stored nor rendered.

Each of the five fixes is pinned by a regression test that drives the real handler
with only the caller's identity stubbed — so a test passes only if the gate is
genuinely present, and a handler with no gate at all would fail.

## Second pass — the new backup subsystem

The v6.3.0 backup work (structured file-backup jobs that generate commands run as
root on hosts, a multi-device "baseline", restore, and an archive browser) got its
own dedicated adversarial pass, since generating root commands is exactly where a
subtle flaw is most costly. All findings were fixed and regression-tested before
release.

- **Cross-tenant backup-job control (fixed).** The backup-job **list / update /
  delete** endpoints matched a job by its id alone — the *run*, *restore* and
  *archive* endpoints already re-filter through the shared scope/tenant chokepoint,
  but these three did not. On a multi-tenant install a tenant administrator could
  therefore read another tenant's job definitions (including destination hosts and
  the command text of legacy jobs, which can embed secrets), delete their jobs, or
  edit a job's command/schedule and let the scheduler run it as root on the other
  tenant's hosts. All three now gate on whether every one of the job's target
  devices is in the caller's scope, returning "not found" otherwise — a no-op on a
  single-tenant install. This is the same device-keyed-store isolation class fixed
  for the alerts store in a prior release.
- **Command-generation stayed injection-proof under stress.** Every field that
  reaches the generated shell command — source paths, host, user, remote path, NFS
  export, SMB share, credentials-file path, port, archive name, job id — is
  validated against a strict allowlist (absolute paths only, no shell
  metacharacters, no `..` traversal) *and* quoted; a battery of injection attempts
  (command substitution, backticks, pipes, semicolons, newlines, globs) was
  rejected. One gap was found and closed: the SMB **share** name allowed `/` and
  `..`, so it could form a traversing `//host/../..` UNC — it is now restricted to
  a single component. No credential ever appears in a generated command (ssh uses
  key auth, NFS needs none, SMB references a host-side credentials file).

## A safety improvement worth calling out

- **Backups now warn when written unencrypted at rest.** RemotePower encrypts its
  disaster-recovery archives (AES-256-GCM) when a passphrase is provided out-of-
  band, and refuses to write plaintext when a passphrase is set but the crypto
  library is missing. When *no* passphrase is configured, a scheduled backup is
  written in plaintext — and that archive contains the whole data directory,
  including session tokens, hashed passwords, configuration secrets and the CMDB
  vault. This was previously silent. It now emits a clear warning on every
  plaintext write; the self-status page already reports the plaintext-archive
  count, and the "Encrypt existing backups" action re-encrypts archives already
  on disk. Operators who want encryption on by default set the backup passphrase
  environment variable (or a passphrase command that fetches from a vault/KMS).

## Surfaces confirmed clean

SSRF is fully hardened — every operator-influenceable outbound request goes
through a connect-time peer-IP re-check with redirects disabled, and every
identifier interpolated into an outbound URL path is reduced to a single quoted
segment or validated to a strict character set. The agents route all HTTP through
a no-redirect opener and read every host fact through the container-aware path
helper. Untrusted XML is parsed through the entity-rejecting safe parser at every
call site. Config-secret redaction withholds every token, password and
URL-with-embedded-secret on `GET /api/config` for all roles including admins.
The command-queue family that takes device targets from the request body is
tenant-filtered at its shared chokepoint, and enforced by a structural test that
fails the build for any new ungated body-device handler.

## Bottom line

SAST is clean across all tools (the one CodeQL result is the by-design syslog
listener, triaged and documented); the live edge is correctly hardened; the
adversarial passes found no remaining exploitable issue; the pre-existing
cross-tenant and stored-XSS gaps were fixed and regression-tested; and the new
backup subsystem's own pass fixed a cross-tenant job-control gap and an SMB-share
traversal, with the root-command generator verified injection-proof under a
battery of attacks. Every fix is regression-tested and no-op on a single-tenant
install. No Critical, High or Medium finding ships in v6.3.0.
