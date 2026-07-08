# Security review — v6.1.0 "Runt1meMatters"

RemotePower is a defensive fleet-management product. Every release goes through a
security pass before it ships; this note is the public record for v6.1.0. The bar
is simple and non-negotiable: **no Critical, High or Medium finding — and nothing
exploitable — ships.**

v6.1.0 is unusual in scope: it replaces the server's transport stack (CGI/fcgiwrap
+ an SCGI worker → a native Flask app served by gunicorn) and makes Postgres +
the out-of-band scheduler + a co-located scanner satellite the single-node
default, instead of each being opt-in. Introducing a new deployment topology is
exactly the kind of change that tends to open new classes of bug that a mature,
already-hardened code path doesn't have — so this review leaned harder on the new
surface than a typical incremental release.

## What was reviewed

- **Static analysis (SAST).** CodeQL (the GitHub `security-extended` Python +
  JavaScript suites), Bandit and Gitleaks all run locally and report **clean**
  (zero new findings; the small set of rule-level exclusions are documented,
  individually triaged false positives — never any injection, SSRF, XSS or auth
  rule). Semgrep (`--config auto`) was also run; every finding was triaged and is
  either a false positive or an already-documented accepted trade-off.
- **Multi-agent code review.** A structured, independently-verified review of the
  full session diff (81 changed files): several finder passes covering
  correctness and cleanup, followed by an independent verifier for every distinct
  finding location. 5 findings were reported this way; all 5 were CONFIRMED by
  verification and fixed (below).
- **Manual audit.** Beyond the automated passes, the Flask request/response
  bridge (`server/cgi-bin/wsgi.py`) was independently exercised end-to-end
  (direct WSGI calls outside any framework, concurrent-thread load, and an
  external-stdout-reassignment scenario) to validate the "no cross-request state
  leak" claim in its own docstring — this surfaced a 6th finding not caught by
  the review pass above (below).
- **Content-Security-Policy.** Unchanged by this release: `default-src 'self'`
  with `script-src 'self'` and `style-src 'self'`, no `unsafe-inline`, verified
  live, alongside HSTS (preload), `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, a locked-down `Permissions-Policy` and a
  `report-uri` for violations.

## Findings

All six findings below were caught and fixed **before** this line was promoted
to production — none shipped. They're recorded here in full because the bar is
"nothing exploitable ships," not "nothing was ever found."

**Client-IP resolution broke under the new proxy_pass transport.** The CGI→
gunicorn cutover replaced nginx's direct `fastcgi_param REMOTE_ADDR $remote_addr`
with a real second TCP hop (`proxy_pass` to gunicorn on loopback) plus
`X-Real-IP`/`X-Forwarded-For` headers — but `api.py`'s client-IP resolver read
`REMOTE_ADDR` unconditionally and never looked at the new headers, so by default
every request appeared to originate from `127.0.0.1`. That silently defeats the
IP allowlist (an admin restricting `/api/` to their office CIDR would lock
themselves out, or make the allowlist a global bypass if `127.0.0.1` were ever
listed), collapses enrollment rate-limiting to one shared bucket, and makes audit
`source_ip` fields useless. Fixed: the resolver now trusts `X-Forwarded-For` /
`X-Real-IP` whenever the immediate peer *is* loopback — a real remote client
cannot forge `REMOTE_ADDR == 127.0.0.1` without a TCP handshake from localhost,
so this is a narrower, always-safe trust boundary that doesn't require the
operator to separately enable the load-balancer-oriented `trust_proxy` flag for
the local proxy hop this repo itself sets up.

**Postgres auto-migration could silently overwrite live data.** The new
single-node Docker topology gates the JSON→Postgres bootstrap migration on a
`.pg_migrated` marker file living on the app-data volume, which has an
independent lifecycle from the actual Postgres volume. Resetting only the
app-data volume (e.g. to force-regenerate the admin account) made the container
think it was booting for the first time, re-running the migration and
overwriting live Postgres users/config/satellite rows with a freshly
re-bootstrapped, near-empty snapshot — with only a generic log line, no warning.
The same volume-independence also let deleting only `users.json` print
"generated admin credentials" that could never actually log in, since the
migration (and therefore the credentials that would make them real) was skipped.
Fixed: both the admin-bootstrap step and the migration step now query Postgres
directly for existing data before acting, instead of trusting a marker file that
can drift out of sync with the store it's meant to guard.

**Postgres shipped with a well-known default password, enabled by default.**
Previously the Postgres service was fully commented out (opt-in); it's now on by
default with a published, static password unless the operator sets
`RP_PG_PASSWORD`. The database isn't exposed to the host, but any other
container sharing the compose network could connect with the known credential.
Mitigated: the container now prints a loud, repeated warning on every boot when
the default password is still in use, alongside the existing code comments
pointing at `RP_PG_PASSWORD=<random>`.

**A Flask routing gap could reject non-standard HTTP methods before they ever
reached the app.** The new Flask catch-all route explicitly lists 7 HTTP
methods; any other verb got a framework-generated, non-JSON 405 from Werkzeug,
bypassing `api.py`'s own error format and security pipeline entirely — a
behavior change from every prior transport, which passed any method through
unconditionally. Fixed with a `405` error handler that falls through to the same
request-handling path as every other method.

**The response-capture proxy could be silently defeated by anything that
reassigns `sys.stdout`.** Found during manual verification of the Flask bridge,
not the structured review pass. `wsgi.py` installs a proxy over `sys.stdout` once
at import time so `respond()`/`HTTPError` output lands in the correct
per-request buffer. If anything later reassigns `sys.stdout` wholesale — verified
directly with a stand-in capture object — the proxy is silently discarded: the
next request's real response content is written to whatever now owns
`sys.stdout` instead of the request buffer, and the client gets a 200 with an
**empty body**. Reproduced and confirmed with a minimal script before fixing.
Fixed by re-verifying (and reinstalling if needed) the proxy at the start of
every request instead of assuming it survives for the life of the process.

## Posture in brief

bcrypt-hashed passwords (with a PBKDF2-HMAC-SHA256 fallback) behind rate-limited
login; TOTP two-factor with one-time recovery codes; constant-time token
comparison; per-endpoint authorization resolved from role permissions (not a role
name allowlist); secrets redacted from every read API and encrypted at rest;
every outbound integration behind a connect-time SSRF guard with no redirects;
the agents post their telemetry over a no-redirect opener so a token can never be
replayed or downgraded. This release's new default topology (Postgres, gunicorn/
Flask, the out-of-band scheduler, a co-located scanner satellite) now carries the
same bar as the rest of the product.

Security is a feature here, and we'd rather over-share the process than under-test
the product. If you find something, please open a report.
