# RemotePower — Security Review (v4.4.1 "DocumentationMatters")

Date: 2026-06-13. Scope: triage of the **13 CodeQL code-scanning alerts** open on
`main` (1 Critical, 12 High), each read against the actual code path and the
feature/function that governs it. This release is a documentation-and-triage pass
on the heels of the security-themed v4.4.0; no new attack surface shipped.

**Verdict: all 13 alerts are false positives.** None represents an exploitable
vulnerability. Each is a known CodeQL limitation — an unrecognised custom
sanitizer, a same-origin request misread as cross-origin, or a non-security
identity/cache hash traced as if it protected a credential. The two genuinely
weak primitives in the flagged set (MD5 cache-key fingerprints) were already
non-security; they now carry `usedforsecurity=False` so the scanner agrees.

The durable description of RemotePower's security model remains
`docs/security.md`; the prior full audit is `docs/security-review-4.4.0.md`
(CRITICAL admin-gate escalation fix + independent pentest).

---

## Cross-site scripting / DOM-text-as-HTML (#33, #38, #39, #41, #42, #43, #44)

Seven alerts on `innerHTML =` assignments in `app.js` and `app-compliance.js`.

**False positive — every interpolated value is sanitized.** RemotePower renders
all dynamic HTML through two project sanitizers that CodeQL's default model does
not recognise:

- `escHtml(s)` (`app.js:3253`) — entity-encodes `& < > " '`. Used for text
  content (process names, log lines, package manager, command output, port
  proto).
- `escAttr(s)` (`app.js:3282`) — replaces every HTML-breaking character
  (`& < > " ' ` `` ` `` `\` newlines, LS/PS) with a `\xNN` escape, so a value can
  never break out of an attribute or introduce markup. Used for `data-*`
  attributes and `value="…"`.

Per alert:

| Alert | Location | Interpolated data | Covered by |
|---|---|---|---|
| #44 | `app.js` device-drawer commands | `o.cmd`, command output, `id` | `escHtml(o.cmd)`, `escHtml(outTxt)`; `id` is an internal device id |
| #43 | `app.js` device-drawer logs | unit, log line | `escHtml(e.unit)`, `escHtml(e.line)`, `escAttr(...)` on `data-*` |
| #42 | `app.js` device-drawer packages | manager, upgradable count | `escHtml(pkg.manager)`; count is numeric |
| #41 | `app.js` device-drawer ports | proto, port, addr, scope, process | `escHtml`/`escAttr` on every field; port is numeric |
| #39, #38 | `app.js` sort-indicator render | base label, arrow glyph, priority index | `baseLabel` is `textContent`; the rest are literal glyphs / integers — no user data |
| #33 | `app-compliance.js` target combo | option value, label | `escAttr(v)`, `escHtml(label)` |

No path reaches `innerHTML` with un-escaped attacker-controlled text. The strict
CSP (`script-src 'self'`, no `unsafe-inline`) is a second, independent barrier:
even a hypothetical injected `<script>`/`on*=` would not execute.

## Server-side request forgery (#45, Critical)

`app.js:932` — `r = await fetch('/api' + path, opts)`.

**False positive — same-origin API client.** This is the central front-end API
helper. The request target is the constant literal prefix `'/api'` concatenated
with an **internal, caller-supplied path**; it is always same-origin and never
takes a full URL, host, or scheme from user input. CodeQL's
`js/request-forgery` flags the data-flow into `fetch()` without modelling that
the destination is origin-pinned. There is no SSRF: a browser `fetch` to a
relative path cannot be redirected to an attacker host, and the server-side SSRF
surface (integration fetches) is governed separately by the anti-rebinding
opener reviewed in v4.4.0.

## Weak cryptographic hashing on sensitive data (#40, #34)

- **#40 — `api.py:3187` (audit chain).** **False positive — this is
  HMAC-SHA256, not a weak primitive.** `_audit_entry_hash` computes
  `hmac.new(_audit_hmac_key(), msg, hashlib.sha256)` — the v4.2.0 tamper-evident
  audit-log chain link. SHA-256 under HMAC is the recommended construction; the
  alert appears to be query/line drift onto a strong call.
- **#34 — `api.py:42320` (`_attention_item_key`).** **False positive — a
  non-security dedup key.** SHA-1 over `kind|device|summary` to give identical
  attention re-firings a stable ignore key; collisions only cost one missed
  dedupe. Already annotated `usedforsecurity=False`. The sibling log-dedup hash
  `_line_signature` (`api.py:409`) is the same pattern, also annotated.

**Hardening applied this release:** the two MD5 *cache-key* fingerprints in the
fleet-checks fast path (`api.py:~23104` and `~25007`) — change-detection over
the checks config, never a credential — now also pass `usedforsecurity=False`,
which is the signal CodeQL's weak-hash query honours. No hash value semantics
change for security; cache keys are recomputed transparently.

## Clear-text logging / storage of sensitive information (#46, #35, #36)

- **#46 — `api.py:14911` (diagnostics download).** **False positive — by
  design, admin-gated.** `sys.stdout.write(json.dumps(bundle, …))` is the body
  of `GET /api/self/diagnostics`, an **admin-authenticated** support-bundle
  download served with `Cache-Control: no-store` and `X-Content-Type-Options:
  nosniff`, and recorded in the audit log. The bundle is intentionally handed to
  the requesting admin; it is config/diagnostics, with the same per-key secret
  redaction the rest of the config surface uses. This is a deliberate export, not
  a logging leak.
- **#35 — `api.py:1904` (stderr).** **False positive — no sensitive data.** A
  one-line `stderr` diagnostic emitted when a `last_seen` regression is prevented:
  it logs the device id, two epoch timestamps, the caller hint, and the pid.
  None of these are secrets.
- **#36 — `api.py:1893` (datastore write).** **False positive — the normal
  atomic data-file write.** `_tf.write(json.dumps(data, …))` is the
  write-temp-then-`os.replace` publish of the application data store, finalised
  `chmod 0600` on a server the operator controls. This is the database, not a
  log; "clear-text storage" of the app's own data file is the intended design,
  and at-rest encryption is a deployment/disk-level concern outside the app.

---

## Documentation coverage (this release's theme)

Confirmed that every feature and function exercised above is described in the
shipped documentation set — the in-app Documentation page, `README.md`,
`docs/Manual.html`, the per-version `docs/vX.Y.Z.md` notes, and the did-you-know
tips — including the audit tamper-evident chain (v4.2.0), the CSP migration, the
diagnostics bundle, and the agent transport floor. Gaps found during the audit
were corrected in this release (see `docs/v4.4.1.md`).

**Posture: unchanged and strong.** No code-execution, injection, SSRF, or
secret-disclosure path was found behind any of the 13 alerts. The cheap
`usedforsecurity=False` annotations bring the scanner into agreement on the two
MD5 fingerprints; the remaining 11 are documented false positives suitable for
dismissal as such on the code-scanning tab.
