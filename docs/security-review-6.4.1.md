# Security review — v6.4.1 "Cust0dyMatters"

A security review of the v6.4.1 changes, weighted heavily toward the **KMIP key
server** — a new network-listening subsystem that holds encryption keys for
other people's storage, which makes it the highest-consequence code this release
adds. Everything reachable from the network, everything that touches key
material, and every new or changed request handler was reviewed against the
recurring defect classes this project tracks.

**Result: no Critical, High or Medium issue. Nothing exploitable.**

## Scope

22 commits since v6.4.0, ~3,200 changed lines across the server and the three
agents. The new or substantially changed surfaces:

| Surface | Why it was reviewed |
|---|---|
| `server/kmip/remotepower-kmipd.py` (1,210 lines) | New TLS listener on tcp/5696, parses untrusted binary protocol |
| `server/cgi-bin/kmip_handlers.py` (1,414 lines) | 19 new handlers; key custody, CA, certificate issuance |
| `snmp_device_handlers.py` | New OID browser reads arbitrary OIDs from a device |
| `advisory.py`, `posture_signals.py`, `advisory_handlers.py` | New security-signal producers and a shared extraction layer |
| `backups_handlers.py`, `tickets_handlers.py`, `cmdb_vault.py` | Changed handlers over shared state |
| `client/remotepower-agent{,-mac}.py` | New on-host collectors; new macOS check evaluation |

## Process

- **SAST** — `ruff --select F821`: **0** on all three agents and every
  `*_handlers.py` module (the 185 hits in `api.py` are the documented
  bound-handler false-positive class, confirmed still confined to that one
  file). `gitleaks -c .gitleaks.toml`: **no leaks**, 1,571 commits scanned.
  `bandit -b .bandit-baseline.json`: **0 High**, and the 4 new findings were the
  by-design `B110`/`B112` "one host's bad data must not abort the fleet loop"
  pattern in the new advisory/posture code — triaged and absorbed into the
  baseline. CodeQL run through `tools/codeql-local.sh` (config-honoring, the
  pass that matches production's advanced setup).
- **Targeted class sweeps** — AST and source analysis for each recurring defect
  class in this codebase: success-`respond()` swallowed by a broad `except`,
  bare `require_auth()` on a mutating handler, `Path.exists()` on a storage key,
  cross-tenant leakage on a fleet aggregate, and unescaped device-supplied data
  reaching `innerHTML`.
- **Boundary tracing** — every trust boundary in the KMIP design followed by
  hand from the network edge to the key material, rather than reviewed as
  isolated functions.
- **Full gate** — the complete suite green on both storage backends
  (8,747 tests, JSON and SQLite).

## KMIP: the trust boundaries

The subsystem is deliberately split so the network-facing process holds nothing
worth stealing. That split is the main security property, so it was verified
rather than assumed:

**The sidecar terminates TLS and holds no secrets.** `remotepower-kmipd` runs
under `DynamicUser=yes` with no data-directory access. It has no master key, no
key material and no store access; it parses the protocol and forwards each
operation over loopback. Confirmed: the only persistent material it holds is the
server certificate and CA it fetches from the control plane, and the shared
secret systemd injects.

**Client authentication is mandatory mTLS, enforced twice.** The listener sets
`verify_mode = CERT_REQUIRED` with `minimum_version = TLSv1_2` and loads the
private CA, so the handshake itself rejects any certificate not signed by it.
Past the handshake, the peer certificate's SHA-256 fingerprint must match a
registered, non-revoked client. The control plane then **re-checks identity and
revocation on every single operation** with a constant-time comparison — so a
revoked client is cut off at the next operation, not merely at the next
reconnect.

**Key objects are scoped to their owning client, on every operation.** This is
the claim that would matter most if it were only a comment. It is enforced:
ownership is stamped at creation (`'client_id': cid`), and the
`_kmip_object_visible(o, client_id)` predicate is applied on **all nine**
operations that touch an existing object — `locate`, `get`, `get_attributes`,
`check`, `set_attribute`, `delete_attribute`, `activate`, `revoke`/`destroy`.
`locate` filters through the same predicate, so one appliance cannot even
enumerate another's keys. There is no path that reads an object without it.

**Key material is encrypted at rest under a dedicated master key.** AES-256-GCM
with a fresh 12-byte random nonce per encryption (`secrets.token_bytes`), via
the shared `cmdb_vault` primitives. The master key is 32 bytes of
`secrets.token_bytes` in a real `0600` file — deliberately not a storage key, so
it is excluded from scheduled backups; a stolen backup archive yields ciphertext
only. The recovery bundle uses PBKDF2-HMAC-SHA256 at **600,000 iterations** with
a 32-byte random salt (OWASP's current floor), and refuses a passphrase under 12
characters.

**The control-plane callbacks fail closed.** The three `/api/kmip/daemon/*`
endpoints are gated on a shared secret compared with `hmac.compare_digest`, and
the gate rejects when the secret is missing or empty — an unconfigured daemon
secret denies rather than admits. Reviewed explicitly against the
`/api/ping/<token>` class (a new endpoint that a global pre-dispatch gate
silently blocks): the daemon reaches the app over loopback, which
`_enforce_ip_allowlist` always permits, so enabling the IP allowlist cannot
strand the sidecar.

**Administrative access is global-admin only, and does not leak its existence.**
All 19 handlers gate uniformly — `_kmip_require_viewer` (admin or auditor) on
the five read endpoints, `_kmip_require_admin` on the eleven mutations,
`_kmip_require_daemon` on the three sidecar callbacks. KMIP is host
infrastructure rather than tenant-scoped, so a tenant admin receives **404, not
403**, keeping the surface invisible to a tenant that should not know it exists.

**The listener is bounded against resource exhaustion.** A 1 MiB cap on a single
request message, a 4 MiB response ceiling, a **TTLV nesting depth cap of 32**
(the structural recursion bomb this format invites), 64 concurrent connections,
a 15-second handshake budget, a 120-second idle timeout, and a bounded
per-peer-IP auth-failure log map so a spoofed-source flood cannot grow it
without limit.

### Accepted trade-off, documented

`RP_KMIP_LEGACY_CIPHERS=1` lowers OpenSSL's security level for the KMIP listener
only, to admit legacy suites (`TLS_RSA_WITH_AES_256_CBC_SHA256`) that some
appliances are hard-coded to offer — no forward secrecy, CBC. It is **off by
default**, opt-in per install, scoped to that one listener, and logs a warning
whenever it is enabled. Enabling it is a deliberate choice to make an otherwise
impossible appliance work; the mTLS client-authentication requirement is
unaffected either way.

### Inherent boundary, stated plainly

A compromised sidecar can impersonate any client whose certificate it has seen,
because it is the process that terminates TLS. This is intrinsic to any
TLS-terminating proxy and is why the sidecar is sandboxed, holds no key material
and has no store access — compromise of it yields the ability to request keys
for clients that connect through it, not the key database, the master key or the
CA. Operators running KMIP should treat the sidecar's host as
equally sensitive to the appliances it serves.

### Availability coupling — an operational risk, not a vulnerability

An appliance that unlocks its storage against this server needs the server
reachable at boot. Running the KMIP server on a machine whose own storage it
unlocks is a deadlock. This is called out in the UI, the release notes and
`docs/kmip.md`; it is repeated here because it is the most likely way for this
feature to cause real damage, and it will not be caught by any scanner.

## The rest of the release

**`_get_client_ip()` re-verified.** Since every default install now has a local
nginx `proxy_pass` hop, the peer is always loopback and the forwarded headers
are always trusted — so the parsing order is what stands between the IP
allowlist and trivial spoofing. Confirmed correct: the code takes the
**rightmost** `X-Forwarded-For` entry, and every shipped nginx config uses
`$proxy_add_x_forwarded_for`, which appends the real peer last. A client
prepending `X-Forwarded-For: 127.0.0.1` cannot forge its way past the allowlist.

**SNMP OID browser.** Reads arbitrary OIDs from a device using stored
credentials — a broader read than the fixed poll set, so it is `require_admin_auth`
only. The OID is strictly validated as dotted-decimal with arc-count and
per-arc-value caps (the value is BER-encoded, never shell-adjacent, but an
unbounded arc count would still let a caller inflate the request); results are
capped at 1–2,000 rows with a timeout. The handler genuinely writes an
`audit_log` entry, matching what its docstring and the release notes claim.
Values are `_sanitize_str`-clamped server-side and `escHtml`-escaped in all three
rendered columns — SNMP v1/v2c is spoofable UDP, and this is exactly the stored-XSS
class fixed in v6.3.0.

**Recurring-class sweeps came back clean.** An AST sweep for a success
`respond(2xx)` inside a broad `except Exception` found five candidate sites, all
of which handle `HTTPError` deliberately — one re-raises it explicitly with a
comment naming this exact class, the other reaches the same 204 on both paths. A
sweep for bare `require_auth()` on a mutating handler surfaced two candidates,
both correct on inspection: one is a read-only Proxmox cache refresh, the other
gates its write on `_caller_can_write()` so a read-only role peeking at a ticket
cannot clear another operator's unread state.

## Fixed in this release

**A macOS gap that was a monitoring failure, not a vulnerability — but worth
recording, because silence is the worst failure mode for a security control.**
The macOS agent never read the `agent_checks` or `watched_files` keys from the
heartbeat response. Custom checks assigned to a Mac — including file-integrity
and file-presence checks used as tamper detection — reported `unknown`
indefinitely, and watched files produced no config-drift report at all, while
the server and UI showed both as configured and applied. An operator could
reasonably have believed a Mac was covered when nothing was evaluating it. Both
now run; a check type macOS genuinely cannot evaluate reports `unknown` with the
reason attached rather than a false OK.

The new macOS evaluation paths were written to the same standard as the Windows
ones: the operator's `log_errors` regular expression is compiled and matched in
Python against `log show` output and never interpolated into the command, and a
launchd label is charset-validated against a strict reverse-DNS pattern before
it reaches the argument list. Neither is shell-adjacent — there is no shell —
but both close the shape unconditionally.

**A dead switch in the check catalog.** The "also watch this on the Services
page" checkbox was displayed for a Windows service check and the server had
accepted the flag since v6.2.0, but the client only ever sent it for
`systemd_unit`. A ticked, enabled control that did nothing. Not a security
issue; recorded because a monitoring control that appears active and is not is
the same failure shape as the macOS gap above.

## Verification

- Full suite green on **both** storage backends — 8,747 tests, JSON and SQLite.
- `make test-fast` returns to a **passing** state. It had been exiting non-zero
  on every run because the e2e guards tested `import playwright` rather than
  whether a browser exists, so they errored instead of skipping. A permanently
  red fast suite is a security-relevant problem in itself: it trains reviewers
  to ignore the signal that would surface a real regression. The guards now
  share a probe that launches and closes a browser, and the exclusion list is
  globbed rather than hand-maintained.
- Every new guardrail in this release was verified against the pre-fix code —
  reverted, confirmed failing, restored. A test that passes both before and
  after a fix proves nothing, and this project has shipped that mistake before.

No Critical / High / Medium issue ships; nothing exploitable. The local SAST
suite (bandit, gitleaks, `ruff --select F821`, CodeQL) reports clean.
