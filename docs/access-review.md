# Access review (recertification)

SOC 2 CC6.2/CC6.3 and ISO 27001 A.5.18 both ask the same question on a schedule:
*is every account that can reach this system still supposed to be able to?*
RemotePower does not run that review for you — it is a decision, not a check —
but every fact the review needs is already in the product. This page is the
procedure, and where each fact comes from.

Run it **quarterly** at minimum; monthly if you have contractors or a fast-moving
team.

---

## 1. Pull the roster

The **Users** page (sidebar), or `GET /api/users`. Each row carries exactly the
fields a recertification needs:

| Field | What it answers |
|---|---|
| `username`, `role`, `team` | Who, and what they can do. |
| `mfa` — `passkey` / `totp` / `none` | Whether the account is defensible if the password leaks. |
| `source` — `local` / `oidc` / `saml` / `scim` | Whether your IdP owns the lifecycle, or you do. |
| `last_login` | **The signal that matters.** `0` means no sign-in is recorded. An account that last signed in before RemotePower began recording this also shows `0`. |
| `disabled` | Already deactivated — confirm it should stay that way. |
| `created` | How long the account has existed. |

The endpoint is tenant-filtered, so on a multi-tenant install each tenant admin
reviews their own roster and sees nobody else's.

Do the same for machine identities — the **API keys** page — which are the ones
reviews usually forget. Each key carries its host **scope**, source-IP
allowlist, expiry, rate limit and rotation lineage (`rotated_from` /
`rotated_to`), and is tenant-scoped like the user roster. Note there is **no
last-used timestamp on a key** — `created` and `expires_at` are what you have, so
an unused key is not distinguishable from a busy one. Expiry is what closes that
gap: set one.

## 2. Ask four questions per account

1. **Should this person still have access at all?** Cross-check leavers. If your
   IdP drives SCIM, this is already automatic — a SCIM deprovision revokes both
   the account and its live sessions immediately. If accounts are `local`, this
   step is entirely manual and is where stale access actually accumulates.
2. **Is the role still the least privilege that works?** Someone who moved from
   on-call to reporting probably needs `auditor`, not `admin`. Custom roles
   scoped to groups/tags/sites exist precisely so the answer does not have to be
   all-or-nothing.
3. **Is MFA on?** `mfa: none` on an `admin` row is a finding. Per-role MFA
   *enforcement* (Settings → Security) makes it structural rather than a
   recurring nag.
4. **Has it been used?** A privileged account with a `last_login` older than the
   review period is the single best candidate for closure — it carries full risk
   and delivers no value.

## 3. Check what the accounts have been doing

The **Audit** page (Compliance group), filtered by actor, answers "what has this
account actually done since the last review". Two things to look for beyond the
obvious:

- Actions from an account whose owner says they no longer use it.
- **`governance_config_change` entries** — changes to four-eyes approval (and its
  rule that the requester cannot approve their own change), MFA-required roles,
  SSO-only sign-in, the IP allowlist, the WORM sink, audit retention or
  forwarding, or tenancy. These need a fresh password or code (step-up) and are
  logged by name (restoring an older configuration revision that changes one of
  them is logged the same way), and they are the changes an access review should notice even
  when the account is legitimate. A litigation hold is logged on its own, as
  `litigation_hold`.

## 4. Act, then record

- Deactivate rather than delete where you can. Deleting a user does **not**
  rewrite the audit entries naming them — that is on purpose, and is what keeps
  the log usable as evidence — but deactivation keeps the history readable.
- Revoke unused API keys, and set an expiry on the ones you keep.
- For live sessions, **Settings → Security → Active sessions** lists every login
  on the instance (click **Load sessions**): user, role, source, IP, last active
  and expiry. **Revoke user** ends them. Revocation is **per user**, not per
  session: the server offers `POST /api/sessions/revoke {username}`, which signs
  that account out everywhere at once. With no username it signs out everyone
  except you. (The per-session revoke on the Account page only ever applies to
  your own sessions.) Use it during offboarding rather than waiting for the idle
  timeout, and when checking an incident against who was actually logged in.

Then record the review itself. Two artifacts are worth keeping, and it is worth
being precise about what each one proves:

- The **compliance evidence pack** (Reports → **Evidence pack**, or
  `GET /api/report/evidence?days=N`, 1 to 366 days, 90 by default) is
  HMAC-signed and bundles the current fleet posture, the compliance-baseline
  trend, the reports that were emailed during the period and an audit-log
  excerpt (the newest 2,000 entries of the period). It does **not** contain the
  user roster, so it is context for the review, not the review itself.
- The roster you actually certified: save the `GET /api/users` response alongside
  it. Generating the evidence pack is itself audit-logged, which dates the
  exercise.

---

## What RemotePower will not do for you

- It will not decide that an account is stale. `last_login` is evidence; closure
  is a judgement call about a person's job.
- It will not detect a shared account. One `username` used by three people looks
  identical to one used by one.
- It will not review access to the *hosts* — SSH keys and local accounts on
  managed machines are surfaced by the SSH-key baseline and posture checks, but
  those are a separate review with a separate owner.

---

← [Back to docs index](README.md) · [Compliance mapping](compliance.md) ·
[Security controls](security.md) · [Data retention](data-retention.md) ·
[SSO and SCIM](sso.md)
