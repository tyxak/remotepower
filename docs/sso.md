# Single sign-on & directory integration

*OIDC in v3.2.0; LDAP/LDAPS in v1.8.6; SCIM provisioning in v3.14.0 (Groups in
v5.8.0); SAML 2.0 in v4.2.0; the shared group→role matrix and SSO-only mode in
v5.4.1.*

RemotePower can hand authentication to your identity provider four ways, all
configured on **Settings → Integrations** (the Connections group):

- **OIDC / OpenID Connect** — browser SSO against Authelia, Authentik,
  Keycloak, Pocket-ID, Google, Entra, …
- **SAML 2.0** — browser SSO against Okta, Azure AD / Entra, OneLogin, Ping,
  ADFS, …
- **LDAP / LDAPS** — password logins verified against a directory (AD,
  OpenLDAP, FreeIPA) through the normal login form.
- **SCIM 2.0** — not a login method: the IdP *pushes* user lifecycle (create,
  role assignment and — crucially — deactivation) into RemotePower.

Local accounts in the users store keep working alongside all of them —
password login is tried locally first, so an emergency local admin never
depends on the IdP being reachable. The login page shows a **Sign in with
SSO** / **Sign in with SAML** button automatically once the matching method is
enabled (the pre-login `GET /api/public-info` exposes only the yes/no flags,
never the IdP config).

---

## How an SSO user becomes a RemotePower account

OIDC and SAML users are **JIT-provisioned**: the first successful sign-in
creates the account with an unusable random password hash (they can only ever
log in via the IdP) and the role resolved from their group memberships.
On later logins a `viewer` is **promoted** to whatever role their groups now
map to — but never auto-demoted (an operator may have changed the role for
cause).

Role resolution, shared by OIDC, SAML and (since v6.2.3) LDAP:

1. **Group → role map** (config `sso_group_roles`) — the "Group → role map"
   textarea on the OIDC card, one `group=role` per line. Maps an IdP group to
   *any* builtin or custom role (`admin`, `viewer`, `auditor`, `finance`, a
   custom role, …). `admin` wins when several groups match; an unknown role
   name is ignored (fail-safe).
2. **Legacy admin group** — the per-method "Admin group" field
   (`oidc_admin_group` / `saml_admin_group`): members get `admin`.
3. Neither matches → `viewer`.

On a multi-tenant install `sso_group_roles` is instance-wide (one IdP for the
whole deployment) and only a platform superadmin may change it.

**LDAP note**: LDAP group memberships are full **DNs** (what `memberOf`
returns), so a matrix line for an LDAP group is
`cn=ops,ou=groups,dc=example,dc=com=auditor`. LDAP matrix keys, like the
legacy "Admin group DN" field, are matched **case-insensitively** (directory
DN casing rarely survives typing); OIDC/SAML group names stay case-sensitive.

---

## OIDC / OpenID Connect

No extra dependencies — the confidential-client authorization-code flow is
built in (implicit flow and front-channel id_tokens are deliberately not
supported).

**On the IdP**: create a confidential (server-side) client with redirect URI

```
https://<your-server>/api/auth/oidc/callback
```

(the exact value is shown on the Settings card, derived from the request host
and `X-Forwarded-Proto`).

**In RemotePower** (Settings → Integrations → OIDC / OpenID Connect):

| Field | Config key | Notes |
|-------|-----------|-------|
| Enable OIDC sign-in | `oidc_enabled` | Enabling requires issuer + client id + secret to be set. |
| Issuer URL | `oidc_issuer` | Must serve `<issuer>/.well-known/openid-configuration`. |
| Client ID | `oidc_client_id` | |
| Client Secret | `oidc_client_secret` | Write-only — blank on save means "keep current"; never echoed back (`GET /api/config` returns only a `*_set` boolean). |
| Scopes | `oidc_scopes` | Default `openid profile email groups`. |
| Admin group | `oidc_admin_group` | Legacy single admin group (see above). |
| Group → role map | `sso_group_roles` | Shared with SAML. |

Use **Test discovery** (`POST /api/auth/oidc/test`, admin) after saving — it
fetches the discovery document fresh and reports the four key endpoints plus
warnings for the common misconfigurations (missing client id/secret, no
`openid` scope, missing endpoints).

Flow details worth knowing:

- `GET /api/auth/oidc/start` stores a state + nonce server-side (10-minute
  TTL) and 302s to the IdP; the callback validates state and nonce, exchanges
  the code over a back-channel POST authenticated with the client secret, and
  checks the id_token's `exp` / `iss` / `aud` claims. The username comes from
  `preferred_username`, then `email`, then `sub`; groups from the `groups`
  (or `roles`) claim.
- The session token is delivered in the URL **hash** fragment, so it never
  appears in server/proxy logs.
- All back-channel fetches are SSRF-guarded (no redirects, link-local/cloud-
  metadata targets rejected) — see [security.md](security.md).
- The callback is rate-limited to 30 attempts/minute per IP.

## SAML 2.0

**Prerequisites**: the `pysaml2` Python library **and** the `xmlsec1` binary
on the server (e.g. `pip3 install pysaml2` + your distro's `xmlsec1`/`xmlsec`
package; on Arch the AUR server package lists pysaml2 as an optdepend). Until
both are present the feature reports unavailable and its endpoints return 503
— `GET /api/saml/available` tells you which state you're in.

**In RemotePower** (Settings → Integrations → SAML 2.0), paste three values
from your IdP:

| Field | Config key | Notes |
|-------|-----------|-------|
| Enable SAML sign-in | `saml_enabled` | |
| IdP entity ID | `saml_idp_entity_id` | |
| IdP SSO URL (HTTP-Redirect) | `saml_idp_sso_url` | |
| IdP signing certificate | `saml_idp_x509_cert` | X.509, PEM or bare base64. |
| Username attribute | `saml_attr_username` | Optional; blank = use the SAML NameID. |
| Groups attribute | `saml_attr_groups` | Default `groups`. |
| Admin group | `saml_admin_group` | Legacy single admin group. |
| Allow IdP-initiated sign-in | `saml_allow_unsolicited` | Off is safer — see below. |

**On the IdP**: hand it the SP metadata from `GET /api/saml/metadata` (the
"View SP metadata" button; public, no auth). The values it contains:

- **ACS URL**: `https://<your-server>/api/saml/acs` (HTTP-POST binding)
- **SP entity ID**: defaults to `https://<your-server>/api/saml/metadata`;
  override with the config-only key `saml_sp_entity_id` (no Settings field —
  set it via `POST /api/config`).

Verification posture: pysaml2 enforces signatures (both the response *and*
the assertions must be signed), audience and validity window; RemotePower
adds `InResponseTo` matching against a 10-minute outstanding-request store
with one-time use, so an assertion can't be replayed. That's why
IdP-initiated ("unsolicited") sign-in is off by default — enabling it accepts
responses with no matching request. The ACS shares the OIDC callback's
30/min/IP rate limit, and a successful login redirects with the token in the
URL hash exactly like OIDC.

## LDAP / LDAPS

**Prerequisite**: the `ldap3` library (`pip3 install ldap3` — pure Python, no
native deps).

LDAP is a fallback on the **normal login form**: local users are verified
first, and only when local verification fails is LDAP tried. Flow: bind as a
service account → search for the user → re-bind as the found DN with the
submitted password → group checks.

Settings → Integrations → LDAP / LDAPS authentication:

| Field | Config key | Notes |
|-------|-----------|-------|
| Enable LDAP authentication | `ldap_enabled` | |
| LDAP URL | `ldap_url` | `ldaps://host:636` for TLS (use it). |
| Verify TLS cert | `ldap_tls_verify` | Default on; off only for self-signed CAs. |
| Timeout (s) | `ldap_timeout` | Default 5. |
| Service account DN | `ldap_bind_dn` | Blank = anonymous bind (rarely works). |
| Service account password | `ldap_bind_password` | Blank on save keeps the current one. **Prefer the `RP_LDAP_BIND_PASSWORD` env var** (systemd unit / container env) — it takes precedence, stays out of `config.json` and out of the backup export. |
| User search base | `ldap_user_base` | e.g. `ou=Users,dc=example,dc=com` |
| User filter | `ldap_user_filter` | `{u}` = username. AD: `(sAMAccountName={u})`, OpenLDAP/FreeIPA: `(uid={u})`. A filter matching more than one entry is treated as an error — tighten it. |
| Required group DN | `ldap_required_group` | Blank = anyone with valid creds may log in. |
| Admin group DN | `ldap_admin_group` | Members get `admin`. Finer roles come from the shared group → role map (matrix keys = group DNs, case-insensitive; v6.2.3). |

Two test buttons: **Test connection** (`POST /api/ldap/test`) verifies the
service-account bind — the body may override saved config for
try-before-save; **Test user login** (`POST /api/ldap/test-user`) runs the
full authentication path for one user and reports the resolved DN/role
without creating a session.

LDAP users are auto-provisioned on first login (placeholder password hash, so
every later login goes back through LDAP) and are promoted on later logins —
to `admin` when they gain the admin group (any non-admin), or from `viewer`
up to their matrix-mapped role — never auto-demoted. Usernames are filter-escaped (RFC
4515), so directory injection via the login form isn't possible.

If LDAP itself is down, logins fall back to local-only and the failure is
recorded in the audit log (`login_ldap_error`) — the client sees a normal
invalid-credentials response, deliberately not revealing directory state.

## SCIM 2.0 provisioning

SSO/LDAP only ever *create* accounts on first login. SCIM closes the
offboarding gap: the IdP (Okta, Azure AD, OneLogin, …) can create users ahead
of time, assign roles, and **deactivate** them the moment they're offboarded
— which also kills their live sessions.

Settings → Integrations → SCIM provisioning: enable it (`scim_enabled`) and
set the **Bearer token** the IdP will authenticate with (`scim_token` —
leave blank to auto-generate on enable; shown once). On the IdP, point
provisioning at:

```
https://<your-server>/api/scim/v2
```

What's implemented (all under the bearer token; the whole surface returns 404
while SCIM is disabled, so it doesn't advertise itself):

| Method | Path | Notes |
|--------|------|-------|
| GET/POST | `/api/scim/v2/Users` | List (supports `?filter=userName eq "x"`) / create. An email-style `userName` becomes the local part. New users start as **viewer**, JIT-compatible. |
| GET/PUT/PATCH/DELETE | `/api/scim/v2/Users/{id}` | `DELETE` and `active: false` **deactivate** (set `disabled`) rather than hard-delete — the audit trail survives, login and existing sessions die. Refuses to deactivate the last enabled admin. |
| GET | `/api/scim/v2/Groups` | Groups are RemotePower **roles** 1:1 (built-ins + custom roles). `POST` returns 501 — roles are defined in RemotePower, not by the IdP. |
| GET/PUT/PATCH | `/api/scim/v2/Groups/{role}` | PATCH members add/remove assigns/clears that role (removal reverts the user to `viewer`); refuses to strip the last admin. This is the push-style alternative to the JIT group→role matrix. |
| GET | `/api/scim/v2/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas` | Discovery documents some IdPs require. |

A deactivated account is refused at login even with valid credentials (local
*and* LDAP), and `verify_token` rejects its existing sessions.

---

## Interaction with local accounts and MFA

- **Local passwords stay primary.** The login form always tries the local
  users store first; SSO/LDAP never has to be reachable for a local admin to
  get in.
- **TOTP / passkeys apply to the password login path** — including LDAP
  logins (the second factor lives on the RemotePower user record). SAML and
  OIDC sign-ins mint a session directly from the IdP's assertion and do
  **not** prompt for a local second factor: for federated users, enforce MFA
  at the IdP.
- **SSO-provisioned accounts have no local password.** A few high-impact
  actions (e.g. clearing the audit log) require re-entering a *local* admin
  password — an SSO-only admin must first set one under My Account, or use an
  admin account that has one.
- **SSO-only mode** (Settings → Security, config `sso_only`): refuses
  local-password logins whenever OIDC or SAML is actually enabled — mandate
  IdP auth org-wide. Break-glass: a user record flagged `local_login: true`
  is always exempt; there is **no UI toggle** for that flag — set it on an
  emergency admin in the users store *before* enabling SSO-only, or you can
  lock yourself out. LDAP logins are not blocked by SSO-only (it's treated as
  an IdP path). The safeguard: if no IdP is enabled, `sso_only` does nothing.
- **Users → source column**: Settings' user list shows each account's origin
  (`local` / `saml` / `oidc` / `scim`) and MFA state, so you can see who is
  IdP-managed at a glance.
- SSO sessions are ordinary sessions: same TTL, same per-user session cap,
  same My Account → Sessions listing.

## Troubleshooting

- **No SSO button on the login page** — the method isn't (fully) enabled:
  OIDC needs `oidc_enabled` + issuer; SAML needs `saml_enabled` + SSO URL.
  Check `GET /api/public-info`.
- **SAML section says unavailable / endpoints 503** — `pysaml2` or `xmlsec1`
  is missing on the server. `GET /api/saml/available` reports both
  availability and configured state.
- **OIDC misbehaves** — run **Test discovery** first; it flags the usual
  suspects. A `redirect_uri mismatch` at the IdP means the registered URI
  differs from the one on the card (scheme comes from `X-Forwarded-Proto`
  when proxied — make sure nginx sets it).
- **"no outstanding SAML request (replay or unsolicited response)"** — the
  sign-in took longer than the 10-minute request TTL, or the IdP initiated
  the login while "Allow IdP-initiated" is off.
- **429 "Too many SSO attempts"** — the per-IP limit (30/minute) on the
  callback/ACS; wait a minute.
- **LDAP** — use the two test buttons; "filter matches >1 user" means the
  user filter needs tightening. Check the audit log for `login_ldap_error`
  (directory unreachable) — the login form intentionally shows a generic
  failure.
- OIDC token-exchange failures log only the HTTP status and the OAuth error
  code, never the IdP response body (it can echo the client secret) — check
  the IdP's own logs for detail.

Implementation: `server/cgi-bin/api.py` (`handle_oidc_*`, `handle_saml_*`,
`handle_ldap_test*`, `handle_scim_*`, `_role_from_groups`,
`_provision_or_promote_user`, `_sso_only_blocks`);
`server/cgi-bin/saml_auth.py` and `server/cgi-bin/ldap_auth.py` (the pure
protocol modules).

Related: [security.md](security.md) for the crypto/verification posture and
hardening checklist, [threat-model.md](threat-model.md) for the SSO rows in
the STRIDE matrix, [settings.md](settings.md) for the surrounding Settings
tabs, [admin-guide.md](admin-guide.md) for operations.
