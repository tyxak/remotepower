# Swagger / OpenAPI

RemotePower ships with an OpenAPI 3.1 specification for its API, plus a Swagger UI
page where you can explore and try the endpoints from your browser. If you write
scripts against the API, start here. The hand-written guide to the main workflows is
[api.md](api.md).

---

## Quick start

1. Sign in to the dashboard as usual.
2. Click **API Reference** in the sidebar (Admin group).
3. The Swagger UI page opens in a new tab. Your session token is attached to every
   **Try it out** request for you, so there is no Authorize step.

The operations are grouped under tags: **Auth**, **Hosts**, **Commands**, **CMDB**,
**Vault**, **Credentials**, **Reporting** and **Other**. Click an operation to expand
it, fill in the path and query parameters, and **Try it out** sends it to your live
server. **Try it out** really runs the request, so use a test host if the call
changes something.

The page needs a signed-in session in the same browser. If you are not signed in, it
says so and links back to the dashboard.

---

## What is documented

The spec covers the whole route table: every route the server answers, except the
agent-only endpoints:

- `/api/heartbeat` (agents post their state and pull queued commands),
- `/api/enroll/pin` and `/api/enroll/register` (enrolment).

These follow a contract that the agent must honour exactly. Showing them in Swagger
UI invites test traffic that corrupts fleet state. If you write a custom agent, read
the agent source.

The larger subsystems have hand-written detail (parameters, bodies, responses). The
rest are listed as stubs with their path parameters and HTTP method.

---

## Where the spec lives

- **Endpoint:** `GET /api/openapi.json`. It needs a signed-in session or an API key,
  because the spec describes the surface that tokens unlock. The server builds it on
  each request from the live route table, so a new route appears without anyone
  editing a list, as long as its method is declared.
- **Page:** `/swagger.html`. It loads a self-hosted Swagger UI bundle from the server
  (nothing comes from a CDN), so it works unchanged on an air-gapped install and
  under the strict `script-src 'self'` content security policy. If the spec cannot be
  fetched, the page shows a plain-text pointer to `/api/openapi.json`.
- **Base path:** the spec lists two servers, `/api/v1` (recommended) and `/api`.
  They are the same API. `/api/v1` is a permanent alias, so a client written against
  it keeps working if a future version changes the unversioned path.

---

## Authentication

The spec defines three header-based schemes:

- **SessionToken** and **ApiKey**: both are sent as `X-Token`. A session token comes
  from `POST /api/login`. An API key comes from **Admin → API Keys**. The server tells
  them apart by lookup.
- **VaultKey**: `X-RP-Vault-Key`, the hex key derived from the CMDB vault passphrase.
  Credential write and reveal calls need it.

In the Swagger UI page:

- **You don't need to click Authorize** for normal calls. The session token is
  attached automatically.
- **Signing out of the dashboard signs the page out too.** The next request fails with
  401. Sign in again and refresh the page.
- **The vault key stays out of this page.** It lives only in the dashboard tab's
  memory, so the Swagger tab cannot see it. To try the credential calls, unlock the
  vault on the dashboard, then paste the hex key under **Authorize → VaultKey**.

---

## Spec versioning

The spec's `info.version` is the version of the server that built it. There is no
separate API version number: the spec describes what the running server serves.

To track changes between releases, save the output of `/api/openapi.json` for each
release and compare them. Added fields and new status codes show up cleanly.

---

## Programmatic use

The spec is a normal OpenAPI 3.1 document, so you can generate a client from it:

```bash
# Save the spec (use an API key from Admin → API Keys)
curl -sSf -H "X-Token: $TOKEN" https://your-server/api/openapi.json > openapi.json

# Generate a Python client
openapi-python-client generate --path openapi.json

# Or a TypeScript client
npx openapi-typescript openapi.json -o api.d.ts

# Or a Go client
oapi-codegen -package remotepower openapi.json > client.go
```

The spec uses `$ref` for shared schemas (Error, Host, CmdbAsset, Credential and so
on), so generators that respect refs produce reasonable output. It does not use
callbacks, OAuth or anything else unusual: header authentication and JSON bodies.

To explore in Postman, Insomnia or Bruno, import `openapi.json` directly. A source
checkout can also build a ready-made Postman collection from the same spec with
`make postman`.

---

## Troubleshooting

- **"Not logged in" on the page.** Sign in on the dashboard first, in the same
  browser and profile. The page reads the session from there.
- **401 on every call.** The session ended. Sign in again and reload the page.
- **403 on a call.** Your role does not allow it. The spec lists every route, but the
  server still checks permissions on each one.
- **A route is missing.** Agent-only routes are left out on purpose. Anything else
  that is missing is a bug worth reporting.
