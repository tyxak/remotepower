# Swagger / OpenAPI

*Introduced in v1.10.0.*

RemotePower ships with an OpenAPI 3.1 specification for the public API
surface, plus a Swagger UI page that lets you explore and exercise the
endpoints from your browser. If you've been writing scripts against
the API by reading `docs/cmdb.md` or grepping `api.py`, this is the
nicer experience.

---

## Quick start

1. Log into the dashboard normally.
2. Click **API Reference** in the sidebar.
3. The Swagger UI page opens in a new tab. Your session token is
   automatically attached to every "Try it out" request — there's no
   Authorize step.

That's it. The endpoints are grouped into tags down the page —
**Auth**, **Devices**, **Commands**, **Checks**, **CVE**, **CMDB**,
**Vault**, **Credentials**, **Virtualization**, **Reporting** and
**Other**. Click any operation to expand it,
fill in path / query parameters, and **Try it out** fires it against
your live server.

---

## What's documented

The spec covers the endpoints a human would reasonably call. It
deliberately **omits** the agent-only endpoints:

- `/api/heartbeat` (agents post sysinfo and pull queued commands)
- `/api/enroll/pin` and `/api/enroll/register` (enrollment with a server-issued ticket)

These speak a contract the agent has to honour exactly, and exposing
them in Swagger UI invites people to push test traffic through them
and corrupt their fleet state. If you're writing a custom agent, read
the source — it's better than what a hand-written spec would give you.

---

## Where the spec lives

- **Module**: `server/cgi-bin/openapi_spec.py` — the spec is a single
  function `build_spec(server_version, routes)` that returns a dict:
  hand-written detail for the rich subsystems, auto-generated stubs for
  everything else in the route table.
- **Endpoint**: `GET /api/openapi.json` — auth-gated. The Swagger UI
  page fetches it with your session token.
- **Page**: `server/html/swagger.html` — a standalone page that loads a
  **self-hosted, SRI-pinned** Swagger UI bundle from
  `/static/vendor/swagger-ui/`, plus `/static/css/swagger.css` and
  `/static/js/swagger-init.js`. Nothing is fetched from a CDN, so it
  works unchanged on air-gapped servers and under the strict
  `script-src 'self'` CSP. If the spec fetch fails, the page falls back
  to a plain-text pointer at `/api/openapi.json`.

The spec is regenerated on every `GET /api/openapi.json` request,
which sounds wasteful but takes about half a millisecond.

### How it's generated

Routing in `api.py` is table-driven (`_EXACT_ROUTES` /
`_PATTERN_ROUTE_DEFS`), so the spec is derived from those route
tables plus hand-written path detail for the richer subsystems —
it is not a hand-maintained list that silently drifts. A new route
is picked up automatically as long as its dispatch branch declares
its HTTP method, and the test suite enforces that the documented
endpoints actually exist (`tests/test_v1100.py::TestOpenAPISpec`).

---

## Authentication in Swagger UI

The page injects your session token via a Swagger UI request
interceptor. This means:

- **You don't need to click Authorize.** Token is attached to every
  request automatically.
- **Logging out from the dashboard kicks Swagger UI too.** The token
  goes stale, the next request fails with 401. Refresh the Swagger
  page after re-login.
- **The vault key is a separate concern.** It is never shared with
  this page — it lives only in the dashboard tab's JS, not in
  localStorage, so the Swagger tab cannot see it. To exercise
  credential endpoints, unlock the vault on the dashboard, then enter
  the hex key here manually via **Authorize → VaultKey**
  (`X-RP-Vault-Key`).

---

## Spec versioning

The spec's `info.version` mirrors `SERVER_VERSION` from `api.py`. So
hitting `/api/openapi.json` against a v1.10.0 server returns a spec
with `info.version: "1.10.0"`, against a v1.10.1 server it'll say
`1.10.1`, and so on. There's no separate API versioning — the spec
just describes what the running server actually serves.

If you need to track API changes across versions for a downstream
client, save the JSON output of `/api/openapi.json` against each
release and diff it. The schema is stable enough that meaningful
changes (field added, status code introduced) show up cleanly.

---

## Programmatic use

Want to generate a client SDK from the spec? It's a normal OpenAPI 3.1
document, so:

```bash
# Save the spec
curl -sSf -H "X-Token: $TOKEN" https://your-server/api/openapi.json > openapi.json

# Generate a Python client
openapi-python-client generate --path openapi.json

# Or a TypeScript client
npx openapi-typescript openapi.json -o api.d.ts

# Or a Go client
oapi-codegen -package remotepower openapi.json > client.go
```

The spec uses `$ref` for shared schemas (Error, Device, CmdbAsset,
Credential, etc.) so generators that respect refs produce reasonable
output. It does **not** use callbacks, OAuth, or anything else
exotic — header-based auth and JSON bodies, that's it.
