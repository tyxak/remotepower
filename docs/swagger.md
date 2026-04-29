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
2. Click **API Docs** in the sidebar.
3. The Swagger UI page opens in a new tab. Your session token is
   automatically attached to every "Try it out" request — there's no
   Authorize step.

That's it. The endpoints are grouped into seven tags down the page:
**Auth**, **Devices**, **Commands**, **CMDB**, **Vault**,
**Credentials**, **Reporting**. Click any operation to expand it,
fill in path / query parameters, and **Try it out** fires it against
your live server.

---

## What's documented

The spec covers the endpoints a human would reasonably call. It
deliberately **omits** the agent-only endpoints:

- `/api/heartbeat` (agents post sysinfo and pull queued commands)
- `/api/enroll` (one-shot enrollment with a server-issued ticket)

These speak a contract the agent has to honour exactly, and exposing
them in Swagger UI invites people to push test traffic through them
and corrupt their fleet state. If you're writing a custom agent, read
the source — it's better than what a hand-written spec would give you.

---

## Where the spec lives

- **Module**: `server/cgi-bin/openapi_spec.py` — the spec is a single
  Python function `build_spec(server_version)` that returns a dict.
  Hand-written. Yes, really.
- **Endpoint**: `GET /api/openapi.json` — auth-gated. The Swagger UI
  page fetches it with your session token.
- **Page**: `server/html/swagger.html` — standalone HTML that loads
  Swagger UI from a pinned CDN version (5.17.14) and feeds it the
  spec.

The spec is regenerated on every `GET /api/openapi.json` request,
which sounds wasteful but takes about half a millisecond.

### Why not auto-generate?

The CGI dispatch table in `api.py` is an `elif` chain over
`path_info`/`method` — there's no decorator metadata to introspect,
and adding one would just be a different way to be wrong. Hand-
writing keeps the spec honest: when an endpoint changes, the spec
changes with it, and the test suite enforces that the documented
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
- **The vault key is a separate concern.** If you're testing
  credential endpoints, you need to unlock the vault on the main
  dashboard first, then come back. The Swagger UI page reads
  `_cmdbVaultKey` is held in the dashboard tab's JS, not in
  localStorage, so the Swagger tab can't see it; you'll need to
  enter the hex key manually using Authorize → VaultKey.

---

## Air-gapped servers

Swagger UI itself loads from `cdnjs.cloudflare.com`. On servers with
no outbound internet:

- The page detects the load failure and falls back to a plain-text
  message: "the raw spec is at /api/openapi.json".
- Bundling Swagger UI inline would add ~700 KB to every page load on
  the main dashboard. The deferred-load model keeps the dashboard
  fast at the cost of this offline degradation.
- If you really need offline Swagger UI, drop
  `swagger-ui-bundle.min.js` and `swagger-ui.min.css` into
  `server/html/` and edit `swagger.html` to point at relative paths
  rather than the CDN. The HTML is small (~3 KB); the patch is one
  search-and-replace.

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
