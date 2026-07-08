# Writing a connector plugin

RemotePower's homelab integrations are **connectors** — small pure functions that
poll a product's HTTP API and return a health result. You can add your own without
patching RemotePower's source: drop a Python file into `server/cgi-bin/connectors.d/`
and it self-registers at startup.

This is the *code* extension tier. If you only need to check an HTTP endpoint's
status/JSON, the built-in **Custom HTTP probe** connector does that with no code —
see [integrations.md](integrations.md). Custom **checks**, custom **scripts** and
inbound **webhook tokens** are the other no-code extension points.

## Security model — read this first

A file in `connectors.d/` is **executed as the web-server user**, exactly like the
rest of `cgi-bin/`. So:

- The directory must be **root-owned and only writable by the operator** (same
  permissions as `cgi-bin/`). Anyone who can write there can run code as the web
  user.
- There is **no UI upload path** and never will be — plugins are installed from a
  shell, deliberately.
- A plugin that raises while importing is logged to the server error log and
  skipped, so a broken file can't disable the integrations feature.

## The contract

A connector is a function `health(inst, c)` registered with `@_register`:

```python
from integrations import _register, _field, TEXT, PASSWORD, OK, WARN, CRIT, _STATS

@_register(
    type_id,        # unique short id, e.g. "mything"
    "Label",        # shown in the Settings dropdown
    "category",     # dns | storage | network | observability | media | apps | …
    [ _field("secret", "API token", PASSWORD),
      _field("slug", "Instance slug", TEXT, optional=True) ],
    notes="One sentence describing what it reads.",
)
def _mything(inst, c):
    ...
    return { "status": OK, "detail": "...", "metrics": {...}, "version": "..." }
```

### `inst` — the instance config

A dict with the operator-entered fields: `inst.get("url")`, `inst.get("secret")`,
`inst.get("username")`, `inst.get("slug")`, plus `verify_tls`. **Field keys must be
one of** `secret` (the primary credential — auto-redacted everywhere),
`username`, or `slug`. The `secret` field is never echoed back to the browser.

### `c` — the SSRF-safe HTTP client

Every request goes through RemotePower's SSRF guard (connect-time peer-IP recheck,
no redirects, loopback/metadata blocked, RFC-1918 LAN allowed). You don't manage
that — just call:

- `c.get_json(path, headers=…, params=…)` → parsed JSON; **raises
  `IntegrationError` on any non-2xx** (the poller turns that into a `critical`
  result, so you often don't need to check status yourself).
- `c.get(path, …)` → a `Resp` with `.status`, `.text`, `.ok`, `.json()`.
- `c.post_json(path, obj, …)` / `c.post_form(path, fields, …)` for login flows.

`path` is appended to the instance URL; an absolute `http(s)://…` path is also
allowed (and still SSRF-checked). Multiple requests per poll are fine (a cookie
jar persists across them within one poll).

### The return dict

```python
{
  "status":  "ok" | "warning" | "critical" | "unknown",   # OK/WARN/CRIT/UNKNOWN
  "detail":  "short human line",       # truncated to 200 chars
  "metrics": {"key": number_or_str},   # shown as tile chips
  "version": "1.2.3",                  # optional
}
```

All keys are optional (the poller fills defaults). Raise `IntegrationError("…")`
for a hard failure — it becomes a `critical` result with your message. Never let
an unexpected exception escape uncaught: the poller catches it, but a clear
`IntegrationError` gives a better message. Keep the parser defensive — chain
`.get()` so a missing field never `KeyError`s.

### The stat spec (required)

Every connector needs a `_STATS` entry so its metrics render as labelled tile
chips:

```python
_STATS["mything"] = [
    ("queue", "Queue", "int"),      # kind ∈ int | pct | num | rate | mb | flag | str
    ("errors", "Errors", "num"),
]
```

## Testing your connector

Connectors are trivially unit-testable with a fake client — no network. Model on
`tests/test_github_integration.py`:

```python
import integrations as I

class FakeClient(I.HTTPClient):
    def __init__(self, routes): super().__init__("http://x"); self.routes = routes
    def request(self, method, path, headers=None, params=None, body=None):
        st, payload = self.routes.get(path.split("?")[0], (404, {}))
        import json
        return I.Resp(st, json.dumps(payload))

def test_mything():
    c = FakeClient({"/api/health": (200, {"status": "ok", "queue": 3})})
    res = I.poll_instance({"type": "mything"}, c)
    assert res["status"] == I.OK
    assert res["metrics"]["queue"] == 3
```

## Installing

1. Copy your `.py` into `server/cgi-bin/connectors.d/` on the server.
2. Make sure the file is root-owned (`chown root:root`), matching `cgi-bin/`.
3. Reload — the connector appears in **Settings → Integrations**. A load error
   shows in the server error log (`journalctl -u remotepower-wsgi`, or nginx's
   error log).
