# connectors.d — operator connector plugins

Drop a `*.py` file here to add your own homelab **integration connector** without
editing RemotePower's source. Each file is imported at startup and self-registers
via the same `@_register` decorator the built-in connectors use.

## Security

Files here are **executed as the web-server user**, exactly like the rest of
`cgi-bin/`. Keep this directory **root-owned and operator-writable only** (same
permissions as `cgi-bin/`). There is deliberately **no UI upload path** —
plugins are filesystem-only, installed by someone with shell access. A plugin
that raises on import is logged to the server error log and skipped; it can't
take the integrations feature down.

## Minimal example

```python
# connectors.d/mything.py
from integrations import _register, _field, TEXT, PASSWORD, OK, WARN, CRIT, _STATS

@_register("mything", "My Thing", "apps",
           [_field("secret", "API token", PASSWORD)],
           notes="Polls My Thing's /api/health endpoint.")
def _mything(inst, c):
    data = c.get_json("/api/health", headers={"Authorization": "Bearer " + (inst.get("secret") or "")})
    ok = (data or {}).get("status") == "ok"
    return {
        "status": OK if ok else CRIT,
        "detail": f"queue={data.get('queue', 0)}",
        "metrics": {"queue": data.get("queue", 0)},
    }

# every connector needs a stat spec (metric_key, "Label", kind)
_STATS["mything"] = [("queue", "Queue", "int")]
```

See **[docs/writing-a-connector.md](../../../docs/writing-a-connector.md)** for the
full contract (the `health(inst, c)` return shape, the HTTP client surface, field
kinds, and the fake-client test harness).
