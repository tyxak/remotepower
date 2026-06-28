#!/usr/bin/env python3
"""Generate a Postman v2.1 collection for the RemotePower API from the OpenAPI
spec (v5.4.1, E5). Because the spec is now route-table-driven (every endpoint is
covered), the collection is too — one request per path+method, foldered by tag.

Auth is wired as an `X-Token` apikey at the collection level (a `{{token}}`
variable); `{{baseUrl}}` defaults to the versioned `/api/v1` base. Import the
output into Postman / Insomnia / Bruno, set `token` + `baseUrl`, and go.

Usage:
    python3 tools/gen-postman.py > remotepower.postman_collection.json
"""
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))

import openapi_spec  # noqa: E402

_METHODS = ("get", "post", "put", "patch", "delete")


def _spec():
    """Build the spec with full route coverage when api is importable; fall back
    to the hand-written paths otherwise (keeps the tool usable in a slim tree)."""
    try:
        import api  # heavy, but gives the whole route table
        return openapi_spec.build_spec(api.SERVER_VERSION,
                                       routes=list(api._build_exact_routes().keys()))
    except Exception:
        return openapi_spec.build_spec("0.0.0")


def _request_item(path, method, op):
    segs = [s for s in path.strip("/").split("/") if s]
    return {
        "name": op.get("summary") or f"{method.upper()} {path}",
        "request": {
            "method": method.upper(),
            "header": [],
            "url": {
                "raw": "{{baseUrl}}" + path,
                "host": ["{{baseUrl}}"],
                "path": segs,
            },
            "description": op.get("description", ""),
        },
    }


def build():
    spec = _spec()
    paths = spec.get("paths", {})
    folders = {}   # tag -> [items]
    for path, ops in sorted(paths.items()):
        for method, op in ops.items():
            if method not in _METHODS or not isinstance(op, dict):
                continue
            tag = (op.get("tags") or ["Other"])[0]
            folders.setdefault(tag, []).append(_request_item(path, method, op))
    items = [{"name": tag, "item": reqs} for tag, reqs in sorted(folders.items())]
    return {
        "info": {
            "name": f"RemotePower API ({spec.get('info', {}).get('version', '')})",
            "description": "Generated from the RemotePower OpenAPI spec (tools/gen-postman.py).",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
        },
        "auth": {
            "type": "apikey",
            "apikey": [
                {"key": "key", "value": "X-Token", "type": "string"},
                {"key": "value", "value": "{{token}}", "type": "string"},
                {"key": "in", "value": "header", "type": "string"},
            ],
        },
        "variable": [
            {"key": "baseUrl", "value": "http://localhost/api/v1"},
            {"key": "token", "value": ""},
        ],
        "item": items,
    }


if __name__ == "__main__":
    json.dump(build(), sys.stdout, indent=2)
    sys.stdout.write("\n")
