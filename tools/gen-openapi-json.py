#!/usr/bin/env python3
"""Dump the RemotePower OpenAPI 3.1 spec as a standalone JSON file (v6.1.1).

Same spec `GET /api/openapi.json` serves live, generated the same way
tools/gen-postman.py already does (route-table-driven, full coverage) --
this is just the raw spec as a file, for offline tools that need one (an
SDK generator, a local Redoc/Swagger-UI preview, a spec linter/diff).

Usage:
    python3 tools/gen-openapi-json.py > openapi.json
"""
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))

import openapi_spec  # noqa: E402


def build():
    """Full route coverage when api is importable; falls back to the
    hand-written paths otherwise (keeps the tool usable in a slim tree) --
    same fallback tools/gen-postman.py uses."""
    try:
        import api  # heavy, but gives the whole route table
        return openapi_spec.build_spec(api.SERVER_VERSION,
                                       routes=list(api._build_exact_routes().keys()))
    except Exception:
        return openapi_spec.build_spec("0.0.0")


if __name__ == "__main__":
    json.dump(build(), sys.stdout, indent=2)
    sys.stdout.write("\n")
