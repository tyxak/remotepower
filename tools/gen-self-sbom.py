#!/usr/bin/env python3
"""Generate a CycloneDX 1.5 SBOM of the RemotePower SERVER's own Python supply
chain (v5.4.1, C7). Distinct from the FLEET SBOM (`/api/sbom`, which inventories
monitored hosts) — this documents the control plane itself for supply-chain
transparency / SLSA.

Reads packaging/requirements-server.txt (PyPI names, one per line, `#` comments),
resolves each installed package's version if present, and emits CycloneDX JSON to
stdout. Stdlib only — no third-party build dependency, so it runs anywhere.

Usage:
    python3 tools/gen-self-sbom.py [SERVER_VERSION] > remotepower-server.sbom.json
"""
import json
import sys
from pathlib import Path

try:
    from importlib import metadata as _md
except ImportError:  # pragma: no cover - py<3.8
    _md = None  # type: ignore

_ROOT = Path(__file__).resolve().parent.parent
_REQ = _ROOT / "packaging" / "requirements-server.txt"


def _read_requirements():
    names = []
    for line in _REQ.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            names.append(line)
    return names


def _installed_version(name):
    if _md is None:
        return None
    for cand in (name, name.replace("-", "_")):
        try:
            return _md.version(cand)
        except Exception:
            continue
    return None


def build(server_version="0.0.0"):
    components = []
    for name in _read_requirements():
        ver = _installed_version(name)
        comp = {
            "type": "library",
            "name": name,
            "purl": f"pkg:pypi/{name}" + (f"@{ver}" if ver else ""),
        }
        if ver:
            comp["version"] = ver
        components.append(comp)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "remotepower-server",
                "version": server_version,
                "description": "RemotePower control plane (server).",
            },
            "tools": [{"name": "remotepower-gen-self-sbom"}],
        },
        "components": components,
    }


if __name__ == "__main__":
    ver = sys.argv[1] if len(sys.argv) > 1 else "0.0.0"
    json.dump(build(ver), sys.stdout, indent=2)
    sys.stdout.write("\n")
