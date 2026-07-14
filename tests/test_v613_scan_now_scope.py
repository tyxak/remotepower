#!/usr/bin/env python3
"""v6.1.3 bug hunt: fleet scan-now endpoints must honour ROLE SCOPE, not just
tenant isolation.

handle_secrets_scan_now / handle_pii_scan_now / handle_image_cve_scan (the
`{}`-body "scan every host" form) originally filtered their target set through a
per-device `_tenant_visible()` check only. A scoped operator (role scope confined
to one group/tag/site) therefore queued a one-shot scan on EVERY agent host in
the tenant, including hosts outside their scope — the same fleet-aggregate gap
the v6.1.1 sweep fixed for scap/sudo-search/risk/etc. The fix routes the target
set through `_scope_filter_devices`, which folds in BOTH role scope AND tenant.

This drives the real handlers with a scoped caller and asserts only in-scope
hosts get the `force_*_scan` flag. Runs under both backends.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
os.environ.setdefault("REQUEST_METHOD", "POST")
os.environ.setdefault("PATH_INFO", "/")
os.environ.setdefault("CONTENT_LENGTH", "0")
_CGI = Path(__file__).resolve().parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

_spec = importlib.util.spec_from_file_location("api_scan_scope", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Case(unittest.TestCase):
    # Attributes this suite monkeypatches on the api module. They MUST be
    # restored in tearDown — a leaked stub (esp. get_json_obj → {}) silently
    # breaks unrelated later tests in the same process (the leaked-monkeypatch
    # false-green class; pytest-randomly / full-suite ordering exposes it).
    _STUBBED = ("require_write_role", "_caller_scope", "get_json_obj",
                "audit_log", "respond")

    def setUp(self):
        self._orig = {name: getattr(api, name) for name in self._STUBBED}
        # Two hosts in different groups; the caller's scope covers only 'prod'.
        api.save(api.DEVICES_FILE, {
            "prod-1": {"name": "prod-1", "group": "prod", "tags": [],
                       "agentless": False, "sysinfo": {}},
            "stag-1": {"name": "stag-1", "group": "staging", "tags": [],
                       "agentless": False, "sysinfo": {}},
        })
        api.save(api.CONFIG_FILE, {
            "secrets_scan_enabled": True, "pii_scan_enabled": True,
            "image_scan_enabled": True,
        })
        api._LOAD_CACHE.clear()
        # Auth + scope stubs: a write-capable operator scoped to the 'prod' group.
        api.require_write_role = lambda *a, **k: "scoped-op"
        api._caller_scope = lambda: {"type": "groups", "values": ["prod"]}
        api.get_json_obj = lambda: {}          # fleet form (no device_id)
        api.audit_log = lambda *a, **k: None
        self._captured = {}

        def _respond(status, data=None):
            self._captured = {"status": status, "data": data}
            raise api.HTTPError(status, data)
        api.respond = _respond

    def tearDown(self):
        for name, val in self._orig.items():
            setattr(api, name, val)

    def _flagged(self, key):
        devs = api.load(api.DEVICES_FILE)
        return {d for d, dev in devs.items() if dev.get(key)}

    def _run(self, handler):
        api._LOAD_CACHE.clear()
        try:
            handler()
        except api.HTTPError:
            pass

    def test_secrets_scan_now_respects_scope(self):
        self._run(api.handle_secrets_scan_now)
        self.assertEqual(self._flagged("force_secrets_scan"), {"prod-1"})

    def test_pii_scan_now_respects_scope(self):
        self._run(api.handle_pii_scan_now)
        self.assertEqual(self._flagged("force_pii_scan"), {"prod-1"})

    def test_image_scan_now_respects_scope(self):
        # image scan targets only hosts that actually run containers.
        api.save(api.CONTAINERS_FILE, {
            "prod-1": {"items": [{"name": "nginx"}]},
            "stag-1": {"items": [{"name": "redis"}]},
        })
        api._LOAD_CACHE.clear()
        self._run(api.handle_image_cve_scan)
        self.assertEqual(self._flagged("force_image_scan"), {"prod-1"})


if __name__ == "__main__":
    unittest.main()
