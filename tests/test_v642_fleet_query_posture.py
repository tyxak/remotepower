"""v6.4.2 (data-binding): host security posture is queryable fleet-wide.

"Which hosts have no active firewall / password-SSH / auto-updates off" had no
query facet, though the signals were stored and drove risk/advisory/checks.
Driven through the real handle_fleet_query.
"""

import importlib.util
import json
import os
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-fqpost-"))

_spec = importlib.util.spec_from_file_location("api_fqpost", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestPostureFacets(unittest.TestCase):
    def setUp(self):
        self.d = pathlib.Path(tempfile.mkdtemp())
        self._df = api.DEVICES_FILE
        api.DEVICES_FILE = self.d / "devices.json"
        api.save(api.DEVICES_FILE, {
            "fwoff": {"name": "fwoff", "last_seen": 1, "monitored": True,
                      "sysinfo": {"firewall": {"active": False, "backends": []}}},
            "fwon": {"name": "fwon", "last_seen": 1, "monitored": True,
                     "sysinfo": {"firewall": {"active": True, "backends": []}}},
            "fwunknown": {"name": "fwunknown", "last_seen": 1, "monitored": True,
                          "sysinfo": {"firewall": {"active": None}}},
            "sshbad": {"name": "sshbad", "last_seen": 1, "monitored": True,
                       "sysinfo": {"ssh_config": {"permit_root_login": "yes",
                                                  "password_authentication": "no"}}},
            "sshgood": {"name": "sshgood", "last_seen": 1, "monitored": True,
                        "sysinfo": {"ssh_config": {"permit_root_login": "no",
                                                   "password_authentication": "no",
                                                   "permit_empty_passwords": "no"}}},
            "auoff": {"name": "auoff", "last_seen": 1, "monitored": True,
                      "sysinfo": {"autoupdate": {"enabled": False}}},
        })
        api._invalidate_load_cache(api.DEVICES_FILE)
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in
                      ("respond", "require_auth", "_env", "_scope_filter_devices",
                       "method")}
        api.require_auth = lambda **k: "admin"
        api._scope_filter_devices = lambda d: d
        api.method = lambda: "GET"

        def _resp(s, b=None):
            self.cap["s"], self.cap["b"] = s, b
            raise api.HTTPError(s, b)
        api.respond = _resp

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        api.DEVICES_FILE = self._df

    def _query(self, qs):
        api._env = lambda k, dv="": (qs if k == "QUERY_STRING" else dv)
        try:
            api.handle_fleet_query()
        except api.HTTPError:
            pass
        b = self.cap.get("b") or {}
        rows = b.get("devices") or b.get("results") or b.get("rows") or []
        return {r.get("id") or r.get("device_id") or r.get("name") for r in rows}

    def test_firewall_off_matches_only_the_inactive_host(self):
        ids = self._query("firewall_off=1")
        self.assertIn("fwoff", ids)
        self.assertNotIn("fwon", ids)
        self.assertNotIn("fwunknown", ids)   # None = unknown, never matched

    def test_ssh_weak_matches_root_login(self):
        ids = self._query("ssh_weak=1")
        self.assertIn("sshbad", ids)
        self.assertNotIn("sshgood", ids)

    def test_autoupdate_off_matches(self):
        ids = self._query("autoupdate_off=1")
        self.assertIn("auoff", ids)
        self.assertNotIn("fwon", ids)

    def test_no_facet_returns_all(self):
        ids = self._query("")
        self.assertGreaterEqual(len(ids), 6)

    def test_facets_are_in_the_whitelist(self):
        for f in ("firewall_off", "ssh_weak", "autoupdate_off"):
            self.assertIn(f, api._FQ_PARAMS)


if __name__ == "__main__":
    unittest.main()
