"""A body of the wrong TYPE is a 400, not a 500.

Every route was sent a body whose keys all held an integer, a list or a number
past the float range. These were the ones that answered `500 Internal server
error`; each is now a client error. The general class (`(body.get('x') or
'').strip()` on a non-string) is held at zero by
test_no_unguarded_str_method_on_get.py; these are the handler-level checks for
the sites that were found, so the status itself is pinned.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-hostile-types-"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server" / "cgi-bin"))

import api  # noqa: E402


class _Base(unittest.TestCase):
    def setUp(self):
        self._saved = {k: getattr(api, k) for k in ("verify_token", "method", "get_json_obj", "_env")}
        api.verify_token = lambda _t=None: ("alice", "admin")
        api.method = lambda: "POST"
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for k, v in self._saved.items():
            setattr(api, k, v)

    def call(self, fn, body=None, method="POST", qs="", *args):
        api.method = lambda: method
        api.get_json_obj = lambda: dict(body or {})
        real_env = self._saved["_env"]
        api._env = lambda k, d="": qs if k == "QUERY_STRING" else real_env(k, d)
        try:
            fn(*args)
        except api.HTTPError as e:
            return e.status, e.body
        self.fail("handler did not respond")


class TestWrongTypesAreClientErrors(_Base):
    def test_a_role_name_that_is_a_number(self):
        status, _ = self.call(api.handle_role_create, {"name": 5, "permissions": []})
        self.assertEqual(status, 400)

    def test_a_webhook_destination_id_that_is_a_number(self):
        status, _ = self.call(api.handle_webhook_test, {"id": 5})
        self.assertIn(status, (400, 404))

    def test_a_snapshot_name_that_is_a_list(self):
        status, _ = self.call(api.proxmox_handlers_mod.handle_proxmox_snapshot_action,
                              {"type": "qemu", "vmid": 100, "action": "create", "name": ["a"]})
        self.assertLess(status, 500)

    def test_an_acme_path_without_a_domain(self):
        status, _ = self.call(api.handle_acme_force_renew, {}, "POST", "", "pmx01", "")
        self.assertEqual(status, 400)
        # and through the router, which split the path into two names and raised
        # when there was only one
        api._env = lambda k, d="": d
        self.assertTrue(callable(api._route_code_81))
        api.method = lambda: "POST"
        try:
            api._route_code_81("/api/acme/pmx01/renew", "POST")
        except api.HTTPError as e:
            self.assertEqual(e.status, 400)

    def test_a_log_search_limit_that_is_not_a_number(self):
        status, body = self.call(api.handle_log_search, None, "GET", "q=error&limit=abc")
        self.assertEqual(status, 400)
        self.assertIn("limit", body["error"])

    def test_hours_past_the_float_range(self):
        status, _ = self.call(api.handle_time_entries,
                              {"hours": 10 ** 400, "date": "2026-10-01", "description": "x"})
        self.assertLess(status, 500)


if __name__ == "__main__":
    unittest.main()
