#!/usr/bin/env python3
"""A host whose services_watched holds a list or a map no longer gets a 500 from every heartbeat.

The heartbeat answer builds the host's watch list with `set(saved_dev.get('services_watched'))`, and a
list or a map in it is not hashable. The 7.5.0 agent security review set `services_watched` to `[[1], {}]` in
a host record and POST /api/heartbeat answered HTTP 500 for that host, every time, until the record was
edited by hand. The field comes from the settings handlers, which store names, so the way in is a hand-
edited store or an old restore; the agent then gets no answer and cannot recover by itself.

Two fixes, and each is held alone: the shape registry types the field (a store read repairs it), and the
heartbeat answer ignores what is not a name even if a read did not repair it.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-sw-"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_v742_container_recovery import DEV, _Base, _Captured, _Stdin, api  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server" / "cgi-bin"))
import store_shapes  # noqa: E402


class TestTheRegistryTypesIt(unittest.TestCase):

    def test_a_list_or_a_map_among_the_names_is_left_out(self):
        doc = {"h1": {"name": "web", "services_watched": ["nginx.service", [1], {}, None, "ssh.service"]}}
        out = store_shapes.normalize("devices.json", doc)
        self.assertEqual(out["h1"]["services_watched"], ["nginx.service", "ssh.service"])

    def test_a_number_is_read_as_the_text_it_is(self):
        """The registry's own rule for a text field: nothing is lost by reading 7 as '7'."""
        doc = {"h1": {"name": "web", "services_watched": ["nginx.service", 7]}}
        out = store_shapes.normalize("devices.json", doc)
        self.assertEqual(out["h1"]["services_watched"], ["nginx.service", "7"])

    def test_a_field_that_is_not_a_list_becomes_an_empty_one(self):
        for junk in ("nginx.service", 5, {"a": 1}):
            out = store_shapes.normalize("devices.json", {"h1": {"name": "web", "services_watched": junk}})
            self.assertEqual(out["h1"]["services_watched"], [], junk)

    def test_a_good_list_is_untouched(self):
        doc = {"h1": {"name": "web", "services_watched": ["a.service", "b.service"]}}
        self.assertEqual(store_shapes.normalize("devices.json", doc)["h1"]["services_watched"],
                         ["a.service", "b.service"])


class TestTheHeartbeatAnswersAnyway(_Base):
    """The real heartbeat. The record is written under the lock, past the registry's read-time repair, to prove the
    reader does not depend on it."""

    def beat(self):
        raw = json.dumps({"device_id": DEV, "token": "tok"}).encode()
        os.environ.update({"REQUEST_METHOD": "POST", "PATH_INFO": "/api/heartbeat",
                           "QUERY_STRING": "", "CONTENT_LENGTH": str(len(raw))})
        for k in ("HTTP_X_TOKEN", "HTTP_X_RP_VAULT_KEY"):
            os.environ.pop(k, None)
        api.sys.stdin = _Stdin(raw)
        api._LOAD_CACHE.clear()
        try:
            api.handle_heartbeat()
        except _Captured as c:
            return c.status, c.body
        self.fail("heartbeat did not answer")

    def setUp(self):
        super().setUp()
        # The registry repairs the field on every read. Switch that off, so that these tests see whether the REPLY copes
        # with what the registry would have fixed.
        self._norm = api.store_shapes.normalize
        api.store_shapes.normalize = lambda name, doc, *a, **k: doc

    def tearDown(self):
        api.store_shapes.normalize = self._norm
        super().tearDown()

    def poison(self, value):
        with api._LockedUpdate(api.DEVICES_FILE) as devs:
            devs[DEV]["services_watched"] = value
        api._LOAD_CACHE.clear()

    def test_a_good_record_is_answered_with_its_names(self):
        self.poison(["nginx.service", "ssh.service"])
        st, body = self.beat()
        self.assertEqual(st, 200, body)
        self.assertEqual(body["services_watched"], ["nginx.service", "ssh.service"])

    def test_a_list_among_the_names_is_a_200_with_the_names_that_are_names(self):
        self.poison([[1], {}, "nginx.service", None])
        st, body = self.beat()
        self.assertEqual(st, 200, body)
        self.assertEqual(body["services_watched"], ["nginx.service"])
        for u in body["services_watched"]:
            self.assertIsInstance(u, str)

    def test_nothing_but_junk_is_an_empty_list(self):
        self.poison([[1], {}])
        st, body = self.beat()
        self.assertEqual((st, body["services_watched"]), (200, []))

    def test_a_field_that_is_null_is_an_empty_list(self):
        self.poison(None)
        st, body = self.beat()
        self.assertEqual((st, body["services_watched"]), (200, []))


if __name__ == "__main__":
    unittest.main()
