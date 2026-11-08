#!/usr/bin/env python3
"""8.0.0: a TrueNAS that no longer has the REST API says so, in words.

The connector speaks the REST API at /api/v2.0, which the newest TrueNAS releases (26) no longer have: the same paths answer 404, and the connector reported "HTTP 404", which names neither the cause nor
the remedy. Its replacement is a JSON-RPC 2.0 API over a WebSocket (/api/current) that the connector does not speak yet, so the failure now says that. A refused key and any other status are said
too, and a TrueNAS that still has the REST API reads as it did.

The connector is run against a fake client that answers by method and path; no TrueNAS is available here.
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server" / "cgi-bin"))
import integrations as I  # noqa: E402


class Fake(I.HTTPClient):
    def __init__(self, routes, base="https://nas"):
        super().__init__(base)
        self.routes, self.calls = routes, []

    def request(self, method, path, headers=None, params=None, body=None):
        self.calls.append((method, path.split("?")[0]))
        v = self.routes.get((method, path.split("?")[0]))
        if v is None:
            return I.Resp(404, "")
        st, payload = v
        return I.Resp(st, payload if isinstance(payload, str) else json.dumps(payload))


def poll(routes):
    c = Fake(routes)
    return I.poll_instance({"type": "truenas", "url": "https://nas", "secret": "KEY"}, c), c


HEALTHY = {
    ("GET", "/api/v2.0/system/info"): (200, {"version": "TrueNAS-SCALE-24.10.2"}),
    ("GET", "/api/v2.0/pool"): (200, [{"name": "tank", "status": "ONLINE"}]),
    ("GET", "/api/v2.0/alert/list"): (200, []),
}


class TestTheRestApiIsGone(unittest.TestCase):
    def test_a_404_says_that_the_newest_releases_have_no_rest_api_and_what_replaces_it(self):
        for status in (404, 410):
            with self.subTest(status=status):
                r, c = poll({("GET", "/api/v2.0/system/info"): (status, "")})
                self.assertEqual(r["status"], I.CRIT)
                self.assertIn("no REST API at /api/v2.0", r["detail"])
                self.assertIn("TrueNAS 26 removed it", r["detail"])
                self.assertIn("WebSocket API", r["detail"])
                self.assertFalse(r["detail"].endswith("…") or len(r["detail"]) >= 200, "the whole sentence reaches the card: the poller keeps 200 characters")
                self.assertEqual(c.calls, [("GET", "/api/v2.0/system/info")], "one question, and no more once it is known")

    def test_a_host_that_is_not_a_truenas_at_all_reads_the_same_and_the_words_leave_the_address_to_check(self):
        r, _ = poll({})
        self.assertIn("check the address", r["detail"])

    def test_a_refused_key_is_said(self):
        for status in (401, 403):
            with self.subTest(status=status):
                r, _ = poll({("GET", "/api/v2.0/system/info"): (status, {"message": "no"})})
                self.assertEqual((r["status"], r["detail"]), (I.CRIT, f"unauthorized (HTTP {status}) — check the API key"))

    def test_any_other_status_is_named(self):
        r, _ = poll({("GET", "/api/v2.0/system/info"): (500, "boom")})
        self.assertEqual((r["status"], r["detail"]), (I.CRIT, "/api/v2.0/system/info answered HTTP 500"))

    def test_a_body_that_is_not_an_object_has_no_version_and_does_not_break_the_poll(self):
        r, _ = poll({**HEALTHY, ("GET", "/api/v2.0/system/info"): (200, [])})
        self.assertEqual(r["status"], I.OK)
        self.assertEqual(r.get("version", ""), "")


class TestATruenasThatHasItIsUnchanged(unittest.TestCase):
    def test_a_healthy_pool_is_ok_with_its_version(self):
        r, c = poll(HEALTHY)
        self.assertEqual((r["status"], r["version"], r["detail"]), (I.OK, "TrueNAS-SCALE-24.10.2", "1 pools healthy"))
        self.assertEqual(c.calls, [("GET", "/api/v2.0/system/info"), ("GET", "/api/v2.0/pool"), ("GET", "/api/v2.0/alert/list")])

    def test_a_degraded_pool_is_critical_as_before(self):
        r, _ = poll({**HEALTHY, ("GET", "/api/v2.0/pool"): (200, [{"name": "tank", "status": "DEGRADED"}])})
        self.assertEqual(r["status"], I.CRIT)
        self.assertIn("DEGRADED: tank", r["detail"])


if __name__ == "__main__":
    unittest.main()
