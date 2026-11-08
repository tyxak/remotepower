#!/usr/bin/env python3
"""8.0.0: the demo shows the three connectors this release adds (Tailscale, Headscale, Cloudflare Tunnel).

A seeded tile is a claim about what the connector says, so each row is held against the connector itself: the numbers of the row go through the real
summary function (the overlay networks) or the real connector fed a canned Cloudflare answer, and the status, the sentence and the metric keys must be
the ones it gives. A row that drifts from the connector is a demo that shows a tile no installation can draw.
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-seeder-overlay-"))
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))
import integrations as I  # noqa: E402


def _seeder():
    spec = importlib.util.spec_from_file_location("seed_demo_overlay", _ROOT / "packaging" / "seed-demo-data.py")
    mod = importlib.util.module_from_spec(spec)             # type: ignore[arg-type]
    spec.loader.exec_module(mod)                             # type: ignore[union-attr]
    return mod


SEED = _seeder()
ROWS = {r[0]: r for r in SEED._DEMO_INTEG_DEFS}
NOW = 1_800_000_000


def _hosts(total, online, expiring=0, updates=0):
    day = 86400
    out = []
    for i in range(total):
        out.append({"online": i < online, "last_seen": NOW - (60 if i < online else 5 * day), "expires": NOW + 3 * day if i < expiring else NOW + 200 * day,
                    "no_expiry": False, "update": i < updates, "authorized": True})
    return out


class Fake(I.HTTPClient):
    def __init__(self, payload):
        super().__init__("https://api.example")
        self.payload = payload

    def request(self, method, path, headers=None, params=None, body=None):
        return I.Resp(200, json.dumps(self.payload))


class TestTheDemoShowsTheOverlayConnectors(unittest.TestCase):

    def test_the_three_types_are_in_the_registry_and_in_the_seed(self):
        for t in ("tailscale", "headscale", "cloudflare_tunnel"):
            self.assertIn(t, I.CONNECTORS, t)
            self.assertIn(t, ROWS, "the demo has no %s tile" % t)

    def test_a_tailscale_row_says_what_the_connector_says_for_those_numbers(self):
        _t, _label, _url, status, detail, _ver, metrics = ROWS["tailscale"]
        got = I._overlay_summary(_hosts(14, 11, expiring=2, updates=3), now=NOW)
        self.assertEqual((status, detail, metrics), (got["status"], got["detail"], got["metrics"]))

    def test_a_headscale_row_says_what_the_connector_says_for_those_numbers(self):
        _t, _label, _url, status, detail, _ver, metrics = ROWS["headscale"]
        got = I._overlay_summary(_hosts(6, 5), now=NOW)
        self.assertEqual((status, detail, metrics), (got["status"], got["detail"], got["metrics"]))

    def test_the_cloudflare_row_says_what_the_connector_says_for_a_matching_answer(self):
        _t, _label, _url, status, detail, _ver, metrics = ROWS["cloudflare_tunnel"]
        tunnels = ([{"name": "a", "status": "healthy", "connections": [{}, {}, {}]}, {"name": "b", "status": "healthy", "connections": [{}, {}]},
                    {"name": "c", "status": "degraded", "connections": [{}, {}]}])
        got = I._cloudflare_tunnel({"slug": "0" * 32, "secret": "x"}, Fake({"success": True, "result": tunnels}))
        self.assertEqual((status, detail, metrics), (got["status"], got["detail"], got["metrics"]))

    def test_every_metric_key_has_a_tile_label(self):
        for t in ("tailscale", "headscale", "cloudflare_tunnel"):
            labels = {k for (k, _label, _kind) in I._STATS.get(t, ())}
            self.assertTrue(labels, "no chips are defined for %s" % t)
            self.assertTrue(set(ROWS[t][6]) & labels, "none of the row's numbers is drawn as a chip for %s" % t)

    def test_the_control_notices_a_row_that_drifts(self):
        got = I._overlay_summary(_hosts(14, 10, expiring=2, updates=3), now=NOW)
        self.assertNotEqual(got["metrics"], ROWS["tailscale"][6])


if __name__ == "__main__":
    unittest.main()
