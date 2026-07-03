"""Federation-lite peer connector — the ``remotepower`` integration.

Reads a PEER RemotePower instance's public health (GET /api/nav-counts, with
the fleet/health total and the no-auth public-info version) so an off-site
instance shows up as a tile beside the homelab integrations. Read-only; not
federation. These tests drive the pure connector against a fake HTTP client
(no network): happy path, degraded peer, unreachable, auth header, and the
stat-chip spec.
"""

import json
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

import integrations as I  # noqa: E402


class FakeClient(I.HTTPClient):
    """Route table keyed by path (query stripped) → (status, json-able body).

    A missing route returns 404 so an "unreachable" peer is modeled by simply
    not registering /api/nav-counts.
    """

    def __init__(self, routes=None):
        super().__init__("https://peer.example.com")
        self.routes = routes or {}
        self.calls = []

    def request(self, method, path, headers=None, params=None, body=None):
        p = path.split("?")[0]
        self.calls.append((method, p, dict(headers or {})))
        v = self.routes.get(p)
        if v is None:
            return I.Resp(404, json.dumps({"error": "not found"}))
        status, obj = v
        return I.Resp(status, json.dumps(obj))


def _navcounts(fleet=0, monitoring=0, security=0, healthy=True, alerts_open=0):
    return {
        "fleet": fleet,
        "monitoring": monitoring,
        "security": security,
        "site_health": {
            "healthy": healthy,
            "issues": 0 if healthy else 1,
            "failing": [] if healthy else ["Disk space"],
        },
        "alerts": {
            "open": alerts_open,
            "acknowledged": 0,
            "resolved": 0,
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        },
    }


def _routes(nav, total_devices=12, version="5.8.0"):
    r = {"/api/nav-counts": (200, nav)}
    if total_devices is not None:
        r["/api/fleet/health"] = (200, {"total_devices": total_devices, "score": 98})
    if version is not None:
        r["/api/public-info"] = (200, {"server_version": version, "server_name": "peer"})
    return r


class TestPeerConnector(unittest.TestCase):
    def test_registered_with_stats(self):
        self.assertIn("remotepower", I.CONNECTORS)
        spec = I.CONNECTORS["remotepower"]
        self.assertEqual(spec["category"], "observability")
        # Single credential, named 'secret' so the config scrubber redacts it.
        self.assertEqual([f["key"] for f in spec["fields"]], ["secret"])
        self.assertEqual(spec["fields"][0]["kind"], I.PASSWORD)
        self.assertTrue(I._STATS.get("remotepower"))
        self.assertEqual(
            [k for k, _l, _kind in I._STATS["remotepower"]], ["devices", "offline", "alerts_open"]
        )

    def test_happy_path_ok_with_metrics(self):
        c = FakeClient(_routes(_navcounts(), total_devices=12))
        res = I.poll_instance({"type": "remotepower", "secret": "rpk_abc"}, c)
        self.assertEqual(res["status"], I.OK)
        self.assertEqual(res["metrics"], {"devices": 12, "offline": 0, "alerts_open": 0})
        self.assertEqual(res["version"], "5.8.0")
        self.assertIn("12 devices", res["detail"])
        self.assertIn("0 offline", res["detail"])
        self.assertIn("0 open alerts", res["detail"])

    def test_auth_sent_as_x_token_and_bearer(self):
        c = FakeClient(_routes(_navcounts()))
        I.poll_instance({"type": "remotepower", "secret": "rpk_secret"}, c)
        # The nav-counts call must carry the peer's viewer key.
        nav_call = next(h for _m, p, h in c.calls if p == "/api/nav-counts")
        self.assertEqual(nav_call.get("X-Token"), "rpk_secret")
        self.assertEqual(nav_call.get("Authorization"), "Bearer rpk_secret")

    def test_degraded_offline_and_alerts_is_warning(self):
        c = FakeClient(_routes(_navcounts(fleet=1, alerts_open=3), total_devices=12))
        res = I.poll_instance({"type": "remotepower", "secret": "k"}, c)
        self.assertEqual(res["status"], I.WARN)
        self.assertEqual(res["metrics"], {"devices": 12, "offline": 1, "alerts_open": 3})
        self.assertIn("1 offline", res["detail"])
        self.assertIn("3 open alerts", res["detail"])

    def test_unhealthy_control_plane_is_warning(self):
        # Quiet fleet but the peer reports its own control-plane as degraded.
        c = FakeClient(_routes(_navcounts(healthy=False), total_devices=5))
        res = I.poll_instance({"type": "remotepower", "secret": "k"}, c)
        self.assertEqual(res["status"], I.WARN)
        self.assertIn("control-plane degraded", res["detail"])

    def test_unreachable_is_critical(self):
        # No route for /api/nav-counts → 404 → IntegrationError → critical.
        c = FakeClient({})
        res = I.poll_instance({"type": "remotepower", "secret": "k"}, c)
        self.assertEqual(res["status"], I.CRIT)

    def test_auth_failure_is_critical(self):
        c = FakeClient({"/api/nav-counts": (401, {"error": "unauthorized"})})
        res = I.poll_instance({"type": "remotepower", "secret": "wrong"}, c)
        self.assertEqual(res["status"], I.CRIT)

    def test_missing_secret_is_critical(self):
        res = I.poll_instance({"type": "remotepower"}, FakeClient(_routes(_navcounts())))
        self.assertEqual(res["status"], I.CRIT)
        self.assertIn("viewer-role API key", res["detail"])

    def test_degrades_gracefully_without_fleet_health_or_version(self):
        # An older/limited peer: only nav-counts answers. devices metric omitted,
        # no version, but the tile still renders OK from the vitals it does have.
        c = FakeClient({"/api/nav-counts": (200, _navcounts())})
        res = I.poll_instance({"type": "remotepower", "secret": "k"}, c)
        self.assertEqual(res["status"], I.OK)
        self.assertNotIn("devices", res["metrics"])
        self.assertNotIn("version", res)
        self.assertEqual(res["metrics"], {"offline": 0, "alerts_open": 0})

    def test_stat_chips_render(self):
        chips = I.format_stats("remotepower", {"devices": 12, "offline": 1, "alerts_open": 3})
        labels = {ch["label"]: ch["value"] for ch in chips}
        self.assertEqual(labels.get("Devices"), "12")
        self.assertEqual(labels.get("Offline"), "1")
        self.assertEqual(labels.get("Open alerts"), "3")


if __name__ == "__main__":
    unittest.main()
