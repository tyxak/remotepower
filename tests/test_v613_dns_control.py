"""v6.2.0 — DNS-blocker control (gap item #11): the WRITE half of the Pi-hole /
AdGuard connectors.

The drivers are pure `fn(inst, client, ...)` over the SSRF-safe client, so they
test against a fake client with no network — the same way every read-only
connector in integrations.py is tested.

The property that matters most here is NOT "can we disable blocking" — it is that
we can only disable it **temporarily**. A DNS blocker switched off and forgotten
is a silent, permanent security regression, which is the exact opposite of what
this product is for. So the tests below pin: every disable carries a timer, the
timer is clamped, and there is no code path that disables blocking indefinitely.
"""

import json
import sys
import unittest
from pathlib import Path

_CGI = Path(__file__).resolve().parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

import dns_control as dc                     # noqa: E402
from integrations import HTTPClient, Resp, IntegrationError   # noqa: E402


class FakeClient(HTTPClient):
    """Records every request and replays canned responses, keyed by (method, path)."""

    def __init__(self, routes):
        super().__init__("http://blocker.local")
        self.routes = routes
        self.calls = []

    def request(self, method, path, headers=None, params=None, body=None):
        parsed = json.loads(body.decode()) if body else None
        self.calls.append({"method": method, "path": path,
                           "headers": headers or {}, "body": parsed})
        key = (method, path.split("?", 1)[0])
        if key not in self.routes:
            return Resp(404, "")
        r = self.routes[key]
        return r(parsed) if callable(r) else r


def _pihole_routes(blocking="enabled", timer=None):
    state = {"blocking": blocking, "timer": timer}

    def _set(body):
        state["blocking"] = "enabled" if body.get("blocking") else "disabled"
        state["timer"] = body.get("timer")
        return Resp(200, json.dumps(state))

    return {
        ("POST", "/api/auth"): Resp(200, json.dumps({"session": {"sid": "SID123"}})),
        ("GET", "/api/dns/blocking"): lambda _b: Resp(200, json.dumps(state)),
        ("POST", "/api/dns/blocking"): _set,
    }, state


def _adguard_routes(enabled=True, ms=0):
    state = {"protection_enabled": enabled, "protection_disabled_duration": ms}

    def _set(body):
        state["protection_enabled"] = bool(body.get("enabled"))
        state["protection_disabled_duration"] = body.get("duration") or 0
        return Resp(200, "{}")

    return {
        ("GET", "/control/status"): lambda _b: Resp(200, json.dumps(state)),
        ("POST", "/control/protection"): _set,
    }, state


class TestClamp(unittest.TestCase):
    """The disable window is the whole safety story."""

    def test_an_absurd_window_is_clamped_not_honoured(self):
        self.assertEqual(dc.MAX_DISABLE_SECONDS, dc.clamp_seconds(10 ** 9))

    def test_a_tiny_window_is_raised_to_the_floor(self):
        self.assertEqual(dc.MIN_DISABLE_SECONDS, dc.clamp_seconds(1))

    def test_garbage_falls_back_to_the_default(self):
        """Refusing to act on a fat-fingered timer is worse than acting on a safe
        default one — the caller has already passed the request model."""
        for junk in (None, "", "abc", {}, []):
            self.assertEqual(dc.DEFAULT_DISABLE_SECONDS, dc.clamp_seconds(junk))

    def test_a_sane_window_is_left_alone(self):
        self.assertEqual(600, dc.clamp_seconds(600))

    def test_the_ceiling_is_hours_not_days(self):
        """A blocker off for a day is not 'debugging', it is 'switched off'."""
        self.assertLessEqual(dc.MAX_DISABLE_SECONDS, 4 * 3600)


class TestPihole(unittest.TestCase):
    def test_status_reads_blocking_and_countdown(self):
        routes, _ = _pihole_routes(blocking="disabled", timer=120)
        st = dc.pihole_status({"secret": "pw"}, FakeClient(routes))
        self.assertEqual({"blocking": False, "remaining": 120}, st)

    def test_status_when_blocking_is_on(self):
        routes, _ = _pihole_routes(blocking="enabled", timer=None)
        st = dc.pihole_status({"secret": "pw"}, FakeClient(routes))
        self.assertEqual({"blocking": True, "remaining": 0}, st)

    def test_disable_always_sends_a_timer(self):
        """The core safety property: Pi-hole itself re-enables when it lapses, so
        the safe state is restored by the remote device — not by a sweep here that
        might never run."""
        routes, state = _pihole_routes()
        c = FakeClient(routes)
        dc.pihole_set_blocking({"secret": "pw"}, c, False, 300)
        post = [x for x in c.calls
                if x["method"] == "POST" and x["path"] == "/api/dns/blocking"][0]
        self.assertIs(False, post["body"]["blocking"])
        self.assertEqual(300, post["body"]["timer"])
        self.assertEqual("disabled", state["blocking"])

    def test_disable_clamps_an_absurd_timer_at_the_driver(self):
        """Belt and braces: even if a caller skipped clamp_seconds, the driver
        clamps. The bound must not depend on the handler remembering."""
        routes, _ = _pihole_routes()
        c = FakeClient(routes)
        dc.pihole_set_blocking({"secret": "pw"}, c, False, 10 ** 9)
        post = [x for x in c.calls if x["method"] == "POST"
                and x["path"] == "/api/dns/blocking"][0]
        self.assertEqual(dc.MAX_DISABLE_SECONDS, post["body"]["timer"])

    def test_enable_sends_no_timer(self):
        """A countdown is meaningless when turning blocking back ON."""
        routes, state = _pihole_routes(blocking="disabled", timer=60)
        c = FakeClient(routes)
        st = dc.pihole_set_blocking({"secret": "pw"}, c, True, 300)
        post = [x for x in c.calls if x["method"] == "POST"
                and x["path"] == "/api/dns/blocking"][0]
        self.assertIs(True, post["body"]["blocking"])
        self.assertIsNone(post["body"]["timer"])
        self.assertTrue(st["blocking"])

    def test_a_write_is_authenticated(self):
        routes, _ = _pihole_routes()
        c = FakeClient(routes)
        dc.pihole_set_blocking({"secret": "pw"}, c, False, 300)
        post = [x for x in c.calls if x["method"] == "POST"
                and x["path"] == "/api/dns/blocking"][0]
        self.assertEqual("SID123", post["headers"].get("X-FTL-SID"))

    def test_a_bad_password_is_a_clear_error_not_a_silent_noop(self):
        routes, _ = _pihole_routes()
        routes[("POST", "/api/auth")] = Resp(200, json.dumps({"session": {}}))
        with self.assertRaises(IntegrationError):
            dc.pihole_set_blocking({"secret": "wrong"}, FakeClient(routes), False, 300)

    def test_a_refused_write_raises(self):
        routes, _ = _pihole_routes()
        routes[("POST", "/api/dns/blocking")] = Resp(403, "nope")
        with self.assertRaises(IntegrationError):
            dc.pihole_set_blocking({"secret": "pw"}, FakeClient(routes), False, 300)


class TestAdGuard(unittest.TestCase):
    def test_status_converts_milliseconds_to_seconds(self):
        """AdGuard counts down in ms; the rest of the module is seconds. Getting
        this backwards would report a 5-minute pause as 5 days."""
        routes, _ = _adguard_routes(enabled=False, ms=300000)
        st = dc.adguard_status({}, FakeClient(routes))
        self.assertEqual({"blocking": False, "remaining": 300}, st)

    def test_disable_sends_a_bounded_duration_in_ms(self):
        routes, state = _adguard_routes()
        c = FakeClient(routes)
        dc.adguard_set_blocking({"username": "u", "secret": "p"}, c, False, 900)
        post = [x for x in c.calls if x["method"] == "POST"][0]
        self.assertIs(False, post["body"]["enabled"])
        self.assertEqual(900 * 1000, post["body"]["duration"])
        self.assertFalse(state["protection_enabled"])

    def test_disable_clamps_at_the_driver(self):
        routes, _ = _adguard_routes()
        c = FakeClient(routes)
        dc.adguard_set_blocking({}, c, False, 10 ** 9)
        post = [x for x in c.calls if x["method"] == "POST"][0]
        self.assertEqual(dc.MAX_DISABLE_SECONDS * 1000, post["body"]["duration"])

    def test_enable_sends_no_duration(self):
        routes, _ = _adguard_routes(enabled=False, ms=60000)
        c = FakeClient(routes)
        dc.adguard_set_blocking({}, c, True, 300)
        post = [x for x in c.calls if x["method"] == "POST"][0]
        self.assertIs(True, post["body"]["enabled"])
        self.assertNotIn("duration", post["body"])

    def test_a_write_is_authenticated(self):
        routes, _ = _adguard_routes()
        c = FakeClient(routes)
        dc.adguard_set_blocking({"username": "u", "secret": "p"}, c, False, 300)
        post = [x for x in c.calls if x["method"] == "POST"][0]
        self.assertTrue(post["headers"].get("Authorization", "").startswith("Basic "))

    def test_a_refused_write_raises(self):
        routes, _ = _adguard_routes()
        routes[("POST", "/control/protection")] = Resp(401, "")
        with self.assertRaises(IntegrationError):
            dc.adguard_set_blocking({}, FakeClient(routes), False, 300)


class TestRegistry(unittest.TestCase):
    def test_only_dns_blockers_are_controllable(self):
        self.assertTrue(dc.has_control("pihole"))
        self.assertTrue(dc.has_control("adguard"))
        for other in ("plex", "truenas", "vcenter", "", None):
            self.assertFalse(dc.has_control(other))

    def test_every_registered_driver_implements_the_whole_contract(self):
        for type_, ops in dc.CONTROL.items():
            self.assertEqual({"status", "set_blocking"}, set(ops), type_)
            for fn in ops.values():
                self.assertTrue(callable(fn))

    def test_there_is_no_disable_forever_verb(self):
        """A permanent-disable action would defeat the entire point. If someone
        adds one, this fails and they have to argue with it."""
        src = (_CGI / "dns_control.py").read_text()
        self.assertNotIn("timer\": None if not enabled", src)
        # Every disable path routes through the clamp.
        self.assertEqual(2, src.count("clamp_seconds(seconds)"))


class TestHandlerGates(unittest.TestCase):
    """Drives the REAL api.py handlers. Only `verify_token` is stubbed (identity)
    — stubbing require_admin_auth would happily pass a handler with no gate at
    all, which is exactly the bug worth looking for."""

    @classmethod
    def setUpClass(cls):
        import importlib.util
        import os
        import tempfile
        os.environ["RP_DATA_DIR"] = tempfile.mkdtemp(prefix="rp-v613-dns-")
        spec = importlib.util.spec_from_file_location("api_v613_dns", _CGI / "api.py")
        cls.api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.api)

    def setUp(self):
        api = self.api
        self.audits = []
        self.captured = {}
        self.body = {}
        self.role = "admin"
        self.routes, self.state = _pihole_routes()

        def _respond(status, data=None):
            self.captured = {"status": status, "data": data}
            raise api.HTTPError(status, data)

        api.respond = _respond
        api.audit_log = lambda actor, action, **kw: self.audits.append((actor, action, kw))
        api.get_json_obj = lambda: self.body
        api.method = lambda: "POST"
        api._get_client_ip = lambda: "10.0.0.1"
        api.get_token_from_request = lambda: "tok"
        api.verify_token = lambda t: ("alice", self.role)
        api._get_integrations = lambda cfg=None: [
            {"id": "i1", "type": "pihole", "label": "Pi-hole", "secret": "pw"},
            {"id": "i2", "type": "plex", "label": "Plex"},
        ]
        api._integration_client = lambda inst: FakeClient(self.routes)

    def _set(self, iid="i1", **body):
        self.body = body
        self.captured = {}
        try:
            self.api.handle_dns_blocking_set(iid)
        except self.api.HTTPError:
            pass
        return self.captured

    def test_a_viewer_cannot_pause_blocking(self):
        self.role = "viewer"
        self.assertEqual(403, self._set(enabled=False, seconds=300)["status"])
        self.assertEqual("enabled", self.state["blocking"])   # and nothing happened

    def test_an_admin_can_pause_blocking(self):
        r = self._set(enabled=False, seconds=300)
        self.assertEqual(200, r["status"])
        self.assertIs(False, r["data"]["blocking"])
        self.assertEqual("disabled", self.state["blocking"])

    def test_pausing_is_audited_with_the_window(self):
        """'Who turned the ad-blocker off, when, and for how long' must be
        answerable after the fact."""
        self._set(enabled=False, seconds=900)
        act = [(a, kw) for _, a, kw in self.audits if a == "dns_blocking_set"]
        self.assertTrue(act)
        self.assertIn("900s", act[0][1].get("detail", ""))

    def test_a_non_blocker_integration_is_refused(self):
        """Plex is not a DNS blocker; the registry — not the client — decides."""
        self.assertEqual(400, self._set(iid="i2", enabled=False)["status"])

    def test_an_unknown_integration_404s(self):
        self.assertEqual(404, self._set(iid="nope", enabled=False)["status"])

    def test_an_absurd_window_is_clamped_by_the_handler(self):
        self._set(enabled=False, seconds=10 ** 9)
        self.assertEqual(dc.MAX_DISABLE_SECONDS, self.state["timer"])

    def test_a_garbage_window_does_not_500(self):
        self.assertEqual(200, self._set(enabled=False, seconds="abc")["status"])


if __name__ == "__main__":
    unittest.main()
