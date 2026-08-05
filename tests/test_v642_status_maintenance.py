"""v6.4.2: declared maintenance no longer reads as an unexplained outage.

The failure was worse than "no banner". `_status_page_component_state` derived
status purely from last_seen, so a host rebooting inside a window its operator
had correctly declared counted as DOWN — and because `device_offline` is
suppressed during maintenance, no incident was recorded either. The public page
showed a red component, an empty incident list, and no explanation at all.

Run: python3 -m pytest tests/test_v642_status_maintenance.py -q
"""
import os
import sys
import json
import time
import datetime
import tempfile
import unittest
import importlib.util
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v642_statmaint", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_REASON = "swapping the failing PSU in rack 3"


def _iso(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class TestStatusPageMaintenance(unittest.TestCase):
    def setUp(self):
        self.now = now = int(time.time())
        # One device, offline, and it is the only member of the component.
        api.save(api.DEVICES_FILE, {
            "spmaint-d1": {"name": "web01", "token": "t", "monitored": True,
                   "last_seen": now - 99999}})
        cfg = api.load(api.CONFIG_FILE) or {}
        self._cfg_before = json.loads(json.dumps(cfg))
        self._maint_before = api.load(api.MAINT_FILE) or {}
        # Pin the TTL rather than inheriting it. Another module sharing this
        # RP_DATA_DIR can leave a large `online_ttl` behind, and then a device
        # 99999s stale still reads as online — the class-4 shared-store
        # order-dependency, which shows up only under xdist and looks like flake.
        #
        # v6.4.2: the SECOND half of that, found the same way. The device id was
        # `d1`, which half the suite uses; a neighbour module sharing this data
        # dir writes `d1` with a CURRENT last_seen, and then the product's
        # last_seen-regression guard correctly REFUSES this setUp's deliberately
        # stale write ("last_seen regression prevented dev=d1 ... by=setUp"), so
        # the host reads online and every status assertion here fails at once.
        # The guard is right; the fixture was using a name it did not own.
        cfg["online_ttl"] = 300
        # ...and the FLOOR, which is the half this originally missed.
        # get_online_ttl() returns max(min_online_ttl, online_ttl), so pinning
        # only online_ttl leaves a neighbour's leaked min_online_ttl in charge —
        # a large one makes the 99999s-stale device read ONLINE and every status
        # assertion in this class fails at once, which is exactly the shape that
        # showed up under xdist and looked like flake.
        cfg["min_online_ttl"] = 150
        cfg["status_page"] = {
            "enabled": True, "title": "Status", "show_incidents": True,
            "show_maintenance": True, "incident_days": 30,
            "components": [{"id": "c1", "group": "Core", "name": "Web",
                            "device_ids": ["spmaint-d1"], "monitors": []}],
        }
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()

    def tearDown(self):
        # Put the shared config back. Pinning online_ttl fixed THIS module, but
        # leaving it behind would make this module the leak for the next one —
        # the same order-dependency, pointed the other way.
        api.save(api.CONFIG_FILE, self._cfg_before)
        api.save(api.MAINT_FILE, self._maint_before)
        api._LOAD_CACHE.clear()

    def _window(self, **kw):
        w = {"id": "w1", "scope": "device", "target": "spmaint-d1",
             "start": _iso(self.now - 3600), "end": _iso(self.now + 3600),
             "reason": _REASON}
        w.update(kw)
        return w

    def _proj(self, windows):
        api.save(api.MAINT_FILE, {"windows": windows})
        api._LOAD_CACHE.clear()
        return api._status_page_projection(
            api.load(api.CONFIG_FILE), api.load(api.DEVICES_FILE),
            self.now, api.get_online_ttl())

    def test_without_a_window_it_is_still_an_outage(self):
        """The baseline must not change — a genuinely down host is down."""
        r = self._proj([])
        self.assertEqual(r["components"][0]["status"], "major_outage")

    def test_a_declared_window_is_not_an_outage(self):
        """Fixed for EVERY operator, not only those who opt into publishing —
        otherwise the original bug survives for anyone who does not set a flag."""
        r = self._proj([self._window()])
        self.assertEqual(r["components"][0]["status"], "maintenance")

    def test_an_unpublished_window_announces_nothing(self):
        """Declaring a window for internal alert suppression is not consent to
        tell the internet what you are doing."""
        r = self._proj([self._window()])
        self.assertEqual(r.get("maintenance"), [])

    def test_a_published_window_announces_its_title(self):
        r = self._proj([self._window(public=True, public_title="Planned network upgrade")])
        self.assertEqual(len(r["maintenance"]), 1)
        self.assertEqual(r["maintenance"][0]["title"], "Planned network upgrade")

    def test_the_internal_reason_never_reaches_the_public_payload(self):
        """`reason` is free text an operator writes for colleagues."""
        for w in (self._window(), self._window(public=True, public_title="Upgrade"),
                  self._window(public=True)):
            r = self._proj([w])
            self.assertNotIn("PSU", json.dumps(r))
            self.assertNotIn(_REASON, json.dumps(r))

    def test_a_published_window_with_no_title_gets_a_generic_one(self):
        r = self._proj([self._window(public=True)])
        self.assertEqual(r["maintenance"][0]["title"], "Scheduled maintenance")

    def test_an_expired_window_does_nothing(self):
        r = self._proj([self._window(start=_iso(self.now - 7200),
                                     end=_iso(self.now - 3600),
                                     public=True, public_title="Old")])
        self.assertEqual(r["components"][0]["status"], "major_outage")
        self.assertEqual(r["maintenance"], [])

    def test_the_operator_can_switch_the_whole_thing_off(self):
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg["status_page"]["show_maintenance"] = False
        api.save(api.CONFIG_FILE, cfg)
        r = self._proj([self._window(public=True, public_title="Upgrade")])
        self.assertEqual(r["components"][0]["status"], "major_outage")
        self.assertEqual(r["maintenance"], [])


class TestWindowFieldSurvivesAnEdit(unittest.TestCase):
    """`handle_maintenance_update` does new_win.update(clean), so a key absent
    from _validate_maintenance_body's dict is SILENTLY CLEARED on every PUT —
    the documented whitelist class. Three places or the flag drops."""

    def test_validate_returns_the_public_fields(self):
        import inspect
        src = inspect.getsource(api._validate_maintenance_body)
        self.assertIn("'public'", src)
        self.assertIn("'public_title'", src)

    def test_the_create_path_stores_them(self):
        import inspect
        src = inspect.getsource(api.handle_maintenance_add)
        self.assertIn("'public'", src)
        self.assertIn("'public_title'", src)

    def test_the_request_model_accepts_them(self):
        import request_models
        m = getattr(request_models, "MaintenanceAddRequest", None)
        if m is None:
            self.skipTest("pydantic not installed")
        ok, _err = request_models.validate(
            m, {"scope": "global", "public": True, "public_title": "x"})
        self.assertTrue(ok)
        # Additive superset: an empty body must still validate.
        self.assertTrue(request_models.validate(m, {})[0])

    def test_the_config_toggle_round_trips(self):
        """The status_page save block REBUILDS the dict, so a key not listed
        there never persists."""
        import inspect
        save_src = inspect.getsource(api.handle_config_save)
        self.assertIn("'show_maintenance'", save_src)
        get_src = inspect.getsource(api.handle_config_get)
        self.assertIn("show_maintenance", get_src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
