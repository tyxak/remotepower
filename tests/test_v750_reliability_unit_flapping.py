#!/usr/bin/env python3
"""A crash-looping service counts in the "likely to fail" score.

The reliability score carried a note saying unit flapping could not be scored:
services.json keeps systemd's cumulative NRestarts, and the flap delta that the
`unit_flapping` alert fires on was said to be worked out in flight and never saved.
The delta is saved. process_service_report() keeps, per host, the set of units whose
count climbed by the operator's limit between two reports and have not settled
since, and that set is what unit_flapping fires from and unit_flapping_cleared
closes.

Driven through the real service report, so the set is the one the ingest writes. The
cumulative counter alone must still score nothing: that half of the old note was
right, and `TestTheCounterAloneStillScoresNothing` holds it.
"""
import importlib.util
import os
import pathlib
import sys
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-flap-"))


def _fresh_api():
    os.environ["RP_DATA_DIR"] = tempfile.mkdtemp(prefix="rp-v750-flap-api-")
    spec = importlib.util.spec_from_file_location("api_v750_flap", _CGI / "api.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _unit(name, restarts, active="active", sub="running"):
    return {"unit": name, "active": active, "sub": sub, "since": 0, "restarts": restarts}


class _Base(unittest.TestCase):
    def setUp(self):
        self.api = api = _fresh_api()
        now = int(time.time())
        api.save(api.DEVICES_FILE, {"d1": {"name": "web01", "last_seen": now,
                                           "monitored": True, "sysinfo": {}}})
        self.set_config(unit_flap_restarts=3)
        self.fired = []
        self._real_fire = api.fire_webhook
        api.fire_webhook = lambda ev, p=None, **k: self.fired.append(ev)

    def tearDown(self):
        self.api.fire_webhook = self._real_fire

    def set_config(self, **cfg):
        api = self.api
        api.save(api.CONFIG_FILE, cfg)
        api._invalidate_load_cache(api.CONFIG_FILE)

    def report(self, *units):
        self.api.process_service_report("d1", list(units))
        self.api._invalidate_load_cache(self.api.SERVICES_FILE)

    def rel(self):
        rows = {r["device_id"]: r for r in self.api._compute_fleet_reliability()}
        return rows["d1"]

    def factor(self):
        hit = [f for f in self.rel()["factors"] if f["kind"] == "unit_flapping"]
        return hit[0] if hit else None


class TestAFlappingUnitScores(_Base):

    def test_the_premise_the_ingest_saves_the_set(self):
        self.report(_unit("app.service", 0))
        self.report(_unit("app.service", 5))
        stored = self.api.load(self.api.SERVICES_FILE)["d1"]
        self.assertEqual(stored["flapping"], ["app.service"])
        self.assertIn("unit_flapping", self.fired)

    def test_it_scores_per_unit_with_the_names(self):
        self.report(_unit("app.service", 0), _unit("db.service", 0))
        self.report(_unit("app.service", 5), _unit("db.service", 1))
        f = self.factor()
        self.assertEqual(f["points"], self.api._RELIABILITY_WEIGHTS["unit_flapping"])
        self.assertIn("1 unit restarting repeatedly", f["detail"])
        self.assertIn("app.service", f["detail"])
        self.assertNotIn("db.service", f["detail"])      # below the limit

    def test_two_units_score_twice(self):
        self.report(_unit("a.service", 0), _unit("b.service", 0))
        self.report(_unit("a.service", 4), _unit("b.service", 9))
        self.assertEqual(self.factor()["points"],
                         2 * self.api._RELIABILITY_WEIGHTS["unit_flapping"])

    def test_the_cap_stops_a_long_list(self):
        names = [f"u{i}.service" for i in range(6)]
        self.report(*[_unit(n, 0) for n in names])
        self.report(*[_unit(n, 7) for n in names])
        f = self.factor()
        self.assertEqual(f["points"], 3 * self.api._RELIABILITY_WEIGHTS["unit_flapping"])
        self.assertEqual(f["points"], self.api._RELIABILITY_CAPS["unit_flapping"])
        self.assertIn("6 units", f["detail"])

    def test_it_stops_scoring_when_the_unit_settles(self):
        self.report(_unit("app.service", 0))
        self.report(_unit("app.service", 5))
        self.assertIsNotNone(self.factor())
        self.report(_unit("app.service", 5))              # stable and running
        self.assertIn("unit_flapping_cleared", self.fired)
        self.assertIsNone(self.factor())

    def test_a_unit_that_gave_up_keeps_scoring(self):
        """The counter freezes when systemd stops restarting a unit that burned
        through its start limit, and the unit is `failed`. That is worse, not
        better, and the set keeps it (the 7.0.2 fix the alert already has)."""
        self.report(_unit("app.service", 0))
        self.report(_unit("app.service", 5))
        self.report(_unit("app.service", 5, active="failed", sub="failed"))
        self.assertIsNotNone(self.factor())

    def test_the_weight_is_tunable_and_zero_turns_it_off(self):
        self.report(_unit("app.service", 0))
        self.report(_unit("app.service", 5))
        self.set_config(unit_flap_restarts=3, reliability_weight_unit_flapping=0)
        self.assertIsNone(self.factor())
        self.set_config(unit_flap_restarts=3, reliability_weight_unit_flapping=20)
        self.assertEqual(self.factor()["points"], 20)


class TestTheCounterAloneStillScoresNothing(_Base):
    """The half of the old note that was right."""

    def test_a_high_cumulative_count_that_never_climbed_scores_nothing(self):
        self.report(_unit("old.service", 7))
        self.report(_unit("old.service", 7))
        self.assertIsNone(self.factor())

    def test_a_deploy_restart_below_the_limit_scores_nothing(self):
        self.report(_unit("app.service", 6))
        self.report(_unit("app.service", 7))
        self.assertIsNone(self.factor())

    def test_with_flap_detection_off_nothing_scores(self):
        self.set_config(unit_flap_restarts=0)
        self.report(_unit("app.service", 0))
        self.report(_unit("app.service", 500))
        self.assertIsNone(self.factor())

    def test_a_counter_that_reset_scores_nothing(self):
        self.report(_unit("app.service", 40))
        self.report(_unit("app.service", 2))              # the unit was stopped and started
        self.assertIsNone(self.factor())


class TestJunkInTheRecord(unittest.TestCase):
    """A hand-edited or damaged store must not break the whole score."""

    @classmethod
    def setUpClass(cls):
        cls.api = _fresh_api()

    def _factors(self, svc_rec):
        api = self.api
        dev = {"name": "h", "last_seen": int(time.time()), "monitored": True, "sysinfo": {}}
        res = api._device_reliability("d1", dev, {}, {}, {}, {}, svc_rec, {}, int(time.time()))
        return [f["kind"] for f in res["factors"]]

    def test_odd_shapes_score_nothing(self):
        for junk in (None, "x", 7, [], {"flapping": "app"}, {"flapping": [None, ""]},
                     {"flapping": {"a": 1}}, {"flapping": 3}):
            self.assertNotIn("unit_flapping", self._factors(junk), junk)

    def test_a_list_of_names_scores(self):
        self.assertIn("unit_flapping", self._factors({"flapping": ["a.service"]}))


class TestRegistriesAndDocs(unittest.TestCase):

    def test_the_weight_is_in_every_registry(self):
        api = _fresh_api()
        js = (ROOT / "server/html/static/js/app.js").read_text()
        html = (ROOT / "server/html/index.html").read_text()
        self.assertIn("unit_flapping", api._RELIABILITY_WEIGHTS)
        self.assertIn("unit_flapping: %d" % api._RELIABILITY_WEIGHTS["unit_flapping"], js)
        self.assertIn('id="ap-lw-unit_flapping"', html)

    def test_the_docs_no_longer_say_it_is_not_scored(self):
        doc = (ROOT / "docs/disk-health.md").read_text()
        self.assertIn("Units restarting repeatedly", doc)
        self.assertNotIn("never saved", doc)

    def test_the_stale_comment_is_gone(self):
        src = (_CGI / "api.py").read_text()
        self.assertNotIn("NOT SCORED, on purpose: unit flapping", src)
        self.assertNotIn("(`svc_rec` stays in the signature", src)


if __name__ == "__main__":
    unittest.main()
