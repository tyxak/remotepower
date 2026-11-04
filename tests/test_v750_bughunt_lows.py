#!/usr/bin/env python3
"""Low findings of the 7.5.0 bug hunt, each held against the real code path.

BH-4. Adding a read-only mount to a container that already had `/` read-only LOWERED
the finding from medium to low (the check required every sensitive mount to be `/`).

BH-6. A refused enrolment source was never in the audit trail. The entry was queued
inside the token store's lock and `respond(403)` raised out of it, which discards what
was queued. The existing test replaces audit_log with a recorder, which cannot see the
difference, so this one reads the real trail.

BH-8. The host's hottest-reading history took the raw SMART and GPU values: a USB
bridge answering 255 or a GPU answering 65535 was charted as the hottest sensor.

BH-9. The text "nan" passes `f < lo or f > hi` (NaN compares false with everything), is
stored by the float tunables, and the save then answers 500. 14 keys.
"""
import json
import math
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-bhl-"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_v749_container_audit import facts, item, rules  # noqa: E402
from test_v749_enroll_source import _Enrol, api  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server" / "cgi-bin"))


def severity(*mounts):
    """The sensitive_mount finding's severity for a container with these (source, writable) mounts, or None."""
    return rules(item(facts(mounts=[{"src": src, "dst": "/h", "rw": rw} for src, rw in mounts]))).get("sensitive_mount")


class TestAddingAMountNeverLowersTheFinding(unittest.TestCase):

    def test_the_root_alone_read_only_is_medium(self):
        self.assertEqual(severity(("/", False)), "medium")

    def test_the_root_and_another_directory_read_only_stays_medium(self):
        self.assertEqual(severity(("/", False), ("/etc", False)), "medium")
        self.assertEqual(severity(("/etc", False), ("/", False)), "medium", "the order does not matter")
        self.assertEqual(severity(("/", False), ("/etc", False), ("/proc", False)), "medium")

    def test_another_directory_alone_read_only_is_low(self):
        self.assertEqual(severity(("/etc", False)), "low")

    def test_a_writable_mount_still_raises_it(self):
        self.assertEqual(severity(("/", True)), "critical")
        self.assertEqual(severity(("/", False), ("/etc", True)), "high")

    def test_no_added_mount_ever_lowers_the_severity(self):
        order = {None: 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        mounts = [("/", False), ("/", True), ("/etc", False), ("/etc", True), ("/proc", False),
                  ("/var/lib/docker", True), ("/data", True)]
        for a in mounts:
            for b in mounts:
                self.assertGreaterEqual(order[severity(a, b)], order[severity(a)], (a, b))
                self.assertGreaterEqual(order[severity(a, b)], order[severity(b)], (b, a))


class TestARefusedEnrolmentSourceIsAudited(_Enrol):
    """The real audit trail: audit_log is not replaced here. Other test modules replace api.audit_log with a recorder and some
    never put it back, so the real function is rebuilt from the source instead of taken from the module as it stands."""

    def setUp(self):
        super().setUp()
        import srcpin
        body = srcpin.py_function((ROOT / "server/cgi-bin/api.py").read_text(), "audit_log")
        exec(compile(body, "audit_log", "exec"), api.__dict__)
        api._LOAD_CACHE.clear()

    def trail(self):
        api._LOAD_CACHE.clear()
        rows = api.load(api.AUDIT_LOG_FILE)
        rows = rows if isinstance(rows, list) else (rows.get("entries") or rows.get("log") or [])
        return [r.get("action") for r in rows if isinstance(r, dict)]

    def test_the_refusal_is_in_the_trail_with_the_prefix_and_the_address(self):
        _, d = self.mint(allowed_cidrs=["10.0.0.0/8"])
        st, _r = self.register(d["token"], "198.51.100.9")
        self.assertEqual(st, 403)
        self.assertIn("enrollment_token_refused_source", self.trail())
        rows = api.load(api.AUDIT_LOG_FILE)
        rows = rows if isinstance(rows, list) else (rows.get("entries") or rows.get("log") or [])
        row = [r for r in rows if r.get("action") == "enrollment_token_refused_source"][0]
        blob = json.dumps(row)
        self.assertIn("198.51.100.9", blob)
        self.assertNotIn(d["token"], blob, "the token itself is never written")

    def test_the_token_is_kept_for_the_right_place(self):
        _, d = self.mint(allowed_cidrs=["10.0.0.0/8"])
        self.register(d["token"], "198.51.100.9")
        self.assertEqual(len(self.stored()), 1)
        st, _r = self.register(d["token"], "10.1.2.3")
        self.assertIn(st, (200, 201))
        self.assertEqual(self.stored(), [])

    def test_a_token_with_no_limit_audits_no_refusal(self):
        _, d = self.mint()
        self.register(d["token"], "198.51.100.9")
        self.assertNotIn("enrollment_token_refused_source", self.trail())


class TestTheHottestReadingIgnoresNoise(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        os.environ["RP_DATA_DIR"] = tempfile.mkdtemp(prefix="rp-v750-bhl-hot-")
        import importlib.util
        spec = importlib.util.spec_from_file_location("api_v750_hot", ROOT / "server/cgi-bin/api.py")
        cls.api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.api)

    def _hottest(self, **body):
        a = self.api
        a.save(a.DEVICES_FILE, {"d1": {"name": "nas01", "last_seen": int(time.time()), "monitored": True,
                                       "sysinfo": {}}})
        a.save(a.THERMAL_HIST_FILE, {})
        a._invalidate_load_cache(a.THERMAL_HIST_FILE)
        a._ingest_hardware("d1", "nas01", body, int(time.time()))
        a._invalidate_load_cache(a.THERMAL_HIST_FILE)
        return [s["temp"] for s in ((a.load(a.THERMAL_HIST_FILE) or {}).get("d1") or {}).get("samples") or []]

    def test_a_usb_bridge_and_a_gpu_that_answer_noise_are_not_the_hottest(self):
        got = self._hottest(hardware={"temps": [{"label": "cpu", "current_c": 41}]},
                            smart=[{"device": "/dev/sdb", "serial": "USB1", "model": "bridge",
                                    "health": "PASSED", "temperature_c": 255}],
                            gpus=[{"vendor": "x", "name": "g", "temp_c": 65535}])
        self.assertEqual(got, [41.0])

    def test_a_real_hot_disk_still_counts(self):
        got = self._hottest(hardware={"temps": [{"label": "cpu", "current_c": 41}]},
                            smart=[{"device": "/dev/sda", "serial": "S1", "model": "m",
                                    "health": "PASSED", "temperature_c": 63}])
        self.assertEqual(got, [63.0])

    def test_a_real_hot_gpu_still_counts(self):
        got = self._hottest(hardware={"temps": [{"label": "cpu", "current_c": 41}]},
                            gpus=[{"vendor": "n", "name": "g", "temp_c": 78}])
        self.assertEqual(got, [78.0])


class TestTextNanIsRefusedByEveryFloatTunable(unittest.TestCase):

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {a: getattr(api, a) for a in ("CONFIG_FILE", "USERS_FILE", "ROLES_FILE")}
        for a in self._files:
            setattr(api, a, self.d / Path(self._files[a]).name)
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in ("require_admin_auth", "verify_token", "audit_log",
                                                    "fire_webhook", "respond", "method", "get_json_obj")}
        api.require_admin_auth = lambda: "t"
        api.verify_token = lambda t: ("t", "admin")
        api.audit_log = lambda *a, **k: None
        api.fire_webhook = lambda *a, **k: None

        def _resp(s, b=None):
            self.cap["s"], self.cap["b"] = s, b
            raise api.HTTPError(s, b)
        api.respond = _resp
        api.method = lambda: "POST"
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for a, v in self._files.items():
            setattr(api, a, v)
        api._LOAD_CACHE.clear()

    def _save(self, **body):
        api.get_json_obj = lambda: dict(body)
        self.cap.clear()
        try:
            api.handle_config_save()
        except api.HTTPError:
            pass
        return self.cap.get("s"), self.cap.get("b")

    def test_forecast_min_r2_nan_is_a_400_not_a_500(self):
        st, b = self._save(forecast_min_r2="nan")
        self.assertEqual(st, 400, b)
        self.assertIn("forecast_min_r2", json.dumps(b))

    def test_every_float_key_in_the_loop_refuses_nan_and_inf_and_stores_nothing(self):
        import re
        src = (ROOT / "server/cgi-bin/api.py").read_text()
        start = src.index("for _tk, _lo, _hi in (")
        head = src[start:src.index("        if _tk in body:", start)]
        keys = re.findall(r"\('([a-z0-9_]+)',\s*[-\d.]+,\s*[-\d.]+\)", head)
        self.assertGreaterEqual(len(keys), 8, "the loop's keys were not found: " + head[:200])
        for k in keys:
            for bad in ("nan", "NaN", "inf", "-inf"):
                st, b = self._save(**{k: bad})
                self.assertEqual(st, 400, (k, bad, st, b))
        api._LOAD_CACHE.clear()
        cfg = api.load(api.CONFIG_FILE) or {}
        for k in keys:
            self.assertFalse(isinstance(cfg.get(k), float) and math.isnan(cfg[k]), k)

    def test_a_real_number_inside_the_range_is_still_stored(self):
        st, b = self._save(forecast_min_r2="0.5")
        self.assertEqual(st, 200, b)
        api._LOAD_CACHE.clear()
        self.assertEqual((api.load(api.CONFIG_FILE) or {}).get("forecast_min_r2"), 0.5)

    def test_a_number_outside_the_range_is_still_refused(self):
        st, _b = self._save(forecast_min_r2="7")
        self.assertEqual(st, 400)


class TestAiParametersRefuseNan(unittest.TestCase):

    def setUp(self):
        self._orig = {n: getattr(api, n) for n in ("require_admin_auth", "verify_token", "audit_log",
                                                    "respond", "method", "get_json_obj")}
        self.cap = {}
        api.require_admin_auth = lambda: "t"
        api.verify_token = lambda t: ("t", "admin")
        api.audit_log = lambda *a, **k: None

        def _resp(s, b=None):
            self.cap["s"], self.cap["b"] = s, b
            raise api.HTTPError(s, b)
        api.respond = _resp
        api.method = lambda: "POST"

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)

    def _save(self, **body):
        api.get_json_obj = lambda: dict(body)
        self.cap.clear()
        try:
            api.handle_ai_params_save()
        except api.HTTPError:
            pass
        return self.cap.get("s"), self.cap.get("b")

    def test_temperature_and_top_p_refuse_nan(self):
        for k in ("temperature", "top_p"):
            for bad in ("nan", "NaN"):
                st, b = self._save(key="access_review", **{k: bad})
                self.assertEqual(st, 400, (k, bad, b))

    def test_a_real_value_is_accepted(self):
        st, b = self._save(key="access_review", temperature="0.5")
        self.assertEqual(st, 200, b)


if __name__ == "__main__":
    unittest.main()
