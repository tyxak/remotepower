"""v6.4.2 — dead board sensors must not become the host's temperature.

A hardware monitoring chip exposes every thermal pin on its die whether or not
the board wired anything to it. An unconnected pin reads whatever rail its ADC
floats to. On this project's own dev box nct6798-isa-0290/AUXTIN2 sits at
115-127 °C while every CPU core reads 30-39 °C — and that one dead pin was
becoming the "hottest sensor", driving the Thermal page headline, temp_high,
the overheating risk factor and the roll-up's max (a 127 °C spike on a chart).

Two defences of deliberately different strength, both pinned here:
  * sentinel rails (127.0 / -128.0 / out-of-range) are DROPPED at ingest;
  * anything else is only FLAGGED — auto-dropping a reading that might be a
    real fire is not a trade this product makes. The operator ignores it.

These drive the real ingest / fleet-thermal / risk paths rather than asserting
on hand-built records: the whole bug class here is a consumer reading a field
nobody actually writes.
"""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v642-sens-"))
_spec = importlib.util.spec_from_file_location("api_v642_sens", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


# The real shape `sensors -A -j` produces on the dev box, trimmed. AUXTIN2 is
# the dead pin; Package id 0 is the reading that actually matters.
JAOVE_TEMPS = [
    {"label": "nct6798-isa-0290/SYSTIN", "current_c": 31.0, "crit_c": 125.0},
    {"label": "nct6798-isa-0290/CPUTIN", "current_c": 34.5, "crit_c": 100.0},
    {"label": "nct6798-isa-0290/AUXTIN2", "current_c": 115.0, "crit_c": 100.0},
    {"label": "coretemp-isa-0000/Package id 0", "current_c": 39.0, "crit_c": 100.0},
]


class TestSentinelRails(unittest.TestCase):
    """127.0 / -128.0 / out-of-range are ADC rails, not measurements."""

    def test_rails_are_not_measurements(self):
        for bad in (127.0, -128.0, 200.0, -60.0, float("nan")):
            self.assertFalse(api._temp_is_measurement(bad), f"{bad} accepted")

    def test_real_readings_survive(self):
        for good in (0.0, 7.0, 31.0, 39.0, 115.0, 126.9, 149.0):
            self.assertTrue(api._temp_is_measurement(good), f"{good} rejected")

    def test_non_numeric_rejected(self):
        for bad in (None, "45", True, [], {}):
            self.assertFalse(api._temp_is_measurement(bad), f"{bad!r} accepted")

    def test_126_9_survives_but_127_does_not(self):
        """The rail is an exact value, not a ceiling — don't widen it into one.

        A GPU or a genuinely cooking VRM can legitimately pass 120 °C; only the
        signed-byte rail itself is definitionally fake.
        """
        self.assertTrue(api._temp_is_measurement(126.9))
        self.assertFalse(api._temp_is_measurement(127.0))
        self.assertTrue(api._temp_is_measurement(127.1))


class TestSuspectFlag(unittest.TestCase):
    """Reading past the sensor's OWN crit is advisory, never an auto-drop."""

    def test_reading_past_own_crit_is_suspect(self):
        self.assertTrue(api._temp_suspect(
            {"label": "AUXTIN2", "current_c": 115.0, "crit_c": 100.0}))

    def test_normal_reading_is_not_suspect(self):
        self.assertFalse(api._temp_suspect(
            {"label": "Package id 0", "current_c": 39.0, "crit_c": 100.0}))

    def test_no_crit_means_no_verdict(self):
        self.assertFalse(api._temp_suspect({"label": "x", "current_c": 115.0}))

    def test_suspect_does_not_filter(self):
        """The suspect flag must NOT remove the sensor from the live set.

        If this ever starts filtering, a genuinely overheating host goes quiet.
        """
        dev = {"id": "d-sens-1"}
        rec = {"hardware": {"temps": list(JAOVE_TEMPS)}}
        live = api._hw_temps_live(dev, rec)
        self.assertEqual(len(live), len(JAOVE_TEMPS))
        self.assertIn("nct6798-isa-0290/AUXTIN2",
                      [t["label"] for t in live])


class TestOperatorIgnore(unittest.TestCase):
    """An ignored sensor drops out of every number the operator acts on."""

    def setUp(self):
        self.dev = {"id": "d-sens-2",
                    "sensor_ignores": ["nct6798-isa-0290/AUXTIN2"]}
        self.rec = {"hardware": {"temps": list(JAOVE_TEMPS)}}

    def test_ignored_sensor_excluded_from_live_set(self):
        labels = [t["label"] for t in api._hw_temps_live(self.dev, self.rec)]
        self.assertNotIn("nct6798-isa-0290/AUXTIN2", labels)
        self.assertIn("coretemp-isa-0000/Package id 0", labels)

    def test_hottest_becomes_the_real_sensor(self):
        live = api._hw_temps_live(self.dev, self.rec)
        self.assertEqual(max(t["current_c"] for t in live), 39.0)

    def test_no_ignores_is_the_untouched_list(self):
        """The no-ignores path must return _hw_temps itself, not a rebuild."""
        plain = {"id": "d-sens-3"}
        self.assertEqual(api._hw_temps_live(plain, self.rec),
                         api._hw_temps(self.rec))

    def test_malformed_ignore_list_is_ignored_not_fatal(self):
        for bad in ("AUXTIN2", 5, None, {"a": 1}, [1, 2, None]):
            dev = {"id": "d", "sensor_ignores": bad}
            self.assertIsInstance(api._sensor_ignores(dev), set)
            self.assertEqual(len(api._hw_temps_live(dev, self.rec)),
                             len(JAOVE_TEMPS))


class TestIngestDropsRails(unittest.TestCase):
    """Drive the real heartbeat hardware ingest, not a hand-built record."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="rp-v642-ing-"))
        self._hw = api.HARDWARE_FILE
        api.HARDWARE_FILE = self.d / "hardware.json"
        api.save(api.HARDWARE_FILE, {})

    def tearDown(self):
        api.HARDWARE_FILE = self._hw

    def test_127_never_reaches_the_store(self):
        body = {"hardware": {"temps": [
            {"label": "nct6798-isa-0290/AUXTIN3", "current_c": 127.0, "crit_c": 100.0},
            {"label": "coretemp-isa-0000/Package id 0", "current_c": 39.0},
        ]}}
        api._ingest_hardware("d-ing-1", "jaove", body, 1_700_000_000,
                             dev={"id": "d-ing-1"})
        rec = (api.load(api.HARDWARE_FILE) or {}).get("d-ing-1") or {}
        labels = [t["label"] for t in api._hw_temps(rec)]
        self.assertNotIn("nct6798-isa-0290/AUXTIN3", labels,
                         "the 127 °C ADC rail was persisted")
        self.assertIn("coretemp-isa-0000/Package id 0", labels)

    def test_ignored_sensor_does_not_fire_temp_high(self):
        """The whole point: a dead pin must stop alerting once ignored."""
        body = {"hardware": {"temps": [
            {"label": "nct6798-isa-0290/AUXTIN2", "current_c": 115.0, "crit_c": 100.0},
            {"label": "coretemp-isa-0000/Package id 0", "current_c": 39.0},
        ]}}
        api._ingest_hardware(
            "d-ing-2", "jaove", body, 1_700_000_000,
            dev={"id": "d-ing-2", "sensor_ignores": ["nct6798-isa-0290/AUXTIN2"]})
        rec = (api.load(api.HARDWARE_FILE) or {}).get("d-ing-2") or {}
        self.assertFalse(rec.get("_temp_high"),
                         "an ignored sensor still drove the temp_high edge")

    def test_unignored_hot_sensor_still_fires(self):
        """The negative control — ignoring must not disarm real alerting."""
        body = {"hardware": {"temps": [
            {"label": "coretemp-isa-0000/Package id 0", "current_c": 96.0},
        ]}}
        api._ingest_hardware("d-ing-3", "jaove", body, 1_700_000_000,
                             dev={"id": "d-ing-3", "sensor_ignores": ["something-else"]})
        rec = (api.load(api.HARDWARE_FILE) or {}).get("d-ing-3") or {}
        self.assertTrue(rec.get("_temp_high"),
                        "a genuinely hot sensor stopped alerting")


class TestBackwardCompatibleSignature(unittest.TestCase):
    """`dev` is optional — older callers/tests must keep working."""

    def test_ingest_without_dev(self):
        d = Path(tempfile.mkdtemp(prefix="rp-v642-bc-"))
        prev = api.HARDWARE_FILE
        api.HARDWARE_FILE = d / "hardware.json"
        api.save(api.HARDWARE_FILE, {})
        try:
            api._ingest_hardware("d-bc", "h", {"hardware": {"temps": list(JAOVE_TEMPS)}},
                                 1_700_000_000)
            rec = (api.load(api.HARDWARE_FILE) or {}).get("d-bc") or {}
            self.assertEqual(len(api._hw_temps(rec)), len(JAOVE_TEMPS))
        finally:
            api.HARDWARE_FILE = prev


if __name__ == "__main__":
    unittest.main()
