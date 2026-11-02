#!/usr/bin/env python3
"""A junk number in the SLO store must not fail the whole /metrics scrape.

The 7.4.8 security pass found that float() of an integer of 400 digits raises OverflowError, and fixed the exporter's `_num`
helper, which 14 of its readers use. It listed eight more places that were not fixed: the SLO block converted its stored
numbers with a bare `float(x or 0)`, so a hand-edited or imported SLO store with a word, a list or an integer too big for a
float in one field made the whole scrape raise, and the exporter's own docstring says a junk field has to vanish.

Each of the eight conversions is driven here with each kind of junk, next to a good record, through generate_metrics. The
junk sample is left out, the good one is still there, and the scrape does not raise. The controls: a good store comes out as it
did, and a missing value is still a 0 (the old `or 0`).
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "server" / "cgi-bin"))

import prometheus_export as pe  # noqa: E402

JUNK = [10 ** 400, -(10 ** 400), "fast", [1], {"a": 1}, float("nan"), float("inf"), -float("inf"), True]
BASE = {"now": 1_800_000_000, "devices": {}, "online_ttl": 300, "server_version": "x"}


def slo(**changes):
    """A good SLO store, with `changes` applied to the 'bad' record (and the same field left good on the 'ok' one)."""
    mon = {"availability": 99.5, "budget_remaining_pct": 40.0, "burn_rate": 0.5}
    obj = {"target": 99.0, "availability": 98.0, "budget_remaining_pct": 10.0}
    store = {"target": 99.9,
             "monitors": [dict(mon, label="ok"), dict(mon, label="bad")],
             "objects": [dict(obj, name="ok"), dict(obj, name="bad")]}
    for key, value in changes.items():
        kind, field = key.split("__")
        if kind == "top":
            store[field] = value
        else:
            store[kind][1][field] = value
    return store


def scrape(store, windows=None):
    ctx = dict(BASE, slo=store)
    if windows is not None:
        ctx["control_uptime"] = {"tracking": True, "windows": windows}
    return pe.generate_metrics(ctx)


def samples(text, metric):
    return [ln for ln in text.splitlines() if ln.startswith(metric + "{") or ln.startswith(metric + " ")]


# (change key, metric it feeds, label that the bad record carries)
FIELDS = [
    ("top__target", "remotepower_slo_target_percent", None),
    ("monitors__availability", "remotepower_monitor_availability_percent", 'label="bad"'),
    ("monitors__budget_remaining_pct", "remotepower_monitor_slo_budget_remaining_percent", 'label="bad"'),
    ("monitors__burn_rate", "remotepower_monitor_slo_burn_rate", 'label="bad"'),
    ("objects__target", "remotepower_slo_object_target_percent", 'name="bad"'),
    ("objects__availability", "remotepower_slo_object_availability_percent", 'name="bad"'),
    ("objects__budget_remaining_pct", "remotepower_slo_object_budget_remaining_percent", 'name="bad"'),
]


class TestAJunkNumberVanishes(unittest.TestCase):

    def test_each_of_the_seven_fields_with_each_kind_of_junk(self):
        n = 0
        for key, metric, bad_label in FIELDS:
            for junk in JUNK:
                with self.subTest(field=key, junk=repr(junk)[:24]):
                    text = scrape(slo(**{key: junk}))        # does not raise
                    got = samples(text, metric)
                    n += 1
                    if bad_label:
                        self.assertFalse([g for g in got if bad_label in g], got)
                        self.assertTrue([g for g in got if 'ok"' in g], "the good record is still exported: " + str(got))
                    else:
                        self.assertEqual(got, [], got)
        self.assertEqual(n, len(FIELDS) * len(JUNK), "the population is the whole product")

    def test_the_control_plane_window(self):
        for junk in JUNK:
            with self.subTest(junk=repr(junk)[:24]):
                text = scrape(slo(), windows={"24h": {"percent": 99.0}, "7d": {"percent": junk}})
                got = samples(text, "remotepower_control_plane_uptime_percent")
                self.assertEqual([g for g in got if "7d" in g], [], got)
                self.assertTrue([g for g in got if "24h" in g], got)

    def test_the_scrape_as_a_whole_is_still_valid_text(self):
        text = scrape(slo(**{"monitors__availability": 10 ** 400, "top__target": [99]}))
        self.assertTrue(text.endswith("\n"))
        for ln in text.splitlines():
            if ln and not ln.startswith("#"):
                self.assertNotIn("nan", ln.lower().split(" ")[-1], ln)
                float(ln.rsplit(" ", 1)[-1])      # every sample's value parses


class TestWhatDidNotChange(unittest.TestCase):

    def test_a_good_store_comes_out_as_it_did(self):
        text = scrape(slo(), windows={"24h": {"percent": 99.0}})
        self.assertIn("remotepower_slo_target_percent 99.9", text)
        self.assertEqual(len(samples(text, "remotepower_monitor_availability_percent")), 2)
        self.assertIn('remotepower_monitor_availability_percent{label="ok"} 99.5', text)
        self.assertIn('remotepower_monitor_slo_burn_rate{label="ok"} 0.5', text)
        self.assertIn('remotepower_slo_object_target_percent{name="ok"} 99.0', text)
        self.assertIn('remotepower_control_plane_uptime_percent{window="24h"} 99.0', text)

    def test_a_missing_value_is_still_a_zero(self):
        for missing in (None, 0, 0.0, "", False, [], {}):      # all falsy: the old `or 0` made each a 0
            text = scrape(slo(**{"monitors__burn_rate": missing, "top__target": missing}))
            self.assertIn('remotepower_slo_target_percent 0.0', text, missing)
            self.assertIn('remotepower_monitor_slo_burn_rate{label="bad"} 0.0', text, missing)

    def test_a_numeric_string_is_accepted_as_in_every_other_family(self):
        text = scrape(slo(**{"monitors__availability": "97.25"}))
        self.assertIn('remotepower_monitor_availability_percent{label="bad"} 97.25', text)

    def test_no_bare_float_conversion_of_a_stored_value_is_left_in_the_exporter(self):
        src = (Path(__file__).resolve().parent.parent / "server" / "cgi-bin" / "prometheus_export.py").read_text()
        import ast
        tree = ast.parse(src)
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "float"]
        owners = []
        for fn in ast.walk(tree):
            if isinstance(fn, ast.FunctionDef):
                owners += [fn.name for c in ast.walk(fn) if c in calls]
        self.assertEqual(sorted(set(owners)), ["_num"], "only the helper converts; everything else goes through it")


if __name__ == "__main__":
    unittest.main()
