#!/usr/bin/env python3
"""Unit tests for the DMARC posture monitor (v4.8.0). Pure parse/grade logic —
no DNS: each parser takes a list of synthetic TXT-record strings."""
import importlib.util
import sys
import unittest
from pathlib import Path

_CGI = Path(__file__).parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("dmarc_monitor_t", _CGI / "dmarc_monitor.py")
dm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dm)


class TestParse(unittest.TestCase):
    def test_dmarc(self):
        d = dm.parse_dmarc(["v=DMARC1; p=reject; pct=100; rua=mailto:d@x.com; adkim=s"])
        self.assertEqual(d["policy"], "reject")
        self.assertEqual(d["pct"], 100)
        self.assertEqual(d["rua"], "mailto:d@x.com")
        self.assertEqual(d["adkim"], "s")

    def test_dmarc_missing(self):
        self.assertEqual(dm.parse_dmarc(["v=spf1 -all", "some other txt"]), {})

    def test_dmarc_default_pct(self):
        self.assertEqual(dm.parse_dmarc(["v=DMARC1; p=none"])["pct"], 100)

    def test_spf(self):
        self.assertEqual(dm.parse_spf(["v=spf1 include:_spf.x.com -all"])["all"], "-")
        self.assertEqual(dm.parse_spf(["v=spf1 ~all"])["all"], "~")
        self.assertEqual(dm.parse_spf(["v=spf1 ?all"])["all"], "?")
        self.assertEqual(dm.parse_spf(["v=spf1 mx"])["all"], "")     # no all qualifier
        self.assertEqual(dm.parse_spf(["not spf"]), {})

    def test_dkim(self):
        self.assertTrue(dm.parse_dkim(["v=DKIM1; k=rsa; p=MIGf..."])["present"])
        self.assertFalse(dm.parse_dkim(["v=DKIM1; p="])["present"])   # revoked key
        self.assertEqual(dm.parse_dkim(["nope"]), {})


class TestGrade(unittest.TestCase):
    def test_ok(self):
        st, reasons = dm.grade({"policy": "reject", "pct": 100, "rua": "mailto:x"},
                               {"all": "-"}, {}, False)
        self.assertEqual(st, "ok")
        self.assertEqual(reasons, [])

    def test_fail_no_dmarc(self):
        st, reasons = dm.grade({}, {"all": "-"}, {}, False)
        self.assertEqual(st, "fail")
        self.assertIn("no DMARC record", reasons)

    def test_fail_policy_none(self):
        st, reasons = dm.grade({"policy": "none", "pct": 100, "rua": "mailto:x"},
                               {"all": "-"}, {}, False)
        self.assertEqual(st, "fail")   # p=none → spoofable

    def test_weak_enforcing_with_gaps(self):
        # enforcing (reject) but no rua + soft SPF → weak, not fail
        st, reasons = dm.grade({"policy": "reject", "pct": 100, "rua": ""},
                               {"all": "~"}, {}, False)
        self.assertEqual(st, "weak")
        self.assertIn("no aggregate-report (rua) address", reasons)

    def test_weak_low_pct(self):
        st, _ = dm.grade({"policy": "reject", "pct": 50, "rua": "mailto:x"},
                         {"all": "-"}, {}, False)
        self.assertEqual(st, "weak")

    def test_dkim_gap(self):
        st, reasons = dm.grade({"policy": "reject", "pct": 100, "rua": "mailto:x"},
                               {"all": "-"}, {"present": False}, True)
        self.assertEqual(st, "weak")
        self.assertIn("DKIM selector has no key published", reasons)


class TestParseTarget(unittest.TestCase):
    def test_valid(self):
        t = dm.parse_target({"domain": "Example.COM.", "dkim_selector": "s1", "label": "x"})
        self.assertEqual(t["domain"], "example.com")
        self.assertEqual(t["dkim_selector"], "s1")

    def test_invalid_domain(self):
        for bad in ("", "no spaces here", "a..b", "http://x.com", "x", "-x.com"):
            self.assertIsNone(dm.parse_target({"domain": bad}), bad)

    def test_invalid_selector(self):
        self.assertIsNone(dm.parse_target({"domain": "x.com", "dkim_selector": "bad sel;"}))

    def test_non_dict(self):
        self.assertIsNone(dm.parse_target("nope"))


if __name__ == "__main__":
    unittest.main()
