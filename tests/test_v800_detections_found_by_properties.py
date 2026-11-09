#!/usr/bin/env python3
"""8.0.0: five defects of the Detections rules that a generated run found, each as the plain example that shows it.

A rule reads a Traffic row, a fleet event and a Threat Intel entry. Each of them came out of a store, and a store can hold what a damaged file, a restored backup or a SQL backend that
gives a value back as it was written holds: an infinite score, an integer of four hundred digits, NaN where a count should be, text where a port should be, a number where a list should
be. The promises of `detections.evaluate` over such a record are the same as over a clean one: no rule raises (a rule that raises finds nothing for the host, which is a way to hide a
connection), every finding is bounded, and what is kept is JSON that a browser can parse (`NaN` is not).

These run everywhere. The same promises, stated for any record, are in test_v800_detections_properties.py, which needs hypothesis and skips where it is not installed (CI).
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-detprops-"))
_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS.parent / "server" / "cgi-bin"))

import detections as D  # noqa: E402

NOW = 1_800_000_000
PUBLIC = "8.8.8.8"


def run(ctx, rules=None):
    """(findings, the rules that raised) for one context."""
    errors: list = []
    return D.evaluate(ctx, rules, errors), errors


def out_row(proc="bash", ip=PUBLIC, **extra):
    return {"d": "out", "ip": ip, "port": 4444, "proc": proc, "n": 1, "tx": 10, "rx": 20, **extra}


def ctx_of(rows=None, events=None, intel=None, rec=None):
    return {
        "now": NOW,
        "host": {"id": "h1", "name": "web01"},
        "rows": rows or [],
        "events": events or [],
        "intel": intel or {},
        "rec": rec or {},
    }


class TestWhatAGeneratedRunFound(unittest.TestCase):
    """Five defects, each with the input that showed it."""

    def known_bad(self, score, **entry):
        return run(ctx_of([out_row(ip=PUBLIC, proc="curl")], intel={PUBLIC: {"score": score, **entry}}))

    def bad_contacts(self, found):
        return [f["severity"] for f in found if f["rule"] == "known_bad_contact"]

    def test_an_infinite_score_is_no_score_and_the_rule_does_not_raise(self):
        # int(inf) raised OverflowError, and the rule found nothing for the host
        found, errors = self.known_bad(float("inf"))
        self.assertEqual(errors, [])
        self.assertEqual(self.bad_contacts(found), [], "an infinite score is not a score of 100")

    def test_an_infinite_score_does_not_hide_an_attack_the_same_entry_records(self):
        found, errors = self.known_bad(float("inf"), last=NOW - 3600)
        self.assertEqual(errors, [])
        self.assertEqual(self.bad_contacts(found), ["high"])

    def test_a_score_of_four_hundred_digits_is_no_score_and_the_rule_does_not_raise(self):
        # float(10**400) raised OverflowError
        found, errors = self.known_bad(10**400)
        self.assertEqual(errors, [])
        self.assertEqual(self.bad_contacts(found), [])

    def test_a_real_score_still_counts_so_the_two_above_are_not_passes_by_finding_nothing_at_all(self):
        found, errors = self.known_bad(90)
        self.assertEqual(errors, [])
        self.assertEqual(self.bad_contacts(found), ["high"])

    def test_a_count_that_is_not_a_number_is_none_in_what_is_kept_and_the_finding_is_json(self):
        # NaN went into the stored finding and into the page's answer, where JSON.parse refuses it
        found, errors = run(ctx_of([out_row(rx=float("nan"), tx=float("inf"), n=float("-inf"))]))
        self.assertEqual(errors, [])
        self.assertEqual(len(found), 1)
        for f in (found[0], D.compact(found[0])):
            json.dumps(f, allow_nan=False)
        self.assertEqual(found[0]["evidence"], {"connections": None, "sent": None, "received": None})

    def test_a_port_that_is_text_or_not_a_port_is_left_out_and_a_real_one_is_kept(self):
        for bad in ("x" * 50, float("inf"), 70000, -1, True, [4444]):
            found, errors = run(ctx_of([out_row(port=bad)]))
            self.assertEqual(errors, [], bad)
            self.assertEqual(len(found), 1, bad)
            self.assertNotIn("port", found[0], "port %r" % (bad,))
        found, _ = run(ctx_of([out_row(port=4444)]))
        self.assertEqual(found[0]["port"], 4444)

    def test_an_address_taken_from_an_event_is_cut_where_a_real_one_ends(self):
        # login_new_source carries the address as text, and a finding kept all of it
        events = [
            {"event": "brute_force_detected", "ts": NOW - 600, "payload": {"count": 40, "source_ip": "9.9.9.9"}},
            {"event": "login_new_source", "ts": NOW - 60, "payload": {"source": "9" * 5000, "user": "root"}},
        ]
        found, errors = run(ctx_of(events=events))
        self.assertEqual(errors, [])
        self.assertEqual([f["rule"] for f in found], ["bruteforce_then_login"])
        self.assertLessEqual(len(found[0]["ip"]), 64)
        self.assertLessEqual(len(found[0]["detail"]), 300)

    def test_rows_and_events_that_are_not_lists_find_nothing_and_raise_nothing(self):
        # `for r in (rows or [])` raised TypeError for a truthy number, once in every rule
        for junk in (5, -89760, 1.5, "rows", {"a": 1}, True):
            ctx = ctx_of()
            ctx["rows"], ctx["events"] = junk, junk
            found, errors = run(ctx)
            self.assertEqual((found, errors), ([], []), repr(junk))

    def test_the_clean_input_of_these_examples_does_find_what_it_should(self):
        """Control: an empty result above means something only if the same shapes with clean values are found."""
        found, errors = run(ctx_of([out_row()]))
        self.assertEqual(errors, [])
        self.assertEqual([(f["rule"], f["severity"], f.get("port")) for f in found], [("interpreter_egress", "high", 4444)])

    def test_a_long_text_fact_is_cut_and_a_nested_one_is_text(self):
        facts = D._facts({"a": "x" * 500, "b": {"c": 1}, "d": [1, 2], "e": 7, "f": True, "g": None, "h": 1.5, "i": float("nan"), 5: "k" * 100})
        self.assertEqual(len(facts["a"]), D.TEXT_MAX)
        self.assertIsInstance(facts["b"], str)
        self.assertIsInstance(facts["d"], str)
        self.assertEqual((facts["e"], facts["f"], facts["g"], facts["h"], facts["i"]), (7, True, None, 1.5, None))
        self.assertIn("5", facts, "a key that is not text is read as text")
        self.assertEqual(len(D._facts({str(i): i for i in range(100)})), D.EVIDENCE_KEYS)


if __name__ == "__main__":
    unittest.main()
