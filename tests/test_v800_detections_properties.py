#!/usr/bin/env python3
"""8.0.0: the promises of the Detections rules, stated for any record and checked by Hypothesis.

No rule raises over a record that holds anything (a rule that raises finds nothing for the host), every finding is bounded, and what is kept is JSON a browser can parse. The inputs
that broke the first version of these rules, as plain examples, are in test_v800_detections_found_by_properties.py; they run everywhere. CI does not install hypothesis (see
test_hypothesis_props.py), so this module skips there and runs where the property tools are.
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

try:
    from hypothesis import HealthCheck, given, settings
    from hypothesis import strategies as st
except ImportError:  # pragma: no cover
    raise unittest.SkipTest("hypothesis is not installed")

import detections as D  # noqa: E402

NOW = 1_800_000_000
PUBLIC = "8.8.8.8"

FAST = settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])


def run(ctx, rules=None):
    """(findings, the rules that raised) for one context."""
    errors: list = []
    return D.evaluate(ctx, rules, errors), errors


ODD_NUMBERS = [10**400, -(10**400), 2**63, -(2**63), 0, 1, -1, float("inf"), float("-inf"), float("nan"), 1e308, -0.0]
ADDRESSES = [PUBLIC, "1.1.1.1", "203.0.113.9", "2001:4860:4860::8888", "10.0.0.1", "127.0.0.1", "::1", "169.254.1.1", "fe80::1%eth0", "999.1.1.1", "", " 8.8.8.8", "８.８.８.８", "x" * 300]
PROGRAMS = ["bash", "sh", "/bin/bash", "nc", "ncat", "mysqld", "nginx", "sshd", "apt", "redis-server", "BASH", "bash -c x", "", "p" * 500]
EVENTS = sorted(D.EVENT_NAMES) + ["brute_force_detected", "login_new_source", "ssh_key_added", "empty_password_account", "firewall_changed", "new_port_detected", "port_exposed_world", "other"]

SCALAR = st.none() | st.booleans() | st.integers() | st.sampled_from(ODD_NUMBERS) | st.floats() | st.text(max_size=40) | st.sampled_from(ADDRESSES) | st.sampled_from(PROGRAMS)
JSON = st.recursive(SCALAR, lambda c: st.lists(c, max_size=4) | st.dictionaries(st.text(max_size=8), c, max_size=4), max_leaves=6)
NUMBER = st.integers(0, 2**40) | st.sampled_from(ODD_NUMBERS) | JSON
STAMP = st.integers(NOW - 3 * 86400, NOW + 100) | st.sampled_from(ODD_NUMBERS) | JSON

ROW = st.fixed_dictionaries(
    {"ip": st.sampled_from(ADDRESSES) | JSON},
    optional={"d": st.sampled_from(["in", "out", "x"]) | JSON, "proc": st.sampled_from(PROGRAMS) | JSON, "port": NUMBER, "n": NUMBER, "tx": NUMBER, "rx": NUMBER},
)
PAYLOAD = JSON | st.fixed_dictionaries(
    {}, optional={"port": NUMBER, "source": st.sampled_from(ADDRESSES) | JSON, "source_ip": st.sampled_from(ADDRESSES) | JSON, "count": NUMBER, "user": st.text(max_size=300) | JSON}
)
EVENT = JSON | st.fixed_dictionaries({"event": st.sampled_from(EVENTS) | JSON, "ts": STAMP}, optional={"payload": PAYLOAD})
SEEN = JSON | st.dictionaries(st.sampled_from(ADDRESSES), STAMP, max_size=6)
REC = JSON | st.fixed_dictionaries({}, optional={"seen": SEEN, "seen_out": SEEN, "first": STAMP, "first_seen": STAMP})
INTEL = JSON | st.dictionaries(st.sampled_from(ADDRESSES), JSON | st.fixed_dictionaries({}, optional={"score": NUMBER, "last": STAMP}), max_size=6)
HOST = JSON | st.fixed_dictionaries({}, optional={"id": st.text(max_size=20) | JSON, "name": st.text(max_size=30) | JSON})
CONTEXT = st.fixed_dictionaries(
    {"now": st.just(NOW) | STAMP, "host": HOST, "rows": st.lists(ROW | JSON, max_size=6) | JSON, "events": st.lists(EVENT, max_size=8) | JSON, "rec": REC, "intel": INTEL}
)


class TestTheRulesOverAnyRecord(unittest.TestCase):

    @FAST
    @given(CONTEXT)
    def test_no_rule_raises_and_every_finding_is_bounded_and_json(self, ctx):
        found, errors = run(ctx)
        self.assertEqual(errors, [], "a rule that raises finds nothing for the host")
        keys = set()
        for f in found:
            self.assertIn(f["severity"], D.RANK)
            self.assertIsInstance(f["key"], str)
            self.assertLessEqual(len(f["key"]), 200)
            self.assertNotIn(f["key"], keys, "a key is found once")
            keys.add(f["key"])
            self.assertLessEqual(len(f["detail"]), 300)
            self.assertIsInstance(f["repeat_s"], int)
            self.assertLessEqual(f["repeat_s"], D.KEEP_S)
            for k in ("ip", "process"):
                if k in f:
                    self.assertIsInstance(f[k], str)
                    self.assertLessEqual(len(f[k]), 64)
            if "port" in f:
                self.assertIs(type(f["port"]), int)
                self.assertTrue(0 <= f["port"] <= 65535)
            json.dumps(D.compact(f), allow_nan=False)
            json.dumps(f["evidence"] if "evidence" in f else {}, allow_nan=False)

    @FAST
    @given(CONTEXT, st.dictionaries(st.sampled_from(sorted(D.RULES)), st.dictionaries(st.text(max_size=12), JSON, max_size=4) | JSON, max_size=6) | JSON)
    def test_rules_of_any_shape_are_read_as_the_defaults_or_skipped_and_never_raise_out_of_evaluate(self, ctx, stored):
        rules = D.settings(stored)
        found, _errors = run(ctx, rules)
        self.assertIsInstance(found, list)
        self.assertEqual(sorted(rules), sorted(D.RULES))

    @FAST
    @given(JSON, st.integers(NOW - 9 * 86400, NOW + 1000))
    def test_what_is_remembered_is_bounded_and_what_is_due_is_a_bool(self, alerted, now):
        f = {"key": "k", "repeat_s": 3600}
        kept = D.remember(alerted, [f], now)
        self.assertLessEqual(len(kept), 100)
        self.assertIn("k", kept)
        self.assertIsInstance(D.is_due(alerted, f, now), bool)


if __name__ == "__main__":
    unittest.main()
