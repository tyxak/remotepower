"""v6.4.2 — a rollout ring can finally say "1 %, then 10 %, then the rest".

Both `handle_rollouts_create` and the auto-patch ring validator hard-rejected
any selector type other than group / tag / ids, and `ids` capped at 500. So the
canonical staged shape — canary 1 % of the fleet, then 10 %, then everything
else — could not be expressed at all. Neither could "ring 1 = site Frankfurt".

On a 4,000-host fleet an admin staging an agent self-update had to invent
throwaway tags (`ring-canary`, `ring-pilot`) and apply them across 420 hosts
through a batch bar that selects one page at a time, before they could create
the rollout. And the last ring had no expression: "broad" was whatever group
they named, so it silently omitted every host with no group and every host
enrolled after the rollout was created.

`docs/rollouts.md` had been telling operators the opposite the whole time —
rings defined "by group / tag / site / count".

The UI shipped exactly three hardcoded ring rows with no add control, so even
the server's existing 10-ring capacity was unreachable.
"""

import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(_CGI))

from srcpin import py_function  # noqa: E402
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-ringsel-"))

_spec = importlib.util.spec_from_file_location("api_ringsel", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_JS = ROOT / "server" / "html" / "static" / "js"
_HTML = ROOT / "server" / "html" / "index.html"

# 40 hosts: h000-h009 in Frankfurt, the rest in Amsterdam.
_DEVICES = {f"h{i:03d}": {"name": f"h{i:03d}", "group": "prod",
                          "site": "fra" if i < 10 else "ams"}
            for i in range(40)}
_STAGED = [
    {"name": "canary", "selector": {"type": "percent", "value": "1"}},
    {"name": "pilot",  "selector": {"type": "percent", "value": "10"}},
    {"name": "rest",   "selector": {"type": "remaining"}},
]


class TestStagedPercentages(unittest.TestCase):
    """The shape the finding is named for."""

    def _rings(self):
        return [api._rollout_ring_ids(_STAGED, i, _DEVICES) for i in range(3)]

    def test_one_percent_of_forty_is_one_host_not_zero(self):
        """Truncating would make a 1 % canary on a 40-host fleet dispatch to
        nobody and immediately report itself done — a ring that verifies
        nothing before the next one goes out."""
        self.assertEqual(len(self._rings()[0]), 1)

    def test_percentages_are_of_the_fleet_not_of_what_is_left(self):
        """"1 %, then 10 %" is how an operator says it. Read as a share of the
        REMAINDER, the second ring would be 10 % of 39 — close enough here to
        pass unnoticed and wrong on every fleet."""
        self.assertEqual(len(self._rings()[1]), 4)

    def test_the_rings_are_disjoint(self):
        a, b, c = self._rings()
        self.assertEqual(set(a) & set(b), set())
        self.assertEqual(set(b) & set(c), set())
        self.assertEqual(set(a) & set(c), set())

    def test_they_cover_the_whole_fleet(self):
        self.assertEqual(sorted(sum(self._rings(), [])), sorted(_DEVICES))
        self.assertEqual(api._rollout_ring_coverage(_STAGED, _DEVICES),
                         set(_DEVICES))

    def test_remaining_picks_up_a_host_no_earlier_ring_named(self):
        """The point of the selector: a host with no group, or one enrolled
        after the rollout was created, still gets reached."""
        rings = [{"selector": {"type": "group", "value": "prod"}},
                 {"selector": {"type": "remaining"}}]
        devs = dict(_DEVICES, orphan={"name": "orphan"})   # no group at all
        self.assertEqual(api._rollout_ring_ids(rings, 1, devs), ["orphan"])

    def test_resolving_a_ring_alone_is_not_enough(self):
        """`_rollout_resolve_ring` on ring 2 by itself has no idea what ring 1
        took. Any caller resolving ring N must replay 0..N-1 — pin that the two
        really do differ, so the helper cannot be quietly bypassed."""
        alone = api._rollout_resolve_ring(_STAGED[2]["selector"], _DEVICES)
        self.assertEqual(len(alone), 40)                      # the whole fleet
        self.assertEqual(len(api._rollout_ring_ids(_STAGED, 2, _DEVICES)), 35)

    def test_the_order_is_deterministic(self):
        """A ring re-resolves at dispatch. An unstable order would let a host
        slip between two rings, or land in both."""
        for _ in range(3):
            self.assertEqual(api._rollout_ring_ids(_STAGED, 0, _DEVICES), ["h000"])


class TestOtherSelectors(unittest.TestCase):
    def test_site(self):
        ids = api._rollout_resolve_ring({"type": "site", "value": "fra"}, _DEVICES)
        self.assertEqual(len(ids), 10)
        self.assertTrue(all(_DEVICES[i]["site"] == "fra" for i in ids))

    def test_count(self):
        self.assertEqual(api._rollout_resolve_ring({"type": "count", "value": "5"},
                                                   _DEVICES),
                         ["h000", "h001", "h002", "h003", "h004"])

    def test_count_larger_than_the_fleet_is_the_fleet(self):
        self.assertEqual(len(api._rollout_resolve_ring(
            {"type": "count", "value": "9999"}, _DEVICES)), 40)

    def test_the_old_selectors_are_untouched(self):
        self.assertEqual(len(api._rollout_resolve_ring(
            {"type": "group", "value": "prod"}, _DEVICES)), 40)
        self.assertEqual(api._rollout_resolve_ring(
            {"type": "ids", "ids": ["h001"]}, _DEVICES), ["h001"])

    def test_an_unknown_type_still_resolves_to_nothing(self):
        self.assertEqual(api._rollout_resolve_ring({"type": "everything"}, _DEVICES),
                         [])


class _Base(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for attr in ("DEVICES_FILE", "ROLLOUTS_FILE", "CONFIG_FILE"):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in
                      ("require_auth", "require_admin_auth", "verify_token",
                       "get_token_from_request", "audit_log", "fire_webhook",
                       "respond", "method", "get_json_body")}
        api.require_auth = lambda require_admin=False: "jakob"
        api.require_admin_auth = lambda: "jakob"
        api.verify_token = lambda t: ("jakob", "admin")
        api.get_token_from_request = lambda: "t"
        api.audit_log = lambda *a, **k: None
        api.fire_webhook = lambda *a, **k: None

        def _resp(s, b=None):
            self.cap["s"], self.cap["b"] = s, b
            raise api.HTTPError(s, b)
        api.respond = _resp
        api.save(api.DEVICES_FILE, dict(_DEVICES))
        api._invalidate_load_cache(api.DEVICES_FILE)

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for a, v in self._files.items():
            setattr(api, a, v)

    def create(self, rings):
        api.method = lambda: "POST"
        api.get_json_body = lambda: {"name": "staged", "action": "self-update",
                                     "rings": rings}
        try:
            api.handle_rollouts_create()
        except api.HTTPError:
            pass
        return self.cap.get("b")


class TestCreateAcceptsThem(_Base):
    def test_the_staged_shape_survives_a_round_trip(self):
        r = self.create(_STAGED)
        self.assertTrue(r and r.get("ok"), r)
        self.assertEqual([x["selector"]["type"] for x in r["rollout"]["rings"]],
                         ["percent", "percent", "remaining"])

    def test_remaining_needs_no_value(self):
        """Every other selector is dropped when its value is blank. `remaining`
        is fully specified by its position, so the same rule would delete the
        ring that exists to catch what the others miss."""
        r = self.create([{"name": "rest", "selector": {"type": "remaining"}}])
        self.assertTrue(r and r.get("ok"), r)
        self.assertEqual(r["rollout"]["rings"][0]["selector"], {"type": "remaining"})

    def test_site_and_smart_are_accepted(self):
        r = self.create([{"selector": {"type": "site", "value": "fra"}}])
        self.assertTrue(r and r.get("ok"), r)

    def test_a_non_numeric_percent_is_rejected_not_silently_zero(self):
        """Left to resolve, "ten" becomes 0 hosts: a 201, a success toast, and a
        ring that reports itself done having dispatched to nobody."""
        self.create([{"selector": {"type": "percent", "value": "ten"}}])
        self.assertEqual(self.cap["s"], 400)

    def test_zero_and_over_a_hundred_percent_are_rejected(self):
        for bad in ("0", "-5", "101"):
            with self.subTest(value=bad):
                self.create([{"selector": {"type": "percent", "value": bad}}])
                self.assertEqual(self.cap["s"], 400)

    def test_an_unknown_type_is_still_rejected(self):
        self.create([{"selector": {"type": "everything", "value": "*"}}])
        self.assertEqual(self.cap["s"], 400)


class TestAutoPatchRingsAgree(unittest.TestCase):
    """The auto-patch validator is a second copy of the same whitelist. Left
    behind, a policy could not express what a hand-made rollout now can."""

    def test_the_two_whitelists_match(self):
        src = (_CGI / "api.py").read_text()
        pv = (_CGI / "provisioning_handlers.py").read_text()
        def types(text, fn):
            body = py_function(text, fn)
            m = re.search(r"if st not in \(([^)]*)\)", body, re.S)
            return set(re.findall(r"'([a-z]+)'", m.group(1)))
        self.assertEqual(types(src, "_autopatch_clean_rings"),
                         types(pv, "handle_rollouts_create"))

    def test_a_policy_accepts_the_staged_shape(self):
        clean = api._autopatch_clean_rings(_STAGED)
        self.assertEqual([c["selector"]["type"] for c in clean],
                         ["percent", "percent", "remaining"])

    def test_a_policy_drops_a_bad_number_rather_than_500ing(self):
        """This path validates silently — no respond() — so a bad ring is
        dropped, not 400'd. What must not happen is a zero-host ring."""
        self.assertEqual(api._autopatch_clean_rings(
            [{"selector": {"type": "percent", "value": "nope"}}]), [])

    def test_policy_coverage_counts_rings_in_order(self):
        """Unioning independently resolved rings counts `remaining` as the whole
        fleet, so the run response reports 40 covered on a 40-host fleet whether
        the rings overlap or not — a number that is right by accident."""
        self.assertEqual(len(api._rollout_ring_coverage(_STAGED, _DEVICES)), 40)
        partial = [{"selector": {"type": "site", "value": "fra"}}]
        self.assertEqual(len(api._rollout_ring_coverage(partial, _DEVICES)), 10)


class TestDispatchUsesTheReplay(unittest.TestCase):
    def test_dispatch_resolves_ring_n_against_rings_before_it(self):
        """A dispatch that called `_rollout_resolve_ring` on the ring alone
        would hand ring 2 the hosts the canary already took."""
        src = (_CGI / "provisioning_handlers.py").read_text()
        i = src.index("def _rollout_dispatch_ring(")
        body = src[i:src.index("\ndef ", i + 10)]
        self.assertIn("_rollout_ring_ids(", body)
        self.assertNotIn("A._rollout_resolve_ring(ring.get('selector')", body)

    def test_the_replay_is_live_not_read_from_dispatched_ids(self):
        """The fleet moves between rings — that is what the verify window is
        for. A host quarantined during ring 1 must not be promoted into
        "everything else" just because ring 1 skipped it at dispatch."""
        src = (_CGI / "provisioning_handlers.py").read_text()
        i = src.index("def _rollout_ring_ids(")
        body = src[i:src.index("\ndef ", i + 10)]
        self.assertNotIn("dispatched_ids", body.split('"""')[-1])


class TestTheUiCanExpressIt(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not _HTML.exists():
            raise unittest.SkipTest("excluded from this tree")
        cls.html = _HTML.read_text()
        cls.js = (_JS / "app-rollouts.js").read_text()

    def test_every_ring_row_offers_the_new_types(self):
        i = self.html.index('<div id="ro-rings">')
        rows = self.html[i:self.html.index("</div>", self.html.index('data-action="addRolloutRing"'))]
        self.assertEqual(rows.count("ro-ring-type"), 3)
        for t in ("site", "percent", "count", "remaining"):
            with self.subTest(type=t):
                self.assertEqual(rows.count(f'<option value="{t}">'), 3,
                                 "all three ring rows need it")

    def test_there_is_an_add_ring_control(self):
        """The server has always accepted 10 rings; the modal shipped 3 static
        rows and no way to add a fourth."""
        self.assertIn('data-action="addRolloutRing"', self.html)
        self.assertIn("function addRolloutRing(", self.js)

    def test_add_ring_stops_at_the_server_cap(self):
        body = self.js[self.js.index("function addRolloutRing("):]
        body = body[:body.index("\n}\n")]
        self.assertIn(">= 10", body,
                      "an 11th row would be accepted here and dropped by "
                      "raw_rings[:10] server-side")

    def test_extra_rows_are_cleared_when_the_modal_reopens(self):
        body = self.js[self.js.index("async function openRolloutModal("):]
        body = body[:body.index("\n}\n")]
        self.assertIn("row.remove()", body)

    def test_a_remaining_ring_is_submitted_with_no_value(self):
        body = self.js[self.js.index("async function saveRollout("):]
        body = body[:body.index("\n}\n")]
        code = re.sub(r"^\s*//.*$", "", body, flags=re.M)
        self.assertIn("type !== 'remaining'", code,
                      "the empty-value skip would drop the ring")
        self.assertIn("{ type }", code)

    def test_the_value_box_says_what_it_wants(self):
        self.assertIn("function roRingTypeChange(", self.js)
        self.assertIn("_RO_RING_PLACEHOLDER", self.js)

    def test_the_value_box_is_disabled_for_remaining(self):
        """A live text box next to a selector that ignores it invites the
        operator to type something and expect it to matter."""
        body = self.js[self.js.index("function roRingTypeChange("):]
        body = body[:body.index("\n}\n")]
        self.assertIn("val.disabled = type === 'remaining'", body)

    def test_no_inline_handlers(self):
        i = self.html.index('data-action="addRolloutRing"')
        self.assertNotIn("onclick", self.html[i - 200:i + 200])


class TestDocsMatchTheCode(unittest.TestCase):
    def test_the_ring_model_lists_what_is_actually_accepted(self):
        p = ROOT / "docs" / "rollouts.md"
        if not p.exists():
            self.skipTest("excluded from this tree")
        txt = p.read_text()
        for word in ("group", "tag", "site", "smart group", "percentage",
                     "everything else"):
            with self.subTest(word=word):
                self.assertIn(word, txt)

    def test_it_no_longer_promises_only_the_old_four(self):
        """The line read "by group / tag / site / count" while the code took
        group/tag/ids — naming `site` and `count`, neither of which existed,
        and omitting `ids`, which did."""
        p = ROOT / "docs" / "rollouts.md"
        if not p.exists():
            self.skipTest("excluded from this tree")
        self.assertNotIn("by group / tag /\n  site / count", p.read_text())


if __name__ == "__main__":
    unittest.main()
