"""v6.4.2 — an SNMP trap stops being an undifferentiated "SNMP trap received".

`handle_snmp_trap_in` stored `{ts, oid, value, type, agent}` verbatim and fired
ONE coalesced `snmp_trap_received` per host with no identity field — so every
trap from a device folded into a single open alert row regardless of what it
said, at one fixed `medium`.

A UPS emitting `.1.3.6.1.4.1.318.0.5` (on battery) and a switch emitting its
fourth linkDown of the hour therefore arrived as the same alert, with an
unreadable dotted string in the payload. Paging on the first while ignoring the
second is the entire reason anyone runs a trap receiver, and it was not
expressible. Acknowledging the noisy one buried the outage.

`snmp.oid_label()` — longest-prefix MIB name resolution — has existed since the
OID walk browser shipped and had exactly ONE caller: the walk browser. The trap
ingest path, the one place an unreadable dotted string costs an operator
something at 3am, was the one place it was not used.
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
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(_CGI))
from srcpin import py_function  # noqa: E402  (growth-proof source pins)
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-traprules-"))

_spec = importlib.util.spec_from_file_location("api_traprules", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_UPS_ON_BATTERY = "1.3.6.1.4.1.318.0.5"
_APC_ENTERPRISE = "1.3.6.1.4.1.318"
_LINK_DOWN = "1.3.6.1.6.3.1.1.5.3"

_RULES = [
    {"id": "r1", "name": "UPS on battery", "oid_prefix": _UPS_ON_BATTERY,
     "value_match": "", "severity": "critical", "device_id": "", "enabled": True},
    {"id": "r2", "name": "APC chatter", "oid_prefix": _APC_ENTERPRISE,
     "value_match": "", "severity": "low", "device_id": "", "enabled": True},
    {"id": "r3", "name": "linkDown", "oid_prefix": _LINK_DOWN,
     "value_match": "", "severity": "ignore", "device_id": "", "enabled": True},
]


class TestTheMatcher(unittest.TestCase):
    def m(self, oid, value="", dev="d1", rules=None):
        return api._snmp_trap_rule_match(oid, value, dev,
                                         _RULES if rules is None else rules)

    def test_longest_prefix_wins_regardless_of_list_order(self):
        """The specific rule was added FIRST here and the broad one second; the
        opposite order must give the same answer, or an operator adding a
        narrower rule later would have to reorder the broad one to make it
        take effect — a trap for anyone who does not know that."""
        self.assertEqual(self.m(_UPS_ON_BATTERY)["name"], "UPS on battery")
        self.assertEqual(
            self.m(_UPS_ON_BATTERY, rules=list(reversed(_RULES)))["name"],
            "UPS on battery")

    def test_a_broad_rule_still_catches_its_subtree(self):
        self.assertEqual(self.m("1.3.6.1.4.1.318.0.9")["name"], "APC chatter")

    def test_a_leading_dot_is_the_same_oid(self):
        """snmptrapd emits both shapes."""
        self.assertEqual(self.m("." + _UPS_ON_BATTERY)["name"], "UPS on battery")

    def test_a_prefix_only_matches_on_arc_boundaries(self):
        """`1.3.6.1.4.1.3180` is a different vendor, not a child of `...318`."""
        self.assertIsNone(self.m("1.3.6.1.4.1.3180.1"))

    def test_no_rule_means_no_rule(self):
        self.assertIsNone(self.m("1.2.3.4"))

    def test_a_disabled_rule_does_not_match(self):
        self.assertIsNone(self.m(_UPS_ON_BATTERY,
                                 rules=[dict(_RULES[0], enabled=False)]))

    def test_a_device_scoped_rule_only_applies_to_that_device(self):
        scoped = [dict(_RULES[0], device_id="d1")]
        self.assertIsNotNone(self.m(_UPS_ON_BATTERY, dev="d1", rules=scoped))
        self.assertIsNone(self.m(_UPS_ON_BATTERY, dev="d2", rules=scoped))

    def test_the_value_regex_narrows_it(self):
        rules = [dict(_RULES[0], value_match=r"^(2|3)$")]
        self.assertIsNotNone(self.m(_UPS_ON_BATTERY, "2", rules=rules))
        self.assertIsNone(self.m(_UPS_ON_BATTERY, "1", rules=rules))

    def test_an_uncompilable_regex_skips_the_rule_not_the_trap(self):
        """A rule that can no longer compile must not silently swallow the
        trap — it steps aside and a broader rule (or the default) takes it."""
        rules = [{"oid_prefix": _UPS_ON_BATTERY, "value_match": "[unclosed",
                  "severity": "critical", "enabled": True},
                 dict(_RULES[1])]
        self.assertEqual(self.m(_UPS_ON_BATTERY, "x", rules=rules)["name"],
                         "APC chatter")

    def test_junk_rules_are_survivable(self):
        for bad in ([None], ["nope"], [{}], [{"oid_prefix": ""}]):
            with self.subTest(rules=bad):
                self.assertIsNone(self.m(_UPS_ON_BATTERY, rules=bad))


class TestSeverityComesFromTheRule(unittest.TestCase):
    def test_a_rule_sets_it(self):
        self.assertEqual(
            api._alert_severity("snmp_trap_received", {"severity": "critical"}),
            "critical")

    def test_an_unmatched_trap_keeps_the_old_medium(self):
        """Not a behaviour change for anyone who never writes a rule."""
        self.assertEqual(api._alert_severity("snmp_trap_received", {}), "medium")
        self.assertEqual(
            api._alert_severity("snmp_trap_received", {"severity": ""}), "medium")

    def test_a_junk_severity_does_not_drop_the_alert(self):
        """Returning None from _alert_severity means "never reaches the inbox".
        A malformed stored rule must not silently mute a host's traps."""
        self.assertEqual(
            api._alert_severity("snmp_trap_received", {"severity": "urgent!!"}),
            "medium")


class TestTheAlertPlumbing(unittest.TestCase):
    """Three lists have to agree or the fix is cosmetic — this is the exact
    trio CLAUDE.md documents for a per-resource alert."""

    def test_rule_is_an_identity_field(self):
        """Without it, _record_alert coalesces two different traps from one
        host into a single row and the per-rule separation buys nothing."""
        self.assertIn("rule", api._ALERT_IDENTITY_FIELDS)

    def test_the_payload_keys_are_stored(self):
        """An identity field the row does not carry discriminates nothing."""
        src = (_CGI / "api.py").read_text()
        block = py_function(src, "_record_alert")
        for key in ("'rule', 'oid', 'oid_label'",):
            self.assertIn(key, block)

    def test_the_event_severity_is_payload_derived(self):
        self.assertIsNone(api.EVENT_REGISTRY["snmp_trap_received"]["severity"])
        self.assertIn("snmp_trap_received", api._ALERT_RULES)

    def test_both_renderers_lead_with_something_actionable(self):
        """Two renderers, two registries: `_alert_title` writes the inbox row,
        notify's `_webhook_message` writes the push. The push one fell through
        to the GENERIC fallback ("sw-core: Snmp trap received") with no OID and
        no MIB name at all."""
        import notify
        p = {"name": "sw-core", "count": 1, "oid": _UPS_ON_BATTERY,
             "value": "2", "rule": "UPS on battery"}
        for render in (api._alert_title,
                       lambda e, pl: notify._webhook_message(e, pl)):
            with self.subTest(render=render):
                msg = render("snmp_trap_received", p)
                self.assertTrue(msg.startswith("UPS on battery on sw-core"), msg)
                self.assertIn(_UPS_ON_BATTERY, msg)

    def test_they_fall_back_to_the_mib_label_then_the_old_wording(self):
        import notify
        for render in (api._alert_title, notify._webhook_message):
            with self.subTest(render=render):
                self.assertIn("upsOnBattery on sw", render(
                    "snmp_trap_received",
                    {"name": "sw", "oid_label": "upsOnBattery", "count": 1}))
                self.assertIn("SNMP trap from sw", render(
                    "snmp_trap_received", {"name": "sw", "count": 1}))


class _Base(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for attr in ("SNMP_TRAP_RULES_FILE", "SNMP_TRAPS_FILE", "DEVICES_FILE",
                     "INBOUND_WEBHOOKS_FILE", "CONFIG_FILE"):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
        self.cap = {}
        self.fired = []
        self._orig = {n: getattr(api, n) for n in
                      ("require_admin_auth", "audit_log", "fire_webhook",
                       "respond", "method", "get_json_body", "_log_inbound",
                       "_scope_block_device")}
        api.require_admin_auth = lambda: "jakob"
        api.audit_log = lambda *a, **k: None
        api._log_inbound = lambda *a, **k: None
        api._scope_block_device = lambda d: None
        api.fire_webhook = lambda ev, p=None, **k: self.fired.append((ev, p or {}))

        def _resp(s, b=None):
            self.cap["s"], self.cap["b"] = s, b
            raise api.HTTPError(s, b)
        api.respond = _resp

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for a, v in self._files.items():
            setattr(api, a, v)

    def call(self, fn, *a):
        try:
            fn(*a)
        except api.HTTPError:
            pass
        return self.cap.get("b")


class TestCrud(_Base):
    def create(self, **kw):
        api.method = lambda: "POST"
        body = {"name": "UPS", "oid_prefix": _UPS_ON_BATTERY, "severity": "critical"}
        body.update(kw)
        api.get_json_body = lambda: body
        return self.call(api.handle_snmp_trap_rules)

    def test_create_and_list(self):
        r = self.create()
        self.assertTrue(r and r.get("ok"), r)
        api.method = lambda: "GET"
        listed = self.call(api.handle_snmp_trap_rules)
        self.assertEqual(len(listed["rules"]), 1)
        self.assertEqual(listed["rules"][0]["severity"], "critical")

    def test_a_bad_oid_is_refused_at_save(self):
        """Silently dropping it would leave the operator looking at a rule
        that saved and does nothing."""
        self.create(oid_prefix="not.an.oid")
        self.assertEqual(self.cap["s"], 400)

    def test_a_missing_oid_is_refused(self):
        self.create(oid_prefix="")
        self.assertEqual(self.cap["s"], 400)

    def test_a_bad_regex_is_refused_at_save_not_at_3am(self):
        self.create(value_match="[unclosed")
        self.assertEqual(self.cap["s"], 400)

    def test_an_unknown_severity_is_refused(self):
        self.create(severity="urgent")
        self.assertEqual(self.cap["s"], 400)

    def test_ignore_is_a_valid_severity(self):
        """Muting the chatty ones is half the point of a trap receiver."""
        r = self.create(severity="ignore")
        self.assertTrue(r and r.get("ok"), r)

    def test_a_scoped_rule_is_scope_checked(self):
        blocked = []
        api._scope_block_device = lambda d: blocked.append(d)
        self.create(device_id="d1")
        self.assertEqual(blocked, ["d1"])

    def test_update_and_delete(self):
        rid = self.create()["rule"]["id"]
        api.method = lambda: "PATCH"
        api.get_json_body = lambda: {"name": "UPS", "oid_prefix": _UPS_ON_BATTERY,
                                     "severity": "low"}
        self.call(api.handle_snmp_trap_rule, rid)
        api.method = lambda: "GET"
        self.assertEqual(self.call(api.handle_snmp_trap_rules)["rules"][0]["severity"],
                         "low")
        api.method = lambda: "DELETE"
        self.call(api.handle_snmp_trap_rule, rid)
        api.method = lambda: "GET"
        self.assertEqual(self.call(api.handle_snmp_trap_rules)["rules"], [])

    def test_deleting_an_unknown_rule_404s(self):
        api.method = lambda: "DELETE"
        self.call(api.handle_snmp_trap_rule, "nope")
        self.assertEqual(self.cap["s"], 404)

    def test_the_dry_run_reports_what_would_happen(self):
        self.create()
        api.method = lambda: "POST"
        api.get_json_body = lambda: {"oid": _UPS_ON_BATTERY, "value": "2"}
        r = self.call(api.handle_snmp_trap_rule_test)
        self.assertEqual(r["matched"]["name"], "UPS")
        self.assertEqual(r["severity"], "critical")
        self.assertEqual(r["action"], "alert")

    def test_the_dry_run_resolves_the_mib_name(self):
        api.method = lambda: "POST"
        api.get_json_body = lambda: {"oid": "1.3.6.1.2.1.1.3.0"}
        r = self.call(api.handle_snmp_trap_rule_test)
        self.assertEqual(r["oid_label"], "sysUpTime")
        self.assertIsNone(r["matched"])
        self.assertEqual(r["severity"], "medium")

    def test_the_dry_run_reports_a_suppression(self):
        self.create(severity="ignore")
        api.method = lambda: "POST"
        api.get_json_body = lambda: {"oid": _UPS_ON_BATTERY}
        self.assertEqual(self.call(api.handle_snmp_trap_rule_test)["action"],
                         "suppressed")


class TestIngest(_Base):
    def setUp(self):
        super().setUp()
        api.save(api.DEVICES_FILE, {"d1": {"name": "sw-core"}})
        api.save(api.INBOUND_WEBHOOKS_FILE, {"tokens": [
            {"id": "t1", "label": "traps", "token": "rpwi_test", "enabled": True,
             "kind": "snmp_trap", "scope_device_id": "d1"}]})
        api.save(api.SNMP_TRAP_RULES_FILE, {"rules": _RULES})
        for f in (api.DEVICES_FILE, api.INBOUND_WEBHOOKS_FILE,
                  api.SNMP_TRAP_RULES_FILE):
            api._invalidate_load_cache(f)
        api.method = lambda: "POST"

    def post(self, traps):
        api.get_json_body = lambda: {"traps": traps}
        for f in (api.SNMP_TRAP_RULES_FILE, api.SNMP_TRAPS_FILE):
            api._invalidate_load_cache(f)
        return self.call(api.handle_snmp_trap_in, "rpwi_test")

    def test_two_different_traps_do_not_share_one_alert(self):
        """The whole finding in one assertion. Before: one fire, one row, one
        severity, whichever OID happened to be first in the batch."""
        self.post([{"oid": _UPS_ON_BATTERY, "value": "2"},
                   {"oid": "1.3.6.1.4.1.318.0.9", "value": "x"}])
        rules = sorted(p.get("rule") for _, p in self.fired)
        self.assertEqual(rules, ["APC chatter", "UPS on battery"])
        sevs = {p["rule"]: p["severity"] for _, p in self.fired}
        self.assertEqual(sevs["UPS on battery"], "critical")
        self.assertEqual(sevs["APC chatter"], "low")

    def test_an_ignore_rule_fires_nothing(self):
        self.post([{"oid": _LINK_DOWN, "value": "1"}])
        self.assertEqual(self.fired, [])

    def test_an_ignored_trap_is_still_recorded(self):
        """Suppressing the ALERT is not the same as pretending the trap never
        arrived — the device's trap view is where an operator reconstructs
        what happened."""
        self.post([{"oid": _LINK_DOWN, "value": "1"}])
        api._invalidate_load_cache(api.SNMP_TRAPS_FILE)
        stored = (api.load(api.SNMP_TRAPS_FILE) or {}).get("d1") or []
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]["rule"], "linkDown")

    def test_unmatched_traps_still_coalesce_into_one(self):
        """Unclassified noise coalescing is the RIGHT behaviour — it is what
        the fixed severity was wrong about, not the batching."""
        self.post([{"oid": "1.2.3.4"}, {"oid": "1.2.3.5"}])
        self.assertEqual(len(self.fired), 1)
        self.assertEqual(self.fired[0][1]["rule"], "")
        self.assertEqual(self.fired[0][1]["count"], 2)

    def test_the_stored_trap_carries_its_mib_label(self):
        self.post([{"oid": "1.3.6.1.2.1.1.3.0", "value": "42"}])
        api._invalidate_load_cache(api.SNMP_TRAPS_FILE)
        stored = (api.load(api.SNMP_TRAPS_FILE) or {})["d1"]
        self.assertEqual(stored[0]["label"], "sysUpTime")

    def test_the_alert_carries_the_label_too(self):
        self.post([{"oid": "1.3.6.1.2.1.1.3.0"}])
        self.assertEqual(self.fired[0][1]["oid_label"], "sysUpTime")

    def test_a_fleet_with_no_rules_behaves_exactly_as_before(self):
        api.save(api.SNMP_TRAP_RULES_FILE, {"rules": []})
        self.post([{"oid": _UPS_ON_BATTERY}, {"oid": _LINK_DOWN}])
        self.assertEqual(len(self.fired), 1)
        self.assertEqual(self.fired[0][1]["count"], 2)
        self.assertEqual(self.fired[0][1]["severity"], "")


class TestTheWastedAsset(unittest.TestCase):
    def test_oid_label_now_has_more_than_one_caller(self):
        """It resolved OIDs for the walk browser and nothing else, while the
        trap store — where an unreadable OID actually costs something — kept
        raw dotted strings."""
        import snmp
        self.assertEqual(snmp.oid_label("1.3.6.1.2.1.1.3.0"), "sysUpTime")
        api_src = (_CGI / "api.py").read_text()
        self.assertIn("oid_label(", api_src)
        self.assertIn("oid_label(", py_function(api_src, "handle_snmp_trap_in"))


class TestUiWiring(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p = ROOT / "server" / "html" / "index.html"
        if not p.exists():
            raise unittest.SkipTest("excluded from this tree")
        cls.html = p.read_text()
        cls.js = (ROOT / "server" / "html" / "static" / "js" / "app.js").read_text()

    def test_the_pane_exists_beside_the_token_table(self):
        self.assertIn('id="trap-rules-tbody"', self.html)
        i, j = self.html.index("Inbound webhooks"), self.html.index("SNMP trap rules")
        self.assertLess(i, j, "the rules belong next to the tokens that feed them")

    def test_the_table_is_sortable_like_every_other(self):
        self.assertIn('id="trap-rules-thead"', self.html)
        self.assertIn("wireSortOnly('trap-rules-thead'", self.js)
        for col in ("name", "oid_prefix", "severity", "enabled"):
            with self.subTest(col=col):
                self.assertIn(f'data-col="{col}"', self.html)

    def test_every_dispatch_name_is_a_real_function(self):
        """The dispatcher looks the name up on `window`, so a typo is an
        undefined global that dies silently in a branch nobody exercises —
        which is why this checks the definition, not just the attribute. The
        per-row actions are wired from the JS-built tbody, not static markup."""
        both = self.html + self.js
        for fn in ("openTrapRuleCreate", "editTrapRule", "deleteTrapRule",
                   "saveTrapRule", "testTrapRule"):
            with self.subTest(fn=fn):
                self.assertIn(f'data-action="{fn}"', both)
                self.assertRegex(self.js, rf"\bfunction {fn}\s*\(")

    def test_it_loads_with_the_tab(self):
        body = self.js[self.js.index("async function loadIntegrationsTab("):]
        body = body[:body.index("\n}\n")]
        self.assertIn("loadTrapRules()", body)

    def test_the_dry_run_is_reachable_from_the_pane(self):
        self.assertIn('id="trap-test-oid"', self.html)
        self.assertIn('data-action="testTrapRule"', self.html)

    def test_the_modal_is_at_body_level(self):
        i = self.html.index('id="trap-rule-modal"')
        self.assertIn("<!-- /app -->", self.html[:i])

    def test_no_inline_handlers_or_styles(self):
        i = self.html.index('id="trap-rules-tbody"')
        seg = self.html[i - 2500:i + 1500]
        self.assertNotIn("onclick", seg)
        self.assertNotIn('style="', seg)


if __name__ == "__main__":
    unittest.main()
