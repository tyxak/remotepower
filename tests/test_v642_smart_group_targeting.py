"""v6.4.2 — a smart group becomes usable as a target, not just as a role scope.

Smart groups are a real dynamic-segment engine: a saved predicate over
group/tag/site/OS/agent-version/monitored/agentless/drift/reboot plus
mem/disk/cpu/swap thresholds, re-materialized every ~60s and referenceable as
`smart:<name>`. It resolved in exactly ONE place — `_device_in_scope` under
`if t == 'groups'` — which covers role scopes, alert routing, service
baselines, report scopes and flat auto-patch scope.

It did not cover the three places an operator actually reaches for a segment:
the Devices page filter chain, the bulk-actions modal, and the rollout ring
resolver (`_rollout_resolve_ring`, whose own selector vocabulary was
ids/group/tag). So an operator who defines `smart:needs-reboot` = agents
reporting reboot_required — precisely the set a staged reboot rollout exists
for — could not stage it. They had to open Sites, click "View members", read
~60 hostnames out of a **toast that auto-dismissed while they were reading
it**, and paste them into an `ids` ring that caps at 500 and freezes the set at
creation time.
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
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-sg-targeting-"))

_spec = importlib.util.spec_from_file_location("api_sgt", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_JS = ROOT / "server" / "html" / "static" / "js"
_HTML = ROOT / "server" / "html" / "index.html"

_DEVICES = {
    "web1": {"name": "web1", "group": "web", "sysinfo": {"reboot_required": True}},
    "web2": {"name": "web2", "group": "web", "sysinfo": {}},
    "db1":  {"name": "db1",  "group": "db",  "sysinfo": {"reboot_required": True}},
    "sw1":  {"name": "sw1",  "agentless": True, "sysinfo": {"reboot_required": True}},
}


class _Base(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for attr in ("DEVICES_FILE", "SMART_GROUPS_FILE", "ROLLOUTS_FILE",
                     "CONFIG_FILE"):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in
                      ("require_auth", "require_admin_auth", "verify_token",
                       "get_token_from_request", "audit_log", "fire_webhook",
                       "respond", "method", "get_json_body", "_env")}
        api.require_auth = lambda require_admin=False: "jakob"
        api.require_admin_auth = lambda: "jakob"
        api.verify_token = lambda t: ("jakob", "admin")
        api.get_token_from_request = lambda: "t"
        api.audit_log = lambda *a, **k: None
        api.fire_webhook = lambda *a, **k: None
        self._qs = ""
        _real_env = self._orig["_env"]
        api._env = lambda k, d="": (self._qs if k == "QUERY_STRING"
                                    else _real_env(k, d))

        def _resp(s, b=None):
            self.cap["s"], self.cap["b"] = s, b
            raise api.HTTPError(s, b)
        api.respond = _resp
        api.save(api.DEVICES_FILE, dict(_DEVICES))
        api.save(api.SMART_GROUPS_FILE, {
            "needs-reboot": {"rules": {"reboot_required": True},
                             # deliberately STALE: the last materialization ran
                             # before db1 and sw1 needed a reboot.
                             "members": ["web1"],
                             "tenant": api.DEFAULT_TENANT, "evaluated_ts": 111},
            "web-tier": {"rules": {"group": "web"}, "members": ["web1", "web2"],
                         "tenant": api.DEFAULT_TENANT, "evaluated_ts": 111},
        })
        api._invalidate_load_cache(api.DEVICES_FILE)
        api._invalidate_load_cache(api.SMART_GROUPS_FILE)

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


class TestLiveResolution(_Base):
    def test_the_helper_matches_device_in_scope(self):
        """Two answers to "is this host in smart:x?" that could drift apart is
        exactly the two-registry shape that keeps biting this codebase, so the
        list form has to agree with the scope form host by host."""
        ids = api._smart_group_device_ids("needs-reboot", _DEVICES)
        scope = {"type": "groups", "values": ["smart:needs-reboot"]}
        for did, dev in _DEVICES.items():
            with self.subTest(device=did):
                self.assertEqual(did in ids, api._device_in_scope(scope, dev))

    def test_it_resolves_live_not_from_the_stored_member_list(self):
        """The stored list is up to SMART_GROUP_INTERVAL (60s) stale. A ring
        resolved off it dispatches to a host that no longer matches, and skips
        one that just started to."""
        stored = (api.load(api.SMART_GROUPS_FILE)["needs-reboot"])["members"]
        self.assertEqual(stored, ["web1"])
        self.assertEqual(api._smart_group_device_ids("needs-reboot", _DEVICES),
                         ["db1", "sw1", "web1"])

    def test_an_unknown_group_targets_nothing(self):
        """A deleted smart group must resolve to zero hosts, never to the whole
        fleet — an empty predicate ANDs to "everything"."""
        self.assertEqual(api._smart_group_device_ids("deleted", _DEVICES), [])
        self.assertEqual(api._smart_group_device_ids("", _DEVICES), [])
        self.assertEqual(api._smart_group_device_ids(None, _DEVICES), [])

    def test_it_matches_over_the_dict_it_is_given(self):
        """A ring resolves against a device dict the caller already scope- and
        tenant-filtered. Matching over that dict keeps the caller's narrower
        boundary; reading the stored members list would widen it back out to
        whatever the group was materialized against."""
        narrowed = {"web1": _DEVICES["web1"]}
        self.assertEqual(api._smart_group_device_ids("needs-reboot", narrowed),
                         ["web1"])


class TestRolloutRings(_Base):
    def test_a_smart_ring_resolves(self):
        self.assertEqual(
            api._rollout_resolve_ring({"type": "smart", "value": "needs-reboot"},
                                      _DEVICES),
            ["db1", "sw1", "web1"])

    def test_the_other_selectors_still_work(self):
        self.assertEqual(
            api._rollout_resolve_ring({"type": "group", "value": "web"}, _DEVICES),
            ["web1", "web2"])
        self.assertEqual(
            api._rollout_resolve_ring({"type": "ids", "ids": ["db1"]}, _DEVICES),
            ["db1"])

    def test_create_accepts_a_smart_ring(self):
        api.method = lambda: "POST"
        api.get_json_body = lambda: {
            "name": "reboot wave", "action": "reboot",
            "rings": [{"name": "w1",
                       "selector": {"type": "smart", "value": "needs-reboot"}}]}
        r = self.call(api.handle_rollouts_create)
        self.assertTrue(r and r.get("ok"), r)
        sel = r["rollout"]["rings"][0]["selector"]
        self.assertEqual(sel, {"type": "smart", "value": "needs-reboot"})

    def test_an_unknown_selector_type_is_still_rejected(self):
        api.method = lambda: "POST"
        api.get_json_body = lambda: {
            "name": "x", "action": "reboot",
            "rings": [{"selector": {"type": "everything", "value": "*"}}]}
        self.call(api.handle_rollouts_create)
        self.assertEqual(self.cap["s"], 400)

    def test_the_reboot_planner_accepts_it_too(self):
        """The rolling-reboot planner is the single most obvious consumer:
        `smart:needs-reboot` is literally the set it plans waves over."""
        api.method = lambda: "POST"
        api.get_json_body = lambda: {
            "scope": {"type": "smart", "value": "needs-reboot"}}
        r = self.call(api.handle_reboot_plan)
        self.assertTrue(r, self.cap)
        # sw1 is agentless — the planner drops it, as it does for every scope type
        self.assertEqual(r["device_count"], 2)
        self.assertEqual(sorted(sum((w["selector"]["ids"] for w in r["rings"]), [])),
                         ["db1", "web1"])

    def test_the_error_message_lists_the_types_it_accepts(self):
        api.method = lambda: "POST"
        api.get_json_body = lambda: {"scope": {"type": "nope"}}
        self.call(api.handle_reboot_plan)
        self.assertIn("smart", self.cap["b"]["error"])


class TestMembersPayload(_Base):
    def test_members_are_opt_in(self):
        api.method = lambda: "GET"
        self._qs = ""
        r = self.call(api.handle_smart_groups)
        self.assertNotIn("members", r["smart_groups"][0])
        self.assertIn("member_count", r["smart_groups"][0])

    def test_members_1_includes_the_ids(self):
        api.method = lambda: "GET"
        self._qs = "members=1"
        r = self.call(api.handle_smart_groups)
        by = {g["name"]: g for g in r["smart_groups"]}
        self.assertEqual(by["web-tier"]["members"], ["web1", "web2"])
        self.assertEqual(by["web-tier"]["member_count"], 2)

    def test_it_stays_admin_only(self):
        """Every smart-group endpoint is require_admin_auth; adding the member
        ids must not have opened a new read path."""
        seen = []
        api.require_admin_auth = lambda: (seen.append(1), "jakob")[1]
        api.method = lambda: "GET"
        self._qs = "members=1"
        self.call(api.handle_smart_groups)
        self.assertEqual(len(seen), 1)


class TestClientWiring(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not _HTML.exists():
            raise unittest.SkipTest("excluded from this tree")
        cls.html = _HTML.read_text()
        cls.app = (_JS / "app.js").read_text()

    def test_the_devices_page_has_a_smart_group_filter(self):
        self.assertIn('id="device-smart-filter"', self.html)
        self.assertIn("_smartGroupMembers", self.app)

    def test_the_filter_uses_server_membership_not_a_second_predicate(self):
        """Re-implementing `_smart_group_match` in JS would be a second copy of
        the matching rules — the drift class this codebase keeps hitting. The
        client asks the server which hosts are members."""
        self.assertIn("/smart-groups?members=1", self.app)
        # The filter is a set-membership test against ids the server resolved,
        # not a rule evaluation. `_fillSmartGroupForm`/`saveSmartGroup` do name
        # the facets — that is the EDITOR building a rule set, which is fine;
        # what must not exist is a second matcher.
        i = self.app.index("const smartFilter =")
        seg = self.app[i:i + 400]
        self.assertIn("_smartGroupMembers.get(", seg)
        self.assertIn(".has(d.id)", seg)
        for facet in ("agent_version_contains", "tags_all", "tags_any",
                      "group_in", "mem_gt"):
            with self.subTest(facet=facet):
                self.assertNotIn(facet, seg, "the smart-group predicate is "
                                             "being reimplemented client-side")

    def test_clearing_filters_clears_it(self):
        body = self.app[self.app.index("function clearDeviceFilters("):]
        body = body[:body.index("\n}\n")]
        self.assertIn("device-smart-filter", body)

    def test_a_saved_view_captures_it(self):
        i = self.app.index("const _VIEW_PAGES")
        self.assertIn("device-smart-filter", self.app[i:i + 900])

    def test_bulk_actions_can_target_one(self):
        body = self.app[self.app.index("function _bulkResolveTargets("):]
        body = body[:body.index("\n}\n")]
        self.assertIn("smart:", body)
        self.assertIn("_smartGroupMembers", body)

    def test_bulk_actions_loads_them_before_building_the_modal(self):
        """The modal is one template string built once, and the palette can open
        it without Devices ever having rendered — so the fetch has to be awaited
        first or the smart rows are silently missing."""
        body = self.app[self.app.index("async function openBulkActions("):]
        body = body[:body.index("\n}\n")]
        self.assertIn("await _ensureSmartGroups()", body)

    def test_the_ring_picker_offers_it(self):
        self.assertEqual(self.html.count('<option value="smart">smart group</option>'), 3,
                         "all three ring rows need the option")
        self.assertIn('<option value="smart">Smart group</option>', self.html,
                      "the rolling-reboot scope picker needs it too")

    def test_the_ring_builder_passes_it_through_unchanged(self):
        """`ids` is the only selector needing special shaping; everything else
        is {type, value}, so `smart` needed no JS change — pin that."""
        js = (_JS / "app-rollouts.js").read_text()
        self.assertIn("{ type, value }", js)

    def test_members_render_as_a_list_not_a_toast(self):
        body = self.app[self.app.index("async function viewSmartGroupMembers("):]
        body = body[:body.index("\n}\n")]
        code = re.sub(r"^\s*//.*$", "", body, flags=re.M)
        self.assertIn("sg-members-modal", code)
        self.assertIn("openDeviceDrawer", code,
                      "a member list you cannot click through from is a "
                      "read-only wall of hostnames")
        # The old shape: join every member name and hand the string to a toast.
        # A single toast naming the group (the no-modal fallback) is fine; the
        # LIST going into one is what auto-dismissed mid-read.
        self.assertNotIn(".join(', ')", code)
        self.assertNotIn("m => m.name", code)

    def test_the_members_modal_exists_and_is_capped(self):
        self.assertIn('id="sg-members-modal"', self.html)
        i = self.html.index('id="sg-members-body"')
        self.assertIn("scroll-cap", self.html[i:i + 120],
                      "a 500-member group would grow the modal unbounded")

    def test_the_modal_is_at_body_level(self):
        """A fixed full-screen overlay nested in .container is sealed under the
        sidebar's stacking context (the v4.10.0 drawer bug)."""
        i = self.html.index('id="sg-members-modal"')
        self.assertIn("<!-- /app -->", self.html[:i])

    def test_the_empty_state_names_the_new_filter(self):
        self.assertIn("smart-group filters", self.app,
                      "the no-match empty state lists the filters that could "
                      "be responsible; leaving one out sends the operator "
                      "hunting the wrong control")


if __name__ == "__main__":
    unittest.main()
