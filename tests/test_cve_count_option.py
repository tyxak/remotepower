"""The CVE count option (the #57 follow-up): the numbers an operator reads can leave out a finding no update can clear.

Six places count CVE findings into a number: the sidebar badge, the severity tiles of the dashboard and of the CVE
page, Needs attention, the risk score and Checks. With `cve_count_fixable_only` on they count only a finding an
update can clear and one on the known-exploited list; with it off they count every finding that is not accepted as a
risk, as before. Two of them (the badge and Checks) used to count accepted risks too.

Every counter is driven for real, on a seeded two-host fleet, with the option off and with it on.
"""
import importlib.util
import json
import os
import re
import sys
import tempfile
import time
import unittest
import urllib.parse
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-cve-count-"))

ROOT = Path(__file__).resolve().parent.parent
CGI = ROOT / "server" / "cgi-bin"
HTML = ROOT / "server" / "html"
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(CGI))

import cve_fixes  # noqa: E402

NOW = int(time.time())


def finding(vid, sev, status, fixed=""):
    return {"vuln_id": vid, "severity": sev, "package": "pkg", "version": "1.0",
            "fixed_version": fixed, "fix_status": status, "aliases": []}


# web01 carries every case. db01 carries only findings that no update can clear and that nobody exploits.
WEB01 = [
    finding("CVE-2026-0001", "critical", "none"),
    finding("CVE-2026-0002", "critical", "newer_release"),
    finding("CVE-2026-0003", "critical", "fixed", "1.2-3"),
    finding("CVE-2026-0004", "critical", "none"),            # on the known-exploited list
    finding("CVE-2026-0005", "critical", "none"),            # accepted as a risk
    finding("CVE-2026-0006", "high", "none"),
    finding("CVE-2026-0007", "high", "fixed", "2.0-1"),
    finding("CVE-2026-0008", "medium", "none"),
    finding("CVE-2026-0009", "medium", "none"),              # on the known-exploited list
]
DB01 = [
    finding("CVE-2026-0101", "critical", "none"),
    finding("CVE-2026-0102", "high", "newer_release"),
]
KEV = ["CVE-2026-0004", "CVE-2026-0009"]
ACCEPTED = {"CVE-2026-0005": {"scope": "global", "reason": "accepted in the test"}}


def _fresh_api():
    d = tempfile.mkdtemp(prefix="rp-cve-count-")
    os.environ["RP_DATA_DIR"] = d
    spec = importlib.util.spec_from_file_location("api_cve_count", CGI / "api.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.require_auth = lambda *a, **k: "admin"
    mod._env = lambda k, d="": ""
    return mod


def _call(api, fn, *a):
    try:
        fn(*a)
    except api.HTTPError as e:
        return e.body
    raise AssertionError(f"{fn.__name__} did not respond")


class _Fleet(unittest.TestCase):
    """Seeds the fleet once per class. The counters only read, so the tests of a class share it."""

    OPTION = False

    @classmethod
    def setUpClass(cls):
        api = cls.api = _fresh_api()
        dev = {"monitored": True, "last_seen": NOW, "sysinfo": {}}
        api.save(api.DEVICES_FILE, {"h1": dict(dev, name="web01"), "h2": dict(dev, name="db01")})
        api.save(api.CVE_FINDINGS_FILE, {"h1": {"scanned_at": NOW, "findings": WEB01},
                                         "h2": {"scanned_at": NOW, "findings": DB01}})
        api.save(api.CVE_IGNORE_FILE, ACCEPTED)
        api.save(api.KEV_EPSS_FILE, {"kev": KEV, "epss": {}, "last_checked": NOW})
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg["cve_count_fixable_only"] = cls.OPTION
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()

    # the six counters, each as the operator reads it
    def badge(self):
        return _call(self.api, self.api.handle_nav_counts)["security"]

    def page(self):
        return _call(self.api, self.api.handle_cve_findings)

    def tile(self):
        rows = _call(self.api, self.api.handle_home)["cves"]["devices"]
        return {r["device_id"]: r["counts"] for r in rows}

    def checks(self):
        return self.api._cve_high_counts()

    def attention(self):
        return {i["device"]: i["summary"] for i in self.api._compute_attention() if i["kind"] == "cve"}

    def risk(self, dev_id):
        row = next(r for r in self.api._compute_fleet_risk() if r["device_id"] == dev_id)
        return {f["kind"]: f["detail"] for f in row["factors"] if f["kind"].startswith("cve")}


class TestOptionOff(_Fleet):
    """Every finding that is not accepted as a risk counts, as it always did."""

    OPTION = False

    def test_the_badge_counts_the_critical_findings_that_are_not_accepted(self):
        # 4 on web01 (0001 to 0004) and 1 on db01. It said 6 before the accepted risk was left out.
        self.assertEqual(self.badge(), 5)

    def test_the_cve_page_counts_the_same_findings(self):
        s = self.page()["summary"]
        self.assertEqual((s["critical"], s["high"], s["medium"], s["ignored"]), (5, 3, 2, 1))
        self.assertEqual(s["devices_with_findings"], 2)

    def test_the_page_says_it_counts_everything(self):
        self.assertEqual(self.page()["counting"], "all")

    def test_the_dashboard_tile_agrees_with_the_page(self):
        t = self.tile()
        self.assertEqual(t["h1"], {"critical": 4, "high": 2, "medium": 2, "low": 0})
        self.assertEqual(t["h2"], {"critical": 1, "high": 1, "medium": 0, "low": 0})

    def test_checks_count_critical_and_high_without_the_accepted_risk(self):
        # web01: 4 critical + 2 high. It said 7 before the accepted risk was left out.
        self.assertEqual(self.checks(), {"h1": 6, "h2": 2})

    def test_needs_attention_lists_both_hosts(self):
        self.assertEqual(self.attention(), {"web01": "4 critical CVEs · 2 fixable", "db01": "1 critical CVE"})

    def test_the_risk_score_counts_what_the_page_counts(self):
        r = self.risk("h1")
        self.assertEqual((r["cve_critical"], r["cve_high"]), ("4 critical CVEs", "2 high CVEs"))
        self.assertIn("cve_kev", r)


class TestOptionOn(_Fleet):
    """Only a finding an update can clear counts, and one on the known-exploited list, whatever its fix status."""

    OPTION = True

    def test_the_badge_counts_one_fixable_and_one_exploited_critical(self):
        self.assertEqual(self.badge(), 2)

    def test_the_cve_page_totals_follow_the_option(self):
        s = self.page()["summary"]
        self.assertEqual((s["critical"], s["high"], s["medium"]), (2, 1, 1))

    def test_a_host_with_nothing_left_is_not_a_host_with_findings(self):
        self.assertEqual(self.page()["summary"]["devices_with_findings"], 1)

    def test_the_fix_tiles_and_the_accepted_count_still_cover_every_finding(self):
        """The tiles are how an operator finds what was left out, so they must not follow the option."""
        s = self.page()["summary"]
        self.assertEqual(s["fix"], {"fixable": 2, "newer_release": 2, "none": 6, "unchecked": 0})
        self.assertEqual(s["ignored"], 1)

    def test_each_host_row_follows_the_option(self):
        rows = {d["device_id"]: d["counts"] for d in self.page()["devices"]}
        self.assertEqual((rows["h1"]["critical"], rows["h1"]["high"], rows["h1"]["medium"]), (2, 1, 1))
        self.assertEqual((rows["h2"]["critical"], rows["h2"]["high"]), (0, 0))

    def test_the_page_says_what_it_counts(self):
        self.assertEqual(self.page()["counting"], "fixable_only")

    def test_the_dashboard_tile_agrees_with_the_page(self):
        t = self.tile()
        self.assertEqual(t["h1"], {"critical": 2, "high": 1, "medium": 1, "low": 0})
        self.assertEqual(t["h2"], {"critical": 0, "high": 0, "medium": 0, "low": 0})

    def test_checks_count_the_same_findings(self):
        self.assertEqual(self.checks(), {"h1": 3, "h2": 0})

    def test_needs_attention_drops_a_host_with_nothing_left(self):
        self.assertEqual(self.attention(), {"web01": "2 critical CVEs · 2 fixable"})

    def test_the_risk_score_drops_what_no_update_clears_and_keeps_the_exploited(self):
        r = self.risk("h1")
        self.assertEqual((r["cve_critical"], r["cve_high"]), ("2 critical CVEs", "1 high CVE"))
        self.assertIn("2 CVEs on CISA KEV", r["cve_kev"])
        self.assertEqual(self.risk("h2"), {})


class _FleetWithMoreHosts(_Fleet):
    """web01 and db01 as above, plus lab01, a host nobody monitors that carries two critical findings an update clears,
    and kiosk01, whose record has no `monitored` key (a host is monitored until it is switched off) and one more."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        api = cls.api
        devs = api.load(api.DEVICES_FILE)
        base = {"last_seen": NOW, "sysinfo": {}}
        devs["h3"] = dict(base, name="lab01", monitored=False)
        devs["h4"] = dict(base, name="kiosk01")
        api.save(api.DEVICES_FILE, devs)
        found = api.load(api.CVE_FINDINGS_FILE)
        found["h3"] = {"scanned_at": NOW, "findings": [finding("CVE-2026-0201", "critical", "fixed", "1.0-2"),
                                                       finding("CVE-2026-0202", "critical", "fixed", "1.0-3")]}
        found["h4"] = {"scanned_at": NOW, "findings": [finding("CVE-2026-0301", "critical", "fixed", "3.0-1")]}
        api.save(api.CVE_FINDINGS_FILE, found)
        api._LOAD_CACHE.clear()


class TestTheBadgeLeavesOutUnmonitoredHosts(_FleetWithMoreHosts):
    """The badge says "critical CVE findings on monitored hosts", and Needs attention skips an unmonitored host: a host
    nobody watches is silent by choice. The CVE page and the dashboard tile still list it, so it can be found."""

    OPTION = False

    def test_the_badge_counts_monitored_hosts_and_a_host_with_no_flag(self):
        # web01 4 + db01 1 + kiosk01 1. lab01's two do not count. It said 8 before.
        self.assertEqual(self.badge(), 6)

    def test_the_cve_page_still_lists_the_unmonitored_host(self):
        s = self.page()["summary"]
        self.assertEqual((s["critical"], s["devices_with_findings"]), (8, 4))

    def test_the_dashboard_tile_still_lists_it(self):
        self.assertEqual(self.tile()["h3"]["critical"], 2)

    def test_needs_attention_and_the_badge_agree_about_who_counts(self):
        self.assertNotIn("lab01", self.attention())
        self.assertIn("kiosk01", self.attention())


class TestTheDigestAndTheFleetQuerySayWhatTheDashboardSays(_Fleet):
    """The scheduled digest and the Fleet query's CVE filter and column were two of the five readers that counted
    accepted risks. They are numbers an operator reads, so they follow the same rule as the six counters."""

    OPTION = False

    def digest(self):
        subject, body = self.api._build_posture_digest()
        m = re.search(r"CVEs critical/high: (\d+) / (\d+)", body)
        return int(m.group(1)), int(m.group(2)), subject

    def query(self, **params):
        self.api._env = lambda k, d="": urllib.parse.urlencode(params) if k == "QUERY_STRING" else ""
        return _call(self.api, self.api.handle_fleet_query)["devices"]

    def test_the_digest_leaves_out_the_accepted_risk(self):
        crit, high, subject = self.digest()
        # web01 4 + db01 1 critical, web01 2 + db01 1 high. It said 6 critical before.
        self.assertEqual((crit, high), (5, 3))
        self.assertIn("5 critical CVEs", subject)

    def test_the_fleet_query_counts_the_same_findings_as_checks(self):
        got = {r["name"]: r["cve_high"] for r in self.query(cve_min="1")}
        self.assertEqual(got, {"web01": 6, "db01": 2})          # web01 said 7 before
        self.assertEqual(got["web01"], self.checks()["h1"])

    def test_the_filter_uses_that_count(self):
        self.assertEqual([r["name"] for r in self.query(cve_min="6")], ["web01"])

    def test_a_query_that_asks_for_no_cve_count_pays_for_none(self):
        self.assertEqual({r["cve_high"] for r in self.query()}, {None})


class TestTheDigestAndTheFleetQueryFollowTheOption(TestTheDigestAndTheFleetQuerySayWhatTheDashboardSays):
    OPTION = True

    def test_the_digest_leaves_out_the_accepted_risk(self):
        crit, high, subject = self.digest()
        self.assertEqual((crit, high), (2, 1))
        self.assertIn("2 critical CVEs", subject)

    def test_the_fleet_query_counts_the_same_findings_as_checks(self):
        got = {r["name"]: r["cve_high"] for r in self.query(cve_min="1")}
        self.assertEqual(got, {"web01": 3})                   # db01 has nothing an update clears
        self.assertEqual(got["web01"], self.checks()["h1"])

    def test_the_filter_uses_that_count(self):
        self.assertEqual([r["name"] for r in self.query(cve_min="3")], ["web01"])
        self.assertEqual(self.query(cve_min="4"), [])


class TestTheDigestCountsMonitoredHostsOnly(_FleetWithMoreHosts):
    """Its own host line says "Hosts monitored", and the badge counts those hosts."""

    OPTION = False

    def test_an_unmonitored_host_is_not_in_the_digest(self):
        subject, body = self.api._build_posture_digest()
        m = re.search(r"CVEs critical/high: (\d+) / (\d+)", body)
        # web01 4 + db01 1 + kiosk01 1 critical. lab01's two are not in it. It said 8 before.
        self.assertEqual((int(m.group(1)), int(m.group(2))), (6, 3))
        self.assertEqual(int(m.group(1)), self.badge())


class TestTheRule(unittest.TestCase):
    """cve_fixes.counted, the one rule the counters and the alert option share."""

    FIXED = finding("CVE-1", "critical", "fixed", "1.0-1")
    NEWER = finding("CVE-2", "critical", "newer_release")
    NONE = finding("CVE-3", "critical", "none")

    def test_with_the_option_off_everything_counts(self):
        for f in (self.FIXED, self.NEWER, self.NONE, {}, {"vuln_id": "x"}):
            self.assertTrue(cve_fixes.counted(f, False, None))

    def test_with_the_option_on_only_a_fixable_finding_counts(self):
        self.assertTrue(cve_fixes.counted(self.FIXED, True, None))
        self.assertFalse(cve_fixes.counted(self.NEWER, True, None))
        self.assertFalse(cve_fixes.counted(self.NONE, True, None))

    def test_a_known_exploited_finding_counts_whatever_its_status(self):
        self.assertTrue(cve_fixes.counted(self.NONE, True, {"CVE-3"}))
        self.assertTrue(cve_fixes.counted(self.NEWER, True, {"CVE-2"}))

    def test_an_alias_is_enough_to_be_known_exploited(self):
        f = dict(self.NONE, aliases=["cve-2020-1111"])
        self.assertTrue(cve_fixes.counted(f, True, {"CVE-2020-1111"}))

    def test_a_finding_stamped_as_exploited_counts_without_a_lookup(self):
        self.assertTrue(cve_fixes.counted(dict(self.NONE, kev=True), True, None))
        self.assertFalse(cve_fixes.counted(dict(self.NONE, kev=False), True, None))

    def test_a_finding_scanned_before_the_status_existed_counts_by_its_fixed_version(self):
        self.assertTrue(cve_fixes.counted({"vuln_id": "a", "fixed_version": "3.1"}, True, None))
        self.assertFalse(cve_fixes.counted({"vuln_id": "a", "fixed_version": ""}, True, None))

    def test_a_row_that_is_not_a_finding_does_not_count_when_the_option_is_on(self):
        for junk in (None, "CVE-1", 7, [], ["x"]):
            self.assertFalse(cve_fixes.counted(junk, True, None))

    def test_the_alert_option_leaves_out_exactly_what_the_count_option_leaves_out(self):
        """One rule for both. They are separate switches, but they must never disagree on a finding."""
        kevs = (None, set(), {"CVE-3"}, {"CVE-2", "CVE-3"})
        for f in (self.FIXED, self.NEWER, self.NONE, dict(self.NONE, kev=True), {}, None, "x"):
            for on in (False, True):
                for kev in kevs:
                    self.assertEqual(cve_fixes.alert_candidate(f, on, kev), cve_fixes.counted(f, on, kev),
                                     (f, on, kev))


class TestTheSetting(unittest.TestCase):
    """The switch is saved, read back and reported by the real config handlers, and takes only true or false."""

    def setUp(self):
        self.api = api = _fresh_api()
        self.cap = {}
        api.require_admin_auth = lambda: "jakob"
        api.verify_token = lambda t: ("jakob", "admin")
        api.audit_log = lambda *a, **k: None
        api.fire_webhook = lambda *a, **k: None
        api.method = lambda: "POST"

        def _resp(s, b=None):
            self.cap["s"], self.cap["b"] = s, b
            raise api.HTTPError(s, b)
        api.respond = _resp

    def save(self, value):
        api = self.api
        self.cap.clear()
        api.get_json_obj = lambda: {"cve_count_fixable_only": value}
        api.get_json_body = lambda: {"cve_count_fixable_only": value}
        try:
            api.handle_config_save()
        except api.HTTPError:
            pass
        api._invalidate_load_cache(api.CONFIG_FILE)
        api._LOAD_CACHE.clear()
        return self.cap.get("s")

    def test_it_is_off_until_someone_turns_it_on(self):
        self.assertIs(self.api.get_cve_count_fixable_only(), False)

    def test_a_real_true_or_false_is_saved_and_read_back(self):
        self.assertEqual(self.save(True), 200)
        self.assertIs(self.api.get_cve_count_fixable_only(), True)
        self.assertEqual(self.save(False), 200)
        self.assertIs(self.api.get_cve_count_fixable_only(), False)

    def test_a_string_that_reads_like_false_does_not_turn_it_on(self):
        """bool("false") is True. The switch hides findings from the score, so a client that meant off must not
        turn it on, and a client that sends junk must not change it."""
        for value in ("false", "0", "no", "", "True", 1, 0, 2.5, None, [], {"a": 1}):
            self.assertEqual(self.save(value), 400, repr(value))
            self.assertIs(self.api.get_cve_count_fixable_only(), False, repr(value))
            self.assertEqual(self.cap["b"], {"error": "cve_count_fixable_only must be true or false"})

    def read_config(self):
        api = self.api
        self.cap.clear()
        try:
            api.handle_config_get()
        except api.HTTPError:
            pass
        return self.cap["b"]

    def test_the_config_the_dashboard_reads_carries_the_switch(self):
        self.assertEqual(self.save(True), 200)
        self.assertIs(self.read_config()["cve_count_fixable_only"], True)

    def test_a_fresh_install_reports_it_off(self):
        self.assertIs(self.read_config()["cve_count_fixable_only"], False)

    def test_the_request_model_accepts_the_key(self):
        import request_models as rm
        ok, err = rm.validate(rm.ConfigSaveRequest, {"cve_count_fixable_only": True})
        self.assertTrue(ok, err)


class TestAcceptingARiskMovesTheBadgeAtOnce(unittest.TestCase):
    """The sidebar badge is cached for 15 seconds. A scan busts the cache; accepting a risk must too."""

    def test_the_badge_does_not_wait_for_its_cache(self):
        api = _fresh_api()
        api.save(api.DEVICES_FILE, {"h1": {"name": "web01", "monitored": True, "last_seen": NOW, "sysinfo": {}}})
        api.save(api.CVE_FINDINGS_FILE, {"h1": {"scanned_at": NOW, "findings": WEB01}})
        before = _call(api, api.handle_nav_counts)["security"]
        time.sleep(1.1)     # the SQLite backend stamps a row to the second
        api.save(api.CVE_IGNORE_FILE, {"CVE-2026-0001": {"scope": "global", "reason": "accepted in the test"}})
        api._LOAD_CACHE.clear()
        self.assertEqual(_call(api, api.handle_nav_counts)["security"], before - 1)


class TestTheChecksCacheKey(unittest.TestCase):
    """Checks are cached for 15 seconds. Flipping the option, or accepting a risk, must not wait for that."""

    def test_the_key_changes_with_the_option_and_with_the_accepted_risks(self):
        api = _fresh_api()
        base = api._fleet_checks_fp({}, [])
        self.assertEqual(base, api._fleet_checks_fp({}, []))
        self.assertNotEqual(base, api._fleet_checks_fp({"cve_count_fixable_only": True}, []))
        api.save(api.CVE_IGNORE_FILE, ACCEPTED)
        self.assertNotEqual(base, api._fleet_checks_fp({}, []))


class TestTheScreens(unittest.TestCase):
    """The switch is on the Security pane, travels with the settings form, and the CVE page says when it is on."""

    @classmethod
    def setUpClass(cls):
        cls.index = (HTML / "index.html").read_text()
        cls.app = (HTML / "static" / "js" / "app.js").read_text()
        cls.cve = (HTML / "static" / "js" / "app-cve.js").read_text()

    def test_the_checkbox_is_on_the_security_pane(self):
        pane = self.index[self.index.index('id="settings-pane-security"'):]
        pane = pane[:pane.index('id="settings-pane-', 40)] if 'id="settings-pane-' in pane[40:] else pane
        self.assertIn('id="cfg-cve-count-fixable-only"', pane)

    def test_the_settings_form_loads_and_saves_it(self):
        self.assertIn("getElementById('cfg-cve-count-fixable-only')", self.app)
        self.assertIn("data.cve_count_fixable_only === true", self.app)
        self.assertIn("cve_count_fixable_only: (document.getElementById('cfg-cve-count-fixable-only') || {}).checked === true", self.app)

    def test_the_cve_page_shows_its_note_only_when_the_option_is_on(self):
        self.assertRegex(self.index, r'id="cve-count-note"[^>]*\bhidden\b')
        self.assertIn("countNote.hidden = data.counting !== 'fixable_only'", self.cve)

    def test_every_new_sentence_is_translated_into_the_six_languages(self):
        text = (HTML / "static" / "js" / "i18n.js").read_text()
        keys = [
            "CVE counts",
            "Count only CVEs an update can fix, or that are known to be exploited",
            "The alert option is separate. It sits beside the severities of cve_found in Settings → Notifications.",
            "Counting only CVEs an update can fix, or that are known to be exploited. The severity totals leave out the others; change this in Settings → Security.",
            "cve_count_fixable_only must be true or false",
        ]
        for k in keys:
            start = text.index(json.dumps(k, ensure_ascii=False) + ":")
            entry = text[start:text.index("\n", start)]
            for lang in ("fr", "de", "zh", "hi", "es", "ar"):
                self.assertIn(f'"{lang}": "', entry, f"{k!r} has no {lang}")
        # the long hint is keyed on the sentence the page shows
        hint = [ln for ln in text.splitlines() if ln.lstrip().startswith('"The sidebar badge, the severity totals,')]
        self.assertEqual(len(hint), 1)
        self.assertIn(hint[0].strip().split('":')[0].strip('"'), self.index)
        for lang in ("fr", "de", "zh", "hi", "es", "ar"):
            self.assertIn(f'"{lang}": "', hint[0])


if __name__ == "__main__":
    unittest.main()
