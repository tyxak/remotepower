#!/usr/bin/env python3
"""8.0.0: the backup monitor form has a tool, editing a monitor keeps what the form does not show, and a refused save leaves the list alone.

A backup monitor has a tool (restic, borg, tar or auto) and two cadences (how often the integrity check and the restore drill run; weekly when unset). Auto only guesses from the
NAME of the path (restic, borg or a tar file name in it) and finds nothing for any other name, so a monitor on a path that says nothing could not be verified unless the API set its
tool, and the form had no field for it. It has one now. The two cadences are still API-only, and editing a monitor built a fresh entry from the form, so both went back to weekly with a
success toast. And the list in the page was changed before the server answered, so a refused save stayed in it and rode into the next one. Found by the survey of settings no page
names (restore_drill_max_age_hours, verify_max_age_hours): the page that edits them could only reset them.

Runs on an empty install. Self-skips without playwright / Chromium / gunicorn, and runs under the default storage backend only.
"""
import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import browser_required  # noqa: E402
from e2e_harness import SKIP_REASON, browser_available  # noqa: E402

_GATE = browser_available() or browser_required.required()

try:
    from playwright.sync_api import sync_playwright
except ImportError:                                     # pragma: no cover
    sync_playwright = None

_STATE = {}


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("the form is backend-agnostic: measured once, under the default backend")
    from e2e_harness import start_stack
    pw = sync_playwright().start()
    try:
        browser = pw.chromium.launch()
    except Exception as exc:
        pw.stop()
        browser_required.skip_or_fail("chromium not available: %s" % exc)
        return
    try:
        base, shutdown = start_stack()
    except Exception as exc:
        browser.close()
        pw.stop()
        raise unittest.SkipTest("app stack not available: %s" % exc)
    _STATE.update(pw=pw, browser=browser, base=base, shutdown=shutdown)


def tearDownModule():
    try:
        _STATE["browser"].close()
        _STATE["pw"].stop()
    finally:
        if _STATE.get("shutdown"):
            _STATE["shutdown"]()


API_ONLY = {"path": "/srv/backups/db", "label": "DB dump", "max_age_hours": 12, "tool": "borg", "verify_enabled": True, "verify_max_age_hours": 48,
            "restore_drill_enabled": False, "restore_sample_path": "", "restore_drill_max_age_hours": 72}
OTHER = {"path": "/srv/backups/files", "label": "Files", "max_age_hours": 24, "tool": "restic", "verify_enabled": False, "verify_max_age_hours": 24,
         "restore_drill_enabled": False, "restore_sample_path": "", "restore_drill_max_age_hours": 96}


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestEditingABackupMonitor(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        ctx = _STATE["browser"].new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
        ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")
        cls.ctx, cls.page, cls.errors = ctx, ctx.new_page(), []
        cls.page.on("pageerror", lambda e: cls.errors.append(str(e)))
        cls.page.goto(_STATE["base"] + "/index.html")
        cls.page.fill("#login-user", "admin")                # a fresh data directory has the one default account
        cls.page.fill("#login-pass", "remotepower")
        cls.page.click('#login-form button[type="submit"]')
        cls.page.wait_for_selector("#app", state="visible", timeout=60000)
        cls.page.evaluate("document.getElementById('tour-backdrop')?.remove(); document.getElementById('tour-pop')?.remove();")
        cls.page.wait_for_timeout(2500)

    @classmethod
    def tearDownClass(cls):
        cls.ctx.close()

    def stored(self):
        return self.page.evaluate("async () => (await api('GET', '/config')).backup_monitors")

    def start_with(self, monitors):
        """The monitors as the API sets them (the page has no field for the tool or the cadences), then Settings opened on the pane that holds the form."""
        r = self.page.evaluate("async (m) => await api('POST', '/config', {backup_monitors: m})", monitors)
        self.assertTrue(r and r.get("ok"), r)
        with self.page.expect_response(lambda x: x.url.endswith("/api/config") and x.request.method == "GET", timeout=60000):
            self.page.evaluate("() => showPage('settings')")
        pane = self.page.evaluate("() => document.getElementById('bm-path').closest('.settings-pane').id.replace('settings-pane-', '')")
        self.page.click("#settings-tab-btn-" + pane)
        self.page.wait_for_function("(n) => document.querySelectorAll('#backup-monitors-list [data-action=\"editBackupMonitor\"]').length === n", arg=len(monitors), timeout=30000)

    def save(self):
        with self.page.expect_response(lambda x: x.url.endswith("/api/config") and x.request.method == "POST", timeout=30000) as info:
            self.page.click('[data-action="addBackupMonitor"]')
        return info.value

    def test_editing_shows_the_tool_keeps_both_cadences_and_changes_what_the_form_shows(self):
        self.start_with([API_ONLY])
        self.page.click('#backup-monitors-list [data-action="editBackupMonitor"]')
        self.assertEqual(self.page.input_value("#bm-tool"), "borg", "the form shows the tool the monitor has")
        self.page.fill("#bm-label", "DB dump (nightly)")
        self.page.fill("#bm-hours", "6")
        self.assertEqual(self.save().status, 200)
        got = self.stored()
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["label"], "DB dump (nightly)")
        self.assertEqual(got[0]["max_age_hours"], 6)
        self.assertEqual(got[0]["tool"], "borg")
        self.assertEqual(got[0]["verify_max_age_hours"], 48, "the form has no field for the cadences, so editing leaves them alone")
        self.assertEqual(got[0]["restore_drill_max_age_hours"], 72)
        self.assertTrue(got[0]["verify_enabled"], "the box the form shows is carried over")
        self.assertEqual(got[0]["path"], "/srv/backups/db")
        self.assertEqual(self.page.input_value("#bm-tool"), "auto", "the form is cleared after a save")

    def test_the_tool_select_sets_the_tool_of_a_new_monitor_and_changes_that_of_an_old_one(self):
        self.start_with([API_ONLY])
        self.page.fill("#bm-path", "/srv/backups/plain-name")
        self.page.fill("#bm-label", "Plain")
        self.page.select_option("#bm-tool", "tar")
        self.assertEqual(self.save().status, 200)
        got = self.stored()
        self.assertEqual([(m["label"], m["tool"]) for m in got], [("DB dump", "borg"), ("Plain", "tar")])
        self.page.evaluate("() => renderBackupMonitors(_backupMonitors)")
        self.page.click('#backup-monitors-list [data-action="editBackupMonitor"][data-arg="0"]')
        self.page.select_option("#bm-tool", "restic")
        self.assertEqual(self.save().status, 200)
        got = self.stored()
        self.assertEqual([(m["label"], m["tool"]) for m in got], [("DB dump", "restic"), ("Plain", "tar")])
        self.assertEqual((got[0]["verify_max_age_hours"], got[0]["restore_drill_max_age_hours"]), (48, 72))

    def test_the_select_offers_auto_and_the_three_tools_the_agent_can_run(self):
        self.start_with([API_ONLY])
        self.assertEqual(self.page.eval_on_selector_all("#bm-tool option", "els => els.map(e => e.value)"), ["auto", "restic", "borg", "tar"])

    def test_a_box_the_form_shows_is_stored_as_it_is_left_and_the_rest_still_stands(self):
        self.start_with([API_ONLY])
        self.page.click('#backup-monitors-list [data-action="editBackupMonitor"]')
        self.assertTrue(self.page.is_checked("#bm-verify"))
        self.page.uncheck("#bm-verify")
        self.page.check("#bm-drill")
        self.page.fill("#bm-drill-sample", "etc/hostname")
        self.assertEqual(self.save().status, 200)
        got = self.stored()[0]
        self.assertIs(got["verify_enabled"], False)
        self.assertIs(got["restore_drill_enabled"], True)
        self.assertEqual(got["restore_sample_path"], "etc/hostname")
        self.assertEqual((got["tool"], got["verify_max_age_hours"], got["restore_drill_max_age_hours"]), ("borg", 48, 72))

    def test_editing_one_monitor_leaves_the_others_as_they_were(self):
        self.start_with([API_ONLY, OTHER])
        self.page.click('#backup-monitors-list [data-action="editBackupMonitor"][data-arg="1"]')
        self.page.fill("#bm-label", "Files (weekly)")
        self.assertEqual(self.save().status, 200)
        got = self.stored()
        self.assertEqual([m["label"] for m in got], ["DB dump", "Files (weekly)"])
        self.assertEqual([(m["tool"], m["verify_max_age_hours"], m["restore_drill_max_age_hours"]) for m in got], [("borg", 48, 72), ("restic", 24, 96)])

    def test_a_new_monitor_starts_on_auto_and_weekly(self):
        self.start_with([API_ONLY])
        self.page.fill("#bm-path", "/srv/backups/new")
        self.page.fill("#bm-label", "New")
        self.assertEqual(self.save().status, 200)
        got = self.stored()
        self.assertEqual([m["label"] for m in got], ["DB dump", "New"])
        self.assertEqual((got[1]["tool"], got[1]["verify_max_age_hours"], got[1]["restore_drill_max_age_hours"]), ("auto", 168, 168), "the select starts on auto")
        self.assertEqual((got[0]["tool"], got[0]["verify_max_age_hours"]), ("borg", 48), "the one that was there is as it was")

    def test_a_save_the_server_refuses_does_not_stay_in_the_list_or_ride_into_the_next_one(self):
        self.start_with([API_ONLY])
        self.page.route("**/api/config", lambda route: route.fulfill(status=400, content_type="application/json", body=json.dumps({"error": "refused for the test"}))
                        if route.request.method == "POST" else route.continue_())
        self.page.fill("#bm-path", "/srv/backups/refused")
        self.page.fill("#bm-label", "Refused")
        self.assertEqual(self.save().status, 400)
        self.assertEqual(self.page.evaluate("() => _backupMonitors.map(m => m.label)"), ["DB dump"], "the refused monitor is not in the page's list")
        self.page.unroute_all()
        self.page.fill("#bm-path", "/srv/backups/accepted")
        self.page.fill("#bm-label", "Accepted")
        self.assertEqual(self.save().status, 200)
        self.assertEqual([m["label"] for m in self.stored()], ["DB dump", "Accepted"], "the refused one did not ride along")

    def test_nothing_in_the_page_broke_on_the_way(self):
        self.start_with([API_ONLY])
        self.page.click('#backup-monitors-list [data-action="editBackupMonitor"]')
        self.assertEqual(self.save().status, 200)
        self.assertEqual([e for e in self.errors if "Failed to load resource" not in e], [])


if __name__ == "__main__":
    unittest.main()
