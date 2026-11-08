#!/usr/bin/env python3
"""8.0.0: a backup monitor's two cadences have a field, and a monitor that checks nothing says so, in a browser on the demo seed.

A backup monitor carries two cadences, how often the integrity check runs and how often the restore drill runs (`verify_max_age_hours`, `restore_drill_max_age_hours`, weekly by default), and the
form had no field for either: they could only be set over the API, and a monitor saved from the page went back to weekly. The form has **Integrity check every (hours)** and **Restore drill
every (hours)** now, filled when a monitor is edited. A monitor with Verify integrity on, the tool on `auto` and a path that names no tool (restic, borg or a tar file) used to check nothing and say
nothing: the form warns when it is saved, and the host drawer shows `no tool chosen` in amber with the reason once the agent has reported it. tests/test_v800_backup_monitor_tool.py holds the agent's half.

Self-skips without playwright / Chromium / gunicorn, and runs under the default storage backend only.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import browser_required  # noqa: E402
from e2e_harness import SKIP_REASON, browser_available  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
_GATE = browser_available() or browser_required.required()

try:
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover
    sync_playwright = None

_STATE = {}
LANGS = ("zh", "hi", "es", "ar", "de", "fr")
WARNING = "names no backup tool"


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("the monitors are backend-agnostic: measured once, under the default backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-backup-cadence-e2e-")
    proc = subprocess.run([sys.executable, str(seeder), "--data-dir", data_dir, "--apply"], capture_output=True, cwd=str(_ROOT), timeout=900)
    if proc.returncode != 0:
        raise unittest.SkipTest("demo seeder failed: " + proc.stderr.decode(errors="replace")[-300:])
    from e2e_harness import start_stack

    pw = sync_playwright().start()
    try:
        browser = pw.chromium.launch()
    except Exception as exc:
        pw.stop()
        browser_required.skip_or_fail("chromium not available: %s" % exc)
        return
    try:
        base, shutdown = start_stack(data_dir=data_dir)
    except Exception as exc:
        browser.close()
        pw.stop()
        raise unittest.SkipTest("app stack not available: %s" % exc)
    _STATE.update(pw=pw, browser=browser, base=base, shutdown=shutdown, data_dir=data_dir)


def tearDownModule():
    try:
        _STATE["browser"].close()
        _STATE["pw"].stop()
    finally:
        if _STATE.get("shutdown"):
            _STATE["shutdown"]()


def _path(name):
    return Path(_STATE["data_dir"]) / name


def read(name):
    return json.loads(_path(name).read_text())


def write(name, doc):
    # a file of the data directory that is written twice in the same second can be read by the server as the first version (its cache looks at the modification time),
    # so every write is given a modification time two seconds after the one it replaces
    tmp = _path(name).with_suffix(".tmp")
    tmp.write_text(json.dumps(doc))
    before = _path(name).stat().st_mtime if _path(name).exists() else 0
    stamp = max(before + 2, time.time())
    os.utime(tmp, (stamp, stamp))
    os.replace(tmp, _path(name))


def _login(browser, user):
    ctx = browser.new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
    ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")
    page = ctx.new_page()
    page.set_default_timeout(20000)
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(_STATE["base"] + "/index.html")
    page.fill("#login-user", user)
    page.fill("#login-pass", "demo")
    page.click('#login-form button[type="submit"]')
    page.wait_for_selector("#app", state="visible", timeout=90000)
    page.wait_for_timeout(3000)
    return ctx, page, errors


def open_settings(page, control):
    """Settings, on the pane that holds `control`, opened the way a person opens it: the tab is pressed and the pane's own loaders run."""
    page.evaluate("() => { showPage('settings'); }")
    page.wait_for_function("(id) => !!document.getElementById(id)", arg=control, timeout=30000)
    pane = page.evaluate("(id) => document.getElementById(id).closest('.settings-pane').id.replace('settings-pane-', '')", control)
    page.click("#settings-tab-btn-" + pane)
    page.wait_for_selector("#" + control, state="visible", timeout=20000)
    page.wait_for_timeout(1500)


A = {"path": "/srv/a.tar.gz", "label": "A", "max_age_hours": 24, "tool": "auto", "verify_enabled": True, "verify_max_age_hours": 36,
     "restore_drill_enabled": True, "restore_sample_path": "etc/hostname", "restore_drill_max_age_hours": 72}


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheCadencesHaveAField(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ctx, cls.page, cls.errors = _login(_STATE["browser"], "alice")
        cls.config0 = read("config.json")

    @classmethod
    def tearDownClass(cls):
        try:
            write("config.json", cls.config0)
        finally:
            cls.ctx.close()

    def setUp(self):
        write("config.json", dict(self.config0, backup_monitors=[dict(A)]))
        self.page.reload()
        self.page.wait_for_selector("#app", state="visible", timeout=90000)
        self.page.wait_for_timeout(2500)
        open_settings(self.page, "bm-path")
        self.page.wait_for_selector("#backup-monitors-list [data-action='editBackupMonitor']", timeout=20000)

    def monitors(self):
        return read("config.json").get("backup_monitors") or []

    def by_path(self, path):
        return next((m for m in self.monitors() if m["path"] == path), None)

    def press_add_and_wait(self):
        """Press Add (or Save) and return the monitors the page sent: the server keeps the cadences in range as well, so what is stored cannot show what the page did."""
        with self.page.expect_response(lambda r: r.request.method == "POST" and r.url.endswith("/api/config"), timeout=20000) as info:
            self.page.click('[data-action="addBackupMonitor"]')
        self.assertEqual(info.value.status, 200, info.value.text()[:200])
        return info.value.request.post_data_json["backup_monitors"]

    def test_both_fields_are_there_and_say_weekly_until_told_otherwise(self):
        self.assertEqual(self.page.input_value("#bm-verify-hours"), "168")
        self.assertEqual(self.page.input_value("#bm-drill-hours"), "168")
        for control in ("bm-verify-hours", "bm-drill-hours"):
            self.assertEqual(self.page.get_attribute("#" + control, "min"), "1")
            self.assertEqual(self.page.get_attribute("#" + control, "max"), "8760")

    def test_a_new_monitor_keeps_the_cadences_it_was_given(self):
        self.page.fill("#bm-path", "/srv/new.tar")
        self.page.check("#bm-verify")
        self.page.fill("#bm-verify-hours", "12")
        self.page.check("#bm-drill")
        self.page.fill("#bm-drill-sample", "etc/hosts")
        self.page.fill("#bm-drill-hours", "48")
        self.press_add_and_wait()
        m = self.by_path("/srv/new.tar")
        self.assertEqual((m["verify_max_age_hours"], m["restore_drill_max_age_hours"]), (12, 48))

    def test_editing_shows_what_is_stored_and_a_save_keeps_it(self):
        self.page.click("#backup-monitors-list [data-action='editBackupMonitor']")
        self.assertEqual((self.page.input_value("#bm-verify-hours"), self.page.input_value("#bm-drill-hours")), ("36", "72"))
        self.page.fill("#bm-label", "A renamed")
        self.press_add_and_wait()
        m = self.by_path("/srv/a.tar.gz")
        self.assertEqual((m["label"], m["verify_max_age_hours"], m["restore_drill_max_age_hours"]), ("A renamed", 36, 72))

    def test_editing_can_change_one_cadence_and_leaves_the_other(self):
        self.page.click("#backup-monitors-list [data-action='editBackupMonitor']")
        self.page.fill("#bm-verify-hours", "6")
        self.press_add_and_wait()
        m = self.by_path("/srv/a.tar.gz")
        self.assertEqual((m["verify_max_age_hours"], m["restore_drill_max_age_hours"]), (6, 72))

    def test_a_cadence_outside_the_range_is_brought_into_it(self):
        for typed, expected in (("99999", 8760), ("", 168), ("-5", 1), ("abc", 168)):
            with self.subTest(typed=typed):
                write("config.json", dict(self.config0, backup_monitors=[]))
                self.page.reload()
                self.page.wait_for_selector("#app", state="visible", timeout=90000)
                self.page.wait_for_timeout(2000)
                open_settings(self.page, "bm-path")
                self.page.fill("#bm-path", "/srv/range.tar")
                self.page.check("#bm-verify")
                self.page.evaluate("(v) => { document.getElementById('bm-verify-hours').value = v; }", typed)
                sent = self.press_add_and_wait()
                self.assertEqual(next(m for m in sent if m["path"] == "/srv/range.tar")["verify_max_age_hours"], expected, "what the page sent")
                self.assertEqual(self.by_path("/srv/range.tar")["verify_max_age_hours"], expected, "what the server kept")

    def test_the_form_goes_back_to_weekly_after_a_save(self):
        self.page.fill("#bm-path", "/srv/new.tar")
        self.page.fill("#bm-verify-hours", "12")
        self.page.fill("#bm-drill-hours", "48")
        self.press_add_and_wait()
        self.assertEqual((self.page.input_value("#bm-verify-hours"), self.page.input_value("#bm-drill-hours")), ("168", "168"))

    def test_a_path_that_names_no_tool_warns_when_verification_is_on_and_still_saves(self):
        self.page.fill("#bm-path", "/srv/nightly")
        self.page.check("#bm-verify")
        self.press_add_and_wait()
        self.page.wait_for_function("(t) => document.body.innerText.includes(t)", arg=WARNING, timeout=10000)
        self.assertEqual(self.by_path("/srv/nightly")["verify_enabled"], True, "a warning, not a refusal")

    def test_no_warning_when_the_path_names_a_tool_or_the_tool_is_chosen_or_verification_is_off(self):
        cases = (
            ("/srv/restic-main", "auto", True),
            ("/srv/borg-repo", "auto", True),
            ("/srv/backup.tar.gz", "auto", True),
            ("/srv/set.tgz", "auto", True),
            ("/srv/nightly", "borg", True),
            ("/srv/nightly", "auto", False),
        )
        for path, tool, verify in cases:
            with self.subTest(path=path, tool=tool, verify=verify):
                write("config.json", dict(self.config0, backup_monitors=[]))
                self.page.reload()
                self.page.wait_for_selector("#app", state="visible", timeout=90000)
                self.page.wait_for_timeout(2000)
                open_settings(self.page, "bm-path")
                self.page.fill("#bm-path", path)
                self.page.select_option("#bm-tool", tool)
                (self.page.check if verify else self.page.uncheck)("#bm-verify")
                self.press_add_and_wait()
                self.page.wait_for_function("() => document.body.innerText.includes('Backup monitor added')", timeout=10000)
                self.assertNotIn(WARNING, self.page.inner_text("body"))

    def test_the_labels_and_the_warning_are_translated_in_all_six_languages(self):
        self.page.evaluate("async () => { await _ensureI18n(); }")
        pick = "() => ['bm-verify-hours', 'bm-drill-hours'].map(id => document.querySelector(`label[for=${id}]`).textContent.trim())"
        english = self.page.evaluate(pick)
        self.page.fill("#bm-path", "/srv/nightly")
        self.page.check("#bm-verify")
        self.press_add_and_wait()
        self.page.wait_for_function("(t) => document.body.innerText.includes(t)", arg=WARNING, timeout=10000)
        warning_en = self.page.evaluate("(t) => [...document.querySelectorAll('.toast, [role=status], [role=alert]')].map(e => e.textContent).find(x => x.includes(t)) || ''", WARNING).strip()
        self.assertTrue(warning_en)
        bad = []
        try:
            for lang in LANGS:
                self.page.evaluate("(l) => RPi18n.setLang(l, false)", lang)
                self.page.wait_for_timeout(300)
                if self.page.evaluate(pick) == english or any(a == b for a, b in zip(self.page.evaluate(pick), english)):
                    bad.append(lang)
        finally:
            self.page.evaluate("() => RPi18n.setLang('en', false)")
        self.assertEqual(bad, [])

    def test_nothing_in_the_page_broke_on_the_way(self):
        self.page.click("#backup-monitors-list [data-action='editBackupMonitor']")
        self.assertEqual([e for e in self.errors if "Failed to load resource" not in e], [])


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheDrawerSaysWhyNothingWasChecked(unittest.TestCase):
    HOST = "ng01"

    @classmethod
    def setUpClass(cls):
        cls.ctx, cls.page, cls.errors = _login(_STATE["browser"], "alice")
        cls.config0 = read("config.json")
        cls.state0 = read("backup_state.json") if _path("backup_state.json").exists() else {}
        now = int(time.time())
        mons = [
            {"path": "/srv/nightly", "label": "Nightly", "max_age_hours": 24, "tool": "auto", "verify_enabled": True},
            {"path": "/srv/restic-ok", "label": "Restic ok", "max_age_hours": 24, "tool": "restic", "verify_enabled": True},
            {"path": "/srv/restic-bad", "label": "Restic bad", "max_age_hours": 24, "tool": "restic", "verify_enabled": True},
        ]
        reason = "The path names no backup tool (restic, borg or a tar file). Choose the tool in the monitor."
        state = dict(cls.state0)
        state[f"{cls.HOST}:/srv/nightly"] = {"ok": True, "age_h": 2, "verify_status": "no_tool", "verify_output": reason, "verify_at": now - 60, "verify_tool": ""}
        state[f"{cls.HOST}:/srv/restic-ok"] = {"ok": True, "age_h": 2, "verify_status": "ok", "verify_output": "", "verify_at": now - 60, "verify_tool": "restic"}
        state[f"{cls.HOST}:/srv/restic-bad"] = {"ok": True, "age_h": 2, "verify_status": "failed", "verify_output": "pack damaged", "verify_at": now - 60, "verify_tool": "restic"}
        write("config.json", dict(cls.config0, backup_monitors=mons))
        write("backup_state.json", state)
        cls.page.reload()
        cls.page.wait_for_selector("#app", state="visible", timeout=90000)
        cls.page.wait_for_timeout(2500)

    @classmethod
    def tearDownClass(cls):
        try:
            write("config.json", cls.config0)
            write("backup_state.json", cls.state0)
        finally:
            cls.ctx.close()

    def open_section(self):
        name = read("devices.json")[self.HOST]["name"]
        self.page.evaluate("([id, n]) => { openDeviceDrawer(id, n, 'audit'); }", [self.HOST, name])
        self.page.wait_for_selector("#audit-body-backups", state="attached", timeout=30000)
        self.page.evaluate("() => _loadAuditSection('backups')")
        self.page.wait_for_function("() => { const b = document.getElementById('audit-body-backups'); return b && b.querySelector('table.audit-table tbody tr'); }", timeout=30000)

    def verify_cell(self, label):
        # the audit section is a <details> that may be closed: the text is read as content (inner_text of a hidden element is empty)
        return self.page.locator("#audit-body-backups tbody tr", has=self.page.locator("code", has_text=label)).locator("td").nth(4)

    def test_a_monitor_that_names_no_tool_shows_it_in_amber_with_the_reason(self):
        self.open_section()
        cell = self.verify_cell("Nightly")
        self.assertTrue(cell.text_content().strip().startswith("no tool chosen"), cell.text_content())
        self.assertIn("c-amber", cell.get_attribute("class") or "")
        self.assertIn("names no backup tool", cell.get_attribute("title") or "")

    def test_the_other_results_are_unchanged(self):
        self.open_section()
        ok, bad = self.verify_cell("Restic ok"), self.verify_cell("Restic bad")
        self.assertIn("c-green", ok.get_attribute("class") or "")
        self.assertTrue(ok.text_content().strip().startswith("verified"))
        self.assertIn("c-red", bad.get_attribute("class") or "")
        self.assertTrue(bad.text_content().strip().startswith("failed"))

    def test_the_status_word_is_translated_in_all_six_languages(self):
        self.open_section()
        self.page.evaluate("async () => { await _ensureI18n(); }")
        english = self.verify_cell("Nightly").text_content().strip()
        bad = []
        try:
            for lang in LANGS:
                self.page.evaluate("(l) => RPi18n.setLang(l, false)", lang)
                self.page.wait_for_timeout(300)
                if self.verify_cell("Nightly").text_content().strip().startswith("no tool chosen"):
                    bad.append(lang)
        finally:
            self.page.evaluate("() => RPi18n.setLang('en', false)")
        self.assertTrue(english.startswith("no tool chosen"))
        self.assertEqual(bad, [])


if __name__ == "__main__":
    unittest.main()
