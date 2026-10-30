#!/usr/bin/env python3
"""7.4.6, issue #57: the CVE page, in a browser, over the seeded demo.

The rules are in test_v746_cve_fix_status (the scanner, the alerts, the report) and the page's own counting
function is held against the server's in test_v746_cve_fix_page. What those cannot show is the page: that the
four tiles hold the numbers the report holds, that clicking one filters the host table and clicking it again
puts the hosts back, that an empty answer says so, that the host view names the fix a finding has (or where
it is, or that it has none), that the filter follows into the host view and can be undone there, that the
alert option is on the Settings page and is saved, and that the words come out in another language.

The page is real (a seeded instance, a signed-in browser). Self-skips without playwright/chromium/gunicorn.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
for p in (_HERE, _ROOT / "server" / "cgi-bin"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import browser_required  # noqa: E402

try:
    from playwright.sync_api import sync_playwright
except ImportError:                                     # pragma: no cover
    sync_playwright = None

from e2e_harness import SKIP_REASON, browser_available  # noqa: E402

_GATE = browser_available() or browser_required.required()
_STACK = {}


def _sign_in(browser, base, user, password):
    context = browser.new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
    page = context.new_page()
    page.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); } catch (e) {}")
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(base + "/index.html")
    page.fill("#login-user", user)
    page.fill("#login-pass", password)
    page.click('#login-form button[type="submit"]')
    page.wait_for_selector("#app", state="visible", timeout=90000)
    page.wait_for_timeout(6000)
    return context, page, errors


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("what is measured is the page, not the backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-cvefix-")
    proc = subprocess.run([sys.executable, str(seeder), "--data-dir", data_dir, "--apply"],
                          capture_output=True, cwd=str(_ROOT), timeout=900)
    if proc.returncode != 0:
        raise unittest.SkipTest("demo seeder failed: " + proc.stderr.decode(errors="replace")[-300:])
    from e2e_harness import start_stack
    pw = sync_playwright().start()
    try:
        browser = pw.chromium.launch()
    except Exception as exc:
        pw.stop()
        browser_required.skip_or_fail(f"chromium not available: {exc}")
    try:
        base, shutdown = start_stack(data_dir=data_dir)
    except Exception as exc:
        browser.close()
        pw.stop()
        raise unittest.SkipTest(f"app stack not available: {exc}")
    context, page, errors = _sign_in(browser, base, "alice", "demo")
    _STACK.update(pw=pw, browser=browser, shutdown=shutdown, page=page, base=base, errors=errors)


def tearDownModule():
    if not _STACK:
        return
    try:
        _STACK["browser"].close()
        _STACK["pw"].stop()
    finally:
        _STACK["shutdown"]()


@unittest.skipUnless(_GATE, SKIP_REASON)
class _Page(unittest.TestCase):

    @property
    def page(self):
        return _STACK["page"]

    def setUp(self):
        self.page.evaluate("() => { if (window.RPi18n) RPi18n.setLang('en', false); cveFixFilter = ''; }")

    def tearDown(self):
        try:
            self.page.evaluate("() => { closeModal('cve-detail-modal'); }")
        except Exception:
            pass
        self.assertEqual(_STACK["errors"], [], "the page threw")

    def report(self):
        return self.page.evaluate("async () => await api('GET', '/cve/findings')")

    def open_cve(self):
        self.page.evaluate("showPage('cve')")
        self.page.wait_for_function(
            "() => parseInt(document.getElementById('cve-fix-fixable').textContent) > 0"
            " && document.querySelectorAll('#cve-tbody tr td').length > 4 && !document.querySelector('#cve-tbody .skeleton')",
            timeout=60000)

    def tiles(self):
        return self.page.evaluate("""() => Object.fromEntries([...document.querySelectorAll('#cve-fix-row .stat-card')].map(el =>
            [el.dataset.arg, {n: parseInt(el.querySelector('.stat-value').textContent), on: el.getAttribute('aria-pressed'),
                              label: el.querySelector('.stat-label').textContent.trim()}]))""")

    def hosts(self):
        return self.page.evaluate("() => [...document.querySelectorAll('#cve-tbody tr td.fw-500')].map(td => td.textContent.trim())")

    def tile(self, key):
        return self.page.locator(f'#cve-fix-row [data-arg="{key}"]')

    def host_with(self, key):
        return next(d for d in self.report()["devices"] if (d.get("fix") or {}).get(key, 0) > 0)


class TestTheCountsOnThePage(_Page):

    def test_the_four_tiles_hold_the_numbers_of_the_report(self):
        self.open_cve()
        fix = self.report()["summary"]["fix"]
        t = self.tiles()
        self.assertEqual({k: v["n"] for k, v in t.items()}, fix)
        self.assertEqual(sorted(t), ["fixable", "newer_release", "none", "unchecked"])
        self.assertGreater(fix["fixable"], 0)
        self.assertGreater(fix["newer_release"], 0)
        self.assertGreater(fix["none"], 0)

    def test_the_tiles_say_what_they_count(self):
        self.open_cve()
        self.assertEqual({k: v["label"] for k, v in self.tiles().items()},
                         {"fixable": "Fixable now", "newer_release": "Newer release only",
                          "none": "No fix yet", "unchecked": "Not checked"})

    def test_no_tile_is_pressed_until_one_is_clicked(self):
        self.open_cve()
        self.assertEqual({v["on"] for v in self.tiles().values()}, {"false"})


class TestTheTilesFilterTheHostTable(_Page):

    def test_a_tile_keeps_the_hosts_that_have_such_a_finding_and_a_second_click_brings_the_rest_back(self):
        self.open_cve()
        all_hosts = self.hosts()
        wanted = sorted(d["name"] for d in self.report()["devices"] if (d.get("fix") or {}).get("newer_release", 0) > 0)
        self.assertTrue(wanted)
        self.assertGreater(len(all_hosts), len(wanted), "the filter must have something to remove")
        self.tile("newer_release").click()
        self.assertEqual(self.tiles()["newer_release"]["on"], "true")
        self.assertEqual(sorted(self.hosts()), wanted)
        self.tile("newer_release").click()
        self.assertEqual(self.tiles()["newer_release"]["on"], "false")
        self.assertEqual(self.hosts(), all_hosts)

    def test_a_tile_with_nothing_behind_it_says_so(self):
        self.open_cve()
        self.assertEqual(self.tiles()["unchecked"]["n"], 0, "the demo has no finding that cannot be told")
        self.tile("unchecked").click()
        self.assertEqual(self.hosts(), [])
        self.assertIn("No CVE rows match the filter.", self.page.inner_text("#cve-tbody"))

    def test_only_one_tile_is_pressed_at_a_time(self):
        self.open_cve()
        self.tile("fixable").click()
        self.tile("none").click()
        self.assertEqual({k: v["on"] for k, v in self.tiles().items()},
                         {"fixable": "false", "newer_release": "false", "none": "true", "unchecked": "false"})


class TestTheHostView(_Page):

    def open_host(self, dev):
        self.page.evaluate("([id, name]) => openDeviceCVE(id, name)", [dev["device_id"], dev["name"]])
        self.page.wait_for_function("() => document.querySelectorAll('#cve-detail-body .isl-390').length > 0", timeout=30000)
        return self.page.inner_text("#cve-detail-body")

    def test_a_finding_fixed_only_in_a_newer_release_says_so_and_where(self):
        self.open_cve()
        text = self.open_host(self.host_with("newer_release"))
        self.assertIn("Fixed in a newer release", text)
        self.assertIn("Debian:13 1.9.16-1", text)

    def test_a_finding_with_no_fix_says_so(self):
        self.open_cve()
        self.assertIn("No fix yet", self.open_host(self.host_with("none")))

    def test_a_fixable_finding_names_the_version_to_install(self):
        self.open_cve()
        text = self.open_host(self.host_with("fixable"))
        self.assertRegex(text, r"fixed in \S*\d")

    def test_the_filter_follows_into_the_host_view_and_can_be_undone_there(self):
        self.open_cve()
        dev = next(d for d in self.report()["devices"]
                   if (d.get("fix") or {}).get("fixable", 0) > 0 and sum((d.get("fix") or {}).values()) > d["fix"]["fixable"])
        total, fixable = sum(dev["fix"].values()), dev["fix"]["fixable"]
        self.tile("fixable").click()
        text = self.open_host(dev)
        self.assertEqual(self.page.locator("#cve-detail-body .isl-390").count(), fixable)
        self.assertIn(f"{fixable} / {total}", text)
        self.page.click('#cve-detail-body [data-action="clearCveFixFilter"]')
        self.page.wait_for_function(f"() => document.querySelectorAll('#cve-detail-body .isl-390').length === {total}", timeout=30000)
        self.assertEqual(self.tiles()["fixable"]["on"], "false")


class TestTheAlertOption(_Page):
    """The option is on the Settings page, shows what is stored, and is sent when the page saves.

    The page's own Save posts the whole form, and the server asks for a re-verification when a governance
    switch in it differs from the stored one, which a seeded instance's form can. So the choice is stored
    with a small POST, as the API client does, and the Save is run against a stand-in that records what
    the page sent."""

    def config(self):
        return self.page.evaluate("async () => await api('GET', '/config')")

    def post(self, on):
        return self.page.evaluate("async (on) => await api('POST', '/config', {cve_alert_fixable_only: on})", on)

    def open_settings(self):
        self.page.evaluate("showPage('settings')")
        self.page.wait_for_selector("#cfg-cve-fixable-only", state="attached", timeout=60000)

    def checked(self):
        return self.page.evaluate("() => document.getElementById('cfg-cve-fixable-only').checked")

    def test_it_is_off_to_begin_with(self):
        self.assertIs(self.config()["cve_alert_fixable_only"], False)
        self.open_settings()
        self.assertIs(self.checked(), False)

    def test_the_checkbox_follows_the_stored_value(self):
        try:
            self.assertTrue(self.post(True)["ok"])
            self.open_settings()
            self.page.evaluate("async () => { await loadSettings(); }")
            self.page.wait_for_function("() => document.getElementById('cfg-cve-fixable-only').checked === true", timeout=30000)
        finally:
            self.post(False)
        self.page.evaluate("async () => { await loadSettings(); }")
        self.page.wait_for_function("() => document.getElementById('cfg-cve-fixable-only').checked === false", timeout=30000)

    def test_saving_sends_the_choice(self):
        sent = []

        def stand_in(route):
            if route.request.method == "POST":
                sent.append(json.loads(route.request.post_data or "{}"))
                route.fulfill(status=200, content_type="application/json", body='{"ok": true}')
            else:
                route.continue_()

        self.page.route("**/api/config", stand_in)
        try:
            self.open_settings()
            for want in (True, False):
                self.page.evaluate("(on) => { document.getElementById('cfg-cve-fixable-only').checked = on; }", want)
                self.page.evaluate("async () => { await saveSettings(); }")
                self.assertIs(sent[-1]["cve_alert_fixable_only"], want)
        finally:
            self.page.unroute("**/api/config", stand_in)
        self.assertEqual(len(sent), 2)


class TestInAnotherLanguage(_Page):

    def test_the_tiles_come_out_in_german(self):
        self.open_cve()
        self.page.evaluate("async () => { await _ensureI18n(); }")
        self.page.wait_for_timeout(800)
        self.page.evaluate("RPi18n.setLang('de', false)")
        self.page.wait_for_function(
            "() => [...document.querySelectorAll('#cve-fix-row .stat-label')].some(l => l.textContent.trim() === 'Jetzt behebbar')",
            timeout=20000)
        self.assertEqual([v["label"] for v in self.tiles().values()],
                         ["Jetzt behebbar", "Nur in neuerer Version", "Noch keine Korrektur", "Nicht geprüft"])


if __name__ == "__main__":
    unittest.main()
