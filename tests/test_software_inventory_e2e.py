#!/usr/bin/env python3
"""The pages that show the software of a Windows or macOS host, in a browser, over the seeded demo.

The server and the page functions are held in test_software_inventory_server and test_software_inventory_views. What those cannot show
is the page: that the words come out in the right place, that nothing runs past the edge of a narrow screen, that a language
that is written right to left lays out, and that the pages ask the server for nothing that fails.

The demo's Windows host (design-win11) and its Mac (mette-macbook) are given what their agents now send: a list of programs and a
list of applications with their Homebrew packages. The seeder gave them the package lists of Ubuntu, which no agent of theirs could
send; the lists are replaced here, and so are the CVE findings the seeder wrote for them, which the scan cannot produce for an
application list.

A control checks that each page rendered the host it is about before anything is measured, so a page that failed to draw cannot pass
by having nothing on it. Self-skips without playwright, chromium and gunicorn.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
for p in (_HERE, _ROOT / "server" / "cgi-bin"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import browser_required  # noqa: E402
import software_inventory as si  # noqa: E402

try:
    from playwright.sync_api import sync_playwright
except ImportError:                                     # pragma: no cover
    sync_playwright = None

from e2e_harness import SKIP_REASON, browser_available  # noqa: E402

_GATE = browser_available() or browser_required.required()
_STACK = {}
WIN, MAC = "wks01", "mbp01"
WIDTHS = (1440, 768, 390)
SEND_TIP = "Ask the agent to send the software installed on this host now"

WINDOWS_ROWS = [
    {"name": "Google Chrome", "version": "120.0.6099.109", "publisher": "Google LLC", "installed": "2023-12-15", "arch": "x64"},
    {"name": "7-Zip 23.01 (x64)", "version": "23.01", "publisher": "Igor Pavlov", "installed": "2023-11-02", "arch": "x64"},
    {"name": "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33130", "version": "14.38.33130.0",
     "publisher": "Microsoft Corporation", "installed": "2023-10-30", "arch": "x64"},
    {"name": "Microsoft Visual C++ 2015-2022 Redistributable (x86) - 14.38.33130", "version": "14.38.33130.0",
     "publisher": "Microsoft Corporation", "installed": "2023-10-30", "arch": "x86"},
    {"name": "Microsoft Edge", "version": "120.0.2210.91", "publisher": "Microsoft Corporation", "arch": "x86"},
    {"name": "TeamViewer", "version": "15.49.2", "publisher": "TeamViewer Germany GmbH", "arch": "x64"},
    {"name": "Git", "version": "2.43.0.windows.1", "publisher": "The Git Development Community", "arch": "x64"},
    {"name": "Windows Driver Package - Intel (e1dexpress) Net", "version": "12.19.2.45"},
]
MAC_ROWS = [
    {"name": "Safari", "version": "17.2", "id": "com.apple.Safari", "manager": "macos"},
    {"name": "Google Chrome", "version": "120.0.6099.129", "id": "com.google.Chrome", "manager": "macos"},
    {"name": "wget", "version": "1.21.4", "manager": "brew"},
    {"name": "git", "version": "2.43.0", "manager": "brew"},
]


def _entry(manager, rows, skipped):
    packages = si.clean_list(rows, manager)
    return {"hash": "e2e", "collected_at": int(time.time()), "ecosystem": "", "pkg_manager": manager, "count": len(packages),
            "packages": packages, "os_id": "", "version_id": "", "skipped": skipped}


def _prepare(data_dir):
    packages = json.loads((Path(data_dir) / "packages.json").read_text())
    packages[WIN] = _entry("windows", WINDOWS_ROWS, 41)
    packages[MAC] = _entry("macos", MAC_ROWS, 0)
    (Path(data_dir) / "packages.json").write_text(json.dumps(packages))
    findings = json.loads((Path(data_dir) / "cve_findings.json").read_text())
    for host in (WIN, MAC):
        findings.pop(host, None)
    (Path(data_dir) / "cve_findings.json").write_text(json.dumps(findings))


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("what is measured is the page, not the backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-softinv-e2e-")
    proc = subprocess.run([sys.executable, str(seeder), "--data-dir", data_dir, "--apply"],
                          capture_output=True, cwd=str(_ROOT), timeout=900)
    if proc.returncode != 0:
        raise unittest.SkipTest("demo seeder failed: " + proc.stderr.decode(errors="replace")[-300:])
    _prepare(data_dir)
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
    context = browser.new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
    page = context.new_page()
    page.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")
    problems = {"console": [], "page": [], "failed": []}
    page.goto(base + "/index.html")
    page.fill("#login-user", "alice")
    page.fill("#login-pass", "demo")
    page.click('#login-form button[type="submit"]')
    page.wait_for_selector("#app", state="visible", timeout=90000)
    page.wait_for_timeout(6000)
    page.on("console", lambda m: problems["console"].append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: problems["page"].append(str(e)))
    page.on("response", lambda r: problems["failed"].append(f"{r.status} {r.url}") if r.status >= 400 else None)
    _STACK.update(pw=pw, browser=browser, shutdown=shutdown, page=page, base=base, problems=problems, data_dir=data_dir)


def tearDownModule():
    if not _STACK:
        return
    try:
        _STACK["browser"].close()
        _STACK["pw"].stop()
    finally:
        _STACK["shutdown"]()
        import shutil
        shutil.rmtree(_STACK["data_dir"], ignore_errors=True)


OVERFLOW = """modalId => {
  const d = document.documentElement;
  const out = {page: d.scrollWidth - window.innerWidth, dir: d.dir || document.body.dir || ''};
  if (modalId) {
    const modal = document.querySelector('#' + modalId + '.active .modal');
    out.modal = modal ? modal.scrollWidth - modal.clientWidth : null;      // null: the dialog is not open, and nothing was measured
  }
  return out;
}"""


@unittest.skipUnless(_GATE, SKIP_REASON)
class _Page(unittest.TestCase):
    @property
    def page(self):
        return _STACK["page"]

    @classmethod
    def setUpClass(cls):
        page = _STACK["page"]
        page.set_viewport_size({"width": 1440, "height": 900})
        page.evaluate("() => { if (window.RPi18n) RPi18n.setLang('en', false); }")
        # the policy: a banned program the Windows host has, saved through the page, so the server judges every host with a list
        rules = page.evaluate("async () => (await api('GET', '/software-policy')).rules")
        rules = [r for r in rules if r.get("id") != "banned:teamviewer"] + [
            {"id": "banned:teamviewer", "type": "banned", "package": "teamviewer", "note": "Remote access that bypasses the gateway."},
            {"id": "min_version:chrome", "type": "min_version", "package": "google chrome", "version": "121.0"}]
        saved = page.evaluate("async rules => await api('POST', '/software-policy', {rules})", rules)
        assert saved and saved.get("ok"), saved

    def setUp(self):
        _STACK["problems"].update(console=[], page=[], failed=[])
        self.page.evaluate("() => { if (window.RPi18n) RPi18n.setLang('en', false); }")
        self.page.set_viewport_size({"width": 1440, "height": 900})

    def tearDown(self):
        try:
            self.page.evaluate("() => { try { closeModal('cve-detail-modal'); } catch (e) {} try { closeDeviceDrawer(); } catch (e) {} }")
        except Exception:
            pass
        problems = _STACK["problems"]
        self.assertEqual(problems["page"], [], "the page threw")
        self.assertEqual(problems["console"], [], "the console reported an error")
        failed = [f for f in problems["failed"] if "/api/" in f]
        self.assertEqual(failed, [], "a request failed")

    def set_language(self, lang):
        """The dictionary is fetched when a language other than English is asked for; wait for it."""
        self.page.evaluate("async l => { const i = await _ensureI18n(); i.setLang(l, false); }", lang)
        self.page.wait_for_timeout(800)

    def fits(self, label, modal_id=None):
        """No horizontal overflow at the three widths, of the page and, when a dialog is open, of the dialog."""
        for width in WIDTHS:
            self.page.set_viewport_size({"width": width, "height": 900})
            self.page.wait_for_timeout(250)
            got = self.page.evaluate(OVERFLOW, modal_id)
            self.assertLessEqual(got["page"], 1, f"{label} at {width}px runs {got['page']}px past the edge")
            if modal_id:
                self.assertIsNotNone(got["modal"], f"{label}: the dialog {modal_id} was not open to measure")
                self.assertLessEqual(got["modal"], 1, f"{label} (dialog) at {width}px")
        self.page.set_viewport_size({"width": 1440, "height": 900})

    def policy_page(self):
        self.page.evaluate("showPage('software-policy')")
        self.page.wait_for_function(
            "() => document.querySelectorAll('#swpol-viol-tbody tr td').length > 2 && !document.querySelector('#swpol-viol-tbody .skeleton')"
            " && document.querySelectorAll('#swcatalog-body tr').length > 2", timeout=60000)


class TestTheMeasure(_Page):
    def test_a_box_wider_than_the_screen_is_seen_by_the_measure(self):
        """The control: a measure that cannot see overflow would pass every page below it."""
        self.page.evaluate("showPage('software-policy')")
        self.page.evaluate("""() => { const d = document.createElement('div'); d.id = 'e2e-wide'; d.textContent = 'wide';
            d.style.cssText = 'position:absolute;left:0;top:0;width:3000px;height:4px'; document.body.appendChild(d); }""")
        try:
            self.page.set_viewport_size({"width": 390, "height": 900})
            self.page.wait_for_timeout(250)
            self.assertGreater(self.page.evaluate(OVERFLOW, None)["page"], 1000)
        finally:
            self.page.evaluate("() => { const d = document.getElementById('e2e-wide'); if (d) d.remove(); }")
        self.assertLessEqual(self.page.evaluate(OVERFLOW, None)["page"], 1)
        self.page.set_viewport_size({"width": 1440, "height": 900})


class TestTheSoftwarePolicyPage(_Page):
    HINT = ("A required rule with no tags is checked on Linux hosts only. To require an application on a Windows or macOS host, "
            "give the rule a tag that host carries. Application names are matched without regard to case.")

    def rows(self):
        return self.page.evaluate("""() => [...document.querySelectorAll('#swpol-viol-tbody tr')].map(tr => ({
            host: (tr.cells[0] || {}).textContent, rule: (tr.cells[1] || {}).textContent, pkg: (tr.cells[2] || {}).textContent,
            found: (tr.cells[4] || {}).textContent, fix: !!tr.querySelector('[data-action="swPolFixViolation"]')}))""")

    def test_a_windows_host_is_judged_by_its_titles_and_offers_no_install_or_remove_button(self):
        self.policy_page()
        rows = self.rows()
        win = [r for r in rows if r["host"] == "design-win11"]
        self.assertTrue(win, rows)                                   # control: the host is on the page
        by = {(r["rule"], r["pkg"]): r for r in win}
        self.assertIn(("banned", "teamviewer"), by)                  # rule `teamviewer`, installed as `TeamViewer`
        self.assertEqual(by[("banned", "teamviewer")]["found"], "15.49.2")
        self.assertIn(("min_version", "google chrome"), by)          # 120.0.6099.109 is below 121.0 as a number
        self.assertFalse(any(r["fix"] for r in win), win)
        # the control: a Linux host's violation keeps the button
        linux = [r for r in rows if r["host"] not in ("design-win11", "mette-macbook")]
        self.assertTrue(linux and any(r["fix"] for r in linux), linux)
        # and the required rule with no tags (fail2ban) is not judged on the Windows host
        self.assertNotIn(("required", "fail2ban"), by)

    def test_the_sentence_that_says_how_a_required_rule_is_read_is_on_the_page(self):
        self.policy_page()
        hint = self.page.evaluate("""() => { const p = [...document.querySelectorAll('#page-software-policy p.hint')]
            .find(x => x.textContent.startsWith('A required rule with no tags')); return p ? p.textContent : ''; }""")
        self.assertEqual(hint, self.HINT)

    def test_the_software_center_lists_the_applications_of_a_windows_host(self):
        self.policy_page()
        text = self.page.evaluate("() => document.getElementById('swcatalog-body').textContent")
        self.assertIn("Google Chrome", text)
        self.assertIn("Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33130", text)

    def test_nothing_runs_past_the_edge_of_a_narrow_screen(self):
        self.policy_page()
        self.fits("the Software Policy page")

    def test_it_reads_in_german_and_in_arabic_and_lays_out_right_to_left(self):
        from test_v710_i18n_glue import dict_rows
        row = dict_rows()[self.HINT]
        self.policy_page()
        for lang in ("de", "ar"):
            self.set_language(lang)
            self.page.wait_for_timeout(800)
            texts = self.page.evaluate("() => [...document.querySelectorAll('#page-software-policy p.hint')].map(p => p.textContent)")
            self.assertIn(row[lang], texts, (lang, texts))
            if lang == "ar":
                self.assertEqual(self.page.evaluate("() => document.documentElement.dir"), "rtl")
            self.fits(f"the Software Policy page in {lang}")


class TestTheCvePages(_Page):
    def cve_page(self):
        self.page.evaluate("showPage('cve')")
        self.page.wait_for_function(
            "() => document.querySelectorAll('#cve-tbody tr td').length > 4 && !document.querySelector('#cve-tbody .skeleton')", timeout=60000)

    def send_tip(self):
        """The tip (title) of the Send package list now button in the open host view."""
        return self.page.evaluate("""() => { const b = document.querySelector('#cve-detail-body [data-action-btn="_forcePackageScanBtn"]');
            return b ? b.title : null; }""")

    def last_scan(self, dev_id):
        return self.page.evaluate("""id => { const tr = document.querySelector('#cve-tbody tr[data-arg="' + id + '"]');
            return tr ? {ecosystem: tr.cells[2].textContent, last: tr.querySelector('td.meta-sm-nm').textContent.trim()} : null; }""", dev_id)

    def test_the_cve_page_says_not_checked_for_the_windows_host_and_the_mac(self):
        self.cve_page()
        for host in (WIN, MAC):
            row = self.last_scan(host)
            self.assertIsNotNone(row, host)                          # control: the host is in the table
            self.assertEqual(row, {"ecosystem": "unsupported", "last": "● not checked"}, host)

    def test_the_host_view_says_nothing_on_the_host_is_checked(self):
        self.cve_page()
        self.page.evaluate("() => openDeviceCVE('%s', 'design-win11')" % WIN)
        self.page.wait_for_function(
            "() => { const b = document.getElementById('cve-detail-body'); return b && b.textContent.includes('Packages') && !b.querySelector('.skeleton'); }",
            timeout=30000)
        body = self.page.evaluate("() => document.getElementById('cve-detail-body').textContent")
        self.assertIn("no vulnerability database is matched against it", body)
        self.assertNotIn("No vulnerabilities found", body)
        # the tip of the button under that sentence does not say the list is compared with OSV
        self.assertEqual(self.send_tip(), SEND_TIP)
        self.assertIn(str(len(si.clean_list(WINDOWS_ROWS, "windows"))), body)      # the host still says how many packages it has
        self.fits("the host's CVE view", "cve-detail-modal")

    def test_the_drawers_summary_says_not_checked(self):
        self.page.evaluate("() => openDeviceDrawer('%s', 'design-win11', 'audit')" % WIN)
        self.page.wait_for_selector("#audit-sec-cve", timeout=30000)
        self.page.evaluate("() => { const d = document.getElementById('audit-sec-cve'); d.open = true; }")
        self.page.wait_for_function("() => document.getElementById('audit-badge-cve').textContent === 'not checked'", timeout=30000)
        body = self.page.evaluate("() => document.getElementById('audit-body-cve').textContent")
        self.assertIn("nothing on it is checked", body)
        self.assertNotIn("No CVEs found", body)

    def test_it_reads_in_german_and_in_arabic(self):
        from test_v710_i18n_glue import dict_rows
        sentence = ("The software of this host is listed, but no vulnerability database is matched against it, so nothing on it is "
                    "checked. No findings here does not mean no vulnerabilities.")
        row = dict_rows()[sentence]
        tip_row = dict_rows()[SEND_TIP]
        self.cve_page()
        for lang in ("de", "ar"):
            self.set_language(lang)
            self.page.evaluate("() => openDeviceCVE('%s', 'design-win11')" % WIN)
            self.page.wait_for_function(
                "() => { const b = document.getElementById('cve-detail-body'); return b && b.querySelector('[data-cve-coverage]'); }", timeout=30000)
            self.page.wait_for_timeout(800)
            shown = self.page.evaluate("() => document.querySelector('#cve-detail-body [data-cve-coverage]').textContent.trim()")
            self.assertEqual(shown, row[lang], lang)
            self.assertEqual(self.send_tip(), tip_row[lang], lang)           # the tip is a title attribute: the page translates it too
            if lang == "ar":
                self.assertEqual(self.page.evaluate("() => document.documentElement.dir"), "rtl")
            self.fits(f"the host's CVE view in {lang}", "cve-detail-modal")
            self.page.evaluate("() => closeModal('cve-detail-modal')")


class TestTheSoftwareSearch(_Page):
    def test_the_search_finds_the_windows_and_the_mac_by_a_name_in_any_case(self):
        self.page.evaluate("showPage('patches')")
        self.page.wait_for_timeout(1500)
        self.page.evaluate("() => { const b = document.querySelector('[data-pg-tab-btn=\"software\"]'); if (b) b.click(); }")
        self.page.fill("#inv-q", "GOOGLE CHROME")
        self.page.evaluate("() => runInventorySearch()")
        self.page.wait_for_function("() => document.querySelectorAll('#inv-results tbody tr').length >= 2", timeout=30000)
        rows = self.page.evaluate("() => [...document.querySelectorAll('#inv-results tbody tr')].map(tr => [...tr.cells].map(c => c.textContent))")
        self.assertIn(["design-win11", "Google Chrome", "120.0.6099.109"], rows)
        self.assertIn(["mette-macbook", "Google Chrome", "120.0.6099.129"], rows)
        self.fits("the software inventory search")
        # a dotted version is a number: 14.38 is above 14.9
        self.page.fill("#inv-q", "visual c++")
        self.page.select_option("#inv-op", "lt")
        self.page.fill("#inv-version", "14.9")
        self.page.evaluate("() => runInventorySearch()")
        self.page.wait_for_function("() => document.getElementById('inv-results').textContent.includes('No hosts have a matching package')", timeout=30000)



class TestInstallOnAWindowsHost(_Page):
    """Install, uninstall and hold are commands for Linux hosts. Aimed at a Windows host they queue nothing, and the page says
    so: an error that names the reason, a dialog that stays open, and a job that lists the host as skipped, in a sentence."""
    ONLY_LINUX = "Install, uninstall and hold run on Linux hosts only. Nothing was queued."
    SKIPPED = "Skipped: not a Linux host"

    def expect_refusal_of_install(self):
        """The 400 of /api/install is the expected answer: take it, and the line the browser writes to the console for any
        4xx, out of what the teardown counts as a failure, once both are seen to be there."""
        failed = _STACK["problems"]["failed"]
        refused = [f for f in failed if f.startswith("400 ") and f.endswith("/api/install")]
        self.assertTrue(refused, failed)
        failed[:] = [f for f in failed if f not in refused]
        console = _STACK["problems"]["console"]
        logged = [c for c in console if "status of 400" in c]
        self.assertEqual(len(logged), len(refused), console)
        console[:] = [c for c in console if c not in logged]

    def toasts(self):
        return self.page.evaluate("() => [...document.querySelectorAll('#toast-container .toast')].map(t => ({cls: t.className, text: t.textContent}))")

    def tearDown(self):
        try:
            self.page.evaluate("() => { if (window.__confirm) { window.uiConfirm = window.__confirm; window.__confirm = null; } try { closeModal('one-time-install-modal'); } catch (e) {} }")
        except Exception:
            pass
        super().tearDown()

    def test_the_one_time_install_dialog_stays_open_and_the_toast_says_why_once(self):
        self.page.evaluate("showPage('rollouts')")
        self.page.wait_for_timeout(1500)
        self.page.evaluate("() => openInstallModal()")
        self.page.fill("#oti-pkgs", "htop")
        self.page.evaluate("id => { document.getElementById('oti-device').value = id; }", WIN)
        self.assertEqual(self.page.evaluate("() => document.getElementById('oti-device').value"), WIN)      # control: the host is picked
        self.page.evaluate("() => { window.__confirm = window.uiConfirm; window.uiConfirm = async () => true; "
                           "document.querySelectorAll('#toast-container .toast').forEach(t => t.remove()); }")
        self.page.evaluate("() => runOneTimeInstall()")
        self.page.wait_for_timeout(600)
        shown = self.toasts()
        self.expect_refusal_of_install()
        self.assertEqual([t for t in shown if "success" in t["cls"]], [], shown)
        said = [t for t in shown if self.ONLY_LINUX in t["text"]]
        self.assertEqual(len(said), 1, shown)                                  # said once: api() toasts it and the page stays quiet
        self.assertIn("error", said[0]["cls"])
        self.assertTrue(self.page.evaluate("() => !!document.querySelector('#one-time-install-modal.active')"))      # still open

    def test_the_job_lists_the_host_as_skipped_in_a_sentence_in_three_languages(self):
        from test_v710_i18n_glue import dict_rows
        body = self.page.evaluate("async id => await api('POST', '/install', {device_ids: [id], packages: 'htop'})", WIN)
        self.expect_refusal_of_install()
        self.assertEqual(body["error"], self.ONLY_LINUX)
        self.assertEqual(body["per_device"][WIN]["reason"], "unsupported")
        self.page.evaluate("showPage('rollouts')")
        self.page.wait_for_timeout(1500)
        self.page.evaluate("id => { _batchExpanded.add(String(id)); return loadBatchJobs(); }", body["job_id"])
        selector = "#batch-detail-%s .batch-host" % body["job_id"]
        self.page.wait_for_function("sel => document.querySelectorAll(sel).length >= 1 && !document.querySelector(sel + ' .skeleton')",
                                    arg=selector, timeout=30000)
        row = self.page.evaluate("sel => [...document.querySelectorAll(sel)].map(r => r.textContent.trim())[0]", selector)
        self.assertIn("design-win11", row)                                      # control: the row is the host of the request
        self.assertIn(self.SKIPPED, row)
        self.assertNotIn("unsupported", row)
        words = dict_rows()[self.SKIPPED]
        self.assertEqual(sorted(words), ["ar", "de", "es", "fr", "hi", "zh"])
        self.fits("the Rollouts job list")
        for lang in ("de", "ar"):
            self.set_language(lang)
            self.page.wait_for_timeout(800)
            row = self.page.evaluate("sel => [...document.querySelectorAll(sel)].map(r => r.textContent.trim())[0]", selector)
            self.assertIn("design-win11", row)
            self.assertNotIn(self.SKIPPED, row, lang)
            self.assertIn(words[lang], row, lang)
            if lang == "ar":
                self.assertEqual(self.page.evaluate("() => document.documentElement.dir"), "rtl")
            self.fits(f"the Rollouts job list in {lang}")

if __name__ == "__main__":
    unittest.main()
