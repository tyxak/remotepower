#!/usr/bin/env python3
"""8.0.2: accepting a host on the CVE page, in a browser on the demo seed.

tests/test_v802_cve_host_accept.py holds the server's side (the numbers, a finding two hosts share, tenancy, the index). This file holds what a person presses and reads: Accept host in
a host's view opens a dialog that asks for a reason, the view then says the host is accepted and since when, who and why, every finding it listed says it is accepted, the page counts the
host out of its tiles and marks its row, a finding that comes after is marked New and counts, Stop accepting counts the findings again, a viewer who tries is told no, and every word has a
translation.

The demo seed holds the data: its host pmx01 lists ten findings and has 648 vulnerabilities counted per package. Self-skips without playwright / Chromium / gunicorn, and runs under
the default storage backend only.
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
except ImportError:                                     # pragma: no cover
    sync_playwright = None

_STATE = {}
LANGS = ("zh", "hi", "es", "ar", "de", "fr")
INIT = "try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); %s } catch (e) {}"
HOST, NAME = "pmx01", "proxmox.lab"
ROW = 'tr[data-action="openDeviceCVE"][data-arg="%s"]' % HOST
BODY = "#cve-detail-body"


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("the view is backend-agnostic: measured once, under the default backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-hostaccept-e2e-")
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
        d = _STATE.get("data_dir")
        if d:
            import shutil
            shutil.rmtree(d, ignore_errors=True)                  # the seeded instance is tmpfs


def _path(name):
    return Path(_STATE["data_dir"]) / name


def read(name):
    return json.loads(_path(name).read_text()) if _path(name).exists() else {}


def write(name, doc):
    # a file of the data directory that is written twice in the same second can be read by the server as the first version (its cache looks at the modification time),
    # so every write is given a modification time two seconds after the one it replaces
    tmp = _path(name).with_suffix(".tmp")
    tmp.write_text(json.dumps(doc))
    before = _path(name).stat().st_mtime if _path(name).exists() else 0
    stamp = max(before + 2, time.time())
    os.utime(tmp, (stamp, stamp))
    os.replace(tmp, _path(name))


def _login(page, user="alice", password="demo"):
    page.goto(_STATE["base"] + "/index.html")
    page.fill("#login-user", user)                        # the seeder builds its own accounts: there is no 'admin'
    page.fill("#login-pass", password)
    page.click('#login-form button[type="submit"]')
    page.wait_for_selector("#app", state="visible", timeout=90000)
    page.wait_for_timeout(3500)


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestAcceptingAHostInTheBrowser(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        ctx = _STATE["browser"].new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
        ctx.add_init_script(INIT % "")
        cls.ctx, cls.page, cls.errors, cls.requests = ctx, ctx.new_page(), [], []
        cls.page.on("pageerror", lambda e: cls.errors.append(str(e)))
        cls.page.on("request", lambda r: cls.requests.append((r.method, r.url.split("/api", 1)[-1], r.post_data)))
        _login(cls.page)
        cls.findings0, cls.devices0 = read("cve_findings.json"), read("devices.json")

    @classmethod
    def tearDownClass(cls):
        try:
            write("cve_findings.json", cls.findings0)
            write("devices.json", cls.devices0)
            write("cve_ignore.json", {})
        finally:
            cls.ctx.close()

    def setUp(self):
        write("cve_findings.json", self.findings0)
        write("devices.json", self.devices0)
        write("cve_ignore.json", {})
        del self.requests[:]

    def tearDown(self):
        self.page.evaluate("""() => {
          document.querySelectorAll('.modal-overlay.active').forEach(m => closeModal(m.id));
          try { localStorage.removeItem('pgtab.cve'); } catch (e) {}
        }""")

    # ── helpers ──────────────────────────────────────────────────────────────

    def open_cve(self):
        self.page.evaluate("() => showPage('cve')")
        self.page.wait_for_selector('#cve-tbody tr[data-action="openDeviceCVE"]', timeout=30000)

    def reload_the_page_data(self):
        self.page.evaluate("async () => { await loadCVEReport(); }")
        self.page.wait_for_selector('#cve-tbody tr[data-action="openDeviceCVE"]', timeout=30000)

    def summary(self):
        return self.page.evaluate("async () => (await api('GET', '/cve/findings')).summary")

    def host_row(self):
        return self.page.evaluate("async (h) => (await api('GET', '/cve/findings')).devices.find(d => d.device_id === h)", HOST)

    def open_host(self):
        self.open_cve()
        self.page.click(ROW)
        self.page.wait_for_selector(BODY + ' [data-action-btn="_sbomDeviceBtn"]', timeout=30000)

    def accept_through_the_api(self, reason="a lab box"):
        r = self.page.evaluate("async ([h, why]) => await api('POST', '/devices/' + h + '/cve/accept', {reason: why})", [HOST, reason])
        self.assertTrue(r and r.get("ok"), r)
        return r

    def add_a_new_finding(self):
        doc = json.loads(json.dumps(self.findings0))
        first = doc[HOST]["findings"][0]
        doc[HOST]["findings"].append(dict(first, vuln_id="CVE-2026-99999", severity="critical", summary="found after the host was accepted", kev=False))
        write("cve_findings.json", doc)

    def text(self, selector):
        return " ".join(self.page.inner_text(selector).split())

    # ── the dialog, the view and the page ────────────────────────────────────

    def test_accepting_asks_for_a_reason_and_the_view_says_since_when_who_and_why(self):
        self.open_host()
        n = len(self.findings0[HOST]["findings"])
        self.assertEqual(n, 10, "control: the demo host lists ten findings")
        self.assertEqual(self.page.eval_on_selector_all(BODY + ' [data-action="cveUnacceptHost"]', "els => els.length"), 0, "an accepted host has the other buttons, this one has Accept host")
        self.page.click(BODY + ' [data-action="cveAcceptHost"]')
        self.page.wait_for_selector("#cve-accept-modal.active", timeout=30000)
        self.assertEqual(self.page.inner_text("#cve-accept-host"), NAME)
        self.assertEqual(self.page.input_value("#cve-accept-reason"), "")
        self.page.fill("#cve-accept-reason", "the lab box, retired in March")
        self.page.click("#cve-accept-confirm")
        self.page.wait_for_selector(BODY + ' [data-action="cveUnacceptHost"]', timeout=30000)
        banner = self.text(BODY)
        self.assertIn("Host accepted", banner)
        self.assertIn("Reason: the lab box, retired in March", banner)
        self.assertIn("by alice", banner)
        self.assertIn("Accepted findings: %d" % n, banner)
        self.assertEqual(self.page.eval_on_selector_all(BODY + " .is-ignored", "els => els.length"), n, "every finding the host listed says it is accepted")
        self.assertIn("(ignored: the lab box, retired in March)", banner)
        (post,) = [r for r in self.requests if r[0] == "POST" and r[1].endswith("/cve/accept")]
        self.assertEqual((post[1], json.loads(post[2])), ("/devices/%s/cve/accept" % HOST, {"reason": "the lab box, retired in March"}))
        self.assertEqual(self.page.eval_on_selector_all(BODY + ' [data-action="cveAcceptNew"]', "els => els.length"), 1, "and the host can be accepted again for what is new")

    def test_the_page_counts_the_host_out_of_its_tiles_and_marks_its_row_and_says_how_many_are_left_out(self):
        self.open_cve()
        before, row0 = self.summary(), self.host_row()
        self.assertGreater(sum(row0["counts"][k] for k in ("critical", "high", "medium", "low")), 0, "control: the host counted something")
        self.assertEqual(self.page.eval_on_selector("#cve-accepted-note", "e => e.hidden"), True, "nothing is accepted yet, so the page says nothing of it")
        self.accept_through_the_api()
        self.reload_the_page_data()
        after, row = self.summary(), self.host_row()
        for k in ("critical", "high", "medium", "low"):
            self.assertEqual(after[k], before[k] - row0["counts"][k], k)
        self.assertEqual((after["accepted_hosts"], after["accepted_findings"]), (1, 10))
        self.assertEqual(after["rollup"], before["rollup"] - 648, "what its scan counted per package is left out of the line under the tiles")
        self.assertEqual((row["counts"]["critical"], row["accepted"]["n"], row["accepted_new"]), (0, 10, 0))
        held = self.page.evaluate("() => ({critical: cveReportData.summary.critical, accepted_hosts: cveReportData.summary.accepted_hosts, rollup: cveReportData.summary.rollup})")
        self.assertEqual(held, {"critical": after["critical"], "accepted_hosts": 1, "rollup": after["rollup"]}, "the page holds the new numbers (the tiles animate towards them)")
        self.assertIn("Host accepted", self.text(ROW), "the row is marked")
        self.assertNotIn("New", self.text(ROW).replace("Host accepted", ""), "and nothing on it is new")
        self.assertFalse(self.page.eval_on_selector("#cve-accepted-note", "e => e.hidden"))
        self.assertEqual(self.text("#cve-accepted-note"), "Accepted hosts, left out of the numbers above: 1 · Findings accepted on them: 10")

    def test_a_finding_that_comes_after_counts_and_is_marked_new_on_the_row_and_in_the_view(self):
        self.open_cve()
        self.accept_through_the_api("lab box")
        before = self.summary()
        self.add_a_new_finding()
        self.reload_the_page_data()
        after, row = self.summary(), self.host_row()
        self.assertEqual((after["critical"], row["counts"]["critical"], row["accepted_new"]), (before["critical"] + 1, 1, 1))
        self.assertIn("New 1", self.text(ROW), "the row says one finding is new")
        self.page.click(ROW)
        self.page.wait_for_selector(BODY + ' [data-action="cveUnacceptHost"]', timeout=30000)
        cards = self.page.eval_on_selector_all(BODY + " .is-ignored", "els => els.length")
        self.assertEqual(cards, 10, "the ten it was accepted with still say so")
        new = self.page.eval_on_selector_all(BODY + " code", "els => els.map(e => e.textContent).filter(t => t === 'CVE-2026-99999')")
        self.assertEqual(new, ["CVE-2026-99999"])
        self.assertEqual(self.page.evaluate("() => [...document.querySelectorAll('#cve-detail-body .status-pill.warn')].map(e => e.textContent.trim())"), ["New"], "one finding is marked New")

    def test_stopping_counts_the_findings_again_and_the_view_goes_back_to_accept_host(self):
        self.open_cve()
        before = self.summary()
        self.accept_through_the_api()
        self.open_host()
        self.page.click(BODY + ' [data-action="cveUnacceptHost"]')
        self.page.wait_for_selector("#ui-prompt-modal.active", timeout=30000)
        self.assertIn("Stop accepting this host? Its findings will count again.", self.text("#ui-prompt-message"))
        self.page.click("#ui-prompt-confirm")
        self.page.wait_for_selector(BODY + ' [data-action="cveAcceptHost"]', timeout=30000)
        self.assertEqual(self.page.eval_on_selector_all(BODY + " .is-ignored", "els => els.length"), 0)
        self.assertNotIn("Host accepted", self.text(BODY))
        after = self.summary()
        for k in ("critical", "high", "medium", "low", "kev", "rollup"):
            self.assertEqual(after[k], before[k], k)
        self.assertEqual(after["accepted_hosts"], 0)
        records = [r for v in read("cve_ignore.json").values() for r in ([v] + (v.get("others") or [])) if isinstance(v, dict)]
        self.assertEqual(records, [], "the records are gone")
        self.assertNotIn("cve_accepted", read("devices.json")[HOST])

    def open_ignored_items(self):
        self.page.evaluate("() => showPage('settings')")
        self.page.wait_for_selector("#settings-tab-btn-ignored", state="visible", timeout=30000)
        self.page.click("#settings-tab-btn-ignored")
        # drawn afresh and awaited: the page is the same one for every test, and the list of the test before is still on it until the answer of this one arrives
        self.page.evaluate("async () => { await loadIgnoredItems(); }")
        self.page.wait_for_function("() => document.getElementById('ignored-items-list').textContent.includes('Accepted hosts')", timeout=30000)

    def accepted_block(self):
        """The text of the Accepted hosts block of Settings → Ignored items: its heading and each row."""
        return self.page.evaluate("""() => {
          const h = [...document.querySelectorAll('#ignored-items-list h4')].find(e => e.textContent.trim().startsWith('Accepted hosts'));
          if (!h) return null;
          const block = h.closest('.mb-16');
          return {heading: h.textContent.replace(/\\s+/g, ' ').trim(),
                  rows: [...block.querySelectorAll('.isl-669')].map(e => e.innerText.replace(/\\s+/g, ' ').trim()),
                  none: [...block.querySelectorAll('.isl-616')].map(e => e.textContent.trim()),
                  buttons: [...block.querySelectorAll('[data-action="cveUnacceptFromList"]')].map(e => [e.textContent.trim(), e.getAttribute('data-arg')])};
        }""")

    def test_settings_lists_the_accepted_hosts_and_stop_accepting_takes_one_off_the_list(self):
        self.open_ignored_items()
        block = self.accepted_block()
        self.assertEqual((block["heading"], block["rows"], block["none"]), ("Accepted hosts (0)", [], ["— none —"]), "nothing is accepted yet")
        self.accept_through_the_api("the lab box, retired in March")
        n = len(self.findings0[HOST]["findings"])
        self.open_ignored_items()
        block = self.accepted_block()
        self.assertEqual(block["heading"], "Accepted hosts (1)")
        (row,) = block["rows"]
        self.assertTrue(row.startswith(NAME), row)
        self.assertIn("Host accepted", row)
        self.assertIn("by alice", row)
        self.assertIn("Accepted findings: %d" % n, row)
        self.assertIn("“the lab box, retired in March”", row)
        self.assertEqual(block["buttons"], [["Stop accepting", "dev-" + HOST]], "one button, with the id of the host behind the prefix that keeps it text")
        self.assertEqual(block["none"], [])
        # the dictionary: the heading is in all six languages
        self.page.evaluate("async () => { await _ensureI18n(); }")
        english = self.page.evaluate("() => [...document.querySelectorAll('#ignored-items-list h4')].find(e => e.textContent.trim().startsWith('Accepted hosts')).firstChild.textContent.trim()")
        self.assertEqual(english, "Accepted hosts")
        bad = []
        try:
            for lang in LANGS:
                self.page.evaluate("(l) => RPi18n.setLang(l, false)", lang)
                self.page.wait_for_timeout(300)
                now = self.page.evaluate("() => [...document.querySelectorAll('#ignored-items-list h4')].map(e => e.firstChild.textContent.trim()).filter(t => !['Needs Attention', 'Stale containers', 'Ignored CVEs', 'Cleared log lines'].includes(t))")
                if english in now:
                    bad.append(lang)
        finally:
            self.page.evaluate("() => RPi18n.setLang('en', false)")
        self.assertEqual(bad, [], "the heading is not translated in these languages")
        del self.requests[:]
        self.page.click('#ignored-items-list [data-action="cveUnacceptFromList"]')
        self.page.wait_for_selector("#ui-prompt-modal.active", timeout=30000)
        self.assertIn("Stop accepting this host? Its findings will count again.", self.text("#ui-prompt-message"))
        self.page.click("#ui-prompt-confirm")
        self.page.wait_for_function("() => document.getElementById('ignored-items-list').textContent.includes('Accepted hosts (0)')", timeout=30000)
        block = self.accepted_block()
        self.assertEqual((block["rows"], block["none"]), ([], ["— none —"]))
        posts = [r for r in self.requests if r[0] == "POST"]
        self.assertEqual([(r[1], r[2]) for r in posts], [("/devices/%s/cve/unaccept" % HOST, "{}")], "the host's own route, with nothing else")
        records = [r for v in read("cve_ignore.json").values() for r in ([v] + (v.get("others") or [])) if isinstance(v, dict)]
        self.assertEqual(records, [], "the records are gone")
        self.assertNotIn("cve_accepted", read("devices.json")[HOST])
        self.assertEqual(self.summary()["accepted_hosts"], 0, "and the page counts the findings again")

    def test_declining_the_question_leaves_the_host_accepted(self):
        self.accept_through_the_api()
        self.open_ignored_items()
        self.assertEqual(self.accepted_block()["heading"], "Accepted hosts (1)")
        del self.requests[:]
        self.page.click('#ignored-items-list [data-action="cveUnacceptFromList"]')
        self.page.wait_for_selector("#ui-prompt-modal.active", timeout=30000)
        self.page.click('#ui-prompt-modal [data-action="_uiPromptCancel"]')
        self.page.wait_for_function("() => !document.getElementById('ui-prompt-modal').classList.contains('active')", timeout=30000)
        self.assertEqual([r for r in self.requests if r[0] == "POST"], [], "nothing was sent")
        self.assertEqual(self.accepted_block()["heading"], "Accepted hosts (1)")
        self.assertIn("cve_accepted", read("devices.json")[HOST])

    def test_a_viewer_who_tries_is_told_no_and_nothing_is_written(self):
        ctx = _STATE["browser"].new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
        ctx.add_init_script(INIT % "")
        page = ctx.new_page()
        try:
            _login(page, "demo", "demo")
            page.evaluate("() => showPage('cve')")
            page.wait_for_selector(ROW, timeout=30000)
            page.click(ROW)
            page.wait_for_selector(BODY + ' [data-action="cveAcceptHost"]', timeout=30000)
            page.click(BODY + ' [data-action="cveAcceptHost"]')
            page.wait_for_selector("#cve-accept-modal.active", timeout=30000)
            page.click("#cve-accept-confirm")
            page.wait_for_selector(".toast.error", timeout=30000)
            self.assertTrue(page.eval_on_selector("#cve-accept-modal", "e => e.classList.contains('active')"), "the dialog stays open: nothing was accepted")
            self.assertEqual(page.eval_on_selector_all(BODY + " .is-ignored", "els => els.length"), 0)
        finally:
            ctx.close()
        self.assertEqual(read("cve_ignore.json"), {})
        self.assertNotIn("cve_accepted", read("devices.json")[HOST])

    def test_every_word_of_it_is_translated_in_all_six_languages(self):
        self.open_host()
        self.page.evaluate("async () => { await _ensureI18n(); }")
        grab_dialog = """() => ({
          title: document.getElementById('cve-accept-modal-title').textContent.trim(),
          sub: document.querySelector('#cve-accept-modal .modal-subtitle').textContent.trim(),
          label: [...document.querySelectorAll('#cve-accept-modal label span')].map(e => e.textContent.trim())[0],
          placeholder: document.getElementById('cve-accept-reason').getAttribute('placeholder'),
          confirm: document.getElementById('cve-accept-confirm').textContent.trim(),
          button: document.querySelector('#cve-detail-body [data-action="cveAcceptHost"]').textContent.trim(),
        })"""
        self.page.click(BODY + ' [data-action="cveAcceptHost"]')
        self.page.wait_for_selector("#cve-accept-modal.active", timeout=30000)
        english = self.page.evaluate(grab_dialog)
        self.assertTrue(all(english.values()), english)
        bad = []
        try:
            for lang in LANGS:
                self.page.evaluate("(l) => RPi18n.setLang(l, false)", lang)
                self.page.wait_for_timeout(300)
                now = self.page.evaluate(grab_dialog)
                bad += [(lang, "dialog", k) for k, v in english.items() if now[k] == v]
        finally:
            self.page.evaluate("() => RPi18n.setLang('en', false)")
        self.assertEqual(bad, [])
        self.page.evaluate("() => closeModal('cve-accept-modal')")
        self.accept_through_the_api("lab box")
        self.page.evaluate("async () => { await openDeviceCVE('%s', '%s'); await loadCVEReport(); }" % (HOST, NAME))
        self.page.wait_for_selector(BODY + ' [data-action="cveUnacceptHost"]', timeout=30000)
        grab_view = """() => ({
          heading: document.querySelector('#cve-detail-body > div.mb-14 > strong').textContent.trim(),
          findings: [...document.querySelectorAll('#cve-detail-body .hint > span')].map(e => e.textContent.trim()).filter(t => t.startsWith('Accepted findings') || t.startsWith('A finding')).join(' | '),
          again: document.querySelector('#cve-detail-body [data-action="cveAcceptNew"]').textContent.trim(),
          stop: document.querySelector('#cve-detail-body [data-action="cveUnacceptHost"]').textContent.trim(),
          pill: document.querySelector('#cve-tbody tr[data-arg="%s"] .status-pill.info').textContent.trim(),
          note: document.querySelector('#cve-accepted-note > span').textContent.trim(),
        })""" % HOST
        english = self.page.evaluate(grab_view)
        self.assertTrue(all(english.values()), english)
        try:
            for lang in LANGS:
                self.page.evaluate("(l) => RPi18n.setLang(l, false)", lang)
                self.page.wait_for_timeout(300)
                now = self.page.evaluate(grab_view)
                bad += [(lang, "view", k) for k, v in english.items() if now[k] == v]
        finally:
            self.page.evaluate("() => RPi18n.setLang('en', false)")
        self.assertEqual(bad, [])

    def test_nothing_in_the_page_broke_on_the_way(self):
        self.open_host()
        self.assertEqual([e for e in self.errors if "Failed to load resource" not in e], [])


if __name__ == "__main__":
    unittest.main()
