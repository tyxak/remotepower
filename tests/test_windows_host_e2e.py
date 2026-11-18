#!/usr/bin/env python3
"""The pages that show what a Windows host reports about itself, in a browser, over the seeded demo: the Windows Update search and the definition
updates, the build, the file shares and the TPM.

The server side and the page functions are held in test_windows_update_search, test_windows_build, test_windows_shares_tpm and their views modules.
What those cannot show is the page: that the words come out in the right place, that nothing runs past the edge of a narrow screen, that a language that
is written right to left lays out, that a control can be reached from the keyboard and shows where it is, and that the pages ask the server for nothing
that fails.

The demo's Windows host (design-win11) is given what its agent now sends. The agent's own functions read a registry stand-in and parse canned PowerShell
answers, the server's own functions clean the result, and that is what is written to the store: the same dictionaries the heartbeat would have stored.
A second Windows host (design-win10) is a copy whose search failed five days ago, with another build and no TPM.

Elements measured: the OS text of the Hosts list (table and cards), the host drawer (OS, Shares and TPM pills, the share chips, the Packages card with its
definition-updates pill and its search line), the patch report of a host, the Checks page row, and the three new Fleet Query criteria.

A control checks that each page rendered the host it is about before anything is measured, so a page that failed to draw cannot pass by having nothing on
it. Self-skips without playwright, chromium and gunicorn.
"""
import copy
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
for p in (_HERE, _ROOT / "server" / "cgi-bin"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import browser_required  # noqa: E402
import win_host_support as S  # noqa: E402
import windows_host as wh  # noqa: E402

try:
    from playwright.sync_api import sync_playwright
except ImportError:                                     # pragma: no cover
    sync_playwright = None

from e2e_harness import SKIP_REASON, browser_available  # noqa: E402

_GATE = browser_available() or browser_required.required()
_STACK = {}
WIN11, WIN10 = "wks01", "wks02"
WIDTHS = (1440, 768, 390)

SHARES = json.dumps([
    {"name": "ADMIN$", "path": "C:\\Windows", "description": "Remote Admin", "encrypted": False},
    {"name": "C$", "path": "C:\\", "description": "Default share", "encrypted": False},
    {"name": "Data", "path": "D:\\Data", "description": "Team data", "encrypted": True},
    {"name": "IPC$", "path": "", "description": "Remote IPC", "encrypted": False},
    {"name": "Public", "path": "C:\\Public", "description": "", "encrypted": False},
    {"name": "Scans", "path": "D:\\Scans with a very long folder name that has to wrap\\and go on", "description": "Scanner drop", "encrypted": False},
])
PENDING = ["2024-05 Cumulative Update for Windows 11 Version 23H2 for x64-based Systems (KB5037771)",
           "2024-04 .NET 8.0.4 Security Update for x64 Client (KB5036620)",
           "Update for Microsoft Defender Antivirus antimalware platform - KB4052623 (Version 4.18.24040.4)"]


def _prepare(data_dir):
    import importlib.util
    spec = importlib.util.spec_from_file_location("rp_win_e2e_agent", S.WIN_AGENT)
    agent = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(agent)
    path = Path(data_dir) / "devices.json"
    devices = json.loads(path.read_text())
    now = int(time.time())

    def build_of(values):
        with mock.patch.dict(sys.modules, {"winreg": S.FakeWinreg({S.NT_KEY: values})}):
            return wh.clean_win_build(agent.get_win_build())

    win = devices[WIN11]
    si = win.setdefault("sysinfo", {})
    si["win_build"] = build_of(S.nt_values())
    si["shares"] = wh.clean_shares(agent._parse_smb_shares(SHARES))
    si["tpm"] = wh.clean_tpm(agent._parse_tpm(json.dumps({"present": True, "ready": True, "enabled": True, "spec": "2.0, 0, 1.59"})))
    si["packages"] = {"manager": "windows-update", "upgradable": 3, "upgradable_names": PENDING, "definition_updates": 2, "security_updates": None}
    si["pkg_scan_ts"] = now - 720
    si["wu_search"] = wh.clean_search_state({"at": now - 720, "ok": True, "source": "windows-update-agent", "error_class": ""}, now)

    other = copy.deepcopy(win)
    other.update(name="design-win10", hostname="design-win10", os="Windows 10 (Build 19045)", ip="10.0.3.11", mac="52:54:00:11:03:11")
    if "id" in other:
        other["id"] = WIN10
    osi = other["sysinfo"]
    osi["win_build"] = build_of(S.nt_values(CurrentBuildNumber=("19045", S.SZ), CurrentBuild=("19045", S.SZ), UBR=(4291, S.DWORD),
                                            DisplayVersion=("22H2", S.SZ), ProductName=("Windows 10 Pro", S.SZ)))
    osi.pop("shares", None)
    osi["tpm"] = wh.clean_tpm(agent._parse_tpm(json.dumps({"present": False, "ready": False, "enabled": False})))
    osi["packages"] = {"manager": "windows-update", "upgradable": 5, "upgradable_names": PENDING, "definition_updates": 0, "security_updates": None}
    osi["pkg_scan_ts"] = now - 5 * 86400
    prev = {"wu_search": {"at": now - 5 * 86400, "ok": True, "ok_at": now - 5 * 86400, "fail_since": 0}}
    osi["wu_search"] = wh.clean_search_state({"at": now - 600, "ok": False, "source": "wsus", "error_class": "access"}, now, prev)
    devices[WIN10] = other
    path.write_text(json.dumps(devices))


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("what is measured is the page, not the backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-winhost-e2e-")
    proc = subprocess.run([sys.executable, str(seeder), "--data-dir", data_dir, "--apply"], capture_output=True, cwd=str(_ROOT), timeout=900)
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
  const drawer = document.getElementById('device-drawer');
  out.drawer = (drawer && drawer.classList.contains('open')) ? drawer.scrollWidth - drawer.clientWidth : null;
  return out;
}"""
RING = """() => { const cs = getComputedStyle(document.activeElement);
  return {id: document.activeElement.id, outline: cs.outlineStyle !== 'none' && parseFloat(cs.outlineWidth) >= 1,
          shadow: cs.boxShadow !== 'none', border: cs.borderColor}; }"""


@unittest.skipUnless(_GATE, SKIP_REASON)
class _Page(unittest.TestCase):
    @property
    def page(self):
        return _STACK["page"]

    def setUp(self):
        _STACK["problems"].update(console=[], page=[], failed=[])
        self.page.evaluate("() => { if (window.RPi18n) RPi18n.setLang('en', false); }")
        self.page.set_viewport_size({"width": 1440, "height": 900})

    def tearDown(self):
        try:
            self.page.evaluate("() => { try { closeModal('device-patch-modal'); } catch (e) {} try { closeDeviceDrawer(); } catch (e) {} }")
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
        """No horizontal overflow at the three widths: of the page, of the open dialog and of the open drawer."""
        for width in WIDTHS:
            self.page.set_viewport_size({"width": width, "height": 900})
            self.page.wait_for_timeout(250)
            got = self.page.evaluate(OVERFLOW, modal_id)
            self.assertLessEqual(got["page"], 1, f"{label} at {width}px runs {got['page']}px past the edge")
            if modal_id:
                self.assertIsNotNone(got["modal"], f"{label}: the dialog {modal_id} was not open to measure")
                self.assertLessEqual(got["modal"], 1, f"{label} (dialog) at {width}px")
            if got["drawer"] is not None:
                self.assertLessEqual(got["drawer"], 1, f"{label} (drawer) at {width}px")
        self.page.set_viewport_size({"width": 1440, "height": 900})

    def open_drawer(self, host, name, section):
        """The host drawer on the Audit tab with one section open and loaded."""
        self.page.evaluate("([id, name]) => openDeviceDrawer(id, name, 'audit')", [host, name])
        self.page.wait_for_selector(f"#audit-sec-{section}", timeout=30000)
        self.page.evaluate("s => { const d = document.getElementById('audit-sec-' + s); d.open = true; }", section)
        self.page.wait_for_function(
            "s => { const b = document.getElementById('audit-body-' + s); return b && b.textContent.trim().length > 5 && !b.querySelector('.skeleton'); }",
            arg=section, timeout=30000)

    def pills(self):
        return self.page.evaluate("""() => Object.fromEntries([...document.querySelectorAll('#audit-body-sysinfo .sysinfo-pill')]
            .map(p => [p.querySelector('.label').textContent, p.querySelector('.value').textContent]))""")

    def search_line(self):
        """The line of the Packages card that says how the last Windows Update search went: its text and whether it is amber. (The Upgradable pill
        is amber whenever something is pending, so a query for amber in the card would find that one.)"""
        return self.page.evaluate("""() => { const d = [...document.querySelectorAll('#audit-body-packages div')]
            .find(x => x.textContent.trim().startsWith('Last search'));
          return d ? {text: d.textContent.replace(/\\s+/g, ' ').trim(), amber: d.classList.contains('c-amber')} : {text: '', amber: false}; }""")


class TestTheMeasure(_Page):
    def test_a_box_wider_than_the_screen_is_seen_by_the_measure(self):
        """The control: a measure that cannot see overflow would pass every page below it."""
        self.page.evaluate("showPage('devices')")
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

    def test_the_focus_measure_sees_a_ring_and_the_lack_of_one(self):
        self.page.evaluate("showPage('query')")
        self.page.wait_for_selector("#fq-os", timeout=30000)
        self.page.evaluate("() => document.querySelectorAll('#fq-groups details').forEach(d => d.open = true)")
        self.page.focus("#fq-os")
        self.page.keyboard.press("Tab")
        ring = self.page.evaluate(RING)
        self.assertTrue(ring["outline"] or ring["shadow"], ring)
        self.page.evaluate("""() => { const s = document.createElement('style'); s.id = 'e2e-noring';
            s.textContent = '*,*:focus,*:focus-visible{outline:none!important;box-shadow:none!important}'; document.head.appendChild(s); }""")
        try:
            self.page.focus("#fq-os")
            ring = self.page.evaluate(RING)
            self.assertFalse(ring["outline"] or ring["shadow"], "with every ring removed the measure still found one")
        finally:
            self.page.evaluate("() => { const s = document.getElementById('e2e-noring'); if (s) s.remove(); }")


class TestTheHostsList(_Page):
    NAMES = ".dev-name-cell, .device-card .device-name, .device-row .device-name"

    BOTH = ("design-win10", "design-win11")

    def hosts_page(self, search="design-win", shows=BOTH, hides=("nginx.lab",)):
        """The Hosts list narrowed by the search box (the table shows the first rows of the whole fleet, and the Windows hosts are not among them),
        once a row of each name in `shows` is on the page and none of `hides` is. The page redraws a moment after the box changes, and the rows of
        the search before it satisfy a looser wait, so the names that must be gone are part of it."""
        self.page.evaluate("showPage('devices')")
        self.page.wait_for_selector("#device-search-input", timeout=60000)
        self.page.fill("#device-search-input", search)
        self.page.wait_for_function(
            """([sel, shows, hides]) => { const names = [...document.querySelectorAll(sel)].map(n => n.textContent);
                 return shows.every(s => names.some(n => n.includes(s))) && !hides.some(h => names.some(n => n.includes(h))); }""",
            arg=[self.NAMES, list(shows), list(hides)], timeout=60000)

    def tearDown(self):
        try:
            self.page.fill("#device-search-input", "")
        except Exception:
            pass
        super().tearDown()

    def os_cells(self):
        """{host name: the OS text of its row}, from the table (`.dev-os-cell`) when the page draws one, else from the cards."""
        return self.page.evaluate("""() => {
          const out = {};
          document.querySelectorAll('tr.dev-row').forEach(tr => { const n = tr.querySelector('.dev-name-cell'); const o = tr.querySelector('.dev-os-cell');
            if (n && o) out[n.textContent.trim()] = o.textContent.trim(); });
          document.querySelectorAll('.device-card, .device-row').forEach(c => { const n = c.querySelector('.device-name'); if (!n) return;
            const items = [...c.querySelectorAll('.meta-item')].filter(m => m.querySelector('.meta-label') && m.querySelector('.meta-label').textContent === 'OS');
            if (items.length) out[n.textContent.trim()] = items[0].querySelector('.meta-value').textContent.trim(); });
          return out; }""")

    def test_a_windows_host_shows_the_build_label_and_another_host_shows_its_own_text(self):
        self.hosts_page()
        cells = self.os_cells()
        self.assertTrue(cells, "no host row was found on the page")           # control: the page drew hosts
        win11 = [v for k, v in cells.items() if "design-win11" in k]
        win10 = [v for k, v in cells.items() if "design-win10" in k]
        self.assertEqual(win11, ["Windows 11 Pro 23H2 (build 22631.3593)"], cells)
        self.assertEqual(win10, ["Windows 10 Pro 22H2 (build 19045.4291)"], cells)
        self.hosts_page("nginx.lab", shows=("nginx.lab",), hides=self.BOTH)
        cells = self.os_cells()
        linux = [v for k, v in cells.items() if "nginx.lab" in k]
        self.assertEqual(linux, ["Ubuntu 24.04 LTS"], cells)

    def test_the_search_box_finds_a_host_by_its_display_version(self):
        self.hosts_page("23H2", shows=("design-win11",), hides=("design-win10", "nginx.lab"))
        names = list(self.os_cells())
        self.assertTrue(any("design-win11" in n for n in names), names)
        self.assertFalse(any("design-win10" in n for n in names), "22H2 is not 23H2")
        self.assertFalse(any("nginx.lab" in n for n in names), names)
        self.hosts_page("19045.4291", shows=("design-win10",), hides=("design-win11", "nginx.lab"))
        names = list(self.os_cells())
        self.assertTrue(any("design-win10" in n for n in names), names)
        self.assertFalse(any("design-win11" in n for n in names), names)

    def test_nothing_runs_past_the_edge_of_a_narrow_screen(self):
        self.hosts_page()
        self.fits("the Hosts list")

    def test_it_lays_out_in_german_and_in_arabic(self):
        self.hosts_page()
        for lang in ("de", "ar"):
            self.set_language(lang)
            if lang == "ar":
                self.assertEqual(self.page.evaluate("() => document.documentElement.dir"), "rtl")
            self.assertIn("Windows 11 Pro 23H2 (build 22631.3593)", " ".join(self.os_cells().values()))
            self.fits(f"the Hosts list in {lang}")


class TestTheDrawer(_Page):
    def test_the_windows_11_host_shows_the_os_the_shares_and_the_tpm(self):
        self.open_drawer(WIN11, "design-win11", "sysinfo")
        pills = self.pills()
        self.assertIn("Uptime", pills)                                           # control: the section rendered the host
        self.assertEqual(pills["OS"], "Windows 11 Pro 23H2 (build 22631.3593)")
        self.assertEqual(pills["Shares"], "3 shares · 3 administrative, not listed")
        self.assertEqual(pills["TPM"], "present · ready · spec 2.0")
        chips = self.page.evaluate("""() => [...document.querySelectorAll('#audit-body-sysinfo .scroll-cap-sm .cmd-badge')].map(c => ({
            text: c.textContent.replace(/\\s+/g, ' ').trim(), tip: c.title}))""")
        self.assertEqual([c["text"] for c in chips][:2], ["Data D:\\Data encrypted", "Public C:\\Public"], chips)
        self.assertTrue(chips[0]["tip"].startswith("D:\\Data — Team data"), chips[0])
        self.assertEqual(len(chips), 3, chips)
        self.fits("the System info section of the drawer")

    def test_a_host_with_no_tpm_and_no_shares(self):
        self.open_drawer(WIN10, "design-win10", "sysinfo")
        pills = self.pills()
        self.assertEqual(pills["OS"], "Windows 10 Pro 22H2 (build 19045.4291)")
        self.assertEqual(pills["TPM"], "none")
        self.assertNotIn("Shares", pills)
        self.assertEqual(self.page.evaluate("() => document.querySelectorAll('#audit-body-sysinfo .scroll-cap-sm .cmd-badge').length"), 0)

    def test_the_packages_card_says_how_the_last_search_went_and_counts_the_definition_updates(self):
        self.open_drawer(WIN11, "design-win11", "packages")
        body = self.page.evaluate("() => document.getElementById('audit-body-packages').innerText.replace(/\\s+/g, ' ')")
        self.assertIn("Upgradable 3", body.replace("UPGRADABLE", "Upgradable"))
        text = self.page.evaluate("() => document.getElementById('audit-body-packages').textContent.replace(/\\s+/g, ' ')")
        self.assertRegex(text, r"Definition updates\s*2\b")
        self.assertRegex(text, r"Last search .*ago.*, ok")
        line = self.search_line()
        self.assertTrue(line["text"].startswith("Last search"), line)
        self.assertFalse(line["amber"], "a search that worked is not amber")
        tip = self.page.evaluate("() => document.querySelector('#audit-body-packages [title*=\"Defender\"]').title")
        self.assertEqual(tip, "Defender definition updates are counted here and left out of the pending updates.")
        self.fits("the Packages card of the drawer")

    def test_a_failed_search_is_amber_and_says_how_old_the_count_is(self):
        self.open_drawer(WIN10, "design-win10", "packages")
        text = self.page.evaluate("() => document.getElementById('audit-body-packages').textContent.replace(/\\s+/g, ' ')")
        self.assertRegex(text, r"Last search failed \(access\); count taken 5d ago")
        self.assertIn("WSUS", text)
        self.assertNotIn("Definition updates", text, "a host with no definition updates has no pill")
        line = self.search_line()
        self.assertTrue(line["text"].startswith("Last search failed"), line)
        self.assertTrue(line["amber"], "a search that failed is amber")
        self.fits("the Packages card of a host whose search failed")

    def test_it_reads_in_german_and_in_arabic_and_lays_out_right_to_left(self):
        from test_v710_i18n_glue import dict_rows
        rows = dict_rows()
        self.open_drawer(WIN10, "design-win10", "packages")
        for lang in ("de", "ar"):
            self.set_language(lang)
            text = self.page.evaluate("() => document.getElementById('audit-body-packages').textContent.replace(/\\s+/g, ' ')")
            for phrase in ("Last search failed", "count taken", "access"):
                self.assertIn(rows[phrase][lang], text, (lang, phrase, text))
            if lang == "ar":
                self.assertEqual(self.page.evaluate("() => document.documentElement.dir"), "rtl")
            self.fits(f"the Packages card in {lang}")
        self.open_drawer(WIN11, "design-win11", "sysinfo")
        for lang in ("de", "ar"):
            self.set_language(lang)
            labels = self.page.evaluate("() => [...document.querySelectorAll('#audit-body-sysinfo .sysinfo-pill .label')].map(l => l.textContent)")
            self.assertIn(rows["Shares"][lang], labels, (lang, labels))
            self.assertIn(rows["OS"][lang], labels, (lang, labels))
            chip = self.page.evaluate("() => document.querySelector('#audit-body-sysinfo .scroll-cap-sm .cmd-badge .c-green').textContent")
            self.assertEqual(chip, rows["encrypted"][lang])
            self.fits(f"the System info section in {lang}")


class TestThePatchReport(_Page):
    def open_report(self, host, name):
        self.page.evaluate("([id, n]) => openDevicePatchReport(id, n)", [host, name])
        self.page.wait_for_function(
            "() => { const b = document.getElementById('device-patch-body'); return b && b.textContent.includes('Status') && !b.querySelector('.skeleton'); }",
            timeout=30000)

    def test_the_report_has_the_line_for_a_search_that_worked_and_for_one_that_failed(self):
        self.open_report(WIN11, "design-win11")
        good = self.page.evaluate("() => document.getElementById('device-patch-body').textContent.replace(/\\s+/g, ' ')")
        self.assertRegex(good, r"Last search .*ago.*, ok")
        self.assertIn("3 patches pending", good)
        self.fits("the patch report", "device-patch-modal")
        self.page.evaluate("() => closeModal('device-patch-modal')")
        self.open_report(WIN10, "design-win10")
        bad = self.page.evaluate("() => document.getElementById('device-patch-body').textContent.replace(/\\s+/g, ' ')")
        self.assertRegex(bad, r"Last search failed \(access\); count taken 5d ago")
        self.assertIn("No data", bad, "a count that a failed search left five days ago is not the host's count now")
        self.assertNotIn("5 patches pending", bad)
        self.fits("the patch report of a host whose search failed", "device-patch-modal")


class TestTheChecksPage(_Page):
    def test_the_row_is_on_the_page_for_both_hosts_with_the_state_of_each(self):
        self.page.evaluate("showPage('checks')")
        self.page.wait_for_function("() => document.body.textContent.includes('design-win11') && document.querySelectorAll('#page-checks tr').length > 20",
                                    timeout=60000)
        # a search that worked 12 minutes ago is fine; no successful search for five days is amber (3 days) and not yet red (14)
        for host, expect, snippet in ((WIN11, "ok", "last search"), (WIN10, "warning", "last search failed (access)")):
            body = self.page.evaluate("async id => await api('GET', '/devices/' + id + '/checks')", host)
            row = next((r for r in body["checks"] if r["key"] == "win_update_search"), None)
            self.assertIsNotNone(row, host)
            self.assertEqual(row["status"], expect, (host, row))
            self.assertIn(snippet, row["output"])
        text = self.page.evaluate("() => document.getElementById('page-checks').textContent")
        self.assertIn("Windows Update search", text)
        self.fits("the Checks page")


class TestFleetQuery(_Page):
    def query_page(self):
        self.page.evaluate("showPage('query')")
        self.page.wait_for_selector("#fq-winbuild", timeout=30000)
        self.page.evaluate("() => document.querySelectorAll('#fq-groups details').forEach(d => d.open = true)")

    def run_query(self, **fields):
        self.page.evaluate("clearFleetQuery()")
        for ident, value in fields.items():
            self.page.fill(f"#{ident}", value) if ident != "fq-tpm" else self.page.select_option(f"#{ident}", value)
        self.page.click('button[data-action="runFleetQuery"]')
        self.page.wait_for_function("() => { const r = document.getElementById('fq-results'); return r && !r.textContent.includes('Querying') && !r.textContent.includes('Set criteria'); }",
                                    timeout=30000)
        return self.page.evaluate("() => document.getElementById('fq-results').textContent")

    def test_the_three_criteria_find_the_hosts(self):
        self.query_page()
        text = self.run_query(**{"fq-winbuild": "23H2"})
        self.assertIn("design-win11", text)
        self.assertNotIn("design-win10", text)
        text = self.run_query(**{"fq-winbuild": "19045"})
        self.assertIn("design-win10", text)
        self.assertNotIn("design-win11", text)
        text = self.run_query(**{"fq-shares": "1"})
        self.assertIn("design-win11", text)
        self.assertNotIn("design-win10", text)
        text = self.run_query(**{"fq-tpm": "missing"})
        self.assertIn("design-win10", text)
        self.assertNotIn("design-win11", text)
        text = self.run_query(**{"fq-tpm": "notready"})
        self.assertIn("No hosts match", text)
        text = self.run_query(**{"fq-tpm": "present"})
        self.assertIn("design-win11", text)
        self.assertNotIn("design-win10", text)
        text = self.run_query(**{"fq-tpm": "ready"})
        self.assertIn("design-win11", text)
        self.assertNotIn("design-win10", text)

    def test_each_control_is_reached_from_the_keyboard_and_shows_where_it_is(self):
        self.query_page()
        for before, target in (("fq-platform", "fq-winbuild"), ("fq-encoff", "fq-shares"), ("fq-shares", "fq-tpm")):
            self.page.focus(f"#{before}")
            self.page.keyboard.press("Tab")
            ring = self.page.evaluate(RING)
            self.assertEqual(ring["id"], target, f"Tab from {before} did not reach {target}")
            self.assertTrue(ring["outline"] or ring["shadow"], f"{target} shows no ring when it has the focus: {ring}")

    def test_the_criteria_count_in_the_heading_of_their_group(self):
        self.query_page()
        self.page.evaluate("clearFleetQuery()")
        self.page.fill("#fq-winbuild", "23H2")
        self.page.select_option("#fq-tpm", "missing")
        counts = self.page.evaluate("""() => [...document.querySelectorAll('#fq-groups details.fq-group')].map(d => ({
            title: d.querySelector('summary').childNodes[0].textContent.trim(), n: d.querySelector('.fq-count').textContent}))""")
        by = {c["title"]: c["n"] for c in counts}
        self.assertEqual(by.get("Identity"), "1", counts)
        self.assertEqual(by.get("Security posture"), "1", counts)

    def test_the_page_lays_out_at_three_widths_and_in_german_and_arabic(self):
        from test_v710_i18n_glue import dict_rows
        rows = dict_rows()
        self.query_page()
        self.fits("the Fleet Query page")
        for lang in ("de", "ar"):
            self.set_language(lang)
            labels = self.page.evaluate("() => [...document.querySelectorAll('#fq-groups label.form-label')].map(l => l.textContent.trim())")
            for phrase in ("Windows build contains", "Shares >", "TPM"):
                self.assertIn(rows[phrase][lang], labels, (lang, phrase, labels))
            options = self.page.evaluate("() => [...document.querySelectorAll('#fq-tpm option')].map(o => o.textContent.trim())")
            self.assertEqual(options[1:], [rows[w][lang] for w in ("no TPM", "TPM present", "TPM ready", "not ready")], (lang, options))
            placeholder = self.page.evaluate("() => document.getElementById('fq-winbuild').placeholder")
            self.assertEqual(placeholder, rows["e.g. 23H2 / 22631.3593"][lang])
            if lang == "ar":
                self.assertEqual(self.page.evaluate("() => document.documentElement.dir"), "rtl")
            self.fits(f"the Fleet Query page in {lang}")


if __name__ == "__main__":
    unittest.main()
