#!/usr/bin/env python3
"""The package-list refresh state and "What this agent can see", measured in a real browser.

test_pkg_refresh and test_agent_capabilities drive the agent's functions and the server's handlers. What they cannot show is the page: whether
the two new cards fit the screen, read in German and Arabic, can be reached with the keyboard, and answer without an error in the console.

The page is real: a seeded instance, a signed-in browser, the server's own answers. The two things a seeded fleet does not have are written into
its host store before it starts, the way an agent's report would have left them: one Linux host whose lists were refreshed twelve minutes ago and
whose agent reports a Debian host with some tools missing, one whose refresh failed and whose agent runs in a container, and one that has
reported neither.

For each new element: no sideways scroll at 1440, 768 and 390 px, no console error and no failed request, English, German and Arabic (right to
left) render, the control is reached by keyboard and shows a focus ring, and a button with only an icon would be a Lucide `btn-icon` (the refresh
button has an icon and a label, like the buttons beside it). Self-skips without playwright/chromium/gunicorn, like its siblings.
"""
import json
import os
import shutil
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

try:
    from playwright.sync_api import sync_playwright
except ImportError:                                     # pragma: no cover
    sync_playwright = None

from e2e_harness import SKIP_REASON, browser_available  # noqa: E402
import agent_capabilities as caps_mod  # noqa: E402

_GATE = browser_available() or browser_required.required()
_STACK = {}
WIDTHS = (1440, 768, 390)
LANGS = ("en", "de", "ar")

PRESENT_A = {"ss", "lsblk", "ufw", "journalctl", "systemctl", "apt", "dmidecode", "docker"}
CAPS_A = {
    "root": True, "container": False, "init": "systemd", "distro": "debian", "like": "ubuntu",
    "tools": {k: (k in PRESENT_A) for k in caps_mod.TOOL_KEYS},
    "logs": [{"kind": "web", "path": "/var/log/nginx/access.log", "readable": True},
             {"kind": "err", "path": "/var/log/nginx/error.log", "readable": True},
             {"kind": "f2b", "path": "/var/log/fail2ban.log", "readable": False}],
    "agent": {"version": "8.0.1", "python": "3.12.3"},
}
CAPS_B = {
    "root": False, "container": True, "init": "systemd", "distro": "debian", "mapped": ["/etc", "/proc", "/var/log"],
    "tools": {k: (k == "ss") for k in caps_mod.TOOL_KEYS}, "logs": [],
    "agent": {"version": "8.0.1", "python": "3.12.3"},
}


def _is_linux_agent(dev):
    """A host the refresh can be queued on: a Linux agent that is neither quarantined nor in audit mode (the queue refuses both)."""
    os_name = str(dev.get("os") or "").lower()
    return (not dev.get("agentless") and not any(w in os_name for w in ("windows", "mac", "darwin")) and bool(dev.get("name"))
            and not dev.get("quarantined") and not (dev.get("sysinfo") or {}).get("audit_mode"))


def _seed_reports(data_dir):
    """Write the two reports into the host store of a seeded data directory. Returns the three hosts: reported (ok), reported (failed,
    container), and one that has reported neither."""
    path = Path(data_dir) / "devices.json"
    devices = json.loads(path.read_text())
    linux = [(i, d) for i, d in sorted(devices.items()) if isinstance(d, dict) and _is_linux_agent(d)]
    if len(linux) < 3:
        raise unittest.SkipTest("the seeded fleet has fewer than three Linux hosts with an agent")
    now = int(time.time())
    (ia, da), (ib, db), (ic, dc) = linux[0], linux[1], linux[2]
    da.setdefault("sysinfo", {}).update(pkg_refresh={"at": now - 720, "status": "ok", "source": "apt", "error_class": ""},
                                       capabilities=CAPS_A)
    db.setdefault("sysinfo", {}).update(pkg_refresh={"at": now - 3600, "status": "failed", "source": "apt", "error_class": "network"},
                                       capabilities=CAPS_B)
    for d in (dc,):
        d.setdefault("sysinfo", {}).pop("pkg_refresh", None)
        d["sysinfo"].pop("capabilities", None)
    path.write_text(json.dumps(devices))
    return {"ok": {"id": ia, "name": da["name"]}, "failed": {"id": ib, "name": db["name"]}, "none": {"id": ic, "name": dc["name"]}}


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("what is measured is the page, not the backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-agentstate-")
    unittest.addModuleCleanup(shutil.rmtree, data_dir, True)       # a seeded instance is tens of MB of tmpfs; this runs on a skip too
    proc = subprocess.run([sys.executable, str(seeder), "--data-dir", data_dir, "--apply"],
                          capture_output=True, cwd=str(_ROOT), timeout=900)
    if proc.returncode != 0:
        raise unittest.SkipTest("demo seeder failed: " + proc.stderr.decode(errors="replace")[-300:])
    hosts = _seed_reports(data_dir)
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
    problems = {"console": [], "page": [], "requests": []}
    page.on("console", lambda m: problems["console"].append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: problems["page"].append(str(e)))
    page.on("response", lambda r: problems["requests"].append(f"{r.status} {r.url}") if r.status >= 400 and "/api/" in r.url else None)
    page.goto(base + "/index.html")
    page.fill("#login-user", "alice")
    page.fill("#login-pass", "demo")
    page.click('#login-form button[type="submit"]')
    page.wait_for_selector("#app", state="visible", timeout=90000)
    page.wait_for_timeout(6000)
    page.evaluate("() => _ensureI18n()")
    _STACK.update(pw=pw, browser=browser, shutdown=shutdown, page=page, base=base, hosts=hosts, problems=problems, data_dir=data_dir)


def tearDownModule():
    if not _STACK:
        return
    try:
        _STACK["browser"].close()
        _STACK["pw"].stop()
    finally:
        _STACK["shutdown"]()


# What is measured is the three new pieces and nothing around them: the body of each of the two drawer sections and the Settings card. The
# drawer as a whole is not: its header and its Integrations tiles are other code, and on the seeded OPNsense host they already scroll the
# panel sideways at 390 px (see the control test, which shows an offender outside the new pieces is not blamed on them).
_SIDEWAYS = """() => {
  const over = [];
  const cb = document.getElementById('cfg-pkg-refresh-before-scan');
  const roots = [['the Packages section', document.querySelector('#audit-body-packages')],
                 ['the What this agent can see section', document.querySelector('#audit-body-capabilities')],
                 ['the Package lists card', cb ? cb.closest('.settings-section') : null]];
  for (const [name, el] of roots) {
    if (!el || getComputedStyle(el).display === 'none' || el.clientWidth === 0) continue;
    const box = el.getBoundingClientRect();
    if (el.scrollWidth > el.clientWidth + 1) {
      const wide = Array.from(el.querySelectorAll('*')).filter(c => { const r = c.getBoundingClientRect(); return r.right > box.right + 1 || r.left < box.left - 1; })
        .slice(0, 3).map(c => c.tagName + '.' + String(c.className).slice(0, 30) + ' "' + (c.textContent || '').trim().slice(0, 30) + '"');
      over.push(name + ' scrolls sideways by ' + (el.scrollWidth - el.clientWidth) + ' px: ' + wide.join(' | '));
    }
    // A drawer section is held to the drawer's panel, not to the window: the panel is 100vw wide inside a box that leaves out a page
    // scrollbar, so it sits a scrollbar's width off the window's edge and takes every section in it along (measured: -10 px at 390 px
    // for the sections of every host, with or without the new ones). What a section can get wrong is leaving its own panel.
    const panel = el.closest('.drawer-panel');
    const frame = panel ? panel.getBoundingClientRect() : {left: 0, right: window.innerWidth};
    if (box.right > frame.right + 1 || box.left < frame.left - 1) {
      over.push(name + ' leaves ' + (panel ? 'the drawer' : 'the screen') + ': ' + Math.round(box.left) + ' to ' + Math.round(box.right)
                + ' in ' + Math.round(frame.left) + ' to ' + Math.round(frame.right));
    }
  }
  const de = document.documentElement;
  if (de.scrollWidth > window.innerWidth + 1) over.push('the page scrolls sideways by ' + (de.scrollWidth - window.innerWidth) + ' px');
  return over;
}"""


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestThePackagesAndCapabilitiesCards(unittest.TestCase):

    @property
    def page(self):
        return _STACK["page"]

    def setUp(self):
        self.page.evaluate("() => { const m = document.getElementById('step-up-modal'); if (m) m.classList.remove('active'); }")
        self.page.set_viewport_size({"width": 1440, "height": 900})
        self.page.evaluate("() => { try { RPi18n.setLang('en', false) } catch (e) {} }")
        self.page.evaluate("document.querySelectorAll('.toast').forEach(t => t.remove())")
        self.mark = {k: len(v) for k, v in _STACK["problems"].items()}

    def tearDown(self):
        try:
            self.page.evaluate("closeDeviceDrawer()")
        except Exception:
            pass

    def new_problems(self):
        return {k: v[self.mark[k]:] for k, v in _STACK["problems"].items() if v[self.mark[k]:]}

    def open_sections(self, host, *sections):
        self.page.evaluate("([id, name]) => openDeviceDrawer(id, name, 'audit')", [host["id"], host["name"]])
        for key in sections:
            self.page.wait_for_selector(f"#audit-sec-{key}", state="attached", timeout=30000)
            if not self.page.eval_on_selector(f"#audit-sec-{key}", "d => d.open"):
                self.page.click(f"#audit-sec-{key} > summary")
        if "packages" in sections:
            self.page.wait_for_selector("#audit-body-packages .sysinfo-pill", state="visible", timeout=30000)
        if "capabilities" in sections:
            self.page.wait_for_selector("#audit-body-capabilities .sysinfo-pill, #audit-body-capabilities .c-muted", state="visible", timeout=30000)
        self.page.wait_for_timeout(500)

    def text(self, sel):
        """The words as written. innerText returns what CSS makes of them, and the pill labels and table headers are upper-cased."""
        return " ".join(self.page.eval_on_selector(sel, "e => e.textContent").split())

    # ── the content ──
    def test_the_packages_section_shows_when_the_lists_were_refreshed_and_how_it_went(self):
        hosts = _STACK["hosts"]
        self.open_sections(hosts["ok"], "packages")
        body = self.text("#audit-body-packages")
        self.assertIn("Lists refreshed", body)
        self.assertIn("Succeeded", body)
        self.assertIn("Check for updates now", body)
        self.assertEqual(self.page.eval_on_selector("#audit-body-packages time", "t => t.getAttribute('datetime') !== ''"), True)
        self.page.evaluate("closeDeviceDrawer()")
        self.open_sections(hosts["failed"], "packages")
        body = self.text("#audit-body-packages")
        self.assertIn("Failed", body)
        self.assertIn("the repositories could not be reached", body)
        self.page.evaluate("closeDeviceDrawer()")
        self.open_sections(hosts["none"], "packages")
        self.assertIn("Never", self.text("#audit-body-packages"))
        self.assertEqual(self.new_problems(), {})

    def test_what_the_agent_can_see_lists_a_missing_tool_with_its_feature_and_a_hint(self):
        hosts = _STACK["hosts"]
        self.open_sections(hosts["ok"], "capabilities")
        rows = self.page.evaluate("""() => Array.from(document.querySelectorAll('#audit-body-capabilities table')[0].querySelectorAll('tbody tr'))
            .map(tr => Array.from(tr.cells).map(c => c.innerText.trim()))""")
        by_tool = {r[0]: r for r in rows}
        self.assertIn("smartctl", by_tool)
        self.assertEqual(by_tool["smartctl"][1], "Disk health (SMART)")
        self.assertEqual(by_tool["smartctl"][2], "apt install smartmontools")
        self.assertEqual(by_tool["cscli"][2], "Follow CrowdSec's own installation guide.", "no command for it, so a sentence")
        self.assertNotIn("ss", by_tool, "a tool that is there is not listed as missing")
        self.assertIn("Optional", by_tool["lynis"][1])
        badge = self.text("#audit-badge-capabilities")
        self.assertRegex(badge, r"^\d+ missing$", "the count and the word")
        self.assertEqual(int(badge.split()[0]), len(by_tool))
        self.assertEqual(self.page.eval_on_selector("#audit-body-capabilities", "b => b.querySelectorAll('button').length"), 0,
                         "a hint is text to copy, never a button")
        logs = self.page.evaluate("""() => Array.from(document.querySelectorAll('#audit-body-capabilities table')[1].querySelectorAll('tbody tr'))
            .map(tr => Array.from(tr.cells).map(c => c.innerText.trim()))""")
        self.assertEqual([r[2] for r in logs], ["Yes", "Yes", "No"])
        self.assertEqual(self.new_problems(), {})

    def test_a_container_says_not_available_and_lists_the_mapped_paths_and_a_host_that_has_not_reported_says_so(self):
        hosts = _STACK["hosts"]
        self.open_sections(hosts["failed"], "capabilities")
        body = self.text("#audit-body-capabilities")
        self.assertIn("not available in a container", body)
        self.assertIn("The agent runs in a container.", body)
        self.assertIn("The agent is not running as root", body)
        self.assertIn("/var/log", body)
        self.assertNotIn("apt install", body, "no install command inside a container")
        self.page.evaluate("closeDeviceDrawer()")
        self.open_sections(hosts["none"], "capabilities")
        body = self.text("#audit-body-capabilities")
        self.assertIn("This agent has not reported what it can see.", body)
        self.assertIn("An older agent never does: update it.", body, "most hosts without a report run an agent from before the panel")
        self.assertEqual(self.text("#audit-badge-capabilities"), "Not reported")
        self.assertEqual(self.new_problems(), {})

    def test_the_section_is_not_offered_for_a_host_without_an_agent_report(self):
        found = self.page.evaluate("""async () => {
            const devs = await api('GET', '/devices');
            return (devs.devices || devs).find(d => d.agentless || /windows|mac|darwin/i.test(String(d.os || ''))) || null;
        }""")
        if not found:
            self.skipTest("the seeded fleet has no Windows, macOS or agentless host")
        self.page.evaluate("([id, name]) => openDeviceDrawer(id, name, 'audit')", [found["id"], found["name"]])
        self.page.wait_for_selector("#audit-sec-packages", state="attached", timeout=30000)
        self.assertEqual(self.page.evaluate("() => document.querySelectorAll('#audit-sec-capabilities').length"), 0)

    # ── the fit, in each language ──
    def test_every_card_fits_the_screen_in_every_language(self):
        hosts = _STACK["hosts"]
        wide = {}
        for width in WIDTHS:
            self.page.set_viewport_size({"width": width, "height": 900})
            for host in (hosts["ok"], hosts["failed"]):
                self.open_sections(host, "packages", "capabilities")
                for lang in LANGS:
                    self.page.evaluate("l => RPi18n.setLang(l, false)", lang)
                    self.page.wait_for_timeout(300)
                    for what in self.page.evaluate(_SIDEWAYS):
                        wide.setdefault((width, lang, host["name"]), []).append(what)
                self.page.evaluate("() => RPi18n.setLang('en', false)")
                self.page.evaluate("closeDeviceDrawer()")
        self.assertEqual(wide, {}, "these views scroll sideways:\n" + "\n".join("  %s: %s" % kv for kv in sorted(wide.items())))
        self.assertEqual(self.new_problems(), {})

    def test_the_measurement_sees_a_wide_block_in_a_card_and_blames_nothing_outside_them(self):
        """Controls for the instrument, both directions: a block wider than the section is reported, and one wider than the screen in the
        drawer, outside them, is not put on the new sections (it is why the drawer as a whole is not what is measured)."""
        self.page.set_viewport_size({"width": 390, "height": 900})
        self.open_sections(_STACK["hosts"]["ok"], "packages", "capabilities")
        self.assertEqual(self.page.evaluate(_SIDEWAYS), [], "the cards were already wide before the control block was added")
        self.page.evaluate("""() => { const d = document.createElement('div'); d.id = 'rp-control-outside';
            d.style.cssText = 'width:2400px;min-width:2400px;flex:none;height:4px'; document.querySelector('.drawer-panel').appendChild(d); }""")
        self.assertGreater(self.page.evaluate("() => document.querySelector('.drawer-panel').scrollWidth - document.querySelector('.drawer-panel').clientWidth"), 1000,
                           "the block outside the cards did not widen the drawer, so this control proves nothing")
        self.assertEqual(self.page.evaluate(_SIDEWAYS), [], "a wide block elsewhere in the drawer was blamed on the cards")
        self.page.evaluate("() => document.getElementById('rp-control-outside').remove()")
        self.page.evaluate("() => { document.getElementById('audit-sec-capabilities').style.marginLeft = '600px'; }")
        pushed = self.page.evaluate(_SIDEWAYS)
        self.assertTrue(any("leaves the drawer" in m for m in pushed), f"a section pushed out of its panel went unnoticed: {pushed}")
        self.page.evaluate("() => { document.getElementById('audit-sec-capabilities').style.marginLeft = ''; }")
        self.assertEqual(self.page.evaluate(_SIDEWAYS), [], "the control left the section out of place")
        self.page.evaluate("""() => { const d = document.createElement('div'); d.style.cssText = 'width:2400px;height:4px';
            document.getElementById('audit-body-capabilities').appendChild(d); }""")
        seen = self.page.evaluate(_SIDEWAYS)
        self.assertTrue(seen and "What this agent can see" in seen[0], f"a wide block inside the section went unnoticed: {seen}")

    def test_german_and_arabic_render_the_words_the_page_and_the_server_chose(self):
        hosts = _STACK["hosts"]
        self.open_sections(hosts["ok"], "packages", "capabilities")
        wanted = {
            "de": ["Listen aktualisiert", "Jetzt nach Updates suchen", "Erfolgreich", "Fehlende Werkzeuge", "Festplattenzustand (SMART)",
                   "Benötigt für", "So beheben Sie es", "Lesbar", "Folgen Sie der Installationsanleitung von CrowdSec.", "fehlen"],
            "ar": ["تحديث القوائم", "التحقق من وجود تحديثات الآن", "نجح", "الأدوات الناقصة", "سلامة الأقراص (SMART)", "مطلوبة من أجل",
                   "كيفية الإصلاح", "قابل للقراءة", "اتبع دليل التثبيت الخاص بـ CrowdSec.", "ناقصة"],
        }
        for lang, words in wanted.items():
            self.page.evaluate("l => RPi18n.setLang(l, false)", lang)
            self.page.wait_for_timeout(500)
            if lang == "ar":
                self.assertEqual(self.page.evaluate("() => document.documentElement.dir"), "rtl")
            text = (self.text("#audit-body-packages") + "\n" + self.text("#audit-body-capabilities") + "\n"
                    + self.text("#audit-badge-capabilities"))
            self.assertEqual([w for w in words if w not in text], [], f"{lang}: words that are still English or missing")
        self.assertIn("apt install smartmontools", self.text("#audit-body-capabilities"), "an install command is a command and is not translated")
        self.assertEqual(self.new_problems(), {})

    # ── the keyboard, and what the button does ──
    def test_the_section_is_opened_and_closed_from_the_keyboard_and_shows_a_focus_ring(self):
        """The section adds no button: its heading is the control, and the browser gives a details element its keyboard behaviour. What
        is held here is that the heading is reached, that it shows where the focus is, and that Enter and Space both work."""
        self.open_sections(_STACK["hosts"]["ok"], "capabilities")
        page = self.page
        page.focus("#audit-sec-capabilities > summary")
        page.keyboard.press("Tab")                      # a ring shows for keyboard focus, and the last input here was a click
        page.keyboard.press("Shift+Tab")
        ring = page.evaluate("""() => { const a = document.activeElement, cs = getComputedStyle(a);
            return {tag: a.tagName, outline: cs.outlineStyle, width: cs.outlineWidth, shadow: cs.boxShadow, within: !!a.closest('#audit-sec-capabilities')}; }""")
        self.assertEqual((ring["tag"], ring["within"]), ("SUMMARY", True))
        self.assertTrue(ring["outline"] != "none" and ring["width"] != "0px" or ring["shadow"] != "none", f"no visible focus ring: {ring}")
        is_open = "() => document.getElementById('audit-sec-capabilities').open"
        self.assertEqual(page.evaluate(is_open), True)
        for key in ("Enter", "Space"):
            page.keyboard.press(key)
            self.assertEqual(page.evaluate(is_open), False, f"{key} did not close the section")
            page.keyboard.press(key)
            self.assertEqual(page.evaluate(is_open), True, f"{key} did not open the section")
        self.assertEqual(self.new_problems(), {})

    def test_the_refresh_button_is_reached_by_keyboard_shows_a_focus_ring_and_queues_the_command(self):
        host = _STACK["hosts"]["ok"]
        self.open_sections(host, "packages")
        self.page.focus('#audit-body-packages button[data-action-btn="_forcePackageScanBtn"]')
        self.page.keyboard.press("Tab")
        info = self.page.evaluate("""() => { const a = document.activeElement, cs = getComputedStyle(a);
            return {attr: a.getAttribute('data-action-btn'), outline: cs.outlineStyle, width: cs.outlineWidth, shadow: cs.boxShadow,
                    svg: a.querySelectorAll('svg').length, label: a.innerText.trim()}; }""")
        self.assertEqual(info["attr"], "_pkgRefreshBtn", "Tab from Scan now did not reach the refresh button")
        self.assertTrue(info["outline"] != "none" and info["width"] != "0px" or info["shadow"] != "none", f"no visible focus ring: {info}")
        self.assertEqual(info["svg"], 1)
        self.assertEqual(info["label"], "Check for updates now")
        self.page.keyboard.press("Enter")
        self.page.wait_for_selector(".toast", timeout=15000)
        toast = self.page.evaluate("() => ({cls: document.querySelector('.toast').className, text: document.querySelector('.toast').textContent})")
        self.assertIn("success", toast["cls"], f"the refresh was not queued: {toast}")
        self.assertIn("Refresh queued", toast["text"])
        queued = self.page.evaluate("""async (id) => { const r = await api('GET', '/command-queue');
            const row = (r.devices || []).find(d => d.device_id === id);
            return row ? row.commands.map(c => c.raw) : []; }""", host["id"])
        self.assertIn("pkg_refresh", queued)
        self.assertEqual(self.new_problems(), {})

    def test_the_settings_card_is_reached_by_keyboard_saves_and_fits(self):
        page = self.page
        page.evaluate("showPage('settings')")
        page.wait_for_timeout(800)
        page.evaluate("() => document.querySelector('.settings-tab[data-tab=\"security\"]').click()")
        page.wait_for_selector("#cfg-pkg-refresh-before-scan", state="attached", timeout=15000)
        label = page.evaluate("() => { const c = document.getElementById('cfg-pkg-refresh-before-scan'); return c.closest('label').innerText.trim(); }")
        self.assertEqual(label, "Refresh the package lists before each scheduled scan")
        self.assertEqual(page.evaluate("() => document.getElementById('cfg-pkg-refresh-before-scan').checked"), False, "off by default")
        self.assertEqual(page.evaluate("api('GET', '/config').then(c => c.pkg_refresh_before_scan)"), False)
        for width in WIDTHS:
            page.set_viewport_size({"width": width, "height": 900})
            for lang in LANGS:
                page.evaluate("l => RPi18n.setLang(l, false)", lang)
                page.wait_for_timeout(200)
                self.assertEqual(page.evaluate(_SIDEWAYS), [], f"{width}px {lang}")
        page.evaluate("() => RPi18n.setLang('en', false)")
        page.set_viewport_size({"width": 1440, "height": 900})
        page.focus("#cfg-pkg-refresh-before-scan")
        page.keyboard.press("Tab")
        page.keyboard.press("Shift+Tab")
        ring = page.evaluate("""() => { const a = document.activeElement, cs = getComputedStyle(a);
            return {id: a.id, outline: cs.outlineStyle, width: cs.outlineWidth, shadow: cs.boxShadow}; }""")
        self.assertEqual(ring["id"], "cfg-pkg-refresh-before-scan")
        self.assertTrue(ring["outline"] != "none" and ring["width"] != "0px" or ring["shadow"] != "none", f"no visible focus ring: {ring}")
        page.keyboard.press("Space")
        self.assertEqual(page.evaluate("() => document.getElementById('cfg-pkg-refresh-before-scan').checked"), True)
        # The page's own save collects the whole form and the server asks for a step-up before it takes a governance setting the form
        # carries, so the request is caught on its way out: what the page sends is what is read, and nothing is saved by the click.
        sent = []

        def catch(route, request):
            if request.method == "POST":
                sent.append(json.loads(request.post_data or "{}"))
                route.fulfill(status=200, content_type="application/json", body='{"ok": true}')
            else:
                route.continue_()

        page.route("**/api/config", catch)
        try:
            page.click("#btn-save-settings")
            page.wait_for_selector(".toast.success", timeout=15000)
        finally:
            page.unroute("**/api/config")
        self.assertEqual(len(sent), 1)
        self.assertIs(sent[0].get("pkg_refresh_before_scan"), True, "the page did not send the switch as a real true")
        page.focus("#cfg-pkg-refresh-before-scan")           # the click on Save moved the focus to the button
        page.keyboard.press("Space")
        self.assertEqual(page.evaluate("() => document.getElementById('cfg-pkg-refresh-before-scan').checked"), False)
        # and the server end, through the same call the page makes
        saved = page.evaluate("api('POST', '/config', {pkg_refresh_before_scan: true}).then(r => r && r.ok)")
        self.assertTrue(saved)
        self.assertEqual(page.evaluate("api('GET', '/config').then(c => c.pkg_refresh_before_scan)"), True)
        page.evaluate("api('POST', '/config', {pkg_refresh_before_scan: false})")
        self.assertEqual(page.evaluate("api('GET', '/config').then(c => c.pkg_refresh_before_scan)"), False)
        self.assertEqual(self.new_problems(), {})

if __name__ == "__main__":
    unittest.main()
