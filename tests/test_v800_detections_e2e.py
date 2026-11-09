#!/usr/bin/env python3
"""8.0.0: Detections in a browser on the demo seed: the Detections tab of the Threat Intel page, its findings, its rules and the alert behind them.

tests/test_v800_detections_rules.py holds the rules and tests/test_v800_detections_sweep.py the sweep and the routes. This file holds what a person sees and presses: the tab
lists what the rules found over the demo (one finding for each of the six rules, the worst first), a host line opens that host's drawer, the operator switches a rule off and
changes a limit and the page keeps what was typed when an answer arrives late, a viewer reads the rules and cannot change them, a module that is off has no tab and makes no
request, text that came from a host is text and never markup, the inbox and the activity feed carry the same findings, every word has a translation, and nothing in the page broke.

The demo seed holds the data (packaging/seed-demo-data.py builds detections.json by running the rules themselves over the demo's traffic, events and Threat Intel). Self-skips
without playwright / Chromium / gunicorn, and runs under the default storage backend only.
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
TAB = '.pg-tabs[data-pg="ipintel"] [data-pg-tab-btn="detections"]'
INIT = "try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); %s } catch (e) {}"


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("the view is backend-agnostic: measured once, under the default backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-detections-e2e-")
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


def _login(page, user="alice", password="demo"):
    page.goto(_STATE["base"] + "/index.html")
    page.fill("#login-user", user)                        # the seeder builds its own accounts: there is no 'admin'
    page.fill("#login-pass", password)
    page.click('#login-form button[type="submit"]')
    page.wait_for_selector("#app", state="visible", timeout=90000)
    page.wait_for_timeout(3500)


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestDetectionsInTheBrowser(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        ctx = _STATE["browser"].new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
        ctx.add_init_script(INIT % "")
        cls.ctx, cls.page, cls.errors, cls.requests = ctx, ctx.new_page(), [], []
        cls.page.on("pageerror", lambda e: cls.errors.append(str(e)))
        cls.page.on("request", lambda r: cls.requests.append((r.method, r.url.split("/api", 1)[-1], r.post_data)))
        _login(cls.page)
        cls.config0, cls.detections0 = read("config.json"), read("detections.json")

    @classmethod
    def tearDownClass(cls):
        try:
            write("config.json", cls.config0)
            write("detections.json", cls.detections0)
        finally:
            cls.ctx.close()

    def setUp(self):
        write("config.json", self.config0)
        write("detections.json", self.detections0)
        del self.requests[:]

    def tearDown(self):
        self.page.evaluate("""() => {
          document.querySelectorAll('.modal-overlay.active').forEach(m => closeModal(m.id));
          if (typeof closeDeviceDrawer === 'function') closeDeviceDrawer();
          if (window.__realApi) { window.api = window.__realApi; window.__realApi = null; }
          (window.__held || []).splice(0).forEach(release => release());
          try { localStorage.removeItem('pgtab.ipintel'); } catch (e) {}
        }""")

    # ── helpers ──────────────────────────────────────────────────────────────

    def open_tab(self, reload=True):
        self.page.evaluate("() => showPage('ipintel')")
        self.page.wait_for_selector(TAB, state="visible", timeout=30000)
        self.page.click(TAB)
        self.page.wait_for_function("() => { const w = document.getElementById('detections-wrap'); return w && !w.hidden && typeof loadDetections === 'function'; }", timeout=30000)
        if reload:
            self.page.evaluate("async () => { await loadDetections(true); }")        # drawn afresh: a box a test left edited is the operator's and a plain reload keeps it
        self.page.wait_for_function("() => document.querySelectorAll('#detections-findings-tbody tr').length > 0 && document.querySelectorAll('#detections-rules input[type=checkbox]').length > 0", timeout=30000)
        self.page.evaluate("() => { try { tableCtl.resetView('detections-findings'); } catch (e) {} }")

    def texts(self, selector):
        """The text of each element; a table row is its cells, a space apart (the cells have no whitespace between them in the markup)."""
        return self.page.eval_on_selector_all(selector, """els => els.map(e => e.tagName === 'TR'
            ? [...e.children].map(c => c.textContent.replace(/\\s+/g, ' ').trim()).join(' | ')
            : e.textContent.replace(/\\s+/g, ' ').trim())""")

    def drawn(self):
        return self.page.evaluate("() => ({ boxes: [...document.querySelectorAll('#detections-rules input[type=checkbox]')].map(c => [c.dataset.rule, c.checked, c.disabled]), nums: [...document.querySelectorAll('#detections-rules input[type=number]')].map(n => [n.dataset.rule, n.dataset.param, n.value, n.disabled]) })")

    # ── the tab ──────────────────────────────────────────────────────────────

    def test_the_tab_lists_what_each_rule_found_over_the_demo_and_the_worst_comes_first(self):
        self.open_tab()
        rows = self.texts("#detections-findings-tbody tr")
        self.assertEqual(len(rows), 6, rows)
        self.assertTrue(rows[0].startswith("Critical | proxmox.lab | Password guessing, then a login from a new address"), rows[0])
        self.assertIn("The address that guessed passwords on proxmox.lab was followed by a first login from 20.52.131.9 as root", rows[0])
        self.assertEqual([r.split(" | ")[0] for r in rows], ["Critical", "High", "High", "High", "Medium", "Medium"])
        titles = {r.split(" | ")[2] for r in rows}
        self.assertEqual(titles, {"Password guessing, then a login from a new address", "A host calls an address Threat Intel marks as bad", "A way back in, then a new destination",
                                  "A shell or network tool talks to the Internet", "A new open port is already used from the Internet", "A database or SSH server connects to a new address"},
                         'one finding for each of the six rules')
        shell = next(r for r in rows if "A shell or network tool" in r)
        self.assertIn("bash on nextcloud.lab is connected to 35.193.77.120:4444", shell)
        self.assertIn("35.193.77.120:4444", shell.split(" | ")[4])
        self.assertRegex(shell.split(" | ")[5], r"ago|now|\bmin\b|\bh\b", "when the alert was raised")

    def test_the_summary_counts_what_the_table_lists(self):
        self.open_tab()
        stats = self.page.inner_text("#detections-stats")
        for want in ("Findings 6", "Critical 1", "High 3", "Medium 2", "Last sweep"):
            self.assertIn(want, " ".join(stats.split()), stats)
        self.assertEqual(self.page.inner_text("#detections-note").strip(), "", "the last sweep is recent and Traffic is on: nothing to say")

    def test_a_host_line_opens_that_hosts_drawer(self):
        self.open_tab()
        self.page.click('#detections-findings-tbody a[data-action="detectionsOpenHost"] >> nth=0')
        self.page.wait_for_function("() => /Online|Offline/.test(document.getElementById('drawer-device-sub').textContent)", timeout=30000)
        self.assertIn("proxmox.lab", self.page.inner_text("#drawer-device-name"))

    def test_the_filter_and_the_sort_find_a_finding(self):
        self.open_tab()
        self.page.fill("#detections-findings-filter", "35.193.77")
        self.page.wait_for_function("() => document.querySelectorAll('#detections-findings-tbody tr').length === 1", timeout=10000)
        self.assertIn("bash", self.texts("#detections-findings-tbody tr")[0])
        self.page.fill("#detections-findings-filter", "gitea")
        self.page.wait_for_function("() => document.querySelectorAll('#detections-findings-tbody tr').length === 2", timeout=10000)
        self.page.fill("#detections-findings-filter", "")
        self.page.wait_for_function("() => document.querySelectorAll('#detections-findings-tbody tr').length === 6", timeout=10000)
        self.page.click('#detections-findings-thead th[data-col="host"]')
        hosts = [t.split(" | ")[1] for t in self.texts("#detections-findings-tbody tr")]
        self.assertEqual(hosts, sorted(hosts), "a click on the column heading sorts it")

    def test_the_inbox_and_the_activity_feed_carry_the_same_findings(self):
        self.open_tab()
        alerts = self.page.evaluate("async () => { const r = await api('GET', '/alerts'); return (r.alerts || r).filter(a => a.event === 'detection_found').map(a => [a.device_id, a.severity, a.payload.rule, a.payload.detail]); }")
        self.assertEqual(len(alerts), 6, alerts)
        self.assertEqual(sorted(a[1] for a in alerts), ["critical", "high", "high", "high", "medium", "medium"])
        listed = {r.split(" | ")[3] for r in self.texts("#detections-findings-tbody tr")}
        self.assertEqual({a[3] for a in alerts}, listed, "the sentence of an alert is the sentence of the finding")
        events = self.page.evaluate("async () => { const r = await api('GET', '/fleet/events?limit=500'); return ((r && r.events) || r || []).filter(e => e.event === 'detection_found').length; }")
        self.assertEqual(events, 6)
        # the Home feed shows the eight newest of the whole fleet, and a demo has many events newer than these: draw the feed from the real answer, as the page does
        feed = self.page.evaluate("""async () => {
          const r = await api('GET', '/fleet/events?limit=500');
          const ev = (r.events || r).filter(e => e.event === 'detection_found');
          showPage('home');
          _renderHomeActivity({ events: ev });
          return [...document.querySelectorAll('#home-activity .dash-feed-item')].map(i => [i.textContent.replace(/\\s+/g, ' ').trim(), i.dataset.homeAct]);
        }""")
        self.assertEqual(len(feed), 6, "two findings on one host are two rows of the feed")
        self.assertEqual({a for _t, a in feed}, {"detections"})
        self.assertTrue(all(t.startswith("Detection found") for t, _a in feed), feed)
        self.assertTrue(any("guessed passwords" in t for t, _a in feed))

    def test_a_click_on_a_detection_in_the_activity_feed_lands_on_the_tab(self):
        self.page.evaluate("() => showPage('home')")
        self.page.evaluate("() => _homeNavAction({ dataset: { homeAct: 'detections', devId: 'gt01', devName: 'gitea.lab' } })")
        self.page.wait_for_function("() => { const w = document.getElementById('detections-wrap'); return w && !w.hidden; }", timeout=30000)
        self.assertEqual(self.page.eval_on_selector('.pg-tabs[data-pg="ipintel"] .pg-tab.active', "b => b.dataset.pgTabBtn"), "detections")

    # ── what else shows the findings ─────────────────────────────────────────

    def open_drawer(self, dev_id):
        name = read("devices.json")[dev_id]["name"]
        self.page.evaluate("([id, name]) => openDeviceDrawer(id, name)", [dev_id, name])
        self.page.wait_for_function("() => /Online|Offline/.test(document.getElementById('drawer-device-sub').textContent)", timeout=30000)

    def test_the_host_drawer_lists_the_findings_of_that_host_and_a_quiet_host_has_no_section(self):
        self.open_drawer("nc01")
        self.page.wait_for_function("() => { const s = document.getElementById('drawer-detections-section'); return s && !s.hidden && document.querySelectorAll('#drawer-detections-body .row-8-center').length > 0; }", timeout=30000)
        rows = self.texts("#drawer-detections-body .row-8-center")
        self.assertEqual(len(rows), 3, rows)
        self.assertTrue(any("bash on nextcloud.lab is connected to 35.193.77.120:4444" in r for r in rows), rows)
        self.assertEqual(self.page.inner_text("#drawer-detections-section .section-title").strip(), "Detections")
        self.page.evaluate("() => closeDeviceDrawer()")
        self.open_drawer("ng01")
        self.page.wait_for_timeout(1500)
        self.assertTrue(self.page.eval_on_selector("#drawer-detections-section", "s => s.hidden"), "ng01 has no finding: no empty section")

    def test_a_late_answer_for_the_host_that_was_open_before_does_not_paint_over_the_one_open_now(self):
        self.page.evaluate("""() => {
          window.__held = [];
          window.__realApi = window.api;
          window.api = function (m, p, ...rest) {
            const out = window.__realApi.call(this, m, p, ...rest);
            if (m !== 'GET' || p !== '/detections?host=nc01') return out;
            return out.then(v => new Promise(r => window.__held.push(() => r(v))));
          };
        }""")
        self.page.evaluate("() => openDeviceDrawer('nc01', 'nextcloud.lab')")
        self.page.wait_for_function("() => window.__held.length >= 1", timeout=30000)
        self.page.evaluate("() => openDeviceDrawer('ng01', 'nginx.lab')")
        self.page.wait_for_timeout(1500)
        self.page.evaluate("() => window.__held.splice(0).forEach(release => release())")
        self.page.wait_for_timeout(1200)
        self.assertTrue(self.page.eval_on_selector("#drawer-detections-section", "s => s.hidden"), "the answer of the host that was closed arrived late and was dropped")

    def test_fleet_query_has_the_detection_field_and_it_finds_the_host(self):
        self.page.evaluate("() => showPage('query')")
        self.page.wait_for_selector("#fq-detected", state="attached", timeout=30000)
        self.assertFalse(self.page.eval_on_selector("#fq-detected", "e => e.closest('[data-module]').classList.contains('d-none')"), "the module is on: the field is there")
        self.page.evaluate("() => { document.querySelectorAll('#page-query details.fq-group').forEach(d => d.open = true); }")
        self.assertTrue(self.page.is_visible("#fq-detected"))
        self.page.fill("#fq-detected", "reverse")
        self.page.fill("#fq-detected", "bash")
        self.page.evaluate("async () => { await runFleetQuery(); }")
        self.page.wait_for_function("() => document.querySelectorAll('#fq-results tbody tr').length > 0", timeout=30000)
        self.assertEqual(self.texts("#fq-results tbody tr .tl-devchip"), ["nextcloud.lab"])
        self.page.fill("#fq-detected", "")

    def test_the_data_explorer_offers_the_entity_and_answers_it(self):
        names = self.page.evaluate("async () => { const r = await api('GET', '/query/fields'); return Object.keys(r.entities || {}); }")
        self.assertIn("detections", names)
        rows = self.page.evaluate("async () => { const r = await api('POST', '/query', {entity: 'detections', sort: 'device_name'}); return r.rows.map(x => [x.device_name, x.rule, x.severity]); }")
        self.assertEqual(len(rows), 6, rows)
        self.assertEqual({r[1] for r in rows}, {"interpreter_egress", "service_new_destination", "known_bad_contact", "persistence_then_egress", "bruteforce_then_login", "exposed_port_in_use"})

    def test_the_risk_page_explains_the_score_with_the_findings(self):
        factors = self.page.evaluate("async () => { const r = await api('GET', '/risk'); return (r.devices || []).filter(d => d.device_name === 'nextcloud.lab').flatMap(d => d.factors.map(f => [f.kind, f.points, f.detail])); }")
        kinds = {f[0]: f for f in factors}
        self.assertIn("detections", kinds, factors)
        self.assertGreater(kinds["detections"][1], 0)
        self.assertIn("serious finding", kinds["detections"][2])

    # ── the rules ────────────────────────────────────────────────────────────

    def test_the_rules_are_listed_with_what_they_mean_and_what_they_read(self):
        self.open_tab()
        titles = self.texts("#detections-rules strong")
        self.assertEqual(len(titles), 6)
        self.assertIn("A shell or network tool talks to the Internet", titles)
        reads = self.texts("#detections-rules .hint")
        self.assertTrue(any(t.startswith("Reads Traffic, Threat Intel") for t in reads), reads)
        d = self.drawn()
        self.assertEqual(sorted(d["nums"]), sorted([["known_bad_contact", "min_score", "75", False], ["known_bad_contact", "days", "14", False], ["persistence_then_egress", "hours", "2", False],
                                                    ["bruteforce_then_login", "hours", "1", False], ["exposed_port_in_use", "hours", "6", False]]))
        self.assertTrue(all(on and not off for _id, on, off in d["boxes"]), "every rule is on and the operator may change it")

    def test_a_rule_switched_off_and_a_limit_changed_are_saved_and_shown_again(self):
        self.open_tab()
        self.page.uncheck('#detections-rules input[data-rule="interpreter_egress"][data-param="enabled"]')
        self.page.fill('#detections-rules input[data-rule="known_bad_contact"][data-param="min_score"]', "90")
        with self.page.expect_response(lambda r: r.url.endswith("/api/detections/rules") and r.request.method == "POST", timeout=15000):
            self.page.click('[data-action="detectionsSave"]')
        self.page.wait_for_function("() => document.querySelector('#detections-rules input[data-rule=\"known_bad_contact\"][data-param=\"min_score\"]').defaultValue === '90'", timeout=15000)
        sent = [(m, p, json.loads(b)) for m, p, b in self.requests if p.endswith("/detections/rules")]
        self.assertEqual(len(sent), 1, self.requests)
        self.assertEqual(sent[0][0], "POST")
        self.assertEqual(sent[0][2]["rules"]["interpreter_egress"]["enabled"], False)
        self.assertEqual(sent[0][2]["rules"]["known_bad_contact"]["min_score"], 90)
        saved = read("config.json")["detections"]
        self.assertEqual((saved["interpreter_egress"]["enabled"], saved["known_bad_contact"]["min_score"], saved["exposed_port_in_use"]["hours"]), (False, 90, 6))
        self.page.evaluate("async () => { await loadDetections(); }")
        self.assertEqual(self.page.input_value('#detections-rules input[data-rule="known_bad_contact"][data-param="min_score"]'), "90")

    def test_a_refused_value_is_said_and_nothing_is_saved(self):
        self.open_tab()
        self.page.fill('#detections-rules input[data-rule="known_bad_contact"][data-param="min_score"]', "500")
        self.page.click('[data-action="detectionsSave"]')
        self.page.wait_for_timeout(1500)
        self.assertNotIn("detections", read("config.json"))
        self.assertTrue(any(p.endswith("/detections/rules") for _m, p, _b in self.requests))

    def test_a_late_answer_does_not_take_back_what_was_typed(self):
        self.open_tab()
        self.page.fill('#detections-rules input[data-rule="exposed_port_in_use"][data-param="hours"]', "12")
        self.page.evaluate("async () => { await loadDetections(); }")
        self.assertEqual(self.page.input_value('#detections-rules input[data-rule="exposed_port_in_use"][data-param="hours"]'), "12", "a number the operator typed is theirs until it is saved")

    def test_a_viewer_reads_the_rules_and_has_no_way_to_change_them(self):
        ctx = _STATE["browser"].new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
        ctx.add_init_script(INIT % "")
        page = ctx.new_page()
        try:
            _login(page, "demo", "demo")
            page.evaluate("() => showPage('ipintel')")
            page.wait_for_selector(TAB, state="visible", timeout=30000)
            page.click(TAB)
            page.wait_for_function("() => document.querySelectorAll('#detections-rules input[type=checkbox]').length > 0", timeout=30000)
            self.assertTrue(page.eval_on_selector("#detections-rules-edit", "e => e.hidden"))
            self.assertIn("The platform operator changes the rules.", page.inner_text("#detections-rules-note"))
            self.assertEqual(page.eval_on_selector_all("#detections-rules input", "els => els.filter(e => !e.disabled).length"), 0)
        finally:
            ctx.close()

    # ── the module switch ────────────────────────────────────────────────────

    def test_with_the_module_off_there_is_no_tab_and_no_request(self):
        config = json.loads(json.dumps(self.config0))
        config["detections_module_enabled"] = False
        write("config.json", config)
        ctx = _STATE["browser"].new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
        ctx.add_init_script(INIT % "localStorage.setItem('pgtab.ipintel', 'detections');")
        page, seen = ctx.new_page(), []
        page.on("request", lambda r: seen.append(r.url))
        try:
            _login(page)
            page.evaluate("() => showPage('ipintel')")
            page.wait_for_timeout(2500)
            self.assertTrue(page.eval_on_selector(TAB, "b => b.classList.contains('d-none')"), "the Threat Intel page's own button is the one the gate hides")
            self.assertFalse(page.is_visible(TAB))
            self.assertTrue(page.eval_on_selector("#detections-wrap", "w => w.hidden"))
            self.assertEqual(page.eval_on_selector('.pg-tabs[data-pg="ipintel"] .pg-tab.active', "b => b.dataset.pgTabBtn"), "attackers", "a tab remembered from before falls back to the page's own")
            self.assertEqual([u for u in seen if "/detections" in u or "app-detections" in u], [], "nothing is fetched for a module that is off")
        finally:
            ctx.close()

    def test_one_long_page_shows_the_cards_with_the_others_and_draws_them(self):
        ctx = _STATE["browser"].new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
        ctx.add_init_script(INIT % "localStorage.setItem('rp_pagetabs', 'stacked');")
        page = ctx.new_page()
        try:
            _login(page)
            page.evaluate("() => showPage('ipintel')")
            page.wait_for_function("() => document.querySelectorAll('#detections-findings-tbody tr').length > 1", timeout=30000)
            self.assertTrue(page.is_visible("#detections-wrap"))
            self.assertTrue(page.is_visible("#ipintel-att-thead"), "the other cards show too")
        finally:
            ctx.close()

    # ── text that came from a host ───────────────────────────────────────────

    def test_text_that_came_from_a_host_is_text_and_never_markup(self):
        bad = '<img src=x onerror="window.__owned=1">'
        doc = json.loads(json.dumps(self.detections0))
        f = doc["gt01"]["found"][0]
        f.update(detail="took %s" % bad, ip=bad, process=bad)
        f["evidence"] = {"user": bad}
        write("detections.json", doc)
        self.page.evaluate("() => { window.__owned = 0; }")
        self.open_tab()
        self.assertEqual(self.page.evaluate("() => [window.__owned, document.querySelectorAll('#detections-findings-tbody img, #detections-rules img').length]"), [0, 0])
        self.assertTrue(any("<img" in t for t in self.texts("#detections-findings-tbody tr")), "it is shown as the text it is")

    # ── words ────────────────────────────────────────────────────────────────

    def test_the_words_are_translated_in_all_six_languages(self):
        self.open_tab()
        self.page.evaluate("async () => { await _ensureI18n(); }")
        grab = """() => ({
          titles: [...document.querySelectorAll('#detections-wrap .section-title')].map(e => e.textContent.trim()),
          heads: [...document.querySelectorAll('#detections-wrap th')].map(e => e.textContent.replace(/\\s*[\\u2191-\\u2195\\u25B2\\u25BC]+\\s*$/u, '').trim()),
          hints: [...document.querySelectorAll('#detections-wrap > .dash-card:first-child .hint')].map(e => e.firstChild ? e.firstChild.textContent.trim() : ''),
          rules: [...document.querySelectorAll('#detections-rules strong')].map(e => e.textContent.trim()),
          whys: [...document.querySelectorAll('#detections-rules .hint')].filter((e, i) => i % 2 === 0).map(e => e.textContent.trim()),
          labels: [...document.querySelectorAll('#detections-rules label.meta-sm')].map(e => e.firstChild.textContent.trim()),
          placeholder: [document.getElementById('detections-findings-filter').placeholder],
          kinds: [...document.querySelectorAll('#detections-findings-tbody td:first-child .patch-badge')].map(e => e.textContent.trim()),
        })"""
        english = self.page.evaluate(grab)
        self.assertTrue(english["rules"] and english["whys"] and english["labels"] and english["titles"] and english["kinds"])
        bad = []
        try:
            for lang in LANGS:
                self.page.evaluate("(l) => RPi18n.setLang(l, false)", lang)
                self.page.wait_for_timeout(300)
                now = self.page.evaluate(grab)
                for key in english:
                    for en, got in zip(english[key], now[key]):
                        if en and en == got and en not in ("Host", "Hosts", "Port"):
                            bad.append((lang, key, en))
        finally:
            self.page.evaluate("() => RPi18n.setLang('en', false)")
        self.assertEqual(bad, [])

    def test_nothing_in_the_page_broke_on_the_way(self):
        self.open_tab()
        self.page.click('#detections-findings-tbody a[data-action="detectionsOpenHost"] >> nth=0')
        self.page.wait_for_function("() => /Online|Offline/.test(document.getElementById('drawer-device-sub').textContent)", timeout=30000)
        self.assertEqual([e for e in self.errors if "Failed to load resource" not in e], [])


if __name__ == "__main__":
    unittest.main()
