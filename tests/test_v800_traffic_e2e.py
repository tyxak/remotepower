#!/usr/bin/env python3
"""8.0.0: the Traffic view in a browser on the demo seed: the Traffic tab of the Network page, the host drawer's Traffic section and the watch list editor.

tests/test_v800_traffic.py holds the rules and the routes and tests/test_v800_traffic_agent.py the agent. This file holds what a person sees and presses: the tab adds the
fleet up (hosts sampling, the busiest remote addresses, programs, ports, one line for each host), a new address and a watch list match are marked, the Show select and the
filter find them, a host line opens that host's drawer with its own rows and chart, the four other states of a host say why there is nothing to show, the operator edits the
watch list and the interval and a viewer cannot, a module that is off has no tab and makes no request, text that came from a host is text and never markup, a late answer for the
host that was open before does not paint over the one open now, every word has a translation, and nothing in the page broke.

The demo seed holds the data (packaging/seed-demo-data.py builds traffic.json through the same cleaner a real report goes through). Self-skips without playwright / Chromium /
gunicorn, and runs under the default storage backend only.
"""
import csv
import importlib.util
import io
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


def _seeder():
    spec = importlib.util.spec_from_file_location("seed_traffic_e2e", _ROOT / "packaging" / "seed-demo-data.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["seed_traffic_e2e"] = mod
    spec.loader.exec_module(mod)
    return mod


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("the view is backend-agnostic: measured once, under the default backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-traffic-e2e-")
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


def _login(page, user="alice", password="demo"):
    page.goto(_STATE["base"] + "/index.html")
    page.fill("#login-user", user)                        # the seeder builds its own accounts: there is no 'admin'
    page.fill("#login-pass", password)
    page.click('#login-form button[type="submit"]')
    page.wait_for_selector("#app", state="visible", timeout=90000)
    page.wait_for_timeout(3500)


# The Server Status page has a tab called "traffic" too, and it comes first in the page: a bare selector finds that hidden one.
TAB = '.pg-tabs[data-pg="netmap"] [data-pg-tab-btn="traffic"]'

INIT = "try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); %s } catch (e) {}"


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTrafficInTheBrowser(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.seed = _seeder()
        ctx = _STATE["browser"].new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
        ctx.add_init_script(INIT % "")
        cls.ctx, cls.page, cls.errors, cls.requests = ctx, ctx.new_page(), [], []
        cls.page.on("pageerror", lambda e: cls.errors.append(str(e)))
        cls.page.on("request", lambda r: cls.requests.append((r.method, r.url.split("/api", 1)[-1], r.post_data)))
        _login(cls.page)
        cls.config0, cls.devices0, cls.traffic0 = read("config.json"), read("devices.json"), read("traffic.json")

    @classmethod
    def tearDownClass(cls):
        try:
            write("config.json", cls.config0)
            write("devices.json", cls.devices0)
            write("traffic.json", cls.traffic0)
        finally:
            cls.ctx.close()

    def setUp(self):
        write("config.json", self.config0)
        write("devices.json", self.devices0)
        write("traffic.json", self.traffic0)
        del self.requests[:]

    def tearDown(self):
        self.page.evaluate("""() => {
          document.querySelectorAll('.modal-overlay.active').forEach(m => closeModal(m.id));
          if (typeof closeDeviceDrawer === 'function') closeDeviceDrawer();
          if (window.__realApi) { window.api = window.__realApi; window.__realApi = null; }
          (window.__held || []).splice(0).forEach(release => release());
          try { localStorage.removeItem('pgtab.netmap'); } catch (e) {}
        }""")

    # ── helpers ──────────────────────────────────────────────────────────────

    def open_tab(self, reload=True):
        self.page.evaluate("() => showPage('netmap')")
        self.page.wait_for_selector(TAB, state="visible", timeout=30000)
        self.page.click(TAB)
        self.page.wait_for_function("() => { const w = document.getElementById('traffic-wrap'); return w && !w.hidden && typeof loadTraffic === 'function'; }", timeout=30000)
        if reload:
            self.page.evaluate("async () => { await loadTraffic(); }")
        self.page.wait_for_function("() => document.querySelectorAll('#traffic-remotes-tbody tr').length > 1", timeout=30000)
        # the sort and the filter of a table are the user's and are kept: a test that sorted a table must not leave the next one reading it in that order
        self.page.evaluate("() => { for (const n of ['traffic-remotes', 'traffic-programs', 'traffic-ports', 'traffic-hosts', 'traffic-hits']) { try { tableCtl.resetView(n); } catch (e) {} } }")
        self.page.select_option("#traffic-show", "all")

    def texts(self, selector):
        """The text of each element; a table row is its cells, a space apart (the cells have no whitespace between them in the markup)."""
        return self.page.eval_on_selector_all(selector, """els => els.map(e => e.tagName === 'TR'
            ? [...e.children].map(c => c.textContent.replace(/\\s+/g, ' ').trim()).join(' ')
            : e.textContent.replace(/\\s+/g, ' ').trim())""")

    def remote_row(self, ip):
        """The row of one address, found through the filter: the table shows fifteen rows a page and the fleet has more addresses than that."""
        self.page.fill("#traffic-remotes-filter", ip)
        self.page.wait_for_function("(ip) => [...document.querySelectorAll('#traffic-remotes-tbody tr')].some(r => r.textContent.trim().startsWith(ip))", arg=ip, timeout=10000)
        rows = [t for t in self.texts("#traffic-remotes-tbody tr") if t.startswith(ip)]
        self.page.fill("#traffic-remotes-filter", "")
        self.page.wait_for_function("() => document.querySelectorAll('#traffic-remotes-tbody tr').length > 5", timeout=10000)
        self.assertEqual(len(rows), 1, "%s in %r" % (ip, rows))
        return rows[0]

    def show(self, mode):
        self.page.select_option("#traffic-show", mode)
        self.page.wait_for_timeout(300)

    def open_drawer(self, dev_id):
        name = read("devices.json")[dev_id]["name"]
        self.page.evaluate("([id, name]) => openDeviceDrawer(id, name)", [dev_id, name])
        self.page.wait_for_function("() => /Online|Offline/.test(document.getElementById('drawer-device-sub').textContent)", timeout=30000)

    def wait_drawer_traffic(self, hidden=False):
        self.page.wait_for_function("(h) => { const s = document.getElementById('drawer-traffic-section'); return s && s.hidden === h && (h || document.getElementById('drawer-traffic-body').children.length > 0); }", arg=hidden, timeout=30000)

    # ── the tab ──────────────────────────────────────────────────────────────

    def test_the_tab_adds_the_fleet_up_and_the_busiest_address_comes_first(self):
        self.open_tab()
        stats = self.page.inner_text("#traffic-stats")
        self.assertIn("10 / 14", stats, "ten of the fourteen hosts that run an agent are sampling")
        self.assertIn("60 s", stats)
        first = self.texts("#traffic-remotes-tbody tr")[0]
        self.assertTrue(first.startswith("206.190.215.14"), first)
        self.assertIn("truenas.lab", first)
        self.assertIn("443 https", first)

    def test_a_new_address_and_a_watch_list_match_are_marked_and_the_select_and_the_filter_find_them(self):
        self.open_tab()
        tor = self.remote_row("185.220.101.45")
        self.assertIn("New", tor)
        self.assertIn("Watch list", tor)
        benign = self.remote_row("141.101.64.10")
        self.assertIn("New", benign)
        self.assertNotIn("Watch list", benign)
        self.show("new")
        self.assertEqual(sorted(t.split(" ")[0] for t in self.texts("#traffic-remotes-tbody tr")), ["141.101.64.10", "185.220.101.45"])
        self.show("watched")
        self.assertEqual([t.split(" ")[0] for t in self.texts("#traffic-remotes-tbody tr")], ["185.220.101.45"])
        self.show("local")
        local = [t.split(" ")[0] for t in self.texts("#traffic-remotes-tbody tr")]
        self.assertTrue(local and all(a.startswith("10.") for a in local), local)
        self.show("public")
        public = [t.split(" ")[0] for t in self.texts("#traffic-remotes-tbody tr")]
        self.assertTrue(public and not any(a.startswith("10.") for a in public), public)
        self.show("all")
        self.page.fill("#traffic-remotes-filter", "185.220")
        self.page.wait_for_function("() => document.querySelectorAll('#traffic-remotes-tbody tr').length === 1", timeout=10000)
        self.page.fill("#traffic-remotes-filter", "")
        self.page.wait_for_function("() => document.querySelectorAll('#traffic-remotes-tbody tr').length > 5", timeout=10000)

    def test_programs_ports_hosts_and_the_watch_list_matches_are_added_up(self):
        self.open_tab()
        programs = " | ".join(self.texts("#traffic-programs-tbody tr"))
        self.assertIn("kworker-net", programs)
        self.assertIn("Unknown", programs, "a connection the kernel holds for a mount has no program")
        self.page.select_option("#tablepagesize-traffic-ports", "100")                 # fifteen rows a page, and the fleet has more ports than that
        self.page.wait_for_function("() => document.querySelectorAll('#traffic-ports-tbody tr').length > 15", timeout=10000)
        ports = self.texts("#traffic-ports-tbody tr")
        self.assertTrue(any(t.startswith("Outbound 23 telnet") for t in ports), ports)
        self.assertTrue(any(t.startswith("Inbound 443 https") for t in ports), ports)
        self.assertTrue(any(t.startswith("Inbound 8006 proxmox") for t in ports), "the names of the apps a homelab runs are in the table")
        self.assertFalse(any("hbci" in t or "wpl-analytics" in t for t in ports), "the services file of the machine is not read: 3000 is not 'hbci', and Gitea listens there")
        hosts = {t.split(" ")[0]: t for t in self.texts("#traffic-hosts-tbody tr")}
        self.assertEqual(len(hosts), 14)
        self.assertEqual(sum(1 for t in hosts.values() if "Sampling" in t), 10)
        self.assertIn("Cannot read", hosts["home-assistant.lab"])
        self.assertIn("the ss tool is not installed", hosts["home-assistant.lab"], "the line says why")
        self.assertIn("Waiting", hosts["backup.lab"])
        self.assertIn("Not supported", hosts["design-win11"])
        self.assertIn("Not supported", hosts["mette-macbook"])
        hits = self.texts("#traffic-hits-tbody tr")
        joined = " | ".join(hits)
        self.assertEqual(len(hits), 4, hits)
        for want in ("gitea.lab 185.220.101.45 9001 kworker-net Outbound Address 185.220.101.45 A Tor relay", "gitea.lab 185.220.101.45 9001 kworker-net Outbound Network 185.220.100.0/22 Tor relays",
                     "proxmox.lab 10.0.0.1 23 telnet Outbound Port 23", "truenas.lab 10.0.1.99 9000 nc Outbound Program nc netcat"):
            self.assertIn(want, joined)

    def test_a_column_sorts_and_the_sort_is_kept_when_the_data_is_drawn_again(self):
        self.open_tab()
        self.page.click('#traffic-remotes-thead th[data-col="connections"]')
        self.page.click('#traffic-remotes-thead th[data-col="connections"]')       # descending
        conns = self.page.eval_on_selector_all("#traffic-remotes-tbody tr", "els => els.map(e => parseInt(e.children[3].textContent, 10))")
        self.assertEqual(conns, sorted(conns, reverse=True), conns)
        self.page.evaluate("async () => { await loadTraffic(); }")
        again = self.page.eval_on_selector_all("#traffic-remotes-tbody tr", "els => els.map(e => parseInt(e.children[3].textContent, 10))")
        self.assertEqual(again, sorted(again, reverse=True))

    def test_a_download_quotes_a_cell_a_spreadsheet_would_run_as_a_formula(self):
        traffic = json.loads(json.dumps(self.traffic0))
        traffic["gt01"]["sample"]["rows"][0]["proc"] = '=HYPERLINK("http://attacker.example/x","open")'
        traffic["gt01"]["sample"]["rows"][1]["proc"] = "-2+3"
        traffic["gt01"]["sample"]["rows"][2]["proc"] = "@SUM(1,1)"
        write("traffic.json", traffic)
        self.open_tab()
        self.assertTrue(self.page.evaluate("() => !!document.querySelector('[data-action=\"tblExportCsv\"][data-arg=\"traffic-programs\"]')"), "the table has its download button")
        with self.page.expect_download() as dl:
            self.page.click('[data-action="tblExportCsv"][data-arg="traffic-programs"]')
        rows = list(csv.reader(io.StringIO(Path(dl.value.path()).read_text())))
        self.assertEqual(rows[0], ["program", "hosts", "connections", "sent", "received"])
        programs = {r[0]: r for r in rows[1:]}
        self.assertIn("'=HYPERLINK(\"http://attacker.example/x\",\"open\")", programs, "the formula is text in the file, quoted with a leading '")
        self.assertIn("'-2+3", programs, "a name that is text and starts with - is quoted too")
        self.assertIn("'@SUM(1,1)", programs)
        self.assertEqual([r[0] for r in rows[1:] if r[0] and r[0][0] in "=+-@\t\r"], [], "no cell of the file starts with a character a spreadsheet runs")
        for r in rows[1:]:
            self.assertTrue(all(c.isdigit() for c in r[1:]), "the numbers of a row are written as they are: %r" % (r,))
        self.assertIn("nginx", programs, "an ordinary name is written as it is")

    # ── the drawer ───────────────────────────────────────────────────────────

    def test_a_host_line_opens_its_drawer_and_the_drawer_has_the_hosts_own_rows_and_chart(self):
        self.open_tab()
        self.page.click('#traffic-hosts-tbody a:has-text("gitea.lab")')
        self.page.wait_for_selector("#device-drawer.open", timeout=20000)
        self.wait_drawer_traffic()
        rows = self.texts("#drawer-traffic-tbody tr")
        self.assertEqual(len(rows), 5, rows)
        tor = [r for r in rows if r.startswith("185.220.101.45")][0]
        self.assertIn("New", tor)
        self.assertIn("Watch list", tor)
        self.assertIn("9001", tor)
        self.assertIn("kworker-net", tor)
        self.assertEqual(self.page.eval_on_selector_all("#drawer-traffic-body svg.sparkline", "els => els.length"), 2, "one chart for what the host sent and one for what it received")
        self.assertIn("Sampling", self.page.inner_text("#drawer-traffic-body"))
        self.assertIn("Peak", self.page.inner_text("#drawer-traffic-body"))

    def test_the_other_states_say_why_there_is_nothing_to_show(self):
        self.open_drawer("ha01")
        self.wait_drawer_traffic()
        body = self.page.inner_text("#drawer-traffic-body")
        self.assertIn("Cannot read", body)
        self.assertIn("the ss tool is not installed on this host (package iproute2)", body)
        self.assertEqual(self.page.eval_on_selector_all("#drawer-traffic-tbody tr", "els => els.length"), 0)
        self.page.evaluate("() => closeDeviceDrawer()")
        self.open_drawer("bk01")
        self.wait_drawer_traffic()
        self.assertIn("No sample yet", self.page.inner_text("#drawer-traffic-body"))
        self.page.evaluate("() => closeDeviceDrawer()")
        self.open_drawer("wks01")
        self.page.wait_for_timeout(1500)
        self.assertTrue(self.page.eval_on_selector("#drawer-traffic-section", "s => s.hidden"), "a Windows host has no connection sample to show")

    def test_a_stale_host_says_it_is_out_of_date_and_keeps_its_last_rows(self):
        traffic = json.loads(json.dumps(self.traffic0))
        traffic["gt01"]["at"] = int(time.time()) - 7200
        write("traffic.json", traffic)
        self.open_drawer("gt01")
        self.wait_drawer_traffic()
        self.assertIn("Out of date", self.page.inner_text("#drawer-traffic-body"))
        self.assertEqual(self.page.eval_on_selector_all("#drawer-traffic-tbody tr", "els => els.length"), 5)

    # ── the watch list ───────────────────────────────────────────────────────

    def test_the_operator_edits_the_watch_list_and_the_interval_and_a_bad_entry_is_refused_with_the_reason(self):
        self.open_tab()
        self.assertFalse(self.page.eval_on_selector("#traffic-wl-edit", "e => e.hidden"))
        self.assertEqual(len(self.texts("#traffic-wl-list > div")), 4)
        self.page.select_option("#traffic-wl-kind", "port")
        self.page.fill("#traffic-wl-value", "4444")
        self.page.fill("#traffic-wl-label", "reverse shell")
        self.page.click('[data-action="trafficWatchAdd"]')
        self.assertEqual(len(self.texts("#traffic-wl-list > div")), 5)
        self.assertEqual(len(read("config.json")["traffic_watch"]), 4, "nothing is saved until Save is pressed")
        self.page.fill("#traffic-every", "90")
        self.page.click('[data-action="trafficWatchSave"]')
        self.page.wait_for_function("() => /Saved/.test(document.getElementById('toast-container').textContent)", timeout=20000)
        sent = json.loads([r for r in self.requests if r[0] == "POST" and r[1] == "/traffic/config"][-1][2])
        self.assertEqual((len(sent["watch"]), sent["every"]), (5, 90))
        saved = read("config.json")
        self.assertEqual((saved["traffic_every"], saved["traffic_watch"][-1]), (90, {"kind": "port", "value": "4444", "label": "reverse shell"}))
        self.assertEqual(len(self.texts("#traffic-wl-list > div")), 5, "the saved list is what is shown")
        self.page.click('#traffic-wl-list [data-action="trafficWatchRemove"][data-arg="4"]')
        self.page.select_option("#traffic-wl-kind", "ip")
        self.page.fill("#traffic-wl-value", "not an address")
        self.page.click('[data-action="trafficWatchAdd"]')
        self.page.click('[data-action="trafficWatchSave"]')
        self.page.wait_for_function("() => /not an address/.test(document.getElementById('toast-container').textContent)", timeout=20000)
        self.assertEqual(len(read("config.json")["traffic_watch"]), 5, "a list with one bad entry is refused whole")

    def test_a_refresh_that_arrives_while_the_operator_is_editing_takes_nothing_back(self):
        self.open_tab()
        self.page.select_option("#traffic-wl-kind", "port")
        self.page.fill("#traffic-wl-value", "5555")
        self.page.click('[data-action="trafficWatchAdd"]')
        self.page.fill("#traffic-every", "150")
        self.page.evaluate("async () => { await loadTraffic(); }")               # the answer of a refresh that was on its way
        self.assertEqual(len(self.texts("#traffic-wl-list > div")), 5, "the entry that was added and not saved is still there")
        self.assertEqual(self.page.input_value("#traffic-every"), "150", "and so is the number that was typed")
        self.page.click('#traffic-wl-list [data-action="trafficWatchRemove"][data-arg="4"]')
        self.page.fill("#traffic-every", "")
        self.page.evaluate("async () => { await loadTraffic(); }")
        self.assertEqual(self.page.input_value("#traffic-every"), "60", "an empty box takes the saved interval again")

    def test_a_viewer_reads_the_list_and_has_no_editor(self):
        ctx = _STATE["browser"].new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
        ctx.add_init_script(INIT % "")
        page = ctx.new_page()
        try:
            _login(page, "demo", "demo")
            page.evaluate("() => showPage('netmap')")
            page.wait_for_selector(TAB, state="visible", timeout=30000)
            page.click(TAB)
            page.wait_for_function("() => document.querySelectorAll('#traffic-remotes-tbody tr').length > 1", timeout=30000)
            self.assertTrue(page.eval_on_selector("#traffic-wl-edit", "e => e.hidden"))
            self.assertIn("The platform operator edits it.", page.inner_text("#traffic-wl-note"))
            self.assertEqual(page.eval_on_selector_all('#traffic-wl-list [data-action="trafficWatchRemove"]', "els => els.length"), 0)
        finally:
            ctx.close()

    # ── the module switch ────────────────────────────────────────────────────

    def test_with_the_module_off_there_is_no_tab_no_request_and_no_section(self):
        config = json.loads(json.dumps(self.config0))
        config["traffic_module_enabled"] = False
        write("config.json", config)
        ctx = _STATE["browser"].new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
        ctx.add_init_script(INIT % "localStorage.setItem('pgtab.netmap', 'traffic');")
        page, seen = ctx.new_page(), []
        page.on("request", lambda r: seen.append(r.url))
        try:
            _login(page)
            page.evaluate("() => showPage('netmap')")
            page.wait_for_timeout(2500)
            self.assertTrue(page.eval_on_selector(TAB, "b => b.classList.contains('d-none')"), "the Network page's own button is the one the gate hides")
            self.assertFalse(page.is_visible(TAB))
            self.assertTrue(page.eval_on_selector("#traffic-wrap", "w => w.hidden"))
            self.assertEqual(page.eval_on_selector('.pg-tabs[data-pg="netmap"] .pg-tab.active', "b => b.dataset.pgTabBtn"), "map", "a tab remembered from before falls back to the page's own")
            page.evaluate("([id, name]) => openDeviceDrawer(id, name)", ["gt01", "gitea.lab"])
            page.wait_for_function("() => /Online|Offline/.test(document.getElementById('drawer-device-sub').textContent)", timeout=30000)
            page.wait_for_timeout(1000)
            self.assertTrue(page.eval_on_selector("#drawer-traffic-section", "s => s.hidden"))
            self.assertEqual([u for u in seen if "/traffic" in u or "app-traffic" in u], [], "nothing is fetched for a module that is off")
        finally:
            ctx.close()

    def test_one_long_page_shows_the_cards_with_the_others_and_draws_them(self):
        ctx = _STATE["browser"].new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
        ctx.add_init_script(INIT % "localStorage.setItem('rp_pagetabs', 'stacked');")
        page = ctx.new_page()
        try:
            _login(page)
            page.evaluate("() => showPage('netmap')")
            page.wait_for_function("() => document.querySelectorAll('#traffic-remotes-tbody tr').length > 1", timeout=30000)
            self.assertTrue(page.is_visible("#traffic-wrap"))
            self.assertTrue(page.is_visible("#netmap-svg"), "the other cards show too")
        finally:
            ctx.close()

    def test_one_long_page_with_the_module_off_hides_the_cards_and_fetches_nothing(self):
        config = json.loads(json.dumps(self.config0))
        config["traffic_module_enabled"] = False
        write("config.json", config)
        ctx = _STATE["browser"].new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
        ctx.add_init_script(INIT % "localStorage.setItem('rp_pagetabs', 'stacked');")
        page, seen = ctx.new_page(), []
        page.on("request", lambda r: seen.append(r.url))
        try:
            _login(page)
            page.evaluate("() => showPage('netmap')")
            page.wait_for_timeout(2500)
            self.assertTrue(page.is_visible("#netmap-svg"), "the other cards show: this is the one long page")
            self.assertFalse(page.is_visible("#traffic-wrap"))
            self.assertEqual([u for u in seen if "/traffic" in u or "app-traffic" in u], [], "every tab shows in this mode, and a module that is off still fetches nothing")
        finally:
            ctx.close()

    # ── what came from a host is text ────────────────────────────────────────

    def test_a_program_name_and_a_host_name_are_text_and_never_markup(self):
        traffic = json.loads(json.dumps(self.traffic0))
        traffic["gt01"]["sample"]["rows"][0]["proc"] = '<img src=x onerror="window.__owned=1">'
        write("traffic.json", traffic)
        devices = json.loads(json.dumps(self.devices0))
        devices["gt01"]["name"] = '<b id="bold-host">gitea</b>'
        write("devices.json", devices)
        self.page.evaluate("() => { window.__owned = 0; }")
        self.open_tab()
        self.page.wait_for_timeout(500)
        self.assertEqual(self.page.evaluate("() => [window.__owned, document.querySelectorAll('#traffic-wrap img, #traffic-wrap #bold-host').length]"), [0, 0])
        self.assertIn('<img src=x onerror="window.__owned=1">', self.page.inner_text("#traffic-programs-tbody"))
        self.assertIn('<b id="bold-host">gitea</b>', self.page.inner_text("#traffic-hosts-tbody"))
        self.page.evaluate("() => openDeviceDrawer('gt01', 'gitea')")
        self.wait_drawer_traffic()
        self.assertEqual(self.page.evaluate("() => [window.__owned, document.querySelectorAll('#drawer-traffic-body img').length]"), [0, 0])

    def test_a_late_answer_for_the_host_that_was_open_before_does_not_paint_over_the_one_open_now(self):
        self.page.evaluate("""() => {
          window.__held = [];
          window.__realApi = window.api;
          window.api = function (m, p, ...rest) {
            const out = window.__realApi.call(this, m, p, ...rest);
            if (m !== 'GET' || p !== '/devices/jf01/traffic') return out;
            return out.then(v => new Promise(r => window.__held.push(() => r(v))));
          };
        }""")
        self.page.evaluate("() => openDeviceDrawer('jf01', 'jellyfin.lab')")
        self.page.wait_for_function("() => window.__held.length >= 1", timeout=30000)
        self.page.evaluate("() => openDeviceDrawer('gt01', 'gitea.lab')")
        self.page.wait_for_function("() => document.querySelectorAll('#drawer-traffic-tbody tr').length === 5", timeout=30000)
        self.page.evaluate("() => window.__held.splice(0).forEach(release => release())")
        self.page.wait_for_timeout(1200)
        rows = self.texts("#drawer-traffic-tbody tr")
        self.assertEqual(len(rows), 5, "the answer of the host that was closed arrived late and was dropped")
        self.assertTrue(any("kworker-net" in r for r in rows))

    # ── words ────────────────────────────────────────────────────────────────

    def test_the_words_are_translated_in_all_six_languages(self):
        self.open_tab()
        self.page.evaluate("async () => { await _ensureI18n(); }")
        grab = """() => ({
          titles: [...document.querySelectorAll('#traffic-wrap .section-title')].map(e => e.textContent.trim()),
          heads: [...document.querySelectorAll('#traffic-wrap th')].map(e => e.textContent.replace(/\\s*[\\u2191-\\u2195\\u25B2\\u25BC]+\\s*$/u, '').trim()),
          options: [...document.querySelectorAll('#traffic-show option, #traffic-wl-kind option')].map(e => e.textContent.trim()),
          hints: [...document.querySelectorAll('#traffic-wrap .hint')].slice(0, 2).map(e => e.firstChild ? e.firstChild.textContent.trim() : ''),
          states: [...document.querySelectorAll('#traffic-hosts-tbody .patch-badge')].map(e => e.textContent.trim()),
          reasons: [...document.querySelectorAll('#traffic-hosts-tbody .hint')].map(e => e.textContent.trim()),
        })"""
        english = self.page.evaluate(grab)
        self.assertTrue(english["states"] and english["reasons"] and english["titles"])
        bad = []
        try:
            for lang in LANGS:
                self.page.evaluate("(l) => RPi18n.setLang(l, false)", lang)
                self.page.wait_for_timeout(300)
                now = self.page.evaluate(grab)
                for key in english:
                    for en, got in zip(english[key], now[key]):
                        if en == got and en not in ("Port", "Ports", "Host", "Hosts", "Service", "Score", "Connections"):
                            bad.append((lang, key, en))
        finally:
            self.page.evaluate("() => RPi18n.setLang('en', false)")
        self.assertEqual(bad, [])

    def test_nothing_in_the_page_broke_on_the_way(self):
        self.open_tab()
        self.open_drawer("gt01")
        self.wait_drawer_traffic()
        self.assertEqual([e for e in self.errors if "Failed to load resource" not in e], [])


if __name__ == "__main__":
    unittest.main()
