#!/usr/bin/env python3
"""8.0.0: app discovery in a browser on the demo seed: the host drawer's "Discovered on this host" and the Integrations page's "Found on your hosts".

tests/test_v800_app_discovery.py holds the catalog, the agent's copy and the server's routes. This file holds what a person sees and presses: a host's list says what each app
is doing (monitored, connected, listening on the host only), Monitor makes the monitor and the row says so, Connect starts the integration wizard on its connection step with the
address filled in and the instance bound to the host, Hide takes an app out of the list and Show brings it back, the Integrations page offers the apps nothing reads yet, a late
answer for the host that was open before does not paint over the one that is open now, every word has a translation, and nothing in the page broke.

The demo's agents say what they found (packaging/seed-demo-data.py), so this runs on the seed as it is. Self-skips without playwright / Chromium / gunicorn, and runs under the
default storage backend only.
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


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("the lists are backend-agnostic: measured once, under the default backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-app-discovery-e2e-")
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


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestAppDiscoveryInTheBrowser(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        ctx = _STATE["browser"].new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
        ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")
        cls.ctx, cls.page, cls.errors, cls.posts = ctx, ctx.new_page(), [], []
        cls.page.on("pageerror", lambda e: cls.errors.append(str(e)))
        cls.page.on("request", lambda r: cls.posts.append((r.url.split("/api", 1)[-1], r.post_data)) if r.method == "POST" and ("/apps/" in r.url or "/integrations" in r.url) else None)
        cls.page.goto(_STATE["base"] + "/index.html")
        cls.page.fill("#login-user", "alice")                # the seeder builds its own operator accounts: there is no 'admin'
        cls.page.fill("#login-pass", "demo")
        cls.page.click('#login-form button[type="submit"]')
        cls.page.wait_for_selector("#app", state="visible", timeout=90000)
        cls.page.wait_for_timeout(3500)
        cls.config0 = read("config.json")
        cls.devices0 = read("devices.json")

    @classmethod
    def tearDownClass(cls):
        try:
            write("config.json", cls.config0)
            write("devices.json", cls.devices0)
        finally:
            cls.ctx.close()

    def setUp(self):
        write("config.json", self.config0)
        write("devices.json", self.devices0)
        del self.posts[:]
        self.page.evaluate("() => { _appsShowHidden = false; }") if self.page.evaluate("() => typeof _appsShowHidden") != "undefined" else None

    def tearDown(self):
        self.page.evaluate("""() => {
          document.querySelectorAll('.modal-overlay.active').forEach(m => closeModal(m.id));
          if (typeof closeDeviceDrawer === 'function') closeDeviceDrawer();
          if (window.__realApi) { window.api = window.__realApi; window.__realApi = null; }
          (window.__held || []).splice(0).forEach(release => release());
        }""")

    def open_drawer(self, dev_id, rows=1):
        name = read("devices.json")[dev_id]["name"]
        self.page.evaluate("([id, name]) => openDeviceDrawer(id, name)", [dev_id, name])
        self.page.wait_for_function("(n) => { const s = document.getElementById('drawer-apps-section'); return s && !s.hidden && document.querySelectorAll('#drawer-apps-list .app-row').length >= n; }", arg=rows, timeout=30000)

    def rows(self):
        return self.page.evaluate("""() => [...document.querySelectorAll('#drawer-apps-list .app-row')].map(r => ({
          name: r.querySelector('.app-name').textContent,
          port: (r.querySelector('.hint') || {}).textContent || '',
          text: r.textContent.replace(/\\s+/g, ' ').trim(),
          buttons: [...r.querySelectorAll('button')].map(b => b.getAttribute('data-action'))}))""")

    def row(self, name):
        got = [r for r in self.rows() if r["name"] == name]
        self.assertEqual(len(got), 1, "%s in %r" % (name, [r["name"] for r in self.rows()]))
        return got[0]

    def test_the_drawer_says_what_each_app_is_doing(self):
        self.open_drawer("gt01", 2)
        gitea, pg = self.row("Gitea / Forgejo"), self.row("PostgreSQL")
        self.assertIn("Monitored", gitea["text"], "the demo already has a monitor of its port, run from gt01")
        self.assertIn("appConnect", gitea["buttons"], "no integration reads it yet")
        self.assertNotIn("appMonitor", gitea["buttons"])
        self.assertIn("Monitored", pg["text"])
        self.assertEqual(pg["buttons"], ["appHide"], "Postgres has no connector and is monitored: only Hide is left")
        self.page.evaluate("() => closeDeviceDrawer()")
        self.open_drawer("jf01", 3)
        jf = self.row("Jellyfin")
        self.assertIn("Connected", jf["text"])
        self.assertNotIn("appConnect", jf["buttons"])
        self.assertIn("appMonitor", jf["buttons"])
        self.page.evaluate("() => closeDeviceDrawer()")
        self.open_drawer("vw01", 2)
        redis = self.row("Redis / Valkey")
        self.assertEqual(redis["buttons"], ["appMonitor", "appHide"])

    def test_a_host_that_found_nothing_has_no_section(self):
        self.page.evaluate("([id, name]) => openDeviceDrawer(id, name)", ["pmx01", "proxmox.lab"])
        self.page.wait_for_function("() => /Online|Offline/.test(document.getElementById('drawer-device-sub').textContent)", timeout=30000)
        self.page.wait_for_timeout(800)
        self.assertTrue(self.page.eval_on_selector("#drawer-apps-section", "s => s.hidden"))

    def test_an_app_that_listens_on_the_host_only_says_the_server_cannot_read_it(self):
        devices = json.loads(json.dumps(self.devices0))
        devices["gt01"]["sysinfo"]["discovered"][0]["scope"] = "local"
        write("devices.json", devices)
        self.open_drawer("gt01", 2)
        gitea = self.row("Gitea / Forgejo")
        self.assertIn("listens on this host only, so the server cannot read it", gitea["text"])
        self.assertNotIn("appConnect", gitea["buttons"])

    def test_monitor_makes_the_monitor_and_the_row_says_so(self):
        self.open_drawer("vw01", 2)
        self.page.click('#drawer-apps-list [data-action="appMonitor"][data-arg="redis"]')
        self.page.wait_for_function("() => /Monitored/.test([...document.querySelectorAll('#drawer-apps-list .app-row')].find(r => /Redis/.test(r.textContent)).textContent)", timeout=20000)
        self.assertEqual(json.loads([p for p in self.posts if p[0].endswith("/apps/monitor")][0][1]), {"app": "redis"})
        mons = [m for m in read("config.json")["monitors"] if m.get("via_host") == "vw01"]
        self.assertEqual([(m["type"], m["target"], m["label"]) for m in mons], [("tcp", "127.0.0.1:6379", "Redis / Valkey on vaultwarden.lab")])
        self.assertNotIn("appMonitor", self.row("Redis / Valkey")["buttons"])
        self.assertIn("Monitor added", self.page.inner_text("#toast-container"))

    def test_connect_starts_the_integration_wizard_on_its_connection_step_with_the_address_and_the_host(self):
        self.open_drawer("gt01", 2)
        self.page.click('#drawer-apps-list [data-action="appConnect"][data-arg="gitea"]')
        self.page.wait_for_selector("#wizard-modal.active", timeout=20000)
        self.page.wait_for_selector("#wiz-url", timeout=20000)
        self.assertEqual(self.page.inner_text("#wiz-title"), "Add an integration")
        steps = self.page.eval_on_selector_all("#wiz-steps .wiz-lbl", "els => els.map(e => e.textContent)")
        self.assertEqual(steps, ["Connection", "Test", "Finish"], "the service is known, so the first step is not asked")
        self.assertEqual(self.page.input_value("#wiz-url"), "http://10.0.2.40:3000")
        self.assertEqual(self.page.input_value("#wiz-name"), "Gitea / Forgejo on gitea.lab")
        self.assertTrue(self.page.eval_on_selector("#wiz-back", "b => b.classList.contains('wiz-off')"), "nothing to go back to")
        inst = self.page.evaluate("() => _wizIntegInst(_wiz.st)")
        self.assertEqual((inst["type"], inst["url"], inst["device_id"], inst["label"]), ("gitea", "http://10.0.2.40:3000", "gt01", "Gitea / Forgejo on gitea.lab"))

    def test_the_wizard_started_from_the_service_list_is_what_it_was(self):
        self.page.evaluate("() => wizOpen('integration')")
        self.page.wait_for_selector("#wizard-modal.active", timeout=20000)
        self.page.wait_for_selector("#wiz-search", timeout=20000)
        steps = self.page.eval_on_selector_all("#wiz-steps .wiz-lbl", "els => els.map(e => e.textContent)")
        self.assertEqual(steps, ["Service", "Connection", "Test", "Finish"])

    def test_hide_takes_the_app_out_of_the_list_and_show_brings_it_back(self):
        self.open_drawer("vw01", 2)
        self.page.click('#drawer-apps-list [data-action="appHide"][data-arg="redis"]')
        self.page.wait_for_function("() => ![...document.querySelectorAll('#drawer-apps-list .app-row')].some(r => /Redis/.test(r.textContent))", timeout=20000)
        self.assertEqual(read("config.json")["app_discovery_dismissed"], {"vw01": ["redis"]})
        self.assertIn("Hidden apps", self.page.inner_text("#drawer-apps-list"))
        self.page.click('#drawer-apps-list [data-action="appToggleHidden"]')
        self.page.wait_for_selector('#drawer-apps-list [data-action="appShow"][data-arg="redis"]', timeout=20000)
        self.page.click('#drawer-apps-list [data-action="appShow"][data-arg="redis"]')
        self.page.wait_for_function("() => [...document.querySelectorAll('#drawer-apps-list .app-row')].some(r => /Redis/.test(r.textContent) && r.querySelector('[data-action=appHide]'))", timeout=20000)
        self.assertEqual(read("config.json")["app_discovery_dismissed"], {})

    def test_the_integrations_page_offers_the_apps_nothing_reads_yet_and_none_that_is_connected(self):
        self.page.evaluate("() => showPage('integrations')")
        self.page.wait_for_function("() => { const c = document.getElementById('found-apps-card'); return c && !c.hidden && document.querySelectorAll('#found-apps-list .app-row').length > 0; }", timeout=30000)
        rows = self.page.eval_on_selector_all("#found-apps-list .app-row", "els => els.map(e => e.textContent.replace(/\\s+/g, ' ').trim())")
        joined = " | ".join(rows)
        for want in ("Gitea / Forgejo gitea.lab:3000", "Vaultwarden vaultwarden.lab:80", "Syncthing truenas.lab:8384", "Prometheus node exporter prometheus.lab:9100"):
            self.assertIn(want, joined)
        for unwanted in ("Jellyfin", "Home Assistant", "Pi-hole", "Nextcloud", "Grafana", "Sonarr"):
            self.assertNotIn(unwanted, joined, "the demo already has an integration for it")
        last = len(rows) - 1                                   # the buttons name their row by its place: the last one is not the first
        self.page.click('#found-apps-list [data-action="appFoundHide"][data-arg="%d"]' % last)
        self.page.wait_for_function("(n) => document.querySelectorAll('#found-apps-list .app-row').length === n - 1", arg=len(rows), timeout=20000)
        self.assertEqual(read("config.json")["app_discovery_dismissed"], {"tnas": ["syncthing"]} if "Syncthing" in rows[last] else {"pr01": ["node_exporter"]} if "node exporter" in rows[last] else
                         {"vw01": ["vaultwarden"]} if "Vaultwarden" in rows[last] else {"gt01": ["gitea"]})
        self.assertIn(rows[last].split(" ")[0], rows[last], "the row that was pressed is the one that went")
        gone = self.page.eval_on_selector_all("#found-apps-list .app-row", "els => els.map(e => e.textContent.replace(/\\s+/g, ' ').trim())")
        self.assertEqual(gone, rows[:last])

    def test_with_nothing_to_offer_the_card_is_not_there(self):
        config = json.loads(json.dumps(self.config0))
        config["app_discovery_dismissed"] = {"gt01": ["gitea"], "vw01": ["vaultwarden"], "tnas": ["syncthing"], "pr01": ["node_exporter"]}
        write("config.json", config)
        self.page.evaluate("() => showPage('integrations')")
        self.page.wait_for_function("() => document.querySelectorAll('#integrations-page-tiles .integ-tile, #integrations-page-tiles .integration-tile, #integrations-page-tiles > *').length > 0", timeout=30000)
        self.page.wait_for_timeout(1500)
        self.assertTrue(self.page.eval_on_selector("#found-apps-card", "c => c.hidden"))
        config = json.loads(json.dumps(self.config0))
        config["show_homelab"] = False
        write("config.json", config)
        self.page.evaluate("() => showPage('integrations')")
        self.page.wait_for_timeout(1500)
        self.assertTrue(self.page.eval_on_selector("#found-apps-card", "c => c.hidden"), "with the integrations switched off nothing is offered")

    def test_a_host_name_is_text_and_never_markup(self):
        devices = json.loads(json.dumps(self.devices0))
        devices["gt01"]["name"] = '<img src=x onerror="window.__owned=1">gitea'
        write("devices.json", devices)
        self.page.evaluate("() => { window.__owned = 0; showPage('integrations'); }")
        self.page.wait_for_function("() => document.querySelectorAll('#found-apps-list .app-row').length > 0", timeout=30000)
        self.page.wait_for_timeout(1000)
        self.assertEqual(self.page.evaluate("() => [window.__owned, document.querySelectorAll('#found-apps-list img').length]"), [0, 0])
        self.assertIn('<img src=x onerror="window.__owned=1">gitea', self.page.inner_text("#found-apps-list"))

    def test_a_late_answer_for_the_host_that_was_open_before_does_not_paint_over_the_one_open_now(self):
        self.page.evaluate("""() => {
          window.__held = [];
          window.__realApi = window.api;
          window.api = function (m, p, ...rest) {
            const out = window.__realApi.call(this, m, p, ...rest);
            if (m !== 'GET' || p !== '/devices/jf01/apps') return out;
            return out.then(v => new Promise(r => window.__held.push(() => r(v))));
          };
        }""")
        self.page.evaluate("() => openDeviceDrawer('jf01', 'jellyfin.lab')")
        self.page.wait_for_function("() => window.__held.length >= 1", timeout=20000)
        self.page.evaluate("() => openDeviceDrawer('gt01', 'gitea.lab')")
        self.page.wait_for_function("() => [...document.querySelectorAll('#drawer-apps-list .app-row .app-name')].some(n => /Gitea/.test(n.textContent))", timeout=30000)
        self.page.evaluate("() => window.__held.splice(0).forEach(release => release())")
        self.page.wait_for_timeout(1200)
        names = self.page.eval_on_selector_all("#drawer-apps-list .app-name", "els => els.map(e => e.textContent)")
        self.assertIn("Gitea / Forgejo", names)
        self.assertNotIn("Jellyfin", names, "the answer of the host that was closed arrived late and was dropped")

    def test_another_hosts_apps_are_not_left_under_this_hosts_name_while_its_own_are_on_the_way(self):
        self.open_drawer("jf01", 3)
        self.page.evaluate("""() => {
          window.__held = [];
          window.__realApi = window.api;
          window.api = function (m, p, ...rest) {
            const out = window.__realApi.call(this, m, p, ...rest);
            if (m !== 'GET' || p !== '/devices/gt01/apps') return out;
            return out.then(v => new Promise(r => window.__held.push(() => r(v))));
          };
        }""")
        self.page.evaluate("() => openDeviceDrawer('gt01', 'gitea.lab')")
        self.page.wait_for_function("() => window.__held.length >= 1", timeout=20000)
        self.assertEqual(self.page.evaluate("() => [document.getElementById('drawer-apps-section').hidden, document.querySelectorAll('#drawer-apps-list .app-row').length]"), [True, 0],
                         "nothing of jellyfin.lab is on screen under gitea.lab")
        self.page.evaluate("() => window.__held.splice(0).forEach(release => release())")
        self.page.wait_for_function("() => [...document.querySelectorAll('#drawer-apps-list .app-name')].some(n => /Gitea/.test(n.textContent))", timeout=20000)

    def test_the_words_are_translated_in_all_six_languages(self):
        self.open_drawer("gt01", 2)
        self.page.evaluate("async () => { await _ensureI18n(); }")      # the dictionary is a lazy module: an English page has not fetched it
        english = self.page.evaluate("""() => ({
          title: document.querySelector('#drawer-apps-section .section-title').textContent,
          hint: document.querySelector('#drawer-apps-section .hint').textContent,
          words: [...document.querySelectorAll('#drawer-apps-list button, #drawer-apps-list .c-green')].map(b => b.textContent.trim())})""")
        self.assertEqual(english["title"], "Discovered on this host")
        self.assertTrue({"Connect", "Hide", "Monitored"} <= set(english["words"]), english["words"])
        bad = []
        try:
            for lang in LANGS:
                self.page.evaluate("(l) => RPi18n.setLang(l, false)", lang)
                self.page.wait_for_timeout(250)
                now = self.page.evaluate("""() => ({
                  title: document.querySelector('#drawer-apps-section .section-title').textContent,
                  hint: document.querySelector('#drawer-apps-section .hint').textContent,
                  words: [...document.querySelectorAll('#drawer-apps-list button, #drawer-apps-list .c-green')].map(b => b.textContent.trim())})""")
                if now["title"] == english["title"] or now["hint"] == english["hint"]:
                    bad.append((lang, "title or hint", now["title"][:30]))
                for en, got in zip(english["words"], now["words"]):
                    if en == got:
                        bad.append((lang, en))
        finally:
            self.page.evaluate("() => RPi18n.setLang('en', false)")
        self.assertEqual(bad, [])

    def test_nothing_in_the_page_broke_on_the_way(self):
        self.open_drawer("gt01", 2)
        self.page.evaluate("() => showPage('integrations')")
        self.page.wait_for_timeout(1500)
        self.assertEqual([e for e in self.errors if "Failed to load resource" not in e], [])


if __name__ == "__main__":
    unittest.main()
