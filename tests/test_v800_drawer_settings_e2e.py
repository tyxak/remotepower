#!/usr/bin/env python3
"""8.0.0: the host drawer's settings form shows what is stored and a save keeps what the form did not change, in a browser on the demo seed.

The form used to open empty for the watched services, the watched files, the log rules, the command allowlist, the SSH mode, user and port and the quarantine switch, because the
roster it read them from never carried them; "Save settings" then posted the empties back and a change of the group cleared the rest. tests/test_v800_drawer_settings.py holds the route and
the contract; this file holds what a person sees and what is on disk afterwards: the stored values are on screen, a save that changes one field leaves the others as they were (checked
in the data directory), an agentless host keeps its SSH mode, a viewer and a failed read get a form that is read-only with the words for it, the answer for the host that was open before
does not land in the form of this one, and nothing in the page broke.

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
    data_dir = tempfile.mkdtemp(prefix="rp-drawer-settings-e2e-")
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



AGENT, AGENTLESS, BARE = "ng01", "sw01", "gt01"
SETTINGS = ("services_watched", "allowed_commands", "watched_files", "log_watch", "quarantined", "reachability", "ssh_user", "ssh_port", "manual_status")
STORED_AGENT = dict(services_watched=["nginx", "sshd"], allowed_commands=["uptime"], watched_files=["/etc/hosts"], log_watch=[{"unit": "ssh", "pattern": "Failed"}], quarantined=True)
STORED_AGENTLESS = dict(reachability="ssh", ssh_user="root", ssh_port=2222, manual_status=True)


def _login(browser, user):
    ctx = browser.new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
    ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")
    page = ctx.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(_STATE["base"] + "/index.html")
    page.fill("#login-user", user)
    page.fill("#login-pass", "demo")
    page.click('#login-form button[type="submit"]')
    page.wait_for_selector("#app", state="visible", timeout=90000)
    page.wait_for_timeout(3000)
    return ctx, page, errors


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheHostSettingsForm(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ctx, cls.page, cls.errors = _login(_STATE["browser"], "alice")          # the seeder builds its own operator accounts: there is no 'admin'
        cls.devices0 = read("devices.json")

    @classmethod
    def tearDownClass(cls):
        try:
            write("devices.json", cls.devices0)
        finally:
            cls.ctx.close()

    def setUp(self):
        devices = json.loads(json.dumps(self.devices0))
        devices[AGENT].update(STORED_AGENT)
        devices[AGENTLESS].update(STORED_AGENTLESS)
        write("devices.json", devices)

    def tearDown(self):
        # a fresh page for the next test: a route that was held or aborted, and a form left on screen, must not be the next test's starting point
        self.page.unroute_all(behavior="ignoreErrors")
        self.page.reload()
        self.page.wait_for_selector("#app", state="visible", timeout=90000)
        self.page.wait_for_timeout(2500)

    def open_drawer(self, dev_id):
        name = read("devices.json")[dev_id]["name"]
        self.page.evaluate("([id, name]) => openDeviceDrawer(id, name)", [dev_id, name])
        # the Name field of the form carries the host's own name: when it does, the form on screen is this host's
        self.page.wait_for_function("(n) => (document.getElementById('ds-name') || {}).value === n", arg=name, timeout=30000)
        self.page.wait_for_timeout(300)

    def form(self):
        return self.page.evaluate("""() => { const v = id => { const e = document.getElementById(id); return e ? (e.type === 'checkbox' ? e.checked : e.value) : null; };
          return {services: v('ds-services'), allow: v('ds-allowlist'), files: v('ds-drift'), logs: v('ds-logrules'), quarantine: v('ds-quarantine'),
                  reach: v('ds-reachability'), user: v('ds-ssh-user'), port: v('ds-ssh-port'), manual: v('ds-manual-status'), group: v('ds-group')}; }""")

    def save(self):
        with self.page.expect_response(lambda r: r.request.method == "POST" and "/api/devices/" in r.url and not r.url.endswith("/settings"), timeout=30000) as info:
            self.page.click('#drawer-settings-form [data-action="_drawerSaveSettings"]')
        self.assertEqual(info.value.status, 200, info.value.text()[:200])

    def stored(self, dev_id):
        d = read("devices.json")[dev_id]
        return {k: d.get(k) for k in SETTINGS}

    def test_the_form_shows_what_is_stored_for_a_host_with_the_agent(self):
        self.open_drawer(AGENT)
        f = self.form()
        self.assertEqual((f["services"], f["allow"], f["files"], f["logs"]), ("nginx, sshd", "uptime", "/etc/hosts", "ssh : Failed"))
        self.assertTrue(f["quarantine"], "a quarantined host shows its quarantine switch on")

    def test_a_save_that_changes_one_field_leaves_every_other_setting_as_it_was(self):
        before = self.stored(AGENT)
        self.open_drawer(AGENT)
        self.page.fill("#ds-group", "web-tier")
        self.save()
        after = self.stored(AGENT)
        self.assertEqual(after, before, "nothing but the group changed")
        self.assertEqual(read("devices.json")[AGENT]["group"], "web-tier")

    def test_an_agentless_host_shows_and_keeps_its_ssh_mode_user_and_port(self):
        self.open_drawer(AGENTLESS)
        f = self.form()
        self.assertEqual((f["reach"], f["user"], f["port"]), ("ssh", "root", "2222"))
        self.page.fill("#ds-group", "core")
        self.save()
        after = self.stored(AGENTLESS)
        self.assertEqual((after["reachability"], after["ssh_user"], after["ssh_port"], after["manual_status"]), ("ssh", "root", 2222, True))
        self.assertEqual(read("devices.json")[AGENTLESS]["group"], "core")

    def test_a_host_with_nothing_stored_shows_nothing_and_saves_nothing_new(self):
        self.open_drawer(BARE)
        f = self.form()
        self.assertEqual((f["services"], f["allow"], f["files"], f["logs"], f["quarantine"]), ("", "", "", "", False))

    def test_a_change_the_operator_makes_is_what_is_stored(self):
        self.open_drawer(AGENT)
        self.page.fill("#ds-allowlist", "uptime\ndf -h")
        self.page.fill("#ds-services", "nginx")
        self.save()
        d = read("devices.json")[AGENT]
        self.assertEqual((d["allowed_commands"], d["services_watched"]), (["uptime", "df -h"], ["nginx"]))
        self.assertEqual(d["watched_files"], ["/etc/hosts"], "the field they did not touch is as it was")

    def test_a_failed_read_leaves_the_form_read_only_and_says_why_and_no_save_goes_out(self):
        posted = []
        self.page.on("request", lambda r: posted.append(r.url) if r.method == "POST" and "/api/devices/" in r.url else None)
        self.page.route("**/api/devices/*/settings", lambda route: route.abort())
        self.open_drawer(AGENT)
        self.assertTrue(self.page.eval_on_selector("#drawer-settings-form #drawer-settings-locked", "e => e.textContent.length > 20"))
        self.assertTrue(self.page.eval_on_selector_all("#drawer-settings-form input, #drawer-settings-form select, #drawer-settings-form textarea, #drawer-settings-form button",
                                                       "els => els.length > 5 && els.every(e => e.disabled)"))
        self.page.evaluate("() => { const b = document.querySelector('#drawer-settings-form [data-action=\"_drawerSaveSettings\"]'); b.disabled = false; }")
        self.page.click('#drawer-settings-form [data-action="_drawerSaveSettings"]', force=True)
        self.page.wait_for_timeout(1200)
        self.assertEqual([u for u in posted if not u.endswith("/settings")], [], "a form that could not be read saves nothing")

    def test_the_answer_for_the_host_that_was_open_before_does_not_land_in_this_hosts_form(self):
        held = []
        self.page.route("**/api/devices/%s/settings" % AGENT, lambda route: held.append(route))
        # no value is returned: the drawer's own promise waits for the answer that is being held, and evaluate would wait for it too
        self.page.evaluate("([id, name]) => { openDeviceDrawer(id, name); }", [AGENT, "nginx.lab"])
        deadline = time.time() + 20
        while time.time() < deadline and not held:
            self.page.wait_for_timeout(200)
        self.assertTrue(held, "the settings of the first host are held")
        self.open_drawer(AGENTLESS)
        for route in held:
            route.continue_()
        self.page.wait_for_timeout(1500)
        f = self.form()
        self.assertEqual((f["reach"], f["user"]), ("ssh", "root"), "the form of the host that is open")
        self.assertEqual(f["services"], "", "none of the other host's units")

    def test_the_hint_for_a_read_only_form_is_translated_in_all_six_languages(self):
        self.page.route("**/api/devices/*/settings", lambda route: route.abort())
        self.open_drawer(AGENT)
        self.page.evaluate("async () => { await _ensureI18n(); }")
        english = self.page.inner_text("#drawer-settings-locked").strip()
        bad = []
        try:
            for lang in LANGS:
                self.page.evaluate("(l) => RPi18n.setLang(l, false)", lang)
                self.page.wait_for_timeout(300)
                if self.page.inner_text("#drawer-settings-locked").strip() == english:
                    bad.append(lang)
        finally:
            self.page.evaluate("() => RPi18n.setLang('en', false)")
        self.assertEqual(bad, [])

    def test_nothing_in_the_page_broke_on_the_way(self):
        self.open_drawer(AGENT)
        self.open_drawer(AGENTLESS)
        self.assertEqual([e for e in self.errors if "Failed to load resource" not in e], [])


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestAViewerHasAReadOnlyForm(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ctx, cls.page, cls.errors = _login(_STATE["browser"], "demo")           # the demo's viewer

    @classmethod
    def tearDownClass(cls):
        cls.ctx.close()

    def test_the_form_is_read_only_with_the_words_for_it_and_nothing_can_be_saved(self):
        self.page.evaluate("([id, name]) => openDeviceDrawer(id, name)", [AGENT, "nginx.lab"])
        self.page.wait_for_selector("#drawer-settings-form #ds-group", timeout=30000)
        self.page.wait_for_timeout(800)
        self.assertTrue(self.page.eval_on_selector("#drawer-settings-form #drawer-settings-locked", "e => /administrator/.test(e.textContent)"))
        self.assertTrue(self.page.eval_on_selector("#drawer-settings-form [data-action=\"_drawerSaveSettings\"]", "b => b.disabled"))
        self.assertTrue(self.page.eval_on_selector("#ds-group", "e => e.disabled"))


if __name__ == "__main__":
    unittest.main()
