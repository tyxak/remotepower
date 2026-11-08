#!/usr/bin/env python3
"""8.0.0: the push mark, in a browser on the demo seed: the small bolt beside the name of a host whose agent holds the push channel open.

tests/test_v800_push_mark.py holds what produces the field (the agent's flag against the real push daemon, the heartbeat, the host list). This file holds what draws it:
the host table, the cards and the drawer mark the host that said it a moment ago and no other (not one that said it an hour ago, not an offline one, not one that said
nothing), the mark has a name for assistive technology and a translation in all six languages, and nothing in the page broke.

The demo's Linux agents hold a channel (all but two: packaging/seed-demo-data.py), so the test clears every `push_seen` and plants it on three seeded hosts the way a heartbeat
would, and a fourth says nothing: the marks it counts are exactly the ones it made.

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
TEXT = "Connected to the push channel: commands reach this host within seconds"
LANGS = ("zh", "hi", "es", "ar", "de", "fr")


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("the mark is backend-agnostic: measured once, under the default backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-push-mark-e2e-")
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
    tmp = _path(name).with_suffix(".tmp")
    tmp.write_text(json.dumps(doc))
    os.replace(tmp, _path(name))


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestThePushMark(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        ctx = _STATE["browser"].new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
        ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")
        cls.ctx, cls.page, cls.errors = ctx, ctx.new_page(), []
        cls.page.on("pageerror", lambda e: cls.errors.append(str(e)))
        cls.page.goto(_STATE["base"] + "/index.html")
        cls.page.fill("#login-user", "alice")                # the seeder builds its own operator accounts: there is no 'admin'
        cls.page.fill("#login-pass", "demo")
        cls.page.click('#login-form button[type="submit"]')
        cls.page.wait_for_selector("#app", state="visible", timeout=90000)
        cls.page.wait_for_timeout(3500)
        cls.devices0 = read("devices.json")
        rows = cls.page.evaluate("async () => await api('GET', '/devices')")
        agented = [r for r in rows if not r.get("agentless")]
        on = [r for r in agented if r.get("online")]
        off = [r for r in agented if not r.get("online")]
        assert len(on) >= 3, "the seed has online agents to plant on: %d" % len(on)
        if not off:                                           # the seed keeps every agent up: take one down the way a quiet host looks
            quiet = on.pop()
            devices = json.loads(json.dumps(cls.devices0))
            devices[quiet["id"]]["last_seen"] = int(time.time()) - 86400
            cls.devices0 = devices
            write("devices.json", devices)
            off = [quiet]
        cls.fresh, cls.stale, cls.silent, cls.offline = on[0], on[1], on[2], off[0]

    @classmethod
    def tearDownClass(cls):
        try:
            write("devices.json", cls.devices0)
        finally:
            cls.ctx.close()

    def setUp(self):
        devices = json.loads(json.dumps(self.devices0))
        for d in devices.values():
            d.pop("push_seen", None)        # the demo's Linux agents hold the channel now (the seeder says so): this test measures exactly the hosts it plants
        now = int(time.time())
        devices[self.fresh["id"]]["push_seen"] = now - 5
        devices[self.stale["id"]]["push_seen"] = now - 3600
        devices[self.offline["id"]]["push_seen"] = now - 5
        devices[self.silent["id"]].pop("push_seen", None)
        write("devices.json", devices)

    def tearDown(self):
        self.page.evaluate("""() => {
          document.querySelectorAll('.modal-overlay.active').forEach(m => closeModal(m.id));
          if (typeof closeDeviceDrawer === 'function') closeDeviceDrawer();
          getTablePrefs('devices').density = 'minimal';
          delete getTablePrefs('devices_minimal').pageSize;
        }""")

    def open_hosts(self, density):
        # the table shows 15 hosts a page: all of them, so the host that is marked and the ones that are not are all in the page
        self.page.evaluate("async (d) => { getTablePrefs('devices').density = d; getTablePrefs('devices_minimal').pageSize = 100; showPage('devices'); await loadDevices(); renderDevices(); }", density)
        self.page.wait_for_function("() => document.querySelectorAll('#devices-container .dev-row, #devices-container .device-card').length > 3", timeout=30000)

    def marks(self, selector):
        return self.page.evaluate("""(sel) => {
          const out = {};
          document.querySelectorAll('#devices-container ' + sel).forEach(n => { out[n.getAttribute('data-dev-id')] = n.querySelectorAll('.dev-push').length; });
          return out;
        }""", selector)

    def test_the_table_marks_the_host_that_said_it_a_moment_ago_and_no_other(self):
        self.open_hosts("minimal")
        got = self.marks(".dev-row")
        self.assertEqual(got.get(self.fresh["id"]), 1, "the host that holds the channel has the bolt")
        for who, why in ((self.stale, "said it an hour ago"), (self.silent, "said nothing"), (self.offline, "is offline")):
            self.assertEqual(got.get(who["id"]), 0, "a host that %s has none" % why)
        self.assertEqual(sum(got.values()), 1, "no other host of the seed has one")

    def test_the_cards_mark_the_same_host_and_only_that_one(self):
        self.open_hosts("comfortable")
        got = self.marks(".device-card")
        self.assertEqual(got.get(self.fresh["id"]), 1)
        self.assertEqual(sum(got.values()), 1)

    def test_the_drawer_marks_the_host_in_its_header_and_a_host_without_the_channel_has_none(self):
        for who, want in ((self.fresh, 1), (self.stale, 0)):
            self.page.evaluate("([id, name]) => openDeviceDrawer(id, name)", [who["id"], who["name"]])
            self.page.wait_for_function("() => /Online|Offline/.test(document.getElementById('drawer-device-sub').textContent)", timeout=30000)
            self.assertEqual(self.page.locator("#drawer-device-sub .dev-push").count(), want, who["name"])
            self.page.evaluate("() => closeDeviceDrawer()")

    def test_the_mark_has_a_name_for_assistive_technology_and_a_translation_in_each_language(self):
        self.open_hosts("minimal")
        self.page.evaluate("async () => { await _ensureI18n(); }")      # the dictionary is a lazy module: an English page has not fetched it
        sel = '#devices-container .dev-row[data-dev-id="%s"] .dev-push' % self.fresh["id"]
        self.page.mouse.move(1, 1)                                      # the tooltip script takes the title off the element under the pointer
        got = self.page.eval_on_selector(sel, "n => [n.getAttribute('role'), n.getAttribute('aria-label'), n.getAttribute('title'), n.querySelector('svg') ? n.querySelector('svg').getAttribute('aria-hidden') : null]")
        self.assertEqual(got, ["img", TEXT, TEXT, "true"])
        bad = []
        try:
            for lang in LANGS:
                self.page.evaluate("(l) => RPi18n.setLang(l, false)", lang)
                self.page.evaluate("async () => { await loadDevices(); renderDevices(); }")
                self.page.mouse.move(1, 1)
                label, title = self.page.eval_on_selector(sel, "n => [n.getAttribute('aria-label'), n.getAttribute('title')]")
                if not label or label == TEXT or not title or title == TEXT:
                    bad.append((lang, label, title))
        finally:
            self.page.evaluate("() => RPi18n.setLang('en', false)")
        self.assertEqual(bad, [], "the label and the tooltip, in every language")

    def test_nothing_in_the_page_broke_on_the_way(self):
        self.open_hosts("minimal")
        self.assertEqual([e for e in self.errors if "Failed to load resource" not in e], [])


if __name__ == "__main__":
    unittest.main()
