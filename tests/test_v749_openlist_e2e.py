#!/usr/bin/env python3
"""7.4.9, the open-list batch: what the new pages and sections look like in a real browser on the seeded demo.

The server side of each feature has its own module (test_v749_zfs, ...). What those cannot show is the page: that a card is
laid out the way the seeded data says, that a hostile name is text and not markup, that a table sorts, and that a section that
has nothing to show is not there. One stack serves every class here, because a seeded stack costs about a minute and a half and
each class would otherwise pay it. Self-skips without playwright/chromium/gunicorn, like its siblings.
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


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("what is measured is the page, not the backend (a test edits the JSON store)")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-openlist-")
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
    context = browser.new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
    page = context.new_page()
    page.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); } catch (e) {}")
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(base + "/index.html")
    page.fill("#login-user", "alice")
    page.fill("#login-pass", "demo")
    page.click('#login-form button[type="submit"]')
    page.wait_for_selector("#app", state="visible", timeout=90000)
    page.wait_for_timeout(6000)
    _STACK.update(pw=pw, browser=browser, shutdown=shutdown, page=page, base=base, errors=errors, data=Path(data_dir))


def tearDownModule():
    if not _STACK:
        return
    try:
        _STACK["browser"].close()
        _STACK["pw"].stop()
    finally:
        _STACK["shutdown"]()


class _Page(unittest.TestCase):

    @property
    def page(self):
        return _STACK["page"]

    @property
    def data(self):
        return _STACK["data"]

    def edit_store(self, name, fn):
        """Change one JSON store of the running stack the way the server would have written it."""
        f = self.data / name
        original = f.read_text()
        self.addCleanup(f.write_text, original)          # the next test sees the seeded data again
        doc = json.loads(original)
        fn(doc)
        f.write_text(json.dumps(doc))

    def setUp(self):
        self.page.evaluate("() => document.querySelectorAll('.toast').forEach(t => t.remove())")

    def tearDown(self):
        try:
            self.page.evaluate("() => { if (typeof closeDeviceDrawer === 'function') closeDeviceDrawer(); }")
        except Exception:
            pass
        self.assertEqual(_STACK["errors"], [], "the page threw")

    def open_drawer_section(self, dev, name, key):
        self.page.evaluate("([d, n]) => openDeviceDrawer(d, n, 'audit')", [dev, name])
        self.page.wait_for_selector(f"#audit-sec-{key}", timeout=30000)
        # the drawer keeps a section it has loaded for a host between views, so load it afresh
        self.page.evaluate("async (k) => { const d = document.getElementById('audit-sec-' + k); d.open = true; "
                           "_drawerAuditLoaded[k] = true; await _loadAuditSection(k); }", key)


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestZfs(_Page):

    def open_storage(self):
        self.page.evaluate("() => showPage('storage', document.querySelector('.nav-btn[data-page=\"storage\"]'))")
        self.page.wait_for_function(
            "() => { const t = document.getElementById('storage-tbody'); return t && t.children.length && !t.innerText.includes('Loading'); }",
            timeout=30000)

    def rows(self, tbody):
        return self.page.eval_on_selector_all(
            f"#{tbody} tr", "rs => rs.map(r => [...r.children].map(c => c.innerText.trim().replace(/\\s+/g, ' ')))")

    def test_the_storage_page_shows_the_cache_and_the_datasets_of_the_zfs_hosts(self):
        self.open_storage()
        self.page.wait_for_selector("#storage-arc-card:not([hidden])", timeout=30000)
        arc = self.rows("storage-arc-tbody")
        self.assertEqual(len(arc), 2, arc)
        self.assertIn("truenas.lab", [r[0] for r in arc])
        for r in arc:
            self.assertRegex(r[1], r"^\d+(\.\d)? (GB|MB) / 16\.0 GB$", r)
            self.assertRegex(r[2], r"^\d+\.\d%$")
            self.assertRegex(r[3], r"^\d+\.\d%$")
        ds = self.rows("storage-ds-tbody")
        names = {r[1] for r in ds}
        self.assertTrue({"tank/media", "tank/backups", "tank/vm"} <= names, names)
        backups = [r for r in ds if r[1] == "tank/backups"][0]
        self.assertIn("94.0%", backups[4])
        self.assertIn("1.61", backups[6])
        media = [r for r in ds if r[1] == "tank/media"][0]
        self.assertEqual(media[4], "—", "no quota")
        # the biggest dataset first, fleet-wide
        self.assertEqual(ds[0][1], "tank/media")

    def test_the_tables_sort(self):
        self.open_storage()
        self.page.wait_for_selector("#storage-ds-card:not([hidden])", timeout=30000)
        before = [r[1] + "@" + r[0] for r in self.rows("storage-ds-tbody")]
        self.page.click("#storage-ds-thead th[data-col='name']")
        self.page.wait_for_timeout(300)
        first = [r[1] for r in self.rows("storage-ds-tbody")]
        self.page.click("#storage-ds-thead th[data-col='name']")
        self.page.wait_for_timeout(300)
        second = [r[1] for r in self.rows("storage-ds-tbody")]
        self.assertNotEqual(first, second, "a second click reverses the order")
        self.assertEqual(sorted(first), sorted(second))
        self.assertEqual(len(before), len(first))

    def test_the_cards_are_not_there_when_no_host_has_zfs(self):
        self.open_storage()
        self.page.evaluate("() => { _storageResp = Object.assign({}, _storageResp, {arc: [], datasets: []}); _renderStorageZfs(); }")
        self.assertTrue(self.page.eval_on_selector("#storage-arc-card", "e => e.hidden"))
        self.assertTrue(self.page.eval_on_selector("#storage-ds-card", "e => e.hidden"))
        self.assertEqual(self.page.eval_on_selector("#storage-arc-card", "e => getComputedStyle(e).display"), "none")
        self.page.evaluate("() => loadStorage()")

    def test_the_host_drawer_shows_it_under_system_info(self):
        self.open_drawer_section("tnas", "truenas.lab", "sysinfo")
        self.page.wait_for_function("() => document.getElementById('audit-body-sysinfo').innerText.includes('tank/backups')", timeout=30000)
        text = self.page.inner_text("#audit-body-sysinfo")
        self.assertIn("hit ratio", text.lower(), "the pill label is drawn in capitals")
        self.assertIn("tank/media", text)
        self.assertIn("datasets, the ones that hold the most space", text)
        self.assertIn("94.0%", text)

    def test_a_host_without_zfs_has_no_zfs_block_and_does_not_load_the_module_for_it(self):
        self.open_drawer_section("ng01", "nginx.lab", "sysinfo")
        self.page.wait_for_function("() => document.getElementById('audit-body-sysinfo').innerText.length > 40", timeout=30000)
        self.assertNotIn("hit ratio", self.page.inner_text("#audit-body-sysinfo").lower())

    def test_names_from_a_host_are_text(self):
        evil = "<img src=x onerror=\"window.__zpwn=1\">"

        def patch(devs):
            ds = devs["tnas"]["sysinfo"]["zfs_datasets"]["rows"]
            ds[0]["name"] = evil              # what a hand edit could leave; the server validates names when a host reports
        self.edit_store("devices.json", patch)
        self.open_storage()
        self.page.wait_for_selector("#storage-ds-card:not([hidden])", timeout=30000)
        self.assertEqual(self.page.locator("#storage-ds-tbody img").count(), 0)
        self.assertIsNone(self.page.evaluate("() => window.__zpwn"))
        self.assertIn("<img src=x", self.page.inner_text("#storage-ds-tbody"))
        self.open_drawer_section("tnas", "truenas.lab", "sysinfo")
        self.page.wait_for_function("() => document.getElementById('audit-body-sysinfo').innerText.toLowerCase().includes('hit ratio')", timeout=30000)
        self.assertEqual(self.page.locator("#audit-body-sysinfo img").count(), 0)
        self.assertIsNone(self.page.evaluate("() => window.__zpwn"))


if __name__ == "__main__":
    unittest.main()
