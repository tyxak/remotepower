#!/usr/bin/env python3
"""v7.5.0 (signals matrix G11): three fields the server stored and no page showed, now shown, measured on the seeded demo in a browser.

* A ZFS or btrfs pool's newest snapshot. It drove the snapshot_stale alert and the AI index, and the Storage page had no column for it.
* When a backup was last integrity-checked and when its restore drill last ran. A result from last week looked as fresh as one from a
  minute ago, because the drawer's table showed the verdict and not the time.
* Why a container is unhealthy. The agent keeps the last output of the health check and the number of checks in a row that failed;
  the alert carried them and the Containers page showed the badge only.

Each check has a control that fails when it finds nothing: the rows, the cells and the badges it looks at are counted first.
"""
import os
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "tests"))
import browser_required  # noqa: E402

try:
    from playwright.sync_api import sync_playwright
except Exception:                                               # pragma: no cover
    sync_playwright = None

from e2e_harness import SKIP_REASON, browser_available  # noqa: E402

_GATE = browser_available() or browser_required.required()


def _epoch(iso):
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestStoredFieldsAreShown(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if sync_playwright is None:
            browser_required.skip_or_fail("playwright not installed")
        if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
            raise unittest.SkipTest("what a page shows is backend-agnostic: measured once")
        seeder = _ROOT / "packaging" / "seed-demo-data.py"
        if not seeder.is_file():
            raise unittest.SkipTest("demo seeder not in this tree")
        cls.data_dir = tempfile.mkdtemp(prefix="rp-v750-shown-")
        proc = subprocess.run([sys.executable, str(seeder), "--data-dir", cls.data_dir, "--apply"],
                              capture_output=True, cwd=str(_ROOT), timeout=900)
        if proc.returncode != 0:
            raise unittest.SkipTest("demo seeder failed: " + proc.stderr.decode(errors="replace")[-300:])
        from e2e_harness import start_stack
        cls._pw = sync_playwright().start()
        try:
            cls.browser = cls._pw.chromium.launch()
        except Exception as exc:
            cls._pw.stop()
            browser_required.skip_or_fail(f"chromium not available: {exc}")
        try:
            cls.base, cls._shutdown = start_stack(data_dir=cls.data_dir)
        except Exception as exc:
            cls.browser.close()
            cls._pw.stop()
            raise unittest.SkipTest(f"app stack not available: {exc}")
        cls.ctx = cls.browser.new_context(viewport={"width": 1440, "height": 900})
        cls.ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")
        cls.page = cls.ctx.new_page()
        cls.page.goto(cls.base + "/index.html")
        cls.page.fill("#login-user", "alice")
        cls.page.fill("#login-pass", "demo")
        cls.page.click('#login-form button[type="submit"]')
        cls.page.wait_for_selector("#app", state="visible", timeout=90000)
        cls.page.wait_for_timeout(6000)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.ctx.close()
            cls.browser.close()
            cls._pw.stop()
        finally:
            cls._shutdown()

    def setUp(self):
        """Every test starts with nothing open: a dialog left behind by one would intercept the clicks of the next."""
        self.page.evaluate("""() => { try { closeModal('containers-detail-modal'); } catch (e) {} try { closeDeviceDrawer(); } catch (e) {} }""")
        self.page.wait_for_timeout(300)

    def test_the_storage_page_shows_the_newest_snapshot(self):
        page = self.page
        page.evaluate("() => showPage('storage')")
        page.wait_for_function("() => { const t = document.getElementById('storage-tbody'); return t && t.querySelector('td.fw-500'); }", timeout=60000)
        head = page.evaluate("() => { const th = document.querySelector('#storage-thead th[data-col=snapshot]'); return th && th.textContent.trim(); }")
        self.assertTrue(head and head.startswith("Last snapshot"), head)   # the sort arrow follows the label
        rows = page.evaluate("""() => [...document.querySelectorAll('#storage-tbody tr')].map(tr => {
            const td = [...tr.children];
            const t = td[6] && td[6].querySelector('time');
            return {n: td.length, pool: td[1] && td[1].textContent.trim(), cell: td[6] ? td[6].textContent.trim() : null, at: t ? t.getAttribute('datetime') : null};
        })""")
        now = time.time()
        by_pool = {}
        for r in rows:
            by_pool.setdefault(r["pool"], []).append(r)
        for pool in ("tank", "btrfs:data", "md0"):
            self.assertTrue(by_pool.get(pool), f"control: a {pool} row was found ({sorted(by_pool)})")
        for r in rows:
            self.assertEqual(r["n"], 8, "the header has eight columns and so has every row")
        for r in by_pool["tank"]:
            self.assertIsNotNone(r["at"], r)
            self.assertTrue(3600 < now - _epoch(r["at"]) < 2.5 * 3600, ("the demo's tank snapshot is about 1.5 h old", r))
        for r in by_pool["btrfs:data"]:
            self.assertIsNotNone(r["at"], r)
            self.assertTrue(2.5 * 3600 < now - _epoch(r["at"]) < 3.5 * 3600, ("the demo's btrfs snapshot is about 3 h old", r))
        for r in by_pool["md0"]:
            self.assertIsNone(r["at"], "an md array has no snapshots and shows none")
            self.assertEqual(r["cell"], "—")

    def test_the_backup_table_says_when_it_was_checked(self):
        page = self.page
        page.evaluate("() => openDeviceDrawer('tnas', 'truenas.lab', 'audit')")
        page.wait_for_selector("#audit-sec-backups", state="attached", timeout=30000)
        if not page.eval_on_selector("#audit-sec-backups", "d => d.open"):
            page.click("#audit-sec-backups > summary")
        page.wait_for_function("() => document.querySelectorAll('#audit-sec-backups table tbody tr').length > 0", timeout=30000)
        row = page.evaluate("""() => {
            const tr = [...document.querySelectorAll('#audit-sec-backups table tbody tr')].find(r => r.textContent.includes('/tank/backups'));
            if (!tr) return null;
            const td = [...tr.children];
            const at = c => { const t = c && c.querySelector('time'); return t ? t.getAttribute('datetime') : null; };
            return {n: td.length, verify: td[4].textContent.trim(), verify_at: at(td[4]), drill: td[5].textContent.trim(), drill_at: at(td[5])};
        }""")
        self.assertIsNotNone(row, "control: the /tank/backups row was found")
        self.assertEqual(row["n"], 6)
        self.assertTrue(row["verify"].startswith("verified"), row)
        self.assertTrue(row["drill"].startswith("restored"), row)
        now = time.time()
        self.assertIsNotNone(row["verify_at"], row)
        self.assertIsNotNone(row["drill_at"], row)
        self.assertTrue(4 * 3600 < now - _epoch(row["verify_at"]) < 6 * 3600, ("verified about 5 h ago", row))
        self.assertTrue(29 * 3600 < now - _epoch(row["drill_at"]) < 31 * 3600, ("restore drill about 30 h ago", row))

    def test_an_unhealthy_container_says_why(self):
        page = self.page
        page.evaluate("() => containersOpen('ha01', 'home-assistant.lab')")
        page.wait_for_function("() => document.querySelectorAll('#containers-detail-body .status-pill').length > 0", timeout=30000)
        pills = page.evaluate("""() => [...document.querySelectorAll('#containers-detail-body .status-pill')]
            .map(p => ({text: p.textContent.trim(), cls: p.className, title: p.getAttribute('title')}))""")
        bad = [p for p in pills if p["text"] == "unhealthy"]
        self.assertTrue(pills and any(p["text"] == "healthy" for p in pills), f"control: healthy and unhealthy badges were found ({pills})")
        self.assertEqual(len(bad), 1, pills)
        self.assertIn("4 in a row", bad[0]["title"])
        self.assertIn("Connection refused", bad[0]["title"])
        for p in pills:
            if p["text"] == "healthy":
                self.assertFalse(p["title"], "a healthy badge has no tooltip")


if __name__ == "__main__":
    unittest.main()
