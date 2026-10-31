"""The Problems page (#56), in a browser, over the seeded demo.

The demo has a host (nextcloud.lab) that reports a failed unit, an alert for that unit that alice resolved by hand,
and the Systemd units check failing: the three views of the issue's own story. The page must show them as ONE row,
say that the host still reports it, filter by state from its tiles, and let an administrator close the open alerts of
a problem from its row.

Self-skips without playwright/chromium/gunicorn.
"""
import json
import os
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

_GATE = browser_available() or browser_required.required()
_STACK = {}
HOST_ID, HOST = "nc01", "nextcloud.lab"


def patch_the_demo(data_dir):
    """nextcloud.lab reported a moment ago, after the resolve: the unit is still failed on its last report."""
    dev_file = data_dir / "devices.json"
    devs = json.loads(dev_file.read_text())
    devs[HOST_ID]["metrics_ts"] = int(time.time()) - 10
    dev_file.write_text(json.dumps(devs))


def _sign_in(browser, base, user, password):
    context = browser.new_context(viewport={"width": 1440, "height": 1000}, service_workers="block")
    page = context.new_page()
    page.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); } catch (e) {}")
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(base + "/index.html")
    page.fill("#login-user", user)
    page.fill("#login-pass", password)
    page.click('#login-form button[type="submit"]')
    page.wait_for_selector("#app", state="visible", timeout=90000)
    page.wait_for_timeout(6000)
    return context, page, errors


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("what is measured is the page, not the backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = Path(tempfile.mkdtemp(prefix="rp-problems-e2e-"))
    proc = subprocess.run([sys.executable, str(seeder), "--data-dir", str(data_dir), "--apply"],
                          capture_output=True, cwd=str(_ROOT), timeout=900)
    if proc.returncode != 0:
        raise unittest.SkipTest("demo seeder failed: " + proc.stderr.decode(errors="replace")[-300:])
    patch_the_demo(data_dir)
    from e2e_harness import start_stack
    pw = sync_playwright().start()
    try:
        browser = pw.chromium.launch()
    except Exception as exc:
        pw.stop()
        browser_required.skip_or_fail(f"chromium not available: {exc}")
    try:
        base, shutdown = start_stack(data_dir=str(data_dir))
    except Exception as exc:
        browser.close()
        pw.stop()
        raise unittest.SkipTest(f"app stack not available: {exc}")
    context, page, errors = _sign_in(browser, base, "alice", "demo")
    _STACK.update(pw=pw, browser=browser, shutdown=shutdown, page=page, base=base, errors=errors)


def tearDownModule():
    if not _STACK:
        return
    try:
        _STACK["browser"].close()
        _STACK["pw"].stop()
    finally:
        _STACK["shutdown"]()


ROWS = """() => [...document.querySelectorAll('#problems-tbody tr')].filter(tr => !tr.querySelector('.empty-state, .skeleton'))
    .map(tr => { const td = tr.querySelectorAll('td'); return {
        host: td[1] ? td[1].textContent.trim() : '',
        family: td[2] && td[2].querySelector('.hint') ? td[2].querySelector('.hint').textContent.trim() : '',
        text: td[2] ? td[2].textContent.replace(/\\s+/g, ' ').trim() : '',
        state: td[3] ? td[3].textContent.trim() : '',
        where: td[4] ? [...td[4].querySelectorAll('button')].map(b => b.textContent.trim()) : [],
        resolve: td[6] ? !!td[6].querySelector('[data-action="resolveProblem"]') : false }; })"""


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheProblemsPage(unittest.TestCase):

    @property
    def page(self):
        return _STACK["page"]

    def tearDown(self):
        self.assertEqual(_STACK["errors"], [], "the page threw")

    def open(self, state="active"):
        self.page.evaluate("showPage('problems')")
        self.page.wait_for_selector("#page-problems.active", timeout=60000)
        self.page.select_option("#problems-filter-state", state)
        self.page.evaluate("loadProblems()")
        self.page.wait_for_function("() => { const t = document.querySelector('#problems-tbody');"
                                    " return t && t.querySelector('tr td') && !t.querySelector('.skeleton-row') && !t.textContent.includes('Loading'); }",
                                    timeout=60000)
        return self.page.evaluate(ROWS)

    def test_the_page_lists_problems_and_the_tiles_count_them(self):
        rows = self.open()
        self.assertGreater(len(rows), 3, rows)
        tiles = self.page.evaluate("""() => Object.fromEntries([...document.querySelectorAll('#problems-state-row .stat-value')]
            .map(e => [e.id.replace('problems-n-', ''), e.textContent.trim()]))""")
        self.assertEqual(set(tiles), {"failing", "resolved_but_failing", "waiting_for_report", "host_clear"})
        self.assertTrue(all(v.isdigit() for v in tiles.values()), tiles)

    def test_the_failed_unit_in_all_three_views_is_one_row_that_says_the_host_still_reports_it(self):
        rows = [r for r in self.open() if HOST in r["host"] and r["family"] == "failed_units"]
        self.assertEqual(len(rows), 1, rows)
        row = rows[0]
        self.assertEqual(row["state"], "Resolved, still failing")
        self.assertEqual(sorted(row["where"]), ["Alert", "Check", "Needs Attention"])
        self.assertIn("backup-nightly.service", row["text"])

    def test_a_host_has_one_row_for_each_kind_of_problem_and_never_two(self):
        rows = self.open("all")
        keys = [(r["host"], r["family"]) for r in rows if r["host"] != "—"]
        self.assertEqual(len(keys), len(set(keys)), "a host and kind appear twice")

    def test_a_tile_filters_the_list_and_a_second_click_undoes_it(self):
        self.open()
        self.page.click('#problems-state-row [data-arg="resolved_but_failing"]')
        self.page.wait_for_function("() => document.querySelector('#problems-state-row [data-arg=\"resolved_but_failing\"]').getAttribute('aria-pressed') === 'true'")
        self.page.wait_for_function("() => [...document.querySelectorAll('#problems-tbody tr')].every(tr => tr.querySelector('.empty-state') || tr.querySelectorAll('td')[3].textContent.trim() === 'Resolved, still failing')")
        shown = self.page.evaluate(ROWS)
        self.assertTrue(shown and all(r["state"] == "Resolved, still failing" for r in shown), shown)
        self.page.click('#problems-state-row [data-arg="resolved_but_failing"]')
        self.page.wait_for_function("() => document.querySelector('#problems-filter-state').value === 'active'")

    def test_the_text_filter_narrows_the_list_to_a_host(self):
        self.open()
        self.page.fill("#problems-filter-text", "nextcloud")
        self.page.wait_for_function("() => [...document.querySelectorAll('#problems-tbody tr td:nth-child(2)')].length > 0 && [...document.querySelectorAll('#problems-tbody tr td:nth-child(2)')].every(td => td.textContent.includes('nextcloud'))", timeout=30000)
        self.page.fill("#problems-filter-text", "")
        self.page.evaluate("loadProblems()")

    def test_an_administrator_can_close_the_open_alerts_of_a_problem_from_its_row(self):
        rows = self.open()
        open_rows = [r for r in rows if r["resolve"]]
        self.assertTrue(open_rows, "no problem with an open alert in the demo")
        target = open_rows[0]
        self.page.evaluate("""(sel) => { const tr = [...document.querySelectorAll('#problems-tbody tr')]
            .find(t => t.querySelector('[data-action="resolveProblem"]')); tr.querySelector('[data-action="resolveProblem"]').click(); }""", None)
        self.page.wait_for_function("(n) => [...document.querySelectorAll('#problems-tbody tr')].filter(t => t.querySelector('[data-action=\"resolveProblem\"]')).length < n",
                                    arg=len(open_rows), timeout=60000)
        after = self.page.evaluate(ROWS)
        self.assertLess(len([r for r in after if r["resolve"]]), len(open_rows))
        self.assertTrue(target["host"])


if __name__ == "__main__":
    unittest.main()
