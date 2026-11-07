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
    # With alerts open the sidebar pins itself open over the left 248 px of every page, and a click on the left of the
    # page lands on it. The account setting that keeps it auto-hiding makes the pointer tests independent of the data.
    page.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_pagetabs', 'stacked'); localStorage.setItem('rp_autohide_thru_alerts', '1'); } catch (e) {}")
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
        self.page.wait_for_function("() => _problemsSeq > 0 && _problemsDrawn === _problemsSeq", timeout=60000)
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

    def test_a_problem_only_needs_attention_or_checks_list_shows_when_its_host_reported_it(self):
        """The reporter's second report on #56: such a row read "never" under Updated, current ones included (pending
        updates, agent version). It has no alert, so the time is when its host last reported; a host that never said when
        shows a dash. No cell says never. Both groups are checked for being non-empty: a population of zero proves nothing
        (the demo's hosts carry no report time but the one patched in setUpModule)."""
        self.open("all")
        rows = self.page.evaluate("""() => {
            const cell = {};
            for (const tr of document.querySelectorAll('#problems-tbody tr')) {
                const b = tr.querySelector('[data-action="openProblemHistory"]');
                if (b) cell[b.dataset.arg] = tr.querySelectorAll('td')[5].textContent.trim();
            }
            return _problemsRows.map(r => ({host: r.device, family: r.family, updated: r.updated || 0,
                                            report: r.last_report || 0, cell: cell[r.key]}));
        }""")
        by_report = [r for r in rows if not r["updated"] and r["report"]]
        no_time = [r for r in rows if not r["updated"] and not r["report"]]
        by_alert = [r for r in rows if r["updated"]]
        self.assertGreater(len(by_report), 3, rows)
        self.assertGreater(len(no_time), 3, rows)
        self.assertGreater(len(by_alert), 3, rows)
        for r in rows:
            self.assertNotIn(r["cell"], (None, "", "never"), r)
        for r in by_report + by_alert:
            self.assertNotEqual(r["cell"], "—", r)
        for r in no_time:
            self.assertEqual(r["cell"], "—", r)



@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheViewsAndTheActions(unittest.TestCase):
    """The four views are filters of the one list, and the actions on a row change what the other pages hold."""

    @property
    def page(self):
        return _STACK["page"]

    def tearDown(self):
        self.assertEqual(_STACK["errors"], [], "the page threw")

    def drawn(self):
        """Wait until the newest request the page made has been drawn, so no answer is still on its way."""
        self.page.wait_for_function("() => _problemsSeq > 0 && _problemsDrawn === _problemsSeq", timeout=60000)

    def api(self, method, path, body=None):
        return self.page.evaluate("([m, p, b]) => api(m, p, b || undefined)", [method, path, body])

    def ignored(self):
        """The Needs attention entries of the ignored list, by key."""
        return {e["key"]: e for e in self.api("GET", "/ignored")["needs_attention"]}

    def until(self, what, ask, timeout=30.0):
        """Poll `ask()` until it returns something truthy, and fail with `what` if it never does. (A Playwright
        wait_for_function with an async predicate does not wait: it takes the returned Promise for a truthy value.)"""
        end = time.time() + timeout
        while time.time() < end:
            got = ask()
            if got:
                return got
            time.sleep(0.4)
        self.fail(f"never happened: {what}")

    def open(self, state="active", view=""):
        self.page.evaluate("showPage('problems')")
        self.page.wait_for_selector("#page-problems.active", timeout=60000)
        self.page.select_option("#problems-filter-state", state)
        self.page.evaluate("v => setProblemsView(v)", view)
        self.page.wait_for_function("() => _problemsSeq > 0 && _problemsDrawn === _problemsSeq", timeout=60000)

    def row(self, host, family):
        return (self.page.locator("#problems-tbody tr", has=self.page.locator(".tl-devchip", has_text=host))
                .filter(has_text=family).first)

    def press(self, host, family, label):
        """Open the row's More menu and choose an item by its text. The menu closes on any scroll, by design, so the
        row is brought into view first, as a person would, and nothing scrolls between the two clicks. On a busy machine
        a scroll that is still settling closes the menu between them (it failed in two full gates and passed alone every
        time), so the menu is opened again, three times at most, and the failure says what the menu held."""
        seen = ""
        for _ in range(3):
            self.page.keyboard.press("Escape")
            row = self.row(host, family)
            row.scroll_into_view_if_needed()
            self.page.wait_for_timeout(300)
            try:
                row.locator('[data-action="rowMoreMenu"]').click()
                self.page.wait_for_selector("#row-more-pop", timeout=5000)
                self.page.locator("#row-more-pop button", has_text=label).click(timeout=5000)
                return
            except Exception:
                seen = self.page.evaluate("() => { const p = document.getElementById('row-more-pop'); "
                                          "return p ? p.innerText : '(the menu had closed)'; }")
        self.fail(f"no {label!r} in the menu of {host} / {family} after three tries; the menu held {seen!r}")

    def answer_dialog(self, text=None):
        self.page.wait_for_selector("#ui-prompt-modal.active", timeout=15000)
        if text is not None:
            self.page.fill("#ui-prompt-input", text)
        self.page.click("#ui-prompt-confirm")

    def test_the_views_are_filters_of_the_one_list_and_carry_their_counts(self):
        self.open()
        counts = self.page.evaluate("""() => Object.fromEntries([...document.querySelectorAll('#problems-views button')]
            .map(b => [b.dataset.arg || 'all', parseInt(b.querySelector('.hint').textContent, 10)]))""")
        self.assertEqual(set(counts), {"all", "alert", "attention", "check"})
        self.assertGreater(counts["all"], 0)
        for view, label in (("alert", "Alert"), ("attention", "Needs Attention"), ("check", "Check")):
            self.open(view=view)
            rows = self.page.evaluate(ROWS)
            self.assertTrue(rows, view)
            self.assertTrue(all(label in r["where"] for r in rows), (view, [r["where"] for r in rows]))
            self.assertEqual(len(rows), counts[view], f"the {view} view lists {len(rows)} and its count says {counts[view]}")
            self.assertEqual(self.page.evaluate("() => document.querySelector('#problems-views .active').dataset.arg"), view)
        self.open()

    def test_the_history_of_the_failed_unit_reads_back_who_resolved_it(self):
        self.open()
        self.row(HOST, "failed_units").locator('[data-action="openProblemHistory"]').click()
        self.page.wait_for_selector("#problem-history-modal.active table", timeout=30000)
        text = self.page.inner_text("#problem-history-body")
        self.assertIn("Raised", text)
        self.assertIn("Resolved", text)
        self.assertIn("alice", text)
        self.assertIn("backup-nightly.service", text)
        self.page.click('#problem-history-modal [data-action="closeModal"]')

    def test_muting_a_problem_from_its_row_mutes_its_event_on_its_host(self):
        self.open()
        row = self.row("jellyfin.lab", "service_down")
        self.assertTrue(row.count(), "the demo has no service_down problem on jellyfin.lab")
        before = {m["id"] for m in self.api("GET", "/alert-mutes")["mutes"]}
        self.press("jellyfin.lab", "service_down", "Mute")
        self.answer_dialog("1")
        new = self.until("a mute for service_down appeared", lambda: [
            m for m in self.api("GET", "/alert-mutes")["mutes"] if m["id"] not in before and m["event"] == "service_down"])
        self.addCleanup(lambda: [self.api("DELETE", "/alert-mutes/" + m["id"]) for m in new])
        self.assertEqual({(m["event"], m.get("device_id")) for m in new}, {("service_down", "jf01")})

    def test_ignoring_a_problem_hides_its_needs_attention_items(self):
        self.open()
        # a problem that Needs attention lists and no alert raised: the patches of a host
        victims = self.page.evaluate("""() => _problemsRows.filter(r => r.device_id && !r.alert_total && (r.attention || []).some(i => i.ignore_key))
            .map(r => [r.device, r.family])""")
        self.assertTrue(victims, "the demo has no Needs attention item without an alert")
        host, family = victims[0]
        keys = self.page.evaluate("([h, f]) => _problemsRows.find(r => r.device === h && r.family === f).attention.map(i => i.ignore_key)", [host, family])
        self.press(host, family, "Ignore")
        self.addCleanup(lambda: [self.api("POST", "/ignored/remove", {"category": "needs_attention", "key": k}) for k in keys])
        got = self.until("every item of the problem is on the ignored list",
                         lambda: (lambda have: have if all(k in have for k in keys) else None)(self.ignored()))
        for k in keys:
            self.assertNotIn("expires_at", got[k], "Ignore is permanent: it must not carry an expiry")
        self.page.wait_for_function("([h, f]) => !_problemsRows.some(r => r.device === h && r.family === f && (r.attention || []).length)", arg=[host, family], timeout=30000)

    def test_snoozing_sets_an_expiry_a_day_ahead(self):
        self.open()
        victims = self.page.evaluate("""() => _problemsRows.filter(r => r.device_id && !r.alert_total && (r.attention || []).some(i => i.ignore_key))
            .map(r => [r.device, r.family])""")
        host, family = victims[-1]
        keys = self.page.evaluate("([h, f]) => _problemsRows.find(r => r.device === h && r.family === f).attention.map(i => i.ignore_key)", [host, family])
        self.press(host, family, "Snooze 24 h")
        self.addCleanup(lambda: [self.api("POST", "/ignored/remove", {"category": "needs_attention", "key": k}) for k in keys])
        got = self.until("every item of the problem is on the ignored list",
                         lambda: (lambda have: have if all(k in have for k in keys) else None)(self.ignored()))
        soon = int(time.time()) + 86400
        for k in keys:
            self.assertIn("expires_at", got[k], "the snooze carries no expiry")
            self.assertAlmostEqual(got[k]["expires_at"], soon, delta=600)

    def test_disabling_a_check_from_its_row_switches_it_off_on_that_host(self):
        self.open()
        self.press(HOST, "failed_units", "Disable check")
        self.answer_dialog()
        self.addCleanup(lambda: self.api("POST", "/checks/toggle", {"device_id": HOST_ID, "check": "services", "enabled": True}))

        def services_off():
            h = next((x for x in self.api("GET", "/checks")["hosts"] if x["device_id"] == HOST_ID), None)
            return bool(h) and any(c["key"] == "services" and c["enabled"] is False for c in h["checks"])
        self.until("the services check of nextcloud.lab is switched off", services_off)

    def test_fix_opens_the_investigate_dialog_for_the_host_and_kind_the_row_names(self):
        self.open()
        self.page.evaluate("() => { window.__fix = null; window.__realFix = openMitigateModal; openMitigateModal = (...a) => { window.__fix = a; }; }")
        try:
            self.press(HOST, "failed_units", "Fix")
            args = self.page.evaluate("() => window.__fix")
        finally:
            self.page.evaluate("() => { openMitigateModal = window.__realFix; }")
        self.assertIsNotNone(args, "Fix did not open the dialog")
        self.assertEqual((args[0], args[1]), (HOST_ID, "failed_units"))
        self.assertEqual(args[3], HOST)

    def test_a_late_answer_does_not_overwrite_the_view_just_chosen(self):
        """Two loads in flight, the older one answering last: the table must show the view that was chosen last. The first
        answer is held back on purpose, so the order is not left to timing."""
        self.open()
        self.page.evaluate("""() => {
            window.__realApi = api; let n = 0;
            api = (m, p, b) => {
                if (String(p).startsWith('/problems?')) {
                    const mine = ++n;
                    return window.__realApi(m, p, b).then(r => new Promise(res => setTimeout(() => res(r), mine === 1 ? 1500 : 0)));
                }
                return window.__realApi(m, p, b);
            };
            loadProblems();              // the first answer (every problem) is held back for 1.5 s
            setProblemsView('check');    // the second (only the problems a check shows) comes at once
        }""")
        try:
            self.page.wait_for_timeout(2600)       # long enough for the held-back answer to arrive
            self.drawn()
            rows = self.page.evaluate(ROWS)
            self.assertTrue(rows)
            self.assertTrue(all("Check" in r["where"] for r in rows),
                            "the late answer for every problem was drawn over the view that was chosen last")
        finally:
            self.page.evaluate("() => { api = window.__realApi; }")
            self.open()

    def test_a_row_offers_exactly_the_actions_its_data_allows(self):
        """Every row of the seeded demo: the menu in the page is the menu the row's own fields call for, so a row never
        offers an action it cannot do and never hides one it can."""
        self.open("all")
        report = self.page.evaluate("""() => {
            const admin = !!(_meCache && _meCache.admin);
            const out = {checked: 0, withMenu: 0, wrong: []};
            for (const tr of document.querySelectorAll('#problems-tbody tr')) {
                const btn = tr.querySelector('[data-action="openProblemHistory"]');
                if (!btn) continue;
                const r = _problemsRows.find(x => x.key === btn.dataset.arg);
                const tpl = tr.querySelector('template.row-more-items');
                const got = tpl ? [...tpl.content.querySelectorAll('[data-action]')].map(b => b.dataset.action).sort() : [];
                const want = [];
                if (admin && ((r.mute_events || []).length || (!r.device_id && (r.open_ids || []).length))) want.push('muteProblem');
                if (admin && (r.attention || []).some(i => i.ignore_key)) want.push('snoozeProblem', 'ignoreProblem');
                if (admin && (r.checks || []).some(c => c.key) && r.device_id) want.push('disableProblemChecks');
                if (r.fix && r.device_id) want.push('fixProblem');
                want.sort();
                const resolve = !!tr.querySelector('[data-action="resolveProblem"]');
                out.checked++;
                if (tpl) out.withMenu++;
                if (JSON.stringify(got) !== JSON.stringify(want) || resolve !== (admin && (r.open_ids || []).length > 0)) out.wrong.push([r.key, got, want, resolve]);
            }
            return out;
        }""")
        self.assertGreater(report["checked"], 20, "the check looked at too few rows to mean anything")
        self.assertGreater(report["withMenu"], 5, "the demo has too few rows with a menu to mean anything")
        self.assertEqual(report["wrong"], [])

TAG = {"resolved_but_failing": "Alert resolved, still failing", "waiting_for_report": "Alert resolved, waiting for the host"}


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheStateIsTheSameOnEveryPage(unittest.TestCase):
    """Alerts, Needs Attention and Checks say what Problems says about a problem, and a bar links the four pages.

    Named so that it runs after TestTheProblemsPage and before TestTheViewsAndTheActions: the last test here
    resolves a problem, which the first class has done already and the second does not depend on."""

    @property
    def page(self):
        return _STACK["page"]

    def tearDown(self):
        self.assertEqual(_STACK["errors"], [], "the page threw")

    def api(self, method, path, body=None):
        return self.page.evaluate("([m, p, b]) => api(m, p, b || undefined)", [method, path, body])

    def until(self, what, ask, timeout=45.0):
        end = time.time() + timeout
        while time.time() < end:
            got = ask()
            if got:
                return got
            time.sleep(0.4)
        self.fail(f"never happened: {what}")

    def show(self, name):
        self.page.evaluate("n => showPage(n)", name)
        self.page.wait_for_selector(f"#page-{name}.active", timeout=60000)

    def press_bar(self, src, dest):
        """Click a button of the bar. The sidebar opens over the left 248 px of the page while the pointer is on it,
        and the bar starts at 80, so the pointer is parked on the page first, as a person's would be."""
        self.page.mouse.move(900, 600)
        self.page.wait_for_timeout(500)
        self.page.click(f'#page-{src} .problem-views [data-arg="{dest}"]', timeout=15000)

    def cells(self, tbody):
        """The text of every cell of every row of a table body."""
        return self.page.evaluate("""id => [...document.querySelectorAll('#' + id + ' tr')]
            .map(tr => [...tr.querySelectorAll('td')].map(td => td.textContent.replace(/\\s+/g, ' ').trim()))""", tbody)

    # ── the state beside the item and the check ──────────────────────────────────────────────────────────────

    def test_needs_attention_says_the_alert_was_resolved_and_the_host_still_reports_it(self):
        self.show("attention")
        self.page.fill("#attention-filter", "backup-nightly")      # the table shows 15 rows a page
        try:
            rows = self.until("the failed-units item carries the tag", lambda: [
                c for c in self.cells("attention-tbody")
                if len(c) > 3 and HOST in c[2] and c[1] == "failed_units" and TAG["resolved_but_failing"] in c[3]])
        finally:
            self.page.fill("#attention-filter", "")
        self.assertEqual(len(rows), 1, rows)

    def test_checks_says_it_beside_the_failing_check(self):
        self.show("checks")
        name = self.until("the page holds the check", lambda: self.page.evaluate(
            "([h]) => { const r = (typeof _checksRows !== 'undefined' ? _checksRows : []).find(x => x.device_id === h && x.key === 'services'); return r ? r.check : ''; }", [HOST_ID]))
        self.page.fill("#checks-filter-text", "nextcloud")
        try:
            rows = self.until("the check carries the tag", lambda: [
                c for c in self.cells("checks-tbody") if len(c) > 4 and HOST in c[0] and name in c[2] and TAG["resolved_but_failing"] in c[3]])
        finally:
            self.page.fill("#checks-filter-text", "")
        self.assertEqual(len(rows), 1, rows)

    def test_the_state_is_only_built_when_it_is_asked_for(self):
        plain = self.api("GET", "/attention")
        self.assertFalse([i for i in plain["items"] if "problem" in i], "the dashboard card would pay for the state")
        asked = self.api("GET", "/attention?problems=1")
        mine = [i for i in asked["items"] if i.get("device_id") == HOST_ID and i.get("kind") == "failed_units"]
        self.assertEqual([i["problem"]["state"] for i in mine], ["resolved_but_failing"])
        self.assertEqual(mine[0]["problem"]["resolved_by"], "alice")

        def checks(path):
            hosts = self.api("GET", path)["hosts"]
            return [c for h in hosts if h["device_id"] == HOST_ID for c in h["checks"] if c["key"] == "services"]
        self.assertFalse([c for c in checks("/checks") if "problem" in c])
        self.assertEqual([c["problem"]["state"] for c in checks("/checks?problems=1")], ["resolved_but_failing"])

    # ── the bar ────────────────────────────────────────────────────────────────────────────────────────────

    def test_the_bar_links_the_four_pages_and_marks_the_one_you_are_on(self):
        for name in ("alerts", "attention", "checks"):
            self.show(name)
            shown = self.page.evaluate("""n => ({
                marked: [...document.querySelectorAll('#page-' + n + ' .problem-views [aria-current=page]')].map(b => b.dataset.arg),
                labels: [...document.querySelectorAll('#page-' + n + ' .problem-views button')].map(b => b.textContent.trim()) })""", name)
            self.assertEqual(shown["marked"], [name])
            self.assertEqual(shown["labels"], ["All problems", "Alerts", "Needs Attention", "Checks"])
        for src in ("alerts", "attention", "checks"):
            for dest in ("problems", "alerts", "attention", "checks"):
                self.show(src)
                self.press_bar(src, dest)
                self.page.wait_for_selector(f"#page-{dest}.active", timeout=60000)

    def test_arriving_from_a_bar_starts_at_every_problem(self):
        self.show("problems")
        self.page.evaluate("setProblemsView('alert')")
        self.page.wait_for_function("() => _problemsView === 'alert' && _problemsSeq > 0 && _problemsDrawn === _problemsSeq", timeout=60000)
        before = self.page.evaluate("() => _problemsSeq")
        self.show("alerts")
        self.press_bar("alerts", "problems")
        self.page.wait_for_selector("#page-problems.active", timeout=60000)
        # arriving asks again (a counter that has not moved would also read as "drawn"), and the answer is the whole list
        self.page.wait_for_function("(n) => _problemsView === '' && _problemsSeq > n && _problemsDrawn === _problemsSeq", arg=before, timeout=20000)
        self.assertEqual(self.page.evaluate("() => document.querySelector('#problems-views .active').dataset.arg"), "")
        shown = len(self.page.evaluate(ROWS))
        self.assertEqual(shown, int(self.page.inner_text("#problems-view-n-all")), "arriving drew a filtered list")

    # ── one click, four pages ──────────────────────────────────────────────────────────────────────────────

    def test_resolving_a_problem_changes_what_every_page_says_about_it(self):
        self.show("problems")
        self.page.evaluate("loadProblems()")
        self.page.wait_for_function("() => _problemsSeq > 0 && _problemsDrawn === _problemsSeq", timeout=60000)
        # a problem with an open alert and something the host reports: an item or a check. Not the two the other tests use.
        victims = self.page.evaluate("""() => _problemsRows.filter(r => r.device_id && (r.open_ids || []).length
                && ((r.attention || []).length || (r.checks || []).length) && !['jellyfin.lab', HOSTNAME].includes(r.device))
            .map(r => ({device_id: r.device_id, device: r.device, family: r.family, ids: r.open_ids,
                        items: (r.attention || []).length, checks: (r.checks || []).length}))""".replace("HOSTNAME", repr(HOST)))
        self.assertTrue(victims, "the demo has no problem with an open alert and an item or a check to resolve")
        v = victims[0]
        row = (self.page.locator("#problems-tbody tr", has=self.page.locator(".tl-devchip", has_text=v["device"]))
               .filter(has_text=v["family"]).first)
        row.scroll_into_view_if_needed()
        row.locator('[data-action="resolveProblem"]').click()

        def settled():
            rows = self.api("GET", f"/problems?state=all&device_id={v['device_id']}")["problems"]
            return next((r["state"] for r in rows if r["family"] == v["family"] and r["state"] in TAG), None)
        state = self.until("the problem reads as resolved while the host still reports it", settled)

        # the Alerts page's own data: the alerts that were resolved carry the same word
        listing = self.api("GET", f"/alerts?status=resolved&limit=200&device_id={v['device_id']}")["alerts"]
        marked = {a["id"]: a.get("problem_state") for a in listing if a["id"] in v["ids"]}
        self.assertEqual(marked, {i: state for i in v["ids"]})
        # the Needs attention data and the page
        if v["items"]:
            items = [i for i in self.api("GET", "/attention?problems=1")["items"]
                     if i.get("device_id") == v["device_id"] and i.get("kind") == v["family"]]
            self.assertEqual({i["problem"]["state"] for i in items}, {state})
            self.show("attention")
            self.page.fill("#attention-filter", v["device"])      # the table shows 15 rows a page
            try:
                self.until("the page prints the tag", lambda: [c for c in self.cells("attention-tbody")
                           if len(c) > 3 and v["device"] in c[2] and c[1] == v["family"] and TAG[state] in c[3]])
            finally:
                self.page.fill("#attention-filter", "")
        # the Checks data
        if v["checks"]:
            hosts = self.api("GET", "/checks?problems=1")["hosts"]
            tagged = [c["problem"]["state"] for h in hosts if h["device_id"] == v["device_id"] for c in h["checks"] if c.get("problem")]
            self.assertTrue(tagged and set(tagged) == {state}, tagged)


if __name__ == "__main__":
    unittest.main()
