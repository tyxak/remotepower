#!/usr/bin/env python3
"""8.0.0: the Timeline can send a past event through the notification channels again, in a browser on the demo seed.

`POST /api/webhook/replay` has re-fired an event of the activity feed since 5.0.0 and nothing in the page called it. A Timeline row that is a fleet event has a replay button for the platform
operator, and it asks first, because the other end is a person who will be told again. This file holds what a person sees and what the server holds afterwards: the button is on the rows that are
fleet events and not on a command run, cancelling sends nothing, confirming sends the row's own event and time and leaves an audit entry, a refusal is said in words, a viewer and a tenant's
administrator are not offered it, and the words are translated. tests/test_v800_timeline_event_field.py holds the server's half.

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
except ImportError:  # pragma: no cover
    sync_playwright = None

_STATE = {}
LANGS = ("zh", "hi", "es", "ar", "de", "fr")
BUTTON = '#timeline-body [data-action="timelineReplay"]'


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("the timeline is backend-agnostic: measured once, under the default backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-webhook-replay-e2e-")
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


def _login(browser, user):
    ctx = browser.new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
    ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")
    page = ctx.new_page()
    page.set_default_timeout(20000)
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(_STATE["base"] + "/index.html")
    page.fill("#login-user", user)
    page.fill("#login-pass", "demo")
    page.click('#login-form button[type="submit"]')
    page.wait_for_selector("#app", state="visible", timeout=90000)
    page.wait_for_timeout(3000)
    return ctx, page, errors


def open_timeline(page):
    page.evaluate("() => { showPage('timeline'); }")
    page.wait_for_selector("#timeline-body .tl-row", timeout=30000)


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheOperatorReplaysAnEvent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ctx, cls.page, cls.errors = _login(_STATE["browser"], "alice")  # the seeder's operator account: an admin of the default tenant

    @classmethod
    def tearDownClass(cls):
        cls.ctx.close()

    def setUp(self):
        self.page.reload()
        self.page.wait_for_selector("#app", state="visible", timeout=90000)
        self.page.wait_for_timeout(2000)
        open_timeline(self.page)

    def tearDown(self):
        self.page.unroute_all(behavior="ignoreErrors")

    def test_a_fleet_event_row_has_the_button_and_the_other_rows_do_not(self):
        shown = self.page.evaluate("() => _timelineItems.slice(0, _timelineShown).map(i => !!i.event)")
        self.assertIn(True, shown, "the demo has fleet events")
        self.assertIn(False, shown, "and rows that are not (a command run or the CVE row): the control of this check")
        buttons = self.page.locator(BUTTON).count()
        self.assertEqual(buttons, shown.count(True))
        rows = self.page.locator("#timeline-body .tl-row")
        self.assertEqual(rows.count(), len(shown))
        for i, has_event in enumerate(shown):
            self.assertEqual(rows.nth(i).locator('[data-action="timelineReplay"]').count(), 1 if has_event else 0, i)

    def test_the_button_asks_first_and_cancel_sends_nothing(self):
        posts = []
        self.page.on("request", lambda r: posts.append(r.url) if r.method == "POST" and r.url.endswith("/api/webhook/replay") else None)
        self.page.locator(BUTTON).first.click()
        self.page.wait_for_selector("#ui-prompt-modal.active", timeout=20000)
        self.assertEqual(self.page.inner_text("#ui-prompt-title").strip(), "Replay this event")
        self.assertIn("the people on those channels are told again", self.page.inner_text("#ui-prompt-message"))
        self.page.click('#ui-prompt-modal [data-action="_uiPromptCancel"]')
        self.page.wait_for_timeout(1000)
        self.assertEqual(posts, [])

    def test_confirming_sends_the_rows_own_event_and_time_and_leaves_an_audit_entry(self):
        button = self.page.locator(BUTTON).first
        event, ts = button.get_attribute("data-arg"), int(button.get_attribute("data-arg2"))
        button.click()
        self.page.wait_for_selector("#ui-prompt-modal.active", timeout=20000)
        with self.page.expect_response(lambda r: r.request.method == "POST" and r.url.endswith("/api/webhook/replay"), timeout=20000) as info:
            self.page.click("#ui-prompt-confirm")
        self.assertEqual(info.value.status, 200, info.value.text()[:200])
        self.assertEqual(info.value.request.post_data_json, {"event": event, "ts": ts})
        self.page.wait_for_function("() => document.body.innerText.includes('Event replayed')", timeout=10000)
        log = self.page.evaluate("async () => await api('GET', '/audit-log')")
        entries = log if isinstance(log, list) else (log.get("entries") or log.get("log") or [])
        self.assertTrue(any(e.get("action") == "webhook_replay" and f"event={event} ts={ts}" in str(e.get("detail", "")) for e in entries), entries[-3:])

    def test_a_refusal_is_said_in_words(self):
        reason = "no matching fleet event to replay"
        self.page.route("**/api/webhook/replay", lambda route: route.fulfill(status=404, content_type="application/json", body=json.dumps({"error": reason})))
        self.page.locator(BUTTON).first.click()
        self.page.wait_for_selector("#ui-prompt-modal.active", timeout=20000)
        self.page.click("#ui-prompt-confirm")
        self.page.wait_for_function("(t) => document.body.innerText.includes(t)", arg=reason, timeout=15000)
        self.assertNotIn("Event replayed", self.page.inner_text("body"))

    def test_a_replay_that_gets_no_answer_says_so(self):
        self.page.route("**/api/webhook/replay", lambda route: route.abort())
        self.page.locator(BUTTON).first.click()
        self.page.wait_for_selector("#ui-prompt-modal.active", timeout=20000)
        self.page.click("#ui-prompt-confirm")
        self.page.wait_for_function("() => document.body.innerText.includes('The server did not answer.')", timeout=15000)
        self.assertNotIn("Event replayed", self.page.inner_text("body"))

    def test_a_refusal_is_said_once_not_twice(self):
        reason = "no matching fleet event to replay"
        self.page.route("**/api/webhook/replay", lambda route: route.fulfill(status=404, content_type="application/json", body=json.dumps({"error": reason})))
        self.page.locator(BUTTON).first.click()
        self.page.wait_for_selector("#ui-prompt-modal.active", timeout=20000)
        self.page.click("#ui-prompt-confirm")
        self.page.wait_for_function("(t) => document.body.innerText.includes(t)", arg=reason, timeout=15000)
        self.page.wait_for_timeout(800)
        self.assertEqual(self.page.evaluate("(t) => [...document.querySelectorAll('.toast')].filter(e => e.textContent.includes(t)).length", reason), 1)

    def test_the_words_are_translated_in_all_six_languages(self):
        self.page.evaluate("async () => { await _ensureI18n(); }")
        button = self.page.locator(BUTTON).first
        button.click()
        self.page.wait_for_selector("#ui-prompt-modal.active", timeout=20000)
        pick = "() => [document.getElementById('ui-prompt-title').textContent.trim(), document.getElementById('ui-prompt-message').textContent.trim(), document.getElementById('ui-prompt-confirm').textContent.trim(), document.querySelector('#timeline-body [data-action=\"timelineReplay\"]').getAttribute('title')]"
        english = self.page.evaluate(pick)
        bad = []
        try:
            for lang in LANGS:
                self.page.evaluate("(l) => RPi18n.setLang(l, false)", lang)
                self.page.wait_for_timeout(400)
                now = self.page.evaluate(pick)
                same = [i for i in range(3) if now[i] == english[i]]
                if same or now[3] == english[3]:
                    bad.append((lang, same, now[3] == english[3]))
        finally:
            self.page.evaluate("() => RPi18n.setLang('en', false)")
        self.assertEqual(bad, [])

    def test_nothing_in_the_page_broke_on_the_way(self):
        self.page.locator(BUTTON).first.click()
        self.page.wait_for_selector("#ui-prompt-modal.active", timeout=20000)
        self.assertEqual([e for e in self.errors if "Failed to load resource" not in e], [])


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestWhoIsOfferedTheButton(unittest.TestCase):
    """The same rows, rendered for other callers: the button follows the caller, not the data."""

    ITEM = "{kind: 'device_offline', event: 'device_offline', ts: 1790000000, severity: 'high', title: 'Host offline', detail: 'x', device_id: 'd', device_name: 'd'}"

    def render_for(self, page):
        open_timeline(page)
        page.evaluate("() => { _timelineItems = [" + self.ITEM + "]; _timelineShown = 50; _renderTimeline(); }")
        return page.locator(BUTTON).count()

    def test_the_operator_is_offered_it_on_the_row_that_carries_an_event(self):
        ctx, page, _ = _login(_STATE["browser"], "alice")
        try:
            self.assertEqual(self.render_for(page), 1)
        finally:
            ctx.close()

    def test_a_viewer_is_not(self):
        ctx, page, _ = _login(_STATE["browser"], "demo")  # the seeder's read-only login
        try:
            self.assertEqual(self.render_for(page), 0)
        finally:
            ctx.close()

    def test_a_tenant_s_administrator_is_not(self):
        ctx_a, page_a, _ = _login(_STATE["browser"], "alice")
        try:
            tid = page_a.evaluate("async () => (await api('POST', '/tenants', {name: 'Replay Tenant'})).id")
        finally:
            ctx_a.close()
        users = read("users.json")
        users["tenantadmin"] = dict(users["alice"], tenant_id=tid)  # alice's login, in another tenant
        write("users.json", users)
        ctx, page, _ = _login(_STATE["browser"], "tenantadmin")
        try:
            self.assertEqual(self.render_for(page), 0)
        finally:
            ctx.close()


if __name__ == "__main__":
    unittest.main()
