#!/usr/bin/env python3
"""7.4.2, issue #44: the host's card shows the integrations bound to it, drawn by the real page.

What the server answers is in test_v742_host_integrations. What that cannot show is the drawer:
that the section is there for every host, opens by itself when something is bound (the point of
the issue is a host that looks empty), stays out of the way when nothing is, draws the status,
the latest values and a trend, and cannot be pushed onto the wrong host by a slow answer. The
page is real (a seeded instance, a signed-in browser, the drawer opened the way a person opens
it); only the one answer is canned.

Self-skips without playwright/chromium/gunicorn, like its siblings.
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
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

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
        raise unittest.SkipTest("what is measured is the page, not the backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-hostint-")
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
    # Service workers answer the page's requests before Playwright can see them.
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
    devs = page.evaluate("async () => (await api('GET', '/devices')).map(d => ({id: d.id, name: d.name}))")
    _STACK.update(pw=pw, browser=browser, shutdown=shutdown, page=page, base=base, errors=errors, devs=devs)


def tearDownModule():
    if not _STACK:
        return
    try:
        _STACK["browser"].close()
        _STACK["pw"].stop()
    finally:
        _STACK["shutdown"]()
        _STACK.clear()


NOW = int(time.time())


def row(label, status="ok", detail="HTTP 200", metrics=None, series=None, history=None,
        enabled=True, stats=None, type_="custom_probe", checked=NOW - 120, series_long=None):
    return {"id": label, "label": label, "type": type_, "type_label": "Custom HTTP probe",
            "enabled": enabled, "status": status, "detail": detail, "checked": checked,
            "version": None, "metrics": metrics or {}, "stats": stats or [],
            "series": series or {}, "series_long": series_long or {}, "history": history or []}


def pts(*vals):
    return [{"ts": NOW - 300 * (len(vals) - i), "val": v} for i, v in enumerate(vals)]


def hpts(*vals):
    """Hourly averages, the longer trend."""
    return [{"ts": NOW - 3600 * (len(vals) - i), "val": v} for i, v in enumerate(vals)]


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheSection(unittest.TestCase):

    def setUp(self):
        _STACK["errors"].clear()
        self.page = _STACK["page"]
        # The drawer keeps its audit sections between views of a host, so what one test left open
        # would be the next test's starting point. Start each from a freshly rendered tab.
        self.page.evaluate("""() => {
            const el = document.getElementById('drawer-audit-sections');
            if (el) { el.innerHTML = ''; delete el.dataset.rendered; }
        }""")

    def tearDown(self):
        self.page.evaluate("() => closeDeviceDrawer()")
        self.page.unroute("**/api/devices/*/integrations")

    def answer(self, rows, show_homelab=True, status=200, hold=None):
        """Answer the integrations read. A host id in `hold` has its request kept, unanswered,
        in self.held until the test releases it: the way to make an answer slow on purpose
        (a sleep inside the handler stops this side, not the page)."""
        self.held = []

        def handler(route):
            if hold and f"/devices/{hold}/" in route.request.url:
                self.held.append(route)
                return
            route.fulfill(status=status, content_type="application/json",
                          body=json.dumps({"integrations": rows, "show_homelab": show_homelab}))
        self.page.route("**/api/devices/*/integrations", handler)

    def release(self, rows):
        for route in self.held:
            route.fulfill(status=200, content_type="application/json",
                          body=json.dumps({"integrations": rows, "show_homelab": True}))
        self.held = []

    def open_audit(self, idx=0):
        dev = _STACK["devs"][idx]
        self.page.evaluate("([id, name]) => openDeviceDrawer(id, name, 'audit')", [dev["id"], dev["name"]])
        self.page.wait_for_selector("#audit-sec-integrations", state="attached", timeout=30000)
        return dev

    def section(self):
        return self.page.evaluate("""() => {
            const sec = document.getElementById('audit-sec-integrations');
            const body = document.getElementById('audit-body-integrations');
            const badge = document.getElementById('audit-badge-integrations');
            return {open: sec.open, badge: badge.textContent.trim(), text: body.textContent,
                    rows: Array.from(body.querySelectorAll('.integ-row')).map(r => ({
                        name: (r.querySelector('.integ-row-name') || {}).textContent,
                        pill: (r.querySelector('.status-pill') || {}).textContent,
                        pillClass: (r.querySelector('.status-pill') || {}).className,
                        stats: (r.querySelector('.integ-row-stats') || {}).textContent})),
                    sparks: body.querySelectorAll('svg').length,
                    html: body.innerHTML};
        }""")

    def wait_open(self):
        self.page.wait_for_function(
            "() => document.getElementById('audit-sec-integrations').open && "
            "document.querySelectorAll('#audit-body-integrations .integ-row').length > 0", timeout=30000)

    def test_it_opens_by_itself_and_draws_status_values_and_a_trend(self):
        self.answer([
            row("hub memory", status="warning", detail="freeMemory=412345 fails (lt 500000)",
                metrics={"http_status": 200, "freeMemory": 412345},
                series={"freeMemory": pts(520000, 480000, 455000, 412345), "http_status": pts(200, 200)},
                history=[{"ts": NOW - 600, "status": "ok"}, {"ts": NOW - 300, "status": "ok"},
                         {"ts": NOW, "status": "warning"}]),
            row("zigbee", status="critical", detail="radio offline", metrics={"devices": 31},
                series={"devices": pts(31)}),
            row("old probe", enabled=False, detail="disabled"),
        ])
        self.open_audit()
        self.wait_open()
        s = self.section()
        self.assertTrue(s["open"], "the section stays shut on a host that has integrations bound")
        self.assertEqual(s["badge"], "3 integrations")
        self.assertEqual([r["name"] for r in s["rows"]], ["hub memory", "zigbee", "old probe"],
                         "the order the server gave")
        self.assertIn("critical", s["rows"][1]["pillClass"])
        self.assertIn("warn", s["rows"][0]["pillClass"])
        self.assertIn("412,345", s["rows"][0]["stats"], "the latest value, formatted")
        self.assertIn("31", s["rows"][1]["stats"])
        self.assertEqual(s["sparks"], 2, "a trend per number with two or more points, none for the single one")
        self.assertIn("520000 → 412345", s["text"])
        self.assertNotIn("31 → 31", s["text"],
                         "a number with one point has no line, and no 'from, to' text either")
        self.assertIn("Last 3 checks: 2 ok · 1 warning", s["text"])
        self.assertEqual(_STACK["errors"], [], "the page threw")

    def test_a_longer_trend_is_drawn_when_it_reaches_further_back_than_the_last_polls(self):
        self.answer([row("hub memory", metrics={"freeMemory": 400000},
                         series={"freeMemory": pts(520000, 480000, 455000, 412345)},
                         series_long={"freeMemory": hpts(900000, 800000, 700000, 600000, 520000)})])
        self.open_audit()
        self.wait_open()
        s = self.section()
        self.assertEqual(s["sparks"], 2, "the last polls, and the hourly averages behind them")
        self.assertIn("hourly average", s["text"])
        self.assertIn("900000 → 520000", s["text"])
        self.assertIn("520000 → 412345", s["text"], "the short trend is still there")
        self.assertEqual(_STACK["errors"], [])

    def test_the_same_line_twice_is_not_drawn(self):
        """A long trend that reaches no further back than the short one, or has too few points to
        be a line, adds nothing to the card."""
        self.answer([
            # two points are not a line, however far apart they are
            row("a", series={"n": pts(1, 2, 3, 4)},
                series_long={"n": [{"ts": NOW - 36000, "val": 5}, {"ts": NOW - 3600, "val": 6}]}),
            row("b", series={"n": hpts(1, 2, 3, 4)}, series_long={"n": hpts(1, 2, 3, 4)}),
        ])
        self.open_audit()
        self.wait_open()
        s = self.section()
        self.assertEqual(s["sparks"], 2, "one line for each of a and b, and no second line")
        self.assertNotIn("hourly average", s["text"])

    def test_a_longer_trend_is_drawn_for_a_number_the_last_polls_no_longer_carry(self):
        self.answer([row("x", series={}, series_long={"old_metric": hpts(1, 2, 3)})])
        self.open_audit()
        self.wait_open()
        s = self.section()
        self.assertEqual(s["sparks"], 1)
        self.assertIn("old_metric", s["text"])

    def test_the_name_of_a_longer_trend_is_text_not_markup(self):
        evil = "<img src=x onerror=window.__pwned=1>"
        self.answer([row("x", series_long={evil: hpts(1, 2, 3)})])
        self.open_audit()
        self.wait_open()
        s = self.section()
        self.assertNotIn("<img", s["html"])
        self.assertIn(evil, s["text"])
        self.assertIsNone(self.page.evaluate("() => window.__pwned || null"))

    def test_a_host_with_nothing_bound_is_left_shut_and_says_so_when_opened(self):
        self.answer([])
        self.open_audit()
        self.page.wait_for_timeout(1500)
        s = self.section()
        self.assertFalse(s["open"], "an empty section must not take the screen")
        self.assertEqual(s["badge"], "collapsed")
        self.page.click("#audit-sec-integrations > summary")
        self.page.wait_for_function(
            "() => /No integrations are bound/.test(document.getElementById('audit-body-integrations').textContent)")
        s = self.section()
        self.assertIn("Runs on host", s["text"])
        self.assertEqual(s["badge"], "none")

    def test_the_homelab_switch_off_says_so(self):
        self.answer([], show_homelab=False)
        self.open_audit()
        self.page.wait_for_timeout(1000)
        self.page.click("#audit-sec-integrations > summary")
        self.page.wait_for_function(
            "() => /hidden on this instance/.test(document.getElementById('audit-body-integrations').textContent)")

    def test_a_refused_request_is_shown_as_the_refusal_when_the_section_is_opened(self):
        """A host outside the caller's scope answers with an error object. The section must say
        that, not 'no integrations are bound', which would be false."""
        page = self.page

        def handler(route):
            route.fulfill(status=403, content_type="application/json",
                          body=json.dumps({"error": "Host outside your role scope"}))
        page.route("**/api/devices/*/integrations", handler)
        self.open_audit()
        page.wait_for_timeout(1000)
        self.assertFalse(self.section()["open"], "an error must not open the section by itself")
        page.click("#audit-sec-integrations > summary")
        page.wait_for_function(
            "() => /outside your role scope/.test(document.getElementById('audit-body-integrations').textContent)")
        s = self.section()
        self.assertEqual(s["badge"], "error")
        self.assertNotIn("No integrations are bound", s["text"])

    def test_a_refusal_on_a_second_view_replaces_the_rows_that_were_there(self):
        """The sections are kept between views. A host seen with rows, then refused (its scope
        changed, say), must not go on showing the rows."""
        self.answer([row("old row", metrics={"n": 1})])
        self.open_audit(0)
        self.wait_open()
        self.page.evaluate("() => closeDeviceDrawer()")

        def refuse(route):
            route.fulfill(status=403, content_type="application/json",
                          body=json.dumps({"error": "Host outside your role scope"}))
        self.page.route("**/api/devices/*/integrations", refuse)
        self.open_audit(0)
        self.page.wait_for_function(
            "() => /outside your role scope/.test(document.getElementById('audit-body-integrations').textContent)",
            timeout=30000)
        s = self.section()
        self.assertNotIn("old row", s["text"])
        self.assertEqual(s["badge"], "error")

    def test_a_failed_request_leaves_the_section_shut_and_the_page_quiet(self):
        self.answer([], status=500)
        self.open_audit()
        self.page.wait_for_timeout(1500)
        self.assertFalse(self.section()["open"])
        self.assertEqual(_STACK["errors"], [])

    def test_a_slow_answer_cannot_open_the_section_of_the_host_you_moved_to(self):
        """Host A's answer arrives after the drawer has moved to host B. It must not open B's
        section or label B's badge."""
        if len(_STACK["devs"]) < 2:
            self.skipTest("the seeded fleet has one host")
        a = _STACK["devs"][0]
        page = self.page
        self.answer([], hold=a["id"])
        self.open_audit(0)
        page.wait_for_timeout(500)
        self.assertEqual(len(self.held), 1, "host A's request should be waiting")
        self.open_audit(1)
        page.wait_for_timeout(1000)
        self.release([row("A's probe", metrics={"n": 1})])
        page.wait_for_timeout(1500)
        s = self.section()
        self.assertFalse(s["open"], "host A's answer opened host B's section")
        self.assertEqual(s["badge"], "collapsed")
        self.assertNotIn("A's probe", s["html"])
        self.assertEqual(_STACK["errors"], [])

    def test_closing_the_drawer_before_the_answer_arrives_is_harmless(self):
        self.answer([], hold=_STACK["devs"][0]["id"])
        self.open_audit(0)
        self.page.wait_for_timeout(500)
        self.page.evaluate("() => closeDeviceDrawer()")
        self.release([row("late", metrics={"n": 1})])
        self.page.wait_for_timeout(1500)
        self.assertIsNone(self.page.evaluate("() => _drawerIntegrations"))
        self.assertEqual(_STACK["errors"], [])

    def test_a_late_answer_from_an_earlier_open_does_not_overwrite_a_newer_one(self):
        """Open a host, leave, come back: two requests for the same host are in flight. The one
        that was asked for first and answered last is the stale one."""
        host = _STACK["devs"][0]["id"]
        page = self.page
        self.answer([row("fresh", metrics={"n": 2})], hold=host)
        self.open_audit(0)
        page.wait_for_timeout(500)
        stale_route = self.held.pop()                    # the first open's request, unanswered
        page.evaluate("() => closeDeviceDrawer()")
        # A handler registered later runs first, so this answers the second open at once. The
        # first handler is not removed: unrouting would end the request it is holding.
        self.answer([row("fresh", metrics={"n": 2})])
        self.open_audit(0)
        self.wait_open()
        stale_route.fulfill(status=200, content_type="application/json", body=json.dumps(
            {"integrations": [row("stale", metrics={"n": 1})], "show_homelab": True}))
        page.wait_for_timeout(1500)
        self.assertEqual([r["name"] for r in self.section()["rows"]], ["fresh"])

    def test_reopening_the_same_host_asks_again_and_redraws(self):
        """The audit sections are kept between views of a host. A section left open must not
        go on showing what was bound last time."""
        self.answer([row("first", metrics={"n": 1})])
        self.open_audit(0)
        self.wait_open()
        self.assertEqual([r["name"] for r in self.section()["rows"]], ["first"])
        self.page.evaluate("() => closeDeviceDrawer()")
        self.page.unroute("**/api/devices/*/integrations")
        self.answer([row("second", metrics={"n": 2}), row("third")])
        self.open_audit(0)
        self.page.wait_for_function(
            "() => document.querySelectorAll('#audit-body-integrations .integ-row').length === 2", timeout=30000)
        self.assertEqual(sorted(r["name"] for r in self.section()["rows"]), ["second", "third"])
        self.assertEqual(self.section()["badge"], "2 integrations")

    def test_nothing_the_probe_said_is_taken_as_markup(self):
        self.answer([row("<img src=x onerror=window.__pwned=1>", detail="<b>bold</b>",
                         metrics={"<i>k</i>": "<script>window.__pwned=1</script>"},
                         series={"<u>s</u>": pts(1, 2)})])
        self.open_audit()
        self.wait_open()
        s = self.section()
        self.assertNotIn("<img", s["html"].replace("&lt;img", ""))
        self.assertFalse(self.page.evaluate("() => !!window.__pwned"))
        self.assertIn("<b>bold</b>", s["text"], "shown as the text it is")
        self.assertIn("<u>s</u>", s["text"], "a series label is text too")
        self.assertIn("<i>k</i>", s["text"], "and so is a metric name")


if __name__ == "__main__":
    unittest.main()
