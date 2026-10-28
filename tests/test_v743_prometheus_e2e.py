#!/usr/bin/env python3
"""7.4.3, issue #46: the Prometheus connectors in Settings -> Integrations.

The parsers, the connectors and the server's handlers are in test_v743_prometheus. What that cannot show
is the page: that the card of a Prometheus instance has a box of several lines for its values (the other
connectors only have one-line fields), that it takes the whole row, that an instance saved with its lines,
its path, its thresholds and the host it runs on comes back from the server with all of them when the page
reads it again (before 7.4.3 the form came back without the thresholds, and the next save from it wiped
them), that saving what the form was given changes nothing, and that a line the server cannot read is
refused with its line number and nothing is kept.

The page is real (a seeded instance, a signed-in browser). Self-skips without playwright/chromium/gunicorn,
like its siblings.
"""
import os
import re
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
HOST = "fw01"


def _sign_in(browser, base, user, password):
    context = browser.new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
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
    data_dir = tempfile.mkdtemp(prefix="rp-prom-")
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


@unittest.skipUnless(_GATE, SKIP_REASON)
class _Page(unittest.TestCase):

    @property
    def page(self):
        return _STACK["page"]

    def setUp(self):
        self.page.evaluate("() => document.querySelectorAll('.toast').forEach(t => t.remove())")
        self.remove_mine()

    def tearDown(self):
        self.remove_mine()
        self.assertEqual(_STACK["errors"], [], "the page threw")

    def remove_mine(self):
        """Take out what a test added, through the API, so the next one starts from the seeded fleet."""
        self.page.evaluate("""async () => {
            const r = await api('GET', '/integrations');
            const keep = ((r && r.integrations) || []).filter(i => !String(i.label || '').startsWith('E2E '));
            if (keep.length !== ((r && r.integrations) || []).length)
              await api('POST', '/integrations', {integrations: keep, interval: r.interval, show_homelab: true});
        }""")

    @classmethod
    def setUpClass(cls):
        page = _STACK["page"]
        page.evaluate("showPage('settings')")
        page.wait_for_selector("#settings-tab-btn-integrations", state="attached", timeout=30000)
        # the page loads what it shows on its own as it opens; let that finish once, here, or it draws
        # the cards a second time under whatever a test has just done
        page.wait_for_timeout(10000)

    def open_pane(self):
        self.page.evaluate("switchSettingsTab('integrations')")
        # read the list from the server again, as opening the page after a reload does
        self.page.evaluate("async () => { await loadIntegrations(); }")
        self.page.wait_for_function(
            "() => { const s = document.getElementById('integration-add-type'); return !!s && s.options.length > 10; }",
            timeout=30000)

    def press(self, selector):
        """Press a button by dispatching its click, which the page's own handler answers; where the
        button sits on screen is what the layout gates measure, not this test."""
        self.page.eval_on_selector(selector, "e => e.click()")

    def add(self, kind):
        """Pick the type in the box under the list and press Add, as a person does."""
        before = self.page.eval_on_selector_all("#integrations-list .integration-card", "els => els.length")
        self.page.select_option("#integration-add-type", kind)
        self.assertEqual(self.page.input_value("#integration-add-type"), kind)
        self.press('#settings-pane-integrations [data-action="addIntegration"]')
        self.page.wait_for_function(
            "(n) => document.querySelectorAll('#integrations-list .integration-card').length === n + 1", arg=before,
            timeout=15000)
        return self.page.query_selector_all("#integrations-list .integration-card")[-1]

    def listing(self):
        return self.page.evaluate("async () => (await api('GET', '/integrations')).integrations")

    def mine(self):
        return [i for i in self.listing() if str(i.get("label") or "").startswith("E2E ")]

    def last_card(self):
        return self.page.query_selector_all("#integrations-list .integration-card")[-1]


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheCard(_Page):

    LINES = "mem_active = node_memory_active_bytes\nroot_free = node_filesystem_avail_bytes{mountpoint=\"/\"}"

    def test_the_catalog_offers_both_and_the_card_has_a_box_for_the_lines(self):
        self.open_pane()
        options = self.page.eval_on_selector_all("#integration-add-type option", "els => els.map(o => [o.value, o.textContent])")
        labels = dict(options)
        self.assertIn("Prometheus (PromQL query)", labels["prometheus"])
        self.assertIn("Prometheus exporter (/metrics scrape)", labels["prometheus_exporter"])
        card = self.add("prometheus_exporter")
        box = card.query_selector('textarea[data-ifield="prom_lines"]')
        self.assertIsNotNone(box, "several lines need a textarea, not a one-line input")
        self.assertIn("node_memory_active_bytes", box.get_attribute("placeholder"))
        self.assertGreaterEqual(box.evaluate("e => e.rows"), 3)
        self.assertIsNotNone(card.query_selector('input[data-ifield="prom_path"]'))
        self.assertIsNotNone(card.query_selector('input[type="password"][data-ifield="secret"]'))
        # the box has the room of the card, not the width of a short field
        card_w = card.evaluate("e => e.getBoundingClientRect().width")
        self.assertGreater(box.evaluate("e => e.getBoundingClientRect().width"), card_w * 0.7)

    def test_the_promql_card_has_its_own_placeholder_and_no_path(self):
        self.open_pane()
        card = self.add("prometheus")
        self.assertIn("PromQL", card.inner_text() + (card.query_selector("p.hint").inner_text()))
        self.assertIn("instance=", card.query_selector('textarea[data-ifield="prom_lines"]').get_attribute("placeholder"))
        self.assertIsNone(card.query_selector('input[data-ifield="prom_path"]'))

    def fill_card(self, card, lines=None):
        card.query_selector('input[data-ifield="label"]').fill("E2E node_exporter")
        card.query_selector('input[data-ifield="url"]').fill("http://192.0.2.50:9100")
        card.query_selector('input[data-ifield="prom_path"]').fill("/stats/prom")
        card.query_selector('textarea[data-ifield="prom_lines"]').fill(lines if lines is not None else self.LINES)
        card.query_selector('select[data-ifield="device_id"]').select_option(HOST)
        card.query_selector("details summary").click()                # Alert on a metric
        card.query_selector("textarea[data-ithresh]").fill("mem_active gt 2000000000 high")

    def save(self):
        self.press('#settings-pane-integrations [data-action="saveIntegrations"]')

    def test_everything_typed_comes_back_when_the_page_reads_it_again(self):
        self.open_pane()
        self.fill_card(self.add("prometheus_exporter"))
        self.save()
        self.page.wait_for_selector(".toast.success", timeout=20000)
        saved = self.mine()
        self.assertEqual(len(saved), 1, saved)
        self.assertEqual(saved[0]["prom_lines"], self.LINES)
        self.assertEqual(saved[0]["prom_path"], "/stats/prom")
        self.assertEqual(saved[0]["device_id"], HOST)
        self.assertEqual(saved[0]["metric_thresholds"][0]["metric"], "mem_active")
        # the form was drawn again from that answer: the box and the thresholds hold what was typed
        self.page.wait_for_function(
            "() => Array.from(document.querySelectorAll('#integrations-list .integration-card')).some(c => "
            "(c.querySelector('[data-ifield=label]') || {}).value === 'E2E node_exporter')", timeout=15000)
        card = [c for c in self.page.query_selector_all("#integrations-list .integration-card")
                if c.query_selector('[data-ifield="label"]').input_value() == "E2E node_exporter"][0]
        self.assertEqual(card.query_selector('textarea[data-ifield="prom_lines"]').input_value(), self.LINES)
        self.assertEqual(card.query_selector('input[data-ifield="prom_path"]').input_value(), "/stats/prom")
        self.assertIn("mem_active gt 2000000000 high", card.query_selector("textarea[data-ithresh]").input_value())
        self.assertEqual(card.query_selector('select[data-ifield="device_id"]').input_value(), HOST)

    def test_saving_what_the_form_was_given_changes_nothing(self):
        self.open_pane()
        self.fill_card(self.add("prometheus_exporter"))
        self.save()
        self.page.wait_for_selector(".toast.success", timeout=20000)
        before = self.mine()[0]
        self.page.evaluate("() => document.querySelectorAll('.toast').forEach(t => t.remove())")
        self.save()                                                    # nothing edited
        self.page.wait_for_selector(".toast.success", timeout=20000)
        after = self.mine()[0]
        for key in ("prom_lines", "prom_path", "metric_thresholds", "device_id", "url", "label"):
            self.assertEqual(after.get(key), before.get(key), key)

    def test_a_line_the_server_cannot_read_is_refused_with_its_number(self):
        self.open_pane()
        self.fill_card(self.add("prometheus_exporter"), lines='ok = node_load1\nbad = m{a=~"x"}')
        self.save()
        self.page.wait_for_selector(".toast.error", timeout=20000)
        text = self.page.inner_text(".toast.error")
        self.assertIn("line 2", text)
        self.assertIn("E2E node_exporter", text)
        self.assertEqual(self.mine(), [], "nothing was kept")

    def test_a_custom_probe_keeps_its_fields_through_a_save_from_the_form(self):
        """The same fix for a connector that was already there: its path and thresholds used to vanish."""
        self.page.evaluate("""async () => {
            const r = await api('GET', '/integrations');
            const list = (r.integrations || []).concat([{type: 'custom_probe', label: 'E2E probe',
              url: 'http://192.0.2.60:8080', enabled: true, probe_path: '/health', probe_expect: '204',
              metric_thresholds: [{metric: 'http_status', op: 'gt', value: 300, severity: 'high'}]}]);
            await api('POST', '/integrations', {integrations: list, interval: r.interval, show_homelab: true});
        }""")
        self.open_pane()
        self.page.wait_for_function(
            "() => Array.from(document.querySelectorAll('#integrations-list .integration-card')).some(c => "
            "(c.querySelector('[data-ifield=label]') || {}).value === 'E2E probe')", timeout=15000)
        card = [c for c in self.page.query_selector_all("#integrations-list .integration-card")
                if c.query_selector('[data-ifield="label"]').input_value() == "E2E probe"][0]
        self.assertEqual(card.query_selector('input[data-ifield="probe_path"]').input_value(), "/health")
        self.assertIn("http_status gt 300 high", card.query_selector("textarea[data-ithresh]").input_value())
        self.save()
        self.page.wait_for_selector(".toast.success", timeout=20000)
        kept = self.mine()[0]
        self.assertEqual((kept["probe_path"], kept["probe_expect"]), ("/health", "204"))
        self.assertEqual(kept["metric_thresholds"][0]["metric"], "http_status")


if __name__ == "__main__":
    unittest.main()
