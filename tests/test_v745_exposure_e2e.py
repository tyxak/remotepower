#!/usr/bin/env python3
"""7.4.5, issue #55: a host marked internal, on the pages.

The rules (what is private, what the switch does to the rows) are in test_v745_exposure_scope, the ingest
in test_v745_exposure_ingest and the route in test_v745_exposure_route. What those cannot show is the page:
that a socket on a host that holds reads "assumed internal" and not "world", that a host whose mark does
not hold says why on the first of its rows and only there, that the button beside a host is "Treat as
internal" until it is marked and "Not internal" after, that it can be clicked through its confirmation and
back, that the host's Ports card says the same, and that the new words come out in another language.

The page is real (a seeded instance, a signed-in browser, the dialogs opened the way a person opens them).
Self-skips without playwright/chromium/gunicorn, like its siblings.
"""
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
HOLDS, HOLDS_NAME = "jf01", "jellyfin.lab"          # private addresses only: the mark holds
BLOCKED, BLOCKED_NAME = "nc01", "nextcloud.lab"     # also a public address: it does not
PLAIN, PLAIN_NAME = "ng01", "nginx.lab"             # not marked, reports no addresses


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
    data_dir = tempfile.mkdtemp(prefix="rp-exposure-")
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
        # the engine loads on demand, the first time a language other than English is asked for
        self.page.evaluate("() => { if (window.RPi18n) RPi18n.setLang('en', false); }")

    def tearDown(self):
        try:
            self.page.evaluate("closeDeviceDrawer()")
        except Exception:
            pass
        self.assertEqual(_STACK["errors"], [], "the page threw")

    def switch(self, dev_id):
        return self.page.evaluate("async (id) => (await api('GET', `/devices/${id}/exposure-internal`))", dev_id)

    def put(self, dev_id, on):
        return self.page.evaluate("async ([id, on]) => (await api('PUT', `/devices/${id}/exposure-internal`, {internal: on}))",
                                  [dev_id, on])

    def open_exposure(self):
        self.page.evaluate("showPage('exposure')")
        self.page.wait_for_function(
            "() => document.querySelectorAll('#exposure-tbody tr td').length > 6 && !document.querySelector('#exposure-tbody .skeleton')",
            timeout=60000)

    def rows(self):
        """One dict per row of the Exposure table: the host, the scope pill, the note under the host, the buttons."""
        return self.page.evaluate("""() => [...document.querySelectorAll('#exposure-tbody tr')].map(tr => {
            const t = tr.querySelectorAll('td');
            if (t.length < 6) return null;
            return {
              host: (t[0].querySelector('[data-dev-hover]') || {}).textContent || '',
              port: t[1].textContent.trim(),
              pill: (t[4].querySelector('.pill') || {}).textContent || '',
              note: (t[0].querySelector('.hint') || {}).textContent || '',
              noteCode: (t[0].querySelector('.hint code') || {}).textContent || '',
              buttons: [...t[5].querySelectorAll('button')].map(b => b.textContent.trim()),
            };
        }).filter(Boolean)""")

    def of(self, name):
        return [r for r in self.rows() if r["host"] == name]

    def confirm(self):
        self.page.wait_for_selector("#ui-prompt-modal:not(.d-none) #ui-prompt-confirm, #ui-prompt-modal.open #ui-prompt-confirm",
                                    timeout=15000)
        self.page.click("#ui-prompt-confirm")

    def toast(self):
        self.page.wait_for_selector(".toast", timeout=20000)
        return self.page.evaluate("() => [...document.querySelectorAll('.toast')].map(t => t.textContent.trim()).join(' | ')")


class TestTheExposurePage(_Page):

    def test_a_socket_on_a_host_that_holds_reads_assumed_internal_and_not_world(self):
        self.open_exposure()
        mine = self.of(HOLDS_NAME)
        self.assertGreaterEqual(len(mine), 2)
        assumed = [r for r in mine if r["pill"] == "assumed internal"]
        self.assertGreaterEqual(len(assumed), 2, mine)
        self.assertEqual([r for r in mine if r["pill"] == "world"], [])
        self.assertEqual([r["note"] for r in mine], [""] * len(mine), "nothing to explain on a host that holds")

    def test_a_host_whose_mark_does_not_hold_says_why_once_and_stays_world(self):
        self.open_exposure()
        mine = self.of(BLOCKED_NAME)
        self.assertGreaterEqual(len([r for r in mine if r["pill"] == "world"]), 2, mine)
        noted = [r for r in mine if r["note"]]
        self.assertEqual(len(noted), 1, "the reason is printed on the first row of the host and only there")
        self.assertIn("Marked internal, but it has a public address:", noted[0]["note"])
        self.assertEqual(noted[0]["noteCode"], "203.0.113.40")

    def test_the_button_beside_a_host_follows_the_mark(self):
        self.open_exposure()
        for r in self.of(HOLDS_NAME):
            if r["pill"] == "assumed internal":
                self.assertIn("Not internal", r["buttons"])
                self.assertNotIn("Treat as internal", r["buttons"])
        for r in self.of(BLOCKED_NAME):
            if r["pill"] == "world":
                self.assertIn("Not internal", r["buttons"])
        world = [r for r in self.of(PLAIN_NAME) if r["pill"] == "world"]
        self.assertTrue(world, "the nginx host has a world socket in the demo")
        for r in world:
            self.assertIn("Treat as internal", r["buttons"])

    def test_the_summary_counts_what_is_assumed(self):
        self.open_exposure()
        text = self.page.inner_text("#exposure-summary")
        self.assertRegex(text, r"assumed internal \d+")

    def test_marking_a_host_and_taking_it_back_through_the_page(self):
        self.assertFalse(self.switch(PLAIN)["internal"])
        try:
            self.open_exposure()
            self.page.eval_on_selector_all(
                "#exposure-tbody tr",
                """(trs, name) => { for (const tr of trs) { const b = tr.querySelector('button[data-action="setHostInternal"][data-arg3="1"]');
                    const h = tr.querySelector('[data-dev-hover]'); if (b && h && h.textContent === name) { b.click(); return true; } } return false; }""",
                PLAIN_NAME)
            self.confirm()
            said = self.toast()
            self.assertIn("Marked internal. It does not hold yet", said, "this demo host reports no addresses")
            self.page.wait_for_function(
                "(n) => [...document.querySelectorAll('#exposure-tbody .hint')].some(h => h.textContent.includes('its agent does not report its addresses'))",
                arg=PLAIN_NAME, timeout=20000)
            self.assertTrue(self.switch(PLAIN)["internal"])
            self.assertEqual(self.switch(PLAIN)["blocked"], "no_address_data")
            self.assertTrue([r for r in self.of(PLAIN_NAME) if r["pill"] == "world"], "and its sockets are still world")
            self.page.evaluate("() => document.querySelectorAll('.toast').forEach(t => t.remove())")
            self.page.eval_on_selector_all(
                "#exposure-tbody tr",
                """(trs, name) => { for (const tr of trs) { const b = tr.querySelector('button[data-action="setHostInternal"][data-arg3="0"]');
                    const h = tr.querySelector('[data-dev-hover]'); if (b && h && h.textContent === name) { b.click(); return true; } } return false; }""",
                PLAIN_NAME)
            self.assertIn("No longer treated as internal", self.toast())
            self.page.wait_for_function(
                "() => ![...document.querySelectorAll('#exposure-tbody .hint')].some(h => h.textContent.includes('its agent does not report its addresses'))",
                timeout=20000)
            self.assertFalse(self.switch(PLAIN)["internal"])
        finally:
            self.put(PLAIN, False)

    def test_the_new_words_come_out_in_another_language(self):
        self.open_exposure()
        self.page.evaluate("async () => { await _ensureI18n(); }")
        self.page.wait_for_timeout(800)
        self.page.evaluate("RPi18n.setLang('de', false)")
        self.page.wait_for_function(
            "() => [...document.querySelectorAll('#exposure-tbody .pill')].some(p => p.textContent === 'als intern angenommen')",
            timeout=20000)
        buttons = self.page.evaluate("() => [...document.querySelectorAll('#exposure-tbody button[data-action=\"setHostInternal\"]')].map(b => b.textContent.trim())")
        self.assertTrue(buttons)
        self.assertTrue(set(buttons) <= {"Als intern behandeln", "Nicht intern"}, buttons)
        note = self.page.evaluate("() => [...document.querySelectorAll('#exposure-tbody .hint span')].map(s => s.textContent).join('|')")
        self.assertIn("Als intern markiert, hat aber eine öffentliche Adresse:", note)


class TestTheHostsPortsCard(_Page):

    def ports_card(self, dev_id, name):
        self.page.evaluate("([id, n]) => openDeviceDrawer(id, n, 'audit')", [dev_id, name])
        self.page.wait_for_selector("#audit-body-ports", state="attached", timeout=30000)
        self.page.evaluate("() => _loadAuditSection('ports')")
        self.page.wait_for_function(
            "() => { const b = document.getElementById('audit-body-ports'); return b && b.querySelector('table.ports-table'); }",
            timeout=30000)
        return self.page.evaluate("""() => {
            const b = document.getElementById('audit-body-ports');
            const line = b.querySelector('.hint-mb');
            return {
              line: line ? line.textContent.replace(/\\s+/g, ' ').trim() : '',
              button: line && line.querySelector('button') ? line.querySelector('button').textContent.trim() : '',
              pills: [...b.querySelectorAll('tbody .pill')].map(p => p.textContent),
            };
        }""")

    def test_a_host_that_holds_says_so_and_labels_its_sockets(self):
        card = self.ports_card(HOLDS, HOLDS_NAME)
        self.assertIn("This host is treated as internal", card["line"])
        self.assertEqual(card["button"], "Not internal")
        self.assertIn("assumed internal", card["pills"])
        self.assertNotIn("world", card["pills"])

    def test_a_host_whose_mark_does_not_hold_says_why(self):
        card = self.ports_card(BLOCKED, BLOCKED_NAME)
        self.assertIn("Marked internal, but it has a public address: 203.0.113.40", card["line"])
        self.assertEqual(card["button"], "Not internal")
        self.assertIn("world", card["pills"])

    def test_a_host_that_is_not_marked_offers_the_switch_when_it_has_a_world_socket(self):
        card = self.ports_card(PLAIN, PLAIN_NAME)
        self.assertIn("Services that listen on every address are graded world-reachable.", card["line"])
        self.assertEqual(card["button"], "Treat as internal")


if __name__ == "__main__":
    unittest.main()
