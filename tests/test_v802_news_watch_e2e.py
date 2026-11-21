#!/usr/bin/env python3
"""8.0.2: the security news watch in a browser on the demo seed: the Security news tab of the CVE page, its items, its form and the alert event behind it.

tests/test_v802_news_watch_rules.py holds the rules, tests/test_v802_news_watch_sweep.py the sweep, the routes and the fetch and tests/test_v802_news_watch_wiring.py the registries.
This file holds what a person sees and presses: the tab lists the critical items the demo's watch found, each with why it counts and what the watch did about it; the form shows what
is saved, saves what is typed and says why a value is refused; the viewer is told who manages it; text that came from a feed is text and never markup; one long page draws the card
without a click; every word has a translation; a headline in the activity feed lands on the tab; and nothing in the page broke.

The demo seed holds the data (packaging/seed-demo-data.py builds news_watch.json and a setting that is off, with a feed at example.net, so the demo never reads a real feed). Self-skips
without playwright / Chromium / gunicorn, and runs under the default storage backend only.
"""
import json
import os
import re
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
TAB = '.pg-tabs[data-pg="cve"] [data-pg-tab-btn="news"]'
INIT = "try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); %s } catch (e) {}"
FEED = "https://news.example.net/security.xml"
LOCAL_A, LOCAL_B = "http://127.0.0.1:9/a.xml", "http://127.0.0.1:9/b.xml"      # refused before any connection, so the test needs no network


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("the view is backend-agnostic: measured once, under the default backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-newswatch-e2e-")
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
        d = _STATE.get("data_dir")
        if d:
            import shutil
            shutil.rmtree(d, ignore_errors=True)                  # the seeded instance is tmpfs


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


def _login(page, user="alice", password="demo"):
    page.goto(_STATE["base"] + "/index.html")
    page.fill("#login-user", user)                        # the seeder builds its own accounts: there is no 'admin'
    page.fill("#login-pass", password)
    page.click('#login-form button[type="submit"]')
    page.wait_for_selector("#app", state="visible", timeout=90000)
    page.wait_for_timeout(3500)


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestSecurityNewsInTheBrowser(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        ctx = _STATE["browser"].new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
        ctx.add_init_script(INIT % "")
        cls.ctx, cls.page, cls.errors, cls.requests = ctx, ctx.new_page(), [], []
        cls.page.on("pageerror", lambda e: cls.errors.append(str(e)))
        cls.page.on("request", lambda r: cls.requests.append((r.method, r.url.split("/api", 1)[-1], r.post_data)))
        _login(cls.page)
        cls.config0, cls.store0, cls.devices0 = read("config.json"), read("news_watch.json"), read("devices.json")
        cls.containers0 = read("containers.json") if _path("containers.json").exists() else {}

    @classmethod
    def tearDownClass(cls):
        try:
            write("config.json", cls.config0)
            write("news_watch.json", cls.store0)
            write("devices.json", cls.devices0)
            write("containers.json", cls.containers0)
        finally:
            cls.ctx.close()

    def setUp(self):
        write("config.json", self.config0)
        write("news_watch.json", self.store0)
        write("devices.json", self.devices0)
        write("containers.json", self.containers0)
        del self.requests[:]

    def tearDown(self):
        self.page.evaluate("""() => {
          document.querySelectorAll('.modal-overlay.active').forEach(m => closeModal(m.id));
          document.querySelectorAll('.toast').forEach(t => t.remove());          // a refusal's toast of one test is not the answer the next one waits for
          if (window.__realApi) { window.api = window.__realApi; window.__realApi = null; }
          try { localStorage.removeItem('pgtab.cve'); localStorage.removeItem('rp_news_seen'); } catch (e) {}
          if (typeof _nwAt !== 'undefined') _nwAt = 0;      // the tab draws at most every few seconds: the next test is a new visit
        }""")

    # ── helpers ──────────────────────────────────────────────────────────────

    def open_tab(self, page=None, wait_items=True):
        page = page or self.page
        page.evaluate("() => showPage('cve')")
        page.wait_for_selector(TAB, state="visible", timeout=30000)
        page.click(TAB)
        page.wait_for_function("() => typeof newsWatchLoad === 'function'", timeout=30000)
        page.evaluate("async () => { await newsWatchLoad(); }")                       # drawn afresh, form included: the form is only filled from the server when it is asked to
        if wait_items:
            page.wait_for_function("() => document.querySelectorAll('#news-watch-items > div').length > 0", timeout=30000)

    def hosts_running(self, program):
        """How many demo hosts (with an agent, not decommissioned, heard from in the last week) run `program`, as a process, a program that listens or a container that is up.
        Counted here from the stored hosts and containers, with a rule of its own: the first word of the name, without its digits."""
        def word(name):
            return re.split(r"[-.+:~ /]", str(name).lower(), 1)[0].rstrip("0123456789")
        containers = read("containers.json") if _path("containers.json").exists() else {}
        n = 0
        for dev_id, dev in read("devices.json").items():
            if dev.get("agentless") or dev.get("decommissioned") or time.time() - (dev.get("last_seen") or 0) > 7 * 86400:
                continue
            si = dev.get("sysinfo") or {}
            names = {word(p) for p in si.get("proc_names") or []} | {word(p.get("process")) for p in si.get("listening_ports") or []}
            for c in (containers.get(dev_id) or {}).get("items") or []:
                if not str(c.get("status") or "").lower().startswith(("exited", "dead", "created", "removing", "paused")):
                    names.add(word(str(c.get("image") or "").split("@")[0].split(":")[0].rsplit("/", 1)[-1]))
            n += program in names
        return n

    def items(self, page=None):
        """Each item as text: the headline, the chips, then the line under them."""
        return (page or self.page).eval_on_selector_all("#news-watch-items > div", "els => els.map(e => e.innerText.replace(/\\s+/g, ' ').trim())")

    # ── the tab ──────────────────────────────────────────────────────────────

    def test_the_tab_lists_what_the_watch_found_with_why_it_counts_and_what_was_done(self):
        self.open_tab()
        rows = self.items()
        self.assertEqual(len(rows), 6, rows)
        self.assertTrue(rows[0].startswith("! nginx patches an HTTP/2 flaw that attackers already use"), rows[0])
        self.assertIn("Called critical", rows[0])
        self.assertIn("Exploited in attacks", rows[0])
        self.assertIn("Alert raised, no scan: one was started less than six hours ago", rows[0])
        self.assertIn("Running on your hosts: nginx Hosts %d" % self.hosts_running("nginx"), rows[0])
        self.assertIn("reachable from the Internet", rows[0], "a demo host listens to the Internet with nginx")
        self.assertNotIn("Names software on your hosts: nginx", rows[0], "what runs is not also listed as installed")
        self.assertIn("Alert raised and a scan of all hosts started", rows[1])
        self.assertTrue(rows[1].startswith("! PHP fixes critical flaws"), rows[1])
        self.assertIn("Running on your hosts: php Hosts %d" % self.hosts_running("php"), rows[1])
        self.assertIn("Code execution without signing in", rows[1])
        self.assertIn("Zero-day", rows[2])
        self.assertIn("Listed only", rows[2])
        self.assertNotIn("Names software on your hosts", rows[2], "it names nothing a host has")
        self.assertIn("CVSS score of 9 or more", rows[3])
        self.assertIn("CVE that CISA lists as exploited", rows[4])
        self.assertIn("Names software on your hosts: openssl", rows[4], "installed and not running: named under the headline")
        self.assertFalse(rows[4].startswith("!") or "Running on your hosts" in rows[4], "and no mark")
        self.assertIn("Seen when the feed was first read, so no alert", rows[5])
        self.assertIn("Example Security News", rows[0], "the feed an item came from")

    def test_a_red_mark_and_a_line_count_the_items_about_software_that_runs(self):
        self.open_tab()
        self.assertGreaterEqual(self.hosts_running("nginx"), 2, "control: the demo runs nginx on several hosts")
        marks = self.page.eval_on_selector_all("#news-watch-items > div", "els => els.map(e => !!e.querySelector(':scope > div:first-child > .c-red'))")
        self.assertEqual(marks, [True, True, False, False, False, False], "the nginx and the PHP item name software that runs on demo hosts")
        line = " ".join(self.page.inner_text("#news-watch-running").split())
        self.assertEqual(line, "! Items about software running on your hosts: 2 Clear all !", "the line counts them, and offers to clear them")
        self.assertFalse(self.page.eval_on_selector("#news-watch-running", "e => e.hidden"))
        self.assertIn("A red ! marks an item that names software running on one of your hosts.", self.page.inner_text("#news-watch-wrap"))

    def marks(self, selector=".news-mark", page=None):
        """For each element that carries the mark: whether it shows."""
        return (page or self.page).evaluate("(s) => [...document.querySelectorAll(s)].map(e => !e.classList.contains('d-none'))", selector)

    def poll_the_sidebar(self, page=None):
        (page or self.page).evaluate("async () => { await refreshNavCounts(); }")

    def enable_the_watch(self):
        """The demo's watch is off, and a watch that is off has no mark. The feed is one that is refused before any connection is made, and the sweep is made not due, so
        nothing is read: what the tab and the sidebar show is what the seed holds."""
        cfg = json.loads(json.dumps(self.config0))
        cfg["news_watch"] = {"enabled": True, "feeds": [LOCAL_A], "scope": "relevant", "action": "scan", "words": []}
        cfg["last_news_watch_run"] = int(time.time())
        write("config.json", cfg)

    def test_a_watch_that_is_off_has_no_mark(self):
        self.poll_the_sidebar()
        self.assertEqual(self.marks(), [False, False], "the demo's watch is off: the items about software that runs are there, and the mark is not")
        self.assertIsNone(self.page.evaluate("() => window._newsRunningAt"))

    def test_a_mark_on_the_sidebar_and_on_the_tab_shows_until_the_tab_has_shown_the_item(self):
        self.enable_the_watch()
        self.poll_the_sidebar()
        self.assertEqual(self.marks('.nav-btn[data-page="cve"] .news-mark'), [True], "this browser has shown nothing yet: the CVEs entry carries the mark")
        self.page.evaluate("() => showPage('cve')")
        self.page.wait_for_selector(TAB, state="visible", timeout=30000)
        self.assertEqual(self.marks('.pg-tabs[data-pg="cve"] .news-mark'), [True], "and so does the tab, before it is opened")
        self.page.click(TAB)
        # the rows of an earlier visit may still be in the card, so what shows that this visit has drawn is the value the tab stores when it has shown the items
        self.page.wait_for_function("() => !!localStorage.getItem('rp_news_seen')", timeout=30000)
        self.assertEqual(self.marks(), [False, False], "the tab has shown what the mark counts: both go")
        at = self.page.evaluate("async () => (await api('GET', '/news-watch')).attention_at")
        self.assertEqual(self.page.evaluate("() => localStorage.getItem('rp_news_seen')"), str(at), "this browser remembers the newest item it showed")
        self.page.reload()
        self.page.wait_for_selector("#app", state="visible", timeout=90000)
        self.page.wait_for_timeout(2500)
        self.poll_the_sidebar()
        self.assertEqual(self.marks(), [False, False], "and after a reload")
        doc = json.loads(json.dumps(self.store0))
        newest = dict(doc["items"][0], id="demonewnewest", title="nginx patches a second HTTP/2 flaw", seen_at=int(time.time()), published=int(time.time()))
        doc["items"].insert(0, newest)
        write("news_watch.json", doc)
        self.poll_the_sidebar()
        self.assertEqual(self.marks('.nav-btn[data-page="cve"] .news-mark'), [True], "a newer item that names software that runs brings the mark back")

    def test_what_is_only_installed_and_what_is_not_new_are_no_mark(self):
        self.enable_the_watch()
        self.poll_the_sidebar()
        self.assertEqual(self.marks('.nav-btn[data-page="cve"] .news-mark'), [True], "control: with the watch on, the demo's items set the mark")
        doc = json.loads(json.dumps(self.store0))
        for i in doc["items"]:
            if i["software"] == ["nginx"] or i["software"] == ["php"]:
                i["outcome"] = "baseline"                       # recorded when the feed was first read: nothing to look at
        write("news_watch.json", doc)
        self.poll_the_sidebar()
        self.assertEqual(self.marks('.nav-btn[data-page="cve"] .news-mark'), [False], "the items about software that runs are baseline records")
        doc = json.loads(json.dumps(self.store0))
        for i in doc["items"]:
            i["seen_at"] = int(time.time()) - 5 * 86400         # five days ago
        write("news_watch.json", doc)
        self.poll_the_sidebar()
        self.assertEqual(self.marks('.nav-btn[data-page="cve"] .news-mark'), [False], "older than three days")

    def test_a_viewer_is_never_shown_the_mark(self):
        self.enable_the_watch()
        self.poll_the_sidebar()
        self.assertEqual(self.marks(), [True, True], "control: the operator is shown it")
        ctx = _STATE["browser"].new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
        ctx.add_init_script(INIT % "")
        page = ctx.new_page()
        try:
            _login(page, "demo", "demo")
            self.poll_the_sidebar(page)
            self.assertEqual(self.marks(page=page), [False, False], "the entry and the tab have the mark in their markup, hidden")
            self.assertIsNone(page.evaluate("() => window._newsRunningAt"), "the viewer's poll does not carry it")
        finally:
            ctx.close()

    VISIBLE_BANG = """() => [...document.querySelectorAll('.sidebar *')].filter(el => {
      const own = [...el.childNodes].filter(n => n.nodeType === 3).map(n => n.textContent).join('').trim();
      const r = el.getBoundingClientRect(), cs = getComputedStyle(el);
      return own.includes('!') && r.width > 0 && r.height > 0 && cs.display !== 'none' && cs.visibility !== 'hidden';
    }).map(el => (el.parentElement && el.parentElement.getAttribute('data-page')) || el.className)"""

    def test_a_mark_that_is_off_is_not_drawn_when_the_collapsed_sidebar_opens(self):
        """The rules that open the collapsed sidebar (the pointer on the rail, or an alert pinning it open) draw every span of a nav button again, whatever class it has. A hidden mark that
        still held its "!" was drawn in every browser whatever the server said, and after every item was cleared. The other browser tests keep the sidebar open, which is how it went unseen."""
        self.enable_the_watch()
        ctx = _STATE["browser"].new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
        ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); } catch (e) {}")          # the sidebar as it comes: it collapses
        page = ctx.new_page()

        def on_the_rail():
            page.mouse.move(700, 400)
            page.wait_for_timeout(300)
            page.mouse.move(20, 300)
            page.wait_for_timeout(700)
        try:
            _login(page)
            self.assertIn("sidebar-collapsed", page.evaluate("() => document.body.className"), "control: this browser has the sidebar that collapses")
            self.poll_the_sidebar(page)
            on_the_rail()
            self.assertEqual(page.evaluate(self.VISIBLE_BANG), ["cve"], "control: a mark that is on is drawn when the rail opens, and the scan sees it")
            page.evaluate("() => showPage('cve')")
            page.wait_for_selector(TAB, state="visible", timeout=30000)
            page.click(TAB)
            page.wait_for_function("() => document.querySelectorAll('#news-watch-items > div').length > 0", timeout=30000)
            page.click('#news-watch-running [data-action="newsWatchClear"]')
            page.wait_for_function("() => document.getElementById('news-watch-running').textContent.includes('Bring back all')", timeout=30000)
            self.poll_the_sidebar(page)
            self.assertEqual(self.marks('.nav-btn[data-page="cve"] .news-mark', page), [False])
            on_the_rail()
            self.assertEqual(page.evaluate(self.VISIBLE_BANG), [], "nothing is left to look at, and nothing is drawn with the pointer on the rail")
            page.evaluate("() => document.body.classList.add('sidebar-collapsed', 'sidebar-alert-pinned')")
            self.assertEqual(page.evaluate(self.VISIBLE_BANG), [], "nor with an alert pinning the rail open")
            self.assertEqual(page.eval_on_selector('.nav-btn[data-page="cve"] .news-mark', "e => [e.textContent, e.getAttribute('aria-hidden')]"), ["", "true"],
                             "the mark holds no text and is not announced while it is off")
        finally:
            ctx.close()

    def test_when_no_host_runs_it_any_more_the_marks_go_and_the_words_stay(self):
        self.enable_the_watch()
        self.poll_the_sidebar()
        self.assertEqual(self.marks(), [True, True], "control: nginx and php run on the demo hosts, and the watch is on")
        devs = json.loads(json.dumps(self.devices0))
        for dev in devs.values():
            si = dev.get("sysinfo") or {}
            si["proc_names"], si["listening_ports"] = [], []
        write("devices.json", devs)
        write("containers.json", {})
        write("news_watch.json", self.store0)        # the sidebar's answer is kept for 15 seconds, and a change of the hosts does not end that; a change of the store does
        self.open_tab()
        rows = self.items()
        self.assertTrue(rows[0].startswith("nginx patches"), "the mark is gone: " + rows[0])
        self.assertIn("Names software on your hosts: nginx", rows[0], "the word stays, as installed software")
        self.assertIn("Names software on your hosts: php", rows[1])
        self.assertNotIn("Running on your hosts", " ".join(rows))
        self.assertTrue(self.page.eval_on_selector("#news-watch-running", "e => e.hidden"), "nothing to count")
        self.page.evaluate("() => { localStorage.removeItem('rp_news_seen'); }")
        self.poll_the_sidebar()
        self.assertEqual(self.marks(), [False, False], "and nothing for the sidebar to mark")

    # ── clearing the ! ───────────────────────────────────────────────────────

    def clear_buttons(self, page=None):
        return (page or self.page).eval_on_selector_all('#news-watch-items [data-action="newsWatchClear"]', "els => els.length")

    def summary(self):
        return " ".join(self.page.inner_text("#news-watch-running").split())

    def clear_posts(self):
        return [r for r in self.requests if r[0] == "POST" and r[1] == "/news-watch/clear"]

    def test_an_item_with_a_bang_has_a_button_and_clearing_it_keeps_the_item_and_loses_the_bang(self):
        self.open_tab()
        self.assertEqual(self.clear_buttons(), 2, "a button on each of the two items that show a !, and none on the others")
        self.assertEqual(self.summary(), "! Items about software running on your hosts: 2 Clear all !")
        self.page.locator("#news-watch-items > div").nth(1).locator('[data-action="newsWatchClear"]').click()
        self.page.wait_for_function("() => document.querySelectorAll('#news-watch-items [data-action=\"newsWatchClear\"]').length === 1", timeout=30000)
        rows = self.items()
        self.assertEqual(len(rows), 6, "the item is still listed")
        self.assertTrue(rows[0].startswith("! nginx patches"), "the other item keeps its !")
        self.assertFalse(rows[1].startswith("!"), rows[1])
        self.assertRegex(rows[1], r"! cleared \S+", "it says it was cleared, and when")
        self.assertIn("Running on your hosts: php Hosts %d" % self.hosts_running("php"), rows[1], "what runs is still shown")
        self.assertEqual(self.summary(), "! Items about software running on your hosts: 1 Clear all ! · ! cleared 1 Bring back all !", "the line counts what is left to clear and what can be brought back")
        (post,) = self.clear_posts()
        body = json.loads(post[2])
        self.assertEqual(list(body), ["ids"])
        self.assertEqual(body["ids"], [self.store0["items"][1]["id"]], "the id went through the prefix and came out as it was: the PHP item's own")
        cleared = [i["title"] for i in read("news_watch.json")["items"] if i.get("cleared_at")]
        self.assertEqual(len(cleared), 1)
        self.assertTrue(cleared[0].startswith("PHP fixes critical flaws"), cleared)

    def test_clear_all_takes_every_bang_away_and_it_holds_in_another_browser_and_after_a_reload(self):
        self.enable_the_watch()
        ctx = _STATE["browser"].new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
        ctx.add_init_script(INIT % "")
        other = ctx.new_page()
        try:
            _login(other)
            self.poll_the_sidebar(other)
            self.assertEqual(self.marks('.nav-btn[data-page="cve"] .news-mark', other), [True], "control: a browser that has shown nothing has the mark")
            self.open_tab()
            self.page.click('#news-watch-running [data-action="newsWatchClear"]')
            self.page.wait_for_function("() => document.getElementById('news-watch-running').textContent.includes('Bring back all')", timeout=30000)
            self.assertEqual(self.clear_buttons(), 0)
            self.assertEqual(self.summary(), "! cleared 2 Bring back all !", "no ! is left to clear: the line is the way back")
            rows = self.items()
            self.assertEqual([r.startswith("!") for r in rows], [False] * 6, "no row shows a !")
            self.assertEqual(sum("! cleared" in r for r in rows), 2, "the two items that showed a ! say they were cleared")
            self.assertEqual(json.loads(self.clear_posts()[0][2]), {"all": True})
            self.poll_the_sidebar(other)
            self.assertEqual(self.marks('.nav-btn[data-page="cve"] .news-mark', other), [False], "the other browser's mark goes at its next poll: the clear is the server's")
            self.assertIsNone(other.evaluate("() => window._newsRunningAt"))
        finally:
            ctx.close()
        self.page.reload()
        self.page.wait_for_selector("#app", state="visible", timeout=90000)
        self.page.wait_for_timeout(2500)
        self.open_tab()
        self.assertEqual(self.clear_buttons(), 0, "after a reload")
        self.assertEqual(sum("! cleared" in r for r in self.items()), 2)

    def test_a_new_item_shows_its_own_bang_after_the_others_were_cleared(self):
        self.open_tab()
        self.page.click('#news-watch-running [data-action="newsWatchClear"]')
        self.page.wait_for_function("() => document.getElementById('news-watch-running').textContent.includes('Bring back all')", timeout=30000)
        doc = read("news_watch.json")
        fresh = dict(doc["items"][0], id="feedfeedfeedfeed", title="nginx fixes a third flaw", seen_at=int(time.time()))
        fresh.pop("cleared_at", None)
        doc["items"].insert(0, fresh)
        write("news_watch.json", doc)
        self.page.evaluate("async () => { await newsWatchLoad(); }")
        rows = self.items()
        self.assertTrue(rows[0].startswith("! nginx fixes a third flaw"), rows[0])
        self.assertEqual(self.clear_buttons(), 1)
        self.assertIn("! cleared", rows[1])
        self.assertEqual(self.summary(), "! Items about software running on your hosts: 1 Clear all ! · ! cleared 2 Bring back all !")

    def test_a_cleared_item_has_a_button_that_brings_its_bang_back(self):
        self.open_tab()
        self.page.locator("#news-watch-items > div").nth(1).locator('[data-action="newsWatchClear"]').click()
        self.page.wait_for_function("() => document.querySelectorAll('#news-watch-items [data-action=\"newsWatchRestore\"]').length === 1", timeout=30000)
        rows = self.items()
        self.assertFalse(rows[1].startswith("!"), rows[1])
        self.assertRegex(rows[1], r"! cleared \S+")
        self.assertEqual(self.page.eval_on_selector_all('#news-watch-items [data-action="newsWatchRestore"]', "els => els.map(e => e.textContent.trim())"), ["Bring back !"],
                         "one button, on the cleared item and on no other")
        self.page.locator("#news-watch-items > div").nth(1).locator('[data-action="newsWatchRestore"]').click()
        self.page.wait_for_function("() => document.querySelectorAll('#news-watch-items [data-action=\"newsWatchClear\"]').length === 2", timeout=30000)
        rows = self.items()
        self.assertEqual(len(rows), 6, "the item stayed listed")
        self.assertTrue(rows[1].startswith("! PHP fixes critical flaws"), "the ! is back: " + rows[1])
        self.assertNotIn("! cleared", rows[1])
        self.assertEqual(self.clear_buttons(), 2)
        self.assertEqual(self.page.eval_on_selector_all('#news-watch-items [data-action="newsWatchRestore"]', "els => els.length"), 0, "nothing is cleared, so nothing can be brought back")
        self.assertEqual(self.summary(), "! Items about software running on your hosts: 2 Clear all !", "the line is as it was before the clear")
        posts = self.clear_posts()
        self.assertEqual([json.loads(p[2]) for p in posts], [{"ids": [self.store0["items"][1]["id"]]}, {"ids": [self.store0["items"][1]["id"]], "undo": True}],
                         "the clear, then the undo of the same item: the id went through the prefix and came out as it was")
        self.assertEqual([i for i in read("news_watch.json")["items"] if i.get("cleared_at")], [], "nothing is left cleared in the store")

    def test_bring_back_all_undoes_clear_all_and_the_mark_comes_back_in_a_browser_that_had_not_shown_it(self):
        self.enable_the_watch()
        ctx = _STATE["browser"].new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
        ctx.add_init_script(INIT % "")
        other = ctx.new_page()
        try:
            _login(other)
            self.poll_the_sidebar(other)
            self.assertEqual(self.marks('.nav-btn[data-page="cve"] .news-mark', other), [True], "control: a browser that has shown nothing has the mark")
            self.open_tab()
            self.page.click('#news-watch-running [data-action="newsWatchClear"]')
            self.page.wait_for_function("() => document.getElementById('news-watch-running').textContent.includes('Bring back all')", timeout=30000)
            self.poll_the_sidebar(other)
            self.assertEqual(self.marks('.nav-btn[data-page="cve"] .news-mark', other), [False], "the clear took the mark away in the other browser")
            self.page.click('#news-watch-running [data-action="newsWatchRestore"]')
            self.page.wait_for_function("() => document.querySelectorAll('#news-watch-items [data-action=\"newsWatchClear\"]').length === 2", timeout=30000)
            self.assertEqual(self.summary(), "! Items about software running on your hosts: 2 Clear all !")
            self.assertEqual([json.loads(p[2]) for p in self.clear_posts()], [{"all": True}, {"all": True, "undo": True}])
            self.poll_the_sidebar(other)
            self.assertEqual(self.marks('.nav-btn[data-page="cve"] .news-mark', other), [True], "the mark is back in the browser that had not shown the items: the undo is the server's too")
            self.assertTrue(other.evaluate("() => typeof window._newsRunningAt === 'number'"))
        finally:
            ctx.close()
        self.page.reload()
        self.page.wait_for_selector("#app", state="visible", timeout=90000)
        self.page.wait_for_timeout(2500)
        self.open_tab()
        self.assertEqual(self.clear_buttons(), 2, "after a reload")
        self.assertEqual(sum("! cleared" in r for r in self.items()), 0)

    def test_the_words_of_the_clear_are_translated_in_all_six_languages(self):
        self.open_tab()
        self.page.locator("#news-watch-items > div").nth(1).locator('[data-action="newsWatchClear"]').click()
        self.page.wait_for_function("() => document.querySelectorAll('#news-watch-items [data-action=\"newsWatchClear\"]').length === 1", timeout=30000)
        self.page.evaluate("async () => { await _ensureI18n(); }")
        grab = """() => ({
          button: document.querySelector('#news-watch-items [data-action="newsWatchClear"]').textContent.trim(),
          all: document.querySelector('#news-watch-running [data-action="newsWatchClear"]').textContent.trim(),
          cleared: [...document.querySelectorAll('#news-watch-items .hint > .hint')].map(e => e.textContent.trim()).filter(t => t.includes('!'))[0],
          back: document.querySelector('#news-watch-items [data-action="newsWatchRestore"]').textContent.trim(),
          backall: document.querySelector('#news-watch-running [data-action="newsWatchRestore"]').textContent.trim(),
        })"""
        english = self.page.evaluate(grab)
        self.assertEqual(english, {"button": "Clear !", "all": "Clear all !", "cleared": "! cleared", "back": "Bring back !", "backall": "Bring back all !"})
        bad = []
        try:
            for lang in LANGS:
                self.page.evaluate("(l) => RPi18n.setLang(l, false)", lang)
                self.page.wait_for_timeout(300)
                now = self.page.evaluate(grab)
                bad += [(lang, key, en) for key, en in english.items() if now[key] == en]
        finally:
            self.page.evaluate("() => RPi18n.setLang('en', false)")
        self.assertEqual(bad, [])

    def test_a_headline_is_a_link_that_opens_elsewhere_and_hands_over_nothing(self):
        self.open_tab()
        links = self.page.eval_on_selector_all("#news-watch-items a", "els => els.map(a => [a.getAttribute('href'), a.target, a.rel])")
        self.assertEqual(len(links), 6)
        self.assertEqual(links[0], ["https://news.example.net/2026/11/1.html", "_blank", "noopener noreferrer"])
        self.assertTrue(all(t == "_blank" and "noopener" in r and "noreferrer" in r for _, t, r in links), links)

    def test_the_form_shows_what_is_saved_and_the_note_says_the_watch_is_off(self):
        self.open_tab()
        self.assertEqual(self.page.evaluate("() => document.getElementById('nw-enabled').checked"), False)
        self.assertEqual(self.page.input_value("#nw-feeds"), FEED)
        self.assertEqual((self.page.input_value("#nw-scope"), self.page.input_value("#nw-action")), ("relevant", "scan"))
        self.assertEqual(self.page.input_value("#nw-words"), "")
        self.assertEqual(self.page.eval_on_selector_all("#nw-scope option", "os => os.map(o => o.value)"), ["running", "relevant", "all"], "the three choices, narrowest first")
        self.assertEqual(self.page.eval_on_selector_all("#nw-action option", "os => os.map(o => o.value)"), ["list", "alert", "scan"])
        self.assertEqual(self.page.inner_text("#news-watch-note").strip(), "The watch is off. Switch it on below and save.")
        self.assertTrue(self.page.eval_on_selector("#news-watch-run", "e => e.hidden"), "there is nothing to check now while it is off")
        self.assertFalse(self.page.eval_on_selector("#news-watch-form", "e => e.hidden"))

    def test_each_feed_says_when_it_was_read_and_how_much_it_held(self):
        self.open_tab()
        text = " ".join(self.page.inner_text("#news-watch-feeds").split())
        self.assertIn("Example Security News", text)
        self.assertIn(FEED, text)
        self.assertIn("Last read", text)
        self.assertRegex(text, r"New items 2 .*Critical 1")
        self.assertNotIn("Failed", text)

    # ── saving ───────────────────────────────────────────────────────────────

    def test_saving_sends_what_was_typed_keeps_it_and_shows_the_button_that_reads_now(self):
        self.open_tab()
        self.page.check("#nw-enabled")
        self.page.fill("#nw-feeds", "%s\n%s" % (LOCAL_A, LOCAL_B))
        self.page.select_option("#nw-scope", "all")
        self.page.select_option("#nw-action", "alert")
        del self.requests[:]
        self.page.click('#news-watch-form button[data-action="newsWatchSave"]')
        self.page.wait_for_function("() => !document.getElementById('news-watch-run').hidden", timeout=30000)
        posts = [r for r in self.requests if r[0] == "POST" and r[1] == "/news-watch/config"]
        self.assertEqual(len(posts), 1, self.requests)
        self.assertEqual(json.loads(posts[0][2]), {"enabled": True, "feeds": "%s\n%s" % (LOCAL_A, LOCAL_B), "scope": "all", "action": "alert", "words": "", "critical_words": ""})
        self.assertEqual(read("config.json")["news_watch"], {"enabled": True, "feeds": [LOCAL_A, LOCAL_B], "scope": "all", "action": "alert", "words": [], "critical_words": []})
        self.assertEqual(self.page.input_value("#nw-feeds"), "%s\n%s" % (LOCAL_A, LOCAL_B), "the form shows what the server kept")
        self.assertEqual(self.page.eval_on_selector_all("#news-watch-items > div", "e => e.length"), 6, "saving does not lose what the watch found")
        self.assertEqual(self.page.inner_text("#news-watch-note").strip(), "", "last read a few minutes ago: nothing to say")

    def test_the_third_choice_and_a_name_that_is_not_on_the_list_are_saved_and_shown_again(self):
        self.open_tab()
        self.page.check("#nw-enabled")
        self.page.select_option("#nw-scope", "running")
        self.page.fill("#nw-words", "UnrealIRCd6\nsquidguard")
        self.page.fill("#nw-feeds", LOCAL_A)
        self.page.click('#news-watch-form button[data-action="newsWatchSave"]')
        self.page.wait_for_function("() => !document.getElementById('news-watch-run').hidden", timeout=30000)
        self.assertEqual(read("config.json")["news_watch"], {"enabled": True, "feeds": [LOCAL_A], "scope": "running", "action": "scan", "words": ["unrealircd", "squidguard"], "critical_words": []})
        self.assertEqual(self.page.input_value("#nw-words"), "unrealircd\nsquidguard", "the form shows the names as the server kept them")
        self.assertEqual(self.page.input_value("#nw-scope"), "running")
        self.page.evaluate("async () => { await newsWatchLoad(); }")
        self.assertEqual((self.page.input_value("#nw-scope"), self.page.input_value("#nw-words")), ("running", "unrealircd\nsquidguard"), "and again after a reload from the server")

    def test_the_words_that_make_an_item_critical_are_saved_cleaned_and_shown_again(self):
        self.open_tab()
        self.page.check("#nw-enabled")
        self.page.fill("#nw-feeds", LOCAL_A)
        self.assertEqual(self.page.input_value("#nw-critical-words"), "", "none yet")
        self.page.fill("#nw-critical-words", "WP2Shell\nremote  code execution, wp2shell")
        del self.requests[:]
        self.page.click('#news-watch-form button[data-action="newsWatchSave"]')
        self.page.wait_for_function("() => !document.getElementById('news-watch-run').hidden", timeout=30000)
        (post,) = [r for r in self.requests if r[0] == "POST" and r[1] == "/news-watch/config"]
        self.assertEqual(json.loads(post[2])["critical_words"], "WP2Shell\nremote  code execution, wp2shell", "what was typed is what is sent")
        self.assertEqual(read("config.json")["news_watch"]["critical_words"], ["wp2shell", "remote code execution"])
        self.assertEqual(self.page.input_value("#nw-critical-words"), "wp2shell\nremote code execution", "the form shows the words as the server kept them")
        self.page.evaluate("async () => { await newsWatchLoad(); }")
        self.assertEqual(self.page.input_value("#nw-critical-words"), "wp2shell\nremote code execution", "and again after a reload from the server")

    def test_an_everyday_critical_word_is_refused_with_the_reason_and_nothing_is_saved(self):
        self.open_tab()
        self.page.check("#nw-enabled")
        self.page.fill("#nw-critical-words", "wp2shell\npatch")
        self.page.click('#news-watch-form button[data-action="newsWatchSave"]')
        self.page.wait_for_selector(".toast.error", timeout=30000)
        self.assertIn("patch is an everyday word", self.page.inner_text(".toast.error"))
        self.assertEqual(read("config.json")["news_watch"], self.config0["news_watch"])

    def test_an_item_that_matched_a_word_says_so_in_all_six_languages(self):
        doc = read("news_watch.json")
        doc["items"][0]["reasons"] = ["word"]
        write("news_watch.json", doc)
        self.open_tab()
        grab = """() => ({
          chip: document.querySelector('#news-watch-items > div:first-child .status-pill.warn').textContent.trim(),
          label: document.querySelector('label[for="nw-critical-words"]').textContent.trim(),
          hint: document.querySelector('#nw-critical-words ~ .hint').textContent.trim(),
        })"""
        self.page.evaluate("async () => { await _ensureI18n(); }")
        english = self.page.evaluate(grab)
        self.assertEqual(english["chip"], "Matches a word you added")
        self.assertEqual(english["label"], "Words that make an item critical, one on each line")
        self.assertTrue(english["hint"].startswith("A headline or summary that holds one of them"))
        bad = []
        try:
            for lang in LANGS:
                self.page.evaluate("(l) => RPi18n.setLang(l, false)", lang)
                self.page.wait_for_timeout(300)
                now = self.page.evaluate(grab)
                bad += [(lang, k) for k, en in english.items() if now[k] == en]
        finally:
            self.page.evaluate("() => RPi18n.setLang('en', false)")
        self.assertEqual(bad, [])

    def test_an_everyday_word_is_refused_with_the_reason_and_nothing_is_saved(self):
        self.open_tab()
        self.page.check("#nw-enabled")
        self.page.fill("#nw-words", "squidguard\nconsole")
        self.page.click('#news-watch-form button[data-action="newsWatchSave"]')
        self.page.wait_for_selector(".toast.error", timeout=30000)
        self.assertIn("console is an everyday word", self.page.inner_text(".toast.error"))
        self.assertEqual(read("config.json")["news_watch"], self.config0["news_watch"])

    def test_a_refused_value_is_said_and_nothing_is_saved(self):
        self.open_tab()
        self.page.check("#nw-enabled")
        self.page.fill("#nw-feeds", "https://user:secret@news.example.net/feed.xml")
        self.page.click('#news-watch-form button[data-action="newsWatchSave"]')
        self.page.wait_for_selector(".toast.error", timeout=30000)
        self.assertIn("user name or password", self.page.inner_text(".toast.error"))
        self.assertEqual(read("config.json")["news_watch"], self.config0["news_watch"])
        self.assertTrue(self.page.eval_on_selector("#news-watch-run", "e => e.hidden"))

    def test_a_refresh_after_a_visit_does_not_write_over_what_is_being_typed(self):
        self.open_tab()
        self.page.fill("#nw-feeds", "http://127.0.0.1:9/typed.xml")
        self.page.evaluate("() => { newsWatchEnter(); }")                              # what showing the tab again does
        self.page.evaluate("async () => { _nwAt = 0; await _nwLoad(false); }")
        self.assertEqual(self.page.input_value("#nw-feeds"), "http://127.0.0.1:9/typed.xml")
        self.page.evaluate("async () => { await newsWatchLoad(); }")                   # the Refresh button is asked for, so the form follows the server
        self.assertEqual(self.page.input_value("#nw-feeds"), FEED)

    def test_check_now_asks_the_server_and_says_what_it_found(self):
        self.open_tab()
        self.page.evaluate("""() => {
          window.__realApi = window.api;
          window.api = async function (m, p, b, x) {
            if (p === '/news-watch/run') {
              const view = await window.__realApi.call(this, 'GET', '/news-watch');
              return Object.assign({}, view, {ok: true, result: {feeds: 1, failed: 0, new_critical: 2, alerts: 1, scan: 'started'}});
            }
            return window.__realApi.call(this, m, p, b, x);
          };
          document.getElementById('news-watch-run').hidden = false;
        }""")
        self.page.click("#news-watch-run")
        self.page.wait_for_selector(".toast.success", timeout=30000)
        self.assertIn("Read 1 feed: 2 new critical items, 1 alert raised", self.page.inner_text(".toast.success"))
        self.assertFalse(self.page.eval_on_selector("#news-watch-run", "e => e.disabled"), "the button is given back")

    # ── who sees it ──────────────────────────────────────────────────────────

    def test_a_viewer_is_told_who_manages_it_and_is_shown_nothing_else(self):
        ctx = _STATE["browser"].new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
        ctx.add_init_script(INIT % "")
        page = ctx.new_page()
        try:
            _login(page, "demo", "demo")
            self.open_tab(page, wait_items=False)
            page.wait_for_function("() => document.getElementById('news-watch-note').textContent.length > 0", timeout=30000)
            self.assertEqual(page.inner_text("#news-watch-note").strip(), "The platform operator manages the security news watch.")
            self.assertTrue(page.eval_on_selector("#news-watch-form", "e => e.hidden"))
            self.assertTrue(page.eval_on_selector("#news-watch-run", "e => e.hidden"))
            self.assertEqual(page.inner_text("#news-watch-items").strip(), "")
            self.assertEqual(page.inner_text("#news-watch-feeds").strip(), "")
            got = page.evaluate("async () => (await api('GET', '/news-watch'))")
            self.assertEqual(got, {"editable": False}, "the server sent a viewer nothing that the page left out")
        finally:
            ctx.close()

    # ── one long page ────────────────────────────────────────────────────────

    def test_one_long_page_shows_the_card_with_the_others_and_draws_it(self):
        ctx = _STATE["browser"].new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
        ctx.add_init_script(INIT % "localStorage.setItem('rp_pagetabs', 'stacked');")
        page = ctx.new_page()
        try:
            _login(page)
            page.evaluate("() => showPage('cve')")
            page.wait_for_function("() => document.querySelectorAll('#news-watch-items > div').length > 1", timeout=30000)
            self.assertTrue(page.is_visible("#news-watch-wrap"))
            self.assertTrue(page.is_visible("#cve-tbody"), "the other cards show too")
        finally:
            ctx.close()

    # ── text that came from a feed ───────────────────────────────────────────

    def test_text_that_came_from_a_feed_is_text_and_never_markup(self):
        bad = '<img src=x onerror="window.__owned=1">'
        doc = json.loads(json.dumps(self.store0))
        doc["items"][0].update(title="took %s" % bad, feed=bad, software=[bad], cves=[bad], link="javascript:window.__owned=1")
        doc["feeds"][FEED].update(title=bad, last_error=bad)
        write("news_watch.json", doc)
        self.page.evaluate("() => { window.__owned = 0; }")
        self.open_tab()
        self.assertEqual(self.page.evaluate("() => [window.__owned, document.querySelectorAll('#news-watch-wrap img').length]"), [0, 0])
        self.assertTrue(any("<img" in t for t in self.items()), "it is shown as the text it is")
        self.assertEqual(self.page.eval_on_selector_all("#news-watch-items a", "els => els.length"), 5, "the headline whose link is not http or https is no link")
        self.assertTrue(self.page.evaluate("() => !document.querySelector('#news-watch-items a[href^=\"javascript\"]')"))

    # ── words ────────────────────────────────────────────────────────────────

    def test_the_words_are_translated_in_all_six_languages(self):
        self.open_tab()
        self.page.evaluate("async () => { await _ensureI18n(); }")
        grab = """() => ({
          tab: [document.querySelector('.pg-tabs[data-pg="cve"] [data-pg-tab-btn="news"]').textContent.trim()],
          titles: [...document.querySelectorAll('#news-watch-wrap .section-title')].map(e => e.textContent.trim()),
          labels: [...document.querySelectorAll('#news-watch-wrap label')].map(e => e.textContent.trim()),
          options: [...document.querySelectorAll('#news-watch-wrap option')].map(e => e.textContent.trim()),
          buttons: [...document.querySelectorAll('#news-watch-wrap button')].map(e => e.textContent.trim()),
          hints: [...document.querySelectorAll('#news-watch-wrap p.hint, #news-watch-wrap #news-watch-form > .hint, #news-watch-form .form-group > .hint, #news-watch-wrap > .form-label')].map(e => e.textContent.trim()),
          chips: [...document.querySelectorAll('#news-watch-items .status-pill')].map(e => e.textContent.trim()),
          words: [...document.querySelectorAll('#news-watch-feeds .hint:not([data-no-i18n]), #news-watch-items .hint > .hint:not([data-no-i18n]), #news-watch-running .hint')].map(e => e.textContent.trim()),
        })"""
        english = self.page.evaluate(grab)
        for key in ("tab", "titles", "labels", "options", "buttons", "hints", "chips", "words"):
            self.assertTrue(english[key], key)
        bad = []
        try:
            for lang in LANGS:
                self.page.evaluate("(l) => RPi18n.setLang(l, false)", lang)
                self.page.wait_for_timeout(300)
                now = self.page.evaluate(grab)
                for key in english:
                    for en, got in zip(english[key], now[key]):
                        if en and en == got and (lang, en) not in {("fr", "Zero-day")} and en != "Hosts":     # Spanish and German write Hosts as English does
                            bad.append((lang, key, en))
        finally:
            self.page.evaluate("() => RPi18n.setLang('en', false)")
        self.assertEqual(bad, [])

    # ── the activity feed ────────────────────────────────────────────────────

    def test_a_headline_in_the_activity_feed_lands_on_the_tab(self):
        self.page.evaluate("() => showPage('home')")
        self.page.wait_for_function("() => typeof _homeNavAction === 'function' && typeof _homeActivityAttrs === 'function'", timeout=30000)
        attrs = self.page.evaluate("() => _homeActivityAttrs('security_news_critical', {title: 'PHP Fixes 7 Critical Flaws'})")
        self.assertIn('data-home-act="cve-news"', attrs)
        self.page.evaluate("() => _homeNavAction({dataset: {homeAct: 'cve-news'}})")
        self.page.wait_for_function("() => document.getElementById('page-cve').classList.contains('active')", timeout=30000)
        self.page.wait_for_selector(TAB + '[aria-current="true"]', timeout=30000)
        self.page.wait_for_function("() => document.querySelectorAll('#news-watch-items > div').length > 0", timeout=30000)

    def test_nothing_in_the_page_broke_on_the_way(self):
        self.open_tab()
        self.page.click("#news-watch-wrap .section-header button[data-action='newsWatchLoad']")
        self.page.wait_for_timeout(500)
        self.assertEqual([e for e in self.errors if "Failed to load resource" not in e], [])


if __name__ == "__main__":
    unittest.main()
