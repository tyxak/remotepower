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


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestContainerAudit(_Page):

    def open_audit(self, floor="medium"):
        self.page.evaluate("() => showPage('containers', document.querySelector('.nav-btn[data-page=containers]'))")
        self.page.wait_for_function("() => typeof loadContainerAudit === 'function'", timeout=60000)
        # start every test from the same state: the floor asked for, no filter, a fresh answer
        self.page.evaluate("async (f) => { document.getElementById('ca-min').value = f; document.getElementById('ca-filter').value = ''; "
                           "_caOpen.clear(); await loadContainerAudit(); }", floor)
        self.page.wait_for_selector("#ca-tbody tr [data-action-btn='_caToggleBtn']", timeout=30000)

    def names(self):
        return self.page.eval_on_selector_all("#ca-tbody tr[data-ca-row] a", "as => as.map(a => a.innerText.trim())")

    def open_row(self, name):
        self.page.click(f"#ca-tbody a[data-action-btn='_caToggleBtn']:text-is('{name}')")
        self.page.wait_for_selector("#ca-tbody .ca-findings", timeout=10000)

    def tearDown(self):
        try:
            self.page.evaluate("() => { _caOpen.clear(); if (typeof closeModal === 'function') closeModal('ui-prompt-modal'); }")
        except Exception:
            pass
        (self.data / "container_audit_accepts.json").write_text("{}")      # whatever a test accepted is gone for the next
        super().tearDown()

    def test_the_audit_lists_what_the_demo_containers_allow_worst_first(self):
        self.open_audit()
        names = self.names()
        self.assertTrue({"gitea", "homeassistant", "node-exporter", "pihole", "gitea-db"} <= set(names), names)
        self.assertNotIn("vaultwarden", names, "a carefully started container has nothing at this level")
        self.assertNotIn("mosquitto", names)
        self.assertIn(names.index("homeassistant"), (0, 1), "the two critical ones lead")
        self.assertIn(names.index("gitea"), (0, 1))
        summary = self.page.inner_text("#ca-summary").lower()
        self.assertIn("critical", summary)
        self.assertIn("not audited", summary)
        self.assertRegex(summary, r"\d+ low")

    def test_the_severity_filter(self):
        self.open_audit("critical")
        self.assertEqual(sorted(self.names()), ["gitea", "homeassistant"])
        self.page.select_option("#ca-min", "high")
        self.page.wait_for_function("() => [...document.querySelectorAll('#ca-tbody a')].some(a => a.innerText.trim() === 'node-exporter')", timeout=15000)
        self.assertEqual(sorted(self.names()), ["gitea", "homeassistant", "node-exporter"])
        self.page.select_option("#ca-min", "low")
        self.page.wait_for_function("() => [...document.querySelectorAll('#ca-tbody a')].some(a => a.innerText.trim() === 'vaultwarden')", timeout=15000)
        self.assertIn("vaultwarden", self.names(), "everything includes a container with one low finding")

    def test_a_row_opens_to_its_findings_with_the_evidence(self):
        self.open_audit()
        self.open_row("gitea")
        text = self.page.inner_text("#ca-tbody .ca-findings")
        self.assertIn("Container engine socket mounted", text)
        self.assertIn("/var/run/docker.sock", text)
        self.assertIn("critical", text.lower())
        self.assertEqual(self.page.get_attribute("#ca-tbody a:text-is('gitea')", "aria-expanded"), "true")
        self.page.click("#ca-tbody a:text-is('gitea')")
        self.assertEqual(self.page.locator("#ca-tbody .ca-findings").count(), 0, "a second click closes it")

    def test_the_filter_box(self):
        self.open_audit()
        self.page.fill("#ca-filter", "node-exp")
        self.page.wait_for_timeout(500)
        self.assertEqual(self.names(), ["node-exporter"])
        self.page.fill("#ca-filter", "no-such-thing-here")
        self.page.wait_for_timeout(500)
        self.assertIn("No container matches the filter.", self.page.inner_text("#ca-tbody"))
        self.page.fill("#ca-filter", "")
        self.page.wait_for_timeout(300)

    def test_accepting_a_finding_and_taking_it_back(self):
        self.open_audit("critical")
        self.open_row("gitea")
        btn = "#ca-tbody [data-action-btn='_caAcceptBtn'][data-rule='engine_socket']"
        self.page.click(btn)
        self.page.wait_for_selector("#ui-prompt-modal.active", timeout=10000)
        self.page.fill("#ui-prompt-input", "CI runner needs the engine")
        self.page.click("#ui-prompt-confirm")
        # the row says so once the change is saved and the list drawn again
        self.page.wait_for_function("() => [...document.querySelectorAll('#ca-tbody tr[data-ca-row]')].some(r => /accepted/.test(r.innerText))", timeout=20000)
        self.assertEqual(self.names(), ["homeassistant", "gitea"], "gitea stays findable, after the one that still counts")
        stored = json.loads((self.data / "container_audit_accepts.json").read_text())
        row = stored["gt01"][0]
        self.assertEqual((row["container"], row["rule"], row["by"], row["note"]), ("gitea", "engine_socket", "alice", "CI runner needs the engine"))
        # the row stayed open through the reload, with the finding marked
        self.assertIn("accepted", self.page.inner_text("#ca-tbody .ca-findings").lower())
        self.page.click("#ca-tbody [data-action-btn='_caAcceptBtn'][data-rule='engine_socket']")
        self.page.wait_for_function("() => [...document.querySelectorAll('#ca-tbody [data-rule=\"engine_socket\"]')].every(b => b.innerText.trim() === 'Accept')", timeout=20000)
        self.assertEqual(json.loads((self.data / "container_audit_accepts.json").read_text()), {})

    def test_cancelling_the_prompt_changes_nothing(self):
        self.open_audit("critical")
        self.open_row("homeassistant")
        self.page.click("#ca-tbody [data-action-btn='_caAcceptBtn'][data-rule='privileged']")
        self.page.wait_for_selector("#ui-prompt-modal.active", timeout=10000)
        self.page.keyboard.press("Escape")
        self.page.wait_for_timeout(800)
        f = self.data / "container_audit_accepts.json"
        self.assertEqual(json.loads(f.read_text()) if f.exists() else {}, {})

    def test_a_slow_answer_to_an_earlier_request_does_not_replace_a_later_one(self):
        self.open_audit("critical")
        self.page.evaluate("() => { window.__origApi = window.api; window.api = async (m, p, ...r) => { "
                           "if (String(p).includes('/containers/audit?min=medium')) await new Promise(x => setTimeout(x, 2000)); "
                           "return window.__origApi(m, p, ...r); }; }")
        try:
            self.page.select_option("#ca-min", "medium")     # slow
            self.page.select_option("#ca-min", "high")       # quick, and the one asked for last
            self.page.wait_for_timeout(3500)
            self.assertEqual(sorted(self.names()), ["gitea", "homeassistant", "node-exporter"], "what was asked for last is what is shown")
        finally:
            self.page.evaluate("() => { window.api = window.__origApi; }")

    def test_names_from_a_host_are_text(self):
        evil = "<img src=x onerror=\"window.__capwn=1\">"

        def patch(store):
            it = store["gt01"]["items"][0]
            it["name"] = evil
            it["image"] = evil
            it["audit"]["mounts"][0]["src"] = "/var/run/docker.sock"
        self.edit_store("containers.json", patch)
        self.open_audit()
        self.page.click("#ca-tbody a[data-action-btn='_caToggleBtn'] >> nth=0")
        self.page.wait_for_timeout(500)
        self.assertEqual(self.page.locator("#ca-tbody img").count(), 0)
        self.assertIsNone(self.page.evaluate("() => window.__capwn"))
        self.assertIn("<img src=x", self.page.inner_text("#ca-tbody"))


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestRepositories(_Page):

    def open_repos(self, floor="low"):
        self.page.evaluate("() => showPage('patches', document.querySelector('.nav-btn[data-page=patches]'))")
        self.page.wait_for_function("() => typeof loadRepositories === 'function'", timeout=60000)
        self.page.evaluate("async (f) => { document.getElementById('repo-min').value = f; document.getElementById('repo-filter').value = ''; "
                           "_repoOpen.clear(); await loadRepositories(); }", floor)
        self.page.wait_for_selector("#repo-tbody tr [data-action-btn='_repoToggleBtn']", timeout=30000)

    def labels(self):
        return self.page.eval_on_selector_all("#repo-tbody tr[data-repo-row] a", "as => as.map(a => a.innerText.trim())")

    def tearDown(self):
        try:
            self.page.evaluate("() => { if (typeof _repoOpen !== 'undefined') _repoOpen.clear(); }")
        except Exception:
            pass
        super().tearDown()

    def test_the_card_lists_the_fleets_repositories_worst_first(self):
        self.open_repos()
        labels = self.labels()
        joined = "\n".join(labels)
        for want in ("download.docker.com", "apt.grafana.com", "repo.jellyfin.org", "nginx.org", "download.proxmox.com", "mirror.lab.local"):
            self.assertIn(want, joined)
        self.assertIn("mirror.lab.local", labels[0], "the unsigned internal mirror leads")
        summary = self.page.inner_text("#repo-summary").lower()
        self.assertIn("high", summary)
        self.assertIn("third party", summary)
        self.assertIn("9 hosts reporting", summary)

    def test_a_shared_repository_says_how_many_hosts_use_it(self):
        self.open_repos()
        rows = self.page.eval_on_selector_all("#repo-tbody tr[data-repo-row]", "rs => rs.map(r => [r.querySelector('a').innerText.trim(), r.children[2].innerText.trim()])")
        by = {l: n for l, n in rows}
        debian = [n for l, n in by.items() if "deb.debian.org/debian bookworm" in l and "security" not in l and "updates" not in l]
        self.assertTrue(debian and all(int(n) >= 5 for n in debian), by)

    def test_a_row_opens_to_its_hosts_and_findings(self):
        self.open_repos()
        self.page.click("#repo-tbody a:has-text('mirror.lab.local')")
        self.page.wait_for_selector("#repo-tbody .ca-findings", timeout=10000)
        text = self.page.inner_text("#repo-tbody .ca-detail")
        self.assertIn("nextcloud.lab", text)
        self.assertIn("Signature checking is switched off", text)
        self.assertIn("Fetched over plain http", text)
        self.assertIn("/etc/apt/sources.list.d/lab-mirror.list", text)
        self.assertEqual(self.page.get_attribute("#repo-tbody a:has-text('mirror.lab.local')", "aria-expanded"), "true")

    def test_the_severity_filter_and_the_text_filter(self):
        self.open_repos("high")
        labels = self.labels()
        self.assertEqual(len(labels), 1, labels)
        self.assertIn("mirror.lab.local", labels[0])
        self.page.select_option("#repo-min", "low")
        self.page.wait_for_function("() => document.querySelectorAll('#repo-tbody tr[data-repo-row]').length > 3", timeout=15000)
        self.page.fill("#repo-filter", "grafana")
        self.page.wait_for_timeout(500)
        self.assertEqual([l for l in self.labels() if "grafana" in l], self.labels())
        self.assertEqual(len(self.labels()), 1)
        self.page.fill("#repo-filter", "no-such-repository-anywhere")
        self.page.wait_for_timeout(500)
        self.assertIn("No repository matches the filter.", self.page.inner_text("#repo-tbody"))
        self.page.fill("#repo-filter", "")

    def test_the_table_sorts(self):
        self.open_repos()
        self.page.click("#repo-thead th[data-col='hosts']")
        self.page.wait_for_timeout(300)
        first = self.page.eval_on_selector_all("#repo-tbody tr[data-repo-row]", "rs => rs.map(r => Number(r.children[2].innerText))")
        self.page.click("#repo-thead th[data-col='hosts']")
        self.page.wait_for_timeout(300)
        second = self.page.eval_on_selector_all("#repo-tbody tr[data-repo-row]", "rs => rs.map(r => Number(r.children[2].innerText))")
        self.assertEqual(first, sorted(first))
        self.assertEqual(second, sorted(second, reverse=True))

    def test_a_slow_answer_to_an_earlier_request_does_not_replace_a_later_one(self):
        self.open_repos("high")
        self.page.evaluate("() => { window.__origApi = window.api; window.api = async (m, p, ...r) => { "
                           "if (String(p).includes('/repositories?min=low')) await new Promise(x => setTimeout(x, 2000)); "
                           "return window.__origApi(m, p, ...r); }; }")
        try:
            self.page.select_option("#repo-min", "low")      # slow
            self.page.select_option("#repo-min", "high")     # quick, and the one asked for last
            self.page.wait_for_timeout(3500)                 # the slow one has answered by now
            self.assertEqual(len(self.labels()), 1, "the answer to the request made last is what is shown")
            self.assertEqual(self.page.eval_on_selector("#repo-min", "e => e.value"), "high")
        finally:
            self.page.evaluate("() => { window.api = window.__origApi; }")

    def test_a_host_name_is_text(self):
        evil = "<img src=x onerror=\"window.__repwn2=1\">"

        def patch(devs):
            devs["nc01"]["name"] = evil
        self.edit_store("devices.json", patch)
        self.open_repos("high")
        self.page.click("#repo-tbody a:has-text('mirror.lab.local')")
        self.page.wait_for_selector("#repo-tbody .ca-detail", timeout=10000)
        self.assertEqual(self.page.locator("#repo-tbody img").count(), 0)
        self.assertIsNone(self.page.evaluate("() => window.__repwn2"))
        self.assertIn("<img src=x", self.page.inner_text("#repo-tbody .ca-detail"))

    def test_addresses_from_a_host_are_text(self):
        evil = "<img src=x onerror=\"window.__repwn=1\">"

        def patch(store):
            files = store["gt01"]["files"]
            files["/etc/apt/sources.list.d/evil.list"] = f"deb http://{evil}/u noble main\ndeb http://evil.example/{evil} noble main"
        self.edit_store("repo_inventory.json", patch)
        self.open_repos()
        self.assertEqual(self.page.locator("#repo-tbody img").count(), 0)
        self.assertIsNone(self.page.evaluate("() => window.__repwn"))
        self.assertIn("<img src=x", self.page.inner_text("#repo-tbody"))


if __name__ == "__main__":
    unittest.main()
