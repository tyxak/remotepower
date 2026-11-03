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


@unittest.skipUnless(_GATE, SKIP_REASON)
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


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestHostProbes(_Page):
    """A check that runs from a host's own agent: the rows on the Remote checks table and the editor that creates them."""

    LABEL = "zz host-probe e2e"

    def setUp(self):
        super().setUp()
        self.page.evaluate("closeModal('monitor-add-modal')")
        self.page.evaluate("showPage('monitor')")

    def tearDown(self):
        self.page.evaluate("closeModal('monitor-add-modal')")
        self.page.evaluate("""async (label) => {
            const cfg = await api('GET', '/config');
            await api('POST', '/config', {monitors: (cfg.monitors || []).filter(m => !String(m.label).startsWith(label))});
        }""", self.LABEL)
        super().tearDown()

    def rows(self):
        self.page.wait_for_function("() => (window.monitorTargets || []).some(r => r.label === 'Gitea Postgres \u2014 from gt01')", timeout=90000)
        self.page.wait_for_function("() => { const t = document.getElementById('monitor-tbody'); return t && t.innerText.includes('from gt01'); }",
                                    timeout=30000)
        return self.page.eval_on_selector_all("#monitor-tbody tr", "rs => rs.map(r => [...r.children].map(c => c.innerText.trim().replace(/\\s+/g, ' ')))")

    def open_add(self):
        # the dialog fills its "Probe from" list after its requests answer, and a later fill supersedes an earlier one:
        # wait for the last, or a choice made now would be replaced when the list arrives
        self.page.evaluate("async () => { openMonitorAdd(); await _fillMonitorSatellites(''); }")
        self.page.wait_for_function("() => document.querySelectorAll('#mon-satellite option').length > 3", timeout=30000)

    def monitors(self):
        return self.page.evaluate("api('GET', '/config').then(c => c.monitors || [])")

    def wait_closed(self):
        self.page.wait_for_function("() => !document.getElementById('monitor-add-modal').classList.contains('active')", timeout=15000)

    def test_the_table_names_the_host_that_probes(self):
        rows = {r[0]: r for r in self.rows()}
        db = rows["Gitea Postgres \u2014 from gt01"]
        self.assertEqual(db[1], "tcp")
        self.assertIn("127.0.0.1:5432", db[2])
        self.assertIn("via host", db[2])
        self.assertIn("gitea.lab", db[2], "the badge is followed by the host's name")
        self.assertIn("up", db[3])
        self.assertEqual(db[4], "open")
        web = rows["Gitea web \u2014 from gt01"]
        self.assertIn("200", web[4])
        # the satellite's row keeps its own badge and is not taken for a host's
        sat = [r for r in rows.values() if r[0].startswith("Edge site")][0]
        self.assertIn("via satellite", sat[2])
        self.assertNotIn("via host", sat[2])
        self.assertIn("up", sat[3], "the demo's satellite has reported")

    def test_a_result_that_is_no_longer_current_does_not_read_as_up_or_down(self):
        db, web = "Gitea Postgres \u2014 from gt01", "Gitea web \u2014 from gt01"
        self.assertIn("up", {r[0]: r for r in self.rows()}[db][3], "a recent result is a reading")

        def age(doc):
            # the demo checks every hour and the host reports every 5 minutes, so a result is current for 2 x 65 minutes
            doc[db]["checked"] = int(time.time()) - 20000       # the host stopped reporting hours ago
            doc.pop(web)                                          # and this one never reported

        self.edit_store("satellite_monitors.json", age)
        self.page.evaluate("() => runMonitor(false)")
        self.page.wait_for_function("() => document.getElementById('monitor-tbody').innerText.includes('NO DATA')", timeout=30000)
        rows = {r[0]: r for r in self.rows()}
        self.assertEqual(rows[db][3], "NO DATA")
        self.assertEqual(rows[db][4], "no recent result from the host (the last one was up: open)")
        self.assertIn("ago", rows[db][5], "and the age column still says how old it is")
        self.assertEqual(rows[web][3], "WAITING")
        self.assertEqual(rows[web][4], "awaiting first probe from the host")
        self.assertEqual(self.page.eval_on_selector_all("#monitor-tbody .mon-status", "els => els.map(e => e.innerText.trim())")
                         .count("\u2191 up") >= 1, True, "rows that are readings still show the arrow")
        for label in (db, web):
            self.assertNotIn("\u2191", rows[label][3])
            self.assertNotIn("\u2193", rows[label][3])

    def test_the_editor_offers_the_linux_hosts_that_have_an_agent(self):
        self.rows()
        self.open_add()
        opts = self.page.eval_on_selector_all("#mon-satellite option", "os => os.map(o => [o.value, o.textContent.trim()])")
        hosts = [(v[5:], t) for v, t in opts if v.startswith("host:")]
        names = {t for _, t in hosts}
        self.assertIn("gitea.lab", names)
        self.assertIn("vaultwarden.lab", names)
        for not_a_prober in ("design-win11", "mette-macbook", "switch-core", "ap-living"):
            self.assertNotIn(not_a_prober, names, "a Windows or macOS host and a host with no agent do not probe")
        self.assertEqual(len(hosts), 12, hosts)
        self.assertEqual([t.lower() for _, t in hosts], sorted(t.lower() for _, t in hosts), "sorted by name")

    def test_a_check_is_saved_with_its_host(self):
        self.rows()
        self.open_add()
        self.page.fill("#mon-label", self.LABEL)
        self.page.select_option("#mon-type", "tcp")
        self.page.fill("#mon-target", "127.0.0.1:6379")
        self.page.select_option("#mon-satellite", "host:vw01")
        self.page.click('#monitor-add-modal [data-action="addMonitor"]')
        self.wait_closed()
        saved = [m for m in self.monitors() if m["label"] == self.LABEL]
        self.assertEqual(len(saved), 1, saved)
        self.assertEqual(saved[0].get("via_host"), "vw01")
        self.assertNotIn("via_satellite", saved[0])
        self.page.wait_for_function("(l) => (window.monitorTargets || []).some(r => r.label === l)", arg=self.LABEL, timeout=60000)
        row = self.page.evaluate("(l) => window.monitorTargets.find(r => r.label === l)", self.LABEL)
        self.assertEqual(row["origin"], "host:vw01")
        self.assertEqual(row["detail"], "awaiting first probe from the host")

    def test_editing_a_check_shows_its_host_and_a_save_keeps_it(self):
        self.rows()
        idx = self.page.evaluate("() => window.monitorTargets.findIndex(r => r.label === 'Gitea Postgres \u2014 from gt01')")
        self.page.evaluate("(i) => editMonitor(i)", idx)
        self.page.wait_for_function("() => document.getElementById('mon-satellite').value === 'host:gt01'", timeout=30000)
        self.page.click('#monitor-add-modal [data-action="addMonitor"]')
        self.wait_closed()
        kept = [m for m in self.monitors() if m["label"] == "Gitea Postgres \u2014 from gt01"]
        self.assertEqual(kept[0].get("via_host"), "gt01")

    def test_a_host_that_is_gone_stays_on_screen_instead_of_moving_the_check_to_the_server(self):
        self.edit_store("config.json", lambda cfg: [m.update(via_host="gone-host") for m in cfg["monitors"] if m.get("label") == "Gitea web \u2014 from gt01"])
        self.page.evaluate("showPage('monitor')")
        self.rows()
        idx = self.page.evaluate("() => window.monitorTargets.findIndex(r => r.label === 'Gitea web \u2014 from gt01')")
        self.page.evaluate("(i) => editMonitor(i)", idx)
        self.page.wait_for_function("() => document.getElementById('mon-satellite').value === 'host:gone-host'", timeout=30000)
        self.assertEqual(self.page.eval_on_selector("#mon-satellite", "s => s.selectedOptions[0].textContent.trim()"), "Removed host")
        self.page.click('#monitor-add-modal [data-action="addMonitor"]')
        self.page.wait_for_selector(".toast", timeout=15000)
        self.assertIn("not enrolled", self.page.inner_text(".toast"))
        self.assertTrue(self.page.evaluate("document.getElementById('monitor-add-modal').classList.contains('active')"), "the dialog stays open")

    def test_a_check_the_agent_cannot_evaluate_is_refused_with_the_reason(self):
        self.rows()
        self.open_add()
        self.page.fill("#mon-label", self.LABEL)
        self.page.select_option("#mon-type", "http")
        self.page.fill("#mon-target", "http://127.0.0.1:8080/")
        self.page.select_option("#mon-body-mode", "regex")
        self.page.fill("#mon-body-value", "ok.*")
        self.page.select_option("#mon-satellite", "host:vw01")
        self.page.click('#monitor-add-modal [data-action="addMonitor"]')
        self.page.wait_for_selector(".toast", timeout=15000)
        self.assertIn("regex", self.page.inner_text(".toast"))
        self.assertEqual([m for m in self.monitors() if m["label"] == self.LABEL], [])


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestS3Backup(_Page):
    """Settings, Backups: the form for the copy to an S3-compatible bucket."""

    def open_pane(self):
        # the saved settings are put in the form when the settings document has been read, and the note under the form is set by the
        # same call: empty it first and wait for it to come back, or the load of an earlier visit looks like this one and what is
        # typed is overwritten by the answer
        self.page.evaluate("() => { const n = document.getElementById('backup-s3-secret-state'); if (n) n.textContent = ''; }")
        self.page.evaluate("() => { showPage('settings'); }")
        self.page.wait_for_selector("#settings-tab-btn-backups", timeout=30000)
        self.page.evaluate("() => switchSettingsTab('backups')")
        self.page.wait_for_selector("#backup-s3-endpoint", state="visible", timeout=30000)
        self.page.wait_for_function("() => (document.getElementById('backup-s3-secret-state')?.innerText || '').trim() !== ''", timeout=60000)

    def config(self):
        return self.page.evaluate("api('GET', '/config')")

    def tearDown(self):
        self.page.evaluate("() => api('POST', '/config', {backup: {s3: {enabled: false}}})")
        super().tearDown()

    def test_the_form_has_its_fields_and_says_where_the_secret_key_is(self):
        self.open_pane()
        for fid in ("backup-s3-enabled", "backup-s3-endpoint", "backup-s3-bucket", "backup-s3-region", "backup-s3-prefix", "backup-s3-key",
                    "backup-s3-path-style", "backup-s3-verify-tls"):
            self.assertTrue(self.page.is_visible("#" + fid), fid)
        self.assertIn("RP_BACKUP_S3_SECRET_KEY", self.page.inner_text("#backup-s3-secret-state"), "the demo has no secret key in its environment, and the page says where it goes")
        self.assertIsNone(self.page.query_selector("#backup-s3-secret"), "there is no box to type a secret key into")

    def test_a_save_stores_what_was_typed_and_never_a_secret(self):
        self.open_pane()
        self.page.fill("#backup-s3-endpoint", "https://s3.eu-central-1.amazonaws.com")
        self.page.fill("#backup-s3-bucket", "my-remotepower-backups")
        self.page.fill("#backup-s3-region", "eu-central-1")
        self.page.fill("#backup-s3-prefix", "/rp/main")
        self.page.fill("#backup-s3-key", "AKIAEXAMPLE")
        self.page.check("#backup-s3-enabled")
        r = self.page.evaluate("() => api('POST', '/config', {backup: {s3: _backupS3Form()}})")
        self.assertTrue(r.get("ok"), r)
        s3 = self.config()["backup"]["s3"]
        self.assertEqual((s3["bucket"], s3["prefix"], s3["region"], s3["access_key_id"], s3["enabled"]),
                         ("my-remotepower-backups", "rp/main/", "eu-central-1", "AKIAEXAMPLE", True))
        self.assertEqual(set(s3), {"enabled", "endpoint", "bucket", "region", "prefix", "access_key_id", "path_style", "verify_tls"})

    def test_a_form_the_server_refuses_says_why(self):
        self.open_pane()
        self.page.fill("#backup-s3-endpoint", "ftp://nowhere")
        self.page.fill("#backup-s3-bucket", "my-remotepower-backups")
        self.page.fill("#backup-s3-key", "AKIAEXAMPLE")
        self.page.check("#backup-s3-enabled")
        self.page.click('[data-action="testS3Backup"]')
        self.page.wait_for_selector(".toast", timeout=20000)
        self.assertIn("endpoint", self.page.inner_text(".toast").lower())

    def test_the_connection_test_names_the_step_that_failed(self):
        self.open_pane()
        self.page.fill("#backup-s3-endpoint", "http://127.0.0.1:1")
        self.page.fill("#backup-s3-bucket", "my-remotepower-backups")
        self.page.fill("#backup-s3-key", "AKIAEXAMPLE")
        self.page.check("#backup-s3-enabled")
        self.page.click('[data-action="testS3Backup"]')
        self.page.wait_for_function("() => document.getElementById('backup-s3-result').innerText.trim() !== 'Testing…'", timeout=60000)
        text = self.page.inner_text("#backup-s3-result")
        self.assertTrue("RP_BACKUP_S3_SECRET_KEY" in text or "cannot write" in text, text)


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestConfirmAndPromptAnswerWhenClosed(_Page):
    """uiConfirm and uiPrompt hand back a promise. The dialog closed with Escape used to disappear and leave the promise waiting, which the
    next dialog to open then answered with null. Every way of closing it has to answer the code that is waiting, now."""

    def setUp(self):
        super().setUp()
        self.page.evaluate("() => { window.__answers = []; }")

    def tearDown(self):
        self.page.evaluate("() => { closeModal('ui-prompt-modal'); }")
        super().tearDown()

    def ask(self, kind):
        call = ("uiConfirm({message: 'Go on?'})" if kind == "confirm"
                else "uiPrompt({title: 'Name', message: 'A name', type: 'text'})")
        self.page.evaluate(f"() => {{ {call}.then(v => window.__answers.push([{kind!r}, v])); }}")
        self.page.wait_for_selector("#ui-prompt-modal.active", timeout=10000)

    def answers(self):
        return self.page.evaluate("() => window.__answers")

    def wait_answers(self, n):
        self.page.wait_for_function("(n) => window.__answers.length >= n", arg=n, timeout=5000)
        return self.answers()

    def waiting(self):
        return self.page.evaluate("() => _uiPromptResolve !== null")

    def test_escape_on_a_confirm_answers_false(self):
        self.ask("confirm")
        self.page.keyboard.press("Escape")
        self.assertEqual(self.wait_answers(1), [["confirm", False]])
        self.assertFalse(self.waiting())
        self.assertFalse(self.page.evaluate("() => document.getElementById('ui-prompt-modal').classList.contains('active')"))

    def test_escape_on_a_prompt_answers_null(self):
        self.ask("prompt")
        self.page.fill("#ui-prompt-input", "half typed")
        self.page.keyboard.press("Escape")
        self.assertEqual(self.wait_answers(1), [["prompt", None]], "what was typed is not an answer")
        self.assertFalse(self.waiting())

    def test_the_buttons_still_answer_as_they_did(self):
        self.ask("confirm")
        self.page.click("#ui-prompt-confirm")
        self.assertEqual(self.wait_answers(1), [["confirm", True]])
        self.ask("confirm")
        self.page.click("[data-action='_uiPromptCancel']")
        self.assertEqual(self.wait_answers(2)[1], ["confirm", False])
        self.ask("prompt")
        self.page.fill("#ui-prompt-input", "abc")
        self.page.click("#ui-prompt-confirm")
        self.assertEqual(self.wait_answers(3)[2], ["prompt", "abc"])
        self.ask("prompt")
        self.page.fill("#ui-prompt-input", "def")
        self.page.keyboard.press("Enter")
        self.assertEqual(self.wait_answers(4)[3], ["prompt", "def"])
        self.assertFalse(self.waiting())

    def test_closing_it_from_a_script_answers_too(self):
        self.ask("prompt")
        self.page.evaluate("() => closeModal('ui-prompt-modal')")
        self.assertEqual(self.wait_answers(1), [["prompt", None]])

    def test_a_dialog_closed_with_escape_does_not_answer_the_next_one(self):
        self.ask("confirm")
        self.page.keyboard.press("Escape")
        self.wait_answers(1)
        self.ask("confirm")                                           # the second dialog, opened after the first was cancelled
        self.page.wait_for_timeout(300)
        self.assertEqual(self.answers(), [["confirm", False]], "the second is still waiting for its own answer")
        self.assertTrue(self.waiting())
        self.page.click("#ui-prompt-confirm")
        self.assertEqual(self.wait_answers(2)[1], ["confirm", True])

    def test_a_dialog_opened_over_another_modal_cancels_alone(self):
        self.page.evaluate("() => openModal('s3-restore-modal')")
        self.ask("confirm")
        self.page.keyboard.press("Escape")
        self.assertEqual(self.wait_answers(1), [["confirm", False]])
        self.assertTrue(self.page.evaluate("() => document.getElementById('s3-restore-modal').classList.contains('active')"),
                        "Escape closed the dialog on top and left the one under it")
        self.page.evaluate("() => closeModal('s3-restore-modal')")


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestS3Restore(_Page):
    """Restore from the S3 bucket, from the page. The demo has no store and no secret key in its environment, so the two requests are
    answered inside the browser: what is tested here is what the page asks for, what it shows of the answer, and what it sends when a
    person confirms. The server side is driven against a real store in test_v749_s3_backup."""

    ARCHIVES = {"ok": True, "bucket": "bkt", "total": 2, "archives": [
        {"name": "remotepower_data_20260302_030000.tar.gz.enc", "size": 5242880, "mtime": 1772420400},
        {"name": "remotepower_data_20260301_030000.tar.gz.enc", "size": 5100000, "mtime": 1772334000}]}

    def setUp(self):
        super().setUp()
        self.seen = []
        self.answers = {"s3-archives": (200, dict(self.ARCHIVES)), "s3-restore": (200, {"ok": True, "restored": 12, "expected": 12,
                                                                                         "snapshot": "pre-restore-20260303-101500.tar.gz.enc", "stores_imported": 0})}
        self.page.evaluate("() => { const n = document.getElementById('backup-s3-secret-state'); if (n) n.textContent = ''; }")
        self.page.evaluate("() => { showPage('settings'); }")
        self.page.wait_for_selector("#settings-tab-btn-backups", timeout=30000)
        self.page.evaluate("() => switchSettingsTab('backups')")
        self.page.wait_for_selector("#backup-s3-endpoint", state="visible", timeout=30000)
        self.page.wait_for_function("() => (document.getElementById('backup-s3-secret-state')?.innerText || '').trim() !== ''", timeout=60000)
        self.page.fill("#backup-s3-endpoint", "http://127.0.0.1:9000")
        self.page.fill("#backup-s3-bucket", "bkt")
        self.page.fill("#backup-s3-key", "AKIAEXAMPLE")

        def answer(route):
            req = route.request
            which = req.url.rsplit("/", 1)[1]
            self.seen.append((which, req.post_data, {k.lower(): v for k, v in req.headers.items()}))
            status, body = self.answers[which]
            route.fulfill(status=status, content_type="application/json", body=json.dumps(body))
        self.page.route("**/api/backup/s3-*", answer)
        self.addCleanup(lambda: self.page.unroute("**/api/backup/s3-*"))

    def tearDown(self):
        self.page.evaluate("() => { closeModal('s3-restore-modal'); closeModal('ui-prompt-modal'); }")
        self.page.evaluate("() => { const r = document.getElementById('backup-result'); if (r) { r.hidden = true; r.textContent = ''; } }")
        super().tearDown()

    def open_list(self):
        self.page.click('[data-action="openS3Restore"]')
        self.page.wait_for_function("() => { const l = document.getElementById('s3-restore-list'); return l && !l.innerText.includes('Loading'); }", timeout=20000)

    def rows(self):
        return self.page.eval_on_selector_all("#s3-restore-list tbody tr", "rs => rs.map(r => [...r.children].map(c => c.innerText.trim().replace(/\\s+/g, ' ')))")

    def test_the_list_asks_with_the_form_as_it_stands_and_shows_the_archives(self):
        self.open_list()
        which, raw, headers = self.seen[0]
        self.assertEqual(which, "s3-archives")
        sent = json.loads(raw)
        self.assertEqual((sent["s3"]["endpoint"], sent["s3"]["bucket"], sent["s3"]["access_key_id"]), ("http://127.0.0.1:9000", "bkt", "AKIAEXAMPLE"))
        self.assertNotIn("secret", raw.lower(), "the page has no secret key to send")
        rows = self.rows()
        self.assertEqual([r[0] for r in rows], ["remotepower_data_20260302_030000.tar.gz.enc", "remotepower_data_20260301_030000.tar.gz.enc"])
        self.assertEqual(rows[0][1], "5.0 MB")
        self.assertRegex(rows[0][2], r"2026")
        self.assertEqual(rows[0][3], "Restore")
        self.assertNotIn("Older archives", self.page.inner_text("#s3-restore-list"))

    def test_an_empty_bucket_says_so(self):
        self.answers["s3-archives"] = (200, {"ok": True, "bucket": "bkt", "total": 0, "archives": []})
        self.open_list()
        self.assertIn("No archives in the bucket.", self.page.inner_text("#s3-restore-list"))

    def test_more_than_are_shown_says_so(self):
        self.answers["s3-archives"] = (200, dict(self.ARCHIVES, total=130))
        self.open_list()
        self.assertIn("Older archives are not shown.", self.page.inner_text("#s3-restore-list"))

    def test_a_store_that_refuses_shows_the_reason_and_no_table(self):
        self.answers["s3-archives"] = (200, {"ok": False, "error": "the store answered 403 AccessDenied: Access Denied"})
        self.open_list()
        self.assertIn("AccessDenied", self.page.inner_text("#s3-restore-error"))
        self.assertIsNone(self.page.query_selector("#s3-restore-list table"))

    def test_a_request_the_server_refuses_shows_the_reason(self):
        self.answers["s3-archives"] = (403, {"error": "Restoring from the S3 bucket is for the platform operator"})
        self.open_list()
        self.assertIn("platform operator", self.page.inner_text("#s3-restore-error"))

    def test_a_name_from_the_bucket_is_text(self):
        hostile = 'x"><img src=x id=pwned>.tar.gz.enc'
        self.answers["s3-archives"] = (200, {"ok": True, "bucket": "bkt", "total": 1, "archives": [{"name": hostile, "size": 1, "mtime": 0}]})
        self.open_list()
        self.assertIsNone(self.page.query_selector("#pwned"), "it was not parsed as markup")
        self.assertEqual(self.page.get_attribute("#s3-restore-list [data-action='restoreFromS3']", "data-arg"), hostile)
        self.assertEqual(self.rows()[0][0], hostile)

    def confirm_restore(self, passphrase="correct horse"):
        self.open_list()
        self.page.click("#s3-restore-list [data-action='restoreFromS3']")
        self.page.wait_for_selector("#ui-prompt-modal.active", timeout=10000)
        self.assertIn("OVERWRITES", self.page.inner_text("#ui-prompt-message"))
        self.assertIn("remotepower_data_20260302_030000.tar.gz.enc", self.page.inner_text("#ui-prompt-message"))
        self.page.click("#ui-prompt-confirm")
        self.page.wait_for_function("() => document.getElementById('ui-prompt-input') && !document.getElementById('ui-prompt-input').classList.contains('d-none')", timeout=10000)
        self.assertEqual(self.page.get_attribute("#ui-prompt-input", "type"), "password")
        self.page.fill("#ui-prompt-input", passphrase)
        self.page.click("#ui-prompt-confirm")

    def test_a_restore_sends_the_name_the_settings_and_the_passphrase_and_shows_the_result(self):
        self.confirm_restore()
        self.page.wait_for_function("() => (document.getElementById('backup-result')?.innerText || '').includes('Restored')", timeout=20000)
        which, raw, headers = [x for x in self.seen if x[0] == "s3-restore"][0]
        sent = json.loads(raw)
        self.assertEqual(sent["name"], "remotepower_data_20260302_030000.tar.gz.enc")
        self.assertEqual(sent["s3"]["bucket"], "bkt")
        self.assertEqual(headers["x-rp-backup-passphrase"], "correct horse")
        self.assertTrue(headers["x-token"], "the session goes with it")
        self.assertNotIn("correct horse", raw, "the passphrase is in the header, not in the body")
        text = self.page.inner_text("#backup-result")
        self.assertIn("Restored 12 files", text)
        self.assertIn("pre-restore-20260303-101500.tar.gz.enc", text)
        self.assertFalse(self.page.evaluate("() => document.getElementById('s3-restore-modal').classList.contains('active')"), "the list is closed")

    def test_a_restore_the_server_refuses_says_why(self):
        self.answers["s3-restore"] = (400, {"error": "decryption failed: wrong passphrase or damaged archive"})
        self.confirm_restore("wrong")
        self.page.wait_for_function("() => (document.getElementById('backup-result')?.innerText || '').includes('Restore failed')", timeout=20000)
        self.assertIn("decryption failed", self.page.inner_text("#backup-result"))

    def test_a_restore_the_store_could_not_serve_says_why(self):
        self.answers["s3-restore"] = (200, {"ok": False, "error": "the store answered 404 NoSuchKey"})
        self.confirm_restore()
        self.page.wait_for_function("() => (document.getElementById('backup-result')?.innerText || '').includes('Restore failed')", timeout=20000)
        self.assertIn("NoSuchKey", self.page.inner_text("#backup-result"))

    def test_cancelling_the_confirmation_sends_nothing(self):
        self.open_list()
        self.page.click("#s3-restore-list [data-action='restoreFromS3']")
        self.page.wait_for_selector("#ui-prompt-modal.active", timeout=10000)
        self.page.keyboard.press("Escape")
        self.page.wait_for_timeout(800)
        self.assertEqual([x for x in self.seen if x[0] == "s3-restore"], [])

    def test_cancelling_the_passphrase_sends_nothing(self):
        self.open_list()
        self.page.click("#s3-restore-list [data-action='restoreFromS3']")
        self.page.wait_for_selector("#ui-prompt-modal.active", timeout=10000)
        self.page.click("#ui-prompt-confirm")
        self.page.wait_for_function("() => document.getElementById('ui-prompt-input') && !document.getElementById('ui-prompt-input').classList.contains('d-none')", timeout=10000)
        self.page.keyboard.press("Escape")
        self.page.wait_for_timeout(800)
        self.assertEqual([x for x in self.seen if x[0] == "s3-restore"], [])

    def test_an_empty_passphrase_is_sent_as_none_so_the_servers_own_is_used(self):
        self.confirm_restore("")
        self.page.wait_for_function("() => (document.getElementById('backup-result')?.innerText || '').includes('Restored')", timeout=20000)
        headers = [x for x in self.seen if x[0] == "s3-restore"][0][2]
        self.assertNotIn("x-rp-backup-passphrase", headers)


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestCpuTime(_Page):

    def test_the_drawer_shows_where_the_cpu_time_goes(self):
        self.open_drawer_section("tnas", "truenas.lab", "sysinfo")
        self.page.wait_for_function("() => document.getElementById('audit-body-sysinfo').innerText.includes('I/O wait')", timeout=30000)
        text = self.page.inner_text("#audit-body-sysinfo")
        self.assertIn("cpu time", text.lower(), "the pill label is drawn in capitals")
        self.assertIn("user 18.4% · nice 0.8% · system 5.7% · I/O wait 31.0% · interrupts 1.0% · steal 0.0% · idle 43.1%", text)

    def test_a_windows_host_has_no_cpu_time_row(self):
        """Only the Linux agent sends the shares, so a Windows host shows none rather than a row of zeros."""
        self.open_drawer_section("wks01", "design-win11", "sysinfo")
        self.page.wait_for_function("() => document.getElementById('audit-body-sysinfo').innerText.length > 40", timeout=30000)
        text = self.page.inner_text("#audit-body-sysinfo").lower()
        self.assertIn("disk", text, "control: the drawer for this host did load")
        self.assertNotIn("cpu time", text)
        self.assertNotIn("i/o wait", text)

    def test_the_host_editor_shows_the_fleets_lines_and_saves_its_own(self):
        self.page.evaluate("() => openMetricThresholds('tnas', 'truenas.lab')")
        self.page.wait_for_selector("#thr-iowait-warn", state="visible", timeout=30000)
        self.page.wait_for_function("() => document.getElementById('thr-iowait-warn').placeholder !== ''", timeout=30000)
        self.assertEqual(self.page.get_attribute("#thr-iowait-warn", "placeholder"), "25")
        self.assertEqual(self.page.get_attribute("#thr-steal-crit", "placeholder"), "25")
        self.addCleanup(lambda: self.page.evaluate("() => api('DELETE', '/devices/tnas/metric-thresholds')"))
        self.page.fill("#thr-iowait-warn", "40")
        self.page.click('#metric-thresholds-modal [data-action="saveMetricThresholds"]')
        self.page.wait_for_function("() => !document.getElementById('metric-thresholds-modal').classList.contains('active')", timeout=30000)
        got = self.page.evaluate("() => api('GET', '/devices/tnas/metric-thresholds')")
        self.assertEqual(got["overrides"]["iowait_warn_percent"], 40.0)

    def test_the_fleet_lines_are_in_alert_parameters(self):
        self.page.evaluate("() => { showPage('settings'); }")
        self.page.wait_for_selector("#settings-tab-btn-alertparams", timeout=30000)
        self.page.click("#settings-tab-btn-alertparams")          # the tab button also loads the values: switchSettingsTab alone does not
        self.page.wait_for_selector("#ap-iowait-warn", state="visible", timeout=30000)
        self.page.wait_for_function("() => document.getElementById('ap-iowait-warn').value === '25'", timeout=30000)
        self.assertEqual(self.page.input_value("#ap-steal-warn"), "10")
        self.assertEqual(self.page.input_value("#ap-cputime-sustain"), "3")


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestProfileLines(_Page):
    """The host profile dialog: boxes for disk busy, I/O wait and steal, and a save that keeps the lines it has no box for."""

    NAME = "zz e2e profile"

    def setUp(self):
        super().setUp()
        self.page.evaluate("closeModal('device-profile-modal')")

    def tearDown(self):
        self.page.evaluate("closeModal('device-profile-modal')")
        self.page.evaluate("""async (name) => {
            const r = await api('GET', '/device-profiles');
            for (const p of (r && r.profiles) || []) if (p.name === name) await api('DELETE', '/device-profiles/' + encodeURIComponent(p.id));
        }""", self.NAME)
        super().tearDown()

    def profiles(self):
        return [p for p in self.page.evaluate("api('GET', '/device-profiles').then(r => r.profiles || [])") if p["name"] == self.NAME]

    def make(self, mt):
        return self.page.evaluate("""async ([name, mt]) => (await api('POST', '/device-profiles', {name, metric_thresholds: mt})).id""", [self.NAME, mt])

    def edit(self, pid):
        self.page.evaluate("""async (pid) => { await loadDeviceProfiles(); editDeviceProfile(_deviceProfiles.findIndex(p => p.id === pid)); }""", pid)
        self.page.wait_for_selector("#dp-iowait-warn", state="visible", timeout=30000)

    def save(self):
        self.page.click('[data-action="saveDeviceProfile"]')
        self.page.wait_for_function("() => !document.getElementById('device-profile-modal').classList.contains('active')", timeout=15000)

    def test_the_dialog_saves_the_disk_busy_and_cpu_time_lines(self):
        self.page.evaluate("() => openDeviceProfileCreate()")
        self.page.wait_for_selector("#dp-name", state="visible", timeout=30000)
        self.page.fill("#dp-name", self.NAME)
        for box, value in (("diskio-warn", "60"), ("diskio-crit", "90"), ("iowait-warn", "20"), ("iowait-crit", "40"), ("steal-warn", "5"), ("steal-crit", "15")):
            self.page.fill(f"#dp-{box}", value)
        self.save()
        mine = self.profiles()
        self.assertEqual(len(mine), 1)
        self.assertEqual(mine[0]["metric_thresholds"], {"diskio_warn_percent": 60.0, "diskio_crit_percent": 90.0, "iowait_warn_percent": 20.0,
                                                          "iowait_crit_percent": 40.0, "steal_warn_percent": 5.0, "steal_crit_percent": 15.0})

    def test_the_boxes_show_what_the_profile_holds(self):
        pid = self.make({"iowait_warn_percent": 25, "iowait_crit_percent": 45, "steal_warn_percent": 6, "diskio_crit_percent": 95, "mem_warn_percent": 70})
        self.edit(pid)
        got = {b: self.page.input_value(f"#dp-{b}") for b in ("diskio-warn", "diskio-crit", "iowait-warn", "iowait-crit", "steal-warn", "steal-crit", "mem-warn", "mem-crit")}
        self.assertEqual(got, {"diskio-warn": "", "diskio-crit": "95", "iowait-warn": "25", "iowait-crit": "45", "steal-warn": "6", "steal-crit": "", "mem-warn": "70", "mem-crit": ""})

    def test_saving_keeps_the_lines_the_dialog_has_no_box_for(self):
        pid = self.make({"swap_warn_percent": 30, "temp_crit_celsius": 90, "mailq_warn_count": 200, "drivetemp_hdd_crit_c": 55, "nic_err_alert_min": 9,
                         "cpu_crit_load_ratio": 4, "iowait_warn_percent": 20})
        self.edit(pid)
        self.page.fill("#dp-iowait-warn", "30")
        self.page.fill("#dp-steal-warn", "7")
        self.save()
        mt = self.profiles()[0]["metric_thresholds"]
        self.assertEqual(mt["iowait_warn_percent"], 30.0)
        self.assertEqual(mt["steal_warn_percent"], 7.0)
        self.assertEqual((mt["swap_warn_percent"], mt["temp_crit_celsius"], mt["mailq_warn_count"], mt["drivetemp_hdd_crit_c"], mt["nic_err_alert_min"], mt["cpu_crit_load_ratio"]),
                         (30.0, 90.0, 200, 55.0, 9, 4.0), "these used to be replaced by the four the dialog showed")

    def test_emptying_the_last_box_removes_the_line(self):
        pid = self.make({"mem_warn_percent": 70})
        self.edit(pid)
        self.page.fill("#dp-mem-warn", "")
        self.save()
        self.assertEqual(self.profiles()[0]["metric_thresholds"], {}, "an update that left the field out kept the old line")

    def test_a_warning_line_above_its_critical_line_is_refused_with_the_reason(self):
        pid = self.make({"iowait_warn_percent": 20})
        self.edit(pid)
        self.page.fill("#dp-iowait-warn", "50")
        self.page.fill("#dp-iowait-crit", "30")
        self.page.click('[data-action="saveDeviceProfile"]')
        self.page.wait_for_function("() => [...document.querySelectorAll('.toast')].some(t => t.innerText.includes('I/O wait: warning'))", timeout=15000)
        self.assertTrue(self.page.evaluate("() => document.getElementById('device-profile-modal').classList.contains('active')"), "the dialog stays open")
        self.assertEqual(self.profiles()[0]["metric_thresholds"], {"iowait_warn_percent": 20.0}, "nothing was saved")


class TestTicketHours(_Page):
    """The hours of the ticket SLA calendar are edited with the editor the time periods use: a day takes several ranges."""

    def setUp(self):
        super().setUp()
        self.original = self.page.evaluate("api('GET', '/config').then(c => c.ticket_business_hours || {})")
        self.addCleanup(lambda: self.page.evaluate("async (bh) => { await api('POST', '/config', {ticket_business_hours: bh}); }", {
            "enabled": bool(self.original.get("enabled")), "tz_offset_min": self.original.get("tz_offset_min", 0), "weekly": self.original.get("weekly") or {},
            "holidays": self.original.get("holidays") or [], "period": self.original.get("period") or ""}))
        # opening the page starts a load of the settings that draws the hours when it answers. Open it once and wait for that draw, or
        # a late one lands in the middle of a test and replaces the ranges the test has just added; then draw them again so that every
        # test starts from what is stored, whatever the one before did to the editor
        if not self.page.evaluate("() => !!document.querySelector('#page-settings.active')"):
            self.page.evaluate("() => { showPage('settings'); }")
            self.page.wait_for_function("() => document.querySelectorAll('#bh-days .tp-day').length === 7", timeout=60000)
        self.page.wait_for_selector("#settings-tab-btn-tickets", timeout=30000)
        self.page.evaluate("() => switchSettingsTab('tickets')")
        self.page.evaluate("() => loadBusinessHours()")
        self.page.wait_for_function("() => document.querySelectorAll('#bh-days .tp-day').length === 7", timeout=60000)

    def stored(self):
        return self.page.evaluate("api('GET', '/config').then(c => c.ticket_business_hours)")

    def draw(self, weekly, holidays=()):
        self.page.evaluate("""async ([w, h]) => {
            await api('POST', '/config', {ticket_business_hours: {enabled: true, tz_offset_min: 0, weekly: w, holidays: h}});
            await loadBusinessHours();
        }""", [weekly, list(holidays)])

    def day(self, d):
        return self.page.eval_on_selector_all(f'#bh-days .tp-day[data-day="{d}"] .tp-range',
                                              "rs => rs.map(r => [r.querySelector('.tp-from').value, r.querySelector('.tp-to').value])")

    def save(self):
        self.page.click('[data-action="saveBusinessHours"]')
        self.page.wait_for_function("() => [...document.querySelectorAll('.toast')].some(t => t.innerText.includes('Business hours saved'))", timeout=15000)

    def test_a_day_with_a_lunch_break_is_shown_whole(self):
        self.draw({"0": [[540, 720], [780, 1020]], "1": [[540, 1020]]})
        self.assertEqual(self.day(0), [["09:00", "12:00"], ["13:00", "17:00"]])
        self.assertEqual(self.day(1), [["09:00", "17:00"]])
        self.assertEqual(self.day(5), [], "a day with none is closed")

    def test_saving_without_a_change_keeps_every_range(self):
        # the editor used to show the first range of a day and save only that one
        self.draw({"0": [[540, 720], [780, 1020]], "2": [[480, 600], [660, 780], [900, 1020]]})
        self.save()
        weekly = self.stored()["weekly"]
        self.assertEqual(weekly["0"], [[540, 720], [780, 1020]])
        self.assertEqual(weekly["2"], [[480, 600], [660, 780], [900, 1020]])

    def test_a_break_is_added_from_the_page(self):
        self.draw({"3": [[540, 1020]]})
        self.page.fill('#bh-days .tp-day[data-day="3"] .tp-to', "12:00")
        self.page.click('#bh-days .tp-day[data-day="3"] [data-action-btn="_tpAddRangeBtn"]')
        self.page.fill('#bh-days .tp-day[data-day="3"] .tp-range:nth-child(2) .tp-from', "13:00")
        self.save()
        self.assertEqual(self.stored()["weekly"]["3"], [[540, 720], [780, 1020]])
        self.page.evaluate("() => loadBusinessHours()")
        self.page.wait_for_function("() => document.querySelectorAll('#bh-days .tp-day[data-day=\"3\"] .tp-range').length === 2", timeout=15000)

    def test_a_range_across_midnight_is_kept_as_two_days(self):
        self.draw({})
        self.page.click('#bh-days .tp-day[data-day="4"] [data-action-btn="_tpAddRangeBtn"]')
        self.page.fill('#bh-days .tp-day[data-day="4"] .tp-from', "22:00")
        self.page.fill('#bh-days .tp-day[data-day="4"] .tp-to', "06:00")
        self.save()
        weekly = self.stored()["weekly"]
        self.assertEqual(weekly, {"4": [[1320, 1440]], "5": [[0, 360]]}, "the call used to drop it without a word")
        self.page.evaluate("() => loadBusinessHours()")
        self.page.wait_for_function("() => document.querySelectorAll('#bh-days .tp-day[data-day=\"5\"] .tp-range').length === 1", timeout=15000)
        self.assertEqual(self.day(4), [["22:00", "00:00"]])
        self.assertEqual(self.day(5), [["00:00", "06:00"]])

    def test_add_hours_switches_itself_off_at_six_and_on_again(self):
        self.draw({})
        add = '#bh-days .tp-day[data-day="6"] [data-action-btn="_tpAddRangeBtn"]'
        for _ in range(8):
            if self.page.is_enabled(add):
                self.page.click(add)
        self.assertEqual(len(self.day(6)), 6)
        self.assertFalse(self.page.is_enabled(add))
        self.page.click('#bh-days .tp-day[data-day="6"] .tp-range:nth-child(3) [data-action-btn="_tpDropRangeBtn"]')
        self.assertEqual(len(self.day(6)), 5)
        self.assertTrue(self.page.is_enabled(add))

    def test_the_period_dialog_has_the_same_cap(self):
        self.page.evaluate("() => openTimePeriodEdit('')")
        self.page.wait_for_selector("#tp-days .tp-day", timeout=30000)
        add = '#tp-days .tp-day[data-day="0"] [data-action-btn="_tpAddRangeBtn"]'
        for _ in range(8):
            if self.page.is_enabled(add):
                self.page.click(add)
        self.assertEqual(self.page.eval_on_selector_all('#tp-days .tp-day[data-day="0"] .tp-range', "rs => rs.length"), 6)
        self.assertFalse(self.page.is_enabled(add))
        self.page.evaluate("closeModal('time-period-modal')")

    def test_a_whole_day_is_midnight_to_midnight(self):
        self.draw({})
        self.page.click('#bh-days .tp-day[data-day="2"] [data-action-btn="_tpAddRangeBtn"]')
        self.page.fill('#bh-days .tp-day[data-day="2"] .tp-from', "00:00")
        self.page.fill('#bh-days .tp-day[data-day="2"] .tp-to', "00:00")
        self.save()
        self.assertEqual(self.stored()["weekly"], {"2": [[0, 1440]]}, "an end at 00:00 is the end of that day, so this day is open all day")

    def test_the_holidays_are_shown_and_kept(self):
        self.draw({"0": [[540, 1020]]}, holidays=["2026-12-25", "2026-12-26"])
        self.assertEqual(self.page.input_value("#bh-holidays").split("\n"), ["2026-12-25", "2026-12-26"])
        self.save()
        self.assertEqual(self.stored()["holidays"], ["2026-12-25", "2026-12-26"])

    def test_an_editor_that_was_never_drawn_does_not_save_an_empty_calendar(self):
        self.draw({"0": [[540, 1020]]})
        self.page.evaluate("() => { document.getElementById('bh-days').innerHTML = ''; }")
        self.page.click('[data-action="saveBusinessHours"]')
        self.page.wait_for_function("() => [...document.querySelectorAll('.toast')].some(t => t.innerText.includes('The hours are not loaded yet.'))", timeout=15000)
        self.assertEqual(self.stored()["weekly"], {"0": [[540, 1020]]}, "nothing was sent")

    def test_the_text_over_the_editor_no_longer_says_one_window(self):
        text = self.page.inner_text("#settings-pane-tickets")
        self.assertNotIn("One open window per weekday", text)
        self.assertIn("up to six ranges", text)


class TestTimePeriods(_Page):

    def open_settings(self):
        self.page.evaluate("() => { showPage('settings'); }")
        self.page.wait_for_selector("#settings-tab-btn-dashboard", timeout=30000)
        self.page.evaluate("() => switchSettingsTab('dashboard')")
        self.page.wait_for_function("() => document.querySelectorAll('#tp-tbody tr').length >= 3 && !document.getElementById('tp-tbody').innerText.includes('No time periods')", timeout=60000)

    def config(self):
        return self.page.evaluate("api('GET', '/config')")

    def tearDown(self):
        self.page.evaluate("closeModal('time-period-modal')")
        super().tearDown()

    def test_the_list_summarises_each_period(self):
        self.open_settings()
        rows = self.page.eval_on_selector_all("#tp-tbody tr", "rs => rs.map(r => [...r.children].map(c => c.innerText.trim().replace(/\\s+/g, ' ')))")
        by = {r[0]: r for r in rows}
        office = by["Office hours (Copenhagen)"]
        self.assertEqual(office[1], "Europe/Copenhagen")
        self.assertIn("Mon–Fri 08:30–17:00", office[2])
        self.assertIn("3 holidays", office[2])
        self.assertIn("Sun 02:00–05:00", by["Sunday change window"][2])
        self.assertIn("Mon 22:00–24:00", by["Night shift"][2])

    def test_the_selects_of_the_forms_list_them_and_keep_a_period_that_is_gone(self):
        self.open_settings()
        opts = self.page.eval_on_selector_all("#qh-period option", "os => os.map(o => o.textContent.trim())")
        self.assertEqual(opts[0], "Use the times below")
        self.assertIn("Night shift", opts)
        self.page.evaluate("() => setPeriodSelect('qh-period', 'tp-deadbeef')")
        self.assertEqual(self.page.eval_on_selector("#qh-period", "s => s.selectedOptions[0].textContent.trim()"), "Removed time period")

    def test_a_period_is_added_and_used_by_quiet_hours(self):
        self.open_settings()
        self.addCleanup(lambda: self.page.evaluate("""async () => {
            const c = await api('GET', '/config');
            await api('POST', '/config', {quiet_hours: {enabled: true, start: '22:00', end: '07:00', min_severity: 'high', period: ''},
                                         time_periods: (c.time_periods || []).filter(p => p.name !== 'zz e2e period')});
        }"""))
        self.page.click('[data-action="openTimePeriodEdit"]')
        self.page.wait_for_selector("#tp-name", state="visible", timeout=30000)
        self.page.fill("#tp-name", "zz e2e period")
        self.page.fill("#tp-tz", "Europe/Berlin")
        self.page.click('#tp-days .tp-day[data-day="0"] [data-action-btn="_tpAddRangeBtn"]')
        self.page.click('#time-period-modal [data-action="saveTimePeriod"]')
        self.page.wait_for_function("() => !document.getElementById('time-period-modal').classList.contains('active')", timeout=30000)
        mine = [p for p in self.config()["time_periods"] if p["name"] == "zz e2e period"]
        self.assertEqual(len(mine), 1)
        self.assertEqual((mine[0]["tz"], mine[0]["weekly"]), ("Europe/Berlin", {"0": [[540, 1020]]}))
        self.page.wait_for_function("() => [...document.querySelectorAll('#qh-period option')].some(o => o.textContent.trim() === 'zz e2e period')", timeout=30000)
        self.page.select_option("#qh-period", label="zz e2e period")
        self.page.click('[data-action="saveQuietHours"]')
        self.page.wait_for_timeout(1500)
        self.assertEqual(self.config()["quiet_hours"]["period"], mine[0]["id"])

    def test_a_read_that_was_asked_for_earlier_and_answers_late_does_not_put_the_old_list_back(self):
        """The settings page, the ticket hours and the editor after a save each read the settings with a request of their own and fill
        the period lists from the answer. The answer to the earlier request can arrive after the later one's, and used to replace the
        list with the old one, which took the period that had just been saved out of every form."""
        self.open_settings()
        self.addCleanup(lambda: self.page.evaluate("() => _tpReload()"))
        names = self.page.evaluate("""async () => {
            const was = (await api('GET', '/config')).time_periods;
            const added = {id: 'tp-e2e00001', name: 'zz late answer', tz: 'UTC', tz_offset_min: null, weekly: {'0': [[540, 1020]]}, holidays: []};
            const early = _tpTicket();                 // a read is asked for ...
            const later = _tpTicket();                 // ... and then another one, which sees the period saved in between
            await _tpApply({time_periods: [...was, added]}, null, later);
            await _tpApply({time_periods: was}, null, early);          // the earlier one answers last
            return {
              select: [...document.querySelectorAll('#qh-period option')].map(o => o.textContent.trim()),
              table: [...document.querySelectorAll('#tp-tbody tr td:first-child')].map(c => c.textContent.trim()),
              forms: _tpListForForms.map(p => p.name),
            };
        }""")
        self.assertIn("zz late answer", names["select"])
        self.assertIn("zz late answer", names["table"])
        self.assertIn("zz late answer", names["forms"])

    def test_a_period_in_use_can_not_be_deleted_and_the_page_says_by_what(self):
        self.open_settings()
        r = self.page.evaluate("""async () => {
            const c = await api('GET', '/config');
            return await api('POST', '/config', {time_periods: (c.time_periods || []).filter(p => p.name !== 'Sunday change window')});
        }""")
        self.assertIn("maintenance window", r.get("error", ""))
        self.assertEqual(len([p for p in self.config()["time_periods"] if p["name"] == "Sunday change window"]), 1)

    def test_the_maintenance_form_can_follow_a_period(self):
        self.page.evaluate("() => showPage('maintenance')")
        self.page.evaluate("() => openNewMaintModal()")
        self.page.wait_for_selector("#maint-type", state="visible", timeout=30000)
        self.page.select_option("#maint-type", "period")
        self.assertTrue(self.page.is_visible("#maint-period-row"))
        self.assertFalse(self.page.is_visible("#maint-oneshot-row"))
        self.page.wait_for_function("() => document.querySelectorAll('#maint-period option').length > 2", timeout=30000)
        self.page.evaluate("closeModal('new-maint-modal')")

    def test_the_list_of_windows_names_the_period(self):
        self.page.evaluate("() => showPage('maintenance')")
        self.page.wait_for_function("() => document.body.innerText.includes('follows the Sunday change window')", timeout=60000)
        row = self.page.locator("tr", has_text="follows the Sunday change window").first.inner_text()
        self.assertIn("Sunday change window", row)


if __name__ == "__main__":
    unittest.main()
