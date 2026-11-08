#!/usr/bin/env python3
"""8.0.0: the shared logins a host inherits, in the host's CMDB dialog on the demo seed in a browser.

A login stored once for a site, a group or a tag was listed on the CMDB page and nowhere on the hosts it applies to; GET /api/cmdb/<id>/inherited-credentials answered that and
no page asked. The Credentials tab of a host's dialog now lists them: the ones whose scope the host is in and no others, as text and never markup, with Reveal that is switched
off while the vault is locked and names the right credential when it is not, nothing at all for a host none applies to, and no answer for the host that was open before painted
over the one open now. Every word has a translation and nothing in the page broke.

The demo has no scoped credentials, so the test writes four (metadata only: the server lists them without the vault). vw01 is in the group services and has the tag secrets; jf01 is in the group media and none applies to it.
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
except ImportError:                                     # pragma: no cover
    sync_playwright = None

_STATE = {}
LANGS = ("zh", "hi", "es", "ar", "de", "fr")


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("the lists are backend-agnostic: measured once, under the default backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-inherited-creds-e2e-")
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


def _creds():
    t = int(time.time()) - 86400
    base = {"created_by": "alice", "created_at": t, "ct": "00", "nonce": "00"}
    return {"creds": [
        dict(base, id="sc_aaaa", scope_type="group", scope_value="services", label="Services admin", username="svc-admin", note="rotated in May"),
        dict(base, id="sc_bbbb", scope_type="tag", scope_value="secrets", label='Vault <b>login</b>', username=""),
        dict(base, id="sc_cccc", scope_type="site", scope_value="nowhere", label="Elsewhere", username="x"),
        dict(base, id="sc_dddd", scope_type="group", scope_value="infra", label="Infra admin", username="y"),
    ]}


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheCmdbDialogListsTheSharedLoginsOfTheHost(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        ctx = _STATE["browser"].new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
        ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")
        cls.ctx, cls.page, cls.errors, cls.reveals = ctx, ctx.new_page(), [], []
        cls.page.on("pageerror", lambda e: cls.errors.append(str(e)))
        cls.page.on("request", lambda r: cls.reveals.append(r.url.split("/api", 1)[-1]) if r.method == "POST" and "/scoped-credentials/" in r.url and r.url.endswith("/reveal") else None)
        cls.page.goto(_STATE["base"] + "/index.html")
        cls.page.fill("#login-user", "alice")                # the seeder builds its own operator accounts: there is no 'admin'
        cls.page.fill("#login-pass", "demo")
        cls.page.click('#login-form button[type="submit"]')
        cls.page.wait_for_selector("#app", state="visible", timeout=90000)
        cls.page.wait_for_timeout(3500)
        cls.page.evaluate("() => showPage('cmdb')")
        cls.page.wait_for_function("() => typeof cmdbOpenAsset === 'function'", timeout=60000)
        cls.page.wait_for_timeout(1500)

    @classmethod
    def tearDownClass(cls):
        try:
            _path("scoped_credentials.json").unlink()
        except FileNotFoundError:
            pass
        finally:
            cls.ctx.close()

    def setUp(self):
        write("scoped_credentials.json", _creds())
        del self.reveals[:]

    def tearDown(self):
        self.page.evaluate("""() => {
          document.querySelectorAll('.modal-overlay.active').forEach(m => closeModal(m.id));
          _cmdbVaultKey = null;
        }""")
        for route in getattr(self, "_routes", []):
            try:
                route.continue_()
            except Exception:
                pass
        self.page.unroute_all()

    def open_creds(self, dev_id):
        self.page.evaluate("async (id) => { await cmdbOpenAsset(id); cmdbSwitchTab('creds'); }", dev_id)
        self.page.wait_for_function("() => getComputedStyle(document.getElementById('cmdb-tab-creds')).display !== 'none'", timeout=30000)

    def wait_rows(self, n):
        self.page.wait_for_function("(n) => { const w = document.getElementById('cmdb-inherited-wrap'); return w && !w.hidden && document.querySelectorAll('#cmdb-inherited-list > div').length >= n; }", arg=n, timeout=30000)

    def rows(self):
        return self.page.evaluate("""() => [...document.querySelectorAll('#cmdb-inherited-list > div')].map(r => ({
          text: r.textContent.replace(/\\s+/g, ' ').trim(),
          reveal: r.querySelector('button') ? {arg: r.querySelector('button').getAttribute('data-arg'), disabled: r.querySelector('button').disabled} : null}))""")

    def test_a_host_lists_the_logins_of_its_group_and_its_tag_and_no_others(self):
        self.open_creds("vw01")
        self.wait_rows(2)
        rows = self.rows()
        self.assertEqual(len(rows), 2, rows)
        by_arg = {r["reveal"]["arg"]: r for r in rows}
        self.assertEqual(sorted(by_arg), ["sc_aaaa", "sc_bbbb"], "the site nowhere and the group infra are not vw01's")
        self.assertIn("Services admin", by_arg["sc_aaaa"]["text"])
        self.assertIn("group", by_arg["sc_aaaa"]["text"])
        self.assertIn("services", by_arg["sc_aaaa"]["text"])
        self.assertIn("svc-admin", by_arg["sc_aaaa"]["text"])
        self.assertIn("rotated in May", by_arg["sc_aaaa"]["text"])
        self.assertIn("tag", by_arg["sc_bbbb"]["text"])
        self.assertIn("secrets", by_arg["sc_bbbb"]["text"])

    def test_a_label_is_text_and_never_markup(self):
        self.open_creds("vw01")
        self.wait_rows(2)
        self.assertEqual(self.page.eval_on_selector_all("#cmdb-inherited-list b", "els => els.length"), 0)
        self.assertTrue(any("Vault <b>login</b>" in r["text"] for r in self.rows()))

    def test_a_host_none_applies_to_has_no_list(self):
        self.open_creds("jf01")
        self.page.wait_for_timeout(1500)
        self.assertTrue(self.page.eval_on_selector("#cmdb-inherited-wrap", "w => w.hidden"))
        self.assertEqual(self.page.eval_on_selector("#cmdb-inherited-list", "b => b.children.length"), 0)

    def test_reveal_is_switched_off_while_the_vault_is_locked(self):
        self.open_creds("vw01")
        self.wait_rows(2)
        self.assertTrue(all(r["reveal"]["disabled"] for r in self.rows()), "the vault key is not held in a fresh session")

    def test_reveal_names_the_right_login_when_the_vault_is_open(self):
        self.open_creds("vw01")
        self.wait_rows(2)
        self.page.evaluate("() => { _cmdbVaultKey = 'a'.repeat(64); cmdbLoadCreds(_cmdbCurrent.device_id); }")
        self.page.wait_for_function("() => [...document.querySelectorAll('#cmdb-inherited-list button')].every(b => !b.disabled) && document.querySelectorAll('#cmdb-inherited-list button').length === 2", timeout=20000)
        self.page.click('#cmdb-inherited-list button[data-arg="sc_bbbb"]')
        self.page.wait_for_timeout(1500)
        self.assertEqual(self.reveals, ["/scoped-credentials/sc_bbbb/reveal"])

    def test_an_answer_for_the_host_that_was_open_before_does_not_paint_over_this_one(self):
        self._routes = []
        self.page.route("**/api/cmdb/vw01/inherited-credentials", lambda route: self._routes.append(route))
        self.page.evaluate("(id) => { cmdbOpenAsset(id).then(() => cmdbSwitchTab('creds')); }", "vw01")
        self.page.wait_for_function("() => document.getElementById('cmdb-asset-title').textContent.indexOf('vaultwarden') >= 0", timeout=30000)
        deadline = time.time() + 20
        while time.time() < deadline and not self._routes:
            self.page.wait_for_timeout(200)
        self.assertTrue(self._routes, "the request for vw01 is held")
        self.open_creds("jf01")
        self.page.wait_for_timeout(800)
        for route in self._routes:
            route.continue_()
        self._routes = []
        self.page.wait_for_timeout(1200)
        self.assertTrue(self.page.eval_on_selector("#cmdb-inherited-wrap", "w => w.hidden"), "jf01 has none and vw01's late answer is dropped")
        self.assertEqual(self.page.eval_on_selector("#cmdb-inherited-list", "b => b.children.length"), 0)

    def test_the_words_are_translated_in_all_six_languages(self):
        self.open_creds("vw01")
        self.wait_rows(2)
        self.page.evaluate("async () => { await _ensureI18n(); }")      # the dictionary is a lazy module: an English page has not fetched it
        grab = """() => ({
          title: document.querySelector('#cmdb-inherited-wrap .section-title').textContent,
          hint: document.querySelector('#cmdb-inherited-wrap > .hint').textContent})"""
        english = self.page.evaluate(grab)
        self.assertEqual(english["title"], "Shared logins that apply to this host")
        bad = []
        try:
            for lang in LANGS:
                self.page.evaluate("(l) => RPi18n.setLang(l, false)", lang)
                self.page.wait_for_timeout(300)
                now = self.page.evaluate(grab)
                bad += [(lang, k) for k in english if now[k] == english[k]]
        finally:
            self.page.evaluate("() => RPi18n.setLang('en', false)")
        self.assertEqual(bad, [])

    def test_nothing_in_the_page_broke_on_the_way(self):
        self.open_creds("vw01")
        self.wait_rows(2)
        self.open_creds("jf01")
        self.page.wait_for_timeout(800)
        self.assertEqual([e for e in self.errors if "Failed to load resource" not in e], [])


if __name__ == "__main__":
    unittest.main()
