#!/usr/bin/env python3
"""8.0.0: the name and accent colour of a tenant can be set from the page, in a browser on the demo seed.

`GET` and `PUT /api/tenants/<id>/branding` have existed since 6.1.1 (a platform superadmin may brand any tenant, a tenant's own administrator may brand theirs) and nothing in the page called them.
The Tenants list now has a **Branding** button on each row but the built-in one, and a tenant's own administrator has a card under the installation's Branding in Settings → General. Both open one
dialog. This file holds what a person sees and what the server holds afterwards: the dialog opens filled from what is stored, a save changes that tenant and no other, a blank name clears it, the
field stops at the 40 characters the server keeps, a refused save says why and keeps the dialog open, a tenant administrator sees the card and not the list, cannot reach another tenant through the
page's own session, and sees the saved name in the shell at once; and the words are translated.

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


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("the tenant store is backend-agnostic: measured once, under the default backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-tenant-branding-e2e-")
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


def _api(page, method, path, body=None):
    # a GET must not carry a body: api() hands a null to fetch as the text "null"
    return page.evaluate("async ([m, p, b]) => (b === null ? await api(m, p) : await api(m, p, b))", [method, path, body])


def open_settings(page, control):
    """Settings, on the pane that holds `control`, opened the way a person opens it: the tab is pressed and the pane's own loaders run."""
    page.evaluate("() => { showPage('settings'); }")
    page.wait_for_function("(id) => !!document.getElementById(id)", arg=control, timeout=30000)
    pane = page.evaluate("(id) => document.getElementById(id).closest('.settings-pane').id.replace('settings-pane-', '')", control)
    page.click("#settings-tab-btn-" + pane)
    page.wait_for_timeout(1500)


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestASuperadminBrandsATenant(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ctx, cls.page, cls.errors = _login(_STATE["browser"], "alice")  # the seeder's operator account; the default tenant's admin is the superadmin
        cls.acme = _api(cls.page, "POST", "/tenants", {"name": "Acme Ops"})["id"]
        cls.globex = _api(cls.page, "POST", "/tenants", {"name": "Globex"})["id"]

    @classmethod
    def tearDownClass(cls):
        cls.ctx.close()

    def setUp(self):
        _api(self.page, "PUT", f"/tenants/{self.acme}/branding", {"name": "Acme Ops", "accent": "violet"})
        _api(self.page, "PUT", f"/tenants/{self.globex}/branding", {"name": "", "accent": ""})
        self.page.reload()
        self.page.wait_for_selector("#app", state="visible", timeout=90000)
        self.page.wait_for_timeout(2500)

    def stored(self, tid):
        r = _api(self.page, "GET", f"/tenants/{tid}/branding")
        return (r["name"], r["accent"])

    def open_list(self):
        open_settings(self.page, "tenants-list")
        self.page.wait_for_selector("#tenants-list .sb-controls", timeout=20000)

    def row(self, tid):
        return self.page.locator(f'#tenants-list [data-action="openTenantBranding"][data-arg="{tid}"]')

    def open_dialog(self, tid):
        self.open_list()
        self.row(tid).click()
        self.page.wait_for_selector("#tenant-branding-modal.active", timeout=20000)

    def test_every_row_but_the_built_in_one_has_a_branding_button(self):
        self.open_list()
        tenants = _api(self.page, "GET", "/tenants")["tenants"]
        self.assertGreaterEqual(len(tenants), 5, "the demo's own tenants and the two made here")
        rows = self.page.locator("#tenants-list .sb-controls")
        self.assertEqual(rows.count(), len(tenants))
        self.assertEqual(self.page.locator('#tenants-list [data-action="openTenantBranding"]').count(), len([t for t in tenants if not t["builtin"]]))
        builtin = rows.filter(has_text="built-in")
        self.assertEqual(builtin.count(), 1)
        self.assertEqual(builtin.locator('[data-action="openTenantBranding"]').count(), 0)
        # each button names its own tenant
        ids = self.page.eval_on_selector_all('#tenants-list [data-action="openTenantBranding"]', "els => els.map(e => e.dataset.arg)")
        self.assertEqual(sorted(ids), sorted(t["id"] for t in tenants if not t["builtin"]))

    def test_the_dialog_opens_filled_from_what_is_stored(self):
        self.open_dialog(self.acme)
        self.assertEqual(self.page.input_value("#tenant-branding-name"), "Acme Ops")
        self.assertEqual(self.page.input_value("#tenant-branding-accent"), "violet")
        who = self.page.inner_text("#tenant-branding-who")
        self.assertIn("Acme Ops", who)
        self.assertIn(self.acme, who)

    def test_a_save_changes_that_tenant_and_no_other(self):
        self.open_dialog(self.acme)
        self.page.fill("#tenant-branding-name", "Acme Network Ops")
        self.page.select_option("#tenant-branding-accent", "emerald")
        with self.page.expect_response(lambda r: r.request.method == "PUT" and r.url.endswith(f"/tenants/{self.acme}/branding"), timeout=20000) as info:
            self.page.click('#tenant-branding-modal [data-action="saveTenantBranding"]')
        self.assertEqual(info.value.status, 200, info.value.text()[:200])
        self.assertEqual(self.stored(self.acme), ("Acme Network Ops", "emerald"))
        self.assertEqual(self.stored(self.globex), ("", ""), "no other tenant moved")
        self.page.wait_for_function("() => !document.getElementById('tenant-branding-modal').classList.contains('active')", timeout=10000)

    def test_a_blank_name_clears_it(self):
        self.open_dialog(self.acme)
        self.page.fill("#tenant-branding-name", "   ")
        self.page.select_option("#tenant-branding-accent", "")
        with self.page.expect_response(lambda r: r.request.method == "PUT" and r.url.endswith("/branding"), timeout=20000) as info:
            self.page.click('#tenant-branding-modal [data-action="saveTenantBranding"]')
        self.assertEqual(info.value.request.post_data_json, {"name": "", "accent": ""}, "the name is trimmed and both fields are always sent")
        self.assertEqual(self.stored(self.acme), ("", ""))

    def test_the_name_field_stops_at_the_forty_characters_the_server_keeps(self):
        self.open_dialog(self.acme)
        self.assertEqual(self.page.get_attribute("#tenant-branding-name", "maxlength"), "40")
        self.page.fill("#tenant-branding-name", "x" * 60)
        self.assertEqual(len(self.page.input_value("#tenant-branding-name")), 40)

    def test_cancel_changes_nothing(self):
        self.open_dialog(self.acme)
        self.page.fill("#tenant-branding-name", "Not saved")
        self.page.click('#tenant-branding-modal [data-action="closeModal"]')
        self.page.wait_for_function("() => !document.getElementById('tenant-branding-modal').classList.contains('active')", timeout=10000)
        self.assertEqual(self.stored(self.acme), ("Acme Ops", "violet"))

    def test_a_refused_save_says_why_and_keeps_the_dialog_open(self):
        self.open_dialog(self.acme)
        reason = "you may only manage your own tenant's branding"
        self.page.route("**/api/tenants/*/branding", lambda route: route.fulfill(status=403, content_type="application/json", body=json.dumps({"error": reason}))
                        if route.request.method == "PUT" else route.continue_())
        self.page.fill("#tenant-branding-name", "Refused")
        self.page.click('#tenant-branding-modal [data-action="saveTenantBranding"]')
        self.page.wait_for_function("(t) => document.body.innerText.includes(t)", arg=reason, timeout=15000)
        self.assertTrue(self.page.evaluate("() => document.getElementById('tenant-branding-modal').classList.contains('active')"), "the dialog stays for another try")
        self.page.unroute_all(behavior="ignoreErrors")
        self.assertEqual(self.stored(self.acme), ("Acme Ops", "violet"))

    def test_a_superadmin_does_not_get_the_card_for_a_tenant_s_own_administrator(self):
        open_settings(self.page, "tenant-own-branding-btn")
        # the list is loaded when the section is no longer hidden: only then is the card's answer known
        self.page.wait_for_function("() => !document.getElementById('tenants-section').classList.contains('hidden')", timeout=20000)
        self.assertTrue(self.page.evaluate("() => document.getElementById('tenant-own-branding').classList.contains('hidden')"))

    def test_a_tenant_list_that_does_not_load_does_not_make_a_superadmin_a_tenant_administrator(self):
        self.page.route("**/api/tenants", lambda route: route.abort() if route.request.method == "GET" else route.continue_())
        open_settings(self.page, "tenant-own-branding-btn")
        self.page.wait_for_timeout(1500)
        self.assertTrue(self.page.evaluate("() => document.getElementById('tenant-own-branding').classList.contains('hidden')"), "the card is for a tenant's own administrator")
        self.page.unroute_all(behavior="ignoreErrors")

    def test_the_title_and_the_sentence_are_translated_in_all_six_languages(self):
        self.open_dialog(self.acme)
        self.page.evaluate("async () => { await _ensureI18n(); }")
        pick = "() => [document.getElementById('tenant-branding-title').textContent.trim(), document.querySelector('#tenant-branding-modal .modal-subtitle').textContent.trim()]"
        english = self.page.evaluate(pick)
        bad = []
        try:
            for lang in LANGS:
                self.page.evaluate("(l) => RPi18n.setLang(l, false)", lang)
                self.page.wait_for_timeout(300)
                now = self.page.evaluate(pick)
                title_same = now[0] == english[0] and lang != "de"   # German keeps the loan word "Branding" as the title
                if title_same or now[1] == english[1]:
                    bad.append((lang, now))
        finally:
            self.page.evaluate("() => RPi18n.setLang('en', false)")
        self.assertEqual(bad, [])

    def test_nothing_in_the_page_broke_on_the_way(self):
        self.open_dialog(self.acme)
        self.assertEqual([e for e in self.errors if "Failed to load resource" not in e], [])


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestATenantAdministratorBrandsTheirOwnTenant(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ctx_a, cls.page_a, _ = _login(_STATE["browser"], "alice")
        cls.own = _api(cls.page_a, "POST", "/tenants", {"name": "Initech"})["id"]
        cls.other = _api(cls.page_a, "POST", "/tenants", {"name": "Hooli"})["id"]
        users = read("users.json")
        users["bob"] = dict(users["alice"], tenant_id=cls.own)  # a tenant's administrator: alice's login, in another tenant
        write("users.json", users)
        cls.ctx, cls.page, cls.errors = _login(_STATE["browser"], "bob")
        cls.page.set_default_timeout(20000)

    @classmethod
    def tearDownClass(cls):
        cls.ctx.close()
        cls.ctx_a.close()

    def setUp(self):
        _api(self.page_a, "PUT", f"/tenants/{self.own}/branding", {"name": "", "accent": ""})
        _api(self.page_a, "PUT", f"/tenants/{self.other}/branding", {"name": "Hooli Corp", "accent": "rose"})
        self.page.reload()
        self.page.wait_for_selector("#app", state="visible", timeout=90000)
        self.page.wait_for_timeout(2500)

    def test_the_card_is_there_and_the_tenant_list_is_not(self):
        open_settings(self.page, "tenant-own-branding-btn")
        self.page.wait_for_selector("#tenant-own-branding-btn", state="visible", timeout=20000)
        self.assertTrue(self.page.evaluate("() => document.getElementById('tenants-section').classList.contains('hidden')"))
        self.assertEqual(self.page.get_attribute("#tenant-own-branding-btn", "data-arg"), self.own)

    def test_a_save_brands_their_tenant_only_and_the_shell_shows_it_at_once(self):
        open_settings(self.page, "tenant-own-branding-btn")
        self.page.click("#tenant-own-branding-btn")
        self.page.wait_for_selector("#tenant-branding-modal.active", timeout=20000)
        self.assertIn(self.own, self.page.inner_text("#tenant-branding-who"))
        self.page.fill("#tenant-branding-name", "Initech Ops")
        self.page.select_option("#tenant-branding-accent", "amber")
        with self.page.expect_response(lambda r: r.request.method == "PUT" and r.url.endswith(f"/tenants/{self.own}/branding"), timeout=20000) as info:
            self.page.click('#tenant-branding-modal [data-action="saveTenantBranding"]')
        self.assertEqual(info.value.status, 200, info.value.text()[:200])
        self.page.wait_for_function("() => document.querySelector('.logo-text').textContent.trim() === 'Initech Ops'", timeout=20000)
        stored = _api(self.page_a, "GET", f"/tenants/{self.own}/branding")
        other = _api(self.page_a, "GET", f"/tenants/{self.other}/branding")
        self.assertEqual((stored["name"], stored["accent"]), ("Initech Ops", "amber"))
        self.assertEqual((other["name"], other["accent"]), ("Hooli Corp", "rose"), "the other tenant did not move")

    def test_a_viewer_in_the_same_tenant_is_not_offered_the_card(self):
        users = read("users.json")
        users["vic"] = dict(users["alice"], role="viewer", tenant_id=self.own)
        write("users.json", users)
        ctx, page, _ = _login(_STATE["browser"], "vic")
        try:
            open_settings(page, "tenant-own-branding-btn")   # a viewer has no Settings entry, but the page does not refuse the call: what it draws is what is measured
            page.wait_for_timeout(1500)
            self.assertTrue(page.evaluate("() => document.getElementById('tenant-own-branding').classList.contains('hidden')"), "a viewer cannot brand the tenant")
        finally:
            ctx.close()

    def test_the_session_of_a_tenant_administrator_cannot_brand_another_tenant(self):
        r = _api(self.page, "PUT", f"/tenants/{self.other}/branding", {"name": "Hijacked", "accent": ""})
        self.assertIn("own tenant", str(r.get("error")), r)
        self.assertEqual(_api(self.page_a, "GET", f"/tenants/{self.other}/branding")["name"], "Hooli Corp")


if __name__ == "__main__":
    unittest.main()
