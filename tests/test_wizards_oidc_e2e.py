#!/usr/bin/env python3
"""8.0.0: the single sign-on guide ("Set up single sign-on"), in a browser on the demo seed, against a fake identity provider on the loopback.

The OIDC card in Settings, Integrations is seven boxes and a Test discovery button that saves the form first. The guide asks in steps: which
provider (a note on what to create there, and the values to copy into it), the issuer and the client, who is an administrator, and a check that
this server can read the provider's discovery document. The server checks an issuer that is not saved, so nothing is stored before the last step.

Held: what RemotePower really needs from a provider is said (the client secret goes in the request body, the groups come from the ID token, an
account is made as a viewer for everyone the provider lets in), the checks refuse what the server would refuse and in its words, the test names
what the discovery document does not offer, a saved secret is kept only for the same issuer and client, a group map that SAML shares survives, the
card in Settings shows what was saved so that its own Save does not undo it, and every word has a translation. The stored configuration is read
from the file, and the fake provider records what it was asked.

Self-skips without playwright / Chromium / gunicorn, and runs under the default storage backend only.
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
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
KEYS = ("oidc_enabled", "oidc_issuer", "oidc_client_id", "oidc_client_secret", "oidc_scopes", "oidc_admin_group", "sso_group_roles")
PROVIDERS = ["authentik", "authelia", "keycloak", "pocketid", "zitadel", "other"]
BRANDS = {"Authentik", "Authelia", "Keycloak", "Pocket ID", "Zitadel"}
# (English text, language) pairs where the right translation is the same word
SAME = {("Roles", "es"), ("Roles", "fr"), ("Test", "fr"), ("Test", "de"), ("Service", "fr"), ("Issuer URL", "de"), ("Client ID", "de"), ("Client ID", "fr"), ("Documentation", "fr")}


class _Idp(BaseHTTPRequestHandler):
    """A provider that serves one discovery document and remembers what it was asked."""
    hits = []
    doc = {}

    def do_GET(self):
        type(self).hits.append(self.path)
        if self.path.endswith("/.well-known/openid-configuration"):
            body = json.dumps(type(self).doc).encode()
            self.send_response(200)
        else:
            body = b"{}"
            self.send_response(404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def document(base, **extra):
    doc = {"issuer": base, "authorization_endpoint": base + "/authorize", "token_endpoint": base + "/token", "userinfo_endpoint": base + "/userinfo",
           "jwks_uri": base + "/jwks", "scopes_supported": ["openid", "profile", "email", "groups"], "grant_types_supported": ["authorization_code"],
           "response_types_supported": ["code"], "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"]}
    doc.update(extra)
    return doc


def setUpModule():
    if sync_playwright is None:
        browser_required.skip_or_fail("playwright not installed")
    if os.environ.get("RP_STORAGE_BACKEND") == "sqlite":
        raise unittest.SkipTest("the wizard is backend-agnostic: measured once, under the default backend")
    seeder = _ROOT / "packaging" / "seed-demo-data.py"
    if not seeder.is_file():
        raise unittest.SkipTest("demo seeder not in this tree")
    data_dir = tempfile.mkdtemp(prefix="rp-oidc-wizard-")
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


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _config_path():
    return Path(_STATE["data_dir"]) / "config.json"


def read_config():
    return json.loads(_config_path().read_text())


def write_config(changes, remove=()):
    """The stored configuration, edited on disk: the API cannot clear a client secret, and a test has to start without one."""
    cfg = read_config()
    cfg.update(changes)
    for k in remove:
        cfg.pop(k, None)
    tmp = _config_path().with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg))
    os.replace(tmp, _config_path())


@unittest.skipUnless(_GATE, SKIP_REASON)
class TestTheSingleSignOnGuide(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        ctx = _STATE["browser"].new_context(viewport={"width": 1440, "height": 900}, service_workers="block")
        ctx.add_init_script("try { localStorage.setItem('rp_tour_done', '1'); localStorage.setItem('rp_autohide_sidebar', '0'); "
                            "localStorage.setItem('rp_pagetabs', 'stacked'); } catch (e) {}")
        # This stack's front handler drops the Host header, so the server builds the callback address from its own port (and https, unless a proxy
        # says otherwise): it never equals the address of the page. The tests below do not rely on a match; one forces and shows a mismatch.
        cls.ctx, cls.page, cls.errors = ctx, ctx.new_page(), []
        cls.page.on("pageerror", lambda e: cls.errors.append(str(e)))
        cls.page.goto(_STATE["base"] + "/index.html")
        cls.page.fill("#login-user", "alice")                # the seeder builds its own operator accounts: there is no 'admin'
        cls.page.fill("#login-pass", "demo")
        cls.page.click('#login-form button[type="submit"]')
        cls.page.wait_for_selector("#app", state="visible", timeout=90000)
        cls.page.wait_for_timeout(3500)
        cfg = read_config()
        cls.original = {k: cfg[k] for k in KEYS if k in cfg}
        cls.idp = HTTPServer(("127.0.0.1", 0), _Idp)
        threading.Thread(target=cls.idp.serve_forever, daemon=True).start()
        cls.issuer = "http://127.0.0.1:%d/application/o/rp/" % cls.idp.server_address[1]

    @classmethod
    def tearDownClass(cls):
        try:
            write_config(cls.original, remove=[k for k in KEYS if k not in cls.original])
            cls.idp.shutdown()
            cls.idp.server_close()
        finally:
            cls.ctx.close()

    @classmethod
    def api(cls, method, path, body=None):
        return cls.page.evaluate("async ([m, p, b]) => b === null ? await api(m, p) : await api(m, p, b)", [method, path, body])

    def stored(self):
        cfg = read_config()
        return {k: cfg.get(k) for k in KEYS}

    def setUp(self):
        """No single sign-on set up: the starting point of every test, whatever the seed holds."""
        write_config({"oidc_enabled": False, "oidc_issuer": "", "oidc_client_id": "", "oidc_scopes": "", "oidc_admin_group": "", "sso_group_roles": {}},
                     remove=["oidc_client_secret"])
        _Idp.hits.clear()
        _Idp.doc = document(self.base_url())
        self.close_guide()
        self.start = self.stored()

    def tearDown(self):
        self.close_guide()

    def base_url(self):
        return self.issuer.rstrip("/")

    # ── steering ────────────────────────────────────────────────────────────────────────────────────────────────────────────
    def close_guide(self):
        self.page.evaluate("() => { document.querySelectorAll('.modal-overlay.active').forEach(m => closeModal(m.id)); }")

    def open(self):
        self.page.evaluate("() => wizOpen('oidc')")
        self.page.wait_for_selector("#wizard-modal.active .wiz-choice", timeout=30000)

    def steps(self):
        return self.page.eval_on_selector_all("#wiz-steps .wiz-lbl", "els => els.map(e => e.textContent)")

    def pick(self, key):
        self.page.check('#wiz-body input[name="wiz-idp"][value="%s"]' % key)

    def next(self):
        self.page.click("#wiz-next")

    def message(self):
        return self.page.inner_text("#wiz-msg").strip()

    def fill(self, sel, value):
        self.page.fill(sel, value)

    def focused(self):
        return self.page.evaluate("() => document.activeElement.id")

    def to_register(self, key="authentik"):
        self.open()
        self.pick(key)
        self.next()
        self.page.wait_for_selector("#wiz-oidc-redirect")

    def to_connection(self, key="authentik"):
        self.to_register(key)
        self.next()
        self.page.wait_for_selector("#wiz-issuer")

    def connection(self, issuer=None, cid="remotepower", secret="s3cret-value", scopes=None):
        self.fill("#wiz-issuer", issuer if issuer is not None else self.issuer)
        self.fill("#wiz-cid", cid)
        self.fill("#wiz-secret", secret)
        if scopes is not None:
            self.fill("#wiz-scopes", scopes)

    def to_roles(self, key="authentik", **conn):
        self.to_connection(key)
        self.connection(**conn)
        self.next()
        self.page.wait_for_selector("#wiz-admin")

    def to_test(self, key="authentik", **conn):
        self.to_roles(key, **conn)
        self.next()
        self.page.wait_for_selector("#wiz-test")

    def run_test(self):
        self.page.click("#wiz-test")
        self.page.wait_for_selector("#wiz-result .wiz-state", timeout=30000)
        return self.page.inner_text("#wiz-result .wiz-state").strip()

    def result(self):
        return self.page.inner_text("#wiz-result")

    def finish(self):
        self.next()                                              # the Test step
        self.page.wait_for_selector("#wiz-body .wiz-list")
        self.next()                                              # Finish: Turn it on
        self.page.wait_for_selector("#wizard-modal", state="detached", timeout=20000)

    # ── the way in, the providers and what each needs ───────────────────────────────────────────────────────────────────────
    def test_the_button_is_on_the_oidc_card_and_opens_the_guide(self):
        self.page.evaluate("async () => { showPage('settings'); switchSettingsTab('integrations'); await loadIntegrationsTab(); }")
        sel = '[data-action="wizOpen"][data-arg="oidc"]'
        self.page.wait_for_selector(sel, state="visible")
        self.assertEqual(self.page.inner_text(sel).strip(), "Guide me")
        near = self.page.evaluate("(s) => document.querySelector(s).closest('.settings-section').querySelector('.section-title').textContent", sel)
        self.assertEqual(near.strip(), "OIDC / OpenID Connect")
        self.page.click(sel)
        self.page.wait_for_selector("#wizard-modal.active .wiz-choice", timeout=30000)
        self.assertEqual(self.page.inner_text("#wiz-title").strip(), "Set up single sign-on")

    def test_the_guide_lists_the_providers_and_none_is_chosen_when_nothing_is_set_up(self):
        self.open()
        self.assertEqual(self.steps(), ["Provider", "Register", "Connection", "Roles", "Test", "Finish"])
        shown = self.page.eval_on_selector_all('#wiz-body input[name="wiz-idp"]', "els => els.map(e => e.value)")
        self.assertEqual(shown, PROVIDERS)
        names = self.page.eval_on_selector_all("#wiz-body .wiz-choice-t", "els => els.map(e => e.textContent)")
        self.assertEqual(names, ["Authentik", "Authelia", "Keycloak", "Pocket ID", "Zitadel", "Another OpenID Connect provider"])
        self.assertEqual(self.page.eval_on_selector_all('#wiz-body input[name="wiz-idp"]:checked', "els => els.length"), 0)
        self.next()
        self.assertEqual(self.message(), "Choose a service")

    def test_the_register_step_gives_the_values_to_copy_and_a_note_that_says_what_this_provider_needs(self):
        origin = self.page.evaluate("() => location.origin")
        notes = {}
        key_phrases = {"authentik": "/application/o/<slug>/", "authelia": "client_secret_post", "keycloak": "Group Membership", "pocketid": "shown once",
                       "zitadel": "Post as the authentication method", "other": "/.well-known/openid-configuration"}
        for key in PROVIDERS:
            with self.subTest(key):
                self.close_guide()
                self.to_register(key)
                self.assertEqual(self.page.inner_text("#wiz-oidc-redirect").strip(), origin + "/api/auth/oidc/callback")
                self.assertEqual(self.page.inner_text("#wiz-oidc-scopes").strip(), "openid profile email groups")
                self.assertEqual(self.page.eval_on_selector_all('#wiz-body [data-action="wizCopy"]', "els => els.length"), 2)
                note = self.page.inner_text("#wiz-body .hint").strip()
                self.assertIn(key_phrases[key], note)
                notes[key] = note
                self.assertIn("Everyone the provider lets in gets a viewer account here.", self.page.inner_text("#wiz-body"))
                self.assertIn("confidential", self.page.inner_text("#wiz-body"))
        self.assertEqual(len(set(notes.values())), len(PROVIDERS), "each provider says its own thing")
        for key in ("authelia", "zitadel"):
            self.assertIn("request body", notes[key], "the client secret goes in the request body: " + key)

    def test_the_issuer_box_shows_what_an_issuer_of_this_provider_looks_like(self):
        want = {"authentik": "/application/o/", "keycloak": "/realms/", "zitadel": "zitadel.cloud", "authelia": "auth.example.com", "pocketid": "id.example.com"}
        for key, part in want.items():
            with self.subTest(key):
                self.close_guide()
                self.to_connection(key)
                self.assertIn(part, self.page.get_attribute("#wiz-issuer", "placeholder"))
                self.assertEqual(self.page.input_value("#wiz-scopes"), "openid profile email groups")
                self.assertEqual(self.page.get_attribute("#wiz-secret", "type"), "password")
                self.assertEqual(self.page.get_attribute("#wiz-secret", "autocomplete"), "new-password")

    # ── the checks ──────────────────────────────────────────────────────────────────────────────────────────────────────────
    def test_the_connection_is_checked_with_the_servers_own_rules(self):
        self.to_connection()
        self.next()
        self.assertEqual(self.message(), "Set the issuer first")
        self.assertEqual(self.focused(), "wiz-issuer")
        for bad in ("auth.example.com", "ftp://auth.example.com", "https://", "javascript:alert(1)"):
            self.fill("#wiz-issuer", bad)
            self.next()
            self.assertEqual(self.message(), "The issuer must start with http:// or https://", bad)
        self.fill("#wiz-issuer", "https://auth.example.com/application/o/rp/")
        self.next()
        self.assertEqual(self.message(), "Set the client ID first")
        self.assertEqual(self.focused(), "wiz-cid")
        self.fill("#wiz-cid", "remotepower")
        self.next()
        self.assertEqual(self.message(), "This field is needed")
        self.assertEqual(self.focused(), "wiz-secret")
        self.fill("#wiz-secret", "s")
        self.fill("#wiz-scopes", "profile email groups")
        self.next()
        self.assertEqual(self.message(), "The scopes must include openid")
        self.assertEqual(self.focused(), "wiz-scopes")
        self.fill("#wiz-scopes", "openid,profile email")
        self.next()
        self.page.wait_for_selector("#wiz-admin")

    def test_the_group_map_must_be_lines_of_group_equals_role(self):
        self.to_roles()
        for bad in ("sre", "sre=", "=admin", "ok=admin\nbroken"):
            self.fill("#wiz-map", bad)
            self.next()
            self.assertEqual(self.message(), "Each line needs group=role", bad)
            self.assertEqual(self.focused(), "wiz-map")
        self.fill("#wiz-map", "# comments and empty lines are fine\n\nsre=admin\nsec-ops = auditor\n")
        self.next()
        self.page.wait_for_selector("#wiz-test")

    def test_the_roles_step_says_where_the_groups_come_from_and_who_gets_what(self):
        self.to_roles()
        text = self.page.inner_text("#wiz-body")
        self.assertIn("RemotePower reads the groups from the ID token, from a claim named groups or roles.", text)
        self.assertIn("Everyone else gets viewer unless the map below says otherwise.", text)
        self.assertIn("The same map is used for SAML.", text)

    # ── the test reads the discovery document and saves nothing ─────────────────────────────────────────────────────────────
    def test_a_provider_that_answers_is_reachable_and_nothing_is_saved(self):
        self.to_test()
        self.assertEqual(self.run_test(), "Reachable")
        self.assertIn("The provider answered and its settings were read.", self.result())
        self.assertEqual(_Idp.hits, ["/application/o/rp/.well-known/openid-configuration"])
        for words in ("does not list these scopes", "does not list client_secret_post", "does not list the authorization code flow"):
            self.assertNotIn(words, self.result(), "a provider that lists what is needed gets no warning about it")
        self.assertEqual(self.stored(), self.start, "a test stores nothing")

    def test_a_reachable_provider_with_nothing_to_warn_about_is_green_and_one_with_a_warning_is_amber(self):
        self.to_test()
        got = self.page.evaluate("""() => {
          const paint = checks => { _wiz.st.verdict = { kind: 'ok', checks }; _wizOidcPaint(); const o = document.getElementById('wiz-result'); return [o.className, o.querySelectorAll('.hint').length]; };
          return [paint([]), paint([{ text: 'x' }])];
        }""")
        self.assertEqual(got[0], ["wiz-result c-green", 1])
        self.assertEqual(got[1], ["wiz-result c-amber", 2])

    def test_what_the_discovery_document_does_not_offer_is_named(self):
        cases = [
            ("scopes", {"scopes_supported": ["openid", "profile", "email"]}, "The provider does not list these scopes:", "groups"),
            ("secret in the body", {"token_endpoint_auth_methods_supported": ["client_secret_basic", "private_key_jwt"]}, "does not list client_secret_post", None),
            ("flow", {"grant_types_supported": ["implicit", "refresh_token"]}, "does not list the authorization code flow", None),
        ]
        for what, extra, words, mono in cases:
            with self.subTest(what):
                self.close_guide()
                _Idp.doc = document(self.base_url(), **extra)
                self.to_test()
                self.assertEqual(self.run_test(), "Reachable")
                self.assertIn(words, self.result())
                if mono:
                    self.assertEqual(self.page.inner_text("#wiz-result .ff-mono").strip(), mono)
                self.assertTrue(self.page.eval_on_selector("#wiz-result", "e => e.classList.contains('c-amber')"), "a warning is amber")

    def test_a_document_that_lists_nothing_gets_no_warning(self):
        doc = document(self.base_url())
        for k in ("scopes_supported", "grant_types_supported", "token_endpoint_auth_methods_supported"):
            del doc[k]
        _Idp.doc = doc
        self.to_test()
        self.assertEqual(self.run_test(), "Reachable")
        for words in ("does not list these scopes", "does not list client_secret_post", "does not list the authorization code flow"):
            self.assertNotIn(words, self.result(), "a list the provider does not give says nothing")

    def test_a_scope_the_person_added_is_checked_against_the_list(self):
        self.to_test(scopes="openid profile email groups offline_access")
        self.assertEqual(self.run_test(), "Reachable")
        self.assertEqual(self.page.inner_text("#wiz-result .ff-mono").strip(), "offline_access")

    def test_a_callback_address_the_server_sees_differently_is_shown(self):
        # the page and the server see the same host in this stack, so the check is driven with a document the server could have answered with
        got = self.page.evaluate("""async () => {
          await _loadJsModule('app-wizard.js');
          const st = { scopes: 'openid' };
          const mine = location.origin + '/api/auth/oidc/callback';
          return [_wizOidcChecks(st, { redirect_uri_needed: mine }), _wizOidcChecks(st, { redirect_uri_needed: 'https://other.example.com/api/auth/oidc/callback' })];
        }""")
        self.assertEqual(got[0], [])
        self.assertEqual(len(got[1]), 1)
        self.assertIn("The server sees the callback address differently", got[1][0]["text"])
        self.assertEqual(got[1][0]["mono"], "https://other.example.com/api/auth/oidc/callback")

    def test_when_the_server_builds_another_callback_address_than_the_page_shows_the_test_says_so(self):
        # here the server sees its own port and https (the front handler of the test stack drops the Host header), which is not the page's address
        self.to_test()
        self.assertEqual(self.run_test(), "Reachable")
        self.assertIn("The server sees the callback address differently from this page.", self.result())
        shown = self.page.inner_text("#wiz-result .ff-mono").strip()
        mine = self.page.evaluate("() => location.origin") + "/api/auth/oidc/callback"
        self.assertNotEqual(shown, mine)
        self.assertTrue(shown.endswith("/api/auth/oidc/callback"), shown)
        self.assertEqual(self.api("POST", "/auth/oidc/test", {"issuer": self.issuer})["redirect_uri_needed"], shown, "it is the address the server itself reports")
        self.assertTrue(self.page.eval_on_selector("#wiz-result", "e => e.classList.contains('c-amber')"))

    def test_an_issuer_nothing_answers_for_and_a_blocked_one_are_not_reachable_with_the_reason(self):
        for issuer in ("http://127.0.0.1:%d/x" % free_port(), "http://169.254.169.254/latest"):
            with self.subTest(issuer):
                self.close_guide()
                self.to_test(issuer=issuer)
                self.assertEqual(self.run_test(), "Not reachable")
                self.assertIn("Check the issuer, and that this server can reach it.", self.result())
                self.assertTrue(self.page.inner_text("#wiz-result .ff-mono").strip(), "the server's own words are shown")
                self.assertTrue(self.page.eval_on_selector("#wiz-result", "e => e.classList.contains('c-red')"))

    def test_a_change_after_the_test_drops_its_answer(self):
        changes = [
            ("the issuer", 2, lambda: self.fill("#wiz-issuer", self.issuer + "x")),
            ("the client ID", 2, lambda: self.fill("#wiz-cid", "another")),
            ("the secret", 2, lambda: self.fill("#wiz-secret", "another-secret")),
            ("the scopes", 2, lambda: self.fill("#wiz-scopes", "openid profile")),
        ]
        for what, back, change in changes:
            with self.subTest(what):
                self.close_guide()
                self.to_test()
                self.assertEqual(self.run_test(), "Reachable")
                for _ in range(back):
                    self.page.click("#wiz-back")
                change()
                self.next()
                self.page.wait_for_selector("#wiz-admin")
                self.next()
                self.page.wait_for_selector("#wiz-test")
                self.assertEqual(self.page.inner_text("#wiz-result").strip(), "", "the old answer is not shown after %s changed" % what)
                self.next()
                self.page.wait_for_selector("#wiz-body .wiz-list")
                self.assertIn("Not tested", self.page.inner_text("#wiz-body .wiz-list"), what)
                self.assertIn("It was not tested.", self.page.inner_text("#wiz-body"), what)

    # ── turning it on ───────────────────────────────────────────────────────────────────────────────────────────────────────
    def test_turning_it_on_saves_what_the_card_saves_and_the_card_shows_it(self):
        self.page.evaluate("async () => { showPage('settings'); switchSettingsTab('integrations'); await loadIntegrationsTab(); }")
        self.assertEqual(self.page.input_value("#oidc-issuer"), "")
        self.to_roles("keycloak", cid="remotepower", secret="s3cret-value-123")
        self.fill("#wiz-admin", "rp-admins")
        self.fill("#wiz-map", "sre=admin\nsec-ops=auditor")
        self.next()
        self.page.wait_for_selector("#wiz-test")
        self.assertEqual(self.run_test(), "Reachable")
        self.finish()
        saved = self.stored()
        self.assertTrue(saved["oidc_enabled"])
        self.assertEqual((saved["oidc_issuer"], saved["oidc_client_id"], saved["oidc_scopes"]), (self.issuer, "remotepower", "openid profile email groups"))
        self.assertEqual(saved["oidc_admin_group"], "rp-admins")
        self.assertEqual(saved["sso_group_roles"], {"sre": "admin", "sec-ops": "auditor"})
        self.assertTrue(saved["oidc_client_secret"], "the secret was saved")
        # the card shows it without a reload, and never the secret
        self.assertTrue(self.page.is_checked("#oidc-enabled"))
        self.assertEqual(self.page.input_value("#oidc-issuer"), self.issuer)
        self.assertEqual(self.page.input_value("#oidc-client-id"), "remotepower")
        self.assertEqual(self.page.input_value("#oidc-scopes"), "openid profile email groups")
        self.assertEqual(self.page.input_value("#oidc-admin-group"), "rp-admins")
        self.assertEqual(self.page.input_value("#oidc-client-secret"), "")
        self.assertEqual(self.page.input_value("#sso-group-roles"), "sre=admin\nsec-ops=auditor")
        cfg = self.api("GET", "/config")
        self.assertTrue(cfg["oidc_client_secret_set"])
        self.assertNotIn("s3cret-value-123", json.dumps(cfg), "the secret never comes back")
        self.assertIs(self.api("GET", "/public-info")["oidc_enabled"], True, "the sign-in page offers the SSO button")

    def test_a_later_save_of_the_card_keeps_what_the_guide_saved(self):
        self.page.evaluate("async () => { showPage('settings'); switchSettingsTab('integrations'); await loadIntegrationsTab(); }")
        self.to_test(cid="remotepower", secret="s3cret-value-123")
        self.finish()
        self.page.click('[data-action="saveOidcConfig"]')
        self.page.wait_for_timeout(1500)
        saved = self.stored()
        self.assertTrue(saved["oidc_enabled"], "the card did not switch it off again")
        self.assertEqual(saved["oidc_issuer"], self.issuer, "the card did not write its old, empty values over the guide's")
        self.assertEqual(saved["oidc_client_id"], "remotepower")

    def test_a_group_map_that_saml_shares_survives_when_the_guide_does_not_touch_it(self):
        write_config({"sso_group_roles": {"sre": "admin", "ops": "auditor"}})
        self.open()
        self.pick("other")
        self.next()
        self.next()
        self.connection()
        self.next()
        self.page.wait_for_selector("#wiz-admin")
        self.assertEqual(sorted(self.page.input_value("#wiz-map").split("\n")), ["ops=auditor", "sre=admin"])
        self.next()
        self.page.wait_for_selector("#wiz-test")
        self.finish()
        self.assertEqual(self.stored()["sso_group_roles"], {"sre": "admin", "ops": "auditor"})

    def test_an_earlier_setup_is_read_in_and_a_second_run_keeps_its_secret(self):
        self.api("POST", "/config", {"oidc_issuer": self.issuer, "oidc_client_id": "saved-id", "oidc_client_secret": "saved-secret", "oidc_scopes": "openid profile groups",
                                     "oidc_admin_group": "old-admins"})
        before = self.stored()
        self.open()
        self.assertIn("Single sign-on is already set up. This guide replaces those settings.", self.page.inner_text("#wiz-body"))
        self.assertEqual(self.page.eval_on_selector("#wiz-body input[name='wiz-idp']:checked", "e => e.value"), "authentik", "recognised from /application/o/ in the issuer")
        self.next()
        self.next()
        self.page.wait_for_selector("#wiz-issuer")
        self.assertEqual(self.page.input_value("#wiz-issuer"), self.issuer)
        self.assertEqual(self.page.input_value("#wiz-cid"), "saved-id")
        self.assertEqual(self.page.input_value("#wiz-scopes"), "openid profile groups")
        self.assertEqual(self.page.input_value("#wiz-secret"), "", "the saved secret is never shown")
        self.assertIn("Leave empty to keep the saved secret.", self.page.inner_text("#wiz-body"))
        self.next()                                              # the secret may stay empty for this issuer and client
        self.page.wait_for_selector("#wiz-admin")
        self.assertEqual(self.page.input_value("#wiz-admin"), "old-admins")
        self.next()
        self.page.wait_for_selector("#wiz-test")
        self.assertEqual(self.run_test(), "Reachable")
        self.finish()
        self.assertEqual(self.stored()["oidc_client_secret"], before["oidc_client_secret"], "the saved secret was not touched")
        self.assertTrue(self.stored()["oidc_enabled"])

    def test_another_issuer_or_client_needs_the_secret_typed_again(self):
        self.api("POST", "/config", {"oidc_issuer": self.issuer, "oidc_client_id": "saved-id", "oidc_client_secret": "saved-secret"})
        self.open()
        self.next()
        self.next()
        self.page.wait_for_selector("#wiz-issuer")
        self.fill("#wiz-issuer", self.issuer + "other/")
        self.next()
        self.assertEqual(self.message(), "This field is needed")
        self.assertEqual(self.focused(), "wiz-secret", "the saved secret is not sent to a different issuer")
        self.fill("#wiz-issuer", self.issuer)
        self.fill("#wiz-cid", "another-client")
        self.next()
        self.assertEqual(self.message(), "This field is needed")
        self.fill("#wiz-cid", "saved-id")
        self.next()
        self.page.wait_for_selector("#wiz-admin")

    def test_the_finish_says_what_turning_it_on_does_and_how_to_try_it(self):
        self.to_test()
        self.next()
        self.page.wait_for_selector("#wiz-body .wiz-list")
        text = self.page.inner_text("#wiz-body")
        self.assertIn("Turning it on adds a Sign in with SSO button to the sign-in page.", text)
        self.assertIn("anyone the provider lets in gets a viewer account", text)
        self.assertIn("open the sign-in page in a private window", text)
        self.assertIn("Keep this window signed in until it works.", text)
        self.assertIn("It was not tested.", text)
        self.assertEqual(self.page.inner_text("#wiz-next").strip(), "Turn it on")

    def test_closing_early_saves_nothing_even_after_a_test_that_worked(self):
        self.to_test()
        self.assertEqual(self.run_test(), "Reachable")
        self.page.keyboard.press("Escape")
        self.page.wait_for_selector("#wizard-modal", state="detached", timeout=20000)
        self.assertEqual(self.stored(), self.start)

    # ── words ───────────────────────────────────────────────────────────────────────────────────────────────────────────────
    def own_texts(self):
        return self.page.evaluate("""() => {
          const out = new Set();
          document.querySelectorAll('#wizard-modal *').forEach(e => {
            if (e.closest('.ff-mono') || e.closest('pre') || e.matches('dd, .wiz-chip, .wiz-num, option, input, select, textarea, script, style, .visually-hidden')) return;
            const t = [...e.childNodes].filter(n => n.nodeType === 3).map(n => n.textContent).join('').trim();
            if (t) out.add(t);
          });
          return [...out];
        }""")

    def test_every_word_of_every_step_has_a_translation_in_all_six_languages(self):
        self.assertTrue(self.page.evaluate("async () => { await _ensureI18n(); return !!window.RPi18n; }"), "i18n.js did not load")
        seen = set()
        self.open()
        seen.update(self.own_texts())
        for key in PROVIDERS:
            self.pick(key)
            self.next()
            self.page.wait_for_selector("#wiz-oidc-redirect")
            seen.update(self.own_texts())
            self.page.click("#wiz-back")
        self.pick("authentik")
        self.next()
        self.next()
        self.page.wait_for_selector("#wiz-issuer")
        self.next()
        seen.update(self.own_texts())
        self.connection()
        self.next()
        self.page.wait_for_selector("#wiz-admin")
        seen.update(self.own_texts())
        self.next()
        self.page.wait_for_selector("#wiz-test")
        seen.update(self.own_texts())
        _Idp.doc = document(self.base_url(), scopes_supported=["openid"], token_endpoint_auth_methods_supported=["client_secret_basic"], grant_types_supported=["implicit"])
        self.assertEqual(self.run_test(), "Reachable")
        seen.update(self.own_texts())
        self.page.click("#wiz-back")
        self.page.click("#wiz-back")
        self.fill("#wiz-issuer", "http://127.0.0.1:%d/x" % free_port())
        self.next()
        self.page.wait_for_selector("#wiz-admin")
        self.next()
        self.page.wait_for_selector("#wiz-test")
        self.assertEqual(self.run_test(), "Not reachable")
        seen.update(self.own_texts())
        self.next()
        self.page.wait_for_selector("#wiz-body .wiz-list")
        seen.update(self.own_texts())
        texts = {t for t in seen if not (t in BRANDS or t.startswith(("http", "openid", "sre=", "# ")) or "@" in t or t.isdigit())}
        self.assertGreater(len(texts), 40, "the population is not empty")
        langs = self.page.evaluate("() => RPi18n.langs.filter(l => l !== 'en')")
        self.assertEqual(sorted(langs), ["ar", "de", "es", "fr", "hi", "zh"])
        try:
            for lang in langs:
                self.page.evaluate("(l) => RPi18n.setLang(l, false)", lang)
                for t in sorted(texts):
                    got = self.page.evaluate("(k) => RPi18n.t(k)", t)
                    self.assertTrue(got, "%s: %r is empty" % (lang, t))
                    if (t, lang) not in SAME:
                        self.assertNotEqual(got, t, "%s: %r is not translated" % (lang, t))
        finally:
            self.page.evaluate("() => RPi18n.setLang('en', false)")

    def test_no_script_error_was_raised(self):
        self.to_test()
        self.assertEqual(self.run_test(), "Reachable")
        self.assertEqual([e for e in self.errors if "Failed to load resource" not in e], [])


if __name__ == "__main__":
    unittest.main()
