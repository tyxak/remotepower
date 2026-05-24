"""v3.0.3 release tests.

Covers:
  - SMTP password env-var override (RP_SMTP_PASSWORD) — precedence,
    fallback, empty-empty, signalling shape.
  - LDAP bind password env-var override (RP_LDAP_BIND_PASSWORD) — same.
  - /api/config exposes *_password_from_env flags reflecting env state.
  - F2 forced-password-change interceptor:
      * pass-through for /api/users/passwd and /api/public-info
      * pass-through when token is absent
      * pass-through when token is an API key (not a session)
      * pass-through when must_change_password is unset
      * 403 + must_change_password=true for any other path when set
  - PWA install fixes:
      * the `#pwa-install-btn { display: none; }` stylesheet rule is gone
      * manifest icons declare separate any + maskable purposes
      * service worker cache name is bumped to v3.0.3
  - Version bumps: api.py, agent .py + extensionless copy, README badge.
"""
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / 'server' / 'cgi-bin'))


# ─── Shared helpers ─────────────────────────────────────────────────────────

class _ApiTestBase(unittest.TestCase):
    """Each subclass gets a fresh tmpdir + fresh api module import.

    We re-import api per class so DATA_DIR resolves against the tmpdir
    and the per-test environment doesn't leak between classes.
    """

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix='rp_v303_')
        os.environ['RP_DATA_DIR'] = cls.tmpdir
        # Drop any prior import so DATA_DIR rebinds.
        for mod in ('api', 'smtp_notifier', 'ldap_auth'):
            if mod in sys.modules:
                del sys.modules[mod]
        import api          # noqa: E402
        import smtp_notifier
        import ldap_auth
        cls.api = api
        cls.smtp_notifier = smtp_notifier
        cls.ldap_auth = ldap_auth

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)
        os.environ.pop('RP_DATA_DIR', None)


def _clear_env(*names):
    for n in names:
        os.environ.pop(n, None)


# ─── L2: SMTP/LDAP env-var overrides ────────────────────────────────────────

class TestSmtpEnvOverride(_ApiTestBase):
    """RP_SMTP_PASSWORD takes precedence over config.json."""

    def setUp(self):
        _clear_env('RP_SMTP_PASSWORD')

    def tearDown(self):
        _clear_env('RP_SMTP_PASSWORD')

    def test_env_unset_falls_back_to_config(self):
        cfg = {'smtp_password': 'from-config'}
        pw, from_env = self.smtp_notifier.resolve_smtp_password(cfg)
        self.assertEqual(pw, 'from-config')
        self.assertFalse(from_env)

    def test_env_set_overrides_config(self):
        os.environ['RP_SMTP_PASSWORD'] = 'from-env'
        cfg = {'smtp_password': 'from-config'}
        pw, from_env = self.smtp_notifier.resolve_smtp_password(cfg)
        self.assertEqual(pw, 'from-env')
        self.assertTrue(from_env)

    def test_env_set_overrides_empty_config(self):
        os.environ['RP_SMTP_PASSWORD'] = 'from-env'
        pw, from_env = self.smtp_notifier.resolve_smtp_password({})
        self.assertEqual(pw, 'from-env')
        self.assertTrue(from_env)

    def test_both_empty_returns_empty_not_none(self):
        pw, from_env = self.smtp_notifier.resolve_smtp_password({})
        self.assertEqual(pw, '')
        self.assertFalse(from_env)

    def test_empty_env_var_is_treated_as_unset(self):
        """RP_SMTP_PASSWORD='' must not silently disable AUTH on a server
        whose config.json has a real password. Empty env = fall back."""
        os.environ['RP_SMTP_PASSWORD'] = ''
        cfg = {'smtp_password': 'real-password'}
        pw, from_env = self.smtp_notifier.resolve_smtp_password(cfg)
        self.assertEqual(pw, 'real-password')
        self.assertFalse(from_env)


class TestLdapEnvOverride(_ApiTestBase):
    """RP_LDAP_BIND_PASSWORD takes precedence over config.json."""

    def setUp(self):
        _clear_env('RP_LDAP_BIND_PASSWORD')

    def tearDown(self):
        _clear_env('RP_LDAP_BIND_PASSWORD')

    def test_env_unset_falls_back_to_config(self):
        cfg = {'ldap_bind_password': 'from-config'}
        pw, from_env = self.ldap_auth.resolve_bind_password(cfg)
        self.assertEqual(pw, 'from-config')
        self.assertFalse(from_env)

    def test_env_set_overrides_config(self):
        os.environ['RP_LDAP_BIND_PASSWORD'] = 'from-env'
        cfg = {'ldap_bind_password': 'from-config'}
        pw, from_env = self.ldap_auth.resolve_bind_password(cfg)
        self.assertEqual(pw, 'from-env')
        self.assertTrue(from_env)

    def test_both_empty_returns_empty_not_none(self):
        pw, from_env = self.ldap_auth.resolve_bind_password({})
        self.assertEqual(pw, '')
        self.assertFalse(from_env)

    def test_empty_env_var_is_treated_as_unset(self):
        os.environ['RP_LDAP_BIND_PASSWORD'] = ''
        cfg = {'ldap_bind_password': 'real-password'}
        pw, from_env = self.ldap_auth.resolve_bind_password(cfg)
        self.assertEqual(pw, 'real-password')
        self.assertFalse(from_env)


class TestSafeConfigExposesEnvFlags(_ApiTestBase):
    """/api/config response includes the new *_password_from_env flags."""

    def setUp(self):
        _clear_env('RP_SMTP_PASSWORD', 'RP_LDAP_BIND_PASSWORD')
        # Seed a minimal config so handle_config_get() has something to render.
        self.api.save(self.api.CONFIG_FILE, {
            'smtp_password': 'cfg-smtp',
            'ldap_bind_password': 'cfg-ldap',
        })

    def tearDown(self):
        _clear_env('RP_SMTP_PASSWORD', 'RP_LDAP_BIND_PASSWORD')

    def _call_config_get(self, fake_admin_user='admin'):
        """Invoke handle_config_get() inside a faked auth context, capturing
        the HTTPError body the handler emits via respond()."""
        import time
        # Stand up a session token for an admin user
        users = self.api.load(self.api.USERS_FILE)
        users[fake_admin_user] = {
            'password_hash': self.api.hash_password('x'),
            'role': 'admin',
        }
        self.api.save(self.api.USERS_FILE, users)
        token = 'test-token-' + os.urandom(8).hex()
        tokens = self.api.load(self.api.TOKENS_FILE)
        # created must be a real timestamp — verify_token computes
        # (now - created) > ttl and treats stale entries as expired.
        tokens[token] = {'user': fake_admin_user,
                          'created': int(time.time()), 'ttl': 10**9}
        self.api.save(self.api.TOKENS_FILE, tokens)
        os.environ['HTTP_X_TOKEN'] = token
        os.environ['REQUEST_METHOD'] = 'GET'
        try:
            try:
                self.api.handle_config_get()
            except self.api.HTTPError as e:
                self.assertEqual(e.status, 200,
                    f'expected 200, got {e.status}: {e.body}')
                return e.body
            self.fail('handle_config_get() did not raise HTTPError')
        finally:
            _clear_env('HTTP_X_TOKEN', 'REQUEST_METHOD')

    def test_flags_false_when_env_unset(self):
        body = self._call_config_get()
        self.assertFalse(body['smtp_password_from_env'])
        self.assertFalse(body['ldap_bind_password_from_env'])
        # Existing _set flags still work
        self.assertTrue(body['smtp_password_set'])
        self.assertTrue(body['ldap_bind_password_set'])
        # Secrets themselves never appear
        self.assertNotIn('smtp_password', body)
        self.assertNotIn('ldap_bind_password', body)

    def test_flags_true_when_env_set(self):
        os.environ['RP_SMTP_PASSWORD'] = 'env-smtp'
        os.environ['RP_LDAP_BIND_PASSWORD'] = 'env-ldap'
        body = self._call_config_get()
        self.assertTrue(body['smtp_password_from_env'])
        self.assertTrue(body['ldap_bind_password_from_env'])
        # And _set is still True (the env var is "set" by another route)
        self.assertTrue(body['smtp_password_set'])
        self.assertTrue(body['ldap_bind_password_set'])


# ─── F2: forced-password-change interceptor ──────────────────────────────────

class TestPasswordChangeInterceptor(_ApiTestBase):
    """_enforce_password_change() must hard-block every path except the
    minimal allowlist when the session user has must_change_password=True."""

    def setUp(self):
        import time
        # Re-seed users with a default-admin needing a password change
        users = {
            'admin': {
                'password_hash': self.api.hash_password('x'),
                'role': 'admin',
                'must_change_password': True,
            },
            'clean': {
                'password_hash': self.api.hash_password('x'),
                'role': 'admin',
            },
        }
        self.api.save(self.api.USERS_FILE, users)

        # Two session tokens — one for each user. created must be a real
        # timestamp; verify_token treats stale entries as expired.
        now = int(time.time())
        tokens = {
            'tok-default': {'user': 'admin', 'created': now, 'ttl': 10**9},
            'tok-clean':   {'user': 'clean', 'created': now, 'ttl': 10**9},
        }
        self.api.save(self.api.TOKENS_FILE, tokens)

    def tearDown(self):
        _clear_env('HTTP_X_TOKEN', 'PATH_INFO', 'REQUEST_METHOD')

    def _run_interceptor(self, path, token=''):
        os.environ['PATH_INFO'] = path
        os.environ['REQUEST_METHOD'] = 'GET'
        if token:
            os.environ['HTTP_X_TOKEN'] = token
        else:
            _clear_env('HTTP_X_TOKEN')
        try:
            self.api._enforce_password_change()
            return None  # no 403 raised
        except self.api.HTTPError as e:
            return e

    def test_no_token_passes_through(self):
        self.assertIsNone(self._run_interceptor('/api/devices', token=''))

    def test_session_without_flag_passes_through(self):
        self.assertIsNone(self._run_interceptor('/api/devices', token='tok-clean'))

    def test_session_with_flag_blocked_on_arbitrary_path(self):
        err = self._run_interceptor('/api/devices', token='tok-default')
        self.assertIsNotNone(err)
        self.assertEqual(err.status, 403)
        self.assertTrue(err.body['must_change_password'])

    def test_password_change_path_allowed_even_with_flag(self):
        self.assertIsNone(
            self._run_interceptor('/api/users/passwd', token='tok-default'))

    def test_public_info_allowed_even_with_flag(self):
        self.assertIsNone(
            self._run_interceptor('/api/public-info', token='tok-default'))

    def test_api_key_token_passes_through(self):
        """An API key isn't in TOKENS_FILE — interceptor must not block it.
        (An admin with must_change_password set can't create an API key
        anyway because the create-key endpoint is in the blocked set.)"""
        # No matching token entry in tokens.json — simulates an API key
        err = self._run_interceptor('/api/devices', token='rpk_some_api_key_value')
        self.assertIsNone(err,
            'API-key requests must not be intercepted by must_change_password')

    def test_unknown_user_passes_through(self):
        """A session token whose user has been deleted: the interceptor
        must not 500 — it should pass through and let require_auth() handle it."""
        import time
        tokens = self.api.load(self.api.TOKENS_FILE)
        tokens['orphan'] = {'user': 'deleted-user',
                             'created': int(time.time()), 'ttl': 10**9}
        self.api.save(self.api.TOKENS_FILE, tokens)
        self.assertIsNone(self._run_interceptor('/api/devices', token='orphan'))

    def test_changing_password_clears_flag_in_users_file(self):
        """Sanity: handle_user_passwd pops must_change_password on success.
        This guards the interceptor's exit path."""
        # The handler reads request env directly, so set up a fake POST
        os.environ['HTTP_X_TOKEN'] = 'tok-default'
        os.environ['REQUEST_METHOD'] = 'POST'
        os.environ['PATH_INFO'] = '/api/users/passwd'
        # get_body() reads from sys.stdin.buffer.read(CONTENT_LENGTH);
        # provide a minimal shim with a .buffer attribute.
        import io
        body = json.dumps({'old_password': 'x',
                            'new_password': 'new-strong-password-9!'}).encode()
        os.environ['CONTENT_LENGTH'] = str(len(body))

        class _StdinShim:
            buffer = io.BytesIO(body)

        old_stdin = sys.stdin
        sys.stdin = _StdinShim()
        try:
            try:
                self.api.handle_user_passwd()
            except self.api.HTTPError as e:
                self.assertEqual(e.status, 200,
                    f'unexpected status: {e.status} body={e.body}')
        finally:
            sys.stdin = old_stdin
            _clear_env('CONTENT_LENGTH')
        users = self.api.load(self.api.USERS_FILE)
        self.assertNotIn('must_change_password', users['admin'])


# ─── PWA install fixes ───────────────────────────────────────────────────────

class TestPwaInstallFix(unittest.TestCase):
    """Static checks against the shipped HTML / manifest / SW. These are
    not functional tests (we have no browser in CI), but they catch the
    exact regressions that broke v3.0.2's install prompt."""

    INDEX_HTML = REPO_ROOT / 'server' / 'html' / 'index.html'
    MANIFEST   = REPO_ROOT / 'server' / 'html' / 'manifest.json'
    SW_JS      = REPO_ROOT / 'server' / 'html' / 'sw.js'

    def test_no_id_rule_hiding_install_button(self):
        """The `#pwa-install-btn { display: none; }` stylesheet rule had
        higher specificity than the inline style and silently defeated
        the JS reveal. It must stay out of any <style> block.

        Scoped to <style> tags only — JS comments and docs may legitimately
        mention the pattern to document the fix.
        """
        html = self.INDEX_HTML.read_text()
        style_blocks = re.findall(r'<style[^>]*>(.*?)</style>', html, re.DOTALL)
        self.assertTrue(style_blocks, 'no <style> blocks found in index.html — '
                                       'the file structure has changed unexpectedly')
        for css in style_blocks:
            bad = re.search(
                r'#pwa-install-btn\s*\{[^}]*display\s*:\s*none', css, re.IGNORECASE)
            self.assertIsNone(bad,
                'A CSS rule with ID specificity is hiding the PWA install button '
                'and will defeat the JS reveal. Remove it from <style> in <head>.')

    def test_install_button_still_starts_hidden_inline(self):
        """The button itself should still have `style="display:none"`
        so it doesn't flash visible on first paint."""
        html = self.INDEX_HTML.read_text()
        m = re.search(
            r'<button[^>]*id="pwa-install-btn"[^>]*style="[^"]*display:\s*none',
            html)
        self.assertIsNotNone(m,
            'Install button must keep its inline display:none for initial hide.')

    def test_manifest_icons_split_any_and_maskable(self):
        """v3.0.3 splits `purpose: "any maskable"` (which some Brave builds
        treat as only-maskable, gating the install prompt) into separate
        any + maskable entries."""
        manifest = json.loads(self.MANIFEST.read_text())
        purposes = {icon.get('purpose') for icon in manifest['icons']}
        self.assertIn('any', purposes,
            'manifest must include at least one icon with purpose="any" '
            'or the install prompt will not fire in Chrome / Brave.')
        # Combined "any maskable" is the form that v3.0.2 used — we
        # explicitly do NOT want this any more.
        self.assertNotIn('any maskable', purposes,
            'split "any maskable" into separate entries — some browsers '
            'gate install on a pure "any" icon being present.')

    def test_sw_cache_name_bumped(self):
        """The SW cache must change with every release so the activate
        handler evicts the v3.0.2 shell on first reload."""
        sw = self.SW_JS.read_text()
        self.assertIn("'remotepower-shell-v3.0.3'", sw,
            'sw.js CACHE_NAME must be bumped to remotepower-shell-v3.0.3.')
        self.assertNotIn("'remotepower-shell-v3.0.2'", sw,
            'sw.js still references the v3.0.2 cache name.')

    def test_install_js_uses_explicit_display_value(self):
        """`element.style.display = ''` is the bug — it removes the inline
        rule and exposes whatever the stylesheet says. We now use an
        explicit value (inline-flex)."""
        html = self.INDEX_HTML.read_text()
        # The reveal function should set an explicit display value, not ''
        m = re.search(r"_installBtn\.style\.display\s*=\s*'inline-flex'", html)
        self.assertIsNotNone(m,
            'PWA reveal must set an explicit display value, not "".')


# ─── Version bumps ───────────────────────────────────────────────────────────

class TestVersionBumps(unittest.TestCase):
    EXPECTED = '3.0.3'

    def test_api_server_version(self):
        text = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        m = re.search(r"^SERVER_VERSION\s*=\s*'([^']+)'", text, re.MULTILINE)
        self.assertIsNotNone(m, 'SERVER_VERSION line missing from api.py')
        self.assertEqual(m.group(1), self.EXPECTED)

    def test_agent_version(self):
        text = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_text()
        m = re.search(r"^VERSION\s*=\s*'([^']+)'", text, re.MULTILINE)
        self.assertIsNotNone(m, 'VERSION line missing from agent')
        self.assertEqual(m.group(1), self.EXPECTED)

    def test_agent_extensionless_matches_py(self):
        """install-client.sh installs the extensionless file — it must
        not be stale relative to the .py."""
        a = (REPO_ROOT / 'client' / 'remotepower-agent').read_bytes()
        b = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_bytes()
        self.assertEqual(a, b,
            'client/remotepower-agent and remotepower-agent.py have drifted — '
            're-run cp remotepower-agent.py remotepower-agent in the release tasks.')

    def test_readme_badge(self):
        text = (REPO_ROOT / 'README.md').read_text()
        self.assertIn(f'version-{self.EXPECTED}-blue.svg', text,
            'README.md version badge not bumped')

    def test_changelog_top_entry(self):
        """The topmost entry in CHANGELOG.md must match the current
        version. This is the strict pin for v3.0.3 — the equivalent
        test in test_v302.py has been loosened now that v3.0.3 has
        taken over the top slot."""
        chlog = (REPO_ROOT / 'CHANGELOG.md').read_text()
        m = re.search(r'^## v(\d+\.\d+\.\d+)', chlog, re.MULTILINE)
        self.assertIsNotNone(m, 'CHANGELOG.md has no ## v3.0.3 header')
        self.assertEqual(m.group(1), self.EXPECTED,
            f'CHANGELOG.md top entry is v{m.group(1)}, expected v{self.EXPECTED}')

    def test_release_notes_doc_present(self):
        """docs/v3.0.3.md must exist and reference the version."""
        path = REPO_ROOT / 'docs' / 'v3.0.3.md'
        self.assertTrue(path.exists(), 'docs/v3.0.3.md is missing')
        text = path.read_text()
        self.assertIn('3.0.3', text)


class TestMobileNavScrimNoCollision(unittest.TestCase):
    """The body::after pseudo-element is used twice:
      1. line ~250 — ambient blue glow at the top of the page
         (fixed 800×400, translateX(-50%), pointer-events:none).
      2. inside @media (max-width:720px), body.mobile-nav-open::after
         — the mobile drawer's dim scrim.

    Rule 2 only sets inset/background/z-index, so width/height/transform/
    pointer-events from Rule 1 stick. The visible result is a half-sized
    floating square instead of a full-viewport scrim, and tap-to-close
    is broken (pointer-events:none falls through).

    This test ensures the scrim explicitly resets each property that
    bleeds in from the ambient-glow rule.
    """

    CSS = REPO_ROOT / 'server' / 'html' / 'static' / 'css' / 'styles.css'

    def test_scrim_resets_inherited_box_properties(self):
        css = self.CSS.read_text()
        # Pull just the scrim rule body
        m = re.search(
            r'body\.mobile-nav-open::after\s*\{([^}]*)\}', css, re.DOTALL)
        self.assertIsNotNone(m, 'mobile-nav scrim rule missing from styles.css')
        rule = m.group(1)
        for prop in ('width', 'height', 'transform', 'pointer-events'):
            self.assertRegex(
                rule, rf'\b{prop}\s*:',
                f'mobile-nav scrim must explicitly set "{prop}" to override '
                f'the ambient body::after rule that leaks {prop} into the scrim. '
                f'Without this reset the scrim renders as a partial rectangle '
                f'and tap-outside-to-close stops working.')
