#!/usr/bin/env python3
"""
Tests for v2.3.2 — security hardening.

  - Password hashing: the bcrypt-less fallback is now salted PBKDF2,
    not bare unsalted SHA-256. Legacy SHA-256 hashes still verify
    (backward compatibility). PBKDF2 hashes are self-describing and
    salted (two hashes of the same password differ).
  - The seeded default admin carries `must_change_password`, surfaced
    in the login response and cleared when the password is changed.
"""

import hashlib
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT    = Path(__file__).parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

os.environ.setdefault('REQUEST_METHOD', 'GET')
os.environ.setdefault('PATH_INFO', '/')
os.environ.setdefault('CONTENT_LENGTH', '0')
_spec = importlib.util.spec_from_file_location("api_v232", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestPasswordHashing(unittest.TestCase):

    def test_pbkdf2_round_trip(self):
        h = api._pbkdf2_hash('correct horse')
        self.assertTrue(h.startswith('pbkdf2$'))
        self.assertTrue(api.verify_password('correct horse', h))
        self.assertFalse(api.verify_password('wrong horse', h))

    def test_pbkdf2_is_salted(self):
        # Two hashes of the same password must differ — proves a
        # per-hash random salt (the whole point vs. bare sha256).
        h1 = api._pbkdf2_hash('samepw')
        h2 = api._pbkdf2_hash('samepw')
        self.assertNotEqual(h1, h2)
        # ...yet both verify
        self.assertTrue(api.verify_password('samepw', h1))
        self.assertTrue(api.verify_password('samepw', h2))

    def test_pbkdf2_iteration_count(self):
        # OWASP floor — don't let this silently regress
        self.assertGreaterEqual(api._PBKDF2_ITERATIONS, 600_000)
        h = api._pbkdf2_hash('x')
        self.assertEqual(h.split('$')[1], str(api._PBKDF2_ITERATIONS))

    def test_legacy_sha256_still_verifies(self):
        # Pre-2.3.2 hashes are bare hex sha256 — must still work so an
        # upgrade doesn't lock existing users out.
        legacy = hashlib.sha256(b'oldpassword').hexdigest()
        self.assertTrue(api.verify_password('oldpassword', legacy))
        self.assertFalse(api.verify_password('nope', legacy))

    def test_hash_password_no_bare_sha256(self):
        # hash_password must never emit a bare 64-hex sha256 — that was
        # the weak pre-2.3.2 fallback. Output is bcrypt ($2) or pbkdf2$.
        h = api.hash_password('whatever')
        self.assertTrue(h.startswith('$2') or h.startswith('pbkdf2$'),
                        f'unexpected hash format: {h[:12]}')
        # specifically: not a bare hex digest
        self.assertFalse(len(h) == 64 and all(c in '0123456789abcdef' for c in h))

    def test_verify_rejects_garbage(self):
        for junk in ('', 'x', 'pbkdf2$bad', 'pbkdf2$1$2', '$2bad'):
            self.assertFalse(api.verify_password('pw', junk))

    def test_corrupt_pbkdf2_does_not_crash(self):
        # A malformed pbkdf2 string must return False, not raise
        self.assertFalse(api.verify_password('pw', 'pbkdf2$notanint$ab$cd'))


class TestDefaultUserHardening(unittest.TestCase):

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        api.USERS_FILE = self._tmp / 'users.json'

    def test_default_user_not_bare_sha256(self):
        # Re-seed a fresh users.json and check the hash format.
        api.ensure_default_user()
        users = api.load(api.USERS_FILE)
        h = users['admin']['password_hash']
        # Must be bcrypt or pbkdf2 — never the old bare sha256 of
        # b'remotepower'
        self.assertTrue(h.startswith('$2') or h.startswith('pbkdf2$'))
        self.assertNotEqual(h, hashlib.sha256(b'remotepower').hexdigest())
        # The documented default password still works
        self.assertTrue(api.verify_password('remotepower', h))

    def test_default_user_flagged_must_change(self):
        api.ensure_default_user()
        users = api.load(api.USERS_FILE)
        self.assertTrue(users['admin'].get('must_change_password'))


class TestSecurityAssets(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.js = (_ROOT / 'server/html/static/js/app.js').read_text()
        cls.docker_nginx = (_ROOT / 'docker/nginx-docker.conf').read_text()
        cls.bare_nginx = (_ROOT / 'server/conf/remotepower.conf').read_text()

    def test_default_pw_banner_in_js(self):
        self.assertIn('_mustChangePassword', self.js)
        self.assertIn('default-pw-banner', self.js)

    def test_nginx_configs_have_security_headers(self):
        # Both nginx configs ship the hardening headers — regression
        # guard so a future edit doesn't silently drop them.
        for name, conf in (('docker', self.docker_nginx),
                           ('bare-metal', self.bare_nginx)):
            self.assertIn('X-Frame-Options', conf, f'{name} missing X-Frame-Options')
            self.assertIn('Content-Security-Policy', conf, f'{name} missing CSP')
            self.assertIn('X-Content-Type-Options', conf, f'{name} missing nosniff')

    def test_csp_no_unsafe_inline(self):
        # L1 security fix: 'unsafe-inline' must not appear in the CSP directive.
        import re
        for name, conf in (('docker', self.docker_nginx),
                           ('bare-metal', self.bare_nginx)):
            csp_line = next(
                (l for l in conf.splitlines() if 'add_header Content-Security-Policy' in l),
                ''
            )
            self.assertTrue(csp_line,
                            f"{name} has no add_header Content-Security-Policy line")
            self.assertNotIn("'unsafe-inline'", csp_line,
                             f"{name} CSP directive still contains 'unsafe-inline' (L1 finding)")

    # All HTML files that get served to a browser. Anything added here is
    # subject to the strict CSP and must contain no inline code or external
    # auto-loaded resources.
    _SHIPPED_HTML = [
        ('server/html/index.html',   'index.html'),
        ('server/html/swagger.html', 'swagger.html'),
        ('docs/Manual.html',         'Manual.html'),
    ]

    def test_no_inline_scripts_in_html(self):
        import re
        for relpath, name in self._SHIPPED_HTML:
            html = (_ROOT / relpath).read_text()
            inline_scripts = re.findall(r'<script(?![^>]*src=)[^>]*>', html, re.IGNORECASE)
            self.assertEqual(inline_scripts, [],
                             f'Inline <script> blocks found in {name}: {inline_scripts}')
            inline_styles = re.findall(r'<style[^>]*>', html, re.IGNORECASE)
            self.assertEqual(inline_styles, [],
                             f'Inline <style> blocks found in {name}: {inline_styles}')
            # Only flag tags that the browser auto-loads (script/link/img/iframe),
            # not user-clickable <a href> documentation links.
            ext = re.findall(
                r'<(?:script|link|img|iframe)[^>]*\s(?:src|href)="(https?://[^"]+)"',
                html, re.IGNORECASE)
            self.assertEqual(ext, [],
                             f'{name} auto-loads external resources: {ext}')

    def test_no_inline_event_handlers_in_html(self):
        import re
        for relpath, name in self._SHIPPED_HTML:
            html = (_ROOT / relpath).read_text()
            handlers = re.findall(r'\s(on(?:click|change|input|keydown|drop|dragover|dragleave|load|error)=)', html)
            self.assertEqual(handlers, [],
                             f'Inline event handlers found in {name}: {handlers}')
            attr_styles = re.findall(r'<[a-zA-Z][^>]*\sstyle="', html)
            self.assertEqual(attr_styles, [],
                             f'Inline style= attrs found in {name}: {len(attr_styles)}')

    def test_no_javascript_uri_in_html(self):
        # CSP `script-src 'self'` blocks javascript: URIs (e.g. <a href="javascript:foo()">).
        # Use data-action="…" data-prevent-default instead.
        import re
        for relpath, name in self._SHIPPED_HTML:
            html = (_ROOT / relpath).read_text()
            uris = re.findall(r'(?:href|src)\s*=\s*[\'"]javascript:[^\'"]*[\'"]', html, re.IGNORECASE)
            self.assertEqual(uris, [],
                             f'{name} contains javascript: URIs: {uris}')

    def test_vendor_libs_are_self_hosted(self):
        # CSP 'self' only allows /static/* origins, so the vendor libs the
        # app loads at runtime must live on disk under static/vendor/.
        vendor_dir = _ROOT / 'server' / 'html' / 'static' / 'vendor'
        self.assertTrue(vendor_dir.is_dir(), 'static/vendor/ is missing')
        expected = [
            'xterm/xterm.min.js',
            'xterm/xterm.min.css',
            'xterm-addon-fit/addon-fit.min.js',
            'qrcode-generator/qrcode.min.js',
            'fonts/inter-jetbrains.css',
            'swagger-ui/swagger-ui-bundle.min.js',
            'swagger-ui/swagger-ui.min.css',
        ]
        for rel in expected:
            self.assertTrue((vendor_dir / rel).is_file(),
                            f'vendor file missing: {rel}')

    def test_no_external_cdn_in_shipped_assets(self):
        # No code path should auto-load https:// resources — would be blocked
        # by `script-src 'self'` / `style-src 'self'`.
        import re
        css = (_ROOT / 'server' / 'html' / 'static' / 'css' / 'styles.css').read_text()
        # @import / url() in CSS to external origins
        ext = re.findall(r'(?:@import\s+url\(|url\(|src=)\s*[\'"]?(https?://[^\'")\s]+)', css)
        self.assertEqual(ext, [], f'styles.css loads external resources: {ext}')

        js = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        # script.src = 'https://...' or link.href = 'https://...' assignments
        ext = re.findall(r'\.(?:src|href)\s*=\s*[\'"`](https?://[^\'"`]+)', js)
        self.assertEqual(ext, [],
                         f'app.js auto-loads external scripts/stylesheets: {ext}')

    def test_no_inline_event_handlers_in_appjs(self):
        appjs_path = _ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js'
        appjs = appjs_path.read_text()
        import re
        # Only flag occurrences not on comment lines
        code_lines = [l for l in appjs.splitlines() if not l.strip().startswith('//')]
        code = '\n'.join(code_lines)
        for attr in ('onclick=', 'onchange=', 'oninput='):
            self.assertNotIn(attr, code,
                             f"Inline {attr} found in app.js template strings")


if __name__ == '__main__':
    unittest.main(verbosity=2)
