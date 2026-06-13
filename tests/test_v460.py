#!/usr/bin/env python3
"""Strict version-surface pins + New/Old UI guardrails for v4.6.0 "RepellantMatters".

The headline is the Industrial "New UI" (default) with a CSP-safe New/Old toggle.
These tests pin the version surface and the toggle wiring + the industrial theme
tokens, and guard that the toggle stays CSP-clean.

Loosen the TestVersionBumps strict pins to regex on the next bump (see
tests/test_v450.py for the pattern).
"""
import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v460", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_HTML = (_ROOT / "server/html/index.html").read_text()
_CSS = (_ROOT / "server/html/static/css/styles.css").read_text()
_JS = (_ROOT / "server/html/static/js/app.js").read_text()


class TestVersionBumps(unittest.TestCase):
    V = '4.6.0'

    def test_server_version(self):
        self.assertEqual(api.SERVER_VERSION, self.V)

    def test_agent_versions(self):
        self.assertIn(f"VERSION      = '{self.V}'",
                      (_ROOT / 'client/remotepower-agent.py').read_text())
        for rel in ('client/remotepower-agent-win.py', 'client/remotepower-agent-mac.py'):
            self.assertIn(f"VERSION = '{self.V}'", (_ROOT / rel).read_text(), rel)

    def test_agent_extensionless_in_sync(self):
        self.assertEqual((_ROOT / 'client/remotepower-agent.py').read_bytes(),
                         (_ROOT / 'client/remotepower-agent').read_bytes())

    def test_sw_and_cachebust(self):
        self.assertIn(f'remotepower-shell-v{self.V}',
                      (_ROOT / 'server/html/sw.js').read_text())
        self.assertIn(f'?v={self.V}', _HTML)

    def test_no_stale_cachebust(self):
        self.assertEqual(set(re.findall(r'\?v=(4\.5\.0)\b', _HTML)), set(),
                         'stale ?v=4.5.0 cache-busts left')

    def test_readme_and_changelog(self):
        self.assertIn(f'version-{self.V}-blue', (_ROOT / 'README.md').read_text())
        self.assertIn(f'v{self.V}', (_ROOT / 'CHANGELOG.md').read_text()[:2000])

    def test_version_doc_exists(self):
        self.assertTrue((_ROOT / f'docs/v{self.V}.md').exists())

    def test_doc_set_keeps_five_versions(self):
        vdocs = sorted(p.name for p in (_ROOT / 'docs').glob('v*.md'))
        self.assertEqual(len(vdocs), 5, f'expected exactly 5 version docs, got {vdocs}')

    def test_whats_new_card_present(self):
        self.assertIn(f"What's new — v{self.V}", _HTML)

    def test_manual_version(self):
        self.assertIn(f'Version {self.V} —', (_ROOT / 'docs/Manual.html').read_text())


class TestIndustrialTheme(unittest.TestCase):
    """The New UI = body[data-ui="industrial"] design system, keeping the blue accent."""

    def test_industrial_palette_block_exists(self):
        self.assertIn('body[data-ui="industrial"]', _CSS)
        # graphite + the existing logo blue accent
        m = re.search(r'body\[data-ui="industrial"\]\s*\{(.*?)\}', _CSS, re.S)
        self.assertIsNotNone(m)
        block = m.group(1)
        self.assertIn('--accent:#3b7eff', block.replace(' ', ''))
        self.assertIn('--bg:#0f1217', block.replace(' ', ''))
        # body reverted to the old Inter font; the SIDEBAR keeps IBM Plex Mono
        self.assertIn("--font:'Inter'", block.replace(' ', ''))
        self.assertIn("--font-mono:'IBMPlexMono'", block.replace(' ', ''))
        self.assertIn('.sidebar*{font-family:var(--font-mono)', _CSS.replace(' ', ''))

    def test_fonts_are_self_hosted_not_external(self):
        # Space Grotesk + IBM Plex Mono ship as same-origin @font-face (the strict
        # CSP blocks Google Fonts); no external font references anywhere.
        face = (_ROOT / 'server/html/static/vendor/fonts/industrial.css').read_text()
        self.assertIn("font-family:'Space Grotesk'", face)
        self.assertIn("font-family:'IBM Plex Mono'", face)
        self.assertIn('.woff2', face)
        for txt in (_CSS, face):
            self.assertNotIn('fonts.googleapis.com', txt)
            self.assertNotIn('fonts.gstatic.com', txt)
        # the woff2 files actually exist
        fdir = _ROOT / 'server/html/static/vendor/fonts/files'
        self.assertTrue((fdir / 'space-grotesk-latin-500-normal.woff2').exists())
        self.assertTrue((fdir / 'ibm-plex-mono-latin-400-normal.woff2').exists())


class TestUIVersionToggle(unittest.TestCase):
    """New UI / Old UI toggle: default new, CSP-safe wiring, reachable by all users."""

    def test_js_functions_and_default(self):
        self.assertIn('function applyUIVersion(', _JS)
        self.assertIn('function setUIVersion(', _JS)
        # default to 'new' when no preference is stored
        self.assertRegex(_JS, r"getItem\('rp_ui'\)\s*\|\|\s*'new'")
        # applied during showApp() init
        self.assertIn('applyUIVersion();', _JS)

    def test_toggle_present_in_settings_and_account(self):
        # the requested admin tab
        self.assertIn('data-arg="interface"', _HTML)
        self.assertIn('id="settings-pane-interface"', _HTML)
        # both New and Old options, wired via data-action (CSP-safe)
        self.assertIn('data-action="setUIVersion" data-arg="new"', _HTML)
        self.assertIn('data-action="setUIVersion" data-arg="old"', _HTML)
        # appears at least twice (Settings + My Account) so non-admins can revert
        self.assertGreaterEqual(_HTML.count('data-action="setUIVersion"'), 4)

    def test_toggle_is_csp_safe(self):
        # the toggle markup must not introduce inline styles or on* handlers.
        for m in re.finditer(r'<button[^>]*data-action="setUIVersion"[^>]*>', _HTML):
            tag = m.group(0)
            self.assertNotIn('style=', tag)
            self.assertNotIn('onclick=', tag)


class TestSelfSignedCertEndpoint(unittest.TestCase):
    """Generate-a-cert-from-the-UI: admin-gated endpoint + Python cert generation."""

    def test_route_registered_and_admin_gated(self):
        src = (_CGI / 'api.py').read_text()
        self.assertIn("('POST', '/api/tls/gen-self-signed'): handle_tls_gen_self_signed", src)
        m = re.search(r'def handle_tls_gen_self_signed\(\):(.*?)\ndef ', src, re.S)
        self.assertIsNotNone(m)
        body = m.group(1)
        self.assertIn('require_admin_auth()', body)   # admin only
        self.assertIn('audit_log(', body)             # audited
        # the UI control + handler are wired
        self.assertIn('data-action="genSelfSignedCert"', _HTML)
        self.assertIn('id="tls-gen-hosts"', _HTML)
        self.assertIn('function genSelfSignedCert(', _JS)

    def test_p12_import_route_and_hidden_password(self):
        src = (_CGI / 'api.py').read_text()
        self.assertIn("('POST', '/api/tls/import-p12'): handle_tls_import_p12", src)
        m = re.search(r'def handle_tls_import_p12\(\):(.*?)\ndef ', src, re.S)
        self.assertIsNotNone(m)
        self.assertIn('require_admin_auth()', m.group(1))   # admin only
        self.assertIn('audit_log(', m.group(1))             # audited
        # UI: file input + a HIDDEN (type=password) optional password + handler
        self.assertIn('id="p12-file"', _HTML)
        self.assertIn('type="password" id="p12-pass"', _HTML)
        self.assertIn('data-action="importP12"', _HTML)
        self.assertIn('function importP12(', _JS)

    def test_host_validation_rejects_injection(self):
        self.assertTrue(api._valid_tls_host('rp.internal'))
        self.assertTrue(api._valid_tls_host('10.0.0.5'))
        self.assertFalse(api._valid_tls_host('bad;rm -rf /'))
        self.assertFalse(api._valid_tls_host('a b'))
        self.assertFalse(api._valid_tls_host(''))

    def test_generates_verifiable_chain_and_reuses_ca(self):
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.skipTest('cryptography not installed')
        import tempfile
        d = tempfile.mkdtemp()
        out = api._tls_gen_self_signed(['rp.test', '10.9.8.7'], d)
        self.assertTrue(out['ok'])
        self.assertRegex(out['fingerprint'], r'^[0-9A-F:]{40,}$')
        self.assertFalse(out['renewed'])
        self.assertTrue((Path(d) / 'server.crt').exists())
        self.assertEqual(oct((Path(d) / 'ca.key').stat().st_mode)[-3:], '600')
        # re-issuing keeps the SAME CA (enrolled agents keep trust)
        out2 = api._tls_gen_self_signed(['rp.test'], d)
        self.assertEqual(out['fingerprint'], out2['fingerprint'])
        self.assertTrue(out2['renewed'])


if __name__ == '__main__':
    unittest.main()
