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
    """v4.6.0 — loosened to regex on the v4.6.1 bump (live strict pins moved to
    tests/test_v461.py). Doc-housekeeping invariants below stay version-agnostic."""

    def test_server_version(self):
        self.assertRegex(api.SERVER_VERSION, r'^\d+\.\d+\.\d+$')

    def test_agent_versions(self):
        self.assertRegex((_ROOT / 'client/remotepower-agent.py').read_text(),
                         r"\nVERSION\s*=\s*'\d+\.\d+\.\d+'")
        for rel in ('client/remotepower-agent-win.py', 'client/remotepower-agent-mac.py'):
            self.assertRegex((_ROOT / rel).read_text(),
                             r"VERSION\s*=\s*'\d+\.\d+\.\d+'", rel)

    def test_agent_extensionless_in_sync(self):
        self.assertEqual((_ROOT / 'client/remotepower-agent.py').read_bytes(),
                         (_ROOT / 'client/remotepower-agent').read_bytes())

    def test_sw_and_cachebust(self):
        self.assertRegex((_ROOT / 'server/html/sw.js').read_text(),
                         r'remotepower-shell-v\d+\.\d+\.\d+')
        self.assertRegex(_HTML, r'\?v=\d+\.\d+\.\d+')

    def test_readme_and_changelog(self):
        self.assertRegex((_ROOT / 'README.md').read_text(), r'version-\d+\.\d+\.\d+-blue')
        self.assertRegex((_ROOT / 'CHANGELOG.md').read_text()[:2000], r'v\d+\.\d+\.\d+')

    def test_doc_set_keeps_five_versions(self):
        vdocs = sorted(p.name for p in (_ROOT / 'docs').glob('v[0-9]*.md'))
        self.assertEqual(len(vdocs), 5, f'expected exactly 5 version docs, got {vdocs}')

    def test_whats_new_card_present(self):
        self.assertRegex(_HTML, r"What's new — v\d+\.\d+\.\d+")


class TestIndustrialTheme(unittest.TestCase):
    """The New UI = body[data-ui="industrial"] design system, keeping the blue accent."""

    def test_industrial_skin_fully_removed_palette_on_root(self):
        # v6.0.0: the Industrial skin is FULLY REMOVED — no data-ui selector,
        # attribute or JS pin may survive anywhere.
        self.assertNotIn('data-ui', _CSS)
        self.assertNotIn('data-ui', _HTML)
        self.assertNotIn("dataset.ui", _JS)
        # the live ClarityMatters palette + system font stacks live on :root
        css = _CSS.replace(' ', '')
        self.assertIn('--bg:#0c0f13', css)          # design dark ground
        self.assertIn('--bg:#eef1f5', css)          # design light ground (body.light)
        self.assertIn('--accent:#3b7eff', css)      # the design-blessed blue
        self.assertIn('--font:-apple-system', css)
        self.assertIn('--font-mono:ui-monospace', css)
        self.assertNotIn("'Inter'", css)
        self.assertNotIn('IBMPlexMono', css)

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


class TestIndustrialLayoutRegressions(unittest.TestCase):
    """Layout fixes that regressed repeatedly under the industrial skin."""

    def test_section_title_flexrow_reset_outspecifies_margin(self):
        # v6.0.0 surface 3: the industrial 30/34px section-spacing block and its
        # :not(#page-home) specificity-trap resets are DELETED (base card margins
        # own the rhythm) — assert the trap can't come back half-fixed: either
        # both the margin rule and its reset exist, or neither does.
        margin_rule = ('body[data-ui="industrial"] .page:not(#page-home) '
                       '.section-title{ margin-top:34px; }').replace(' ', '')
        self.assertNotIn(margin_rule, _CSS.replace(' ', ''))
        self.assertNotIn('body[data-ui="industrial"] .page:not(#page-home) '
                         '.section-header .section-title', _CSS)

    def test_netmap_card_not_scroll_capped(self):
        # The network-map <svg> (600px tall) lives in a .table-card for its
        # border/background; the bare .table-card 480px cap + overflow:auto grew
        # a redundant inner scrollbar. The id-scoped override lifts the cap.
        self.assertRegex(_CSS, r'#page-netmap > \.table-card\s*\{[^}]*max-height:\s*none')
        self.assertRegex(_CSS, r'#page-netmap > \.table-card\s*\{[^}]*overflow:\s*visible')


class TestUIVersionToggle(unittest.TestCase):
    """v6.0.0 "ClarityMatters": ONE interface; the migration is COMPLETE.

    The v4.6.0 New/Old toggle, the transitional data-ui pin, applyUIVersion and
    every body[data-ui="industrial"] rule are gone for good.
    """

    def test_js_single_ui_no_preference(self):
        # v6.0.0 final: applyUIVersion itself is gone with the transitional pin
        self.assertNotIn('function applyUIVersion(', _JS)
        self.assertNotIn('function setUIVersion(', _JS)
        self.assertNotIn("getItem('rp_ui'", _JS)
        self.assertNotIn("setItem('rp_ui'", _JS)

    def test_single_interface_no_toggle(self):
        # v6.0.0 punch list #4: the Interface pane is REMOVED entirely (it had
        # become a note about its own absence).
        self.assertNotIn('data-arg="interface"', _HTML)
        self.assertNotIn('id="settings-pane-interface"', _HTML)
        # the toggle buttons are gone everywhere (Settings + My Account)
        self.assertNotIn('data-action="setUIVersion"', _HTML)
        self.assertNotIn('ui-opt', _HTML)
        # v6 final: the body carries NO skin attribute at all
        self.assertIn('<body>', _HTML)


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
