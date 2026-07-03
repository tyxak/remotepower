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

    def test_industrial_palette_block_exists(self):
        self.assertIn('body[data-ui="industrial"]', _CSS)
        css = _CSS.replace(' ', '')
        # v5.6.x: the base body[data-ui="industrial"] block holds the STRUCTURE
        # (fonts + palette-derived card gradient); the graphite dark PALETTE moved
        # to the :not([data-theme]):not(.light) default block so a chosen theme
        # can repaint the New UI. Assert both, plus the kept blue + Inter/mono.
        m = re.search(r'body\[data-ui="industrial"\]\s*\{(.*?)\}', _CSS, re.S)
        self.assertIsNotNone(m)
        base = m.group(1).replace(' ', '')
        self.assertIn("--font:'Inter'", base)
        self.assertIn("--font-mono:'IBMPlexMono'", base)
        # card gradient now derives from the live palette (theme-following)
        self.assertIn('--card-grad:linear-gradient(180deg,var(--surface)', base)
        # graphite default palette lives in the scoped default block; the blue
        # accent stays on :root (NOT this block) so the accent picker (0,2,1)
        # and themes (0,1,1) can win — pinning --accent here (0,3,1) is exactly
        # the bug that stuck chamfered buttons on blue in light mode.
        self.assertIn(
            'body[data-ui="industrial"]:not([data-theme]):not(.light){', css)
        dm = re.search(
            r'body\[data-ui="industrial"\]:not\(\[data-theme\]\):not\(\.light\)\s*\{(.*?)\}',
            _CSS, re.S)
        self.assertIsNotNone(dm)
        default_pal = dm.group(1).replace(' ', '')
        self.assertIn('--bg:#0f1217', default_pal)
        self.assertNotIn('--accent:', default_pal)   # must NOT pin accent here
        self.assertIn('--accent:#3b7eff', css)       # the blue default lives on :root
        self.assertIn('.sidebar*{font-family:var(--font-mono)', css)

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
        # The 34px inter-section spacing must NOT win inside a flex header row.
        # The reset has to carry the SAME `.page:not(#page-home)` prefix as the
        # margin rule — its `:not(#page-home)` adds an id (specificity 1,3,1),
        # so a reset without it (0,3,1) loses and the title is pushed 34px
        # off-centre from its tags/filter sibling (Enrolled Devices, Top
        # Processes). Reference fix: this commit.
        self.assertIn('body[data-ui="industrial"] .page:not(#page-home) '
                      '.section-header .section-title', _CSS)
        self.assertIn('body[data-ui="industrial"] .page:not(#page-home) '
                      '[class*="row-"] .section-title', _CSS)

    def test_netmap_card_not_scroll_capped(self):
        # The network-map <svg> (600px tall) lives in a .table-card for its
        # border/background; the bare .table-card 480px cap + overflow:auto grew
        # a redundant inner scrollbar. The id-scoped override lifts the cap.
        self.assertRegex(_CSS, r'#page-netmap > \.table-card\s*\{[^}]*max-height:\s*none')
        self.assertRegex(_CSS, r'#page-netmap > \.table-card\s*\{[^}]*overflow:\s*visible')


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
