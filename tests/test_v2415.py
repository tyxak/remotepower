#!/usr/bin/env python3
"""
Tests for v2.4.15 — Progressive Web App (PWA) support.

  1. manifest.json exists, is valid JSON, and contains required PWA fields.
  2. sw.js exists, registers the correct cache name, and contains
     the /api/ bypass rule.
  3. sw.js never caches /api/ requests.
  4. index.html links the manifest, registers the SW, and has the
     install button.
  5. nginx conf has worker-src in CSP, no-store for sw.js, and the
     manifest.json exact-match location before the .json deny block.
  6. deploy-server.sh and install-server.sh include sw.js.
  7. PWA icon files exist at the required sizes.
  8. Version consistency across all files.
"""

import json
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent


# ── helpers ──────────────────────────────────────────────────────────────────

def _server_version():
    api = (_ROOT / 'server/cgi-bin/api.py').read_text()
    m = re.search(r"SERVER_VERSION\s*=\s*'([^']+)'", api)
    assert m, 'SERVER_VERSION not found in api.py'
    return m.group(1)


# ── manifest.json ─────────────────────────────────────────────────────────────

class TestManifest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        path = _ROOT / 'server/html/manifest.json'
        cls.assertTrue(cls, path.exists(), 'manifest.json missing')
        cls.manifest = json.loads(path.read_text())

    def test_name_present(self):
        self.assertIn('name', self.manifest)
        self.assertEqual(self.manifest['name'], 'RemotePower')

    def test_short_name_present(self):
        self.assertIn('short_name', self.manifest)

    def test_display_standalone(self):
        self.assertEqual(self.manifest.get('display'), 'standalone')

    def test_start_url(self):
        self.assertEqual(self.manifest.get('start_url'), '/')

    def test_has_icons(self):
        icons = self.manifest.get('icons', [])
        self.assertTrue(len(icons) >= 2, 'manifest needs at least two icons')

    def test_has_192_icon(self):
        icons = self.manifest.get('icons', [])
        sizes = [i.get('sizes', '') for i in icons]
        self.assertTrue(any('192' in s for s in sizes),
                        '192x192 icon missing from manifest')

    def test_has_512_icon(self):
        icons = self.manifest.get('icons', [])
        sizes = [i.get('sizes', '') for i in icons]
        self.assertTrue(any('512' in s for s in sizes),
                        '512x512 icon missing from manifest')

    def test_theme_color_present(self):
        self.assertIn('theme_color', self.manifest)

    def test_background_color_present(self):
        self.assertIn('background_color', self.manifest)

    def test_icons_point_to_real_files(self):
        """Every icon src in the manifest must exist on disk."""
        for icon in self.manifest.get('icons', []):
            src = icon.get('src', '').lstrip('/')
            path = _ROOT / 'server/html' / src
            self.assertTrue(path.exists(),
                            f"Manifest icon src not found on disk: {src}")


# ── PWA icon files ────────────────────────────────────────────────────────────

class TestPWAIcons(unittest.TestCase):

    def test_icon_192_exists(self):
        self.assertTrue(
            (_ROOT / 'server/html/static/img/icon-192.png').exists())

    def test_icon_512_exists(self):
        self.assertTrue(
            (_ROOT / 'server/html/static/img/icon-512.png').exists())

    def test_icon_192_is_png(self):
        data = (_ROOT / 'server/html/static/img/icon-192.png').read_bytes()
        self.assertEqual(data[:8], b'\x89PNG\r\n\x1a\n', 'icon-192 is not a PNG')

    def test_icon_512_is_png(self):
        data = (_ROOT / 'server/html/static/img/icon-512.png').read_bytes()
        self.assertEqual(data[:8], b'\x89PNG\r\n\x1a\n', 'icon-512 is not a PNG')


# ── sw.js ─────────────────────────────────────────────────────────────────────

class TestServiceWorker(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        path = _ROOT / 'server/html/sw.js'
        cls.assertTrue(cls, path.exists(), 'sw.js missing')
        cls.sw = path.read_text()
        cls.ver = _server_version()

    def test_cache_name_versioned(self):
        """Cache name must contain the server version so upgrades bust it."""
        self.assertIn(self.ver, self.sw,
                      f'sw.js cache name does not reference version {self.ver}')

    def test_api_bypass_present(self):
        """API calls must never be served from cache."""
        self.assertIn('/api/', self.sw,
                      'sw.js has no /api/ bypass rule')

    def test_api_bypass_returns_early(self):
        """The /api/ bypass must use 'return' to skip cache logic entirely."""
        # Find the actual code check (pathname.startsWith), not the comment.
        idx = self.sw.find("pathname.startsWith('/api/')")
        self.assertGreater(idx, 0,
                           "pathname.startsWith('/api/') not found in sw.js code")
        context = self.sw[idx: idx + 80]
        self.assertIn('return', context,
                      '/api/ check does not return early — API may be cached')

    def test_shell_assets_listed(self):
        """SW must pre-cache at least the main HTML, JS, and CSS."""
        for asset in ('index.html', 'app.js', 'styles.css', 'manifest.json'):
            self.assertIn(asset, self.sw,
                          f'sw.js does not pre-cache {asset}')

    def test_install_event_handler(self):
        self.assertIn("'install'", self.sw)

    def test_activate_event_handler(self):
        self.assertIn("'activate'", self.sw)

    def test_fetch_event_handler(self):
        self.assertIn("'fetch'", self.sw)

    def test_old_caches_deleted_on_activate(self):
        self.assertIn('caches.delete', self.sw,
                      'SW does not delete stale caches on activate')

    def test_skip_waiting_called(self):
        self.assertIn('skipWaiting', self.sw)

    def test_clients_claim_called(self):
        self.assertIn('clients.claim', self.sw)

    def test_non_get_not_intercepted(self):
        """POST/DELETE/PATCH must pass through uncached."""
        self.assertIn("request.method !== 'GET'", self.sw)


# ── index.html ────────────────────────────────────────────────────────────────

class TestIndexHtmlPWA(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # CSP L1 (v3.0.4): the inline <script> that did SW registration +
        # the PWA install handlers was extracted from index.html into
        # /static/js/sw-register.js. Search both files so the PWA-shape
        # assertions still apply.
        idx = (_ROOT / 'server/html/index.html').read_text()
        sw  = (_ROOT / 'server/html/static/js/sw-register.js').read_text()
        cls.html = idx + '\n' + sw

    def test_manifest_link_present(self):
        self.assertIn('rel="manifest"', self.html)
        self.assertIn('href="/manifest.json"', self.html)

    def test_theme_color_meta(self):
        self.assertIn('name="theme-color"', self.html)

    def test_apple_mobile_web_app_capable(self):
        self.assertIn('apple-mobile-web-app-capable', self.html)

    def test_sw_registration_present(self):
        self.assertIn('serviceWorker', self.html)
        self.assertIn("register('/sw.js'", self.html)

    def test_install_button_present(self):
        self.assertIn('pwa-install-btn', self.html)

    def test_install_function_defined(self):
        self.assertIn('pwaInstall', self.html)

    def test_before_install_prompt_handled(self):
        self.assertIn('beforeinstallprompt', self.html)

    def test_app_installed_event_handled(self):
        self.assertIn('appinstalled', self.html)

    def test_install_button_hidden_by_default(self):
        # Button starts hidden; shown only when browser fires
        # beforeinstallprompt. CSP L1 (v3.0.4): the inline
        # `style="display:none"` was replaced by the auto-generated class
        # .isl-6 which carries `display:none` — assert the rule still
        # hides it by default.
        idx = self.html.find('pwa-install-btn')
        context = self.html[idx: idx + 200]
        # Pull the class names attached to the button
        import re
        m = re.search(r'class="([^"]+)"', context)
        self.assertIsNotNone(m, 'Install button has no class attribute')
        css = (_ROOT / 'server/html/static/css/styles.css').read_text()
        # At least one of the button's classes must carry display:none
        hidden = False
        for cls in m.group(1).split():
            for rule in re.finditer(rf'\.{re.escape(cls)}\s*\{{([^}}]*)\}}', css):
                if 'display' in rule.group(1) and 'none' in rule.group(1):
                    hidden = True
                    break
            if hidden:
                break
        self.assertTrue(hidden,
                        'Install button not hidden by default — no class with display:none')

    def test_sw_registration_has_scope(self):
        self.assertIn("scope: '/'", self.html)


# ── nginx config ──────────────────────────────────────────────────────────────

class TestNginxConfig(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.conf = (_ROOT / 'server/conf/remotepower.conf').read_text()

    def test_worker_src_in_csp(self):
        self.assertIn("worker-src 'self'", self.conf,
                      "CSP missing worker-src 'self' — SW will be blocked")

    def test_sw_js_no_store(self):
        self.assertIn('no-store', self.conf,
                      'sw.js location missing Cache-Control: no-store')

    def test_sw_js_location_block(self):
        self.assertIn('location = /sw.js', self.conf)

    def test_manifest_json_location_block(self):
        self.assertIn('location = /manifest.json', self.conf)

    def test_manifest_json_before_json_deny(self):
        """The manifest.json exact-match must appear BEFORE the .json deny rule,
        otherwise nginx will deny the manifest on first match."""
        manifest_idx = self.conf.find('location = /manifest.json')
        deny_idx = self.conf.find('location ~* \\.(json|tmp)$')
        self.assertGreater(manifest_idx, 0, 'manifest.json location block missing')
        self.assertGreater(deny_idx, 0, '.json deny location block missing')
        self.assertLess(manifest_idx, deny_idx,
                        'manifest.json location must appear BEFORE the .json deny rule')

    def test_manifest_content_type(self):
        self.assertIn('application/manifest+json', self.conf)

    def test_gzip_includes_manifest_type(self):
        self.assertIn('application/manifest+json', self.conf)


# ── deploy scripts ────────────────────────────────────────────────────────────

class TestDeployScripts(unittest.TestCase):

    def test_deploy_sh_includes_sw_js(self):
        deploy = (_ROOT / 'deploy-server.sh').read_text()
        self.assertIn('sw.js', deploy,
                      'deploy-server.sh does not deploy sw.js')

    def test_install_sh_includes_sw_js(self):
        install = (_ROOT / 'install-server.sh').read_text()
        self.assertIn('sw.js', install,
                      'install-server.sh does not deploy sw.js')

    def test_deploy_sh_includes_manifest(self):
        deploy = (_ROOT / 'deploy-server.sh').read_text()
        self.assertIn('manifest.json', deploy)

    def test_install_sh_includes_manifest(self):
        install = (_ROOT / 'install-server.sh').read_text()
        self.assertIn('manifest.json', install)


# ── version consistency ───────────────────────────────────────────────────────

class TestVersionConsistency(unittest.TestCase):

    def setUp(self):
        self.ver = _server_version()

    def _agent_version(self, path):
        text = path.read_text()
        m = re.search(r"^VERSION\s*=\s*'([^']+)'", text, re.MULTILINE)
        self.assertIsNotNone(m, f'VERSION not found in {path.name}')
        return m.group(1)

    def test_agent_py_version(self):
        self.assertEqual(
            self._agent_version(_ROOT / 'client/remotepower-agent.py'), self.ver)

    def test_agent_binary_version(self):
        self.assertEqual(
            self._agent_version(_ROOT / 'client/remotepower-agent'), self.ver)

    def test_readme_badge(self):
        readme = (_ROOT / 'README.md').read_text()
        m = re.search(r'version-([0-9.]+)-blue', readme)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), self.ver)

    def test_changelog_top_entry(self):
        cl = (_ROOT / 'CHANGELOG.md').read_text()
        m = re.search(r'^## v([0-9.]+)', cl, re.MULTILINE)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), self.ver)

    def test_cache_bust_strings(self):
        html = (_ROOT / 'server/html/index.html').read_text()
        for asset in ('static/js/app.js', 'static/css/styles.css'):
            m = re.search(re.escape(asset) + r'\?v=([0-9.]+)', html)
            self.assertIsNotNone(m, f'{asset} missing ?v=')
            self.assertEqual(m.group(1), self.ver)

    def test_sw_cache_name_has_version(self):
        sw = (_ROOT / 'server/html/sw.js').read_text()
        self.assertIn(self.ver, sw,
                      'sw.js CACHE_NAME does not match SERVER_VERSION')


if __name__ == '__main__':
    unittest.main(verbosity=2)
