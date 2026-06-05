"""v3.5.0 release tests.

Strict version pins for v3.5.0 (the v3.4.2 strict pins loosen to regex when
this file ships, per the standing convention).

v3.5.0 bundles four features:
  1. SBOM export        — per-host + fleet CycloneDX/SPDX, CVE-enriched (VEX).
  2. Lifecycle expiry   — warranty/license/support dates in CMDB → attention.
  3. VNC over SSH        — graphical remote access tunnelled over the webterm
                           daemon's SSH connection, rendered with noVNC.
  4. Sites/teams         — first-class fleet grouping above device `group`.
"""
import sys as _cj_sys
from pathlib import Path as _cj_Path
_cj_sys.path.insert(0, str(_cj_Path(__file__).resolve().parent))
from clientjs import client_js
import os
import re
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from routing_harness import routes_to  # noqa: E402


class TestVersionBumps(unittest.TestCase):
    """Loosened to regex — v3.6.0 now holds the strict pin (test_v360.py).
    Version-pin assertions relax to pattern-only; the v3.5.0 feature
    regression tests below stay."""

    def test_api_server_version(self):
        text = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        m = re.search(r"^SERVER_VERSION\s*=\s*'(3\.\d+\.\d+)'", text, re.MULTILINE)
        self.assertIsNotNone(m, 'SERVER_VERSION line missing from api.py')

    def test_agent_version(self):
        text = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_text()
        m = re.search(r"^VERSION\s*=\s*'(3\.\d+\.\d+)'", text, re.MULTILINE)
        self.assertIsNotNone(m, 'VERSION line missing from agent')

    def test_agent_extensionless_matches_py(self):
        a = (REPO_ROOT / 'client' / 'remotepower-agent').read_bytes()
        b = (REPO_ROOT / 'client' / 'remotepower-agent.py').read_bytes()
        self.assertEqual(a, b,
            'remotepower-agent and remotepower-agent.py have drifted')

    def test_sw_cache_name(self):
        sw = (REPO_ROOT / 'server' / 'html' / 'sw.js').read_text()
        self.assertRegex(sw, r"'remotepower-shell-v3\.\d+\.\d+(?:-[a-z0-9]+)?'")

    def test_index_cache_bust(self):
        html = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()
        self.assertRegex(html, r'\?v=3\.\d+\.\d+')

    def test_readme_badge(self):
        text = (REPO_ROOT / 'README.md').read_text()
        self.assertRegex(text, r'version-3\.\d+\.\d+-blue\.svg')

    def test_changelog_top_entry(self):
        chlog = (REPO_ROOT / 'CHANGELOG.md').read_text()
        m = re.search(r'^## v(3\.\d+\.\d+)', chlog, re.MULTILINE)
        self.assertIsNotNone(m, 'CHANGELOG.md has no ## v3.x.x header')

    def test_release_notes_doc_present(self):
        # v3.5.0 release notes must stay present forever
        # v3.5.0 notes live in CHANGELOG.md; per-version docs/vX.Y.Z.md are
        # pruned to the last 5 (keep-last-5 housekeeping).
        chlog = (REPO_ROOT / 'CHANGELOG.md').read_text()
        self.assertIn('3.5.0', chlog)


class TestV350Sbom(unittest.TestCase):
    """SBOM export — CycloneDX/SPDX serialisation + routing + UI."""
    API = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
    APP = client_js()
    HTML = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()

    def test_routes(self):
        self.assertEqual(routes_to('GET', '/api/devices/abc/sbom'), 'handle_sbom_device')
        self.assertEqual(routes_to('GET', '/api/sbom'), 'handle_sbom_fleet')

    def test_module_purl_mapping(self):
        sys.path.insert(0, str(REPO_ROOT / 'server' / 'cgi-bin'))
        import sbom
        self.assertEqual(sbom._purl('openssl', '1.1.1f', 'amd64', 'apt', 'ubuntu'),
                         'pkg:deb/ubuntu/openssl@1.1.1f?arch=amd64')
        self.assertEqual(sbom._purl('glibc', '2.38', 'x86_64', 'pacman', ''),
                         'pkg:alpm/arch/glibc@2.38?arch=x86_64')
        self.assertTrue(sbom._purl('musl', '1.2', '', 'apk', 'alpine').startswith('pkg:apk/alpine/musl@1.2'))

    def test_cyclonedx_shape_and_vex(self):
        sys.path.insert(0, str(REPO_ROOT / 'server' / 'cgi-bin'))
        import sbom
        dev = {'id': 'd1', 'name': 'web', 'os': 'ubuntu-22.04'}
        pkg = {'packages': [{'name': 'openssl', 'version': '1.1.1f', 'arch': 'amd64'}],
               'pkg_manager': 'apt', 'os_id': 'ubuntu', 'collected_at': 1700000000}
        findings = [{'vuln_id': 'CVE-2024-1', 'package': 'openssl', 'version': '1.1.1f',
                     'severity': 'critical', 'fixed_version': '1.1.1g'}]
        doc = sbom.build_cyclonedx(dev, pkg, findings, server_version='3.5.0')
        self.assertEqual(doc['bomFormat'], 'CycloneDX')
        self.assertEqual(doc['specVersion'], '1.5')
        self.assertEqual(doc['components'][0]['purl'], 'pkg:deb/ubuntu/openssl@1.1.1f?arch=amd64')
        self.assertEqual(doc['vulnerabilities'][0]['id'], 'CVE-2024-1')
        self.assertEqual(doc['vulnerabilities'][0]['affects'][0]['ref'],
                         doc['components'][0]['bom-ref'])
        # determinism — same inputs → same serial
        self.assertEqual(doc['serialNumber'],
                         sbom.build_cyclonedx(dev, pkg, findings)['serialNumber'])

    def test_spdx_shape(self):
        sys.path.insert(0, str(REPO_ROOT / 'server' / 'cgi-bin'))
        import sbom
        dev = {'id': 'd1', 'name': 'web', 'os': 'ubuntu-22.04'}
        pkg = {'packages': [{'name': 'bash', 'version': '5.1', 'arch': 'amd64'}],
               'pkg_manager': 'apt', 'os_id': 'ubuntu', 'collected_at': 1}
        doc = sbom.build_spdx(dev, pkg, [], server_version='3.5.0')
        self.assertEqual(doc['spdxVersion'], 'SPDX-2.3')
        self.assertTrue(any(p.get('externalRefs') for p in doc['packages']))

    def test_frontend_present(self):
        self.assertIn('function _sbomDeviceBtn(', self.APP)
        self.assertIn('function _sbomFleetBtn(', self.APP)
        self.assertIn('_sbomFleetBtn', self.HTML)


class TestV350Expiry(unittest.TestCase):
    """Lifecycle expiry (warranty/license/support) → attention items."""
    API = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
    APP = client_js()
    HTML = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()

    def test_cmdb_default_has_expiry_fields(self):
        for f in ('warranty_expiry', 'license_expiry', 'support_contract_expiry'):
            self.assertIn(f"'{f}'", self.API, f'{f} missing from CMDB default record')

    def test_contract_status_helper(self):
        self.assertIn('def _device_contract_status(', self.API)
        self.assertIn("'kind': v['kind']", self.API)

    def test_channel_kinds_registered(self):
        import importlib
        sys.path.insert(0, str(REPO_ROOT / 'server' / 'cgi-bin'))
        api = importlib.import_module('api')
        keys = {k for k, *_ in api.CHANNEL_KINDS}
        for kind in ('warranty_expiry', 'license_expiry', 'support_expiry'):
            self.assertIn(kind, keys, f'{kind} missing from CHANNEL_KINDS')

    def test_contract_status_behaviour(self):
        import importlib, datetime as dt
        sys.path.insert(0, str(REPO_ROOT / 'server' / 'cgi-bin'))
        api = importlib.import_module('api')
        today = dt.date.today()
        rec = {'warranty_expiry': (today - dt.timedelta(days=3)).isoformat(),
               'license_expiry': (today + dt.timedelta(days=10)).isoformat(),
               'support_contract_expiry': (today + dt.timedelta(days=400)).isoformat()}
        out = {v['kind']: v['status'] for v in api._device_contract_status(rec)}
        self.assertEqual(out.get('warranty_expiry'), 'expired')
        self.assertEqual(out.get('license_expiry'), 'warn')
        self.assertNotIn('support_expiry', out)  # 400d out → ok, not surfaced

    def test_frontend_present(self):
        self.assertIn('cmdb-asset-warranty', self.HTML)
        self.assertIn('cmdb-asset-warranty', self.APP)


class TestV350Vnc(unittest.TestCase):
    """VNC over SSH — daemon bridge + browser flow."""
    APP = client_js()
    HTML = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()
    DAEMON = (REPO_ROOT / 'server' / 'webterm' / 'remotepower-webterm.py').read_text()

    def test_daemon_vnc_bridge(self):
        self.assertIn('async def _run_vnc(', self.DAEMON)
        self.assertIn("mode = (creds.get('mode')", self.DAEMON)
        self.assertIn("open_connection('127.0.0.1', vnc_port)", self.DAEMON)
        self.assertIn("if mode == 'vnc':", self.DAEMON)

    def test_frontend_flow(self):
        self.assertIn('function openVnc(', self.APP)
        self.assertIn('function vncConnect(', self.APP)
        self.assertIn('function _loadNoVncOnce(', self.APP)
        self.assertIn("mode: 'vnc'", self.APP)
        # raw-channel attach form: new RFB(target, websocket, options)
        self.assertIn('new RFB(canvasDiv, ws', self.APP)

    def test_frontend_markup(self):
        self.assertIn('id="vnc-modal"', self.HTML)
        self.assertIn('id="vnc-canvas"', self.HTML)
        self.assertIn("data-action=\"vncConnect\"", self.HTML)

    def test_novnc_vendored(self):
        """The viewer's loader imports /static/vendor/novnc/core/rfb.js — the
        files must be vendored, with their relative imports intact."""
        base = REPO_ROOT / 'server' / 'html' / 'static' / 'vendor' / 'novnc'
        rfb = base / 'core' / 'rfb.js'
        self.assertTrue(rfb.exists(), 'noVNC core/rfb.js not vendored')
        self.assertIn('export default class RFB', rfb.read_text())
        # pako (rfb.js's transitive dependency) must be present too
        self.assertTrue((base / 'vendor' / 'pako' / 'lib' / 'zlib' / 'inflate.js').exists(),
                        'noVNC vendored without pako — inflator import will 404')
        self.assertIn('/static/vendor/novnc/core/rfb.js', self.APP)


class TestV350Sites(unittest.TestCase):
    """Sites/teams — registry + assignment + admin UI."""
    API = (REPO_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
    APP = client_js()
    HTML = (REPO_ROOT / 'server' / 'html' / 'index.html').read_text()

    def test_routes(self):
        self.assertEqual(routes_to('GET', '/api/sites'), 'handle_sites_list')
        self.assertEqual(routes_to('POST', '/api/sites'), 'handle_site_create')
        self.assertEqual(routes_to('PUT', '/api/sites/s1'), 'handle_site_update')
        self.assertEqual(routes_to('DELETE', '/api/sites/s1'), 'handle_site_delete')
        self.assertEqual(routes_to('PATCH', '/api/devices/d1/site'), 'handle_device_site')

    def test_handlers_admin_gated(self):
        for fn in ('handle_site_create', 'handle_site_update', 'handle_site_delete', 'handle_device_site'):
            m = re.search(rf'def {fn}\(.*?\n(.*?)\ndef ', self.API, re.DOTALL)
            self.assertIsNotNone(m, f'{fn} not found')
            self.assertIn('require_admin_auth()', m.group(1), f'{fn} must be admin-gated')

    def test_device_list_exposes_site(self):
        self.assertIn("'site': dev.get('site', '')", self.API)

    def test_frontend_present(self):
        self.assertIn('data-page="sites"', self.HTML)
        self.assertIn('id="page-sites"', self.HTML)
        self.assertIn('function loadSites(', self.APP)
        self.assertIn('function saveSite(', self.APP)
        self.assertIn('function saveDeviceSite(', self.APP)
        self.assertIn("name === 'sites'", self.APP)


if __name__ == '__main__':
    unittest.main()
