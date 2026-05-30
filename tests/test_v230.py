#!/usr/bin/env python3
"""
Tests for v2.3.0 — Proxmox VE integration.

Covers the proxmox_client module (URL building, auth header, config
parsing, guest normalisation, the action allow-list, connection-test
failure handling) and the api.py wiring (config get masks the token
secret, config save round-trips the proxmox_* keys).

These tests do NOT hit a real Proxmox node — network calls are not
exercised. They cover the pure logic, which is where the bugs would
be.
"""

import sys as _cj_sys
from pathlib import Path as _cj_Path
_cj_sys.path.insert(0, str(_cj_Path(__file__).resolve().parent))
from clientjs import client_js
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT    = Path(__file__).parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

_spec = importlib.util.spec_from_file_location("proxmox_v230", _CGI_BIN / "proxmox_client.py")
px = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(px)


# ─── proxmox_client: URL + auth ─────────────────────────────────────────


class TestProxmoxURL(unittest.TestCase):

    def test_base_url_bare_host(self):
        self.assertEqual(px._base_url('pve.local'),
                         'https://pve.local:8006/api2/json')

    def test_base_url_with_port(self):
        self.assertEqual(px._base_url('pve.local:8006'),
                         'https://pve.local:8006/api2/json')

    def test_base_url_strips_scheme(self):
        self.assertEqual(px._base_url('https://10.0.0.5'),
                         'https://10.0.0.5:8006/api2/json')

    def test_base_url_custom_port_preserved(self):
        self.assertEqual(px._base_url('pve:9999'),
                         'https://pve:9999/api2/json')

    def test_auth_header_format(self):
        h = px._auth_header('root@pam!rp', 'sekret')
        self.assertEqual(h, 'PVEAPIToken=root@pam!rp=sekret')


# ─── proxmox_client: config ─────────────────────────────────────────────


class TestProxmoxConfig(unittest.TestCase):

    def test_config_from_empty(self):
        pc = px.config_from({})
        self.assertFalse(pc['enabled'])
        self.assertEqual(pc['host'], '')
        # TLS verification defaults ON
        self.assertTrue(pc['verify_tls'])

    def test_config_from_full(self):
        pc = px.config_from({
            'proxmox_enabled': True,
            'proxmox_host': 'pve',
            'proxmox_node': 'pve',
            'proxmox_token_id': 'root@pam!rp',
            'proxmox_token_secret': 's',
            'proxmox_verify_tls': False,
        })
        self.assertTrue(pc['enabled'])
        self.assertFalse(pc['verify_tls'])

    def test_is_configured(self):
        self.assertFalse(px.is_configured(px.config_from({})))
        self.assertTrue(px.is_configured(px.config_from({
            'proxmox_host': 'pve', 'proxmox_node': 'pve',
            'proxmox_token_id': 't', 'proxmox_token_secret': 's',
        })))
        # Missing secret → not configured
        self.assertFalse(px.is_configured(px.config_from({
            'proxmox_host': 'pve', 'proxmox_node': 'pve',
            'proxmox_token_id': 't',
        })))


# ─── proxmox_client: guest normalisation ────────────────────────────────


class TestProxmoxGuest(unittest.TestCase):

    def test_norm_qemu_running(self):
        g = px._norm_guest({
            'vmid': 100, 'name': 'web01', 'status': 'running',
            'cpu': 0.25, 'mem': 1073741824, 'maxmem': 2147483648,
            'uptime': 3600,
        }, 'qemu')
        self.assertEqual(g['vmid'], 100)
        self.assertEqual(g['type'], 'qemu')
        self.assertEqual(g['cpu_percent'], 25.0)
        self.assertEqual(g['mem_percent'], 50.0)

    def test_norm_lxc_stopped(self):
        g = px._norm_guest({
            'vmid': 200, 'name': 'ct1', 'status': 'stopped',
        }, 'lxc')
        self.assertEqual(g['type'], 'lxc')
        self.assertEqual(g['status'], 'stopped')

    def test_norm_missing_vmid_dropped(self):
        self.assertIsNone(px._norm_guest({'name': 'x'}, 'qemu'))

    def test_norm_no_name_falls_back(self):
        g = px._norm_guest({'vmid': 5, 'status': 'running'}, 'lxc')
        self.assertEqual(g['name'], 'lxc-5')

    def test_norm_bad_input(self):
        self.assertIsNone(px._norm_guest('not a dict', 'qemu'))
        self.assertIsNone(px._norm_guest(None, 'qemu'))


# ─── proxmox_client: action allow-list ──────────────────────────────────


class TestProxmoxActionGate(unittest.TestCase):

    def _pc(self):
        return px.config_from({
            'proxmox_host': 'pve', 'proxmox_node': 'pve',
            'proxmox_token_id': 't', 'proxmox_token_secret': 's',
        })

    def test_allowed_actions_list(self):
        # The UI uses start/shutdown/status; stop is allowed for a
        # future force-stop. delete/migrate/clone must NOT be present.
        self.assertEqual(set(px.ALLOWED_VM_ACTIONS),
                         {'start', 'shutdown', 'stop', 'status'})

    def test_disallowed_action_rejected(self):
        for bad in ('delete', 'migrate', 'clone', 'destroy', ''):
            with self.assertRaises(px.ProxmoxError):
                px.guest_action(self._pc(), 'qemu', 100, bad)

    def test_unknown_guest_type_rejected(self):
        with self.assertRaises(px.ProxmoxError):
            px.guest_action(self._pc(), 'wibble', 100, 'start')

    def test_bad_vmid_rejected(self):
        with self.assertRaises(px.ProxmoxError):
            px.guest_action(self._pc(), 'qemu', 'not-a-number', 'start')

    def test_list_unknown_guest_type_rejected(self):
        with self.assertRaises(px.ProxmoxError):
            px.list_guests(self._pc(), 'wibble')


# ─── proxmox_client: connection test failure handling ───────────────────


class TestProxmoxConnTest(unittest.TestCase):

    def test_test_connection_unconfigured(self):
        # Never raises — returns ok:false with a message
        r = px.test_connection(px.config_from({}))
        self.assertFalse(r['ok'])
        self.assertIn('required', r['message'].lower())


# ─── api.py wiring: config get masks secret, save round-trips ───────────


class TestProxmoxApiWiring(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault('REQUEST_METHOD', 'GET')
        os.environ.setdefault('PATH_INFO', '/')
        os.environ.setdefault('CONTENT_LENGTH', '0')
        _s = importlib.util.spec_from_file_location("api_v230", _CGI_BIN / "api.py")
        cls.api = importlib.util.module_from_spec(_s)
        _s.loader.exec_module(cls.api)

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        self.api.CONFIG_FILE = self._tmp / 'config.json'

    def test_config_get_masks_token_secret(self):
        api = self.api
        api.save(api.CONFIG_FILE, {
            'proxmox_enabled': True,
            'proxmox_host': 'pve',
            'proxmox_token_id': 'root@pam!rp',
            'proxmox_token_secret': 'SUPERSECRET',
        })
        captured = {}
        def fake_respond(status, body):
            captured['body'] = body
            raise SystemExit(0)
        api.respond = fake_respond
        api.require_auth = lambda **kw: 'admin'
        try:
            api.handle_config_get()
        except SystemExit:
            pass
        body = captured['body']
        # The raw secret must never be in the response
        self.assertNotIn('proxmox_token_secret', body)
        # But the UI is told one is set
        self.assertTrue(body['proxmox_token_secret_set'])
        # Non-secret fields come through
        self.assertEqual(body['proxmox_host'], 'pve')
        self.assertEqual(body['proxmox_token_id'], 'root@pam!rp')

    def test_config_get_no_secret(self):
        api = self.api
        api.save(api.CONFIG_FILE, {'proxmox_enabled': False})
        captured = {}
        def fake_respond(status, body):
            captured['body'] = body
            raise SystemExit(0)
        api.respond = fake_respond
        api.require_auth = lambda **kw: 'admin'
        try:
            api.handle_config_get()
        except SystemExit:
            pass
        self.assertFalse(captured['body']['proxmox_token_secret_set'])

    def test_config_save_roundtrip(self):
        api = self.api
        api.save(api.CONFIG_FILE, {})
        body = {
            'proxmox_enabled': True,
            'proxmox_host': 'pve.example.com',
            'proxmox_node': 'pve',
            'proxmox_token_id': 'root@pam!rp',
            'proxmox_token_secret': 'thesecret',
            'proxmox_verify_tls': False,
        }
        api.require_admin_auth = lambda **kw: 'admin'
        api.method = lambda: 'POST'
        api.get_json_body = lambda: body
        try:
            api.handle_config_save()
        except SystemExit:
            pass
        cfg = api.load(api.CONFIG_FILE)
        self.assertTrue(cfg['proxmox_enabled'])
        self.assertEqual(cfg['proxmox_host'], 'pve.example.com')
        self.assertEqual(cfg['proxmox_token_secret'], 'thesecret')
        self.assertFalse(cfg['proxmox_verify_tls'])

    def test_config_save_blank_secret_preserves(self):
        # Omitting the secret key keeps the existing one; '' clears it.
        api = self.api
        api.save(api.CONFIG_FILE, {'proxmox_token_secret': 'original'})
        api.require_admin_auth = lambda **kw: 'admin'
        api.method = lambda: 'POST'
        # Save without the secret key → preserved
        api.get_json_body = lambda: {'proxmox_host': 'newhost'}
        try:
            api.handle_config_save()
        except SystemExit:
            pass
        self.assertEqual(api.load(api.CONFIG_FILE)['proxmox_token_secret'],
                         'original')
        # Save with empty string → cleared
        api.get_json_body = lambda: {'proxmox_token_secret': ''}
        try:
            api.handle_config_save()
        except SystemExit:
            pass
        self.assertNotIn('proxmox_token_secret', api.load(api.CONFIG_FILE))


# ─── frontend asset presence ─────────────────────────────────────────────


class TestProxmoxAssets(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.js   = client_js()
        cls.html = (_ROOT / 'server/html/index.html').read_text()

    def test_virtualization_page_exists(self):
        self.assertIn('id="page-virtualization"', self.html)
        self.assertIn('nav-virtualization', self.html)

    def test_proxmox_settings_pane_exists(self):
        self.assertIn('id="settings-pane-proxmox"', self.html)
        self.assertIn('proxmox-token-secret', self.html)

    def test_lxc_section_on_containers_page(self):
        self.assertIn('containers-lxc-section', self.html)

    def test_virtualization_js_present(self):
        self.assertIn('function loadVirtualization', self.js)
        self.assertIn('function proxmoxAction', self.js)
        self.assertIn('function loadProxmoxLXC', self.js)

    def test_settings_js_present(self):
        self.assertIn('function saveProxmoxSettings', self.js)
        self.assertIn('function testProxmoxConnection', self.js)


if __name__ == '__main__':
    unittest.main(verbosity=2)
