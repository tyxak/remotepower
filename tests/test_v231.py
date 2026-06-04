#!/usr/bin/env python3
"""
Tests for v2.3.1 — Proxmox token secret hardening.

  - The token secret can be supplied via the RP_PROXMOX_TOKEN_SECRET
    environment variable, which takes precedence over config.json.
  - The backup export redacts secret fields from config.json (the
    Proxmox token, SMTP password, LDAP bind password) — before
    2.3.1 a backup ZIP carried live credentials.
"""

import sys as _cj_sys
from pathlib import Path as _cj_Path
_cj_sys.path.insert(0, str(_cj_Path(__file__).resolve().parent))
from clientjs import client_js
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

_ROOT    = Path(__file__).parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

_spec = importlib.util.spec_from_file_location("proxmox_v231", _CGI_BIN / "proxmox_client.py")
px = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(px)


class TestEnvTokenOverride(unittest.TestCase):

    def tearDown(self):
        os.environ.pop('RP_PROXMOX_TOKEN_SECRET', None)

    def test_env_var_takes_precedence(self):
        os.environ['RP_PROXMOX_TOKEN_SECRET'] = 'from-env'
        pc = px.config_from({'proxmox_token_secret': 'from-config'})
        self.assertEqual(pc['token_secret'], 'from-env')
        self.assertTrue(pc['token_secret_from_env'])

    def test_config_used_when_no_env(self):
        os.environ.pop('RP_PROXMOX_TOKEN_SECRET', None)
        pc = px.config_from({'proxmox_token_secret': 'from-config'})
        self.assertEqual(pc['token_secret'], 'from-config')
        self.assertFalse(pc['token_secret_from_env'])

    def test_empty_env_var_falls_back(self):
        # An empty / whitespace env var must not shadow a real config value
        os.environ['RP_PROXMOX_TOKEN_SECRET'] = '   '
        pc = px.config_from({'proxmox_token_secret': 'from-config'})
        self.assertEqual(pc['token_secret'], 'from-config')
        self.assertFalse(pc['token_secret_from_env'])

    def test_env_var_makes_configured(self):
        # Host/node/token-id in config + secret in env → fully configured
        os.environ['RP_PROXMOX_TOKEN_SECRET'] = 'from-env'
        pc = px.config_from({
            'proxmox_host': 'pve', 'proxmox_node': 'pve',
            'proxmox_token_id': 'root@pam!rp',
        })
        self.assertTrue(px.is_configured(pc))


class TestBackupRedaction(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault('REQUEST_METHOD', 'GET')
        os.environ.setdefault('PATH_INFO', '/')
        os.environ.setdefault('CONTENT_LENGTH', '0')
        _s = importlib.util.spec_from_file_location("api_v231", _CGI_BIN / "api.py")
        cls.api = importlib.util.module_from_spec(_s)
        _s.loader.exec_module(cls.api)

    def _run_export(self):
        """Run handle_export, capture the ZIP bytes it writes to stdout."""
        api = self.api
        api.require_admin_auth = lambda **kw: 'admin'
        buf = io.BytesIO()
        real_stdout = sys.stdout
        real_buffer = real_stdout.buffer if hasattr(real_stdout, 'buffer') else None

        class _FakeStdout:
            def __init__(self): self.buffer = buf
            def write(self, *a, **k): pass
            def flush(self): pass
        sys.stdout = _FakeStdout()
        try:
            api.handle_export()
        except SystemExit:
            pass
        finally:
            sys.stdout = real_stdout
        return buf.getvalue()

    def test_config_secrets_redacted_in_backup(self):
        api = self.api
        tmp = Path(tempfile.mkdtemp())
        api.DATA_DIR = tmp
        # Write a config.json with all three secret fields populated
        # (via api.save so it lands in whichever backend is active).
        api.save(tmp / 'config.json', {
            'server_name': 'rp',
            'proxmox_token_secret': 'PROXMOXSECRET',
            'smtp_password': 'SMTPSECRET',
            'ldap_bind_password': 'LDAPSECRET',
        })
        zip_bytes = self._run_export()
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            self.assertIn('config.json', zf.namelist())
            cfg = json.loads(zf.read('config.json'))
        # Secrets are redacted...
        self.assertEqual(cfg['proxmox_token_secret'], '(redacted)')
        self.assertEqual(cfg['smtp_password'], '(redacted)')
        self.assertEqual(cfg['ldap_bind_password'], '(redacted)')
        # ...non-secret fields survive
        self.assertEqual(cfg['server_name'], 'rp')
        # The raw secret values appear NOWHERE in the ZIP
        self.assertNotIn(b'PROXMOXSECRET', zip_bytes)
        self.assertNotIn(b'SMTPSECRET', zip_bytes)
        self.assertNotIn(b'LDAPSECRET', zip_bytes)

    def test_backup_without_secrets_is_clean(self):
        # A config with no secret fields exports fine, nothing redacted
        api = self.api
        tmp = Path(tempfile.mkdtemp())
        api.DATA_DIR = tmp
        api.save(tmp / 'config.json', {'server_name': 'rp'})
        zip_bytes = self._run_export()
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            cfg = json.loads(zf.read('config.json'))
        self.assertEqual(cfg['server_name'], 'rp')
        self.assertNotIn('proxmox_token_secret', cfg)


class TestSettingsAssets(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.html = (_ROOT / 'server/html/index.html').read_text()
        cls.js   = client_js()

    def test_env_hint_in_settings(self):
        self.assertIn('RP_PROXMOX_TOKEN_SECRET', self.html)
        self.assertIn('proxmox-env-hint', self.html)

    def test_js_handles_env_sourced_secret(self):
        self.assertIn('proxmox_token_secret_from_env', self.js)


if __name__ == '__main__':
    unittest.main(verbosity=2)
