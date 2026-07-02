"""Guardrail tests for the v5.7.0 bughunt + performance sweep.

Covers the durable invariants introduced by that sweep so they can't silently
regress:

* SSRF: the three hand-rolled device-client peer-IP classifiers block the cloud
  instance-metadata endpoints and IPv6-embedded-IPv4 forms (parity with the
  canonical api._ip_class_blocked).
* Backup export redacts the WHOLE config-secret surface, not just three keys.
* /api/tenants* is gated on a platform superadmin, not any admin.
* Per-heartbeat write-amplification: mailbox ingest uses a single-row update.
* Postgres device lock-scope: the per-device fast paths take the shared
  whole-store advisory lock.
"""
import importlib.util
import io
import os
import re
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CGI = HERE.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(CGI))


class TestSSRFClassifiers(unittest.TestCase):
    """proxmox_client / routeros / opnsense each hand-roll _peer_ip_blocked;
    the sweep hardened all three to match api._ip_class_blocked."""

    MODULES = ('proxmox_client', 'routeros', 'opnsense')
    # Endpoints an SSRF attacker targets that a naive is_link_local check misses.
    METADATA = ('fd00:ec2::254', '100.100.100.200', '192.0.0.192')
    # IPv6 forms embedding the v4 metadata IP 169.254.169.254.
    WRAPPED = ('::ffff:169.254.169.254', '2002:a9fe:a9fe::',
               '64:ff9b::a9fe:a9fe')

    def _mod(self, name):
        return importlib.import_module(name)

    def test_metadata_ips_blocked(self):
        for name in self.MODULES:
            m = self._mod(name)
            for ip in self.METADATA:
                self.assertTrue(m._peer_ip_blocked(ip),
                                f'{name} must block metadata IP {ip}')

    def test_ipv6_embedded_v4_metadata_blocked(self):
        for name in self.MODULES:
            m = self._mod(name)
            for ip in self.WRAPPED:
                self.assertTrue(m._peer_ip_blocked(ip),
                                f'{name} must unwrap+block {ip}')

    def test_link_local_still_blocked(self):
        for name in self.MODULES:
            m = self._mod(name)
            self.assertTrue(m._peer_ip_blocked('169.254.169.254'))
            self.assertTrue(m._peer_ip_blocked('0.0.0.0'))

    def test_lan_and_public_allowed(self):
        # RFC1918 LAN + a normal public host must stay reachable (these are LAN
        # devices / legit external targets).
        for name in self.MODULES:
            m = self._mod(name)
            self.assertFalse(m._peer_ip_blocked('192.168.1.10'))
            self.assertFalse(m._peer_ip_blocked('10.0.0.5'))
            self.assertFalse(m._peer_ip_blocked('93.184.216.34'))


class TestTlsMonitorMetadata(unittest.TestCase):
    def test_metadata_blocked_loopback_allowed(self):
        import tls_monitor
        for ip in ('fd00:ec2::254', '100.100.100.200', '192.0.0.192',
                   '169.254.169.254', '::ffff:169.254.169.254'):
            self.assertTrue(tls_monitor._addr_blocked(ip), ip)
        # loopback is intentionally allowed for same-host cert monitoring
        self.assertFalse(tls_monitor._addr_blocked('127.0.0.1'))
        self.assertFalse(tls_monitor._addr_blocked('192.168.1.1'))


class TestSourcePins(unittest.TestCase):
    """Cheap source-level pins for wiring that has no isolated unit seam."""

    @classmethod
    def setUpClass(cls):
        cls.api_src = (CGI / 'api.py').read_text()
        cls.pg_src = (CGI / 'storage_pg.py').read_text()

    def test_tenant_handlers_require_superadmin(self):
        # Every /api/tenants* handler must gate on require_superadmin_auth, not
        # the tenant-agnostic require_admin_auth (privilege-escalation guard).
        for fn in ('handle_tenants_list', 'handle_tenant_create',
                   'handle_tenant_update', 'handle_tenant_delete',
                   'handle_tenant_assign_user'):
            m = re.search(r'def ' + fn + r'\(.*?\n(.*?)\n\n', self.api_src,
                          re.S)
            self.assertIsNotNone(m, fn)
            body = m.group(1)
            self.assertIn('require_superadmin_auth', body,
                          f'{fn} must gate on require_superadmin_auth')

    def test_batch_jobs_clear_requires_write_role(self):
        m = re.search(r'def handle_batch_jobs_clear\(.*?\n(.*?)\n\n',
                      self.api_src, re.S)
        self.assertIn('require_write_role', m.group(1))

    def test_ticket_email_requires_write_role(self):
        m = re.search(r'def handle_ticket_send_email\(.*?\n(.*?)save\(',
                      self.api_src, re.S)
        self.assertIn('require_write_role', m.group(1))

    def test_pg_device_fast_paths_take_shared_whole_store_lock(self):
        # DeviceTxn + upsert_device must take the SHARED whole-store advisory
        # lock so they serialize against a whole-store reconcile-save.
        self.assertEqual(
            self.pg_src.count('DEVICES_FILE_NAME, self.non_blocking, shared=True'),
            1, 'DeviceTxn must take shared whole-store lock')
        self.assertIn('DEVICES_FILE_NAME, False, shared=True', self.pg_src)
        self.assertIn('pg_advisory_xact_lock_shared', self.pg_src)

    def test_mailbox_ingest_uses_single_row_update(self):
        m = re.search(r'def _ingest_mailbox_counts\(.*?\n(.*?)for payload in to_fire',
                      self.api_src, re.S)
        self.assertIsNotNone(m)
        self.assertIn('with _DeviceUpdate(dev_id) as devices:', m.group(1))
        # The whole-store lock statement must be gone (the string also appears in
        # an explanatory comment, so match the `with` form specifically).
        self.assertNotIn('with _LockedUpdate(DEVICES_FILE)', m.group(1))


class TestExportRedaction(unittest.TestCase):
    """The backup export must redact the full config-secret surface."""

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())
        os.environ.setdefault('REQUEST_METHOD', 'GET')
        os.environ.setdefault('PATH_INFO', '/')
        os.environ.setdefault('CONTENT_LENGTH', '0')
        spec = importlib.util.spec_from_file_location('api_export_t',
                                                      CGI / 'api.py')
        cls.api = importlib.util.module_from_spec(spec)
        sys.modules['api_export_t'] = cls.api
        spec.loader.exec_module(cls.api)

    def _export_config(self, cfg):
        api = self.api
        tmp = Path(tempfile.mkdtemp())
        api.DATA_DIR = tmp
        api.save(tmp / 'config.json', cfg)
        captured = {}

        def _fake_admin(*a, **k):
            return 'admin'

        orig_admin = api.require_admin_auth
        orig_audit = api.audit_log
        orig_backup = getattr(api, '_run_data_backup', None)
        api.require_admin_auth = _fake_admin
        api.audit_log = lambda *a, **k: None
        if orig_backup is not None:
            api._run_data_backup = lambda *a, **k: None
        # handle_export writes the ZIP to stdout.buffer and sys.exit(0)s.
        real_stdout = sys.stdout
        buf_out = io.BytesIO()

        class _W:
            def __init__(self, b):
                self.buffer = b

            def write(self, *a, **k):
                pass

            def flush(self):
                pass
        sys.stdout = _W(buf_out)
        try:
            api.handle_export()
        except SystemExit:
            pass
        finally:
            sys.stdout = real_stdout
            api.require_admin_auth = orig_admin
            api.audit_log = orig_audit
            if orig_backup is not None:
                api._run_data_backup = orig_backup
        raw = buf_out.getvalue()
        # strip the CGI header block before the ZIP
        idx = raw.find(b'PK\x03\x04')
        self.assertGreaterEqual(idx, 0, 'no ZIP payload produced')
        return raw[idx:]

    def test_expanded_secret_surface_redacted(self):
        secrets = {
            'server_name': 'rp',
            'ai': {'api_key': 'AISECRET'},
            'oidc_client_secret': 'OIDCSECRET',
            'agentless_ssh_key': 'SSHPRIVATEKEY',
            'status_token': 'STATUSTOKEN',
            'siem_token': 'SIEMTOKEN',
            'vapid_private_key': 'VAPIDKEY',
            'webhook_urls': [{'url': 'https://hooks.slack.com/services/T/B/XSECRET'}],
            'cloud_accounts': [{'provider': 'aws', 'secret_key': 'CLOUDSECRET'}],
            'registry_credentials': {'ghcr': {'username': 'u', 'password': 'REGPW'}},
            'gitops': {'auth_header': 'Bearer GITOPSSECRET'},
        }
        zip_bytes = self._export_config(secrets)
        for leaked in (b'AISECRET', b'OIDCSECRET', b'SSHPRIVATEKEY',
                       b'STATUSTOKEN', b'SIEMTOKEN', b'VAPIDKEY', b'XSECRET',
                       b'CLOUDSECRET', b'REGPW', b'GITOPSSECRET'):
            self.assertNotIn(leaked, zip_bytes,
                             f'{leaked!r} leaked into the backup ZIP')
        # non-secret field survives
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            import json
            cfg = json.loads(zf.read('config.json'))
        self.assertEqual(cfg['server_name'], 'rp')


if __name__ == '__main__':
    unittest.main()
