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

    # v6.4.3: was three of the five copies. The two it did NOT cover were free
    # to diverge, and one had — see TestOneClassifierOnly below.
    MODULES = ('proxmox_client', 'routeros', 'opnsense', 'ai_provider')
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
        # the tickets subsystem lives in tickets_handlers.py (bound-module
        # pilot); the gate is A.require_write_role through the bound namespace.
        from srcpin import py_function
        tk_src = (CGI / 'tickets_handlers.py').read_text()
        body = py_function(tk_src, 'handle_ticket_send_email')
        self.assertIn('require_write_role', body)

    def test_pg_device_fast_paths_take_shared_whole_store_lock(self):
        # DeviceTxn + upsert_device must take the SHARED whole-store advisory
        # lock so they serialize against a whole-store reconcile-save.
        self.assertEqual(
            self.pg_src.count('DEVICES_FILE_NAME, self.non_blocking, shared=True'),
            1, 'DeviceTxn must take shared whole-store lock')
        self.assertIn('DEVICES_FILE_NAME, False, shared=True', self.pg_src)
        self.assertIn('pg_advisory_xact_lock_shared', self.pg_src)

    def test_mailbox_ingest_uses_single_row_update(self):
        m = re.search(r'def _ingest_mailbox_counts\(.*?\n(.*?)for _ev, payload in to_fire',
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


class TestOneClassifierOnly(unittest.TestCase):
    """Five hand-rolled copies of the SSRF peer-IP classifier, one guard over
    three of them. The two uncovered copies were free to diverge and one did.

    `ai_provider` tested `is_reserved` BEFORE loopback. `::1` is both, so with
    `allow_loopback=True` — which `insecure_ssl` sets, and which exists exactly
    so an operator can point the AI at a local Ollama — the reserved test fired
    first and blocked it. The identical setup on `127.0.0.1` worked. api.py's
    canonical version carries a comment about precisely this ordering; the copy
    had lost it.

    So these tests do not check that the copies AGREE — they check there are no
    copies. A behavioural guard over N implementations can only ever catch the
    drift it thought to test for.
    """

    FORKED = ('api', 'ai_provider', 'opnsense', 'routeros', 'proxmox_client',
              # v6.4.3: tls_monitor was outside this list and still carried its
              # own copy of the IPv6 unwrapping AND its own literal metadata-IP
              # set. Being outside the list is what let the previous two copies
              # drift; leaving a sixth outside it for the same reason would
              # repeat the mistake exactly.
              'tls_monitor')

    # Modules that classify IPs under a DELIBERATELY different policy and so
    # cannot call blocked(). They must still delegate the policy-free half —
    # the unwrapping and the metadata set — which is what FORKED enforces.
    # Listed here so the difference is a declaration rather than an omission.
    SEPARATE_POLICY = {
        'tls_monitor': 'allows loopback and RFC1918: probing an internal or '
                       'same-host cert is the feature, and the probe reads '
                       'cert metadata only',
        'dns_resolve': 'stricter — also blocks private ranges',
    }

    def _src(self, name):
        return (CGI / f'{name}.py').read_text()

    def test_no_module_reimplements_the_classification(self):
        """The tells are the constants. Any module that names a metadata IP or
        unwraps the NAT64 prefix itself is classifying, not delegating."""
        offenders = []
        for name in self.FORKED:
            src = self._src(name)
            for tell in ('0x0064ff9b', 'ipv4_mapped', "'100.100.100.200'",
                         "'192.0.0.192'", "'fd00:ec2::254'"):
                if tell in src:
                    offenders.append(f'{name}: still contains {tell}')
        self.assertEqual(offenders, [], '\n'.join(
            ['these modules re-implement the SSRF classifier instead of '
             'calling ssrf_ip:'] + offenders))

    def test_each_one_actually_calls_the_shared_module(self):
        for name in self.FORKED:
            with self.subTest(module=name):
                self.assertIn('ssrf_ip.', self._src(name),
                              f'{name} names no ssrf_ip call — if its outbound '
                              'feature was removed, drop it from FORKED')

    def test_the_shared_module_decides_loopback_before_reserved(self):
        """The exact ordering the drifted copy had lost. `::1` must track
        `127.0.0.1` in both directions, or a local AI provider over IPv6 is
        unreachable while the v4 one works."""
        import ssrf_ip
        for ip in ('127.0.0.1', '::1'):
            with self.subTest(ip=ip):
                self.assertTrue(ssrf_ip.blocked(ip, allow_loopback=False))
                self.assertFalse(ssrf_ip.blocked(ip, allow_loopback=True))

    def test_a_separate_policy_module_still_delegates_the_primitives(self):
        """A different POLICY is legitimate; a different unwrap is not. The
        encodings that smuggle an IPv4 past a v6 check, and the list of cloud
        metadata endpoints, are facts about the internet rather than choices —
        a second copy of either is a second thing to update when a new
        encoding or a new cloud appears, and nothing would compare them."""
        for name in self.SEPARATE_POLICY:
            src = self._src(name)
            if 'ipaddress' not in src:
                continue
            with self.subTest(module=name):
                for tell in ('0x0064ff9b', "'100.100.100.200'",
                             "'192.0.0.192'", "'fd00:ec2::254'"):
                    self.assertNotIn(
                        tell, src,
                        f'{name} keeps its own copy of {tell} — its policy may '
                        'differ, but the unwrapping and the metadata set must '
                        'come from ssrf_ip')

    def test_every_separate_policy_module_documents_why(self):
        """An undocumented exemption is indistinguishable from an oversight —
        which is precisely what tls_monitor was until this release."""
        for name, reason in self.SEPARATE_POLICY.items():
            with self.subTest(module=name):
                self.assertTrue(reason.strip(), f'{name} has no stated reason')
                self.assertTrue((CGI / f'{name}.py').exists())

    def test_the_shared_module_is_a_leaf(self):
        """The objection in the old ai_provider comment — "can't import api
        here, circular" — was true of api and is why the copies existed. It
        must never become true of this module."""
        import ast
        tree = ast.parse(self._src('ssrf_ip'))
        imported = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                imported |= {a.name.split('.')[0] for a in n.names}
            elif isinstance(n, ast.ImportFrom) and n.module:
                imported.add(n.module.split('.')[0])
        self.assertEqual(imported, {'ipaddress'},
                         f'ssrf_ip must stay importable from anywhere; it now '
                         f'imports {sorted(imported)}')
