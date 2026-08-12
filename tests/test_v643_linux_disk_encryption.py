#!/usr/bin/env python3
"""Linux at-rest encryption, from the agent's sysfs read to the SOC 2 control.

`_encryption_at_rest_control` covered BitLocker and FileVault. Linux was never
collected, so on an ALL-LINUX FLEET — the common RemotePower deployment — the
encryption-at-rest control returned NOT ASSESSED permanently, and no amount of
actual encryption could change that. The control's own docstring recorded the
gap, which is how a known hole survives: written down, never closed.

This is the CLAUDE.md dead-signal checklist run forwards instead of backwards.
Rather than asking "is it wired?", each layer is exercised in turn, because the
failure modes are all silent:

  1. the agent COLLECTS it (verified against the real machine this runs on,
     not a fixture — a fixture encodes what I assumed the kernel exposes)
  2. `safe_si` PERSISTS it (a field the agent sends but safe_si drops never
     reaches any consumer, and nothing anywhere reports the drop)
  3. the Checks engine RENDERS a row
  4. the fleet-fact builders COUNT it — BOTH of them, api.py's and
     reports_handlers.py's, which are the same logic maintained twice
  5. the compliance control CHANGES VERDICT because of it

Absence-is-not-evidence is asserted throughout: the agent returns {} rather
than encrypted:False when it cannot see device-mapper, so a host that cannot
answer stays NOT ASSESSED instead of becoming a false FAIL. Getting that
backwards would turn a blind spot into a compliance failure on hosts that are
in fact encrypted.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v643enc-'))

_spec = importlib.util.spec_from_file_location('api_v643_enc', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules.setdefault('api', api)
_spec.loader.exec_module(api)

import checks as checks_mod          # noqa: E402
import compliance                    # noqa: E402


def _agent():
    """The real Linux agent module, loaded without running main()."""
    spec = importlib.util.spec_from_file_location(
        'rp_agent_enc', _ROOT / 'client' / 'remotepower-agent.py')
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except SystemExit:
        pass
    return mod


_LUKS_SI = {
    'disk_encryption': {
        'encrypted': True,
        'crypt_devices': [{'dm': 'dm-0', 'name': 'luks-root', 'type': 'LUKS2'}],
        'crypt_count': 1,
        'dm_count': 1,
        'encrypted_mounts': ['/', '/home', '/var/log'],
    }
}
_PLAIN_SI = {'disk_encryption': {'encrypted': False, 'crypt_devices': [],
                                 'crypt_count': 0, 'dm_count': 2}}


class TestTheAgentCollectsIt(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ag = _agent()

    def test_the_collector_exists_and_returns_a_dict(self):
        out = self.ag.get_disk_encryption()
        self.assertIsInstance(out, dict)

    def test_it_reads_sysfs_not_a_subprocess(self):
        """`lsblk`/`cryptsetup` output changes between distro versions and
        cryptsetup needs root. sysfs publishes the dm target directly."""
        import ast
        import inspect
        # STRIP THE DOCSTRING FIRST. It contains the phrase "no subprocess",
        # so the assertion below matched the sentence explaining the design
        # instead of the code implementing it — and failed against the correct
        # implementation. Same trap as the alert-params test in this release;
        # twice in one session is a habit, not an accident.
        tree = ast.parse(inspect.getsource(self.ag.get_disk_encryption))
        fn = tree.body[0]
        if (fn.body and isinstance(fn.body[0], ast.Expr)
                and isinstance(fn.body[0].value, ast.Constant)):
            fn.body.pop(0)
        src = ast.unparse(fn)
        self.assertIn('/sys/block', src)
        self.assertNotIn('subprocess', src)
        self.assertIn('host_path(', src,
                      'a host fact read without host_path() reads the slim '
                      'container image instead of the host')

    def test_it_reports_nothing_rather_than_false_when_it_cannot_see(self):
        """The load-bearing case. Reporting encrypted:False for a host with no
        visible device-mapper would make every container and many VMs a
        compliance FAILURE on a control they may well satisfy."""
        orig = self.ag.host_path
        self.ag.host_path = lambda p: '/nonexistent-for-this-test'
        try:
            self.assertEqual(self.ag.get_disk_encryption(), {})
        finally:
            self.ag.host_path = orig

    def test_on_this_machine_it_agrees_with_the_kernel(self):
        """Verified against the REAL host rather than a fixture — a fixture
        encodes what I assumed sysfs looks like, which is precisely the
        assumption under test. Skips where there is no device-mapper."""
        blocks = Path('/sys/block')
        if not blocks.exists():
            self.skipTest('no /sys/block on this platform')
        dm = sorted(p for p in os.listdir(blocks) if p.startswith('dm-'))
        if not dm:
            self.skipTest('no device-mapper devices on this host')
        expected = False
        for d in dm:
            try:
                uuid = (blocks / d / 'dm' / 'uuid').read_text().strip()
            except OSError:
                continue
            if uuid.startswith('CRYPT-'):
                expected = True
        out = self.ag.get_disk_encryption()
        self.assertEqual(out.get('encrypted'), expected,
                         f'collector disagrees with sysfs for {dm}')


class TestSafeSiPersistsIt(unittest.TestCase):
    """A field the agent sends that safe_si drops is silently gone — no error,
    no log, and every downstream consumer just sees nothing.

    Drives the REAL handle_heartbeat rather than grepping for the whitelist
    branch: a grep proves a line exists, never that the value survives it, and
    the sanitiser is inline in the handler so there is no function to call.
    """

    def setUp(self):
        tmp = Path(tempfile.mkdtemp(prefix='rp-v643enc-hb-'))
        self._saved = (api.DEVICES_FILE, api.CONFIG_FILE, api.respond)
        api.DEVICES_FILE = tmp / 'devices.json'
        api.CONFIG_FILE = tmp / 'config.json'
        api.save(api.CONFIG_FILE, {})
        api.save(api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'web01',
                                           'token': 'tok', 'monitored': True}})
        api.respond = lambda status, body: (_ for _ in ()).throw(SystemExit(0))

    def tearDown(self):
        api.DEVICES_FILE, api.CONFIG_FILE, api.respond = self._saved

    def _beat(self, si):
        api.get_json_body = lambda: {'device_id': 'd1', 'token': 'tok',
                                     'sysinfo': si}
        api.method = lambda: 'POST'
        try:
            api.handle_heartbeat()
        except SystemExit:
            pass
        api._invalidate_load_cache(api.DEVICES_FILE)
        stored = api.load(api.DEVICES_FILE)['d1']
        return (stored.get('sysinfo') or {}).get('disk_encryption')

    def test_the_value_survives_the_heartbeat_sanitiser(self):
        out = self._beat(dict(_LUKS_SI))
        self.assertIsNotNone(out, 'safe_si dropped disk_encryption — it never '
                                  'reaches a check, the UI or compliance, and '
                                  'nothing reports the drop')
        self.assertIs(out.get('encrypted'), True)
        self.assertEqual(out.get('encrypted_mounts'), ['/', '/home', '/var/log'])
        self.assertEqual(out['crypt_devices'][0]['type'], 'LUKS2')

    def test_an_unencrypted_report_survives_too(self):
        """encrypted:False is the FINDING. If only the True case persisted, an
        unencrypted fleet would read as "nobody reported" — a silent PASS-ish
        NA instead of a FAIL."""
        out = self._beat(dict(_PLAIN_SI))
        self.assertIsNotNone(out)
        self.assertIs(out.get('encrypted'), False)

    def test_a_hostile_agent_cannot_smuggle_junk_through(self):
        """safe_si is a sanitiser, not just a filter: an agent is a
        semi-trusted input and this value renders into the Checks page."""
        out = self._beat({'disk_encryption': {
            'encrypted': True,
            'crypt_count': 10 ** 9,
            'crypt_devices': [{'dm': 'x' * 400, 'name': '<img src=x>' * 40,
                               'type': 'y' * 200}] * 100,
            'encrypted_mounts': ['/m'] * 500,
            'unexpected_key': 'dropped',
        }})
        self.assertNotIn('unexpected_key', out)
        self.assertLessEqual(out['crypt_count'], 4096)
        self.assertLessEqual(len(out['crypt_devices']), 16)
        self.assertLessEqual(len(out['encrypted_mounts']), 32)
        self.assertLessEqual(len(out['crypt_devices'][0]['name']), 64)


class TestTheChecksEngineRendersARow(unittest.TestCase):
    def _rows(self, si):
        # v6.4.3 (reported from use): the check became OPT-IN after an operator
        # pointed out that an unencrypted Linux root is the norm, not a finding.
        # These cases describe what the check REPORTS once enabled; the
        # off-by-default contract lives in test_v643_ux_reported.py.
        dev = {'name': 'web01', 'os': 'Debian GNU/Linux 12', 'sysinfo': si}
        rows = api._host_checks('d1', dev, disk_encryption=True)
        return {r.get('key'): r for r in rows if isinstance(r, dict)}

    def test_an_encrypted_host_shows_ok(self):
        row = self._rows(dict(_LUKS_SI)).get('linux_disk_encryption')
        self.assertIsNotNone(row, 'no LUKS row rendered')
        self.assertEqual(row.get('status'), 'ok')
        self.assertIn('LUKS2', str(row.get('output', '')))

    def test_an_unencrypted_host_warns(self):
        row = self._rows(dict(_PLAIN_SI)).get('linux_disk_encryption')
        self.assertIsNotNone(row)
        self.assertEqual(row.get('status'), 'warning')

    def test_a_host_that_did_not_report_shows_no_row_at_all(self):
        """Not an empty row, not an 'unknown' row — nothing. An empty security
        row reads as a finding to anyone scanning the page."""
        self.assertNotIn('linux_disk_encryption', self._rows({}))


class TestTheComplianceControlChangesVerdict(unittest.TestCase):
    def test_a_linux_only_fleet_used_to_be_stuck_at_not_assessed(self):
        """The bug, stated as a test: no encryption facts at all -> NA."""
        status, _msg = compliance._encryption_at_rest_control({})
        self.assertEqual(status, compliance.NOT_ASSESSED)

    def test_an_encrypted_linux_fleet_now_passes(self):
        status, msg = compliance._encryption_at_rest_control(
            {'encryption_data_devices': 3, 'encryption_off': []})
        self.assertEqual(status, compliance.PASS, msg)

    def test_an_unencrypted_linux_host_now_fails(self):
        status, msg = compliance._encryption_at_rest_control(
            {'encryption_data_devices': 3, 'encryption_off': ['web01']})
        self.assertEqual(status, compliance.FAIL)
        self.assertIn('web01', msg)

    def test_the_na_message_names_luks(self):
        _s, msg = compliance._encryption_at_rest_control({})
        self.assertIn('LUKS', msg,
                      'the NA message tells an operator what would satisfy '
                      'the control — it must name the Linux mechanism too')


class TestBothFactBuildersCountIt(unittest.TestCase):
    """api.py and reports_handlers.py build the SAME facts in two places. A
    sweep like this one always updates the first and forgets the second."""

    def test_both_builders_read_disk_encryption(self):
        srcs = {
            'api.py': (_CGI / 'api.py').read_text(),
            'reports_handlers.py': (_CGI / 'reports_handlers.py').read_text(),
        }
        for name, src in srcs.items():
            self.assertIn("si.get('disk_encryption')", src,
                          f'{name} scores encryption-at-rest but does not '
                          'consider Linux, so the same fleet gets two '
                          'different answers depending which page you open')


if __name__ == '__main__':
    unittest.main()
