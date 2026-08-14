#!/usr/bin/env python3
"""An estate could pass every framework with sshd accepting root on a password.

The agent has reported resolved sshd posture — permit-root-login,
password-authentication, permit-empty-passwords — since v6.4.1, and the Security
Advisory's identity layer has read it since. `_compliance_facts()` did not, and
no control referenced it. PCI DSS 2.2.7, SOC 2 CC6.1 and Essential Eight E8-5
all concern hardened administrative access; all three were evidenced by other
things, so the one signal the product actually collects about remote
administrative access reached the compliance report nowhere.

Not a dead signal — it is read, alerted on and rendered. It just never reached
the surface an auditor reads, which for a compliance feature is the surface that
counts.

WHAT THIS PINS, and why each one:

* The fact is ASSEMBLED, not just consumed. A control reading `ssh_weak` from a
  facts dict that never carries it returns NA forever and looks deliberate.
* Present-and-bad only. A host that never reported sshd state must not appear
  as a finding. This is the exact mistake the encryption-at-rest control made on
  Linux for four releases — it read BitLocker and FileVault, found neither, and
  reported "not assessed" on a fully-encrypted estate. The inverse is worse:
  reporting every silent host as non-compliant.
* NA when nothing reported, not PASS. A fleet with no Linux hosts has not
  demonstrated hardened SSH; it has demonstrated nothing, and a green control
  there is a false assurance an auditor would rely on.
* The three framework mappings exist and point at this control.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-cra-'))

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

_spec = importlib.util.spec_from_file_location('api_cra', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import compliance  # noqa: E402

_HARDENED = {'permit_root_login': 'no', 'password_authentication': 'no',
             'permit_empty_passwords': 'no', 'source': '/etc/ssh/sshd_config'}


def _facts(devices):
    return api._compliance_facts(devices)


class TestTheFactIsAssembled(unittest.TestCase):
    """A control reading a key the facts builder never sets answers NA forever
    and looks like a deliberate scope decision."""

    def test_a_weak_host_reaches_the_facts(self):
        f = _facts({'d1': {'name': 'web01', 'sysinfo': {
            'ssh_config': dict(_HARDENED, permit_root_login='yes')}}})
        self.assertEqual(f['ssh_data_devices'], 1)
        self.assertEqual(len(f['ssh_weak']), 1)
        self.assertIn('web01', f['ssh_weak'][0])
        self.assertIn('root login', f['ssh_weak'][0])

    def test_a_hardened_host_counts_as_reporting_but_not_as_a_finding(self):
        f = _facts({'d1': {'name': 'web01', 'sysinfo': {'ssh_config': _HARDENED}}})
        self.assertEqual(f['ssh_data_devices'], 1)
        self.assertEqual(f['ssh_weak'], [])

    def test_each_weakness_is_named(self):
        f = _facts({'d1': {'name': 'web01', 'sysinfo': {'ssh_config': {
            'permit_root_login': 'yes', 'password_authentication': 'yes',
            'permit_empty_passwords': 'yes'}}}})
        row = f['ssh_weak'][0]
        for expect in ('root login with a password', 'password authentication',
                       'empty passwords'):
            self.assertIn(expect, row)

    def test_key_only_root_login_is_reported_but_not_a_failure(self):
        """`PermitRootLogin prohibit-password` permits root by KEY and is
        DEBIAN'S DEFAULT. Counting it as a failure would fail nearly every
        stock Debian host — a control that fires on every healthy machine, which
        is the guard-on-a-proxy shape CLAUDE.md records from the initramfs
        incident. It is a weaker posture than `no`, so it is surfaced as a note
        on the PASS rather than dropped."""
        f = _facts({'d1': {'name': 'web01', 'sysinfo': {
            'ssh_config': dict(_HARDENED, permit_root_login='prohibit-password')}}})
        self.assertEqual(f['ssh_weak'], [])
        self.assertEqual(f['ssh_keyonly_root'], ['web01'])
        st, msg = compliance._remote_access_control(f)
        self.assertEqual(st, compliance.PASS)
        self.assertIn('by KEY', msg)
        self.assertIn('web01', msg)
        self.assertIn('Debian default', msg)

    def test_a_root_password_is_a_failure(self):
        f = _facts({'d1': {'name': 'web01', 'sysinfo': {
            'ssh_config': dict(_HARDENED, permit_root_login='yes')}}})
        self.assertEqual(len(f['ssh_weak']), 1)
        self.assertEqual(f['ssh_keyonly_root'], [])
        self.assertEqual(compliance._remote_access_control(f)[0], compliance.FAIL)

    def test_permit_root_login_no_is_neither(self):
        """Positive control: the fully hardened case must produce no note at
        all, or the note is just noise on every install."""
        f = _facts({'d1': {'name': 'web01', 'sysinfo': {'ssh_config': _HARDENED}}})
        self.assertEqual(f['ssh_weak'], [])
        self.assertEqual(f['ssh_keyonly_root'], [])
        st, msg = compliance._remote_access_control(f)
        self.assertEqual(st, compliance.PASS)
        self.assertNotIn('by KEY', msg)


class TestASilentHostIsNotAFinding(unittest.TestCase):

    def test_a_host_with_no_sshd_report_is_neither_counted_nor_flagged(self):
        f = _facts({'d1': {'name': 'win01', 'sysinfo': {'cpu_percent': 5}}})
        self.assertEqual(f['ssh_data_devices'], 0)
        self.assertEqual(f['ssh_weak'], [])

    def test_a_mixed_fleet_reports_only_the_reporting_hosts(self):
        f = _facts({
            'd1': {'name': 'web01', 'sysinfo': {
                'ssh_config': dict(_HARDENED, password_authentication='yes')}},
            'd2': {'name': 'win01', 'sysinfo': {'cpu_percent': 5}},
            'd3': {'name': 'db01', 'sysinfo': {'ssh_config': _HARDENED}},
        })
        self.assertEqual(f['ssh_data_devices'], 2)
        self.assertEqual([h.split(' ')[0] for h in f['ssh_weak']], ['web01'])


class TestTheControlAnswersHonestly(unittest.TestCase):

    def test_weak_hosts_fail(self):
        st, msg = compliance._remote_access_control(
            {'devices': 1, 'ssh_data_devices': 1,
             'ssh_weak': ['web01 (root login permitted)']})
        self.assertEqual(st, compliance.FAIL)
        self.assertIn('web01', msg)
        self.assertIn('PermitRootLogin', msg)

    def test_all_hardened_passes_and_declares_its_scope(self):
        st, msg = compliance._remote_access_control(
            {'devices': 2, 'ssh_data_devices': 2, 'ssh_weak': [],
             'ssh_keyonly_root': []})
        self.assertEqual(st, compliance.PASS)
        self.assertIn('out of scope', msg,
                      'a PASS that implies it covered VPN/RDP/console is a '
                      'false assurance')

    def test_nothing_reported_is_NA_not_PASS(self):
        """A fleet with no Linux hosts has demonstrated nothing here. A green
        control would be an assurance an auditor relies on."""
        st, _ = compliance._remote_access_control(
            {'devices': 5, 'ssh_data_devices': 0, 'ssh_weak': []})
        self.assertEqual(st, compliance.NA)


class TestItIsMappedIntoTheFrameworks(unittest.TestCase):

    def test_three_frameworks_reference_it(self):
        rows = [(fw, cid) for (fw, cid, _t, fn, _r) in compliance._CONTROLS
                if fn is compliance._remote_access_control]
        self.assertEqual(sorted(rows),
                         [('e8', 'E8-5b'), ('pci', '2.2.7'), ('soc2', 'CC6.1b')])

    def test_it_reaches_the_built_report(self):
        """The registry entry is not the point; the report an auditor opens is."""
        rep = compliance.build_report(
            {'devices': 1, 'ssh_data_devices': 1,
             'ssh_weak': ['web01 (root login permitted)']})
        blob = repr(rep)
        self.assertIn('2.2.7', blob)
        self.assertIn('web01', blob)


if __name__ == '__main__':
    unittest.main()
