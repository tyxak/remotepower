#!/usr/bin/env python3
"""posture_flags must read what the agents SEND, not what a consumer assumed.

v7.0.3 added `checks.posture_flags` so the Data Explorer, the Fleet Query facets
and the printable report would answer for Windows and macOS hosts as well as
Linux. Its test fixture gave the Windows producer booleans:

    {'win_posture': {'bitlocker': True, 'firewall': False, 'wu_service': True}}

The Windows agent sends lists and a string: `bitlocker` is one {mount, status}
per OS volume, `firewall` one {name, enabled} per profile, `wu_service` the
service's status. Read as booleans, every real Windows host answered None for
all three facts, so the fix never worked for the platform it was written for,
and the fixture could not show it, because it encoded the consumer's assumption.

These tests take the payload from the AGENT'S OWN PARSER, so a change to what the
agent sends, or to how the server reads it, fails here.
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v730-posture-'))

import advisory  # noqa: E402
import ai_context  # noqa: E402
import checks  # noqa: E402
import rag_index  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    'rp_win_agent_posture', _ROOT / 'client' / 'remotepower-agent-win.py')
winagent = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(winagent)

_PROFILES_ON = [{'name': 'Domain', 'enabled': True},
                {'name': 'Private', 'enabled': True},
                {'name': 'Public', 'enabled': True}]


def _wp(**over):
    """What the Windows agent's parser produces from the PowerShell JSON."""
    raw = {'firewall': _PROFILES_ON,
           'bitlocker': [{'mount': 'C:', 'status': 'On'}],
           'defender_realtime': True, 'defender_sig_age_days': 1,
           'wu_service': 'Running', 'wu_start': 'Manual'}
    raw.update(over)
    raw = {k: v for k, v in raw.items() if v is not None}
    return winagent._parse_win_posture(json.dumps(raw))


def _flags(**over):
    return checks.posture_flags({'win_posture': _wp(**over)})


class TestTheAgentsOwnShapeIsRead(unittest.TestCase):

    def test_the_agent_really_sends_lists_and_a_string(self):
        """The premise. If the agent ever sends booleans, this says so first."""
        wp = _wp()
        self.assertIsInstance(wp['firewall'], list)
        self.assertIsInstance(wp['bitlocker'], list)
        self.assertIsInstance(wp['wu_service'], str)

    def test_everything_on(self):
        self.assertEqual(_flags(), {'disk_encrypted': True,
                                    'firewall_active': True,
                                    'autoupdate_enabled': True})

    def test_one_profile_off_is_an_off_firewall(self):
        """The Windows Firewall check row, its alert and the risk score all say
        a profile that is off is a finding; the facet must agree."""
        off = [dict(p) for p in _PROFILES_ON]
        off[2]['enabled'] = False
        self.assertIs(_flags(firewall=off)['firewall_active'], False)

    def test_bitlocker_off_is_unencrypted(self):
        self.assertIs(_flags(bitlocker=[{'mount': 'C:', 'status': 'Off'}])
                      ['disk_encrypted'], False)

    def test_bitlocker_unknown_is_not_a_finding(self):
        """A volume the agent could not read says nothing either way."""
        self.assertIsNone(_flags(bitlocker=[{'mount': 'C:', 'status': 'Unknown'}])
                          ['disk_encrypted'])

    def test_nothing_reported_is_none_not_off(self):
        self.assertEqual(checks.posture_flags({'win_posture': {}}),
                         {'disk_encrypted': None, 'firewall_active': None,
                          'autoupdate_enabled': None})


class TestWindowsUpdateIsTriggerStart(unittest.TestCase):
    """wuauserv is stopped while idle on a healthy Windows 10/11 host, so a
    status of Stopped must not read as 'automatic updates are off'."""

    def test_stopped_with_a_manual_start_type_is_fine(self):
        f = _flags(wu_service='Stopped', wu_start='Manual')
        self.assertIs(f['autoupdate_enabled'], True)

    def test_a_disabled_service_is_off(self):
        f = _flags(wu_service='Stopped', wu_start='Disabled')
        self.assertIs(f['autoupdate_enabled'], False)

    def test_an_older_agent_that_sends_no_start_type_is_unknown_not_off(self):
        f = _flags(wu_service='Stopped', wu_start=None)
        self.assertIsNone(f['autoupdate_enabled'])

    def _update_row(self, **over):
        import time
        dev = {'last_seen': time.time(),
               'sysinfo': {'win_posture': _wp(**over)}}
        return {r['key']: r for r in checks._host_checks('w1', dev)}['win_update_service']

    def test_the_check_row_is_ok_for_an_idle_trigger_start_service(self):
        self.assertEqual(self._update_row(wu_service='Stopped',
                                          wu_start='Manual')['status'], 'ok')

    def test_the_check_row_warns_for_a_disabled_service(self):
        self.assertEqual(self._update_row(wu_service='Stopped',
                                          wu_start='Disabled')['status'], 'warning')

    def test_the_check_row_keeps_the_old_rule_without_a_start_type(self):
        self.assertEqual(self._update_row(wu_service='Stopped',
                                          wu_start=None)['status'], 'warning')

    def test_the_agent_asks_for_the_start_type(self):
        self.assertIn('StartType', winagent._WIN_POSTURE_PS)
        self.assertEqual(
            winagent._parse_win_posture(json.dumps(
                {'wu_service': 'Stopped', 'wu_start': 'Manual'}))['wu_start'],
            'Manual')


class TestTheOtherReadersUseIt(unittest.TestCase):

    def test_ai_context_names_a_windows_host_with_its_firewall_off(self):
        off = [dict(p) for p in _PROFILES_ON]
        off[0]['enabled'] = False
        flags = ai_context._device_flags(
            {'name': 'w1', 'sysinfo': {'win_posture': _wp(firewall=off)}})
        self.assertIn('firewall off', flags)

    def test_ai_context_names_unencrypted_windows_disks(self):
        flags = ai_context._device_flags(
            {'name': 'w1', 'sysinfo': {'win_posture': _wp(
                bitlocker=[{'mount': 'C:', 'status': 'Off'}])}})
        self.assertIn('disks unencrypted', flags)

    def test_ai_context_does_not_call_unreadable_probes_a_missing_firewall(self):
        """Every backend probe failed: that is 'unknown', and `not any()` over
        three Nones is True, which is how it used to read as 'firewall off'."""
        flags = ai_context._device_flags({'name': 'l1', 'sysinfo': {
            'firewall': {'backends': [{'name': 'nftables', 'active': None},
                                      {'name': 'ufw', 'active': None}]}}})
        self.assertNotIn('firewall off', flags)

    def test_a_healthy_windows_host_is_not_flagged(self):
        self.assertEqual(ai_context._device_flags(
            {'name': 'w1', 'sysinfo': {'win_posture': _wp()}}), [])

    def test_the_advisory_names_a_windows_host_with_its_firewall_off(self):
        off = [dict(p) for p in _PROFILES_ON]
        off[2]['enabled'] = False
        found = advisory.build(
            {'w1': {'name': 'w1', 'sysinfo': {'win_posture': _wp(firewall=off)}}}
        )['findings']
        fw = [g for g in found if g['id'] == 'exp.firewall']
        self.assertEqual(len(fw), 1, [g['id'] for g in found])
        self.assertIn('Windows', fw[0]['fix'])
        self.assertNotIn('nftables', fw[0]['fix'])

    def test_the_advisory_does_not_tell_a_mac_to_install_unattended_upgrades(self):
        found = advisory.build({'m1': {'name': 'm1', 'sysinfo': {
            'packages': {'upgradable': 3},
            'mac_posture': {'auto_security_update': False}}}})['findings']
        patches = [g for g in found if g['id'] == 'os.patches']
        self.assertTrue(patches)
        self.assertNotIn('unattended-upgrades', patches[0]['fix'])
        self.assertIn('System Settings', patches[0]['fix'])

    def test_the_fleet_firewall_document_lists_a_windows_host(self):
        off = [dict(p) for p in _PROFILES_ON]
        off[1]['enabled'] = False
        docs = rag_index.build_firewall_corpus(
            [{'id': 'w1', 'name': 'win-01', 'sysinfo': {'win_posture': _wp(firewall=off)}},
             {'id': 'w2', 'name': 'win-02', 'sysinfo': {'win_posture': _wp()}}], now=1)
        fleet = [d for d in docs if 'fleet_firewall' in json.dumps(d, default=str)]
        self.assertEqual(len(fleet), 1, docs)
        text = json.dumps(fleet[0], default=str)
        self.assertIn('win-01', text)
        self.assertNotIn('win-02', text)


class TestEveryConsumerGoesThroughTheHelper(unittest.TestCase):
    """The class is "N places carry their own copy of the fan-out". These are the
    places that read the firewall or the update posture, and each must call the
    helper rather than one producer's key."""

    def test_the_readers(self):
        for rel in ('ai_context.py', 'advisory.py', 'rag_index.py'):
            src = (_CGI / rel).read_text(encoding='utf-8')
            self.assertIn('posture_flags', src, rel)
        api = (_CGI / 'api.py').read_text(encoding='utf-8')
        # the compliance fact and the risk score
        self.assertGreaterEqual(api.count('posture_flags('), 5)


if __name__ == '__main__':
    unittest.main()
