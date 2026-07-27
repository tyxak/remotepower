#!/usr/bin/env python3
"""v6.4.1: canary / honeytoken decoys on Windows and macOS, not just Linux.

Ransomware is overwhelmingly a Windows problem, so a tripwire that existed only
on the Linux agent was the wrong way round. Two things were broken:

  1. Neither the Windows nor the macOS agent read `canary_files` at all.
  2. The SERVER refused to store a Windows path — `handle_config_save` required
     `p.startswith('/')`, so every `C:\\...` entry was silently dropped and the
     operator got a 200 with an empty list back. Even after teaching the agents
     to plant decoys, there would have been nothing to plant.

Both agents are driven for real here (plant, tamper, report) rather than grepped,
and the server-side path validator is tested directly.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))

from sanitize import _canary_path_ok  # noqa: E402


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, _ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestCanaryPathValidator(unittest.TestCase):
    """The path reaches a privileged filesystem write on the agent (the decoy is
    created as root/SYSTEM), so it must be absolute and traversal-free — while
    still accepting the Windows forms the old check rejected."""

    def test_accepts_absolute_posix_windows_and_unc(self):
        for p in ('/etc/passwd.bak', '/srv/finance/payroll.xlsx',
                  '/Users/Shared/aws-creds.txt',
                  r'C:\Users\Public\payroll.xlsx', 'C:/ProgramData/creds.txt',
                  r'\\fileserver\share\decoy.docx'):
            self.assertTrue(_canary_path_ok(p), p)

    def test_rejects_relative_and_empty(self):
        for p in ('', None, 'relative/path', 'etc/passwd', 'decoy.txt', 'D:',
                  '1:\\x'):
            self.assertFalse(_canary_path_ok(p), repr(p))

    def test_rejects_traversal_under_either_separator(self):
        # A Windows path can traverse with EITHER separator, so checking only
        # one is a hole. A POSIX path containing a backslash is a literal
        # filename, and splitting on both is strictly safer than picking one.
        for p in ('/etc/../root/.ssh/id_rsa', r'C:\a\..\b', 'C:/a/../b',
                  r'\\srv\share\..\..\secret'):
            self.assertFalse(_canary_path_ok(p), p)

    def test_rejects_nul_and_overlong(self):
        self.assertFalse(_canary_path_ok('/x\x00y'))
        self.assertFalse(_canary_path_ok('/' + 'a' * 600))

    def test_rejects_windows_reserved_characters(self):
        for p in (r'C:\a<b', r'C:\a|b', r'C:\a"b', r'C:\a?b', r'C:\a*b'):
            self.assertFalse(_canary_path_ok(p), p)

    def test_a_posix_path_may_contain_reserved_chars(self):
        # Those characters are only reserved on Windows; a POSIX filename may
        # legitimately contain them, and rejecting it would be wrong.
        self.assertTrue(_canary_path_ok('/tmp/weird?name'))


class _CanaryAgentContract:
    """Shared behavioural contract. Both agents must satisfy all of it — this is
    the parity guarantee, so a future divergence fails rather than drifts."""

    AGENT_REL = None

    def setUp(self):
        self.ag = _load(f'canary_{self.__class__.__name__}', self.AGENT_REL)
        self.ag._canary_planted.clear()
        self.ag._canary_reported.clear()
        self.d = tempfile.mkdtemp()

    def _path(self, name):
        return os.path.join(self.d, name)

    def test_plants_a_decoy_owner_only(self):
        p = self._path('payroll.xlsx')
        self.ag._plant_canaries([{'path': p, 'content': 'FAKE'}])
        self.assertTrue(os.path.exists(p))
        self.assertEqual(oct(os.stat(p).st_mode)[-3:], '600')
        self.assertEqual(open(p).read(), 'FAKE')

    def test_default_content_looks_like_credentials(self):
        p = self._path('creds')
        self.ag._plant_canaries([{'path': p}])
        self.assertIn('aws_secret_access_key', open(p).read())

    def test_quiet_decoy_does_not_fire(self):
        p = self._path('quiet.txt')
        cfg = [{'path': p}]
        self.ag._plant_canaries(cfg)
        self.assertEqual(self.ag._check_canaries(cfg), [])

    def test_modification_is_detected(self):
        # The ransomware shape: encrypted in place. This is the detection that
        # matters most and the one that works on every filesystem.
        p = self._path('doc.xlsx')
        cfg = [{'path': p}]
        self.ag._plant_canaries(cfg)
        with open(p, 'w') as f:
            f.write('ENCRYPTED-BY-RANSOMWARE-XXXXXXXXXXXX')
        ev = self.ag._check_canaries(cfg)
        self.assertEqual([e['reason'] for e in ev], ['modified'])
        self.assertEqual(ev[0]['path'], p)

    def test_deletion_is_detected(self):
        p = self._path('gone.txt')
        cfg = [{'path': p}]
        self.ag._plant_canaries(cfg)
        os.unlink(p)
        self.assertEqual([e['reason'] for e in self.ag._check_canaries(cfg)],
                         ['deleted'])

    def test_reported_once_not_every_beat(self):
        # Edge-triggered. Without this a single tampered decoy would raise a
        # high-severity alert on every heartbeat, forever.
        p = self._path('once.txt')
        cfg = [{'path': p}]
        self.ag._plant_canaries(cfg)
        os.unlink(p)
        self.assertEqual(len(self.ag._check_canaries(cfg)), 1)
        self.assertEqual(self.ag._check_canaries(cfg), [])

    def test_never_clobbers_a_pre_existing_file(self):
        # The single most damaging thing this feature could do is overwrite real
        # data with a decoy. A pre-existing path is baselined, never written.
        p = self._path('real.txt')
        with open(p, 'w') as f:
            f.write('REAL DATA')
        self.ag._plant_canaries([{'path': p, 'content': 'DECOY'}])
        self.assertEqual(open(p).read(), 'REAL DATA')
        self.assertFalse(self.ag._canary_planted[p]['ours'])

    def test_rejects_relative_and_traversal_paths(self):
        self.ag._plant_canaries([{'path': '../etc/passwd'}, {'path': 'rel/x'},
                                 {'path': self.d + '/a/../b'}])
        for bad in ('../etc/passwd', 'rel/x', self.d + '/a/../b'):
            self.assertNotIn(bad, self.ag._canary_planted)

    def test_capped_at_fifty(self):
        self.ag._plant_canaries([{'path': self._path(f'c{i}')} for i in range(80)])
        self.assertLessEqual(len(self.ag._canary_planted), 50)

    def test_unconfigured_path_stops_being_reported(self):
        # Removing a decoy from the config must stop it alerting, even though
        # the agent still has it in its in-memory baseline.
        p = self._path('dropped.txt')
        self.ag._plant_canaries([{'path': p}])
        os.unlink(p)
        self.assertEqual(self.ag._check_canaries([]), [])

    def test_bad_config_shapes_do_not_raise(self):
        self.ag._plant_canaries([None, 42, {}, {'path': ''}])
        self.ag._check_canaries([None, 42, {}])

    def test_heartbeat_response_plants_and_payload_reports(self):
        """The wiring, not just the collectors — this is what was missing."""
        p = self._path('wired.txt')
        orig = self.ag._post_json
        try:
            self.ag._post_json = lambda *a, **k: {
                'ok': True, 'canary_files': [{'path': p}]}
            self.ag.heartbeat_once(
                {'server_url': 'http://x', 'device_id': 'd1'}, 2)
        finally:
            self.ag._post_json = orig
        self.assertTrue(os.path.exists(p), 'response did not plant the decoy')

        os.unlink(p)
        payload = self.ag.build_heartbeat(
            {'device_id': 'd1', 'token': 't'}, poll_count=2)
        self.assertEqual([e['reason'] for e in payload['canary_events']],
                         ['deleted'])

    def test_no_canary_events_key_when_nothing_happened(self):
        payload = self.ag.build_heartbeat(
            {'device_id': 'd1', 'token': 't'}, poll_count=2)
        self.assertNotIn('canary_events', payload)


class TestWindowsAgentCanary(_CanaryAgentContract, unittest.TestCase):
    AGENT_REL = 'client/remotepower-agent-win.py'

    def test_uninstall_removes_only_our_decoys(self):
        # An uninstall must not leave fake AWS credentials on disk — but must
        # also not delete a real file we only baselined.
        ours, theirs = self._path('ours.txt'), self._path('theirs.txt')
        with open(theirs, 'w') as f:
            f.write('REAL')
        self.ag._plant_canaries([{'path': ours}, {'path': theirs}])
        self.ag._remove_canaries()
        self.assertFalse(os.path.exists(ours))
        self.assertTrue(os.path.exists(theirs))

    def test_uninstall_path_calls_the_cleanup(self):
        src = (_ROOT / self.AGENT_REL).read_text()
        body = src[src.index('def _uninstall():'):]
        body = body[:body.index('\ndef ', 1)]
        self.assertIn('_remove_canaries()', body)


class TestMacAgentCanary(_CanaryAgentContract, unittest.TestCase):
    AGENT_REL = 'client/remotepower-agent-mac.py'

    def test_no_cleanup_helper_because_there_is_no_uninstall_path(self):
        # Deliberate: the macOS agent has no uninstall command, so a cleanup
        # helper would be a function nothing ever calls. If an uninstall path is
        # ever added, this test fails and points at the decoys left behind.
        src = (_ROOT / self.AGENT_REL).read_text()
        self.assertNotIn('def _uninstall', src,
                         'macOS gained an uninstall path — it must now call a '
                         '_remove_canaries() cleanup, or every decoy it planted '
                         'is left on disk')


if __name__ == '__main__':
    unittest.main(verbosity=2)
