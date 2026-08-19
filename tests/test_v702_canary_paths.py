#!/usr/bin/env python3
"""The canary channel was a fifth way to change a host, and it never asked.

`canary_files` is admin-set config that every agent turns into a root-owned
file: the server pushes {path, content} in the heartbeat and the agent creates
it, making the parent directory if it was missing. Audit mode
(/etc/remotepower/audit-mode) and require-signed-commands both exist to stop the
server changing a host — execute_command, apply_host_config, check_for_update
and custom scripts all check one or both. Planting did neither, so on a fleet
where a stolen admin token cannot sign a command it could still write
/etc/cron.d/anything, and an operator running in audit mode was wrong about what
their agent could be made to do.

Three changes, all four places (server + three agents):
  - audit mode skips planting and reports why;
  - paths where the system executes what it finds are refused at both ends;
  - the parent directory is never created — a missing one means a wrong path,
    and making one is how this channel would produce /etc/cron.d on a host
    without it.
"""
import ast
import re
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
import sanitize  # noqa: E402

_AGENTS = ('client/remotepower-agent.py', 'client/remotepower-agent-mac.py',
           'client/remotepower-agent-win.py')


def _agent_tuple(src, name):
    """The literal value of a module-level tuple, without executing the agent."""
    for node in ast.parse(src).body:
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return tuple(ast.literal_eval(node.value))
    raise AssertionError(f'{name} not found')


class TestTheRuleRefusesWhatItShould(unittest.TestCase):

    def test_code_locations_are_refused(self):
        for p in ('/etc/cron.d/rp', '/etc/cron.daily/x', '/etc/sudoers.d/rp',
                  '/etc/profile.d/rp.sh', '/etc/systemd/system/x.service',
                  '/usr/local/bin/helper', '/var/spool/cron/root',
                  '/etc/ld.so.conf.d/x.conf', '/home/u/.ssh/authorized_keys',
                  '/home/u/.ssh/config', '/root/.bashrc', '/etc/rc.local',
                  '/etc/ld.so.preload', '/opt/app/deploy.sh', '/opt/x/run.ps1',
                  'C:\\Windows\\System32\\creds.txt',
                  'C:\\Users\\u\\Start Menu\\Programs\\Startup\\a.txt'):
            ok, why = sanitize.canary_path_safe(p)
            self.assertFalse(ok, p)
            self.assertTrue(why, f'{p} refused with no reason')

    def test_real_decoys_are_still_allowed(self):
        """The control that matters. A rule that refused everything would pass
        the test above and quietly delete the feature."""
        for p in ('/home/u/.ssh/id_rsa', '/srv/data/customers.csv',
                  '/root/aws-credentials.txt', '/home/u/Documents/passwords.txt',
                  '/var/backups/payroll.xlsx', '/opt/app/.env',
                  'C:\\Users\\u\\Documents\\banking.xlsx',
                  '/srv/shares/finance/Q4-forecast.docx'):
            ok, why = sanitize.canary_path_safe(p)
            self.assertTrue(ok, f'{p} refused: {why}')

    def test_separator_and_case_do_not_get_you_past_it(self):
        for p in ('/ETC/CRON.D/rp', '\\etc\\cron.d\\rp', '/etc//cron.d//rp',
                  '/opt/x/RUN.SH'):
            self.assertFalse(sanitize.canary_path_safe(p)[0], p)


class TestEveryAgentCarriesTheSameRule(unittest.TestCase):
    """Three mirrored copies is how one of them ends up a release behind."""

    def test_the_tuples_match_the_server(self):
        for rel in _AGENTS:
            src = (_ROOT / rel).read_text()
            for ours, theirs in (('CANARY_DENY_DIRS', '_CANARY_DENY_DIRS'),
                                 ('CANARY_DENY_ENDINGS', '_CANARY_DENY_ENDINGS'),
                                 ('CANARY_DENY_SUFFIXES', '_CANARY_DENY_SUFFIXES')):
                self.assertEqual(_agent_tuple(src, theirs),
                                 getattr(sanitize, ours),
                                 f'{rel}: {theirs} has drifted from sanitize.py')

    def test_every_agent_skips_planting_in_audit_mode(self):
        sys.path.insert(0, str(Path(__file__).parent))
        import srcpin
        for rel in _AGENTS:
            body = srcpin.py_function((_ROOT / rel).read_text(), '_plant_canaries')
            self.assertIn('_audit_mode()', body, rel)

    def test_no_agent_creates_the_parent_directory(self):
        sys.path.insert(0, str(Path(__file__).parent))
        import srcpin
        for rel in _AGENTS:
            body = srcpin.py_function((_ROOT / rel).read_text(), '_plant_canaries')
            self.assertNotIn('makedirs', body, rel)

    def test_every_agent_consults_the_rule(self):
        sys.path.insert(0, str(Path(__file__).parent))
        import srcpin
        for rel in _AGENTS:
            body = srcpin.py_function((_ROOT / rel).read_text(), '_plant_canaries')
            self.assertIn('_canary_path_safe(', body, rel)


class TestAuditModeActuallyStopsThePlant(unittest.TestCase):
    """Driven, not grepped. The source pin above says the call is there; this
    says the file does not appear on disk."""

    def setUp(self):
        sys.path.insert(0, str(Path(__file__).parent))
        from test_v642_canary_arm_status import _load_canary_ns
        self.ns = _load_canary_ns('remotepower-agent.py')
        import tempfile
        self.work = tempfile.mkdtemp(prefix='rp-canary-audit-')
        self.decoy = str(Path(self.work) / 'aws-credentials.txt')

    def test_it_plants_when_audit_mode_is_off(self):
        """The control. Without it, a plant that silently stopped working for
        any other reason would pass the test below."""
        self.ns['_audit_mode'] = lambda: False
        self.ns['_plant_canaries']([{'path': self.decoy}])
        self.assertTrue(Path(self.decoy).exists())

    def test_it_does_not_plant_when_audit_mode_is_on(self):
        self.ns['_audit_mode'] = lambda: True
        self.ns['_plant_canaries']([{'path': self.decoy}])
        self.assertFalse(Path(self.decoy).exists(),
                         'audit mode is read-only and this wrote a root file')

    def test_and_it_says_why_rather_than_reporting_armed(self):
        """The arm report is the operator's evidence. Silence here is how a
        control gets trusted while doing nothing."""
        self.ns['_audit_mode'] = lambda: True
        self.ns['_plant_canaries']([{'path': self.decoy}])
        self.assertIn('audit', str(self.ns['_canary_failed'].get(self.decoy, '')))

    def test_a_denied_path_is_refused_by_the_agent_too(self):
        """Not just by the server. An older or compromised server must not be
        able to use this channel to write code."""
        self.ns['_audit_mode'] = lambda: False
        self.ns['_plant_canaries']([{'path': '/etc/cron.d/rp-decoy'}])
        self.assertFalse(Path('/etc/cron.d/rp-decoy').exists())
        self.assertIn('cron', str(self.ns['_canary_failed'].get('/etc/cron.d/rp-decoy', '')))

    def test_a_missing_directory_is_not_created(self):
        self.ns['_audit_mode'] = lambda: False
        deep = str(Path(self.work) / 'no' / 'such' / 'dir' / 'decoy.txt')
        self.ns['_plant_canaries']([{'path': deep}])
        self.assertFalse(Path(deep).parent.exists(),
                         'planting made a directory tree that did not exist')
        self.assertIn('directory', str(self.ns['_canary_failed'].get(deep, '')))


class TestTheServerRefusesAndStopsPushing(unittest.TestCase):

    def test_the_save_path_refuses_with_a_reason(self):
        sys.path.insert(0, str(Path(__file__).parent))
        import srcpin
        body = srcpin.py_function((_CGI / 'api.py').read_text(),
                                  'handle_config_save')
        m = re.search(r"if 'canary_files' in body:(.{0,1600})", body, re.S)
        self.assertTrue(m, 'the canary_files save branch moved')
        seg = m.group(1)
        self.assertIn('canary_path_safe(', seg)
        self.assertIn('respond(400', seg,
                      'a refused path must say so, not vanish from the list')

    def test_the_heartbeat_filters_paths_stored_before_this_release(self):
        src = (_CGI / 'api.py').read_text()
        m = re.search(r"'canary_files':\s*(.{0,300})", src, re.S)
        self.assertTrue(m)
        self.assertIn('canary_path_safe', m.group(1),
                      'a bad path saved before v7.0.2 keeps being pushed')


if __name__ == '__main__':
    unittest.main()
