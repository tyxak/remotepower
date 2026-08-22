"""v7.0.2 — the agent's root-mutating channels and the rails that bound them.

The Linux agent runs as root on operator hosts. Four channels can change the
host through it, and this file pins the gates that were missing:

* a check's baseline is bound to the SCOPE it was seeded from, so editing a
  live check's path cannot make every file under the new path read as "added"
  and be quarantined;
* the quarantine vault can never swallow the agent's own config, state or
  binary directory — the trust anchors that make every other gate work;
* require-signed-commands strips the ACTION half of an unsigned agent_checks
  payload while keeping detection;
* audit (read-only) mode refuses every channel that mutates host state.
"""
import importlib.machinery
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

_CLIENT = Path(__file__).parent.parent / 'client'
sys.path.insert(0, str(_CLIENT))
_loader = importlib.machinery.SourceFileLoader('agent_gates',
                                               str(_CLIENT / 'remotepower-agent'))
_spec = importlib.util.spec_from_loader('agent_gates', _loader)
agent = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(agent)


class _AgentSandbox(unittest.TestCase):
    """Point every agent-owned directory at a temp tree.

    CONF_DIR / STATE_DIR / AGENT_BINARY are module globals read at call time, so
    replacing them keeps the real /etc/remotepower and /var/lib/remotepower out
    of reach — and lets the tests assert on the paths the rails protect.
    """

    _SAVED = ('STATE_DIR', 'CONF_DIR', 'AGENT_BINARY', 'AUDIT_MODE_FILE',
              'REQUIRE_SIGNED_CMDS_FILE')

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self._orig = {n: getattr(agent, n) for n in self._SAVED}
        agent.STATE_DIR = self.tmp / 'state'
        agent.CONF_DIR = self.tmp / 'etc'
        agent.STATE_DIR.mkdir(parents=True)
        agent.CONF_DIR.mkdir(parents=True)
        agent.AGENT_BINARY = self.tmp / 'bin' / 'remotepower-agent'
        agent.AGENT_BINARY.parent.mkdir(parents=True)
        agent.AGENT_BINARY.write_text('#!/usr/bin/env python3\n')
        agent.AUDIT_MODE_FILE = agent.CONF_DIR / 'audit-mode'
        agent.REQUIRE_SIGNED_CMDS_FILE = agent.CONF_DIR / 'require-signed-commands'

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(agent, n, v)
        self._tmp.cleanup()

    def _audit_on(self):
        agent.AUDIT_MODE_FILE.write_text('')
        self.assertTrue(agent._audit_mode())

    def _signed_required(self):
        agent.REQUIRE_SIGNED_CMDS_FILE.write_text('')
        self.assertTrue(agent._require_signed_commands())


class TestScopeBoundBaselines(_AgentSandbox):
    def test_scope_edit_quarantines_nothing(self):
        """Editing a live check's scope must RE-SEED, never diff.

        The server keeps the check id and swaps `param`, so before the scope was
        recorded alongside the payload the agent diffed the new tree against a
        baseline taken somewhere else — every file read as new, and protect
        'quarantine' moved the operator's live tree into the vault as root.
        """
        a = self.tmp / 'scopeA'
        a.mkdir()
        (a / 'one.php').write_text('<?php // seeded here')
        c = {'id': 'edited', 'type': 'dir_baseline', 'protect': 'quarantine',
             'param': f'{a}::*.php'}
        st, _ = agent._eval_one_agent_check(c)
        self.assertEqual(st, 'ok')

        b = self.tmp / 'scopeB'
        b.mkdir()
        live = [b / f'prod{i}.php' for i in range(5)]
        for i, f in enumerate(live):
            f.write_text(f'<?php // production {i}')
        c['param'] = f'{b}::*.php'                      # the operator edits the path

        st, out = agent._eval_one_agent_check(c)
        self.assertEqual(st, 'ok', out)
        self.assertIn('scope changed', out)
        self.assertTrue(all(f.exists() for f in live), 'live files were moved')
        self.assertEqual(agent._guard_ledger(), [])     # nothing entered the vault

    def test_glob_widening_is_also_a_scope_change(self):
        d = self.tmp / 'w'
        d.mkdir()
        (d / 'a.php').write_text('<?php')
        (d / 'b.txt').write_text('text')
        c = {'id': 'wide', 'type': 'dir_baseline', 'protect': 'quarantine',
             'param': f'{d}::*.php'}
        agent._eval_one_agent_check(c)
        c['param'] = f'{d}::*'                          # widen the glob, same id
        st, out = agent._eval_one_agent_check(c)
        self.assertEqual(st, 'ok', out)
        self.assertTrue((d / 'b.txt').exists())
        self.assertEqual(agent._guard_ledger(), [])

    def test_same_scope_still_detects_and_quarantines(self):
        """The re-seed must not blunt the tripwire on an UNCHANGED scope."""
        d = self.tmp / 'same'
        d.mkdir()
        (d / 'index.php').write_text('<?php echo 1;')
        c = {'id': 'keep', 'type': 'dir_baseline', 'protect': 'quarantine',
             'param': f'{d}::*.php'}
        self.assertEqual(agent._eval_one_agent_check(c)[0], 'ok')
        shell = d / 'evil.php'
        shell.write_text('<?php system($_GET[0]);')
        st, out = agent._eval_one_agent_check(c)
        self.assertEqual(st, 'critical')
        self.assertIn('quarantined', out)
        self.assertFalse(shell.exists())

    def test_legacy_baseline_reseeds_once_then_binds(self):
        """A record written before scopes were bound carries no scope, so it
        cannot be told apart from one seeded elsewhere: re-seed once."""
        d = self.tmp / 'legacy'
        d.mkdir()
        (d / 'x.php').write_text('<?php')
        c = {'id': 'old', 'type': 'dir_baseline', 'protect': 'quarantine',
             'param': f'{d}::*.php'}
        agent._safe_state_write('checkdir-old', '{}')     # pre-v7.0.2 bare map
        st, out = agent._eval_one_agent_check(c)
        self.assertEqual(st, 'ok', out)
        self.assertIn('baseline reset', out)
        self.assertTrue((d / 'x.php').exists())
        st, out = agent._eval_one_agent_check(c)          # now bound: quiet
        self.assertEqual((st, 'unchanged' in out), ('ok', True))

    def test_file_hash_scope_edit_does_not_report_tampering(self):
        one = self.tmp / 'one.conf'
        two = self.tmp / 'two.conf'
        one.write_text('first\n')
        two.write_text('second\n')
        c = {'id': 'fh', 'type': 'file_hash', 'param': str(one)}
        self.assertEqual(agent._eval_one_agent_check(c)[0], 'ok')
        c['param'] = str(two)
        st, out = agent._eval_one_agent_check(c)
        self.assertEqual(st, 'ok', out)
        self.assertIn('scope changed', out)


class TestQuarantineProtectedPaths(_AgentSandbox):
    def _anchors(self):
        marker = agent.CONF_DIR / 'require-signed-commands'
        pub = agent.CONF_DIR / 'release.pub'
        audit = agent.CONF_DIR / 'audit-mode'
        creds = agent.CONF_DIR / 'creds.json'
        state = agent.STATE_DIR / 'last-cmd'
        for f in (marker, pub, audit, creds, state):
            f.write_text('x')
        return [marker, pub, audit, creds, state, agent.AGENT_BINARY]

    def test_guard_quarantine_refuses_agent_owned_paths(self):
        anchors = self._anchors()
        moved = agent._guard_quarantine([str(f) for f in anchors], 'hostile')
        self.assertEqual(moved, 0)
        for f in anchors:
            self.assertTrue(f.exists(), f'{f} was moved into the vault')
        self.assertEqual(agent._guard_ledger(), [])

    def test_protected_path_reason_names_the_directory(self):
        self.assertEqual(
            agent._guard_protected_path(str(agent.CONF_DIR / 'audit-mode')),
            'agent config dir')
        self.assertEqual(
            agent._guard_protected_path(str(agent.STATE_DIR / 'anything')),
            'agent state dir')
        self.assertEqual(
            agent._guard_protected_path(str(agent.AGENT_BINARY)),
            'agent binary dir')
        self.assertEqual(agent._guard_protected_path(str(self.tmp / 'web/x.php')), '')

    def test_symlink_into_conf_dir_is_refused(self):
        """realpath first: a decoy in a watched tree pointing at a trust anchor
        must not launder the move."""
        target = agent.CONF_DIR / 'require-signed-commands'
        target.write_text('')
        d = self.tmp / 'web'
        d.mkdir()
        link = d / 'innocent.php'
        try:
            link.symlink_to(target)
        except OSError:
            self.skipTest('symlinks unavailable')
        self.assertEqual(agent._guard_quarantine([str(link)], 'c'), 0)
        self.assertTrue(target.exists())

    def test_scope_repointed_at_conf_dir_moves_nothing(self):
        """The chained attack: seed on an empty tree, repoint the same check id
        at CONF_DIR. Both rails have to hold — the scope binding re-seeds, and
        even if it did not, the vault refuses agent-owned paths."""
        anchors = self._anchors()
        empty = self.tmp / 'empty'
        empty.mkdir()
        c = {'id': 'chain', 'type': 'dir_baseline', 'protect': 'quarantine',
             'param': str(empty)}
        agent._eval_one_agent_check(c)
        c['param'] = str(agent.CONF_DIR)
        agent._eval_one_agent_check(c)
        agent._eval_one_agent_check(c)      # and again, now that the scope matches
        for f in anchors:
            if str(f).startswith(str(agent.CONF_DIR)):
                self.assertTrue(f.exists(), f'{f} left the config dir')
        self.assertTrue(agent._require_signed_commands())


class TestUnsignedCheckChannel(_AgentSandbox):
    def test_protect_is_stripped_when_signing_is_required(self):
        pushed = [{'id': 'a', 'type': 'dir_baseline', 'param': '/srv',
                   'protect': 'quarantine'},
                  {'id': 'b', 'type': 'file_hash', 'param': '/etc/hosts'}]
        kept, stripped = agent._strip_unsigned_protect(pushed)
        self.assertEqual(stripped, 1)
        self.assertNotIn('protect', kept[0])
        self.assertEqual(kept[0]['type'], 'dir_baseline')   # detection survives
        self.assertEqual(kept[1], pushed[1])

    def test_heartbeat_applies_the_strip_under_the_flag(self):
        """The gate must be wired into the agent_checks branch of the heartbeat,
        not merely available as a helper."""
        src = (_CLIENT / 'remotepower-agent.py').read_text()
        start = src.index("if 'agent_checks' in resp:")
        block = src[start:start + 2000]
        self.assertIn('_require_signed_commands()', block)
        self.assertIn('_strip_unsigned_protect(new_ac)', block)

    def test_stripped_check_cannot_quarantine(self):
        self._signed_required()
        d = self.tmp / 'srv'
        d.mkdir()
        (d / 'index.php').write_text('<?php echo 1;')
        pushed = [{'id': 'p', 'type': 'dir_baseline', 'param': f'{d}::*.php',
                   'protect': 'quarantine'}]
        gated, _ = agent._strip_unsigned_protect(pushed)
        agent._eval_one_agent_check(gated[0])
        shell = d / 'evil.php'
        shell.write_text('<?php system($_GET[0]);')
        st, out = agent._eval_one_agent_check(gated[0])
        self.assertEqual(st, 'critical')                 # still detected
        self.assertTrue(shell.exists())                  # but not moved
        self.assertEqual(agent._guard_ledger(), [])

    def test_guard_restore_refused_when_signing_is_required(self):
        d = self.tmp / 'web'
        d.mkdir()
        (d / 'index.php').write_text('<?php echo 1;')
        c = {'id': 'g', 'type': 'dir_baseline', 'param': f'{d}::*.php',
             'protect': 'quarantine'}
        agent._eval_one_agent_check(c)
        shell = d / 'dropped.php'
        shell.write_text('<?php evil();')
        agent._eval_one_agent_check(c)
        qid = agent._guard_ledger()[0]['id']
        self._signed_required()
        self.assertEqual(
            agent._apply_guard_actions([{'id': qid, 'op': 'restore'}]), 0)
        self.assertFalse(shell.exists())


class TestAuditModeCoversEveryMutatingChannel(_AgentSandbox):
    """Audit mode's own comment used to assert the host could not be modified
    through the agent. Each channel below is one line of that claim."""

    def test_command_channel_refused(self):
        self._audit_on()
        r = agent.execute_command('reboot')
        self.assertEqual(r['rc'], 126)
        self.assertIn('audit', r['output'])

    def test_custom_scripts_refused(self):
        self._audit_on()
        self.assertEqual(
            agent.run_custom_scripts([{'id': 's', 'body': 'touch /tmp/x'}]), {})

    def test_host_config_apply_refused(self):
        self._audit_on()
        self.assertIn('_refused', agent.apply_host_config({'motd': 'hi'}))

    def test_file_upload_refused(self):
        """`files:` ops are dispatched BEFORE execute_command's blanket refusal,
        so they carry their own check — and `upload` was missing from it while
        the Windows agent's twin already listed it."""
        import base64
        self._audit_on()
        target = '/var/log/rp-audit-probe.txt'
        b64 = base64.urlsafe_b64encode(target.encode()).decode()
        payload = base64.urlsafe_b64encode(b'x').decode()
        r = agent._handle_file_op(f'files:upload:{b64}:{payload}:1')
        self.assertEqual(r['rc'], 126, r)
        self.assertIn('audit', r['output'])
        self.assertFalse(Path(target).exists())

    def test_file_write_refused(self):
        import base64
        self._audit_on()
        b64 = base64.urlsafe_b64encode(b'/var/log/rp-audit-probe2.txt').decode()
        r = agent._handle_file_op(f'files:write:{b64}:aGk=')
        self.assertEqual(r['rc'], 126, r)

    def test_check_quarantine_refused(self):
        self._audit_on()
        d = self.tmp / 'web'
        d.mkdir()
        (d / 'index.php').write_text('<?php echo 1;')
        c = {'id': 'am', 'type': 'dir_baseline', 'param': f'{d}::*.php',
             'protect': 'quarantine'}
        agent._eval_one_agent_check(c)
        shell = d / 'evil.php'
        shell.write_text('<?php system($_GET[0]);')
        st, out = agent._eval_one_agent_check(c)
        self.assertEqual(st, 'critical')          # detection still reports
        self.assertIn('audit mode', out)
        self.assertTrue(shell.exists())           # the action is dropped
        self.assertEqual(agent._guard_ledger(), [])

    def test_guard_restore_and_delete_refused(self):
        d = self.tmp / 'web2'
        d.mkdir()
        (d / 'index.php').write_text('<?php echo 1;')
        c = {'id': 'ga', 'type': 'dir_baseline', 'param': f'{d}::*.php',
             'protect': 'quarantine'}
        agent._eval_one_agent_check(c)
        shell = d / 'dropped.php'
        shell.write_text('<?php evil();')
        agent._eval_one_agent_check(c)
        qid = agent._guard_ledger()[0]['id']
        self._audit_on()
        self.assertEqual(agent._apply_guard_actions([{'id': qid, 'op': 'restore'}]), 0)
        self.assertFalse(shell.exists())
        self.assertEqual(agent._apply_guard_actions([{'id': qid, 'op': 'delete'}]), 0)
        self.assertEqual(len(agent._guard_ledger()), 1)   # still in the vault

    def test_rebaseline_still_works_in_audit_mode(self):
        """It clears the agent's own stored baseline and nothing else, so
        refusing it would only break the operator's way to accept a change."""
        self._audit_on()
        agent._safe_state_write('checkdir-rb', '{}')
        self.assertEqual(
            agent._apply_guard_actions([{'id': 'rb', 'op': 'rebaseline'}]), 1)
        self.assertIsNone(agent._safe_state_read_big('checkdir-rb'))


class TestRestoreRefusalIsReported(_AgentSandbox):
    def test_occupied_path_refusal_reaches_the_ledger(self):
        """The server clears its one-shot restore directive on delivery, so a
        refusal that only reaches the journal is the same as the button doing
        nothing. The reason rides the next heartbeat's vault ledger."""
        d = self.tmp / 'web'
        d.mkdir()
        (d / 'index.php').write_text('<?php echo 1;')
        c = {'id': 'rr', 'type': 'dir_baseline', 'param': f'{d}::*.php',
             'protect': 'quarantine'}
        agent._eval_one_agent_check(c)
        shell = d / 'dropped.php'
        shell.write_text('<?php evil();')
        agent._eval_one_agent_check(c)
        qid = agent._guard_ledger()[0]['id']
        shell.write_text('something else lives here now')
        self.assertEqual(
            agent._apply_guard_actions([{'id': qid, 'op': 'restore'}]), 0)
        row = agent._guard_ledger()[0]
        self.assertIn('err', row)
        self.assertIn('occupied', row['err'])


class TestLogWatchDenyList(_AgentSandbox):
    def test_agent_trust_anchors_are_not_readable_as_logs(self):
        for name in ('require-signed-commands', 'audit-mode', 'release.pub',
                     'creds.json'):
            self.assertFalse(
                agent._file_log_path_allowed(str(agent.CONF_DIR / name)), name)
        self.assertFalse(
            agent._file_log_path_allowed(str(agent.STATE_DIR / 'guard-quarantine.log')))

    def test_credential_shapes_anywhere_are_denied(self):
        for p in ('/etc/shadow', '/srv/app/.env', '/opt/app/tls/server.key',
                  '/opt/app/certs/chain.pem', '/var/www/.ssh/id_rsa',
                  '/etc/ssh/ssh_host_ed25519_key', '/home/bob/.aws/credentials',
                  '/root/.ssh/authorized_keys', '/etc/ssl/private/x.pem'):
            self.assertFalse(agent._file_log_path_allowed(p), p)

    def test_secret_directories_are_denied_by_segment_anywhere(self):
        """The old list named /home/*/.ssh/ and /root/.ssh/ and stopped there,
        so the same directory under any other parent read as an ordinary log
        location. These leaf names are innocuous — only the directory is not."""
        for p in ('/opt/app/.ssh/config', '/srv/deploy/.kube/config',
                  '/var/www/.docker/config.json', '/opt/ci/.gnupg/trustdb.gpg',
                  '/data/jenkins/.aws/config'):
            self.assertFalse(agent._file_log_path_allowed(p), p)

    def test_ordinary_log_paths_still_allowed(self):
        for p in ('/var/log/nginx/access.log', '/opt/app/logs/app.log',
                  '/srv/site/storage/laravel.log', '/home/bob/app/run.log',
                  '/etc/ssh/ssh_host_ed25519_key.pub'):
            self.assertTrue(agent._file_log_path_allowed(p), p)


if __name__ == '__main__':
    unittest.main()
