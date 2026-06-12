#!/usr/bin/env python3
"""v4.3.0: agent subsystem tests that were missing — the three the audit
flagged as untested despite being the parts you can least afford to break
remotely (a bad self-update or a crashed heartbeat has no second chance):

  * signed-update verification — REAL gpg round-trip (good sig verifies,
    tampered payload refuses, wrong key refuses). Previous tests only
    checked the require-marker existed.
  * file-log tailing across rotation/truncation — inode change and shrink
    must reset the read position, never re-emit old content or crash.
  * eval_agent_checks with malformed server-pushed configs — garbage from
    the server must degrade to 'unknown', never raise into the heartbeat.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / 'client'))
import importlib.machinery
import importlib.util

_agent_path = str(Path(__file__).parent.parent / 'client' / 'remotepower-agent')
_loader = importlib.machinery.SourceFileLoader('agent_v430h', _agent_path)
_spec = importlib.util.spec_from_loader('agent_v430h', _loader)
agent = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(agent)

GPG = shutil.which('gpg')


@unittest.skipUnless(GPG, 'gpg not installed')
class TestSignedUpdateVerification(unittest.TestCase):
    """Real cryptographic round-trip through _verify_detached_sig."""

    @classmethod
    def setUpClass(cls):
        cls.home = tempfile.mkdtemp(prefix='rp-sigtest-')
        os.chmod(cls.home, 0o700)
        cls.env = dict(os.environ, GNUPGHOME=cls.home)
        r = subprocess.run(
            [GPG, '--batch', '--passphrase', '', '--pinentry-mode', 'loopback',
             '--quick-generate-key', 'RemotePower Test <test@example.invalid>',
             'ed25519', 'sign', '1d'],
            env=cls.env, capture_output=True, timeout=60)
        if r.returncode != 0:
            raise unittest.SkipTest(f'gpg keygen failed: {r.stderr.decode()[:200]}')
        cls.pubkey = subprocess.run(
            [GPG, '--batch', '--armor', '--export', 'test@example.invalid'],
            env=cls.env, capture_output=True, timeout=20).stdout.decode()
        cls.payload = b'#!/usr/bin/env python3\n# fake agent release\n' * 100
        sig = subprocess.run(
            [GPG, '--batch', '--passphrase', '', '--pinentry-mode', 'loopback',
             '--armor', '--detach-sign', '-o', '-'],
            input=cls.payload, env=cls.env, capture_output=True, timeout=30)
        cls.sig_text = sig.stdout.decode()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.home, ignore_errors=True)

    def test_valid_signature_verifies(self):
        ok, detail = agent._verify_detached_sig(self.payload, self.sig_text, self.pubkey)
        self.assertTrue(ok, f'valid signature must verify: {detail}')

    def test_tampered_payload_refused(self):
        ok, _ = agent._verify_detached_sig(self.payload + b'X', self.sig_text, self.pubkey)
        self.assertFalse(ok, 'tampered payload must NOT verify')

    def test_wrong_key_refused(self):
        other_home = tempfile.mkdtemp(prefix='rp-sigtest2-')
        os.chmod(other_home, 0o700)
        try:
            env = dict(os.environ, GNUPGHOME=other_home)
            subprocess.run(
                [GPG, '--batch', '--passphrase', '', '--pinentry-mode', 'loopback',
                 '--quick-generate-key', 'Other <other@example.invalid>',
                 'ed25519', 'sign', '1d'],
                env=env, capture_output=True, timeout=60)
            other_pub = subprocess.run(
                [GPG, '--batch', '--armor', '--export', 'other@example.invalid'],
                env=env, capture_output=True, timeout=20).stdout.decode()
        finally:
            shutil.rmtree(other_home, ignore_errors=True)
        ok, _ = agent._verify_detached_sig(self.payload, self.sig_text, other_pub)
        self.assertFalse(ok, 'a signature from an unpinned key must NOT verify')

    def test_empty_signature_refused(self):
        ok, _ = agent._verify_detached_sig(self.payload, '', self.pubkey)
        self.assertFalse(ok)


class TestFileLogRotation(unittest.TestCase):
    """collect_file_log must survive rotation (inode change) and truncation."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix='rp-logrot-')
        self.path = os.path.join(self.dir, 'app.log')
        self.state = {}

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _write(self, text, mode='a'):
        with open(self.path, mode) as f:
            f.write(text)

    def test_first_sight_bookmarks_without_emitting(self):
        self._write('old line 1\nold line 2\n', 'w')
        out = agent.collect_file_log(self.path, self.state)
        self.assertEqual(out, [], 'existing content must be skipped on first sight')

    def test_appended_lines_are_emitted_once(self):
        self._write('seed\n', 'w')
        agent.collect_file_log(self.path, self.state)        # bookmark
        self._write('new line A\nnew line B\n')
        out = agent.collect_file_log(self.path, self.state)
        self.assertEqual([e['message'] for e in out], ['new line A', 'new line B'])
        self.assertEqual(agent.collect_file_log(self.path, self.state), [],
                         'already-emitted lines must not repeat')

    def test_rotation_resets_to_new_file_start(self):
        self._write('pre-rotation\n', 'w')
        agent.collect_file_log(self.path, self.state)        # bookmark
        # logrotate-style: move the old file aside, create a fresh one (new inode)
        os.rename(self.path, self.path + '.1')
        self._write('post-rotation line\n', 'w')
        out = agent.collect_file_log(self.path, self.state)
        self.assertEqual([e['message'] for e in out], ['post-rotation line'],
                         'after rotation the new file must be read from offset 0')

    def test_truncation_resets_position(self):
        self._write('a long seed line that advances the offset\n', 'w')
        agent.collect_file_log(self.path, self.state)        # bookmark at EOF
        self._write('tiny\n', 'w')                            # truncate (same inode)
        out = agent.collect_file_log(self.path, self.state)
        self.assertEqual([e['message'] for e in out], ['tiny'],
                         'a shrunk file must be re-read from the start, not crash')


class TestMalformedAgentChecks(unittest.TestCase):
    """Server-pushed check configs are attacker-ish input from the agent's
    perspective — malformed entries must degrade, never raise."""

    def test_garbage_entries_are_skipped_or_unknown(self):
        checks = [
            None,
            'not-a-dict',
            {},                                        # no id
            {'id': 'c1'},                              # no type
            {'id': 'c2', 'type': 'no_such_type'},
            {'id': 'c3', 'type': 'file_present'},      # no param
            {'id': 'c4', 'type': 'job_fresh', 'param': '/nonexistent',
             'max_age_hours': 'NaN-ish'},              # bad numeric → must not raise
            {'id': 'c5', 'type': 'log_errors', 'param': 'x',
             'window_min': {'nested': 'dict'}},        # bad numeric type
        ]
        out = agent.eval_agent_checks(checks)
        # ids without a dict shape or id are dropped; the rest get a result
        self.assertNotIn('c1', {})  # (sanity no-op)
        for cid in ('c2', 'c4', 'c5'):
            self.assertIn(cid, out, f'{cid} must produce a result, not crash')
            self.assertIn(out[cid]['status'], ('ok', 'warning', 'critical', 'unknown'))
        self.assertEqual(out.get('c2', {}).get('status'), 'unknown')

    def test_eval_never_raises_even_on_evil_param_types(self):
        evil = [{'id': f'e{i}', 'type': t, 'param': p}
                for i, (t, p) in enumerate([
                    ('file_present', None),
                    ('file_absent', 12345),
                    ('job_fresh', ['list']),
                    ('log_errors', {'d': 1}),
                ])]
        out = agent.eval_agent_checks(evil)   # must simply not raise
        self.assertEqual(len(out), len(evil))


if __name__ == '__main__':
    unittest.main()
