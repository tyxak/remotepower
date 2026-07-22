"""Guardrails for the on-host integrity & egress check types
(file_hash / dir_baseline / egress_flagged) added to the custom-check engine.

Server side: the types are registered and the shipped catalog rows are
well-formed. Agent side: each evaluator baselines and then trips correctly.
"""
import importlib.machinery
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

_CLIENT = Path(__file__).parent.parent / 'client'
sys.path.insert(0, str(_CLIENT))
_loader = importlib.machinery.SourceFileLoader('agent', str(_CLIENT / 'remotepower-agent'))
_spec = importlib.util.spec_from_loader('agent', _loader)
agent = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(agent)

_CHECKS = Path(__file__).parent.parent / 'server' / 'cgi-bin' / 'checks.py'
_cl = importlib.machinery.SourceFileLoader('checks_mod', str(_CHECKS))
_cs = importlib.util.spec_from_loader('checks_mod', _cl)
checks = importlib.util.module_from_spec(_cs)
_cs.loader.exec_module(checks)

NEW = ('file_hash', 'dir_baseline', 'egress_flagged')


class TestRegistration(unittest.TestCase):
    def test_types_registered(self):
        for t in NEW:
            self.assertIn(t, checks.AGENT_CHECK_TYPES)

    def test_catalog_rows_well_formed(self):
        rows = [t for t in checks.CHECK_BASELINE_CATALOG
                if t['cat'] == 'Web / application security']
        self.assertGreaterEqual(len(rows), 3)
        known = set(checks.SERVER_CHECK_TYPES) | set(checks.AGENT_CHECK_TYPES)
        for t in rows:
            for k in ('cat', 'id', 'type', 'param', 'name', 'desc'):
                self.assertTrue(t.get(k), f'{t.get("id")} missing {k}')
            self.assertIn(t['type'], known)
        # at least one row exercises each new type
        used = {t['type'] for t in rows}
        for t in NEW:
            self.assertIn(t, used, f'no catalog row uses {t}')

    def test_protect_field_pushed_to_agent(self):
        # Integrity Guard: the dir_baseline `protect` flag must be in the
        # heartbeat push whitelist or the agent never receives it.
        api_src = (Path(__file__).parent.parent / 'server' / 'cgi-bin' / 'api.py').read_text()
        self.assertIn("'max_age_hours', 'protect'", api_src)


class TestAgentEval(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        # isolate agent state into the temp dir so we never touch a real
        # /var/lib/remotepower or leak markers into /tmp between runs.
        self._orig_state = agent.STATE_DIR
        agent.STATE_DIR = self.tmp / 'state'
        agent.STATE_DIR.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        agent.STATE_DIR = self._orig_state
        self._tmp.cleanup()

    def test_file_hash_baseline_then_trip(self):
        f = self.tmp / 'watched.conf'
        f.write_text('original\n')
        c = {'id': 'fh1', 'type': 'file_hash', 'param': str(f)}
        st, out = agent._eval_one_agent_check(c)
        self.assertEqual(st, 'ok')            # first run baselines
        st, out = agent._eval_one_agent_check(c)
        self.assertEqual(st, 'ok')            # unchanged
        f.write_text('tampered\n')
        st, out = agent._eval_one_agent_check(c)
        self.assertEqual(st, 'critical')
        self.assertIn('changed', out)

    def test_file_hash_missing(self):
        c = {'id': 'fh2', 'type': 'file_hash', 'param': str(self.tmp / 'nope')}
        st, out = agent._eval_one_agent_check(c)
        self.assertEqual(st, 'critical')

    def test_dir_baseline_detects_new_file(self):
        d = self.tmp / 'web'
        d.mkdir()
        (d / 'index.php').write_text('<?php echo 1;')
        c = {'id': 'db1', 'type': 'dir_baseline', 'param': f'{d}::*.php'}
        st, out = agent._eval_one_agent_check(c)
        self.assertEqual(st, 'ok')            # baseline set
        # a non-matching file must NOT trip (glob scoping)
        (d / 'note.txt').write_text('hi')
        st, out = agent._eval_one_agent_check(c)
        self.assertEqual(st, 'ok')
        # a new PHP file must trip
        (d / 'shell.php').write_text('<?php')
        st, out = agent._eval_one_agent_check(c)
        self.assertEqual(st, 'critical')
        self.assertIn('new', out)

    def test_dir_baseline_quarantine(self):
        d = self.tmp / 'web2'
        d.mkdir()
        (d / 'index.php').write_text('<?php echo 1;')
        c = {'id': 'q1', 'type': 'dir_baseline', 'param': f'{d}::*.php',
             'protect': 'quarantine'}
        st, _ = agent._eval_one_agent_check(c)              # first run baselines
        self.assertEqual(st, 'ok')
        shell = d / 'evil.php'
        shell.write_text('<?php system($_GET[0]);')
        st, out = agent._eval_one_agent_check(c)            # new file -> quarantined
        self.assertEqual(st, 'critical')
        self.assertIn('quarantined', out)
        self.assertFalse(shell.exists())                   # removed from the web root
        vault = agent.STATE_DIR / 'guard-quarantine'
        contents = [p.read_text() for p in vault.iterdir() if p.is_file()]
        self.assertTrue(any('system($_GET' in x for x in contents))  # preserved in vault
        st, _ = agent._eval_one_agent_check(c)             # recovers to OK: threat gone
        self.assertEqual(st, 'ok')

    def _quarantine_one(self):
        """Quarantine a file and return (dir, shell_path, ledger_entry)."""
        d = self.tmp / 'web3'
        d.mkdir()
        (d / 'index.php').write_text('<?php echo 1;')
        c = {'id': 'r1', 'type': 'dir_baseline', 'param': f'{d}::*.php',
             'protect': 'quarantine'}
        agent._eval_one_agent_check(c)                       # baseline
        shell = d / 'dropped.php'
        shell.write_text('<?php evil();')
        agent._eval_one_agent_check(c)                       # quarantines it
        led = agent._guard_ledger()
        return d, shell, led

    def test_guard_ledger_reports_quarantined_file(self):
        _d, shell, led = self._quarantine_one()
        self.assertEqual(len(led), 1)
        self.assertEqual(led[0]['orig'], str(shell))
        self.assertTrue(led[0]['id'])
        self.assertGreater(led[0]['ts'], 0)

    def test_guard_action_restore_puts_the_file_back(self):
        _d, shell, led = self._quarantine_one()
        self.assertFalse(shell.exists())
        n = agent._apply_guard_actions([{'id': led[0]['id'], 'op': 'restore'}])
        self.assertEqual(n, 1)
        self.assertTrue(shell.exists())                      # back at its origin
        self.assertIn('evil()', shell.read_text())
        self.assertEqual(agent._guard_ledger(), [])          # ledger entry cleared

    def test_guard_action_restore_refuses_if_path_reoccupied(self):
        _d, shell, led = self._quarantine_one()
        shell.write_text('something else is here now')       # path no longer free
        n = agent._apply_guard_actions([{'id': led[0]['id'], 'op': 'restore'}])
        self.assertEqual(n, 0)                               # refused, not clobbered
        self.assertEqual(shell.read_text(), 'something else is here now')

    def test_guard_action_delete_removes_from_vault(self):
        _d, shell, led = self._quarantine_one()
        qid = led[0]['id']
        n = agent._apply_guard_actions([{'id': qid, 'op': 'delete'}])
        self.assertEqual(n, 1)
        self.assertFalse((agent.STATE_DIR / 'guard-quarantine' / qid).exists())
        self.assertFalse(shell.exists())                     # NOT restored
        self.assertEqual(agent._guard_ledger(), [])

    def test_restore_survives_a_truncated_ledger(self):
        """The .log is trimmed over time; restorability must NOT depend on it.
        The vault sidecar is the source of truth, so a file stays restorable
        even after its log line is gone."""
        _d, shell, led = self._quarantine_one()
        qid = led[0]['id']
        agent._safe_state_write('guard-quarantine.log', '')   # simulate rotation
        self.assertEqual(len(agent._guard_ledger()), 1)       # still visible
        n = agent._apply_guard_actions([{'id': qid, 'op': 'restore'}])
        self.assertEqual(n, 1)
        self.assertTrue(shell.exists())
        self.assertIn('evil()', shell.read_text())

    def test_vault_view_hides_an_item_whose_payload_vanished(self):
        _d, _shell, led = self._quarantine_one()
        (agent.STATE_DIR / 'guard-quarantine' / led[0]['id']).unlink()
        self.assertEqual(agent._guard_ledger(), [])           # nothing to offer

    def test_guard_action_ignores_unknown_id(self):
        self._quarantine_one()
        self.assertEqual(agent._apply_guard_actions([{'id': 'nope', 'op': 'delete'}]), 0)
        self.assertEqual(len(agent._guard_ledger()), 1)      # untouched

    def test_mass_change_is_reported_not_quarantined(self):
        """Rail: a burst of new files is a deploy, not a dropped payload — it
        must be reported loudly and left ON DISK, never auto-quarantined."""
        d = self.tmp / 'web4'
        d.mkdir()
        (d / 'index.php').write_text('<?php echo 1;')
        c = {'id': 'm1', 'type': 'dir_baseline', 'param': f'{d}::*.php',
             'protect': 'quarantine'}
        agent._eval_one_agent_check(c)                       # baseline
        made = []
        for i in range(agent._GUARD_MASS_CHANGE + 5):        # simulate a rollout
            f = d / f'page{i}.php'
            f.write_text(f'<?php // {i}')
            made.append(f)
        st, out = agent._eval_one_agent_check(c)
        self.assertEqual(st, 'critical')
        self.assertIn('NOT quarantined', out)
        self.assertTrue(all(f.exists() for f in made))       # rollout untouched
        self.assertEqual(agent._guard_ledger(), [])          # nothing vaulted

    def test_under_the_mass_threshold_still_quarantines(self):
        d = self.tmp / 'web5'
        d.mkdir()
        (d / 'index.php').write_text('<?php echo 1;')
        c = {'id': 'm2', 'type': 'dir_baseline', 'param': f'{d}::*.php',
             'protect': 'quarantine'}
        agent._eval_one_agent_check(c)
        (d / 'a.php').write_text('<?php a();')
        (d / 'b.php').write_text('<?php b();')
        st, out = agent._eval_one_agent_check(c)
        self.assertEqual(st, 'critical')
        self.assertIn('2 quarantined', out)
        self.assertEqual(len(agent._guard_ledger()), 2)

    def test_egress_empty_and_no_match(self):
        st, out = agent._eval_one_agent_check(
            {'id': 'e1', 'type': 'egress_flagged', 'param': ''})
        self.assertEqual(st, 'ok')
        # RFC-5737 documentation range — nothing on the box connects there
        st, out = agent._eval_one_agent_check(
            {'id': 'e2', 'type': 'egress_flagged', 'param': '192.0.2.0/24'})
        self.assertEqual(st, 'ok')

    def test_parse_hex_ip_roundtrip(self):
        # 127.0.0.1 in /proc/net/tcp little-endian hex is 0100007F
        self.assertEqual(agent._parse_hex_ip('0100007F'), '127.0.0.1')


if __name__ == '__main__':
    unittest.main()
