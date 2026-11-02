#!/usr/bin/env python3
"""7.4.9 agent security pass: the quarantine vault must not change the mode of what a planted link points at.

A `dir_baseline` check with `protect=quarantine` moves new files out of a watched directory into the root-only vault and sets the
moved file to 0600. A link in that directory is moved as a link (a rename does not follow it), and `os.chmod` does follow it, so a
local user who could write to the watched directory could name any file and have the agent, as root, set its mode to 0600: a link
to a setuid binary took the setuid bit off it for every user. The mode is now set only on what is a real file in the vault.
"""
import importlib.machinery
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
AGENT = Path(os.environ.get('RP_TEST_AGENT') or ROOT / 'client' / 'remotepower-agent.py')
_loader = importlib.machinery.SourceFileLoader('agent_guard_quarantine', str(AGENT))
_spec = importlib.util.spec_from_loader('agent_guard_quarantine', _loader)
agent = importlib.util.module_from_spec(_spec)
_loader.exec_module(agent)


class TestQuarantineAndLinks(unittest.TestCase):

    def setUp(self):
        self._td = tempfile.TemporaryDirectory(prefix='rp-guard-')
        self.addCleanup(self._td.cleanup)
        self.tmp = Path(self._td.name)
        self.state = self.tmp / 'state'
        self.state.mkdir()
        self.watched = self.tmp / 'watched'
        self.watched.mkdir()
        p = mock.patch.object(agent, 'STATE_DIR', self.state)
        p.start()
        self.addCleanup(p.stop)

    def test_a_link_to_a_setuid_file_leaves_that_file_alone(self):
        victim = self.tmp / 'victim'
        victim.write_text('#!/bin/sh\n')
        victim.chmod(0o4755)
        link = self.watched / 'innocent.txt'
        os.symlink(victim, link)
        moved = agent._guard_quarantine([str(link)], 'chk1')
        self.assertEqual(moved, 1)
        self.assertEqual(oct(victim.stat().st_mode & 0o7777), '0o4755', 'the mode of the file behind the link was changed')

    def test_a_real_file_is_still_moved_and_locked_down(self):
        f = self.watched / 'dropper.php'
        f.write_text('x')
        f.chmod(0o644)
        self.assertEqual(agent._guard_quarantine([str(f)], 'chk2'), 1)
        self.assertFalse(f.exists())
        vault = [v for v in (self.state / 'guard-quarantine').iterdir() if not v.name.endswith('.meta')]
        self.assertEqual(len(vault), 1)
        self.assertEqual(oct(vault[0].stat().st_mode & 0o777), '0o600')


if __name__ == '__main__':
    unittest.main()
