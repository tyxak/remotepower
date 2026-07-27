#!/usr/bin/env python3
"""v6.4.1: the macOS agent's log is bounded.

Reported from the field: `/var/log/remotepower-agent.log` looked like it had no
rotation. On Linux and Windows it does — both agents carry a RotatingFileHandler
(5 MB x 5 and 1 MB x 3) and deliberately self-rotate so no logrotate/cron is
required. The macOS agent had **no logging configuration at all**: it wrote to
stderr, and `install-macos.sh` pointed launchd's StandardOutPath/StandardErrorPath
straight at that file. launchd never rotates, so the file grew without limit on
every Mac in the fleet.

Two things this pins that are easy to get wrong:

  * the mode must survive ROLLOVER. The stdlib handler creates each new file at
    the process umask, so a one-off chmod after construction is undone by the
    first rotation and the log silently drifts back to world-readable.
  * launchd's own redirect must NOT share the inode with the rotating handler.
    The handler renames on rollover while launchd keeps an fd to the old inode,
    so its output would disappear into a file nothing reads.
"""
import importlib.util
import logging
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_AGENT = _ROOT / 'client' / 'remotepower-agent-mac.py'
_INSTALLER = _ROOT / 'client' / 'install-macos.sh'


def _fresh_agent(inherit_env=False):
    """Re-import the agent with a PRISTINE environment by default.

    RP_AGENT_LOG redirects the log paths, and other test modules legitimately
    set it at module scope so importing the agent cannot touch a real /var/log.
    Under `unittest discover` every module is imported into one process before
    any test runs, so that set is ambient by the time these tests execute — and
    any assertion about the DEFAULT paths silently reads the other module's temp
    path instead. That failed the gate twice: once for the defaults test, then
    again for the installer test, because the first fix only covered the
    call site I happened to be looking at.

    So the default is now the safe direction: tests get the real defaults unless
    they explicitly ask to inherit the environment.
    """
    saved = None if inherit_env else os.environ.pop('RP_AGENT_LOG', None)
    try:
        logging.getLogger('remotepower').handlers.clear()
        spec = importlib.util.spec_from_file_location('rp_mac_log', _AGENT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        if saved is not None:
            os.environ['RP_AGENT_LOG'] = saved


class TestMacAgentLogRotation(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.ag = _fresh_agent()
        self.ag.LOG_FILE = os.path.join(self.d, 'agent.log')
        self.ag.LOG_MAX_BYTES = 20_000
        self.ag.LOG_BACKUPS = 3
        logging.getLogger('remotepower').handlers.clear()
        self.log = self.ag._make_logger()
        # Drop the stderr handler so the probe doesn't flood the test output.
        for h in list(self.log.handlers):
            if not hasattr(h, 'baseFilename'):
                self.log.removeHandler(h)
        self.addCleanup(logging.getLogger('remotepower').handlers.clear)

    def _spam(self, n=4000):
        for i in range(n):
            self.log.info('heartbeat %d - representative padding line', i)

    def _log_files(self):
        return sorted(f for f in os.listdir(self.d) if f.startswith('agent.log'))

    def test_a_rotating_handler_is_installed(self):
        self.assertTrue(any(hasattr(h, 'baseFilename') for h in self.log.handlers),
                        'no file handler — the macOS log would be unbounded')

    def test_the_log_is_capped_and_keeps_backups(self):
        self._spam()
        files = self._log_files()
        self.assertEqual(len(files), 4, files)   # current + 3 backups, no more
        total = sum(os.path.getsize(os.path.join(self.d, f)) for f in files)
        self.assertLessEqual(total, self.ag.LOG_MAX_BYTES * 4 + 4000,
                             f'log grew past its cap: {total}')

    def test_mode_is_owner_group_only_and_survives_rollover(self):
        # The regression this guards: a chmod at construction is undone by the
        # first rollover, so the log quietly becomes world-readable again. It
        # carries device ids, the server URL and operator command output.
        self._spam()
        for f in self._log_files():
            mode = stat.S_IMODE(os.stat(os.path.join(self.d, f)).st_mode)
            self.assertEqual(mode, 0o640, f'{f} is {oct(mode)}')

    def test_defaults_match_the_linux_agent(self):
        fresh = _fresh_agent()
        self.assertEqual(fresh.LOG_MAX_BYTES, 5 * 1024 * 1024)
        self.assertEqual(fresh.LOG_BACKUPS, 5)
        self.assertEqual(fresh.LOG_FILE, '/var/log/remotepower-agent.log')
        self.assertEqual(fresh.BOOT_LOG_FILE,
                         '/var/log/remotepower-agent-boot.log')

    def test_rp_agent_log_redirects_both_files(self):
        # Importing this module builds the handler, so without an override a
        # root test run (or a root container) would create a REAL system log.
        # The boot path is derived, so the two can never drift apart.
        os.environ['RP_AGENT_LOG'] = os.path.join(self.d, 'redirected.log')
        self.addCleanup(os.environ.pop, 'RP_AGENT_LOG', None)
        ag = _fresh_agent(inherit_env=True)      # this test IS about the override
        self.assertEqual(ag.LOG_FILE, os.path.join(self.d, 'redirected.log'))
        self.assertEqual(ag.BOOT_LOG_FILE,
                         os.path.join(self.d, 'redirected-boot.log'))

    def test_logger_creation_never_raises_when_var_log_is_unwritable(self):
        ag = _fresh_agent()
        ag.LOG_FILE = '/proc/nonexistent-dir/agent.log'
        logging.getLogger('remotepower').handlers.clear()
        lg = ag._make_logger()          # must degrade to stderr, never raise
        self.assertTrue(lg.handlers)

    def test_no_bare_stderr_writes_remain(self):
        # Anything written with sys.stderr.write goes to launchd's file, which
        # is NOT the rotating one — so it would escape the cap.
        self.assertNotIn('sys.stderr.write', _AGENT.read_text())


class TestBootLogTrim(unittest.TestCase):
    """launchd's crash-output file is bounded too, and truncating it must not
    break the fd launchd holds open for the life of the process."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.ag = _fresh_agent()
        self.boot = os.path.join(self.d, 'boot.log')
        self.ag.BOOT_LOG_FILE = self.boot
        self.ag.BOOT_LOG_MAX_BYTES = 1000

    def test_undersized_file_is_left_alone(self):
        with open(self.boot, 'w') as f:
            f.write('x' * 100)
        self.assertFalse(self.ag._trim_boot_log())
        self.assertEqual(os.path.getsize(self.boot), 100)

    def test_missing_file_is_not_an_error(self):
        self.assertFalse(self.ag._trim_boot_log())

    def test_oversized_file_is_truncated_in_place(self):
        with open(self.boot, 'w') as f:
            f.write('x' * 5000)
        self.assertTrue(self.ag._trim_boot_log())
        self.assertEqual(os.path.getsize(self.boot), 0)

    def test_an_open_append_fd_still_writes_after_the_trim(self):
        # This is why it truncates instead of renaming. launchd holds an
        # O_APPEND fd; a rename would leave it writing to an orphaned inode.
        with open(self.boot, 'w') as f:
            f.write('x' * 5000)
        fd = os.open(self.boot, os.O_WRONLY | os.O_APPEND)
        try:
            self.assertTrue(self.ag._trim_boot_log())
            os.write(fd, b'still here\n')
        finally:
            os.close(fd)
        self.assertEqual(open(self.boot).read(), 'still here\n')

    def test_run_loop_trims_the_boot_log(self):
        src = _AGENT.read_text()
        body = src[src.index('def run():'):]
        body = body[:body.index('\ndef ', 1)]
        self.assertIn('_trim_boot_log()', body,
                      'the trim helper is never called — dead code, and the '
                      'boot log would grow unbounded')


class TestInstallerWiring(unittest.TestCase):
    def setUp(self):
        if not _INSTALLER.exists():
            self.skipTest('installer excluded from this tree')
        self.src = _INSTALLER.read_text()

    def test_launchd_does_not_share_the_rotating_logs_inode(self):
        # Both writers on one file: the handler renames on rollover, launchd
        # keeps writing to the old inode, and its output silently disappears.
        for key in ('StandardOutPath', 'StandardErrorPath'):
            line = next(ln for ln in self.src.splitlines() if key in ln)
            self.assertIn('remotepower-agent-boot.log', line, line)
            self.assertNotIn('<string>/var/log/remotepower-agent.log</string>',
                             line, line)

    def test_boot_log_path_matches_the_agent(self):
        self.assertIn(_fresh_agent().BOOT_LOG_FILE, self.src,
                      'the installer and the agent disagree about the boot-log '
                      'path, so the agent would trim a file nothing writes')


if __name__ == '__main__':
    unittest.main(verbosity=2)
