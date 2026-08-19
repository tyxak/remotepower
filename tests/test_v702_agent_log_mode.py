#!/usr/bin/env python3
"""The Linux agent's log was world-readable.

`RotatingFileHandler` creates its file at the process umask — 0644 for a root
daemon — so /var/log/remotepower-agent.log has been readable by every local
account. That log records the command channel: each `Executing custom command:
…` line and the first 200 bytes of its output. Operators paste commands carrying
tokens and passwords, so a world-readable copy hands any local user the fleet's
command traffic on that host.

The macOS agent has subclassed the handler to set 0640 in `_open()` since
v6.4.0, with a docstring naming exactly this problem. The Linux agent — the one
that logs the most — was never given the same treatment.

Setting the mode in `_open()` rather than chmod-after-construction is the part
that matters: a one-off chmod is undone by the first rollover, and the log
drifts back to world-readable with nothing to say so. Both are checked here.
"""
import ast
import logging
import os
import pathlib
import stat
import sys
import tempfile
import types
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_CLIENT = _ROOT / 'client'


def _lift(agent_file, fn_name, log_path):
    """The real handler factory, with geteuid shimmed — the file log is
    root-only by design and this test does not run as root."""
    src = (_CLIENT / agent_file).read_text()
    fake_os = types.SimpleNamespace(
        **{k: getattr(os, k) for k in dir(os) if not k.startswith('_')})
    fake_os.geteuid = lambda: 0
    ns = {'os': fake_os, 'logging': logging, 'LOG_FILE': log_path,
          'BOOT_LOG_FILE': log_path + '-boot', 'BOOT_LOG_MAX_BYTES': 1024,
          'sys': sys}
    tree = ast.parse(src)
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and 'Rotating' in node.name:
            ns['_RFH'] = __import__(
                'logging.handlers', fromlist=['RotatingFileHandler']
            ).RotatingFileHandler
            exec(compile(ast.Module([node], []), '<agent>', 'exec'), ns)
        if isinstance(node, ast.FunctionDef) and node.name == fn_name:
            exec(compile(ast.Module([node], []), '<agent>', 'exec'), ns)
    return ns[fn_name]


class TestTheLinuxAgentLogIsOwnerReadable(unittest.TestCase):

    def setUp(self):
        self.d = tempfile.mkdtemp(prefix='rp-log-mode-')
        self.log = os.path.join(self.d, 'agent.log')
        self._umask = os.umask(0o022)     # the permissive case, on purpose
        self.lg = logging.getLogger('rp-v702-logmode-' + self.d)
        self.lg.handlers = []
        self.lg.setLevel(logging.INFO)

    def tearDown(self):
        os.umask(self._umask)
        for h in list(self.lg.handlers):
            h.close()
            self.lg.removeHandler(h)

    def _handler(self):
        h = _lift('remotepower-agent.py', '_agent_file_log_handler', self.log)()
        self.assertNotIsInstance(h, logging.NullHandler,
                                 'the factory bailed out — nothing under test')
        self.lg.addHandler(h)
        return h

    def test_the_file_is_created_0640(self):
        h = self._handler()
        self.lg.info('hello')
        h.flush()
        self.assertEqual(stat.S_IMODE(os.stat(self.log).st_mode), 0o640,
                         'the agent log is readable by every local account')

    def test_it_is_still_0640_after_a_rollover(self):
        """The reason this lives in `_open()`. A chmod after construction
        passes the test above and fails this one, and rotation is exactly when
        nobody is looking."""
        h = self._handler()
        self.lg.info('hello')
        h.maxBytes = 10
        for i in range(3):
            self.lg.info('rollover padding %d', i)
        h.flush()
        self.assertEqual(stat.S_IMODE(os.stat(self.log).st_mode), 0o640)

    def test_the_rotated_copies_are_0640_too(self):
        """The old content is just as sensitive as the current content."""
        h = self._handler()
        h.maxBytes = 10
        for i in range(4):
            self.lg.info('rollover padding %d', i)
        h.flush()
        rotated = [p for p in os.listdir(self.d) if p.startswith('agent.log.')]
        self.assertTrue(rotated, 'nothing rotated — the test proved nothing')
        for name in rotated:
            self.assertEqual(
                stat.S_IMODE(os.stat(os.path.join(self.d, name)).st_mode), 0o640,
                name)


class TestBothPosixAgentsAgree(unittest.TestCase):

    def test_neither_leaves_the_mode_to_the_umask(self):
        for rel in ('remotepower-agent.py', 'remotepower-agent-mac.py'):
            src = (_CLIENT / rel).read_text()
            self.assertIn('0o640', src, rel)
            self.assertIn('def _open(self):', src,
                          f'{rel}: the mode must be set in _open(), or the '
                          f'first rollover undoes it')


if __name__ == '__main__':
    unittest.main()
