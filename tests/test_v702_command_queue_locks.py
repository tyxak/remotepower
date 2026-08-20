#!/usr/bin/env python3
"""Every write to the command queue holds the lock across its read-modify-write.

The heartbeat's drain pops a command under `_LockedUpdate(CMDS_FILE)`, and its
own comment records why: the unlocked form "had a lost-update race ... (double
execution)". Nine other writers still did `cmds = load(...)` / mutate /
`save(...)` with nothing held across the pair — one locked writer against nine
unlocked ones.

Racing a drain, the stale snapshot is written back and a command the agent has
ALREADY executed returns to the queue, to be handed out and run a second time.
On this channel that is a second reboot, a second package upgrade, a second run
of whatever the operator queued. Two of the nine were cadence sweeps that fire
from EVERY request, so the window was not narrow.

The same shape as the DEVICES_FILE sweep in issue #8, which is why the guard has
the same shape as `tests/test_device_write_locks.py`: a mechanical enumeration
rather than a list of the nine, so a tenth writer added next year is caught.

Two handlers collect their additions and apply them under one short lock at the
end, rather than holding the queue across a whole per-device fan-out —
`handle_upgrade_device` (which also takes the DEVICES lock) and
`process_schedule`. The snapshot they read is still used for duplicate
suppression and queue-depth checks; only the write moved.
"""
import ast
import pathlib
import unittest

_API = pathlib.Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin' / 'api.py'


def _functions_writing_the_queue():
    tree = ast.parse(_API.read_text())
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.FunctionDef):
            continue
        body = ast.unparse(fn)
        if 'save(CMDS_FILE' in body or '_LockedUpdate(CMDS_FILE' in body:
            out.append((fn.name, fn.lineno, body))
    return out


class TestTheScannerWorks(unittest.TestCase):

    def test_it_finds_the_writers(self):
        """Positive control — an empty population passes the check below."""
        found = _functions_writing_the_queue()
        self.assertGreater(len(found), 6,
                           f'only {len(found)} queue writers found; the '
                           f'extraction broke')

    def test_the_heartbeat_drain_is_among_them_and_locked(self):
        """The one writer that was always right, as a known-good case."""
        by_name = {n: b for n, _l, b in _functions_writing_the_queue()}
        self.assertIn('handle_heartbeat', by_name)
        self.assertIn('_LockedUpdate(CMDS_FILE', by_name['handle_heartbeat'])


class TestNoWriterIsUnlocked(unittest.TestCase):

    def test_every_queue_writer_takes_the_lock(self):
        bad = [f'{n} (api.py:{ln})' for n, ln, body in _functions_writing_the_queue()
               if 'save(CMDS_FILE' in body and '_LockedUpdate(CMDS_FILE' not in body]
        self.assertEqual(bad, [],
                         'a bare save(CMDS_FILE, …) loses a concurrent write and '
                         'can re-queue an already-executed command:\n  '
                         + '\n  '.join(bad))

    def test_no_lock_is_nested_inside_another(self):
        """One connection per data directory on the SQL backends, so a second
        _LockedUpdate opened inside the first raises. The two collect-then-apply
        handlers exist to keep these sequential."""
        tree = ast.parse(_API.read_text())
        bad = []
        for fn in ast.walk(tree):
            if not isinstance(fn, ast.FunctionDef):
                continue
            for node in ast.walk(fn):
                if not (isinstance(node, ast.With) and node.items):
                    continue
                outer = ast.unparse(node.items[0].context_expr)
                if '_LockedUpdate' not in outer:
                    continue
                for inner in ast.walk(node):
                    if inner is node or not isinstance(inner, ast.With) or not inner.items:
                        continue
                    itxt = ast.unparse(inner.items[0].context_expr)
                    if '_LockedUpdate' in itxt:
                        bad.append(f'{fn.name}: {itxt[:40]} inside {outer[:40]}')
        self.assertEqual(bad, [], 'nested locks raise on SQLite/Postgres:\n  '
                                  + '\n  '.join(bad))


class TestTheCollectingHandlersStillDeduplicate(unittest.TestCase):
    """Moving the write must not lose the duplicate suppression the snapshot
    provided — queueing the same command twice is the thing being prevented."""

    def test_both_check_membership_before_appending(self):
        by_name = {n: b for n, _l, b in _functions_writing_the_queue()}
        for name in ('handle_upgrade_device', 'process_schedule'):
            self.assertIn(name, by_name)
            body = by_name[name]
            self.assertIn('_LockedUpdate(CMDS_FILE', body)
            code = '\n'.join(l for l in body.splitlines()
                             if not l.lstrip().startswith('#'))
            self.assertIn('not in _slot', code,
                          f'{name} appends without checking for a duplicate')


if __name__ == '__main__':
    unittest.main()
