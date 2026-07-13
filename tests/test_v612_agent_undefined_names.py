"""Guardrail: the agents must contain no undefined global names.

Why this exists — a real bug found in the v6.1.2 finalize sweep:

    if not _re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', name):   # apply_host_config()

`_re` was never imported at module scope (the agent imports `re`; `_re` only
exists as a function-local alias elsewhere), so this raised NameError the moment
a host-config payload carried a `users` entry. The heartbeat's caller wraps the
whole apply in `except Exception: log.warning(...)`, so the exception was
swallowed: host-config apply silently died, and every section ordered AFTER
`users` (groups, sudoers, motd, logrotate, cron) never ran either.

It survived review because every existing test for `apply_host_config` is a
SOURCE-TEXT test (`AGENT.index('def apply_host_config')`, substring assertions).
Those greps see the line present and pass — they never execute it. A swallowed
NameError is invisible to that style of test, and `heartbeat()`/`apply_host_config()`
are not unit-drivable (they shell out to useradd/systemctl as root).

So this pins the invariant statically instead, via stdlib `symtable`: any name a
function READS that is neither a module-level binding, nor a builtin, nor a
runtime dunder, is a NameError waiting for the right payload. This generalises
the sibling `test_v612_agent_sysinfo_scope` guard (which pins one specific
UnboundLocalError) to the whole swallowed-NameError class.
"""
import builtins
import symtable
import unittest
from pathlib import Path

_CLIENT = Path(__file__).resolve().parent.parent / 'client'

AGENTS = [
    _CLIENT / 'remotepower-agent.py',
    _CLIENT / 'remotepower-agent-win.py',
    _CLIENT / 'remotepower-agent-mac.py',
]

# Names that genuinely exist at runtime but are not module-level symtable symbols.
_RUNTIME_DUNDERS = {'__file__', '__name__', '__doc__', '__package__', '__spec__',
                    '__loader__', '__builtins__', '__debug__'}


def undefined_names(src: str, filename: str):
    """Every (scope, name) a nested scope reads that resolves nowhere."""
    top = symtable.symtable(src, filename, 'exec')
    module_globals = {s.get_name() for s in top.get_symbols()}
    known = module_globals | set(dir(builtins)) | _RUNTIME_DUNDERS

    found = []

    def walk(table, path):
        for sym in table.get_symbols():
            # is_global() == the compiler resolved this read to a module global
            # (implicitly or via `global`). If no such global exists, it's a NameError.
            if sym.is_global() and sym.get_name() not in known:
                found.append(('.'.join(path), sym.get_name()))
        for child in table.get_children():
            walk(child, path + [child.get_name()])

    for child in top.get_children():
        walk(child, [child.get_name()])
    return found


class TestAgentsHaveNoUndefinedNames(unittest.TestCase):

    def test_no_undefined_global_names(self):
        for agent in AGENTS:
            with self.subTest(agent=agent.name):
                self.assertTrue(agent.exists(), f'{agent} is missing')
                bad = undefined_names(agent.read_text(), str(agent))
                self.assertEqual(
                    bad, [],
                    f'{agent.name} reads name(s) that are never defined: {bad}. '
                    'Each is a NameError that the agent\'s try/except wrappers will '
                    'swallow, silently killing the surrounding feature.')

    def test_the_check_actually_catches_the_bug_it_was_written_for(self):
        """A guardrail that cannot fail is worthless — prove this one fires."""
        buggy = (
            "import re\n"
            "def apply_host_config(desired):\n"
            "    if not _re.fullmatch(r'[a-z]+', desired['n']):\n"
            "        return 'bad'\n"
            "    return 'ok'\n"
        )
        self.assertEqual(undefined_names(buggy, 'buggy.py'),
                         [('apply_host_config', '_re')])
        fixed = buggy.replace('_re.fullmatch', 're.fullmatch')
        self.assertEqual(undefined_names(fixed, 'fixed.py'), [])


if __name__ == '__main__':
    unittest.main()
