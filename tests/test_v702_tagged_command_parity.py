#!/usr/bin/env python3
"""A tagged command became a shell COMMENT on Windows and macOS.

Two server paths queue a command with a routing prefix —
`exec:#mitigate:<id>#<body>` and `exec:#acme:<id>#<body>` — so the output can be
written to a per-action log. The Linux agent has stripped that prefix since
v3.0.1. The other two never learned about it and handed the whole string to
PowerShell and /bin/sh, where `#` starts a comment. The command became a
comment, the interpreter exited 0, and the operator got a success toast for
something that never ran.

`exec:` is supported on all three platforms, so nothing stopped the command
being queued at a Windows or macOS host — this was reachable, not theoretical.

Driven against the real `command_argv` from each agent, lifted by AST because
the agents import psutil/pywin32 at module scope.
"""
import ast
import os
import re
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CLIENT = _ROOT / 'client'
sys.path.insert(0, str(Path(__file__).parent))
import srcpin  # noqa: E402


def _load_argv(agent_file):
    """The real `command_argv` out of an agent, with a stub namespace."""
    src = (_CLIENT / agent_file).read_text()
    ns = {
        'os': os, 're': re,
        '_powershell_bin': lambda: 'powershell.exe',
        '_system_bin': lambda n: f'C:\\Windows\\System32\\{n}.exe',
        '_brew_path': lambda: '/opt/homebrew/bin/brew',
        '_WINGET_ID_RE': re.compile(r'^[A-Za-z0-9._-]+$'),
    }
    for node in ast.parse(src).body:
        if isinstance(node, ast.FunctionDef) and node.name == 'command_argv':
            exec(compile(ast.Module([node], []), '<agent>', 'exec'), ns)
            return ns['command_argv']
    raise AssertionError(f'{agent_file}: command_argv not found')


class TestTheTagNeverReachesTheInterpreter(unittest.TestCase):

    def setUp(self):
        self.argv = {'win': _load_argv('remotepower-agent-win.py'),
                     'mac': _load_argv('remotepower-agent-mac.py')}

    def test_a_plain_exec_still_works(self):
        """The control. A builder that returned None for everything would pass
        every 'the tag is gone' assertion below."""
        for os_name, fn in self.argv.items():
            got = fn('exec:echo hello')
            self.assertTrue(got, os_name)
            self.assertIn('echo hello', got[-1], os_name)

    def test_the_mitigate_tag_is_stripped(self):
        for os_name, fn in self.argv.items():
            got = fn('exec:#mitigate:a1b2c3#systemctl restart nginx')
            self.assertEqual(got[-1], 'systemctl restart nginx', os_name)
            self.assertNotIn('#mitigate', got[-1], os_name)

    def test_the_acme_tag_is_stripped(self):
        for os_name, fn in self.argv.items():
            got = fn('exec:#acme:deadbeef#acme.sh --renew -d example.com')
            self.assertEqual(got[-1], 'acme.sh --renew -d example.com', os_name)

    def test_it_composes_with_the_timeout_prefix(self):
        """The server can send both. Order matters — timeout first, then tag,
        which is the order the Linux agent parses them in."""
        for os_name, fn in self.argv.items():
            got = fn('exec:to=900:#mitigate:a1b2c3#du -sh /var')
            self.assertEqual(got[-1], 'du -sh /var', os_name)

    def test_a_body_that_merely_starts_with_a_hash_is_left_alone(self):
        """`#!/bin/sh` and a leading comment are ordinary command text. Only
        the exact `#scope:id#` shape is a routing tag."""
        for os_name, fn in self.argv.items():
            for body in ('# a comment then\nls /tmp', '#!/bin/sh\necho hi',
                         '#notatag#ls'):
                got = fn('exec:' + body)
                self.assertEqual(got[-1], body, f'{os_name}: {body!r}')

    def test_the_tag_id_charset_matches_the_server(self):
        """The server builds the id with secrets.token_hex, and both regexes
        must accept exactly what it can produce."""
        for os_name, fn in self.argv.items():
            got = fn('exec:#mitigate:' + 'a' * 12 + '#true')
            self.assertEqual(got[-1], 'true', os_name)


class TestAllThreeAgentsAgree(unittest.TestCase):

    def test_every_agent_strips_both_scopes(self):
        for rel, fn in (('client/remotepower-agent.py', 'execute_command'),
                        ('client/remotepower-agent-win.py', 'command_argv'),
                        ('client/remotepower-agent-mac.py', 'command_argv')):
            body = srcpin.py_function((_ROOT / rel).read_text(), fn)
            code = '\n'.join(ln for ln in body.splitlines()
                             if not ln.lstrip().startswith('#'))
            # Both scope names, in code not comments. Written as separate
            # words rather than 'acme:' — the alternation form is
            # `(?:acme|mitigate):`, so the colon does not follow either one.
            self.assertIn('acme', code, rel)
            self.assertIn('mitigate', code, rel)
            self.assertIn('DOTALL', code,
                          f'{rel}: a tagged body can be multi-line')

    def test_the_server_still_queues_the_shape_they_parse(self):
        src = (_ROOT / 'server/cgi-bin/api.py').read_text()
        self.assertIn("f'exec:#mitigate:{action_id}#{cmd_str}'", src)


if __name__ == '__main__':
    unittest.main()
