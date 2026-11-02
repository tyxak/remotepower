#!/usr/bin/env python3
"""7.4.9 agent security pass: a name put into PowerShell must stay a name.

The Windows agent runs as SYSTEM and builds a few PowerShell scripts around names it was handed: the services to watch, the
service in a `windows_service` check, the service in a `svc:` command. It put each in as a single-quoted literal and doubled the
ASCII apostrophe, which is how a single-quoted literal is escaped. PowerShell, however, reads four typographic quotes
(U+2018, U+2019, U+201A, U+201B) as single quotes too, and a literal ends at any of them unless it is doubled. A service name of

    x<U+2019>;New-Item -Path C:\\pwned;<U+2018>y

therefore closed the literal and ran `New-Item` as SYSTEM. The watched services and the check's service name arrive in the
heartbeat response, which `require-signed-commands` does not sign, and the server only trims them when they come from a device
profile; so this was a way past that setting on every Windows host.

`_ps_single_quote` now doubles all five. The checks below do it twice: on the text of the escaped literal, and (where PowerShell is
installed) by handing the real scripts the agent builds to PowerShell and asking whether the command ran.
"""
import importlib.util
import os
import random
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
AGENT = Path(os.environ.get('RP_TEST_WIN_AGENT') or ROOT / 'client' / 'remotepower-agent-win.py')

_spec = importlib.util.spec_from_file_location('rp_win_agent_quoting', AGENT)
win = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(win)

QUOTES = "'\u2018\u2019\u201a\u201b"
PWSH = shutil.which('pwsh')


class TestTheEscapedLiteral(unittest.TestCase):

    def test_every_quote_character_is_doubled(self):
        for q in QUOTES:
            with self.subTest(quote=hex(ord(q))):
                self.assertEqual(win._ps_single_quote(f'a{q}b'), f"'a{q}{q}b'")

    def test_the_ascii_apostrophe_is_unchanged(self):
        self.assertEqual(win._ps_single_quote("a'b"), "'a''b'")        # what the old test pinned
        self.assertEqual(win._ps_single_quote('plain'), "'plain'")
        self.assertEqual(win._ps_single_quote(''), "''")

    def test_no_quote_is_left_alone_in_what_comes_out(self):
        # Property: inside the outer quotes, every run of quote characters has an even length, so none of them can end the
        # literal. The alphabet is the quotes plus the characters an attack needs.
        rnd = random.Random(7)
        alphabet = QUOTES + ';$(){} abcXYZ-`"\n'
        for _ in range(2000):
            raw = ''.join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 40)))
            lit = win._ps_single_quote(raw)
            self.assertTrue(lit.startswith("'") and lit.endswith("'"))
            run = 0
            for ch in lit[1:-1] + '\0':
                if ch in QUOTES:
                    run += 1
                else:
                    self.assertEqual(run % 2, 0, f'an undoubled quote in {lit!r} (from {raw!r})')
                    run = 0

    def test_the_old_escape_would_have_failed_this(self):
        # The control: the one-line escape the agent used to have leaves the typographic quotes alone.
        old = lambda s: "'" + str(s).replace("'", "''") + "'"        # noqa: E731
        attack = 'x\u2019;New-Item -Path C:\\pwned;\u2018y'
        self.assertEqual(old(attack)[1:-1], attack)
        self.assertNotEqual(win._ps_single_quote(attack)[1:-1], attack)


@unittest.skipUnless(PWSH, 'PowerShell (pwsh) is not installed')
class TestHandedToPowerShell(unittest.TestCase):
    """The scripts the agent really builds, run by PowerShell. `New-Item` stands in for any command."""

    def setUp(self):
        self._td = tempfile.TemporaryDirectory(prefix='rp-winq-')
        self.addCleanup(self._td.cleanup)
        self.marker = Path(self._td.name) / 'PWNED'
        self.attack = f'x\u2019;New-Item -ItemType File -Path {self.marker};\u2018y'
        p = mock.patch.object(win, '_powershell_bin', lambda: PWSH)
        p.start()
        self.addCleanup(p.stop)

    def test_a_watched_service_name_cannot_run_a_command(self):
        win.get_services([self.attack])
        self.assertFalse(self.marker.exists(), 'a watched service name ran a command in PowerShell')

    def test_a_windows_service_check_cannot_run_a_command(self):
        win._eval_one_agent_check_win({'type': 'windows_service', 'param': self.attack})
        self.assertFalse(self.marker.exists(), 'the service name of a check ran a command in PowerShell')

    def test_a_service_command_quotes_its_unit_the_same_way(self):
        # `Restart-Service` stops the script at its first error, so a made-up name never reaches the injected command and this
        # path cannot be tested by whether the command ran. The script it builds is compared with the escaped literal instead.
        # (svc: arrives in the signed command channel; it shares the helper with the two unsigned paths above.)
        seen = []

        class _Done:
            returncode, stdout, stderr = 0, 'restart ok', ''
        with mock.patch.object(win.subprocess, 'run', lambda argv, **kw: (seen.append(list(argv)), _Done())[1]):
            win._run_service_action_win('svc:restart:' + self.attack)
        self.assertEqual(len(seen), 1)
        script = seen[0][-1]
        self.assertIn(win._ps_single_quote(self.attack), script)
        self.assertNotIn('\u2019;New-Item', script.replace('\u2019\u2019;New-Item', ''), 'an undoubled quote reached the script')

    def test_the_control_the_old_escape_does_run_it(self):
        # Without this the three tests above could be passing because the attack text is wrong. Run the attack through the
        # old escape and require that PowerShell does run it.
        import subprocess
        old = "'" + self.attack.replace("'", "''") + "'"
        subprocess.run([PWSH, '-NoProfile', '-NonInteractive', '-Command', f'$names=@({old});'], capture_output=True,
                       text=True, timeout=60)
        self.assertTrue(self.marker.exists(), 'the control attack did not run; the tests above prove nothing')


if __name__ == '__main__':
    unittest.main()
