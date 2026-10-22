"""7.4.0: the Windows and macOS agents answer a person at a terminal the way the Linux agent does.

Measured by running each agent's real command line in an empty data directory:

  * `--help` printed the option names of both and described none of them (the Linux agent describes
    every one);
  * `--once` before enrolling ended in a Python traceback that blamed the address ("Server URL must use
    HTTPS, got: /api/heartbeat"), when the host was simply not enrolled;
  * a plain `http://` server address came back as that same sentence, cut off at 32 characters and
    showing an API path the person never typed.

Nothing here talks to a server: the HTTPS check has to happen before any request, and an address with
no listener is refused at once.
"""
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CLIENT = Path(__file__).resolve().parent.parent / 'client'
AGENTS = {'windows': CLIENT / 'remotepower-agent-win.py', 'macos': CLIENT / 'remotepower-agent-mac.py'}


def run(agent, *args, timeout=30):
    data = tempfile.mkdtemp(prefix='rp-agent-cli-')
    env = dict(os.environ, RP_DATA_DIR=data, HOME=data, APPDATA=data, PROGRAMDATA=data)
    env.pop('RP_CA_BUNDLE', None)
    p = subprocess.run([sys.executable, '-I', str(agent), *args], capture_output=True, text=True, timeout=timeout, env=env)
    return p.returncode, p.stdout, p.stderr


class TestEveryOptionIsDescribed(unittest.TestCase):

    def option_blocks(self, agent):
        """{'--enroll': 'description text', ...} read from the real --help output."""
        code, out, err = run(agent, '--help')
        self.assertEqual(code, 0, err)
        body = out.split('options:', 1)[1].split('\n\n', 1)[0]
        blocks, current = {}, None
        for line in body.split('\n'):
            m = re.match(r'^  ((?:-\w, )?--[\w-]+)(?: [A-Z]+)?(?:\s{2,}(.*))?$', line)
            if m:
                current = m.group(1).split(', ')[-1]
                blocks[current] = (m.group(2) or '').strip()
            elif current and line.startswith(' ' * 10):
                blocks[current] = (blocks[current] + ' ' + line.strip()).strip()
        return blocks

    def test_each_option_says_what_it_does(self):
        for name, agent in AGENTS.items():
            with self.subTest(agent=name):
                blocks = self.option_blocks(agent)
                self.assertGreater(len(blocks), 7, f'{name}: the help output was not read: {blocks}')
                bare = sorted(o for o, text in blocks.items() if len(text) < 12)
                self.assertEqual(bare, [], f'{name}: these options have no description in --help')

    def test_the_help_shows_how_to_start(self):
        for name, agent in AGENTS.items():
            with self.subTest(agent=name):
                code, out, err = run(agent, '--help')
                self.assertIn('--enroll --server https://', out)
                self.assertIn('Add host', out, 'the help should name the dashboard button that gives the PIN')

    def test_the_scan_sees_an_undescribed_option(self):
        """Control: the reader must flag a bare option, or the test above passes for the wrong reason."""
        blocks = {}
        for line in ['  --enroll', '  --server SERVER  RemotePower server address, for example https://x']:
            m = re.match(r'^  ((?:-\w, )?--[\w-]+)(?: [A-Z]+)?(?:\s{2,}(.*))?$', line)
            blocks[m.group(1)] = (m.group(2) or '').strip()
        self.assertEqual(sorted(o for o, t in blocks.items() if len(t) < 12), ['--enroll'])


class TestAFreshHostGetsAnExplanationNotATraceback(unittest.TestCase):

    def test_once_and_run_before_enrolling(self):
        for name, agent in AGENTS.items():
            for flag in ('--once', '--run'):
                with self.subTest(agent=name, flag=flag):
                    code, out, err = run(agent, flag)
                    self.assertEqual(code, 1)
                    self.assertNotIn('Traceback', err + out)
                    self.assertIn('not enrolled', err.lower())
                    self.assertIn('--enroll --server https://', err, 'the message should show the command to run')

    def test_the_macos_hint_says_sudo(self):
        """Its credentials live under /Library, which a normal user cannot write."""
        code, out, err = run(AGENTS['macos'], '--once')
        self.assertIn('sudo ', err)


class TestTheServerAddress(unittest.TestCase):

    def test_plain_http_becomes_https_and_says_so(self):
        """As on Linux. Nothing is ever sent over http://, so upgrading what was typed is safe; the message
        used to be a truncated API path ("Server URL must use HTTPS, got: http://127.0.0.1:9/api/enroll/re")."""
        for name, agent in AGENTS.items():
            with self.subTest(agent=name):
                code, out, err = run(agent, '--enroll', '--server', 'http://127.0.0.1:9', '--pin', '123456')
                self.assertIn('Only HTTPS is supported. Using https://127.0.0.1:9', err)
                self.assertIn('Could not reach https://127.0.0.1:9', err)
                self.assertNotIn('/api/', err, 'an internal path leaked into the message')
                self.assertNotIn('Traceback', err)
                self.assertEqual(code, 1)

    def test_a_bare_host_name_gets_https_and_says_so(self):
        for name, agent in AGENTS.items():
            with self.subTest(agent=name):
                code, out, err = run(agent, '--enroll', '--server', '127.0.0.1:9', '--pin', '123456')
                self.assertIn("Only HTTPS is supported. Using https://127.0.0.1:9", err)
                self.assertEqual(code, 1)

    def test_an_https_address_is_left_alone(self):
        for name, agent in AGENTS.items():
            with self.subTest(agent=name):
                code, out, err = run(agent, '--enroll', '--server', 'https://127.0.0.1:9/', '--pin', '123456')
                self.assertNotIn('Only HTTPS', err)
                self.assertIn('Could not reach https://127.0.0.1:9', err)

    def test_an_address_nobody_answers_says_it_could_not_reach_it(self):
        for name, agent in AGENTS.items():
            with self.subTest(agent=name):
                code, out, err = run(agent, '--enroll', '--server', 'https://127.0.0.1:9', '--pin', '123456')
                self.assertEqual(code, 1)
                self.assertIn('Could not reach https://127.0.0.1:9', err)
                self.assertNotIn('urlopen', err, 'urllib internals leaked into the message')

    def test_a_six_digit_token_is_a_pin(self):
        for name, agent in AGENTS.items():
            with self.subTest(agent=name):
                code, out, err = run(agent, '--enroll', '--server', 'https://127.0.0.1:9', '--token', '123456')
                self.assertEqual(code, 2)
                self.assertIn('use --pin', err)

    def test_enroll_without_a_server_is_a_usage_error(self):
        for name, agent in AGENTS.items():
            with self.subTest(agent=name):
                code, out, err = run(agent, '--enroll')
                self.assertEqual(code, 2)
                self.assertIn('--enroll needs --server', err)


class TestTheWindowsInstallerNamesTheRightButton(unittest.TestCase):

    def test_the_dashboard_button_is_add_host(self):
        text = (CLIENT / 'install-windows.ps1').read_text(encoding='utf-8')
        self.assertNotIn('Add device', text)
        self.assertIn('Add host', text)
        html = (CLIENT.parent / 'server' / 'html' / 'index.html').read_text(encoding='utf-8')
        self.assertIn('Add host', html, 'the installer points at a button that no longer exists')


if __name__ == '__main__':
    unittest.main()
