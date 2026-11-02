#!/usr/bin/env python3
"""The Docker image no longer runs the app tier as root (7.4.9).

docker/entrypoint.sh has to start as root: it chowns the data volume, writes the nginx settings and generates the CA. Until
7.4.9 it then started gunicorn, the scheduler and the push, SSH-gateway and web-terminal daemons from that same root shell, so
every one of them ran as root. A bare-metal install runs them as www-data, and a comment in the entrypoint itself spoke of "the
unprivileged nginx/gunicorn user". Only the nginx workers were unprivileged.

Now every one of the five is started through `APP_DROP` (setpriv to www-data), the volume is handed to www-data after the last
root write and before the first service starts, and the entrypoint stops if setpriv is missing instead of quietly running the app
as root. This file holds that shape. The checks are over the script's text, so each has a control that feeds the same checker the
old shape and requires it to object: a checker nobody has seen fail cannot be told from one that cannot.

The behaviour itself (which user each process really has, that the app tier can still write config.json, that the volume belongs to
www-data) was measured by running the real entrypoint, nginx, gunicorn, the app, the daemons and the real agent in a user namespace
that has a real uid 33; see the 7.4.9 security review.
"""
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
ENTRYPOINT = _ROOT / 'docker' / 'entrypoint.sh'
DROP = '"${APP_DROP[@]}"'

# The five long-running processes the entrypoint starts besides nginx. A sixth must be added here on purpose.
SERVICES = {
    'the app server': re.compile(r'\bgunicorn\b.*\bwsgi:application\b'),
    'the scheduler': re.compile(r'cgi-bin/scheduler\.py'),
    'the push daemon': re.compile(r'/usr/local/bin/remotepower-push\b'),
    'the SSH gateway': re.compile(r'/usr/local/bin/remotepower-sshgw\b'),
    'the web terminal': re.compile(r'/usr/local/bin/remotepower-webterm\b'),
}

# What root writes into the data volume while the script is still setting things up.
ROOT_WRITES = [
    re.compile(r'mkdir -p .*\$(SSHGW|WEBTERM)_DIR'),
    re.compile(r'>\s*"\$(SSHGW|WEBTERM)_DIR/secret"'),
    re.compile(r'rp-gen-ca'),
    re.compile(r'_migrate_storage_pg'),
    re.compile(r'satellites\.json'),
    re.compile(r'\.scanner-token'),
    re.compile(r'config\.json'),
]
HANDOVER = re.compile(r'^chown -R "\$APP_USER:\$APP_USER" "\$DATA_DIR"$')


def logical_lines(text):
    """[(first line number, command)]: comments dropped, backslash continuations joined, spaces squeezed."""
    out, cur, start = [], '', None
    for no, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if not cur and (not line.strip() or line.lstrip().startswith('#')):
            continue
        if start is None:
            start = no
        if line.endswith('\\'):
            cur += line[:-1] + ' '
            continue
        cur += line
        out.append((start, ' '.join(cur.split())))
        cur, start = '', None
    return out


def launches(lines):
    """{service: [(line, command)]} for every backgrounded start of one of the five."""
    found = {name: [] for name in SERVICES}
    for no, cmd in lines:
        if not cmd.endswith('&') or cmd.startswith(('echo', 'cd ')):
            continue
        for name, pat in SERVICES.items():
            if pat.search(cmd):
                found[name].append((no, cmd))
    return found


def violations(text):
    lines = logical_lines(text)
    problems = []
    found = launches(lines)

    for name, starts in found.items():
        if not starts:
            problems.append(f'{name} is never started, so there is nothing to check')
        for no, cmd in starts:
            if DROP not in cmd:
                problems.append(f'line {no}: {name} is started without APP_DROP, so it runs as root')
            elif cmd.index(DROP) > SERVICES[name].search(cmd).start():
                problems.append(f'line {no}: APP_DROP comes after the program of {name}')

    known = {no for starts in found.values() for no, _ in starts}
    for no, cmd in lines:
        if cmd.endswith('&') and no not in known and not cmd.startswith(('echo', 'cd ', '(')):
            problems.append(f'line {no}: a background process that is not one of the five and has no decision: {cmd[:70]}')

    execs = [(no, cmd) for no, cmd in lines if re.match(r'^exec\b', cmd)]
    if [c for _, c in execs] != ["exec nginx -g 'daemon off;'"]:
        problems.append(f'the only exec should be the nginx master, found {[c for _, c in execs]}')

    start_lines = [no for starts in found.values() for no, _ in starts]
    hand = [no for no, cmd in lines if HANDOVER.match(cmd)]
    if len(hand) != 1:
        problems.append(f'expected exactly one hand-over of the data volume to APP_USER, found {len(hand)}')
    elif start_lines:
        writes = [no for no, cmd in lines for p in ROOT_WRITES if p.search(cmd) and not cmd.endswith('&')]
        if max(writes) > hand[0]:
            problems.append(f'line {max(writes)} writes into the volume as root after the hand-over at line {hand[0]}')
        if hand[0] > min(start_lines):
            problems.append(f'the hand-over at line {hand[0]} comes after the first service starts at line {min(start_lines)}')

    guard = [no for no, cmd in lines if cmd.startswith('command -v setpriv')]
    define = [no for no, cmd in lines if cmd.startswith('APP_DROP=(')]
    if not guard or not define or guard[0] > define[0]:
        problems.append('the setpriv check must come before APP_DROP is defined')
    elif 'exit 1' not in ' '.join(c for n, c in lines if guard[0] <= n <= define[0]):
        problems.append('a missing setpriv must stop the container, not fall through to running as root')

    user = [cmd for _, cmd in lines if cmd.startswith('APP_USER=')]
    if user != ['APP_USER=www-data']:
        problems.append(f'APP_USER must be www-data, found {user}')
    for _, cmd in lines:
        if cmd.startswith('APP_DROP=('):
            for flag in ('--reuid="$APP_USER"', '--regid="$APP_USER"', '--init-groups'):
                if flag not in cmd:
                    problems.append(f'APP_DROP lacks {flag}')
    return problems


class TestTheEntrypointDropsRoot(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.text = ENTRYPOINT.read_text(encoding='utf-8')

    def test_no_violations(self):
        self.assertEqual(violations(self.text), [])

    def test_the_population_is_the_five_services(self):
        found = launches(logical_lines(self.text))
        self.assertEqual(sorted(found), sorted(SERVICES))
        for name, starts in found.items():
            self.assertEqual(len(starts), 1, f'{name}: one start expected, found {starts}')

    def test_the_script_is_valid_bash(self):
        bash = shutil.which('bash')
        if not bash:
            self.skipTest('no bash')
        r = subprocess.run([bash, '-n', str(ENTRYPOINT)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)


class TestTheCheckerCanSeeTheOldShape(unittest.TestCase):
    """Controls. Each feeds violations() a script with one thing put back the way it was before 7.4.9."""

    @classmethod
    def setUpClass(cls):
        cls.text = ENTRYPOINT.read_text(encoding='utf-8')

    def test_each_service_started_as_root_is_reported(self):
        for name, pat in SERVICES.items():
            with self.subTest(service=name):
                out = []
                for line in self.text.splitlines(keepends=True):
                    out.append(line.replace(DROP + ' ', '') if pat.search(line) and DROP in line else line)
                mutated = ''.join(out)
                self.assertNotEqual(mutated, self.text, 'the mutation did not apply')
                self.assertTrue(any(name in p for p in violations(mutated)), violations(mutated))

    def test_the_old_early_chown_alone_is_reported(self):
        mutated = self.text.replace('chown -R "$APP_USER:$APP_USER" "$DATA_DIR"\n', '', 1)
        self.assertNotEqual(mutated, self.text)
        self.assertTrue(any('hand-over' in p for p in violations(mutated)), violations(mutated))

    def test_a_hand_over_before_the_last_root_write_is_reported(self):
        line = 'chown -R "$APP_USER:$APP_USER" "$DATA_DIR"\n'
        moved = self.text.replace(line, '', 1).replace('chmod 700 "$DATA_DIR"\n', 'chmod 700 "$DATA_DIR"\n' + line, 1)
        self.assertNotEqual(moved, self.text)
        self.assertTrue(any('as root after the hand-over' in p for p in violations(moved)), violations(moved))

    def test_a_missing_setpriv_must_not_fall_through(self):
        mutated = self.text.replace('    exit 1\n}', '    :\n}', 1)
        self.assertNotEqual(mutated, self.text)
        self.assertTrue(any('must stop the container' in p for p in violations(mutated)), violations(mutated))

    def test_a_sixth_daemon_has_to_be_decided(self):
        mutated = self.text.replace('# First-greeting to the logs', 'python3 /usr/local/bin/newthing &\n# First-greeting to the logs', 1)
        self.assertNotEqual(mutated, self.text)
        self.assertTrue(any('not one of the five' in p for p in violations(mutated)), violations(mutated))

    def test_root_as_the_app_user_is_reported(self):
        mutated = self.text.replace('APP_USER=www-data', 'APP_USER=root', 1)
        self.assertNotEqual(mutated, self.text)
        self.assertTrue(any('APP_USER must be www-data' in p for p in violations(mutated)), violations(mutated))


class TestTheDropArrayBehaves(unittest.TestCase):
    """APP_DROP is a bash array used as a command prefix, with VAR=value prefixes in front of it. Run the lines from the script
    against a stand-in setpriv that records what it was handed, so quoting, the environment and the program's own arguments are
    seen reaching the program."""

    def test_environment_arguments_and_home_reach_the_program(self):
        bash = shutil.which('bash')
        if not bash:
            self.skipTest('no bash')
        lines = [c for _, c in logical_lines(ENTRYPOINT.read_text(encoding='utf-8')) if c.startswith(('APP_USER=', 'APP_DROP=('))]
        self.assertEqual(len(lines), 2, lines)
        with tempfile.TemporaryDirectory() as d:
            fake = Path(d) / 'setpriv'
            fake.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$OUT"\nprintf "HOME=%s\\nRP_DATA_DIR=%s\\n" "$HOME" "$RP_DATA_DIR" >> "$OUT"\n')
            fake.chmod(0o755)
            script = '\n'.join(lines) + '\nRP_DATA_DIR=/var/lib/remotepower ' + DROP + ' gunicorn --bind "127.0.0.1:8090" "a b" &\nwait $!\n'
            out = Path(d) / 'out'
            env = {'PATH': d + ':/usr/bin:/bin', 'OUT': str(out), 'HOME': '/root'}
            r = subprocess.run([bash, '-c', script], env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            got = out.read_text().splitlines()
        self.assertEqual(got, ['--reuid=www-data', '--regid=www-data', '--init-groups',
                               'gunicorn', '--bind', '127.0.0.1:8090', 'a b',
                               'HOME=/var/www', 'RP_DATA_DIR=/var/lib/remotepower'])


if __name__ == '__main__':
    unittest.main()
