#!/usr/bin/env python3
"""7.4.9 agent security pass: root must not follow what a local user left in their own home directory.

The Linux agent runs as root and, for one feature, writes into a directory that belongs to somebody else: host configuration
can set `~user/.ssh/authorized_keys`. The user owns `~/.ssh`, so the user also decides what is in it. The old code did

    ssh_dir.mkdir(...); os.chown(ssh_dir, uid, gid); ak.write_text(keys); os.chmod(ak, 0o600); os.chown(ak, uid, gid)

and every one of those calls follows a symlink. With `~/.ssh` made a link to `/etc` (or `authorized_keys` a link to
`/etc/shadow`, or a hard link to a file the user can write), the next apply made the user the owner of the target, set its mode to
0600 and wrote the key list into it: a local user turning one managed key file into root. Reading has the same shape one level
down: `collect_host_config` and the IaC "ssh_keys" collector read every user's key file as root, so a link to `/etc/shadow` put the
shadow file into the report that goes to the server, and a link to `/dev/zero` or a FIFO stopped the agent's loop.

The writer now walks `home -> .ssh -> authorized_keys` through directory descriptors with O_NOFOLLOW, writes a new file beside the
old one and renames it over the name (a rename replaces a link and never follows it), and the readers refuse anything that is not
a plain file the user owns, and read a bounded amount of it.

Everything runs in a child process with a time limit: the old code blocks forever on a FIFO, and the tests are about that.
The tests run as an ordinary user. Run as root they hand the planted files to the account's uid first, so the ownership rule
sees what it sees on a real host; a user id between 1 and 999 cannot do that and skips the ownership cases.
"""
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# RP_TEST_AGENT lets the same checks run against another copy of the agent (the one from before the fix, for the fail-demo).
AGENT = Path(os.environ.get('RP_TEST_AGENT') or ROOT / 'client' / 'remotepower-agent.py')

# The account's id as the host would report it. collect_host_config only lists accounts from 1000 up.
UID = os.getuid() if os.getuid() >= 1000 else 1000

_PRELUDE = textwrap.dedent('''
    import importlib.machinery, importlib.util, json, os, pwd, resource, subprocess, sys, types
    # An agent that reads /dev/zero to the end must run out of room in here, not in the machine that runs the tests.
    resource.setrlimit(resource.RLIMIT_AS, (3 << 30, 3 << 30))
    loader = importlib.machinery.SourceFileLoader("agent_under_test", sys.argv[1])
    spec = importlib.util.spec_from_loader("agent_under_test", loader)
    agent = importlib.util.module_from_spec(spec)
    loader.exec_module(agent)
    root = sys.argv[2]
    UID = int(sys.argv[3])
    me = types.SimpleNamespace(pw_name="alice", pw_uid=UID, pw_gid=UID, pw_dir=os.path.join(root, "home"),
                               pw_passwd="x", pw_gecos="", pw_shell="/bin/bash")
    pwd.getpwnam = lambda name: me
    pwd.getpwall = lambda: [me]
    class _Done:                                   # what usermod would have returned
        returncode, stdout, stderr = 0, b"", b""
    subprocess.run = lambda *a, **k: _Done()
    KEYS = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLE managed@example\\n"
    def mode(p):
        return oct(os.lstat(p).st_mode & 0o7777)
    def read(p):
        with open(p) as f:
            return f.read()
    def apply(keys=KEYS):
        return agent.apply_host_config({"users": [{"name": "alice", "authorized_keys": keys}]})
''')


def run_child(tmp, body, timeout=30):
    """Run `body` with the agent loaded; the last stdout line is JSON. None when the child hit the time limit."""
    code = _PRELUDE + textwrap.dedent(body)
    try:
        r = subprocess.run([sys.executable, '-I', '-c', code, str(AGENT), str(tmp), str(UID)], capture_output=True, text=True,
                           timeout=timeout)
    except subprocess.TimeoutExpired:
        return None
    if r.returncode != 0:
        raise AssertionError('child failed: ' + r.stderr[-1200:])
    return json.loads(r.stdout.strip().splitlines()[-1])


class _Home(unittest.TestCase):

    def setUp(self):
        if 0 < os.getuid() < 1000:
            self.skipTest('needs to be root or an account with an id of 1000 or more')
        self._td = tempfile.TemporaryDirectory(prefix='rp-hostcfg-')
        self.addCleanup(self._td.cleanup)
        self.tmp = Path(self._td.name)
        self.home = self.tmp / 'home'
        self.home.mkdir()
        # The file root must never be tricked into touching. 0644 is chosen so that a chmod to 0600 is visible.
        self.victim = self.tmp / 'victim.txt'
        self.victim.write_text('root-owned secret\n')
        self.victim.chmod(0o644)
        self.victim_dir = self.tmp / 'victim_dir'
        self.victim_dir.mkdir()
        self.victim_dir.chmod(0o755)

    def own(self, *paths):
        """Hand a planted path to the account, as it would be on a host (only root can; anyone else already is the owner)."""
        if os.getuid() == 0:
            for p in paths:
                os.lchown(p, UID, UID)

    def ssh_dir(self):
        d = self.home / '.ssh'
        d.mkdir(mode=0o700, exist_ok=True)
        self.own(d)
        return d


class TestApplyingAuthorizedKeys(_Home):

    def test_the_ordinary_case_still_works(self):
        res = run_child(self.tmp, '''
            out = apply()
            ssh = os.path.join(me.pw_dir, ".ssh")
            print(json.dumps({"users": out["users"], "keys": read(os.path.join(ssh, "authorized_keys")) == KEYS,
                              "dir_mode": mode(ssh), "file_mode": mode(os.path.join(ssh, "authorized_keys")),
                              "leftovers": sorted(os.listdir(ssh))}))
        ''')
        self.assertIsNotNone(res)
        self.assertEqual(res['users'], 'ok')
        self.assertTrue(res['keys'])
        self.assertEqual((res['dir_mode'], res['file_mode']), ('0o700', '0o600'))
        self.assertEqual(res['leftovers'], ['authorized_keys'], 'a temporary file was left behind')

    def test_an_older_key_file_is_replaced(self):
        (self.ssh_dir() / 'authorized_keys').write_text('ssh-rsa OLD old@example\n')
        res = run_child(self.tmp, '''
            out = apply()
            print(json.dumps({"users": out["users"], "keys": read(os.path.join(me.pw_dir, ".ssh", "authorized_keys")) == KEYS}))
        ''')
        self.assertEqual(res, {'users': 'ok', 'keys': True})

    def test_a_link_in_place_of_the_key_file_is_replaced_not_followed(self):
        os.symlink(self.victim, self.ssh_dir() / 'authorized_keys')
        res = run_child(self.tmp, 'print(json.dumps({"users": apply()["users"]}))')
        self.assertIsNotNone(res)
        self.assertEqual(self.victim.read_text(), 'root-owned secret\n', 'the file the link pointed at was written through')
        self.assertEqual(oct(self.victim.stat().st_mode & 0o7777), '0o644', 'its mode was changed through the link')

    def test_a_hard_link_to_another_file_does_not_write_into_that_file(self):
        os.link(self.victim, self.ssh_dir() / 'authorized_keys')
        run_child(self.tmp, 'apply(); print(json.dumps({}))')
        self.assertEqual(self.victim.read_text(), 'root-owned secret\n', 'the other name of the file was overwritten')
        self.assertEqual(oct(self.victim.stat().st_mode & 0o7777), '0o644')

    def test_a_link_in_place_of_the_dot_ssh_directory_is_not_followed(self):
        os.symlink(self.victim_dir, self.home / '.ssh')
        res = run_child(self.tmp, 'print(json.dumps({"users": apply()["users"]}))')
        self.assertIsNotNone(res)
        self.assertEqual(os.listdir(self.victim_dir), [], 'a key file was written into the directory the link pointed at')
        self.assertEqual(oct(self.victim_dir.stat().st_mode & 0o7777), '0o755', 'its mode was changed through the link')
        self.assertNotEqual(res['users'], 'ok', 'the apply must say it did not write the keys')

    def test_a_fifo_in_place_of_the_key_file_does_not_stop_the_agent(self):
        os.mkfifo(self.ssh_dir() / 'authorized_keys')
        res = run_child(self.tmp, '''
            out = apply()
            print(json.dumps({"users": out["users"], "keys": read(os.path.join(me.pw_dir, ".ssh", "authorized_keys")) == KEYS}))
        ''', timeout=20)
        self.assertIsNotNone(res, 'the apply blocked on a FIFO a local user left in place of authorized_keys')
        self.assertEqual(res, {'users': 'ok', 'keys': True})


class TestReadingAuthorizedKeys(_Home):
    """collect_host_config and the IaC collector read the key files of every account, as root."""

    def _plant(self, kind):
        ak = self.ssh_dir() / 'authorized_keys'
        if kind == 'link_to_secret':
            os.symlink(self.victim, ak)
        elif kind == 'fifo':
            os.mkfifo(ak)
        elif kind == 'link_to_zero':
            os.symlink('/dev/zero', ak)
        elif kind == 'plain':
            ak.write_text('ssh-ed25519 AAAA mine@example\n# comment\nssh-rsa BBBB other@example\n')
        elif kind == 'huge':
            ak.write_text(('ssh-ed25519 ' + 'A' * 70 + ' k@example\n') * 40000)      # about 3 MB
        elif kind == 'link_to_own_file':
            real = self.home / 'keys.txt'
            real.write_text('ssh-ed25519 CCCC linked@example\n')
            self.own(real)
            os.symlink(real, ak)
        self.own(ak)

    def _read_both(self):
        # The IaC collector takes its accounts from /etc/passwd, and only those living under /home; point it at the temporary
        # home through a passwd line and a host_path that maps one to the other.
        return run_child(self.tmp, '''
            host = agent.collect_host_config()
            users = {u["name"]: u["authorized_keys"] for u in host["users"]}
            agent._safe_read = lambda path, max_bytes=200000: "alice:x:%d:%d::/home/alice:/bin/bash\\n" % (UID, UID)
            agent.host_path = lambda p: p.replace("/home/alice", me.pw_dir)
            iac = agent.iac_collect_ssh_keys()["authorized_keys"]
            print(json.dumps({"host": users.get("alice"), "iac": iac.get("alice")}))
        ''', timeout=20)

    def test_a_plain_key_file_is_read_by_both(self):
        self._plant('plain')
        res = self._read_both()
        self.assertIsNotNone(res)
        self.assertIn('mine@example', res['host'])
        self.assertEqual(res['iac'], ['ssh-ed25519 AAAA mine@example', 'ssh-rsa BBBB other@example'])

    def test_a_link_to_a_file_outside_the_home_is_not_read(self):
        # In a test the victim belongs to the same user as the account, so only the "inside the home" rule can keep it out.
        # On a real host a root-owned target fails the ownership rule as well.
        self._plant('link_to_secret')
        res = self._read_both()
        self.assertIsNotNone(res)
        self.assertNotIn('root-owned secret', json.dumps(res))

    def test_a_link_to_the_users_own_file_inside_the_home_is_still_read(self):
        self._plant('link_to_own_file')
        res = self._read_both()
        self.assertIsNotNone(res)
        self.assertIn('linked@example', res['host'])

    def test_a_fifo_does_not_stop_the_agent(self):
        self._plant('fifo')
        res = self._read_both()
        self.assertIsNotNone(res, 'reading the key file of an account stopped on a FIFO the user left there')

    def test_a_link_to_a_device_that_never_ends_does_not_stop_the_agent(self):
        self._plant('link_to_zero')
        res = self._read_both()
        self.assertIsNotNone(res, 'reading the key file of an account never finished (a link to /dev/zero)')

    def test_a_huge_key_file_is_cut_not_loaded_whole(self):
        self._plant('huge')
        res = self._read_both()
        self.assertIsNotNone(res)
        self.assertLessEqual(len(res['host']), 300_000, 'the whole file went into the report')
        self.assertLessEqual(len(json.dumps(res['iac'])), 600_000)
        self.assertTrue(res['host'].endswith('\n'), 'a cut file must end at a whole line')

    def test_both_collectors_go_through_the_one_reader(self):
        # Wiring: a second reader added next to these two is how the rule gets applied in some places and not others.
        res = run_child(self.tmp, '''
            seen = []
            agent._read_account_keyfile = lambda home, uid, *a, **k: (seen.append((os.path.basename(home), uid)) or "ssh-rsa Z z@e\\n")
            host = agent.collect_host_config()
            agent._safe_read = lambda path, max_bytes=200000: "alice:x:%d:%d::/home/alice:/bin/bash\\n" % (UID, UID)
            iac = agent.iac_collect_ssh_keys()["authorized_keys"]
            print(json.dumps({"seen": seen, "host": [u["authorized_keys"] for u in host["users"]], "iac": iac}))
        ''')
        self.assertIsNotNone(res)
        self.assertIn(['home', UID], res['seen'])            # collect_host_config, with the account's own id
        self.assertIn(['alice', UID], res['seen'])           # the IaC collector
        self.assertIn(['root', 0], res['seen'])
        self.assertEqual(res['host'], ['ssh-rsa Z z@e\n'])
        self.assertEqual(res['iac']['alice'], ['ssh-rsa Z z@e'])


if __name__ == '__main__':
    unittest.main()
