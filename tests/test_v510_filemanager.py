"""v5.1.0 — web file manager (agent-based, allowlist-confined).

Covers the security-critical guarantees:
  * server path validators reject traversal / non-absolute / denied prefixes
  * the route + handler are wired and gated
  * the agent worker confines every op to an allowlisted root, follows
    symlinks when re-checking (so a symlink can't escape), refuses mutations
    in audit mode, and never raises.
"""
import importlib.util
import json
import os
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
_AGENT_PY = _ROOT / 'client' / 'remotepower-agent.py'

_spec = importlib.util.spec_from_file_location('api_fm', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _load_agent():
    spec = importlib.util.spec_from_file_location('rpa_fm', _AGENT_PY)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class TestServerValidators(unittest.TestCase):
    def test_valid_abs_path(self):
        self.assertTrue(api._valid_abs_path('/etc/hosts'))
        self.assertTrue(api._valid_abs_path('/var/log/syslog'))
        self.assertFalse(api._valid_abs_path('etc/hosts'))         # not absolute
        self.assertFalse(api._valid_abs_path('/etc/../root/.ssh'))  # traversal
        self.assertFalse(api._valid_abs_path('/etc/\x00boom'))      # NUL
        self.assertFalse(api._valid_abs_path(''))
        self.assertFalse(api._valid_abs_path('/' + 'a' * 5000))     # too long

    def test_under_roots(self):
        roots = ['/etc', '/var/log']
        self.assertTrue(api._file_path_under_roots('/etc/hosts', roots))
        self.assertTrue(api._file_path_under_roots('/etc', roots))
        self.assertTrue(api._file_path_under_roots('/var/log/syslog', roots))
        self.assertFalse(api._file_path_under_roots('/root/.ssh/id_rsa', roots))
        self.assertFalse(api._file_path_under_roots('/etcd/x', roots))  # prefix, not a dir boundary

    def test_deny_prefixes_always_blocked(self):
        # Even if an operator allowlists '/', the kernel pseudo-fs stay denied.
        self.assertFalse(api._file_path_under_roots('/proc/1/mem', ['/']))
        self.assertFalse(api._file_path_under_roots('/sys/kernel', ['/']))
        self.assertFalse(api._file_path_under_roots('/dev/sda', ['/']))


class TestApiWiring(unittest.TestCase):
    def test_handler_and_route_exist(self):
        self.assertTrue(hasattr(api, 'handle_device_files'))
        src = (_CGI / 'api.py').read_text()
        # routed for GET + POST
        self.assertIn("pi.endswith('/files') and m in ('GET', 'POST')", src)
        # gated on the command perm + audited
        h = src[src.index('def handle_device_files'):src.index('def handle_device_files') + 4500]
        self.assertIn("require_perm('command'", h)
        self.assertIn("audit_log(actor, 'file_manager'", h)
        # v6.0.0: always-on — the disabled→403 branch is GONE; the roots
        # allow-list + command permission still gate everything.
        self.assertNotIn("File manager is disabled", h)
        self.assertIn("fm.get('roots')", h)

    def test_longpoll_wait_helper(self):
        self.assertTrue(hasattr(api, '_longpoll_wait'))


class TestAgentFileOps(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.m = _load_agent()
        self.tmp = Path(tempfile.mkdtemp(prefix='rp-fm-'))
        # Allowlist ONLY our sandbox root for the duration of the test.
        self.m.FILE_MGR_DEFAULT_ROOTS = (str(self.tmp),)

    def _op(self, *parts):
        import base64
        enc = [parts[0], parts[1]] + [base64.urlsafe_b64encode(p.encode()).decode()
                                      for p in parts[2:]]
        return self.m._handle_file_op(':'.join(enc))

    def test_list_read_write_roundtrip(self):
        (self.tmp / 'a.txt').write_text('hello')
        r = self._op('files', 'list', str(self.tmp))
        self.assertEqual(r['rc'], 0)
        names = [e['name'] for e in json.loads(r['output'])['entries']]
        self.assertIn('a.txt', names)

        r = self._op('files', 'read', str(self.tmp / 'a.txt'))
        self.assertEqual(json.loads(r['output'])['content'], 'hello')

        # write goes through the 4-part form
        import base64
        cmd = ':'.join(['files', 'write',
                        base64.urlsafe_b64encode(str(self.tmp / 'b.txt').encode()).decode(),
                        base64.urlsafe_b64encode(b'written!').decode()])
        r = self.m._handle_file_op(cmd)
        self.assertEqual(r['rc'], 0)
        self.assertEqual((self.tmp / 'b.txt').read_text(), 'written!')

    def test_mkdir_and_delete(self):
        r = self._op('files', 'mkdir', str(self.tmp / 'sub'))
        self.assertEqual(r['rc'], 0)
        self.assertTrue((self.tmp / 'sub').is_dir())
        r = self._op('files', 'delete', str(self.tmp / 'sub'))
        self.assertEqual(r['rc'], 0)
        self.assertFalse((self.tmp / 'sub').exists())

    def test_outside_root_rejected(self):
        r = self._op('files', 'read', '/etc/passwd')
        self.assertEqual(r['rc'], 1)
        self.assertIn('allowlisted', json.loads(r['output'])['error'])

    def test_symlink_escape_blocked(self):
        # A symlink inside the allowed root pointing OUT must be refused on the
        # symlink-resolved re-check.
        target = self.tmp.parent / 'outside-secret'
        target.write_text('secret')
        link = self.tmp / 'escape'
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest('symlinks unavailable')
        r = self._op('files', 'read', str(link))
        self.assertEqual(r['rc'], 1)
        self.assertIn('escape', json.loads(r['output'])['error'])

    def test_audit_mode_blocks_writes_allows_reads(self):
        (self.tmp / 'c.txt').write_text('x')
        orig = self.m._audit_mode
        self.m._audit_mode = lambda: True
        try:
            # read still works
            r = self._op('files', 'read', str(self.tmp / 'c.txt'))
            self.assertEqual(r['rc'], 0)
            # mkdir refused
            r = self._op('files', 'mkdir', str(self.tmp / 'nope'))
            self.assertEqual(r['rc'], 126)
            self.assertFalse((self.tmp / 'nope').exists())
        finally:
            self.m._audit_mode = orig


class TestAgentArchiveOp(unittest.TestCase):
    """v6.1.1 — folder-as-tar streaming archive, agent side. A SEPARATE channel
    from _handle_file_op above: it tar.gz's the directory locally and streams
    the result back in bounded chunks over its own endpoint, authenticated the
    same way heartbeat is (device_id/token in the body), rather than returning
    one bounded result through the normal cmd_output path (see
    docs/feature-buildout-scoping-internal.md #9)."""

    def setUp(self):
        import tempfile
        self.m = _load_agent()
        self.tmp = Path(tempfile.mkdtemp(prefix='rp-fm-archive-'))
        self.m.FILE_MGR_DEFAULT_ROOTS = (str(self.tmp),)
        self.m.load_credentials = lambda: {
            'server_url': 'https://server.example', 'device_id': 'dev1', 'token': 'tok'}
        self.posts = []

        def _fake_post(url, data, timeout=10):
            self.posts.append((url, data))
            return {'ok': True, 'continue': True}
        self.m.http_post = _fake_post

    def _cmd(self, job_id, path):
        import base64
        return 'files:archive:' + job_id + ':' + base64.urlsafe_b64encode(path.encode()).decode()

    def _posted_blob(self):
        import base64
        return b''.join(base64.b64decode(d['chunk']) for _, d in self.posts if d.get('chunk'))

    def test_archives_directory_and_posts_valid_tar(self):
        (self.tmp / 'a.txt').write_text('hello')
        (self.tmp / 'sub').mkdir()
        (self.tmp / 'sub' / 'b.txt').write_text('world')
        r = self.m._handle_file_archive(self._cmd('job1', str(self.tmp)))
        self.assertEqual(r['rc'], 0)
        self.assertTrue(self.posts)
        for url, data in self.posts:
            self.assertEqual(data['job_id'], 'job1')
            self.assertEqual(data['token'], 'tok')
            self.assertIn('/api/devices/dev1/files/archive-chunk', url)
        self.assertTrue(self.posts[-1][1]['final'])
        import io
        import tarfile
        with tarfile.open(fileobj=io.BytesIO(self._posted_blob()), mode='r:gz') as tar:
            names = sorted(tar.getnames())
        self.assertIn('a.txt', names)
        self.assertIn(os.path.join('sub', 'b.txt'), names)

    def test_symlinked_file_and_dir_excluded(self):
        (self.tmp / 'kept.txt').write_text('x')
        outside = self.tmp.parent / 'archive-outside-secret'
        outside.write_text('secret')
        link = self.tmp / 'escape.txt'
        linkdir = self.tmp / 'escape-dir'
        try:
            link.symlink_to(outside)
            linkdir.symlink_to(self.tmp.parent, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest('symlinks unavailable')
        r = self.m._handle_file_archive(self._cmd('job2', str(self.tmp)))
        self.assertEqual(r['rc'], 0)
        import io
        import tarfile
        with tarfile.open(fileobj=io.BytesIO(self._posted_blob()), mode='r:gz') as tar:
            names = sorted(tar.getnames())
        self.assertIn('kept.txt', names)
        self.assertNotIn('escape.txt', names)
        self.assertFalse(any(n.startswith('escape-dir' + os.sep) for n in names))

    def test_path_outside_roots_reports_error(self):
        r = self.m._handle_file_archive(self._cmd('job3', '/etc/passwd'))
        self.assertEqual(r['rc'], 1)
        self.assertTrue(self.posts)
        self.assertTrue(self.posts[-1][1].get('error'))

    def test_raw_size_cap_reports_error(self):
        (self.tmp / 'big.bin').write_bytes(b'x' * 1000)
        orig_cap = self.m._FILE_ARCHIVE_RAW_MAX
        self.m._FILE_ARCHIVE_RAW_MAX = 500
        try:
            r = self.m._handle_file_archive(self._cmd('job4', str(self.tmp)))
        finally:
            self.m._FILE_ARCHIVE_RAW_MAX = orig_cap
        self.assertEqual(r['rc'], 1)
        self.assertTrue(self.posts[-1][1].get('error'))

    def test_server_stop_breaks_the_loop_before_the_whole_file_is_sent(self):
        orig_chunk = self.m._FILE_ARCHIVE_CHUNK
        self.m._FILE_ARCHIVE_CHUNK = 1024
        (self.tmp / 'a.bin').write_bytes(os.urandom(4000))   # incompressible -> needs >1 chunk
        calls = {'n': 0}

        def _stop_after_one(url, data, timeout=10):
            calls['n'] += 1
            self.posts.append((url, data))
            return {'ok': True, 'continue': False}
        self.m.http_post = _stop_after_one
        try:
            r = self.m._handle_file_archive(self._cmd('job5', str(self.tmp)))
        finally:
            self.m._FILE_ARCHIVE_CHUNK = orig_chunk
        self.assertEqual(r['rc'], 0)
        self.assertEqual(calls['n'], 1)   # stopped after the first chunk, not the whole file

    def test_missing_credentials_does_not_raise(self):
        self.m.load_credentials = lambda: None
        r = self.m._handle_file_archive(self._cmd('job6', str(self.tmp)))
        self.assertEqual(r['rc'], 1)
        self.assertFalse(self.posts)   # nowhere to report the error without creds


if __name__ == '__main__':
    unittest.main()
