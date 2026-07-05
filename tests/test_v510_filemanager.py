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


if __name__ == '__main__':
    unittest.main()
