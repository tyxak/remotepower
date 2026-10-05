"""DELETE /api/sshgw/sessions — the Clear sessions button.

Admin only, limited to what the caller could see in the list, and the audit log
keeps its own record. The handler runs for real against a stored session list.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-sshgw-clear-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))

from test_ip_intel import _fresh_api  # noqa: E402

ROWS = [
    {'device_id': 'd1', 'username': 'a', 'started': 3},
    {'device_id': 'd2', 'username': 'a', 'started': 2},
    {'device_id': 'gone', 'username': 'a', 'started': 1},     # its device was deleted
    {'username': 'a', 'started': 0},                          # no device recorded
]


class TestClearSessions(unittest.TestCase):
    def setUp(self):
        self.api = api = _fresh_api()
        self.cap, self.audit = {}, []

        def _respond(status, data=None):
            self.cap['status'], self.cap['data'] = status, data
            raise api.HTTPError(status, data)
        api.respond = _respond
        api.audit_log = lambda *a, **k: self.audit.append(a)
        api.get_token_from_request = lambda: 'tok'
        api.save(api.CONFIG_FILE, {'sshgw_enabled': True})
        api.save(api.DEVICES_FILE, {'d1': {'name': 'a'}, 'd2': {'name': 'b'}})
        api.save(api.SSHGW_SESSIONS_FILE, {'sessions': [dict(r) for r in ROWS]})
        api._LOAD_CACHE.clear()

    def _call(self, role='admin', method='DELETE'):
        self.api.verify_token = lambda _t=None: ('alice', role)
        self.api.method = lambda: method
        self.cap.clear()
        try:
            self.api.handle_sshgw_sessions_clear()
        except self.api.HTTPError:
            pass
        self.api._LOAD_CACHE.clear()
        return self.cap.get('status'), self.cap.get('data') or {}

    def _left(self):
        return (self.api.load(self.api.SSHGW_SESSIONS_FILE) or {}).get('sessions')

    def test_an_admin_empties_the_list_and_the_audit_log_notes_it(self):
        st, d = self._call()
        self.assertEqual((200, 4), (st, d.get('removed')))
        self.assertEqual([], self._left())
        self.assertEqual(('alice', 'sshgw_sessions_cleared', 'removed=4'), self.audit[-1])

    def test_everyone_else_is_refused_and_nothing_is_removed(self):
        for role in ('viewer', 'auditor', 'mcp'):
            st, _ = self._call(role=role)
            self.assertEqual(403, st, role)
        self.assertEqual(4, len(self._left()))
        self.assertEqual([], self.audit)

    def test_only_delete_is_accepted(self):
        for m in ('GET', 'POST'):
            self.assertEqual(405, self._call(method=m)[0], m)
        self.assertEqual(4, len(self._left()))

    def test_module_off_refuses(self):
        self.api.save(self.api.CONFIG_FILE, {'sshgw_enabled': False})
        self.api._LOAD_CACHE.clear()
        self.assertEqual(404, self._call()[0])
        self.assertEqual(4, len(self._left()))

    def test_a_scoped_caller_clears_only_what_they_could_see(self):
        api = self.api
        api._scope_filter_devices = lambda devs: {k: v for k, v in devs.items() if k == 'd1'}
        api._caller_scope = lambda: {'tags': ['web']}
        st, d = self._call()
        self.assertEqual((200, 2), (st, d.get('removed')))        # d1 and the row with no device
        left = [r.get('device_id') for r in self._left()]
        self.assertEqual(['d2', 'gone'], left, 'the other server and the orphan stay for someone who sees them')


if __name__ == '__main__':
    unittest.main()
