"""v6.2.3: the run-and-wait exec path honours maker-checker change approval.

The exec modal gained a "Run and wait for output" checkbox that POSTs to
/api/exec/wait (handle_longpoll_exec). That handler did NOT enforce the
change-approval gate that the immediate path (/api/exec = handle_custom_cmd)
does — so with change_approval_enabled a caller could run an arbitrary command
via the wait path WITHOUT a second admin's approval. Now it parks a
confirmation and returns 202 instead of queuing + waiting. This test pins that.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v623-execwait-'))
_spec = importlib.util.spec_from_file_location('api_v623_execwait', CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestExecWaitApprovalGate(unittest.TestCase):
    def setUp(self):
        api.save(api.DEVICES_FILE, {'d1': {'name': 'h1', 'token': 't'}})
        api.save(api.CMDS_FILE, {})
        api.save(api.LONGPOLL_FILE, {})
        api._LOAD_CACHE.clear()
        self._orig = {k: getattr(api, k) for k in (
            'require_admin_auth', 'method', 'get_json_obj', 'respond',
            'audit_log', '_scope_block_device', '_check_exec_allowlist', '_validate_id')}
        api.require_admin_auth = lambda *a, **k: 'admin1'
        api.method = lambda: 'POST'
        api.audit_log = lambda *a, **k: None
        api._scope_block_device = lambda *a, **k: None
        api._check_exec_allowlist = lambda *a, **k: (True, '')
        api._validate_id = lambda x: True
        self._resp = {}

        def _cap(status, data=None):
            self._resp = {'status': status, 'data': data or {}}
            raise api.HTTPError(status, data or {})
        api.respond = _cap

    def tearDown(self):
        for k, v in self._orig.items():
            setattr(api, k, v)

    def _run(self, body):
        api.get_json_obj = lambda: body
        try:
            api.handle_longpoll_exec()
        except api.HTTPError:
            pass
        return self._resp

    def test_approval_on_parks_and_does_not_wait(self):
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg['change_approval_enabled'] = True
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()
        r = self._run({'device_id': 'd1', 'cmd': 'systemctl restart nginx'})
        self.assertEqual(r['status'], 202)
        self.assertTrue(r['data'].get('approval_required'))
        self.assertTrue(r['data'].get('confirmation_ids'))
        # It must NOT have created a longpoll slot (i.e. it isn't waiting/queued).
        self.assertNotIn('d1', api.load(api.LONGPOLL_FILE) or {})

    def test_approval_off_creates_the_wait_slot(self):
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg['change_approval_enabled'] = False
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()
        # The handler runs its own poll loop (time.time() against a deadline, one
        # time.sleep(1) per pass), not _longpoll_wait, so stubbing _longpoll_wait
        # changed nothing and this test waited the whole default 90 seconds. A
        # clock that only moves when the handler sleeps makes the wait instant,
        # and the sleep is the place to look at the slot the handler is waiting on.
        slots = []

        class _Clock:
            def __init__(self, real):
                self._real, self._t = real, real.time()

            def time(self):
                return self._t

            def sleep(self, seconds):
                slots.append('d1' in (api.load(api.LONGPOLL_FILE) or {}))
                self._t += 1000          # past the deadline: the next check ends the wait

            def __getattr__(self, name):
                return getattr(self._real, name)

        real_time = api.time
        api.time = _Clock(real_time)
        try:
            r = self._run({'device_id': 'd1', 'cmd': 'uptime'})
        finally:
            api.time = real_time
        # Not an approval response: it went down the wait path ...
        self.assertNotEqual(r['status'], 202)
        # ... and there was a slot for the agent's answer to land in while it waited.
        self.assertEqual(slots, [True])
        self.assertTrue(r['data'].get('timeout'))


if __name__ == '__main__':
    unittest.main()
