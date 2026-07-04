"""Resolving/closing a ticket resolves its linked alert (collect-then-fire, so
the ALERTS_FILE lock is taken AFTER the TICKETS_FILE lock — no nested locks).

Drives the real handle_ticket_update() path with respond/auth/body stubbed.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())
_CGI = Path(__file__).parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

_spec = importlib.util.spec_from_file_location('api_tk_alert', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Resp(Exception):
    def __init__(self, code, body):
        super().__init__(str(code))
        self.code = code
        self.body = body or {}


class TicketResolvesAlert(unittest.TestCase):
    def setUp(self):
        self._orig = (api.respond, api.method, api.require_auth,
                      api.get_json_obj, api._tickets_enabled, api.require_write_role)

        def _respond(code, body=None):
            raise _Resp(code, body)
        api.respond = _respond
        api.require_auth = lambda *a, **k: 'tester'
        # v5.8.0: ticket create/update/hours gate on require_write_role now.
        api.require_write_role = lambda *a, **k: 'tester'
        api._tickets_enabled = lambda: True
        # clean stores
        api.save(api.ALERTS_FILE, {'alerts': []})
        api.save(api.TICKETS_FILE, {'tickets': []})

    def tearDown(self):
        (api.respond, api.method, api.require_auth,
         api.get_json_obj, api._tickets_enabled, api.require_write_role) = self._orig

    def _seed(self, ticket, alerts):
        api.save(api.ALERTS_FILE, {'alerts': alerts})
        api.save(api.TICKETS_FILE, {'tickets': [ticket]})

    def _update(self, tid, body):
        api.method = lambda: 'PATCH'
        api.get_json_obj = lambda: body
        try:
            api.handle_ticket_update(tid)
        except _Resp as r:
            return r
        self.fail('handler did not respond')

    def test_resolving_linked_ticket_resolves_alert(self):
        self._seed(
            {'id': 'tk1', 'number': 42, 'subject': 's', 'status': 'ongoing',
             'priority': 3, 'alert_id': 'al1', 'created_at': 1, 'updated_at': 1},
            [{'id': 'al1', 'event': 'config_drift', 'severity': 'medium'}])
        r = self._update('tk1', {'status': 'resolved'})
        self.assertEqual(r.code, 200)
        self.assertTrue(r.body.get('alert_resolved'))
        al = api.load(api.ALERTS_FILE)['alerts'][0]
        self.assertTrue(al.get('resolved_at'))
        self.assertEqual(al.get('resolved_by'), 'tester')
        self.assertTrue(al.get('acknowledged_at'))   # resolve implies ack

    def test_closing_also_resolves(self):
        self._seed(
            {'id': 'tk1', 'number': 7, 'status': 'ongoing', 'alert_id': 'al1',
             'created_at': 1, 'updated_at': 1},
            [{'id': 'al1', 'event': 'service_down'}])
        self._update('tk1', {'status': 'closed'})
        self.assertTrue(api.load(api.ALERTS_FILE)['alerts'][0].get('resolved_at'))

    def test_already_resolved_alert_untouched(self):
        self._seed(
            {'id': 'tk1', 'number': 7, 'status': 'ongoing', 'alert_id': 'al1',
             'created_at': 1, 'updated_at': 1},
            [{'id': 'al1', 'event': 'service_down', 'resolved_at': 999, 'resolved_by': 'someoneelse'}])
        self._update('tk1', {'status': 'resolved'})
        al = api.load(api.ALERTS_FILE)['alerts'][0]
        self.assertEqual(al.get('resolved_at'), 999)        # not overwritten
        self.assertEqual(al.get('resolved_by'), 'someoneelse')

    def test_standalone_ticket_no_alert_no_error(self):
        self._seed(
            {'id': 'tk1', 'number': 900001, 'status': 'ongoing', 'alert_id': '',
             'created_at': 1, 'updated_at': 1},
            [])
        r = self._update('tk1', {'status': 'resolved'})
        self.assertEqual(r.code, 200)
        self.assertFalse(r.body.get('alert_resolved'))

    def test_non_close_status_leaves_alert_open(self):
        self._seed(
            {'id': 'tk1', 'number': 7, 'status': 'ongoing', 'alert_id': 'al1',
             'created_at': 1, 'updated_at': 1},
            [{'id': 'al1', 'event': 'service_down'}])
        self._update('tk1', {'status': 'pending_customer'})
        self.assertFalse(api.load(api.ALERTS_FILE)['alerts'][0].get('resolved_at'))


if __name__ == '__main__':
    unittest.main()
