#!/usr/bin/env python3
"""v5.6.x ticket lifecycle events: ticket_opened / ticket_resolved.

- Both are registry-wired (kind 'tickets', no severity — they route to the
  activity feed + webhooks, never the Alerts inbox).
- ticket_resolved auto-resolves the ticket's open ticket_sla_breached alert,
  matched by ticket_id. Per CLAUDE.md ("Adding a webhook/alert event" §3)
  the alert is built via the REAL _record_alert/fire_webhook path — a
  hand-built alert dict would bypass the payload whitelist and false-green.
- handle_ticket_update fires only on the transition INTO resolved/closed.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_CGI_BIN = Path(__file__).parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI_BIN))

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())
os.environ.setdefault('REQUEST_METHOD', 'GET')
os.environ.setdefault('PATH_INFO', '/')
os.environ.setdefault('CONTENT_LENGTH', '0')

_spec = importlib.util.spec_from_file_location('api_tkev', _CGI_BIN / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _events():
    api._invalidate_load_cache(api.FLEET_EVENTS_FILE)
    return (api.load(api.FLEET_EVENTS_FILE) or {}).get('events', [])


def _alerts():
    api._invalidate_load_cache(api.ALERTS_FILE)
    return (api.load(api.ALERTS_FILE) or {}).get('alerts', [])


class TestRegistryWiring(unittest.TestCase):
    def test_both_events_registered(self):
        for ev in ('ticket_opened', 'ticket_resolved'):
            self.assertIn(ev, api.EVENT_REGISTRY)
            self.assertEqual(api.EVENT_REGISTRY[ev]['kind'], 'tickets')
            # activity/webhook only — never the Alerts inbox
            self.assertNotIn('severity', api.EVENT_REGISTRY[ev])
            self.assertIn(ev, api.WEBHOOK_EVENT_NAMES)

    def test_resolved_maps_to_sla_breach(self):
        self.assertEqual(api._ALERT_RECOVER['ticket_resolved'],
                         'ticket_sla_breached')


class TestLifecycle(unittest.TestCase):
    def setUp(self):
        for f in (api.FLEET_EVENTS_FILE, api.ALERTS_FILE, api.TICKETS_FILE):
            api.save(f, {})
        api.save(api.CONFIG_FILE, {'tickets_enabled': True})
        for f in (api.CONFIG_FILE,):
            api._invalidate_load_cache(f)
        self.cap = {}
        self._respond = api.respond
        self._auth = api.require_auth

        def fake_respond(status, body):
            self.cap['s'] = status
            self.cap['b'] = body
            raise SystemExit(0)
        api.respond = fake_respond
        api.require_auth = lambda *a, **k: 'tester'

    def tearDown(self):
        api.respond = self._respond
        api.require_auth = self._auth

    def _create_ticket(self, subject='disk broken'):
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'subject': subject, 'type': 'incident',
                                    'priority': 2}
        try:
            with self.assertRaises(SystemExit):
                api.handle_tickets()
        finally:
            del api.method
            del api.get_json_obj
        self.assertEqual(self.cap['s'], 200)
        return self.cap['b']['id'], self.cap['b']['number']

    def _update_status(self, tid, status):
        api.method = lambda: 'PATCH'
        api.get_json_obj = lambda: {'status': status}
        try:
            with self.assertRaises(SystemExit):
                api.handle_ticket_update(tid)
        finally:
            del api.method
            del api.get_json_obj

    def test_create_fires_ticket_opened(self):
        tid, number = self._create_ticket()
        ev = [e for e in _events() if e.get('event') == 'ticket_opened']
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]['payload']['ticket_id'], tid)
        self.assertEqual(ev[0]['payload']['number'], number)
        self.assertEqual(ev[0]['payload']['source'], 'operator')
        # not alertable — nothing lands in the inbox
        self.assertFalse(any(a.get('event') == 'ticket_opened' for a in _alerts()))

    def test_resolve_fires_once_and_clears_sla_alert(self):
        tid, number = self._create_ticket()
        # SLA breach through the REAL fire path (whitelist-sensitive!)
        api.fire_webhook('ticket_sla_breached', {
            'number': number, 'ticket_id': tid, 'subject': 'disk broken',
            'priority': 2, 'assignee': '', 'group': '',
            'device_id': '', 'device_name': '', 'due': 0})
        open_sla = [a for a in _alerts()
                    if a.get('event') == 'ticket_sla_breached'
                    and not a.get('resolved_at')]
        self.assertEqual(len(open_sla), 1, 'SLA breach must land in the inbox')

        self._update_status(tid, 'resolved')
        ev = [e for e in _events() if e.get('event') == 'ticket_resolved']
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]['payload']['resolved_by'], 'tester')
        # the open SLA alert auto-resolved, matched by ticket_id
        still_open = [a for a in _alerts()
                      if a.get('event') == 'ticket_sla_breached'
                      and not a.get('resolved_at')]
        self.assertEqual(still_open, [],
                         'ticket_resolved must auto-resolve the SLA alert')

    def test_no_refire_on_already_resolved(self):
        tid, _ = self._create_ticket()
        self._update_status(tid, 'resolved')
        self._update_status(tid, 'closed')   # resolved → closed: no re-fire
        ev = [e for e in _events() if e.get('event') == 'ticket_resolved']
        self.assertEqual(len(ev), 1)


if __name__ == '__main__':
    unittest.main()
