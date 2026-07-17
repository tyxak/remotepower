"""v6.2.3: a ticket opened from an alert now seeds its first message (an internal
note) with the FULL alert detail. The alert *title* — which became the ticket
subject — kept only the first item plus a "(+N more)" count, so the rest of the
failed units / CVEs / log matches were lost. _alert_ticket_detail expands them
from the live source so the ticket stands on its own.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v623-td-'))
_spec = importlib.util.spec_from_file_location('api_v623_td', CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_UNITS = ['dmesg.service', 'maldet.service', 'snap.lxd.activate.service', 'snapd.seeded.service']


class TestAlertDetailHelper(unittest.TestCase):
    def test_failed_unit_lists_every_unit_from_live_sysinfo(self):
        dev = {'name': 'w1', 'sysinfo': {'failed_units': list(_UNITS)}}
        al = {'event': 'failed_unit', 'device_id': 'd1', 'severity': 'high',
              'title': 'Service failed on w1: dmesg.service (+3 more)',
              'payload': {'unit': 'dmesg.service', 'new_count': 4}}
        body = api._alert_ticket_detail(al, dev)
        for u in _UNITS:
            self.assertIn(u, body, f'{u} must be in the seeded note (title only kept the first)')

    def test_cve_lists_findings_from_the_store(self):
        api.save(api.CVE_FINDINGS_FILE, {'d1': {'findings': [
            {'vuln_id': 'CVE-2025-0001', 'severity': 'critical', 'package': 'openssl', 'fixed_version': '3.1'},
            {'vuln_id': 'CVE-2025-0002', 'severity': 'high', 'package': 'curl', 'fixed_version': ''},
        ]}})
        api._invalidate_load_cache(api.CVE_FINDINGS_FILE)
        al = {'event': 'cve_found', 'device_id': 'd1', 'severity': 'high',
              'title': 'New CVEs Detected', 'payload': {'critical': 1}}
        body = api._alert_ticket_detail(al, {'name': 'w1'})
        self.assertIn('CVE-2025-0001', body)
        self.assertIn('CVE-2025-0002', body)
        self.assertIn('openssl', body)
        self.assertIn('1 critical', body)

    def test_log_alert_shows_pattern_and_sample_lines(self):
        al = {'event': 'log_alert', 'device_id': 'd1', 'severity': 'medium',
              'title': 'Log Pattern Matched',
              'payload': {'unit': 'docker.service', 'pattern': 'ShouldRestart failed',
                          'count': 9, 'sample': ['line A', 'line B', 'line C']}}
        body = api._alert_ticket_detail(al, {})
        for s in ('docker.service', 'ShouldRestart failed', '9', 'line A', 'line B', 'line C'):
            self.assertIn(s, body)

    def test_sample_survives_the_record_alert_whitelist(self):
        # the ticket sample lines only work because 'sample' is whitelisted into
        # the stored alert payload (it used to be dropped).
        src = (CGI / 'api.py').read_text()
        i = src.index('def _record_alert(')
        self.assertIn("'sample'", src[i:i + 6000])

    def test_no_note_when_there_is_nothing_to_add(self):
        al = {'event': 'mystery', 'device_id': 'd1', 'title': 'x', 'payload': {}}
        self.assertEqual(api._alert_ticket_detail(al, {}), '')

    def test_non_dict_alert_is_safe(self):
        self.assertEqual(api._alert_ticket_detail(None, {}), '')


class TestTicketSeedsDetailEndToEnd(unittest.TestCase):
    def setUp(self):
        api.save(api.CONFIG_FILE, {'tickets_enabled': True})
        api.save(api.DEVICES_FILE, {'d1': {'name': 'w1', 'tenant': '',
                 'sysinfo': {'failed_units': list(_UNITS)}}})
        api.save(api.ALERTS_FILE, {'alerts': [{
            'id': 'al1', 'event': 'failed_unit', 'device_id': 'd1', 'device_name': 'w1',
            'severity': 'high', 'title': 'Service failed on w1: dmesg.service (+3 more)',
            'payload': {'unit': 'dmesg.service', 'new_count': 4}}]})
        api.save(api.TICKETS_FILE, {'tickets': []})
        for f in (api.CONFIG_FILE, api.DEVICES_FILE, api.ALERTS_FILE, api.TICKETS_FILE):
            api._invalidate_load_cache(f)
        self.cap = {}
        self._r, self._auth, self._w = api.respond, api.require_auth, api.require_write_role

        def fake_respond(s, b=None):
            self.cap['s'], self.cap['b'] = s, b
            raise SystemExit(0)
        api.respond = fake_respond
        api.require_auth = lambda *a, **k: 'tester'
        api.require_write_role = lambda *a, **k: 'tester'

    def tearDown(self):
        api.respond, api.require_auth, api.require_write_role = self._r, self._auth, self._w

    def test_ticket_from_failed_unit_alert_is_seeded_with_full_list(self):
        api.method = lambda: 'POST'
        api.get_json_obj = lambda: {'alert_id': 'al1'}
        api.get_json_body = api.get_json_obj
        try:
            api.handle_tickets()
        except (SystemExit, Exception):
            pass
        finally:
            for a in ('method', 'get_json_obj', 'get_json_body'):
                if hasattr(api, a):
                    try:
                        delattr(api, a)
                    except Exception:
                        pass
        tickets = (api.load(api.TICKETS_FILE) or {}).get('tickets', [])
        self.assertTrue(tickets, 'a ticket should have been created')
        msgs = tickets[-1].get('messages') or []
        self.assertTrue(msgs, 'the ticket must be seeded with an alert-detail note')
        self.assertEqual(msgs[0].get('direction'), 'note')
        body = msgs[0].get('body', '')
        for u in _UNITS:
            self.assertIn(u, body, 'the full failed-unit list must be in the ticket')


class TestTicketAutoUpdateOnRecover(unittest.TestCase):
    """When a recover event auto-resolves an alert that opened a ticket, the ticket
    updates itself: a recovery note, and an auto-resolve if it's still untouched."""

    def _setup(self, ticket_status='ongoing', auto_resolve=True):
        api.save(api.CONFIG_FILE, {'ticket_auto_resolve_on_recover': auto_resolve})
        # an OPEN service_down alert on d1/nginx, linked to ticket tk1
        api.save(api.ALERTS_FILE, {'alerts': [{
            'id': 'al9', 'event': 'service_down', 'device_id': 'd1',
            'device_name': 'w1', 'severity': 'high', 'title': 'Service down',
            'payload': {'unit': 'nginx', 'device_id': 'd1'},
            'rp_ticket': 5001, 'rp_ticket_id': 'tk1'}]})
        api.save(api.TICKETS_FILE, {'tickets': [{
            'id': 'tk1', 'number': 5001, 'subject': 'Service down', 'status': ticket_status,
            'device_id': 'd1', 'alert_id': 'al9', 'messages': [], 'priority': 2}]})
        for f in (api.CONFIG_FILE, api.ALERTS_FILE, api.TICKETS_FILE):
            api._invalidate_load_cache(f)

    def _recover(self):
        # service_recover resolves service_down (matched by unit)
        api._auto_resolve_alerts('service_recover', {'device_id': 'd1', 'unit': 'nginx'})

    def _ticket(self):
        return next(t for t in (api.load(api.TICKETS_FILE) or {}).get('tickets', []) if t['id'] == 'tk1')

    def test_recover_resolves_alert_and_autocloses_untouched_ticket(self):
        self._setup(ticket_status='ongoing', auto_resolve=True)
        self._recover()
        al = next(a for a in api.load(api.ALERTS_FILE)['alerts'] if a['id'] == 'al9')
        self.assertTrue(al.get('resolved_at'), 'the alert must be auto-resolved')
        t = self._ticket()
        self.assertEqual(t['status'], 'resolved', 'untouched ticket should auto-resolve')
        self.assertTrue(t.get('auto_resolved'))
        self.assertTrue(t['messages'], 'a recovery note should be appended')
        self.assertIn('recovered', t['messages'][-1]['body'].lower())

    def test_ticket_a_human_is_working_only_gets_a_note(self):
        self._setup(ticket_status='pending_internal', auto_resolve=True)
        self._recover()
        t = self._ticket()
        self.assertEqual(t['status'], 'pending_internal', 'do not clobber a ticket in progress')
        self.assertTrue(t['messages'], 'but it still gets a recovery note')
        self.assertIn('recovered', t['messages'][-1]['body'].lower())

    def test_auto_resolve_can_be_disabled(self):
        self._setup(ticket_status='ongoing', auto_resolve=False)
        self._recover()
        t = self._ticket()
        self.assertEqual(t['status'], 'ongoing', 'auto-resolve off → status unchanged')
        self.assertTrue(t['messages'], 'note still added')


if __name__ == '__main__':
    unittest.main()
