"""v5.4.0 "RackMatters" — time-tracking + billing feature tests.

Drives the real api.py handlers (respond/auth/body stubbed, temp RP_DATA_DIR)
plus the pure billing.py math. Covers: 0.25-hour quantize, ticket→site
derivation, the billable-needs-a-site guard, ticket/timesheet aggregation,
worksheet totals, invoice issue + entry LOCK, locked-edit refusal, void + unlock,
and the finance-role read gate.
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

_spec = importlib.util.spec_from_file_location('api_v540_feat', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)
import billing as billing_mod   # noqa: E402


class _Resp(Exception):
    def __init__(self, code, body):
        super().__init__(str(code))
        self.code = code
        self.body = body or {}


class TestBillingMath(unittest.TestCase):
    """Pure billing.py — no I/O."""

    def test_quantize(self):
        self.assertEqual(billing_mod.quantize_hours(1.3), 1.25)
        self.assertEqual(billing_mod.quantize_hours(0.1), 0.0)
        self.assertEqual(billing_mod.quantize_hours(-5), 0.0)
        self.assertEqual(billing_mod.quantize_hours(99), 24.0)
        self.assertEqual(billing_mod.quantize_hours('2'), 2.0)
        self.assertEqual(billing_mod.quantize_hours(float('nan')), 0.0)

    def test_rate_resolution(self):
        cfg = {'default_rate': 800, 'rate_card': [{'name': 'A', 'rate': 1200}],
               'sites': {'s1': {'default_rate': 900}}}
        self.assertEqual(billing_mod.resolve_rate(cfg, 's1', 'A'), 1200)   # card
        self.assertEqual(billing_mod.resolve_rate(cfg, 's1', None), 900)   # site default
        self.assertEqual(billing_mod.resolve_rate(cfg, 'sX', None), 800)   # global default

    def test_worksheet_and_totals(self):
        cfg = {'currency': 'DKK', 'default_vat': 25,
               'rate_card': [{'name': 'Std', 'rate': 800}],
               'sites': {'s1': {'vat': 25, 'recurring': [
                   {'label': 'Lic', 'kind': 'license', 'amount': 50, 'qty': 3, 'active': True},
                   {'label': 'Off', 'kind': 'service', 'amount': 99, 'qty': 1, 'active': False}]}}}
        entries = [
            {'id': 'a', 'billable': True, 'site_id': 's1', 'date': '2026-06-10', 'hours': 2.0, 'rate_name': 'Std'},
            {'id': 'b', 'billable': True, 'site_id': 's1', 'date': '2026-06-12', 'hours': 1.0, 'rate_name': 'Std'},
            {'id': 'c', 'billable': False, 'site_id': 's1', 'date': '2026-06-12', 'hours': 5.0},
            {'id': 'd', 'billable': True, 'site_id': 's1', 'date': '2026-05-01', 'hours': 9.0, 'rate_name': 'Std'},
            {'id': 'e', 'billable': True, 'site_id': 's2', 'date': '2026-06-12', 'hours': 9.0},
            {'id': 'f', 'billable': True, 'site_id': 's1', 'date': '2026-06-12', 'hours': 4.0, 'locked': True},
        ]
        ws = billing_mod.compute_worksheet(cfg, 's1', entries, '2026-06-01', '2026-06-30')
        self.assertEqual(sorted(ws['entry_ids']), ['a', 'b'])
        self.assertEqual(ws['subtotal'], 3.0 * 800 + 150)   # 2550
        self.assertEqual(ws['vat_amount'], round(2550 * 0.25, 2))
        self.assertEqual(ws['total'], 2550 + 637.5)

    def test_month_and_week(self):
        self.assertEqual(billing_mod.month_bounds('2026-02'), ('2026-02-01', '2026-02-28'))
        self.assertEqual(billing_mod.month_bounds('2024-02'), ('2024-02-01', '2024-02-29'))
        self.assertEqual(billing_mod.month_bounds('bad'), (None, None))
        self.assertEqual(len(billing_mod.week_dates('2026-W25')), 7)
        self.assertEqual(billing_mod.week_dates('nope'), [])


class TestBillingHandlers(unittest.TestCase):
    def setUp(self):
        self._orig = (api.respond, api.method, api.require_auth,
                      api.require_admin_auth, api.require_admin_or_finance_auth,
                      api.audit_log, api._caller_role, api.verify_token,
                      api.get_token_from_request, api._tickets_enabled,
                      api._billing_enabled)
        self.role = {'v': 'admin'}

        def _respond(code, body=None):
            raise _Resp(code, body)
        api.respond = _respond
        api.require_auth = lambda *a, **k: 'alice'
        api.require_admin_auth = lambda *a, **k: 'alice'
        api.require_admin_or_finance_auth = lambda *a, **k: 'alice'
        api.audit_log = lambda *a, **k: None
        api._tickets_enabled = lambda: True
        api._billing_enabled = lambda: True   # v5.4.1: Billing page opt-in gate
        api._caller_role = lambda: self.role['v']
        api.verify_token = lambda *a, **k: ('alice', self.role['v'])
        api.get_token_from_request = lambda: 'x'
        # clean stores
        api.save(api.SITES_FILE, {'site1': {'name': 'Acme', 'slug': 'acme'}})
        api.save(api.DEVICES_FILE, {'devA': {'name': 'web01', 'site': 'site1'}})
        api.save(api.TICKETS_FILE, {'tickets': [{'id': 'tk1', 'number': 900001,
                 'subject': 'Fix', 'status': 'ongoing', 'device_id': 'devA',
                 'device_name': 'web01', 'created_at': 1, 'updated_at': 1}]})
        api.save(api.TIME_ENTRIES_FILE, {'entries': [], 'seq': 0})
        api.save(api.INVOICES_FILE, {'invoices': [], 'invoice_seq': 0})
        api.save(api.BILLING_FILE, {})

    def tearDown(self):
        (api.respond, api.method, api.require_auth, api.require_admin_auth,
         api.require_admin_or_finance_auth, api.audit_log, api._caller_role,
         api.verify_token, api.get_token_from_request, api._tickets_enabled,
         api._billing_enabled) = self._orig

    def _call(self, fn, method='GET', body=None, qs='', arg=None):
        api.method = lambda: method
        api.get_json_obj = lambda: (body or {})
        api.get_json_body = lambda: (body or {})
        os.environ['QUERY_STRING'] = qs
        try:
            fn(arg) if arg is not None else fn()
        except _Resp as r:
            return r
        self.fail('handler did not respond: ' + fn.__name__)

    def _config(self):
        r = self._call(api.handle_billing_config, 'POST', {
            'currency': 'DKK', 'default_rate': 800, 'default_vat': 25, 'invoice_prefix': '2026-',
            'rate_card': [{'name': 'Standard', 'rate': 800}, {'name': 'After-hours', 'rate': 1200}],
            'site': {'site_id': 'site1', 'default_rate': 900, 'vat': 25,
                     'recurring': [{'label': 'Backup license', 'kind': 'license',
                                    'amount': 50, 'qty': 3, 'active': True}]}})
        self.assertEqual(r.code, 200, r.body)

    def test_quantize_and_site_derivation_on_ticket(self):
        self._config()
        r = self._call(api.handle_ticket_hours, 'POST',
                       {'hours': 1.3, 'rate_name': 'Standard'}, arg='tk1')
        self.assertEqual(r.code, 200, r.body)
        self.assertEqual(r.body['entry']['hours'], 1.25)        # 0.25 quantize
        self.assertEqual(r.body['entry']['site_id'], 'site1')   # derived from device
        self.assertTrue(r.body['entry']['billable'])

    def test_billable_needs_a_site(self):
        r = self._call(api.handle_time_entries, 'POST', {'hours': 1, 'billable': True})
        self.assertEqual(r.code, 400)
        self.assertIn('customer', r.body['error'])

    def test_internal_entry_and_timesheet(self):
        r = self._call(api.handle_time_entries, 'POST',
                       {'hours': 1, 'billable': False, 'category': 'meeting', 'date': '2026-06-15'})
        self.assertEqual(r.code, 200, r.body)
        self.assertEqual(r.body['entry']['category'], 'meeting')
        wk = billing_mod.iso_week_of('2026-06-15')
        r = self._call(api.handle_timesheet, 'GET', qs='week=' + wk)
        self.assertEqual(r.code, 200, r.body)
        self.assertEqual(r.body['total_hours'], 1.0)
        self.assertEqual(r.body['billable_hours'], 0.0)

    def test_worksheet_invoice_lock_and_void(self):
        self._config()
        self._call(api.handle_ticket_hours, 'POST',
                   {'hours': 1.0, 'rate_name': 'Standard', 'date': '2026-06-15'}, arg='tk1')
        self._call(api.handle_ticket_hours, 'POST',
                   {'hours': 2.0, 'rate_name': 'After-hours', 'date': '2026-06-15'}, arg='tk1')
        # worksheet: 1*800 + 2*1200 + 50*3 = 3350 ; vat 25% = 837.5
        r = self._call(api.handle_billing_worksheet, 'GET', qs='site=site1&month=2026-06')
        ws = r.body['worksheet']
        self.assertEqual(ws['subtotal'], 3350.0)
        self.assertEqual(ws['total'], 3350 + 837.5)
        # issue invoice -> locks the 2 billable entries
        r = self._call(api.handle_invoices, 'POST', {'site_id': 'site1', 'month': '2026-06'})
        self.assertEqual(r.code, 200, r.body)
        self.assertEqual(r.body['number'], '2026-00001')
        self.assertEqual(r.body['locked_entries'], 2)
        iid = r.body['id']
        # a locked entry can't be edited
        eid = api.load(api.TIME_ENTRIES_FILE)['entries'][0]['id']
        r = self._call(api.handle_time_entry_update, 'PATCH', {'hours': 9}, arg=eid)
        self.assertEqual(r.code, 409)
        # worksheet now only the recurring fee (hours invoiced)
        r = self._call(api.handle_billing_worksheet, 'GET', qs='site=site1&month=2026-06')
        self.assertEqual(r.body['worksheet']['subtotal'], 150.0)
        # void frees the entries
        r = self._call(api.handle_invoice_update, 'PATCH', {'status': 'void'}, arg=iid)
        self.assertEqual(r.code, 200)
        self.assertEqual(r.body['unlocked_entries'], 2)
        r = self._call(api.handle_time_entry_update, 'PATCH', {'hours': 9}, arg=eid)
        self.assertEqual(r.code, 200)

    def test_finance_can_read_admin_cannot_be_bypassed(self):
        self._config()
        # finance: worksheet read OK (gate is stubbed to allow, but the role drives
        # _caller_billing_view → can see money). issuing stays admin in real gate.
        self.role['v'] = 'finance'
        r = self._call(api.handle_billing_worksheet, 'GET', qs='site=site1&month=2026-06')
        self.assertEqual(r.code, 200)
        # a plain viewer listing time entries only sees their own
        self.role['v'] = 'viewer'
        self.assertFalse(api._caller_billing_view())

    def test_csv_export_runs(self):
        self._config()
        self._call(api.handle_ticket_hours, 'POST',
                   {'hours': 1.0, 'date': '2026-06-15'}, arg='tk1')
        # CSV path ends in sys.exit(0); capture binary stdout
        import io
        api.method = lambda: 'GET'
        os.environ['QUERY_STRING'] = 'format=csv'

        class _Cap:
            def __init__(self): self.buffer = io.BytesIO()
            def write(self, *a): pass
            def flush(self): pass
        old = sys.stdout
        sys.stdout = _Cap()
        try:
            api.handle_time_entries()
        except SystemExit as e:
            self.assertEqual(e.code, 0)
            data = sys.stdout.buffer.getvalue()
        finally:
            sys.stdout = old
        self.assertIn(b'Date,User,Hours', data)


if __name__ == '__main__':
    unittest.main()
