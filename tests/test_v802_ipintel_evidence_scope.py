"""What the logs of a host showed about an address is read by the owners of that host, and by nobody else (8.0.2).

One address has one row and one evidence ledger for the whole installation: the sweep adds up what every host's logs said, so an
address that two tenants' hosts saw is reported once. The ledger holds the request paths, the jail names, the CVE ids, the rule ids and
the counts of the hosts that collected it. `GET /api/ip-intel` filtered the row's hosts, blocks, sensors and listed hits to the caller's
hosts and then built `evidence` from the merged ledger, so a tenant whose host had seen the address (a host's sensor may name any
public address) read what the other tenants' hosts had collected about it.

A ledger is kept with the places that added to it (`ev_hosts`) and, while more than one did, the part of each (`ev_by`). A caller who
does not read every host is given the sum of their own places' parts. The same rule covers the text of a report, the reasons stored
beside an address and the classes the Data Explorer shows.

Driven through the real producer (a host's sensor posts to `handle_threat_events`), the real sweep and the real handler, as each
caller. Only `verify_token` is stubbed, so a missing tenant gate would show.
"""

import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v802-evscope-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))

import host_purge  # noqa: E402
import threat_evidence as te  # noqa: E402
from test_ip_intel import _fresh_api  # noqa: E402

X = '45.33.32.156'              # the address both tenants' hosts saw
ONLY_B = '45.33.32.157'         # an address only tenant B's host saw
ONLY_A = '45.33.32.158'         # an address only tenant A's host saw

# What each tenant's host collected about X. Each marker is a string no other part of the answer can hold.
B_PATH, B_PATH2, B_JAIL, B_CVE = '/acme-b-portal/payroll-export-2026', '/acme-b-portal/api/employees', 'nginx-acme-b-private', 'CVE-2021-41773'
A_PATH, A_JAIL, A_CVE = '/acme-a-shop/checkout-debug', 'sshd-acme-a-private', 'CVE-2022-22965'
B_MARKS = (B_PATH, B_PATH2, B_JAIL, B_CVE)
A_MARKS = (A_PATH, A_JAIL, A_CVE)


def _events(now, path, jail, cve, web=40, second_path=None, ip=X, cls='traversal'):
    """One address's summary as a sensor sends it: `web` hostile requests of kind `cls`, a ban by `jail` (none when blank)."""
    smp = [{'f': 'web', 'm': 'GET', 'p': path, 'c': 200, 't': now - 120}]
    if second_path:
        smp.append({'f': 'web', 'm': 'POST', 'p': second_path, 'c': 403, 't': now - 110})
    ev = {'ip': ip, 'first': now - 600, 'last': now - 100, 'src': {'web': web}, 'tok': {'web': {f'req:{cls}': web}},
          'cve': [cve] if cve else [], 'smp': smp}
    if jail:
        ev['ban'] = [jail]
        ev['src']['f2b'] = 1
    return ev


class _Fleet(unittest.TestCase):
    """Two tenants with one host each, the platform operator, and a sensor that reports for each host."""

    TENANCY = True

    def setUp(self):
        self.api = api = _fresh_api()
        self.data_dir = os.environ['RP_DATA_DIR']
        self.addCleanup(shutil.rmtree, self.data_dir, True)
        self.cap = {}
        self.now = int(time.time())

        def _respond(status, data=None, headers=None):
            self.cap['status'], self.cap['data'] = status, data
            raise api.HTTPError(status, data)

        api.respond = _respond
        api.get_token_from_request = lambda: 'tok'
        api.audit_log = lambda *a, **k: None
        api.fire_webhook = lambda *a, **k: None
        api.save(api.CONFIG_FILE, {'tenancy_enforced': self.TENANCY, 'ip_intel': {'sensor_enabled': True}})
        api.save(api.TENANTS_FILE, {'default': {'name': 'Default', 'status': 'active', 'created': 0, 'builtin': True},
                                    'tenantA': {'name': 'A', 'status': 'active', 'created': 1},
                                    'tenantB': {'name': 'B', 'status': 'active', 'created': 1}})
        api.save(api.USERS_FILE, {'adminA': {'role': 'admin', 'tenant_id': 'tenantA'},
                                  'viewerA': {'role': 'viewer', 'tenant_id': 'tenantA'},
                                  'adminB': {'role': 'admin', 'tenant_id': 'tenantB'},
                                  'root': {'role': 'admin'}})                 # the operator: an administrator of the default tenant
        api.save(api.DEVICES_FILE, {
            'devA': {'name': 'a-web', 'tenant': 'tenantA', 'token': 'tokA', 'version': '8.0.2', 'os': 'Ubuntu 24.04 (Linux)'},
            'devB': {'name': 'b-web', 'tenant': 'tenantB', 'token': 'tokB', 'version': '8.0.2', 'os': 'Ubuntu 24.04 (Linux)'}})
        api._LOAD_CACHE.clear()

    def config(self, **changes):
        api = self.api
        cfg = api.load(api.CONFIG_FILE)
        cfg.update(changes)
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()

    # ── producers and the sweep ──
    def sensor(self, dev_id, token, events):
        """A host's sensor posts what its logs said, through the endpoint a host uses with its own token."""
        body = {'device_id': dev_id, 'token': token, 'events': events,
                'sources': [{'kind': 'web', 'path': '/var/log/nginx/access.log', 'state': 'ok', 'lines': 10, 'parsed': 10, 'events': len(events)}]}
        self.api.method = lambda: 'POST'
        self.api.get_json_obj = lambda: body
        self.api.get_json_body = lambda: body
        self.cap.clear()
        try:
            self.api.handle_threat_events()
        except self.api.HTTPError:
            pass
        self.assertEqual(self.cap.get('status'), 200, self.cap)
        return self.cap['data']

    def sweep(self):
        api = self.api
        api._LOAD_CACHE.clear()
        st = api.load(api.IPINTEL_FILE) or {}
        st['last_sweep'] = 0
        api.save(api.IPINTEL_FILE, st)
        api._LOAD_CACHE.clear()
        api.run_ip_intel_if_due()
        api._LOAD_CACHE.clear()

    def row(self, ip=X):
        self.api._LOAD_CACHE.clear()
        return (self.api.load(self.api.IPINTEL_FILE) or {}).get('attackers', {}).get(ip)

    def as_user(self, user, role):
        self.api.verify_token = lambda tok=None, _u=user, _r=role: (_u, _r)
        self.api._LOAD_CACHE.clear()

    def listing(self, user, role):
        """(rows by address, the whole answer as text) of GET /api/ip-intel for one caller."""
        self.as_user(user, role)
        self.api.method = lambda: 'GET'
        self.cap.clear()
        try:
            self.api.handle_ip_intel()
        except self.api.HTTPError:
            pass
        self.assertEqual(self.cap.get('status'), 200, self.cap)
        d = self.cap['data']
        return {a['ip']: a for a in d['attackers']}, json.dumps(d)

    def both_report(self, a_events=None, b_events=None):
        """B's host reports first, then A's host names the same address; the sweep runs after each."""
        self.sensor('devB', 'tokB', b_events if b_events is not None else
                    [_events(self.now, B_PATH, B_JAIL, B_CVE, second_path=B_PATH2),
                     _events(self.now, '/only-b/secret', '', '', web=9, ip=ONLY_B)])
        self.sweep()
        self.sensor('devA', 'tokA', a_events if a_events is not None else [_events(self.now, A_PATH, A_JAIL, A_CVE, web=7, cls='sqli')])
        self.sweep()


class TestAnAddressTwoTenantsSaw(_Fleet):
    def test_the_repro_each_tenant_reads_its_own_part_and_the_operator_reads_both(self):
        """The shape of the finding: B's host reports the address first, A's host names it with one event."""
        self.both_report(a_events=[{'ip': X, 'first': self.now - 30, 'last': self.now - 20, 'src': {'web': 1}, 'tok': {'web': {'req:sqli': 1}}}])
        self.assertEqual(sorted(self.row()['devices']), ['devA', 'devB'], 'the control: one row, seen by two tenants')
        for user, role in (('adminA', 'admin'), ('viewerA', 'viewer')):
            rows, text = self.listing(user, role)
            self.assertIn(X, rows, 'the address is on the page: A\'s host saw it')
            for mark in B_MARKS:
                self.assertNotIn(mark, text, f'{user} reads {mark}, which only tenant B\'s host collected')
            self.assertNotIn('only-b', text)
        rows, text = self.listing('adminB', 'admin')
        for mark in B_MARKS:
            self.assertIn(mark, text, 'B reads what B\'s host collected, although A\'s host named the address too')
        rows, text = self.listing('root', 'admin')
        for mark in B_MARKS:
            self.assertIn(mark, text, 'the platform operator reads everything')

    def test_each_tenant_reads_its_own_hosts_part_and_never_the_others(self):
        self.both_report()
        for user, role, mine, theirs in (('adminA', 'admin', A_MARKS, B_MARKS), ('viewerA', 'viewer', A_MARKS, B_MARKS),
                                         ('adminB', 'admin', B_MARKS, A_MARKS)):
            rows, text = self.listing(user, role)
            self.assertIsNotNone(rows[X]['evidence'], f'{user} reads the part its own host collected')
            for mark in mine:
                self.assertIn(mark, text, f'{user} should read {mark}')
            for mark in theirs:
                self.assertNotIn(mark, text, f'{user} reads {mark} of the other tenant')
        rows, _ = self.listing('adminA', 'admin')
        ev = rows[X]['evidence']
        self.assertEqual((ev['jails'], ev['cves'], [s['p'] for s in ev['samples']]), ([A_JAIL], [A_CVE], [A_PATH]))

    def test_the_counts_are_the_tenants_own_and_cannot_be_subtracted_from(self):
        """A reads 7 hostile events (its own), B reads 40, and the sum, 47, is the operator's."""
        self.both_report()
        for user, want in (('adminA', 7), ('adminB', 40), ('root', 47)):
            rows, _ = self.listing(user, 'admin')
            self.assertEqual({s['id']: s['n'] for s in rows[X]['evidence']['sources']}.get('web'), want, user)

    def test_an_address_only_the_other_tenant_saw_is_not_listed(self):
        self.both_report()
        rows, text = self.listing('adminA', 'admin')
        self.assertNotIn(ONLY_B, rows)
        self.assertNotIn('/only-b/', text)
        rows, _ = self.listing('adminB', 'admin')
        self.assertIn(ONLY_B, rows)

    def test_the_control_an_address_only_this_tenant_saw_shows_its_evidence(self):
        """A filter that answered None for everything would pass the tests above: this one has a known good case."""
        self.sensor('devA', 'tokA', [_events(self.now, A_PATH, A_JAIL, A_CVE, ip=ONLY_A)])
        self.sweep()
        rows, text = self.listing('adminA', 'admin')
        ev = rows[ONLY_A]['evidence']
        self.assertEqual((ev['jails'], ev['cves'], [s['p'] for s in ev['samples']]), ([A_JAIL], [A_CVE], [A_PATH]))
        self.assertEqual(self.row(ONLY_A).get('ev_hosts'), ['devA'])
        self.assertNotIn('ev_by', self.row(ONLY_A), 'one place added to it: its part is the whole ledger')

    def test_the_ledger_remembers_who_added_to_it_and_what_each_added(self):
        self.both_report()
        row = self.row()
        self.assertEqual(row['ev_hosts'], ['devA', 'devB'])
        self.assertEqual(sorted(row['ev_by']), ['devA', 'devB'])
        self.assertEqual((row['ev_by']['devA']['src']['web'], row['ev_by']['devB']['src']['web'], row['ev']['src']['web']), (7, 40, 47))
        self.assertEqual(row['ev_by']['devB']['ban'], [B_JAIL])
        self.assertEqual(row['ev_by']['devA']['ban'], [A_JAIL])

    def test_the_other_door_to_the_same_ledger_the_data_explorer(self):
        """The `classes` column of the Data Explorer's attackers entity is dominant(ledger): the same sum."""
        self.both_report(a_events=[{'ip': X, 'first': self.now - 30, 'last': self.now - 20, 'src': {'web': 1}}])
        self.as_user('adminA', 'admin')
        rows = [r for r in self.api._qe_attackers_rows() if r['ip'] == X]
        self.assertEqual([r['device_id'] for r in rows], ['devA'])
        self.assertEqual(rows[0]['classes'], '', 'A\'s own part names no class: the classes B\'s host saw are not A\'s')
        self.as_user('root', 'admin')
        rows = {r['device_id']: r for r in self.api._qe_attackers_rows() if r['ip'] == X}
        self.assertNotEqual(rows['devB']['classes'], '', 'the operator reads the classes of the sum')

    def test_a_part_that_has_classes_is_read_by_its_owner_in_the_explorer(self):
        self.both_report()
        self.as_user('adminB', 'admin')
        rows = [r for r in self.api._qe_attackers_rows() if r['ip'] == X]
        self.assertIn('traversal', rows[0]['classes'])
        self.assertNotIn('sqli', rows[0]['classes'], 'that is A\'s')
        self.as_user('adminA', 'admin')
        rows = [r for r in self.api._qe_attackers_rows() if r['ip'] == X]
        self.assertIn('sqli', rows[0]['classes'])
        self.assertNotIn('traversal', rows[0]['classes'])

    def test_a_host_that_names_an_address_cannot_blank_the_evidence_another_tenant_reads(self):
        """The hostile reading of the rule: A names every address B's host saw, to make the ledger a shared one. B keeps its part."""
        self.sensor('devB', 'tokB', [_events(self.now, B_PATH, B_JAIL, B_CVE)])
        self.sweep()
        self.sensor('devA', 'tokA', [{'ip': X, 'first': self.now - 5, 'last': self.now - 4, 'src': {'web': 1}}])
        self.sweep()
        rows, text = self.listing('adminB', 'admin')
        self.assertEqual(rows[X]['evidence']['jails'], [B_JAIL])
        rows, text = self.listing('adminA', 'admin')
        self.assertNotIn(B_JAIL, text)


class TestWhatIsStoredWithoutItsParts(_Fleet):
    """A ledger written before the places were recorded, or one the parts of which were never kept."""

    def store(self, devices, **row):
        api = self.api
        st = api.load(api.IPINTEL_FILE) or {}
        base = {'first_seen': self.now - 500, 'last_seen': self.now - 50,
                'devices': {d: {'count': 5, 'unit': 'threat-sensor', 'at': self.now - 50} for d in devices},
                'verdict': {'score': 90, 'reports': 3, 'country': 'DE', 'isp': 'Example'}}
        base.update(row)
        st.setdefault('attackers', {})[X] = base
        api.save(api.IPINTEL_FILE, st)
        api._LOAD_CACHE.clear()

    def ledger(self, path=B_PATH, jail=B_JAIL, cve=B_CVE, web=40):
        return te.normalize_event(_events(self.now, path, jail, cve, web=web), now=self.now)

    def test_a_ledger_of_one_place_is_shown_to_the_tenant_whose_host_it_is(self):
        self.store(['devA'], ev=self.ledger())
        rows, text = self.listing('adminA', 'admin')
        self.assertEqual(rows[X]['evidence']['jails'], [B_JAIL])

    def test_a_ledger_of_two_places_with_no_parts_is_shown_to_neither_tenant(self):
        self.store(['devA', 'devB'], ev=self.ledger())
        for user, role in (('adminA', 'admin'), ('adminB', 'admin'), ('viewerA', 'viewer')):
            rows, text = self.listing(user, role)
            self.assertIsNone(rows[X]['evidence'], user)
            self.assertNotIn(B_JAIL, text)
        rows, _ = self.listing('root', 'admin')
        self.assertEqual(rows[X]['evidence']['jails'], [B_JAIL], 'the operator reads the sum')

    def test_a_ledger_that_names_a_place_the_caller_does_not_see_is_not_theirs(self):
        """`ev_hosts` names a host that has since been deleted: it is not among the places A reads."""
        self.store(['devA'], ev=self.ledger(), ev_hosts=['devA', 'devGone'])
        rows, text = self.listing('adminA', 'admin')
        self.assertIsNone(rows[X]['evidence'])
        self.assertNotIn(B_JAIL, text)

    def test_a_list_of_places_that_is_not_a_list_is_read_as_not_there(self):
        self.store(['devA', 'devB'], ev=self.ledger(), ev_hosts='devA', ev_by=['not', 'a', 'map'])
        rows, text = self.listing('adminA', 'admin')
        self.assertIsNone(rows[X]['evidence'])
        self.assertNotIn(B_JAIL, text)

    def test_a_part_that_was_edited_into_nonsense_reads_as_no_part(self):
        self.store(['devA', 'devB'], ev=self.ledger(), ev_hosts=['devA', 'devB'], ev_by={'devA': {'tok': ['x'], 'src': 3}})
        rows, text = self.listing('adminA', 'admin')
        self.assertIsNone(rows[X]['evidence'])

    def test_the_overflow_marker_is_no_place_anyone_reads(self):
        self.store(['devA'], ev=self.ledger(), ev_hosts=['devA', '*'])
        rows, _ = self.listing('adminA', 'admin')
        self.assertIsNone(rows[X]['evidence'])

    def test_the_ledger_a_report_was_made_of_follows_the_same_rule(self):
        self.store(['devA'], ev_reported={'at': self.now - 10, 'ev': self.ledger(), 'hosts': ['devA']})
        rows, _ = self.listing('adminA', 'admin')
        self.assertTrue(rows[X]['evidence']['sent'])
        self.store(['devA', 'devB'], ev_reported={'at': self.now - 10, 'ev': self.ledger(), 'hosts': ['devA', 'devB']})
        rows, text = self.listing('adminA', 'admin')
        self.assertIsNone(rows[X]['evidence'])
        self.assertNotIn(B_JAIL, text)

    def test_a_snapshot_with_its_parts_gives_each_tenant_its_own(self):
        a_part = self.ledger(A_PATH, A_JAIL, A_CVE, web=7)
        b_part = self.ledger()
        self.store(['devA', 'devB'], ev_reported={'at': self.now - 10, 'ev': te.merge(a_part, b_part), 'hosts': ['devA', 'devB'],
                                                  'by': {'devA': a_part, 'devB': b_part}})
        rows, text = self.listing('adminA', 'admin')
        self.assertEqual((rows[X]['evidence']['sent'], rows[X]['evidence']['jails']), (True, [A_JAIL]))
        self.assertNotIn(B_JAIL, text)
        rows, text = self.listing('adminB', 'admin')
        self.assertEqual(rows[X]['evidence']['jails'], [B_JAIL])
        self.assertNotIn(A_JAIL, text)


class TestTheTextOfAReportAndTheReasonsBesideIt(_Fleet):
    """Reporting is on, with the two services faked at the one seam that talks to them."""

    def setUp(self):
        super().setUp()
        self.posted = []

        def http(req):
            if req['method'] == 'POST':
                self.posted.append(req)
            return 200, {'success': True, 'data': {}}
        self.api._ip_intel_http = http
        self.config(abuseipdb_api_key='a' * 80, sniffcat_api_key='s' * 40,
                    ip_intel={'sensor_enabled': True, 'report_enabled': True, 'report_min_count': 10, 'report_samples': True})

    def below_the_bar(self):
        """B's host saw 4 requests and A's host 3: seven between them, and the bar is ten."""
        self.sensor('devB', 'tokB', [_events(self.now, B_PATH, '', B_CVE, web=4, second_path=B_PATH2)])
        self.sweep()
        self.sensor('devA', 'tokA', [_events(self.now, A_PATH, '', A_CVE, web=3, cls='sqli')])
        self.sweep()

    def over_the_bar(self):
        """B's host sends five more: twelve between them, and the address is reported, for both."""
        self.below_the_bar()
        self.sensor('devB', 'tokB', [_events(self.now, B_PATH, '', B_CVE, web=5)])
        self.sweep()

    def test_a_report_made_of_two_tenants_evidence_is_not_read_by_either(self):
        self.over_the_bar()
        row = self.row()
        self.assertTrue(row.get('reported'), 'the address was reported once, for both hosts')
        self.assertTrue(row['report_log'] and all(sorted(e['hosts']) == ['devA', 'devB'] for e in row['report_log']), row['report_log'])
        for user, role in (('adminA', 'admin'), ('adminB', 'admin')):
            rows, text = self.listing(user, role)
            log = rows[X]['report_log']
            self.assertEqual(sorted(e['prov'] for e in log), ['abuseipdb', 'sniffcat'], f'{user} is told that it was reported')
            for e in log:
                self.assertTrue(e.get('ok'), user)
                for hidden in ('comment', 'cats', 'hosts'):
                    self.assertNotIn(hidden, e, f'{user} reads the report\'s {hidden}')
        rows, _ = self.listing('root', 'admin')
        for e in rows[X]['report_log']:
            self.assertTrue(e['comment'] and e['cats'], 'the operator reads what was sent')
            self.assertNotIn('hosts', e, 'the list of places is not part of the answer')
        self.assertIn('acme-b-portal', ' '.join(r['body'].decode() for r in self.posted),
                      'the control: the report did carry the other tenant\'s request path (report_samples is on)')
        self.assertIn('acme-b-portal', rows[X]['report_log'][0]['comment'])

    def test_the_evidence_a_report_was_made_of_is_read_part_by_part(self):
        self.over_the_bar()
        self.assertIn('ev_reported', self.row())
        rows, text = self.listing('adminA', 'admin')
        self.assertTrue(rows[X]['evidence']['sent'])
        self.assertEqual([s['p'] for s in rows[X]['evidence']['samples']], [A_PATH])
        self.assertNotIn('acme-b-portal', text)
        rows, text = self.listing('adminB', 'admin')
        self.assertNotIn('acme-a-shop', text)

    def test_a_report_made_of_one_tenants_evidence_is_read_by_it(self):
        self.sensor('devA', 'tokA', [_events(self.now, A_PATH, A_JAIL, A_CVE, web=50, ip=ONLY_A)])
        self.sweep()
        rows, _ = self.listing('adminA', 'admin')
        log = rows[ONLY_A]['report_log']
        self.assertTrue(log and all(e['comment'] and e['cats'] for e in log))
        rows, _ = self.listing('adminB', 'admin')
        self.assertNotIn(ONLY_A, rows)

    def test_the_reason_nothing_was_reported_is_withheld_when_it_counts_other_hosts(self):
        """Below the bar the sweep says why: "7 of 10 attempts so far", worked out from the whole ledger."""
        self.below_the_bar()
        row = self.row()
        self.assertIn('7 of 10 attempts so far', ' '.join(row.get('errors', {}).values()), row.get('errors'))
        for user, role in (('adminA', 'admin'), ('adminB', 'admin')):
            rows, text = self.listing(user, role)
            self.assertFalse([v for v in rows[X]['errors'].values() if str(v).startswith('not reported')], user)
            self.assertNotIn('7 of 10', text)
        rows, _ = self.listing('root', 'admin')
        self.assertTrue([v for v in rows[X]['errors'].values() if '7 of 10' in str(v)])

    def test_the_reason_is_read_by_a_tenant_when_only_its_hosts_made_it(self):
        self.sensor('devA', 'tokA', [_events(self.now, A_PATH, '', A_CVE, web=3, ip=ONLY_A)])
        self.sweep()
        rows, _ = self.listing('adminA', 'admin')
        self.assertTrue([v for v in rows[ONLY_A]['errors'].values() if '3 of 10' in str(v)], rows[ONLY_A]['errors'])

    def test_what_a_service_answered_is_not_a_reason_and_stays(self):
        """The provider's own error is the instance's, and says nothing of the hosts: only the "not reported" reasons are withheld."""
        self.below_the_bar()
        api = self.api
        st = api.load(api.IPINTEL_FILE)
        st['attackers'][X]['errors']['abuseipdb'] = 'HTTP 429: daily limit'
        api.save(api.IPINTEL_FILE, st)
        api._LOAD_CACHE.clear()
        rows, _ = self.listing('adminA', 'admin')
        self.assertEqual(rows[X]['errors'], {'abuseipdb': 'HTTP 429: daily limit'})


class TestADeletedHostLeavesNothingBehind(_Fleet):
    def test_the_part_of_a_deleted_host_leaves_with_it_and_stays_out_of_the_others_answer(self):
        self.both_report()
        self.assertIn('devB', self.row()['ev_by'])
        self.assertTrue(self.api._purge_device('devB'))
        self.api._LOAD_CACHE.clear()
        row = self.row()
        self.assertNotIn('devB', row['devices'])
        self.assertNotIn('devB', row['ev_by'], 'the host\'s own part goes with it (host_purge)')
        self.assertIn('devB', row['ev_hosts'], 'the id stays on the sum: it holds what that host added')
        rows, text = self.listing('adminA', 'admin')
        for mark in B_MARKS:
            self.assertNotIn(mark, text)
        self.assertEqual(rows[X]['evidence']['jails'], [A_JAIL], 'A keeps its own part')

    def test_a_ledger_nobody_can_take_apart_stays_unreadable_after_the_host_is_deleted(self):
        """The old reading would have made the address look A's alone once B's host was gone."""
        api = self.api
        st = {'attackers': {X: {
            'last_seen': self.now, 'devices': {'devA': {'count': 1, 'unit': 'threat-sensor', 'at': self.now}},
            'ev': te.normalize_event(_events(self.now, B_PATH, B_JAIL, B_CVE), now=self.now), 'ev_hosts': ['devA', 'devB']}}}
        api.save(api.IPINTEL_FILE, st)
        api._LOAD_CACHE.clear()
        rows, text = self.listing('adminA', 'admin')
        self.assertIsNone(rows[X]['evidence'])
        self.assertNotIn(B_JAIL, text)

    def test_the_purge_rules_take_the_part_of_the_snapshot_too(self):
        doc = {'attackers': {X: {'devices': {'h1': {}, 'h2': {}}, 'ev_by': {'h1': {}, 'h2': {}},
                                 'ev_reported': {'at': 1, 'ev': {}, 'hosts': ['h1', 'h2'], 'by': {'h1': {}, 'h2': {}}}}}}
        self.assertEqual(host_purge.apply('ip_intel.json', doc, 'h1'), 3, 'its sighting, its part, its part of the snapshot')
        row = doc['attackers'][X]
        self.assertEqual((sorted(row['devices']), sorted(row['ev_by']), sorted(row['ev_reported']['by'])), (['h2'], ['h2'], ['h2']))
        self.assertEqual(row['ev_reported']['hosts'], ['h1', 'h2'])


class TestTheClearButton(_Fleet):
    def test_a_tenant_that_clears_takes_its_own_part_and_leaves_the_others(self):
        self.both_report()
        self.as_user('adminA', 'admin')
        self.api.method = lambda: 'POST'
        self.api.get_json_obj = lambda: {}
        self.api.get_json_body = lambda: {}
        self.cap.clear()
        try:
            self.api.handle_ip_intel_clear()
        except self.api.HTTPError:
            pass
        self.assertEqual(self.cap.get('status'), 200, self.cap)
        row = self.row()
        self.assertNotIn('devA', row['devices'])
        self.assertNotIn('devA', row['ev_by'])
        self.assertIn('devB', row['ev_by'])
        rows, text = self.listing('adminB', 'admin')
        self.assertEqual(rows[X]['evidence']['jails'], [B_JAIL])
        self.assertNotIn(A_JAIL, text)


class TestWhoReadsEverything(_Fleet):
    def test_a_single_organisation_viewer_reads_the_whole_ledger_as_before(self):
        """No tenancy, no scope: nothing is withheld, and the fix must not blind the common install."""
        self.config(tenancy_enforced=False)
        self.both_report()
        for user, role in (('viewerA', 'viewer'), ('adminA', 'admin'), ('root', 'admin')):
            rows, text = self.listing(user, role)
            for mark in B_MARKS + A_MARKS:
                self.assertIn(mark, text, f'{user} reads the whole ledger on a single-organisation install')
            self.assertEqual({s['id']: s['n'] for s in rows[X]['evidence']['sources']}.get('web'), 47)

    def scoped(self):
        api = self.api
        self.config(tenancy_enforced=False)
        devs = api.load(api.DEVICES_FILE)
        devs['devA']['group'], devs['devB']['group'] = 'shop', 'portal'
        api.save(api.DEVICES_FILE, devs)
        api.save(api.ROLES_FILE, {'roles': [{'name': 'shop-ops', 'permissions': [], 'scope': {'type': 'groups', 'values': ['shop']}}]})
        api._LOAD_CACHE.clear()

    def test_a_role_scoped_to_some_hosts_reads_only_those(self):
        self.scoped()
        self.both_report()
        rows, text = self.listing('scoped', 'shop-ops')
        self.assertIn(X, rows)
        self.assertEqual(rows[X]['evidence']['jails'], [A_JAIL])
        for mark in B_MARKS:
            self.assertNotIn(mark, text, 'a role scoped to the shop hosts reads the portal host\'s evidence')
        self.assertNotIn(ONLY_B, rows)

    def test_a_scoped_api_key_confines_an_administrator_too(self):
        self.scoped()
        self.both_report()
        api = self.api
        api._RCTX.key_scope = {'type': 'groups', 'values': ['shop']}
        try:
            rows, text = self.listing('root', 'admin')
        finally:
            api._RCTX.key_scope = None
        for mark in B_MARKS:
            self.assertNotIn(mark, text)
        self.assertIn(A_JAIL, text)


class TestTheLedgerBookkeeping(unittest.TestCase):
    """_add_to_ledger and the helpers around it, with plain inputs."""

    @classmethod
    def setUpClass(cls):
        cls.api = _fresh_api()
        cls.addClassCleanup(shutil.rmtree, os.environ['RP_DATA_DIR'], True)
        cls.mod = cls.api.ip_intel_handlers_mod

    def setUp(self):
        self.now = int(time.time())

    def entry(self, dev, ev):
        return {'dev_id': dev, 'item': {'evidence': te.normalize_event(ev, now=self.now)}}

    def ev(self, web):
        return {'ip': X, 'first': self.now - 60, 'last': self.now - 10, 'src': {'web': web}, 'tok': {'web': {'req:sqli': web}}}

    def test_one_place_keeps_no_parts(self):
        cur, hosts, by = self.mod._add_to_ledger({'devices': {}}, [self.entry('d1', self.ev(5))], self.now)
        self.assertEqual((hosts, by, cur['src']['web']), (['d1'], None, 5))

    def test_a_second_place_splits_the_ledger_it_joins(self):
        mod = self.mod
        att = {'devices': {'d1': {}}}
        cur, hosts, by = mod._add_to_ledger(att, [self.entry('d1', self.ev(5))], self.now)
        att.update(ev=cur, ev_hosts=mod._cap_hosts(hosts))
        cur, hosts, by = mod._add_to_ledger(att, [self.entry('d2', self.ev(8))], self.now)
        self.assertEqual((sorted(by), by['d1']['src']['web'], by['d2']['src']['web'], cur['src']['web']), (['d1', 'd2'], 5, 8, 13))

    def test_a_place_that_adds_again_adds_to_its_own_part_only(self):
        mod = self.mod
        att = {'devices': {'d1': {}}}
        cur, hosts, by = mod._add_to_ledger(att, [self.entry('d1', self.ev(5)), self.entry('d2', self.ev(8))], self.now)
        att.update(ev=cur, ev_hosts=mod._cap_hosts(hosts), ev_by=by)
        cur, hosts, by = mod._add_to_ledger(att, [self.entry('d2', self.ev(2))], self.now)
        self.assertEqual((by['d1']['src']['web'], by['d2']['src']['web'], cur['src']['web']), (5, 10, 15))

    def test_a_ledger_of_several_places_with_no_parts_stays_one_sum(self):
        legacy = te.normalize_event(self.ev(9), now=self.now)
        att = {'devices': {'d1': {}, 'd2': {}}, 'ev': legacy}
        cur, hosts, by = self.mod._add_to_ledger(att, [self.entry('d1', self.ev(1))], self.now)
        self.assertIsNone(by, 'nobody can say which place added the 9')
        self.assertEqual(sorted(set(hosts)), ['d1', 'd2'])

    def test_a_stale_ledger_starts_over_with_its_own_places(self):
        old = te.normalize_event(dict(self.ev(9), first=self.now - 3 * 86400, last=self.now - 2 * 86400), now=self.now - 3 * 86400)
        att = {'devices': {'d1': {}, 'd2': {}}, 'ev': old, 'ev_hosts': ['d1', 'd2'], 'ev_by': {'d1': old, 'd2': old}}
        cur, hosts, by = self.mod._add_to_ledger(att, [self.entry('d3', self.ev(1))], self.now)
        self.assertEqual((hosts, by, cur['src']['web']), (['d3'], None, 1))

    def test_more_places_than_the_cap_leave_no_parts_and_an_overflow_marker(self):
        mod = self.mod
        group = [self.entry(f'd{i}', self.ev(1)) for i in range(mod.LEDGER_BY_MAX + 1)]
        cur, hosts, by = mod._add_to_ledger({'devices': {}}, group, self.now)
        self.assertIsNone(by)
        self.assertEqual(len(hosts), mod.LEDGER_BY_MAX + 1)
        capped = mod._cap_hosts([f'd{i}' for i in range(mod.LEDGER_HOSTS_MAX + 5)])
        self.assertEqual((len(capped), capped[-1]), (mod.LEDGER_HOSTS_MAX + 1, '*'))
        self.assertTrue(mod._within(capped[:-1], set(capped)), 'without the marker the places are all read')
        self.assertFalse(mod._within(capped, set(capped) - {'*'}), 'the marker is no place anyone reads')

    def test_within_needs_a_list_with_something_in_it(self):
        mod = self.mod
        self.assertTrue(mod._within(['a'], {'a', 'b'}))
        self.assertFalse(mod._within(['a', 'c'], {'a', 'b'}))
        for bad in (None, [], 'a', {'a': 1}, 5):
            self.assertFalse(mod._within(bad, {'a'}), repr(bad))


if __name__ == '__main__':
    unittest.main()
