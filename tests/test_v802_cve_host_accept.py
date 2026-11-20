#!/usr/bin/env python3
"""8.0.2: accepting a host on the CVE page -- the findings it lists stop counting, and a finding that comes after counts and is marked new.

An accepted host writes an accepted-risk record for each finding it lists, with the host as the scope (`checks.is_host_accept`), so every reader that decides whether a finding is
accepted (the page, the badge, Needs attention, the risk score, the reports, the alerts) leaves them out without a change of its own. What this holds, through the real handlers and the
dispatcher: the numbers of the page, a finding that two hosts share, the known-exploited count, a finding that came after, accepting again, taking it back, what an ignore of one finding
does to it, the lists of accepted risks, the ceiling of an organisation's own records, who may accept a host, and that the answer of the index the page uses is the answer of the
question asked of each id.

Only `verify_token` is replaced, the rest is real: `fire_webhook`'s path is driven where an alert is the point.
"""
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-cve-hostaccept-'))
_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS))
sys.path.insert(0, str(_TESTS.parent / 'server' / 'cgi-bin'))

import checks  # noqa: E402
from test_ip_intel import _fresh_api  # noqa: E402
from test_v800_push_mark import _run  # noqa: E402

A, B, C, D, E, F = ('CVE-2026-000%d' % i for i in range(1, 7))


def finding(vid, severity='high', package='openssl', fix='fixed'):
    return {'package': package, 'version': '3.0.11-1', 'vuln_id': vid, 'severity': severity, 'fix_status': fix, 'fixed_version': '3.0.15', 'aliases': [],
            'summary': 'a flaw', 'published': '2026-11-01T00:00:00Z', 'refs': []}


class _Cve(unittest.TestCase):

    def setUp(self):
        self.api = _fresh_api()
        self.api.verify_token = lambda t: {'k': ('admin', 'admin'), 'v': ('vera', 'viewer'), 'b': ('badmin', 'admin')}.get(t, (None, None))
        self.audits = []
        self.api.audit_log = lambda *a, **k: self.audits.append((a, k))
        self.api._run_detached = lambda fn: None          # a request runs the whole cadence, and its detached jobs must not reach the network
        self.now = int(time.time())
        self.put('KEV_EPSS_FILE', {'kev': [B], 'epss': {}, 'last_checked': self.now})
        self.devices()
        # web01 has three findings and what its scan counted per package; web02 shares one of them (A); db01 has one of its own
        self.scan('web01', [finding(A, 'critical'), finding(B, 'high'), finding(C, 'medium')], rollup=40)
        self.scan('web02', [finding(A, 'critical'), finding(D, 'low')])
        self.scan('db01', [finding(E, 'critical')], rollup=7)

    # ── the installation ──
    def put(self, attr, doc):
        self.api.save(getattr(self.api, attr), doc)
        self.api._LOAD_CACHE.clear()

    def devices(self, tenants=None):
        devs = {}
        for dev_id, name in (('web01', 'WEB-1'), ('web02', 'WEB-2'), ('db01', 'DB-1')):
            devs[dev_id] = {'name': name, 'hostname': name, 'os': 'Debian 13', 'monitored': True, 'last_seen': self.now, 'token': 'T-' + dev_id, 'group': 'g', 'ip': '10.0.0.1'}
            if tenants and dev_id in tenants:
                devs[dev_id]['tenant'] = tenants[dev_id]
        self.put('DEVICES_FILE', devs)

    def scan(self, dev_id, findings, rollup=0):
        store = dict(self.api.load(self.api.CVE_FINDINGS_FILE) or {})
        rec = {'scanned_at': self.now, 'ecosystem': 'Debian:13', 'findings': findings}
        if rollup:
            rec['rollup'] = {'total': rollup}
        store[dev_id] = rec
        self.put('CVE_FINDINGS_FILE', store)

    def tenancy(self):
        self.put('TENANTS_FILE', {'default': {'name': 'Default', 'status': 'active', 'builtin': True}, 'tenantB': {'name': 'B', 'status': 'active'}})
        self.put('USERS_FILE', {'admin': {'role': 'admin', 'tenant_id': 'default'}, 'vera': {'role': 'viewer', 'tenant_id': 'default'}, 'badmin': {'role': 'admin', 'tenant_id': 'tenantB'}})
        cfg = dict(self.api.load(self.api.CONFIG_FILE) or {})
        cfg['tenancy_enforced'] = True
        self.put('CONFIG_FILE', cfg)
        self.devices({'web02': 'tenantB', 'db01': 'tenantB'})        # web01 stays the operator's

    def request(self, path, method='GET', token='k', body=None):
        """A request through main(): the dispatcher, with the gates that run before a handler does."""
        names = ('REQUEST_METHOD', 'PATH_INFO', 'REMOTE_ADDR', 'CONTENT_LENGTH', 'QUERY_STRING', 'HTTP_AUTHORIZATION', 'HTTP_X_TOKEN')
        saved = {n: os.environ.get(n) for n in names}

        def go():
            os.environ.update(PATH_INFO=path)
            self.api.main()
        try:
            try:
                return _run(self.api, go, body, method=method, env={'HTTP_AUTHORIZATION': 'Bearer ' + token} if token else {})
            except self.api.HTTPError as e:      # a conditional GET raises its answer itself
                return e.status, e.body
        finally:
            for n, v in saved.items():
                if v is None:
                    os.environ.pop(n, None)
                else:
                    os.environ[n] = v

    # ── what the page and the host's view say ──
    def page(self, token='k'):
        self.api._LOAD_CACHE.clear()
        st, got = self.request('/api/cve/findings', token=token)
        self.assertEqual(st, 200, got)
        return got

    def row(self, page, dev_id):
        return {d['device_id']: d for d in page['devices']}[dev_id]

    def view(self, dev_id, token='k'):
        self.api._LOAD_CACHE.clear()
        st, got = self.request('/api/devices/%s/cve' % dev_id, token=token)
        self.assertEqual(st, 200, got)
        return got

    def accept(self, dev_id='web01', reason='a lab box', token='k'):
        self.api._LOAD_CACHE.clear()
        return self.request('/api/devices/%s/cve/accept' % dev_id, 'POST', token=token, body={'reason': reason} if reason is not None else {})

    def unaccept(self, dev_id='web01', token='k'):
        self.api._LOAD_CACHE.clear()
        return self.request('/api/devices/%s/cve/unaccept' % dev_id, 'POST', token=token, body={})

    def ignore(self, vuln_id, scope='global', token='k'):
        self.api._LOAD_CACHE.clear()
        return self.request('/api/cve/ignore', 'POST', token=token, body={'vuln_id': vuln_id, 'scope': scope, 'reason': 'one finding'})

    def store(self):
        self.api._LOAD_CACHE.clear()
        return self.api.load(self.api.CVE_IGNORE_FILE) or {}

    def numbers(self, page):
        s = page['summary']
        return (s['critical'], s['high'], s['medium'], s['low'], s['kev'], s['rollup'], s['accepted_hosts'], s['accepted_findings'])


# ── the numbers of the page ──────────────────────────────────────────────────────────────────────────────────────

class TestTheNumbersOfThePage(_Cve):

    def test_before_a_host_is_accepted_everything_counts(self):
        page = self.page()
        self.assertEqual(self.numbers(page), (3, 1, 1, 1, 1, 47, 0, 0), 'critical A (twice) and E, high B, medium C, low D, one known exploited, 40 and 7 counted per package')
        self.assertEqual(self.row(page, 'web01')['kev'], 1)
        self.assertIsNone(self.row(page, 'web01')['accepted'])

    def test_an_accepted_host_is_left_out_of_every_number_and_the_others_are_not(self):
        st, got = self.accept('web01')
        self.assertEqual((st, got), (200, {'ok': True, 'accepted': 3, 'findings': 3}))
        page = self.page()
        self.assertEqual(self.numbers(page), (2, 0, 0, 1, 0, 7, 1, 3), 'web01 counts nothing: not its three findings, not the known-exploited one, not the 40 counted per package')
        row = self.row(page, 'web01')
        self.assertEqual((row['counts']['critical'], row['counts']['high'], row['counts']['medium'], row['counts']['ignored']), (0, 0, 0, 3))
        self.assertEqual((row['kev'], row['accepted_new'], row['accepted']['n']), (0, 0, 3))
        self.assertEqual(row['rollup'], 40, 'the row still says what its scan counted, the fleet line does not')
        self.assertEqual(self.row(page, 'web02')['counts']['critical'], 1, 'the finding web02 shares with web01 still counts on web02')
        self.assertEqual(self.row(page, 'db01')['counts']['critical'], 1)
        self.assertEqual(page['summary']['devices_with_findings'], 2)

    def test_a_host_accepted_after_another_that_shares_a_finding_does_not_take_the_first_ones_away(self):
        """The store is keyed by the id of the finding, and an organisation held one record under each id: the second host's record for the finding both share would have
        replaced the first's."""
        self.accept('web01')
        self.accept('web02')
        page = self.page()
        self.assertEqual((self.row(page, 'web01')['counts']['ignored'], self.row(page, 'web02')['counts']['ignored']), (3, 2), 'both hosts keep all of their findings accepted')
        self.assertEqual(page['summary']['accepted_hosts'], 2)
        self.unaccept('web02')
        page = self.page()
        self.assertEqual((self.row(page, 'web01')['counts']['ignored'], self.row(page, 'web02')['counts']['ignored']), (3, 0), 'taking one back leaves the other accepted')
        self.assertEqual((self.row(page, 'web02')['counts']['critical'], self.row(page, 'web02')['counts']['low']), (1, 1))

    def test_an_accepted_finding_does_not_count_as_known_exploited_for_any_ignore(self):
        self.assertEqual(self.numbers(self.page())[4], 1)
        self.ignore(B, scope='web01')                      # one finding, ignored by itself
        page = self.page()
        self.assertEqual((page['summary']['kev'], self.row(page, 'web01')['kev']), (0, 0), 'an ignored finding was counted as known exploited, and ranked the host first')
        self.assertEqual(page['summary']['high'], 0)

    def test_a_host_with_nothing_listed_can_be_accepted_and_its_count_per_package_is_left_out(self):
        self.scan('web02', [], rollup=500)
        self.assertEqual(self.numbers(self.page())[5], 547)
        st, got = self.accept('web02')
        self.assertEqual((st, got), (200, {'ok': True, 'accepted': 0, 'findings': 0}))
        page = self.page()
        self.assertEqual(self.numbers(page)[5:], (47, 1, 0))
        self.assertEqual(self.row(page, 'web02')['accepted']['n'], 0)

    def test_what_the_fixable_only_option_leaves_out_does_not_change_what_an_accepted_host_counts_as_new(self):
        cfg = dict(self.api.load(self.api.CONFIG_FILE) or {})
        cfg['cve_count_fixable_only'] = True
        self.put('CONFIG_FILE', cfg)
        self.accept('web01')
        self.scan('web01', [finding(A, 'critical'), finding(B, 'high'), finding(C, 'medium'), finding(F, 'high', fix='none')], rollup=40)
        page = self.page()
        self.assertEqual(self.row(page, 'web01')['accepted_new'], 0, 'a new finding that no update clears does not count with this option on, so it is not counted as new here either')
        self.scan('web01', [finding(A, 'critical'), finding(B, 'high'), finding(C, 'medium'), finding(F, 'high', fix='fixed')], rollup=40)
        self.assertEqual(self.row(self.page(), 'web01')['accepted_new'], 1)


# ── a finding that comes after ───────────────────────────────────────────────────────────────────────────────────

class TestWhatComesAfter(_Cve):

    def setUp(self):
        super().setUp()
        self.accept('web01', reason='the lab box, patched in the spring')

    def test_a_finding_the_next_scan_lists_counts_and_is_marked_new(self):
        self.scan('web01', [finding(A, 'critical'), finding(B, 'high'), finding(C, 'medium'), finding(F, 'high')], rollup=40)
        page = self.page()
        row = self.row(page, 'web01')
        self.assertEqual((row['counts']['high'], row['counts']['critical'], row['accepted_new'], row['counts']['ignored']), (1, 0, 1, 3))
        self.assertEqual(self.numbers(page)[:2], (2, 1), 'the new one is in the numbers of the page: high 1')
        got = self.view('web01')
        by_id = {f['vuln_id']: f for f in got['findings']}
        self.assertEqual({v: (f['ignored'], f.get('new', False)) for v, f in by_id.items()}, {A: (True, False), B: (True, False), C: (True, False), F: (False, True)})
        self.assertEqual(by_id[A]['ignore_reason'], 'the lab box, patched in the spring')

    def test_the_view_of_the_host_says_since_when_who_and_why(self):
        got = self.view('web01')
        a = got['accepted']
        self.assertEqual((a['n'], a['by'], a['reason']), (3, 'admin', 'the lab box, patched in the spring'))
        self.assertLessEqual(abs(a['at'] - int(time.time())), 5)
        self.assertEqual(a['at'], a['last_at'])
        self.assertIsNone(self.view('web02')['accepted'], 'a host that was not accepted says nothing')
        self.assertNotIn('new', json.dumps(self.view('web02')['findings']), 'and marks nothing new')

    def test_the_alert_goes_out_for_what_came_after_and_for_nothing_the_host_was_accepted_with(self):
        sent = []
        self.api.fire_webhook = lambda event, payload=None, *a, **k: sent.append((event, payload))
        self.api.is_webhook_event_enabled = lambda event: True
        devices = self.api.load(self.api.DEVICES_FILE)
        old = [finding(A, 'critical'), finding(B, 'high'), finding(C, 'medium')]
        self.api._detect_new_cve_and_fire_webhook('web01', devices, [], old, kev={B})                       # the first scan, as it is for a host that was accepted with these
        self.assertEqual([e for e, _ in sent if e == 'cve_found'], [], 'what the host was accepted with raises nothing')
        self.api._detect_new_cve_and_fire_webhook('web01', devices, old, old + [finding(F, 'high')], kev={B})
        found = [p for e, p in sent if e == 'cve_found']
        self.assertEqual(len(found), 1, sent)
        self.assertIn(F, json.dumps(found[0]))
        self.assertNotIn(A, json.dumps(found[0]))

    def test_accepting_again_takes_what_is_new_since_and_keeps_the_first_time(self):
        first = self.view('web01')['accepted']
        self.scan('web01', [finding(A, 'critical'), finding(B, 'high'), finding(C, 'medium'), finding(F, 'high')], rollup=40)
        time.sleep(1.1)
        st, got = self.accept('web01', reason='and the new one too')
        self.assertEqual((st, got), (200, {'ok': True, 'accepted': 1, 'findings': 4}), 'one record was added, and the three that were there were not written twice')
        a = self.view('web01')['accepted']
        self.assertEqual((a['at'], a['n'], a['reason']), (first['at'], 4, 'the lab box, patched in the spring'), 'the first time, and the first reason')
        self.assertGreater(a['last_at'], first['at'])
        self.assertEqual(self.row(self.page(), 'web01')['accepted_new'], 0)
        self.assertEqual(self.accept('web01')[1]['accepted'], 0, 'and a third time adds nothing')


# ── taking it back, and what one finding's ignore does ───────────────────────────────────────────────────────────

class TestTakingItBack(_Cve):

    def test_taking_it_back_counts_the_findings_again_and_leaves_everything_else(self):
        self.ignore(C, scope='web01')                      # one finding of web01, ignored by itself first: the acceptance does not write a second record for it
        self.accept('web01')
        self.accept('web02')
        self.ignore(E, scope='global')
        before_other = {v: len(checks.cve_ignore_records(self.store()[v])) for v in self.store()}
        st, got = self.unaccept('web01')
        self.assertEqual((st, got), (200, {'ok': True, 'removed': 2}), 'A and B: C was ignored on its own and stays')
        page = self.page()
        self.assertEqual(self.row(page, 'web01')['counts']['ignored'], 1, 'C is still ignored, by its own record')
        self.assertEqual((self.row(page, 'web01')['counts']['critical'], self.row(page, 'web01')['counts']['high']), (1, 1))
        self.assertIsNone(self.row(page, 'web01')['accepted'])
        self.assertEqual(self.row(page, 'web02')['counts']['ignored'], 2, 'the other host is still accepted')
        self.assertEqual(self.row(page, 'db01')['counts']['ignored'], 1, 'and the fleet-wide ignore is still there')
        after = {v: len(checks.cve_ignore_records(self.store()[v])) for v in self.store()}
        self.assertEqual(after[A], before_other[A] - 1, 'one record of A went: web01\'s')
        self.assertEqual(self.audits[-1][0][1:], ('cve_host_unaccept',))
        self.assertEqual(self.unaccept('web01')[1], {'ok': True, 'removed': 0}, 'and again is the same answer')

    def test_an_ignore_of_one_finding_leaves_the_acceptance_of_other_hosts_alone(self):
        self.accept('web01')
        st, _ = self.ignore(A, scope='web02')              # the caller's own record of A is replaced by this one
        self.assertEqual(st, 200)
        page = self.page()
        self.assertEqual((self.row(page, 'web01')['counts']['ignored'], self.row(page, 'web02')['counts']['ignored']), (3, 1), 'web01 is still accepted with A')
        self.assertEqual(self.request('/api/cve/ignore/' + A, 'DELETE')[0], 200)
        page = self.page()
        self.assertEqual((self.row(page, 'web01')['counts']['ignored'], self.row(page, 'web02')['counts']['ignored']), (3, 0), 'lifting the ignore of A lifts web02\'s record and not the acceptance of web01')

    def test_the_lists_of_accepted_risks_do_not_fill_up_with_an_accepted_host(self):
        self.accept('web01')
        st, got = self.request('/api/cve/ignore')
        self.assertEqual((st, got['ignores']), (200, []), 'three records of an accepted host are not three rows of the list')
        st, got = self.request('/api/suppressions')
        self.assertEqual([s for s in got.get('suppressions', []) if s.get('kind') == 'cve_accepted'], [])
        self.ignore(D, scope='web02')
        self.assertEqual([i['vuln_id'] for i in self.request('/api/cve/ignore')[1]['ignores']], [D], 'control: a finding ignored by itself is listed')

    def test_the_ceiling_of_an_organisations_own_records_does_not_count_an_accepted_host(self):
        self.api.cve_handlers_mod.MAX_IGNORES_PER_OWNER = 1
        self.assertEqual(self.accept('web01')[0], 200)
        self.assertEqual(self.accept('web02')[0], 200, 'five records of accepted hosts, and a ceiling of one')
        self.assertEqual(self.ignore(C, scope='web01')[0], 200)
        st, got = self.ignore(E, scope='db01')
        self.assertEqual((st, got['limit']), (400, 1), 'the second record of its own is over the ceiling')


# ── who may, and whose records they are ─────────────────────────────────────────────────────────────────────────

class TestWhoMayAcceptAHost(_Cve):

    def test_a_viewer_and_a_caller_with_no_token_may_not_and_nothing_is_written(self):
        for token, want in (('v', 403), (None, 401)):
            self.assertEqual(self.accept('web01', token=token)[0], want, token)
            self.assertEqual(self.unaccept('web01', token=token)[0], want, token)
        self.assertEqual(self.store(), {})
        self.assertNotIn('cve_accepted', self.api.load(self.api.DEVICES_FILE)['web01'])

    def test_a_tenant_administrator_accepts_the_hosts_of_the_tenant_and_no_others(self):
        self.tenancy()
        st, got = self.accept('web01', token='b')
        self.assertEqual((st, got), (403, {'error': 'Host belongs to another tenant'}), 'web01 is the operator\'s: the answer every device route gives another organisation')
        self.assertEqual(self.unaccept('web01', token='b')[0], 403)
        self.assertEqual(self.store(), {})
        st, got = self.accept('web02', token='b')
        self.assertEqual((st, got['accepted']), (200, 2))
        records = [r for v in self.store().values() for r in checks.cve_ignore_records(v)]
        self.assertEqual({r.get('tenant') for r in records}, {'tenantB'}, 'the records are the tenant\'s')
        self.assertEqual(self.numbers(self.page('k'))[7], 2, 'the operator reads the tenant\'s host as accepted: the records apply to that host')
        page_b = self.page('b')
        self.assertEqual({d['device_id'] for d in page_b['devices']}, {'web02', 'db01'}, 'and the tenant reads its own hosts only')

    def test_the_handlers_refuse_another_organisations_host_on_their_own_too(self):
        """The dispatcher refuses first (`_enforce_device_scope`). The handler has the same check of its own, and a request that reaches it another way meets it."""
        self.tenancy()
        for fn, name in ((self.api.handle_cve_host_accept, 'accept'), (self.api.handle_cve_host_unaccept, 'unaccept')):
            st, got = _run(self.api, lambda: fn('web01'), {}, method='POST', env={'HTTP_AUTHORIZATION': 'Bearer b'})
            self.assertEqual((st, got), (403, {'error': 'Host belongs to another tenant'}), name)
        self.assertEqual(self.store(), {})
        st, got = _run(self.api, lambda: self.api.handle_cve_host_accept('web02'), {}, method='POST', env={'HTTP_AUTHORIZATION': 'Bearer b'})
        self.assertEqual(st, 200, 'control: its own host')

    def test_a_tenant_cannot_lift_what_the_operator_accepted_and_the_host_stays_accepted(self):
        self.tenancy()
        self.assertEqual(self.accept('web02', token='k')[0], 200)           # the operator accepts a host of the tenant
        self.assertEqual(self.accept('web02', token='b')[1]['accepted'], 2, 'the tenant\'s own records are written beside the operator\'s: they are two organisations\' records')
        self.assertEqual(self.unaccept('web02', token='b')[1]['removed'], 2, 'it lifts its own two')
        self.assertEqual(self.row(self.page('k'), 'web02')['counts']['ignored'], 2, 'the operator\'s acceptance is still there')
        self.assertEqual(self.row(self.page('b'), 'web02')['counts']['ignored'], 2, 'and it applies to the host the tenant owns')
        self.assertIsNotNone(self.row(self.page('k'), 'web02')['accepted'], 'the marker stays while an acceptance of the host is left')
        self.assertEqual(self.unaccept('web02', token='k')[1]['removed'], 2)
        self.assertIsNone(self.row(self.page('k'), 'web02')['accepted'])

    def test_the_view_shows_a_caller_the_reason_of_a_record_it_may_see_and_not_another_organisations(self):
        self.tenancy()
        self.accept('web02', token='b', reason='tenant B\'s own reason')
        a = self.view('web02', token='b')['accepted']
        self.assertEqual((a['by'], a['reason']), ('badmin', 'tenant B\'s own reason'))
        self.assertNotIn('tenant B\'s own reason', json.dumps(self.page('b')), 'the page row carries no text of a record, only the times and the number')


class TestDeletingTheHost(_Cve):

    def test_deleting_a_host_removes_the_records_its_acceptance_wrote_and_nothing_else(self):
        self.ignore(C, scope='web01')                      # a finding of web01 ignored on its own: a record that stays, as it always did
        self.accept('web01')
        self.accept('web02')
        self.ignore(E, scope='global')
        host_records = lambda dev: sum(1 for v in self.store().values() for r in checks.cve_ignore_records(v) if checks.is_host_accept(r) and r.get('scope') == dev)
        self.assertEqual((host_records('web01'), host_records('web02')), (2, 2))
        self.api._purge_device('web01')
        self.assertEqual((host_records('web01'), host_records('web02')), (0, 2), 'web02 shares A with web01 and keeps its own record of it')
        scopes = sorted(r.get('scope') for v in self.store().values() for r in checks.cve_ignore_records(v) if not checks.is_host_accept(r))
        self.assertEqual(scopes, ['global', 'web01'], 'the finding ignored on its own and the fleet-wide ignore stay')
        page = self.page()
        self.assertEqual(self.row(page, 'web02')['counts']['ignored'], 2)
        self.assertNotIn('web01', {d['device_id'] for d in page['devices']})

    def test_a_store_that_cannot_be_changed_does_not_stop_the_host_from_being_deleted(self):
        self.accept('web01')
        real = self.api._LockedUpdate

        def broken(path, *a, **k):
            if path == self.api.CVE_IGNORE_FILE:
                raise OSError('read only')
            return real(path, *a, **k)
        self.api._LockedUpdate = broken
        try:
            self.assertEqual(self.api.cve_handlers_mod.drop_host_acceptance('web01'), 0)
            self.api._purge_device('web01')
        finally:
            self.api._LockedUpdate = real
        self.assertNotIn('web01', self.api.load(self.api.DEVICES_FILE), 'the host is gone')


# ── hostile input and the routes ─────────────────────────────────────────────────────────────────────────────────

class TestWhatIsNotOurs(_Cve):

    def test_the_reason_is_cut_and_a_body_that_is_not_a_map_is_no_crash(self):
        st, got = self.accept('web01', reason='x' * 5000)
        self.assertEqual(st, 200)
        reasons = {r.get('reason') for v in self.store().values() for r in checks.cve_ignore_records(v)}
        self.assertEqual({len(r) for r in reasons}, {256}, 'a reason is cut to 256 characters')
        for junk in ([], 'x', 7, None, {'reason': ['a', 'list']}, {'reason': {'a': 1}}, {'reason': None}):
            st, _ = self.request('/api/devices/web02/cve/accept', 'POST', body=junk)
            self.assertIn(st, (200, 400), junk)
        st, got = self.accept('web01', reason=None)
        self.assertEqual(st, 200)
        self.assertEqual(self.accept('web02', reason='')[0], 200)
        reasons = {r.get('reason') for v in self.store().values() for r in checks.cve_ignore_records(v) if r.get('scope') == 'web02'}
        self.assertEqual(reasons, {'Host accepted'}, 'no reason is "Host accepted", so the finding says why it does not count')

    def test_damaged_rows_of_a_scan_are_skipped_and_only_ids_that_name_a_vulnerability_are_accepted(self):
        self.scan('web01', [finding(A), 'junk', None, 7, {'vuln_id': ['CVE-2026-0003']}, {'vuln_id': 'has a space'}, {'vuln_id': 'x' * 100}, {'vuln_id': A}, {'severity': 'high'}, finding('GHSA-xxxx-xxxx-xxxx')])
        st, got = self.accept('web01')
        self.assertEqual((st, got['accepted'], got['findings']), (200, 2, 2), 'one record for A, however many rows name it, and one for the GHSA id')
        self.assertEqual(sorted(self.store()), ['GHSA-xxxx-xxxx-xxxx', A] if 'GHSA' < A else [A, 'GHSA-xxxx-xxxx-xxxx'])

    def test_a_host_that_does_not_exist_or_is_named_oddly_is_not_found_and_nothing_is_written(self):
        for dev_id in ('nope', 'a..b', 'WEB01', 'web01%2Fx', 'x' * 300):
            st, _ = self.accept(dev_id)
            self.assertEqual(st, 404, dev_id)
            st, _ = self.unaccept(dev_id)
            self.assertIn(st, (404, 200), dev_id)
        self.assertEqual(self.store(), {})

    def test_the_routes_take_post_only_and_a_delete_does_not_delete_the_host(self):
        for method in ('GET', 'PUT', 'PATCH'):
            st, _ = self.request('/api/devices/web01/cve/accept', method)
            self.assertIn(st, (404, 405), method)
        st, _ = self.request('/api/devices/web01/cve/accept', 'DELETE')
        self.assertIn(st, (404, 405))
        self.assertIn('web01', self.api.load(self.api.DEVICES_FILE), 'the generic route that deletes a host reads the id after /api/devices/, and this path must not reach it')
        self.assertEqual(self.store(), {})


# ── the index is the question asked of each id ───────────────────────────────────────────────────────────────────

class TestTheIndexIsTheQuestionAskedOfEachId(unittest.TestCase):
    """The page asks the index once for every host, where it used to ask every id of the store about every host. The two must give the same set."""

    def _store(self, rng):
        hosts = ['h1', 'h2', 'h3', 'h4']
        tenants = [None, 'tA', 'tB']
        store = {}
        for n in range(rng.randint(0, 25)):
            records = []
            for _ in range(rng.randint(1, 3)):
                scope = rng.choice(['global'] + hosts + [None, 7, '', ['h1']])
                rec = {'scope': scope, 'reason': 'r', 'actor': 'a', 'ts': 1}
                owner = rng.choice(tenants)
                if owner:
                    rec['tenant'] = owner
                if rng.random() < .3:
                    rec[checks.HOST_ACCEPT] = 5
                records.append(rec)
            entry = dict(records[0])
            if records[1:]:
                entry['others'] = records[1:]
            store['CVE-2026-%04d' % n] = rng.choice([entry, entry, entry, 'junk', None, 7, ['x'], {'others': 'no'}])
        return store

    def test_the_same_set_for_every_host_and_tenant_over_many_stores(self):
        rng = random.Random(8021)
        checked = 0
        for _ in range(400):
            store = self._store(rng)
            index = checks.cve_ignore_index(store)
            for host in ('h1', 'h2', 'h3', 'h4', 'other'):
                for tenant in (None, 'default', 'tA', 'tB'):
                    naive = {k for k, v in store.items() if checks.cve_ignore_applies(v, host, tenant)}
                    self.assertEqual(checks.cve_ignored_ids(index, host, tenant), naive, (store, host, tenant))
                    checked += 1
        self.assertGreater(checked, 5000, 'control: the loop measured many cases')

    def test_control_the_index_is_not_empty_for_a_store_that_has_records(self):
        index = checks.cve_ignore_index({'CVE-1': {'scope': 'h1', 'reason': 'r'}, 'CVE-2': {'scope': 'global', 'reason': 'r'}})
        self.assertEqual(checks.cve_ignored_ids(index, 'h1'), {'CVE-1', 'CVE-2'})
        self.assertEqual(checks.cve_ignored_ids(index, 'h2'), {'CVE-2'})
        self.assertEqual(checks.cve_ignored_ids(checks.cve_ignore_index(None), 'h1'), set())

    def test_the_marker_helper_reads_a_whole_number_only(self):
        self.assertTrue(checks.is_host_accept({'host_accept': 5}))
        for junk in (None, True, 5.5, '5', {}, [], 'x', {'host_accept': 'x'}, {'host_accept': True}):
            self.assertFalse(checks.is_host_accept(junk), junk)


@unittest.skipUnless(shutil.which('node'), 'node not installed')
class TestTheViewIsSafe(unittest.TestCase):
    """The banner and the buttons are built from what the server sends: an account name and a reason that people wrote, and the id and name of a host. The real functions,
    run with the app's own escaping."""

    JS = _TESTS.parent / 'server' / 'html' / 'static' / 'js'

    def run_js(self, calls):
        import re
        import srcpin
        app = (self.JS / 'app.js').read_text()
        page = (self.JS / 'app-cve.js').read_text()
        script = '\n'.join([re.search(r'^function escHtml\(s\) \{.*\}$', app, re.M).group(0), re.search(r'^function escAttr\(s\) \{.*\}$', app, re.M).group(0),
                            srcpin.js_function(page, '_cveAcceptButtons'), srcpin.js_function(page, '_cveAcceptedHtml'),
                            "const timeAgoHtml = ts => '<time>' + Number(ts) + '</time>';", "const _icon = () => '';",
                            'console.log(JSON.stringify((' + calls + ')));'])
        r = subprocess.run([shutil.which('node'), '-e', script], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr[-500:])
        return json.loads(r.stdout)

    def test_what_people_wrote_is_text_and_never_markup(self):
        hostile = '"><img src=x onerror=alert(1)><script>x</script>'
        out = self.run_js("[_cveAcceptedHtml({at: 5, n: 3, by: %s, reason: %s}), _cveAcceptButtons({n: 1}, %s, %s), _cveAcceptButtons(null, %s, %s)]"
                          % ((json.dumps(hostile),) * 6))
        for html in out:
            for raw in ('<img', '<script', 'onerror=alert(1)>'):
                self.assertNotIn(raw, html, raw)
        self.assertIn('&lt;img', out[0], 'shown as the text it is')
        self.assertIn('Accepted findings:</span> <strong>3</strong>', out[0])
        self.assertIn('<time>5</time>', out[0])

    def test_numbers_and_shapes_that_are_not_ours_print_as_nothing_or_zero(self):
        out = self.run_js("['x', null, 7, [], {n: '<b>9</b>'}, {n: -4}, {n: NaN}, {n: 1e999}, {at: 'x', n: 2, by: 5, reason: {}}].map(_cveAcceptedHtml)")
        self.assertEqual(out[:4], ['', '', '', ''], 'what is not a map has no banner')
        for html in out[4:8]:
            self.assertIn('Accepted findings:</span> <strong>0</strong>', html, 'a count that is not a number is a zero')
            self.assertNotIn('<b>', html)
        self.assertNotIn('<time>', out[8], 'a time that is not a number is not printed')
        self.assertNotIn('by</span>', out[8], 'nor an account that is not text')
        self.assertIn('<strong>2</strong>', out[8])

    def test_the_buttons_follow_whether_the_host_is_accepted(self):
        out = self.run_js("[_cveAcceptButtons(null, 'h1', 'host one'), _cveAcceptButtons({n: 2}, 'h1', 'host one'), _cveAcceptButtons('junk', 'h1', 'host one')]")
        self.assertEqual([('cveAcceptHost' in h, 'cveAcceptNew' in h, 'cveUnacceptHost' in h) for h in out], [(True, False, False), (False, True, True), (False, True, True)],
                         'a value that is a map or any truthy thing is an accepted host, nothing is not')
        self.assertIn('data-arg="h1" data-arg2="host one"', out[0])


if __name__ == '__main__':
    unittest.main()
