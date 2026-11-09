#!/usr/bin/env python3
"""8.0.0: Detections -- the sweep, the two routes and the alert, through the real handlers.

No stand-in for fire_webhook: an event goes through `_record_alert`'s whitelist and its coalescing identity, which is where a payload key is lost, and the fleet event the rules read
back goes through `_record_fleet_event`'s whitelist, which is what keeps `source_ip`, `count` and `user` for the rules that pair a burst of failed logins with a login. The module is off until an installation switches it
on, a host's sample is the host's word, and the rules belong to the installation, not to a tenant: each of those has its control case here.
"""

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-detections-sweep-'))
_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS))
sys.path.insert(0, str(_TESTS.parent / 'server' / 'cgi-bin'))

import detections as D  # noqa: E402
import traffic as T  # noqa: E402
from test_ip_intel import _fresh_api  # noqa: E402
from test_v800_push_mark import _run  # noqa: E402

PUB, PUB2, PUB3, LAN = '93.184.216.34', '8.8.8.8', '1.1.1.1', '10.0.0.7'
HOUR = 3600


def row(d='out', ip=PUB, port=443, proc='curl', n=1, tx=1000, rx=5000):
    return {'d': d, 'ip': ip, 'port': port, 'proc': proc, 'n': n, 'tx': tx, 'rx': rx}


def device(**kw):
    base = {'id': 'web01', 'name': 'web01', 'os': 'Ubuntu 24.04', 'token': 'tok', 'last_seen': int(time.time()), 'sysinfo': {}}
    base.update(kw)
    return base


class _Server(unittest.TestCase):

    def setUp(self):
        self.api = _fresh_api()
        self.api.verify_token = lambda token: {'k': ('admin', 'admin'), 'v': ('vera', 'viewer')}.get(token, (None, None))
        self.audits = []
        self.api.audit_log = lambda *a, **k: self.audits.append(a)
        self.put({'web01': device(), 'web02': device(id='web02', name='web02', token='t2')}, detections_module_enabled=True, traffic_module_enabled=True)

    def put(self, devices, **cfg):
        # through the storage layer: under SQLite and Postgres a store is a table, and a file written beside it is not what the server reads
        self.api.save(self.api.DEVICES_FILE, devices)
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.api._LOAD_CACHE.clear()

    def cfg(self):
        self.api._LOAD_CACHE.clear()
        return self.api.load(self.api.CONFIG_FILE)

    def call(self, fn, *args, body=None, method='GET', token='k'):
        return _run(self.api, lambda: fn(*args), body, method=method, env={'HTTP_AUTHORIZATION': 'Bearer ' + token})

    def request(self, path, method='GET', token='k', body=None):
        """A request through main(): the dispatcher, with the gates that run before a handler does."""
        names = ('REQUEST_METHOD', 'PATH_INFO', 'REMOTE_ADDR', 'CONTENT_LENGTH', 'QUERY_STRING', 'HTTP_AUTHORIZATION', 'HTTP_X_TOKEN')
        saved = {n: os.environ.get(n) for n in names}

        def go():
            os.environ.update(PATH_INFO=path)
            self.api.main()
        try:
            return _run(self.api, go, body, method=method, env={'HTTP_AUTHORIZATION': 'Bearer ' + token})
        finally:
            for n, v in saved.items():
                if v is None:
                    os.environ.pop(n, None)
                else:
                    os.environ[n] = v

    def plant(self, dev='web01', rows=None, base=None, first_ago=2 * HOUR, at=None):
        """A host's Traffic record, built the way the server keeps it: a first sample `first_ago` back (the baseline) and then the sample of `rows` at `at`."""
        now = int(time.time()) if at is None else at
        start = now - first_ago
        rec = T.merge(None, T.clean_sample({'win': 60, 'rows': base if base is not None else [row(ip=PUB3)]}, start), start)
        rec = T.merge(rec, T.clean_sample({'win': 60, 'rows': rows or []}, now), now)
        self.api._entity_write_one(self.api.TRAFFIC_FILE, dev, rec)
        self.api._LOAD_CACHE.clear()
        return rec

    def sweep(self):
        """One run of the cadence: a request of its own, so the per-request cache starts empty, and due."""
        with self.api._LockedUpdate(self.api.CONFIG_FILE) as c:
            c['last_detections_run'] = 0
        self.api._LOAD_CACHE.clear()
        self.api.run_detections_if_due()
        self.api._LOAD_CACHE.clear()

    def alerts(self, dev=None):
        self.api._LOAD_CACHE.clear()
        store = self.api.load(self.api.ALERTS_FILE) or {}
        rows = [a for a in (store.get('alerts') if isinstance(store, dict) else store) or [] if a.get('event') == 'detection_found']
        return [a for a in rows if dev is None or a.get('device_id') == dev]

    def stored(self, dev='web01'):
        self.api._LOAD_CACHE.clear()
        return self.api._entity_read_one(self.api.DETECTIONS_FILE, dev, None)

    def age_what_was_raised(self, seconds, dev='web01'):
        rec = self.stored(dev)
        rec['alerted'] = {k: v - seconds for k, v in rec['alerted'].items()}
        self.api._entity_write_one(self.api.DETECTIONS_FILE, dev, rec)
        self.api._LOAD_CACHE.clear()


class TestTheModuleIsOffUntilItIsSwitchedOn(_Server):

    def setUp(self):
        super().setUp()
        self.put({'web01': device()})
        self.plant(rows=[row(proc='bash')])

    def test_the_routes_answer_404_and_say_which_module(self):
        st, got = self.request('/api/detections')
        self.assertEqual((st, got.get('module_disabled')), (404, 'detections'))
        st, got = self.request('/api/detections/rules', 'POST', body={'rules': {'interpreter_egress': {'enabled': False}}})
        self.assertEqual((st, got.get('module_disabled')), (404, 'detections'))
        self.assertNotIn('detections', self.cfg(), 'nothing was saved by a request the gate refused')

    def test_the_handlers_refuse_on_their_own_too(self):
        st, got = self.call(self.api.handle_detections_get)
        self.assertEqual((st, got.get('module_disabled')), (404, 'detections'), 'a handler reached some other way than main() still checks the switch')
        st, got = self.call(self.api.handle_detections_rules_set, body={'rules': {'interpreter_egress': {'enabled': False}}}, method='POST')
        self.assertEqual((st, got.get('module_disabled')), (404, 'detections'))
        self.assertNotIn('detections', self.cfg())

    def test_the_sweep_does_nothing_and_leaves_no_mark(self):
        self.api.run_detections_if_due()
        self.assertEqual(self.alerts(), [])
        self.assertNotIn('last_detections_run', self.cfg())
        self.assertFalse(self.api.backend_exists(self.api.DETECTIONS_FILE))

    def test_control_the_same_data_raises_an_alert_once_the_module_is_on(self):
        self.put({'web01': device()}, detections_module_enabled=True, traffic_module_enabled=True)
        self.plant(rows=[row(proc='bash')])
        self.sweep()
        self.assertEqual(len(self.alerts()), 1)

    def test_a_stranger_gets_401_and_the_wrong_method_405(self):
        self.put({'web01': device()}, detections_module_enabled=True)
        self.assertEqual(self.call(self.api.handle_detections_get, token='nobody')[0], 401)
        self.assertEqual(self.call(self.api.handle_detections_get, method='POST')[0], 405)
        self.assertEqual(self.call(self.api.handle_detections_rules_set, method='GET')[0], 405)
        self.assertEqual(self.call(self.api.handle_detections_rules_set, method='POST', token='nobody', body={'rules': {}})[0], 401)


class TestWhatTheSweepRaises(_Server):

    def test_a_shell_holding_a_connection_to_the_internet_is_one_high_alert_with_its_facts(self):
        self.plant(rows=[row(ip=PUB2, port=4444, proc='bash')])
        self.sweep()
        rows = self.alerts()
        self.assertEqual(len(rows), 1, rows)
        a = rows[0]
        self.assertEqual((a['device_id'], a['severity']), ('web01', 'high'), 'the rule sets the severity of the alert: severity=None in the registry')
        p = a['payload']
        self.assertEqual((p['rule'], p['ip'], p['port'], p['process'], p['name']), ('interpreter_egress', PUB2, 4444, 'bash', 'web01'))
        self.assertIn('bash on web01 is connected to %s:4444' % PUB2, p['detail'])

    def test_a_second_sweep_does_not_raise_it_again(self):
        self.plant(rows=[row(proc='bash')])
        self.sweep()
        first = self.alerts()
        self.sweep()
        self.sweep()
        self.assertEqual(len(self.alerts()), 1)
        self.assertEqual(self.alerts()[0].get('count'), first[0].get('count'), 'not even a repeat on the one row: it was raised once')

    def test_the_finding_comes_back_after_its_interval_and_is_still_one_row(self):
        self.plant(rows=[row(proc='bash')])
        self.sweep()
        self.age_what_was_raised(7 * HOUR)
        self.sweep()
        rows = self.alerts()
        self.assertEqual(len(rows), 1, 'the same host, rule, address, port and program: one ongoing condition')
        self.assertGreaterEqual(rows[0].get('count', 1), 2, 'and it says it happened again')

    def test_the_alert_is_gone_from_the_store_only_as_the_alert_store_decides_not_the_sweep(self):
        self.plant(rows=[row(proc='bash')])
        self.sweep()
        self.assertEqual(len(self.stored()['found']), 1)
        self.plant(rows=[])
        self.sweep()
        self.assertEqual(self.stored()['found'], [], 'what is true now: the connection is gone')
        self.assertEqual(len(self.alerts()), 1, 'the alert records that it happened, and nothing clears it but a person')

    def test_a_host_with_more_findings_than_the_cap_reaches_the_later_ones(self):
        rows = [row(ip='9.9.%d.%d' % (i // 200, i % 200 + 1), proc='bash') for i in range(8)]
        self.plant(rows=rows)
        self.sweep()
        self.assertEqual(len(self.alerts()), D.MAX_PER_HOST)
        self.assertEqual(len(self.stored()['found']), D.MAX_PER_HOST, 'the page shows five')
        self.sweep()
        self.assertEqual(len(self.alerts()), 8, 'the next sweep raises the three the cap held back, and not the five again')
        self.sweep()
        self.assertEqual(len(self.alerts()), 8)

    def test_the_brute_force_pair_is_read_from_the_real_events(self):
        """The two events go through fire_webhook and the fleet log's own whitelist: the rule can only pair what that whitelist keeps (`source_ip`, `count`, `user`, `source`)."""
        self.api.fire_webhook('brute_force_detected', {'device_id': 'web01', 'name': 'web01', 'unit': 'ssh', 'source_ip': PUB2, 'count': 212, 'window_s': 300, 'threshold': 5})
        self.api.fire_webhook('login_new_source', {'device_id': 'web01', 'name': 'web01', 'source': PUB2, 'user': 'root'})
        self.api._LOAD_CACHE.clear()
        kept = {e['event']: e['payload'] for e in (self.api.load(self.api.FLEET_EVENTS_FILE) or {}).get('events', [])}
        self.assertEqual((kept['brute_force_detected'].get('source_ip'), kept['brute_force_detected'].get('count'), kept['login_new_source'].get('user')), (PUB2, 212, 'root'))
        self.sweep()
        rows = [a for a in self.alerts('web01') if a['payload']['rule'] == 'bruteforce_then_login']
        self.assertEqual([(a['severity'], a['payload']['ip']) for a in rows], [('critical', PUB2)])

    def test_the_way_back_in_and_a_new_destination_is_read_from_the_real_event(self):
        self.plant(rows=[row(ip=PUB2, proc='curl')])
        self.api.fire_webhook('ssh_key_added', {'device_id': 'web01', 'name': 'web01', 'user': 'root', 'fingerprint': 'SHA256:x'})
        self.sweep()
        rows = [a for a in self.alerts('web01') if a['payload']['rule'] == 'persistence_then_egress']
        self.assertEqual([(a['severity'], a['payload']['ip']) for a in rows], [('high', PUB2)])

    def test_a_new_port_that_a_stranger_uses_is_read_from_the_real_event(self):
        self.plant(rows=[row(d='in', ip=PUB2, port=8081, proc='python3')])
        self.api.fire_webhook('new_port_detected', {'device_id': 'web01', 'name': 'web01', 'proto': 'tcp', 'port': 8081, 'process': 'python3'})
        self.sweep()
        rows = [a for a in self.alerts('web01') if a['payload']['rule'] == 'exposed_port_in_use']
        self.assertEqual([(a['severity'], a['payload']['port']) for a in rows], [('medium', 8081)])

    def test_an_address_marked_bad_after_the_host_called_it_is_found_from_the_stores(self):
        now = int(time.time())
        self.plant(rows=[row(ip=PUB)], base=[row(ip=PUB2)], first_ago=4 * 86400)
        self.api.save(self.api.IPINTEL_FILE, {'attackers': {PUB2: {'verdict': {'score': 91, 'country': 'DE'}, 'devices': {'edge:trap': {'at': now - 100, 'count': 3}}}}})
        self.api._LOAD_CACHE.clear()
        self.sweep()
        rows = [a for a in self.alerts('web01') if a['payload']['rule'] == 'known_bad_contact']
        self.assertEqual([(a['severity'], a['payload']['ip']) for a in rows], [('medium', PUB2)], 'called days ago, marked since')

    def test_a_host_that_stopped_reporting_has_no_live_connections(self):
        self.plant(rows=[row(proc='bash')], at=int(time.time()) - 3 * HOUR)
        self.sweep()
        self.assertEqual(self.alerts(), [], 'the sample is hours old: the connection it shows may be long gone')

    def test_the_traffic_module_off_leaves_the_rules_that_read_it_with_nothing(self):
        self.put({'web01': device()}, detections_module_enabled=True, traffic_module_enabled=False)
        self.plant(rows=[row(proc='bash')])
        self.sweep()
        self.assertEqual(self.alerts(), [])


class TestHowMuchASweepRaises(_Server):

    def test_a_sweep_raises_at_most_the_fleet_cap_worst_first_and_the_next_sweep_raises_the_rest(self):
        hosts = {'h%02d' % i: device(id='h%02d' % i, name='h%02d' % i, token='t%d' % i) for i in range(12)}
        self.put(hosts, detections_module_enabled=True, traffic_module_enabled=True)
        for i, hid in enumerate(hosts):
            self.plant(hid, rows=[row(ip='9.9.%d.%d' % (i, k + 1), proc='bash') for k in range(3)])         # 36 findings of one severity
        self.api.fire_webhook('brute_force_detected', {'device_id': 'h11', 'name': 'h11', 'source_ip': PUB2, 'count': 50})
        self.api.fire_webhook('login_new_source', {'device_id': 'h11', 'name': 'h11', 'source': PUB2, 'user': 'root'})       # and one critical, on the last host of the list
        mod = self.api.detections_handlers_mod
        saved = mod.RAISE_MAX
        mod.RAISE_MAX = 10
        try:
            self.sweep()
            first = self.alerts()
            self.assertEqual(len(first), 10, 'one sweep raises at most the cap for the whole fleet')
            self.assertIn('critical', [a['severity'] for a in first], 'the worst goes first, even from the last host of the list')
            for _ in range(3):
                self.sweep()
            self.assertEqual(len(self.alerts()), 37, 'what was held back stayed due and the next sweeps raised it: 36 and the critical one, none twice')
        finally:
            mod.RAISE_MAX = saved

    def test_the_cap_of_the_fleet_is_a_hundred(self):
        self.assertEqual(self.api.detections_handlers_mod.RAISE_MAX, 100)


class TestARuleThatFails(_Server):

    def test_it_is_said_once_for_the_sweep_with_the_number_of_hosts_and_the_other_rules_still_raise(self):
        import contextlib
        import io
        hosts = {'h%d' % i: device(id='h%d' % i, name='h%d' % i, token='t%d' % i) for i in range(3)}
        self.put(hosts, detections_module_enabled=True, traffic_module_enabled=True)
        for hid in hosts:
            self.plant(hid, rows=[row(proc='bash')])
        real = D._RULE_FUNCS['known_bad_contact']

        def boom(c, p):
            raise RuntimeError('one rule that fails on every host')
        D._RULE_FUNCS['known_bad_contact'] = boom
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err):
                self.sweep()
        finally:
            D._RULE_FUNCS['known_bad_contact'] = real
        lines = [ln for ln in err.getvalue().splitlines() if 'the rule known_bad_contact failed' in ln]
        self.assertEqual(len(lines), 1, err.getvalue())
        self.assertIn('failed on 3 hosts', lines[0])
        self.assertIn('RuntimeError', lines[0])
        self.assertEqual(len(self.alerts()), 3, 'the shell rule ran on every host')


class TestWhoIsLookedAt(_Server):

    def test_an_unmonitored_host_shows_its_findings_and_raises_nothing(self):
        self.put({'web01': device(monitored=False)}, detections_module_enabled=True, traffic_module_enabled=True)
        self.plant(rows=[row(proc='bash')])
        self.sweep()
        self.assertEqual(self.alerts(), [], 'an unmonitored host is silent by design')
        self.assertEqual(len(self.stored()['found']), 1, 'and still shown: telemetry views show unmonitored hosts, flagged')
        self.assertEqual(self.stored()['alerted'], {}, 'nothing was sent, so nothing is remembered as sent')
        st, got = self.call(self.api.handle_detections_get)
        self.assertEqual((st, [(f['id'], f['monitored']) for f in got['findings']]), (200, [('web01', False)]))
        self.put({'web01': device()}, detections_module_enabled=True, traffic_module_enabled=True)
        self.sweep()
        self.assertEqual(len(self.alerts()), 1, 'the day the host is monitored again, the standing finding is raised')

    def test_a_host_with_no_agent_or_one_that_was_decommissioned_is_not_looked_at(self):
        self.put({'web01': device(), 'ping01': device(id='ping01', name='ping01', agentless=True), 'old01': device(id='old01', name='old01', decommissioned=True)},
                 detections_module_enabled=True, traffic_module_enabled=True)
        for d in ('web01', 'ping01', 'old01'):
            self.plant(dev=d, rows=[row(proc='bash')])
        self.sweep()
        self.assertEqual({a['device_id'] for a in self.alerts()}, {'web01'})

    def test_a_host_that_is_deleted_takes_its_findings_with_it_and_the_next_sweep_does_not_bring_them_back(self):
        self.plant(rows=[row(proc='bash')])
        self.sweep()
        self.assertIsNotNone(self.stored())
        self.api._purge_device('web01')
        self.assertIsNone(self.stored())
        self.api._LOAD_CACHE.clear()
        self.sweep()
        self.assertIsNone(self.stored())

    def test_a_record_for_a_host_that_is_not_in_the_list_any_more_is_dropped_by_the_next_sweep(self):
        self.api._entity_write_one(self.api.DETECTIONS_FILE, 'ghost', {'found': [{'rule': 'interpreter_egress', 'key': 'k', 'severity': 'high', 'detail': 'x'}], 'alerted': {'k': int(time.time())}})
        self.api._LOAD_CACHE.clear()
        self.plant(rows=[row(proc='bash')])
        self.sweep()
        self.assertIsNone(self.stored('ghost'))
        self.assertIsNotNone(self.stored('web01'))


class TestNothingIsWrittenWhenNothingChanged(_Server):

    def test_a_quiet_fleet_writes_no_store(self):
        self.plant(rows=[row(proc='curl')])
        self.sweep()
        self.assertFalse(self.api.backend_exists(self.api.DETECTIONS_FILE), 'no finding and nothing remembered: no record, and no write of an empty store')

    def test_a_sweep_that_finds_what_it_found_before_writes_nothing_and_raises_nothing(self):
        self.plant(rows=[row(proc='bash')])
        self.sweep()
        calls = []
        real = self.api._LockedUpdate
        self.api._LockedUpdate = lambda f, *a, **k: (calls.append(f), real(f, *a, **k))[1]
        try:
            self.sweep()
        finally:
            self.api._LockedUpdate = real
        self.assertNotIn(self.api.DETECTIONS_FILE, calls, 'the same finding, already raised: the store is as it was, so it is not locked or rewritten')

    def test_the_cadence_is_five_minutes(self):
        self.assertEqual(self.api.detections_handlers_mod.EVERY_S, 300)
        self.plant(rows=[row(proc='bash')])
        self.api.run_detections_if_due()
        mark = self.cfg()['last_detections_run']
        self.assertAlmostEqual(mark, time.time(), delta=30)
        self.plant(rows=[row(ip=PUB2, proc='bash')])
        self.api.run_detections_if_due()
        self.assertEqual(len(self.alerts()), 1, 'a second run inside the five minutes is not due')
        self.assertEqual(self.cfg()['last_detections_run'], mark)


class TestThePage(_Server):

    def test_it_lists_the_rules_and_what_was_found_worst_first(self):
        self.plant(rows=[row(proc='nc'), row(ip=PUB2, proc='bash')])
        self.sweep()
        st, got = self.call(self.api.handle_detections_get)
        self.assertEqual(st, 200, got)
        self.assertEqual([r['id'] for r in got['rules']], list(D.RULES))
        self.assertEqual([f['severity'] for f in got['findings']], ['high', 'medium'])
        self.assertEqual({f['rule'] for f in got['findings']}, {'interpreter_egress'})
        f = got['findings'][0]
        self.assertEqual((f['id'], f['name'], f['ip'], f['port'], f['process'], f['monitored']), ('web01', 'web01', PUB2, 443, 'bash', True))
        self.assertIsInstance(f['raised_at'], int)
        self.assertEqual((got['total'], got['counts']['high'], got['counts']['medium'], got['every'], got['traffic'], got['editable']), (2, 1, 1, 300, True, True))
        self.assertIsInstance(got['last_run'], int)

    def test_an_administrator_may_change_the_rules_and_a_viewer_may_only_read_them(self):
        st, got = self.call(self.api.handle_detections_get, token='v')
        self.assertEqual((st, got['editable']), (200, False))
        self.assertEqual(len(got['rules']), 6)

    def test_findings_that_are_not_findings_are_left_out_and_the_page_still_answers(self):
        self.api._entity_write_one(self.api.DETECTIONS_FILE, 'web01', {'found': [None, 'x', {'rule': 'nope'}, {'rule': 'interpreter_egress', 'key': 'k', 'severity': 'high', 'detail': 'real'}], 'alerted': 'x'})
        self.api._entity_write_one(self.api.DETECTIONS_FILE, 'web02', 'junk')
        self.api._LOAD_CACHE.clear()
        st, got = self.call(self.api.handle_detections_get)
        self.assertEqual((st, [f['detail'] for f in got['findings']]), (200, ['real']))

    def test_a_hostile_store_does_not_stop_the_sweep(self):
        self.api._entity_write_one(self.api.DETECTIONS_FILE, 'web01', 'junk')
        self.api._entity_write_one(self.api.TRAFFIC_FILE, 'web02', 'junk')
        self.api.save(self.api.FLEET_EVENTS_FILE, {'events': [None, 'x', {'event': 'ssh_key_added', 'ts': 'x', 'payload': 5}, {'event': 'login_new_source', 'ts': int(time.time()), 'payload': {'device_id': ['x']}}]})
        self.api.save(self.api.IPINTEL_FILE, {'attackers': {PUB2: 'x', 5: {'devices': 'x'}, PUB: {'verdict': 'x', 'devices': {'a': 'x'}}}})
        self.api._LOAD_CACHE.clear()
        self.plant(rows=[row(proc='bash')])
        self.sweep()
        self.assertEqual(len(self.alerts('web01')), 1, 'the host with a good record was still looked at')


class TestTheRulesRoute(_Server):

    def test_it_saves_the_whole_document_and_answers_with_it(self):
        st, got = self.call(self.api.handle_detections_rules_set, body={'rules': {'known_bad_contact': {'min_score': 90}, 'interpreter_egress': {'enabled': False}}}, method='POST')
        self.assertEqual(st, 200, got)
        saved = self.cfg()['detections']
        self.assertEqual(set(saved), set(D.RULES), 'every rule has its full row')
        self.assertEqual((saved['known_bad_contact']['min_score'], saved['interpreter_egress']['enabled'], saved['exposed_port_in_use']['hours']), (90, False, 6))
        self.assertEqual({r['id']: r['enabled'] for r in got['rules']}['interpreter_egress'], False)
        self.assertEqual([a[1] for a in self.audits], ['detections_rules_set'])

    def test_a_refused_document_changes_nothing(self):
        for bad in ({'rules': {'nope': {'enabled': True}}}, {'rules': {'known_bad_contact': {'min_score': 500}}}, {'rules': {}}, {'rules': 'x'}, {}, {'rules': {'known_bad_contact': {'enabled': 'yes'}}}):
            st, got = self.call(self.api.handle_detections_rules_set, body=bad, method='POST')
            self.assertEqual(st, 400, (bad, got))
        self.assertNotIn('detections', self.cfg())
        self.assertEqual(self.audits, [])

    def test_a_rule_that_is_switched_off_is_not_run(self):
        self.plant(rows=[row(proc='bash')])
        self.assertEqual(self.call(self.api.handle_detections_rules_set, body={'rules': {'interpreter_egress': {'enabled': False}}}, method='POST')[0], 200)
        self.sweep()
        self.assertEqual(self.alerts(), [])
        self.assertEqual(self.call(self.api.handle_detections_rules_set, body={'rules': {'interpreter_egress': {'enabled': True}}}, method='POST')[0], 200)
        self.sweep()
        self.assertEqual(len(self.alerts()), 1, 'switched back on, it runs')

    def test_every_rule_off_leaves_the_sweep_with_nothing_to_do(self):
        self.plant(rows=[row(proc='bash')])
        self.call(self.api.handle_detections_rules_set, body={'rules': {rid: {'enabled': False} for rid in D.RULES}}, method='POST')
        self.sweep()
        self.assertEqual(self.alerts(), [])

    def test_a_viewer_is_refused_and_so_is_a_stranger(self):
        self.assertEqual(self.call(self.api.handle_detections_rules_set, body={'rules': {'interpreter_egress': {'enabled': False}}}, method='POST', token='v')[0], 403)
        self.assertEqual(self.call(self.api.handle_detections_rules_set, body={'rules': {'interpreter_egress': {'enabled': False}}}, method='POST', token='nobody')[0], 401)
        self.assertNotIn('detections', self.cfg())


class TestTenants(_Server):
    """Two organisations on one installation, with the real gates: only the identity of the caller is stubbed."""

    def setUp(self):
        super().setUp()
        self.api.verify_token = lambda token: {'ta': ('alice', 'admin'), 'tb': ('bob', 'admin'), 'op': ('root', 'admin'), 'tv': ('vic', 'viewer')}.get(token, (None, None))
        self.api._caller_effective_tenant = lambda user: {'alice': 'acme', 'bob': 'globex', 'root': 'default', 'vic': 'acme'}[user]
        self.put({'web01': device(tenant='acme'), 'web02': device(id='web02', name='web02', token='t2', tenant='globex')},
                 detections_module_enabled=True, traffic_module_enabled=True, tenancy_enforced=True)
        self.plant('web01', rows=[row(ip='9.9.9.1', proc='bash')])
        self.plant('web02', rows=[row(ip='9.9.9.2', proc='bash')])
        self.sweep()

    def test_both_hosts_were_looked_at(self):
        self.assertEqual({a['device_id'] for a in self.alerts()}, {'web01', 'web02'})

    def test_a_tenant_reads_the_findings_of_its_own_hosts_and_names_no_other(self):
        for tok, mine, other in (('ta', 'web01', '9.9.9.2'), ('tb', 'web02', '9.9.9.1'), ('tv', 'web01', '9.9.9.2')):
            st, got = self.request('/api/detections', token=tok)
            self.assertEqual(st, 200, got)
            self.assertEqual([f['id'] for f in got['findings']], [mine], tok)
            self.assertEqual(got['total'], 1)
            self.assertNotIn(other, json.dumps(got), tok)
        st, got = self.request('/api/detections', token='op')
        self.assertEqual((st, sorted(f['id'] for f in got['findings'])), (200, ['web01', 'web02']), 'the platform operator sees every tenant')

    def test_the_rules_are_the_installations_and_a_tenant_cannot_change_them(self):
        body = {'rules': {'interpreter_egress': {'enabled': False}}}
        st, got = self.request('/api/detections/rules', 'POST', token='ta', body=body)
        self.assertEqual(st, 403, 'a tenant administrator passes require_admin_auth and is stopped by the platform operator check')
        self.assertIn('platform operator', got['error'])
        self.assertNotIn('detections', self.cfg())
        st, got = self.request('/api/detections', token='ta')
        self.assertEqual(got['editable'], False)
        st, got = self.request('/api/detections/rules', 'POST', token='op', body=body)
        self.assertEqual(st, 200, got)
        self.assertFalse(self.cfg()['detections']['interpreter_egress']['enabled'])

    def test_the_alert_of_one_tenant_is_not_in_the_inbox_of_another(self):
        st, got = self.request('/api/alerts', token='ta')
        self.assertEqual(st, 200, got)
        ids = {a.get('device_id') for a in (got.get('alerts') if isinstance(got, dict) else got) or [] if a.get('event') == 'detection_found'}
        self.assertEqual(ids, {'web01'})
        self.assertNotIn('9.9.9.2', json.dumps(got))


class TestTheEventItself(_Server):

    def test_the_registry_row_lands_in_the_inbox_and_takes_its_severity_from_the_payload(self):
        ev = self.api.EVENT_REGISTRY['detection_found']
        self.assertIn('severity', ev, 'a key that is absent never reaches the inbox')
        self.assertIsNone(ev['severity'])
        self.assertEqual(ev['kind'], 'detections')
        self.assertIn('detection_found', self.api.WEBHOOK_EVENT_NAMES)
        for sev in ('critical', 'high', 'medium', 'low'):
            self.assertEqual(self.api._alert_severity('detection_found', {'severity': sev}), sev)
        for junk in (None, 'info', 5, '', 'CRITICAL ', {'x': 1}):
            got = self.api._alert_severity('detection_found', {'severity': junk})
            self.assertIn(got, ('medium', 'critical'), repr(junk))
        self.assertEqual(self.api._alert_severity('detection_found', {'severity': 'CRITICAL'}), 'critical', 'case is not meaning')
        self.assertEqual(self.api._alert_severity('detection_found', {}), 'medium')

    def test_the_channel_kind_exists_or_the_routing_matrix_drops_the_event(self):
        kinds = {k for k, _label, _group in self.api.CHANNEL_KIND_DEFS}
        self.assertIn('detections', kinds)

    def test_the_message_is_the_rules_own_sentence(self):
        import notify
        text = notify._webhook_message('detection_found', {'name': 'web01', 'detail': 'bash on web01 is connected to 8.8.8.8:4444', 'severity': 'high'})
        self.assertEqual(text, 'bash on web01 is connected to 8.8.8.8:4444')
        self.assertTrue(notify._webhook_message('detection_found', {'name': 'web01'}))

    def test_every_alert_key_a_detection_sends_is_one_the_inbox_keeps(self):
        self.plant(rows=[row(ip=PUB2, port=4444, proc='bash')])
        self.sweep()
        p = self.alerts()[0]['payload']
        sent = {'name', 'device_id', 'rule', 'severity', 'detail', 'ip', 'port', 'process'}
        self.assertEqual(sent - set(p), set(), 'a payload key the whitelist drops reads as missing in the inbox')


class TestTheStoreAndItsRegistries(_Server):

    def test_the_store_is_an_entity_file_and_is_purged_with_the_host(self):
        import storage
        self.assertIn('detections.json', storage.ENTITY_FILES)
        self.assertEqual(self.api.DETECTIONS_FILE.name, 'detections.json')

    def test_the_settings_key_has_a_shape_and_the_store_has_one(self):
        import store_shapes
        self.assertIn('detections.json', store_shapes.SHAPES)

    def test_the_scheduler_runs_the_sweep(self):
        import scheduler
        self.assertIn('run_detections_if_due', scheduler.CADENCE)

    def test_the_sweep_is_in_the_cadence_of_main(self):
        src = (_TESTS.parent / 'server' / 'cgi-bin' / 'api.py').read_text()
        self.assertIn("_safe(run_detections_if_due, 'run_detections_if_due')", src)


if __name__ == '__main__':
    unittest.main()
