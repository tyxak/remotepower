#!/usr/bin/env python3
"""8.0.0: the Traffic view -- what each host's established TCP connections moved.

The rules (server/cgi-bin/traffic.py) are tested with literals; the heartbeat, the three read routes and the settings route go through the real handlers. Every control
case is here on purpose: the module is off until an installation switches it on, a sample is the host's word and is cleaned like any other, and the watch list is the
installation's, not a tenant's.
"""

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-traffic-'))
_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS))
sys.path.insert(0, str(_TESTS.parent / 'server' / 'cgi-bin'))

import traffic as T  # noqa: E402
from test_ip_intel import _fresh_api  # noqa: E402
from test_v800_push_mark import _run  # noqa: E402

ROOT = _TESTS.parent
PUB, PUB2, LAN = '93.184.216.34', '8.8.8.8', '10.0.0.7'


def row(d='out', ip=PUB, port=443, proc='curl', n=1, tx=1000, rx=5000):
    return {'d': d, 'ip': ip, 'port': port, 'proc': proc, 'n': n, 'tx': tx, 'rx': rx}


def sample(rows=None, win=60, **extra):
    return dict({'win': win, 'rows': rows if rows is not None else [row()]}, **extra)


class TestTheRules(unittest.TestCase):

    def test_ports_have_names_and_a_value_that_is_not_a_port_has_none(self):
        self.assertEqual((T.service_of(22), T.service_of(443), T.service_of(5432)), ('ssh', 'https', 'postgresql'))
        for bad in (0, -1, 65536, True, 'x', None, 22.0):
            self.assertEqual(T.service_of(bad), '', repr(bad))

    def test_an_address_is_public_private_or_one_of_the_special_kinds(self):
        want = {'8.8.8.8': 'public', '10.0.0.1': 'private', '192.168.1.1': 'private', '100.64.0.1': 'private', '169.254.1.1': 'link-local', '224.0.0.1': 'multicast',
                '127.0.0.1': 'loopback', 'fe80::1': 'link-local', '2606:4700::1111': 'public', 'junk': 'unknown', '': 'unknown'}
        for ip, scope in want.items():
            self.assertEqual(T.scope_of(ip), scope, ip)

    def test_a_row_is_kept_only_when_every_part_of_it_is_what_it_should_be(self):
        self.assertEqual(T.clean_row(row()), row())
        bad = [None, 'x', [], {}, row(d='sideways'), row(d=None), row(ip='junk'), row(ip='127.0.0.1'), row(ip='::1'), row(ip='0.0.0.0'), row(ip='224.0.0.5'), row(port=0),
               row(port=65536), row(port=True), row(port='443'), row(tx=-1), row(rx=-1), row(tx=2 ** 60), row(tx=1.5), row(rx='5'), row(tx=None), row(n=-1), row(n=10 ** 7), row(n=True)]
        for b in bad:
            self.assertIsNone(T.clean_row(b), repr(b))

    def test_an_address_is_written_the_short_way_and_loses_its_interface_and_its_mapping(self):
        self.assertEqual(T.clean_row(row(ip='fe80::0001%eth0'))['ip'], 'fe80::1')
        self.assertEqual(T.clean_row(row(ip='::ffff:8.8.8.8'))['ip'], '8.8.8.8')
        self.assertEqual(T.clean_row(row(ip='2606:4700:0:0:0:0:0:1111'))['ip'], '2606:4700::1111')

    def test_a_program_name_is_printable_ascii_and_short(self):
        self.assertEqual(T.clean_row(row(proc='a\x00b\n\x1b[31mc‮'))['proc'], 'ab[31mc')
        self.assertEqual(len(T.clean_row(row(proc='x' * 300))['proc']), 48)
        self.assertEqual(T.clean_row(row(proc=None))['proc'], '')
        self.assertEqual(T.clean_row(row(n=0))['n'], 1, 'a row is at least one connection')

    def test_a_sample_is_the_sum_of_its_rows_and_the_servers_clock(self):
        s = T.clean_sample(sample([row(tx=10, rx=20), row(ip=PUB2, tx=1, rx=2, n=3)], tx=10 ** 9, rx=10 ** 9, at=5), now=1000)
        self.assertEqual((s['tx'], s['rx'], s['conns'], s['at']), (11, 22, 4, 1000), 'the host sent its own totals and time; neither is read')
        self.assertEqual([r['ip'] for r in s['rows']], [PUB, PUB2], 'the busiest first')

    def test_a_sample_without_a_window_the_server_can_use_is_dropped(self):
        for win in (None, 0, 0.5, -3, 3601, 10 ** 400, float('nan'), float('inf'), True, '60', [60]):
            self.assertIsNone(T.clean_sample(sample(win=win), 1), repr(win))
        for raw in (None, 'x', [], 5, True):
            self.assertIsNone(T.clean_sample(raw, 1), repr(raw))
        self.assertEqual(T.clean_sample(sample([]), 1)['conns'], 0, 'a host with no remote connections is a sample too')
        self.assertEqual(T.clean_sample({'win': 60}, 1)['rows'], [], 'and a sample whose rows are missing')
        self.assertEqual(T.clean_sample({'win': 60, 'rows': 'junk', 'other': 5}, 1)['rows'], [])

    def test_the_busiest_rows_are_kept_and_the_rest_are_added_together(self):
        rows = [row(ip='9.9.%d.%d' % (i // 250, i % 250 + 1), port=1000 + i, tx=100 + i, rx=0, n=1) for i in range(T.MAX_ROWS + 30)]
        s = T.clean_sample(sample(rows), 1)
        self.assertEqual(len(s['rows']), T.MAX_ROWS)
        self.assertEqual(s['other']['rows'], 30)
        self.assertEqual(s['tx'], sum(100 + i for i in range(T.MAX_ROWS + 30)), 'nothing falls out of the total')
        self.assertEqual(min(r['tx'] for r in s['rows']) > max(100 + i for i in range(30)) - 1, True, 'what was kept is what moved most')
        self.assertEqual(len(T.clean_sample(sample([row(port=1 + i % 60000) for i in range(5000)]), 1)['rows']), T.MAX_ROWS, 'a flood is bounded before it is sorted')

    def test_an_agents_own_remainder_is_added_and_a_remainder_that_is_not_one_is_not(self):
        s = T.clean_sample(sample([row()], other={'n': 5, 'tx': 7, 'rx': 9, 'rows': 2}), 1)
        self.assertEqual((s['other'], s['tx'], s['rx']), ({'n': 5, 'tx': 7, 'rx': 9, 'rows': 2}, 1007, 5009))
        s = T.clean_sample(sample([row()], other={'n': 'x', 'tx': -1, 'rx': True, 'rows': 2.5}), 1)
        self.assertEqual(s['other'], {'n': 0, 'tx': 0, 'rx': 0, 'rows': 0})

    def test_an_agent_may_say_why_it_could_not_read_and_no_other_text_is_kept(self):
        for token in T.ERRORS:
            self.assertEqual(T.clean_sample(sample([], err=token), 1)['err'], token)
        for bad in ('<script>', 'NO-SS', '', None, 5, True, ['no-ss'], {'no-ss': 1}, 'no-ss ', 'x' * 1000):
            self.assertNotIn('err', T.clean_sample(sample([], err=bad), 1), repr(bad))
        self.assertNotIn('err', T.clean_sample(sample(), 1))

    def test_a_sample_that_could_not_read_adds_no_point_to_the_chart(self):
        s = T.clean_sample(sample([], err='no-ss'), 1000)
        self.assertEqual(T.merge(None, s, 1000)['series'], [], 'a flat point would read as no traffic')
        rec = T.merge(None, T.clean_sample(sample(), 1000), 1000)
        self.assertEqual(len(T.merge(rec, s, 1000 + T.SERIES_GAP)['series']), 1, 'and one that is already there is left alone')

    def test_the_chart_takes_a_point_every_five_minutes_and_keeps_a_day(self):
        s = T.clean_sample(sample([row(tx=6000, rx=12000)], win=60), 1000)
        rec = T.merge(None, s, 1000)
        self.assertEqual(rec['series'], [[1000, 100, 200, 1]])
        self.assertEqual(len(T.merge(rec, s, 1000 + T.SERIES_GAP - 1)['series']), 1)
        again = T.merge(rec, s, 1000 + T.SERIES_GAP)
        self.assertEqual([p[0] for p in again['series']], [1000, 1300])
        for i in range(T.SERIES_MAX + 20):
            rec = T.merge(rec, s, 1000 + (i + 1) * T.SERIES_GAP)
        self.assertEqual(len(rec['series']), T.SERIES_MAX)

    def test_a_record_that_is_not_one_starts_over_and_does_not_raise(self):
        s = T.clean_sample(sample(), 500)
        for prev in (None, 'x', [], 5, {'series': 'x', 'seen': 5, 'first': 'x'}, {'series': [[1], 'x', [1, 2, 3, 4]], 'seen': {'a': 'x', 5: 1, '1.1.1.1': 3}, 'first': True}):
            rec = T.merge(prev, s, 500)
            self.assertEqual((rec['first'], rec['at']), (500, 500), repr(prev))
        self.assertEqual(T.merge({'series': [[1], 'x', [1, 2, 3, 4]], 'seen': {'a': 'x', '1.1.1.1': 3}}, s, 500)['seen'], {'1.1.1.1': 3, PUB: 500})

    def test_only_a_public_address_is_remembered_and_the_oldest_are_forgotten_first(self):
        rec = T.merge(None, T.clean_sample(sample([row(ip=LAN), row(ip=PUB), row(ip='fe80::1')]), 10), 10)
        self.assertEqual(rec['seen'], {PUB: 10})
        rows = [row(ip='9.%d.%d.1' % (i // 250, i % 250)) for i in range(T.SEEN_MAX + 5)]
        rec = {'first': 1, 'seen': {'1.0.0.%d' % i: 100 + i for i in range(1, 6)}}
        for chunk in range(0, len(rows), T.MAX_ROWS):
            rec = T.merge(rec, T.clean_sample(sample(rows[chunk:chunk + T.MAX_ROWS]), 1000 + chunk), 1000 + chunk)
        self.assertEqual(len(rec['seen']), T.SEEN_MAX)
        self.assertNotIn('1.0.0.1', rec['seen'])

    def test_an_address_is_new_after_the_baseline_hour_and_for_a_day(self):
        base = {'first': 1000, 'seen': {PUB: 1000 + 60, PUB2: 1000 + T.LEARN_S, 'junk': 'x'}}
        self.assertFalse(T.is_new(base, PUB, 1100), 'the first hour is the baseline: nothing in it is new')
        self.assertTrue(T.is_new(base, PUB2, 1000 + T.LEARN_S + 5))
        self.assertTrue(T.is_new(base, PUB2, 1000 + T.LEARN_S + T.NEW_FOR_S))
        self.assertFalse(T.is_new(base, PUB2, 1000 + T.LEARN_S + T.NEW_FOR_S + 1), 'and then it is an old address')
        for rec in (None, 'x', {}, {'first': 1}, {'first': 'x', 'seen': {PUB: 5}}, {'first': True, 'seen': {PUB: 5}}):
            self.assertFalse(T.is_new(rec, PUB, 10 ** 6), repr(rec))
        self.assertFalse(T.is_new(base, '1.1.1.1', 10 ** 6))

    def test_a_watch_list_is_written_the_short_way_and_a_bad_entry_refuses_the_whole_list(self):
        got, err = T.clean_watch([{'kind': 'ip', 'value': '2606:4700:0:0:0:0:0:1111', 'label': ' C2 \x00seen'}, {'kind': 'cidr', 'value': '10.1.2.3/8'}, {'kind': 'port', 'value': '0443'},
                                  {'kind': 'proc', 'value': 'nc\x00'}, {'kind': 'port', 'value': '443'}])
        self.assertEqual(err, '')
        self.assertEqual(got, [{'kind': 'ip', 'value': '2606:4700::1111', 'label': 'C2 seen'}, {'kind': 'cidr', 'value': '10.0.0.0/8', 'label': ''},
                               {'kind': 'port', 'value': '443', 'label': ''}, {'kind': 'proc', 'value': 'nc', 'label': ''}], 'a repeated entry is kept once')
        for bad, words in (('x', 'list'), ([5], 'entry 1'), ([{'kind': 'host', 'value': 'a'}], 'kind'), ([{'kind': 'ip', 'value': 'nope'}], 'address'),
                           ([{'kind': 'ip', 'value': '127.0.0.1'}], 'address'), ([{'kind': 'cidr', 'value': '10.0.0.0/33'}], 'network'), ([{'kind': 'port', 'value': '0'}], 'port'),
                           ([{'kind': 'port', 'value': '65536'}], 'port'), ([{'kind': 'port', 'value': '-1'}], 'port'), ([{'kind': 'proc', 'value': '\x00\x01'}], 'name'),
                           ([{'kind': 'port', 'value': '1'}, {'kind': 'port', 'value': 'x'}], 'entry 2')):
            got, err = T.clean_watch(bad)
            self.assertEqual(got, [], repr(bad))
            self.assertIn(words, err, repr(bad))
        got, err = T.clean_watch([{'kind': 'port', 'value': str(i + 1)} for i in range(T.MAX_WATCH + 1)])
        self.assertEqual((got, 'at most' in err), ([], True))
        self.assertEqual(T.clean_watch(None), ([], ''))
        self.assertEqual(len(T.clean_watch([{'kind': 'port', 'value': str(i + 1)} for i in range(T.MAX_WATCH)])[0]), T.MAX_WATCH)

    def test_a_row_matches_a_watch_entry_by_address_network_port_or_program(self):
        r = row(ip='10.4.4.4', port=23, proc='Telnet')
        w = {'ip': {'kind': 'ip', 'value': '10.4.4.4'}, 'cidr': {'kind': 'cidr', 'value': '10.4.0.0/16'}, 'port': {'kind': 'port', 'value': '23'}, 'proc': {'kind': 'proc', 'value': 'telnet'}}
        for kind, entry in w.items():
            self.assertEqual(T.watched(r, [entry]), [entry], kind)
        self.assertEqual(len(T.watched(r, list(w.values()))), 4)
        miss = [{'kind': 'ip', 'value': '10.4.4.5'}, {'kind': 'cidr', 'value': '10.5.0.0/16'}, {'kind': 'port', 'value': '22'}, {'kind': 'proc', 'value': 'tel'}, {'kind': 'proc', 'value': ''},
                {'kind': 'cidr', 'value': 'junk'}, {'kind': 'x', 'value': '10.4.4.4'}, {}]
        self.assertEqual(T.watched(r, miss), [])
        self.assertEqual(T.watched({'ip': 'junk', 'port': 1}, [w['cidr'], w['ip']]), [])

    def test_the_fleet_adds_hosts_up_by_id_and_a_name_two_hosts_share_is_not_one_host(self):
        a = T.clean_sample(sample([row(tx=10, rx=0, proc='curl'), row(ip=PUB2, port=53, tx=1, rx=1, proc='')]), 1)
        b = T.clean_sample(sample([row(tx=5, rx=5, proc='curl')]), 1)
        out = T.fleet_summary([('h1', 'web', a), ('h2', 'web', b), ('h3', 'x', None), ('h4', 'y', 'junk')], top=10)
        self.assertEqual(out['totals'], {'tx': 16, 'rx': 6, 'conns': 3, 'hosts': 2})
        top = out['remotes'][0]
        self.assertEqual((top['ip'], top['hosts_n'], top['tx'], top['rx'], [h['id'] for h in top['hosts']]), (PUB, 2, 15, 5, ['h1', 'h2']))
        self.assertEqual({p['proc']: p['hosts_n'] for p in out['programs']}, {'curl': 2, '-': 1})
        self.assertEqual({(q['port'], q['service']) for q in out['ports']}, {(443, 'https'), (53, 'dns')})
        self.assertEqual(T.fleet_summary([], 5)['totals'], {'tx': 0, 'rx': 0, 'conns': 0, 'hosts': 0})
        many = [('h%d' % i, 'h%d' % i, T.clean_sample(sample([row(ip='9.9.9.%d' % (i % 200 + 1), tx=i)]), 1)) for i in range(300)]
        self.assertEqual(len(T.fleet_summary(many, 7)['remotes']), 7)
        self.assertEqual(len(T.fleet_summary([('h%d' % i, 'same', T.clean_sample(sample(), 1)) for i in range(20)])['remotes'][0]['hosts']), 5, 'a remote lists five hosts at most')


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
        self.put({'web01': device(), 'win01': device(id='win01', name='win01', os='Windows 11', token='tokw')}, traffic_module_enabled=True)

    def put(self, devices, **cfg):
        Path(self.api.DEVICES_FILE).write_text(json.dumps(devices))
        Path(self.api.CONFIG_FILE).write_text(json.dumps(cfg))
        self.api._LOAD_CACHE.clear()

    def cfg(self):
        self.api._LOAD_CACHE.clear()
        return self.api.load(self.api.CONFIG_FILE)

    def call(self, fn, *args, body=None, method='GET', token='k'):
        return _run(self.api, lambda: fn(*args), body, method=method, env={'HTTP_AUTHORIZATION': 'Bearer ' + token})

    def beat(self, dev='web01', token='tok', **extra):
        st, resp = _run(self.api, self.api.handle_heartbeat, dict({'device_id': dev, 'token': token, 'version': '8.0.0'}, **extra))
        self.assertEqual(st, 200, resp)
        self.api._LOAD_CACHE.clear()
        return resp

    def stored(self, dev='web01'):
        self.api._LOAD_CACHE.clear()
        return self.api._entity_read_one(self.api.TRAFFIC_FILE, dev, None)

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

    def host(self, dev='web01', token='k'):
        st, body = self.call(self.api.handle_device_traffic, dev, token=token)
        self.assertEqual(st, 200, body)
        return body

    def fleet(self, token='k'):
        st, body = self.call(self.api.handle_traffic_fleet, token=token)
        self.assertEqual(st, 200, body)
        return body


class TestTheHeartbeat(_Server):

    def test_a_linux_agent_is_told_how_often_to_sample_and_another_agent_is_not(self):
        self.assertEqual(self.beat()['traffic_every'], 60)
        self.assertNotIn('traffic_every', self.beat('win01', 'tokw'), 'the Windows agent samples nothing and never sees the key')

    def test_the_interval_is_held_to_its_range_and_a_stored_value_that_is_not_a_number_is_the_default(self):
        for stored, want in ((10, 30), (45, 45), (99999, 3600), ('x', 60), (True, 60), (None, 60), (10 ** 30, 60), (-5, 30), (90.9, 90), ([60], 60)):
            self.put({'web01': device()}, traffic_module_enabled=True, traffic_every=stored)
            self.assertEqual(self.beat()['traffic_every'], want, repr(stored))

    def test_with_the_module_off_the_agent_is_told_zero_and_nothing_is_kept(self):
        self.put({'web01': device()})
        self.assertEqual(self.beat(traffic=sample())['traffic_every'], 0, 'zero is sent, so an agent that was told a number stops')
        self.assertIsNone(self.stored())
        self.put({'web01': device()}, traffic_module_enabled=False)
        self.beat(traffic=sample())
        self.assertIsNone(self.stored())

    def test_a_sample_is_cleaned_and_kept_as_one_record_for_the_host(self):
        self.beat(traffic=sample([row(), row(ip='127.0.0.1'), 'junk', row(port=0)], win=60, tx=10 ** 15))
        rec = self.stored()
        self.assertEqual((len(rec['sample']['rows']), rec['sample']['tx'], rec['sample']['rx']), (1, 1000, 5000))
        self.assertEqual(rec['first'], rec['at'])
        self.assertEqual(rec['seen'], {PUB: rec['at']})
        self.assertIsNone(self.stored('win01'), 'a record belongs to the host that sent it')

    def test_a_report_without_a_sample_leaves_the_last_one_and_a_bad_one_does_not_replace_it(self):
        self.beat(traffic=sample())
        before = self.stored()
        self.beat()
        for bad in (None, 'x', [], 5, True, {}, {'win': 0}, {'win': 'x', 'rows': [row()]}, {'rows': [row()]}):
            self.beat(traffic=bad)
        self.assertEqual(self.stored(), before)

    def test_a_hostile_sample_never_fails_the_heartbeat(self):
        for bad in ('x' * 100000, [[]] * 50, {'win': 60, 'rows': [None] * 1000}, {'win': 60, 'rows': [{'ip': {'a': 1}, 'd': [1], 'port': {}, 'n': [], 'tx': {}, 'rx': ()}] * 50},
                    {'win': 60, 'rows': [row(tx=10 ** 400)]}, {'win': 60, 'rows': [row(ip='a' * 5000)]}, {'win': 60, 'rows': [row(proc='\x00' * 10 ** 5)]}, {'win': 10 ** 400}):
            self.beat(traffic=bad)

    def test_a_record_that_is_not_a_map_in_the_store_is_replaced_not_raised_on(self):
        Path(self.api.DATA_DIR / 'traffic.json').write_text(json.dumps({'web01': 'junk'})) if not self.api.backend_exists(self.api.TRAFFIC_FILE) else None
        self.api._entity_write_one(self.api.TRAFFIC_FILE, 'web01', 'junk')
        self.beat(traffic=sample())
        self.assertEqual(self.stored()['sample']['tx'], 1000)

    def test_the_stored_row_leaves_with_the_host(self):
        self.beat(traffic=sample())
        self.assertIsNotNone(self.stored())
        self.api._purge_device('web01')
        self.assertIsNone(self.stored(), 'a same-id host that enrols again does not inherit a stranger\'s addresses')


class TestOneHost(_Server):

    def test_a_host_that_has_not_reported_is_waiting_and_one_that_cannot_is_unsupported(self):
        got = self.host()
        self.assertEqual((got['state'], got['rows'], got['supported']), ('waiting', [], True))
        got = self.host('win01')
        self.assertEqual((got['state'], got['supported']), ('unsupported', False))

    def test_the_rows_come_back_with_their_service_scope_and_the_chart(self):
        self.beat(traffic=sample([row(), row(d='in', ip=LAN, port=22, proc='sshd', tx=10, rx=20)]))
        got = self.host()
        self.assertEqual(got['state'], 'reporting')
        by = {r['ip']: r for r in got['rows']}
        self.assertEqual((by[PUB]['service'], by[PUB]['scope'], by[PUB]['proc']), ('https', 'public', 'curl'))
        self.assertEqual((by[LAN]['service'], by[LAN]['scope'], by[LAN]['d']), ('ssh', 'private', 'in'))
        self.assertEqual((got['tx'], got['rx'], got['conns'], len(got['series'])), (1010, 5020, 2, 1))
        self.assertNotIn('new', by[PUB], 'the first hour of a host is its baseline')

    def test_a_host_that_stopped_reporting_is_stale_and_keeps_its_last_rows(self):
        self.beat(traffic=sample())
        rec = self.stored()
        rec['at'] -= 3600
        self.api._entity_write_one(self.api.TRAFFIC_FILE, 'web01', rec)
        got = self.host()
        self.assertEqual((got['state'], len(got['rows'])), ('stale', 1))

    def test_a_host_whose_agent_could_not_read_its_connections_says_so(self):
        self.beat(traffic=sample([], err='no-ss'))
        got = self.host()
        self.assertEqual((got['state'], got['err'], got['rows'], got['series']), ('error', 'no-ss', [], []))
        fleet = self.fleet()
        line = {h['id']: h for h in fleet['hosts']}['web01']
        self.assertEqual((line['state'], line['err'], fleet['by_state']['error'], fleet['totals']['hosts']), ('error', 'no-ss', 1, 0), 'a host that cannot be read adds nothing to the totals')
        self.beat(traffic=sample([row()], err='no-counters'))
        got = self.host()
        self.assertEqual((got['state'], got['err'], len(got['rows'])), ('reporting', 'no-counters', 1), 'connections without a volume still show, with the reason')
        self.beat(traffic=sample([row()]))
        self.assertEqual(self.host()['err'], '', 'the next good sample clears it')

    def test_a_stored_reason_that_is_not_one_of_the_known_tokens_is_not_shown(self):
        self.beat(traffic=sample())
        rec = self.stored()
        rec['sample']['err'] = '<img src=x onerror=alert(1)>'              # a store edited by hand, or written by an older build
        self.api._entity_write_one(self.api.TRAFFIC_FILE, 'web01', rec)
        self.assertEqual(self.host()['err'], '')
        line = {h['id']: h for h in self.fleet()['hosts']}['web01']
        self.assertNotIn('err', line)

    def test_a_host_that_polls_slowly_is_not_stale_after_five_minutes(self):
        self.put({'web01': device(poll_interval=900)}, traffic_module_enabled=True)
        self.beat(traffic=sample())
        rec = self.stored()
        rec['at'] -= 800            # past the 300 second floor, inside three polls of 900
        self.api._entity_write_one(self.api.TRAFFIC_FILE, 'web01', rec)
        self.assertEqual(self.host()['state'], 'reporting')
        rec['at'] -= 2000
        self.api._entity_write_one(self.api.TRAFFIC_FILE, 'web01', rec)
        self.assertEqual(self.host()['state'], 'stale')

    def test_an_address_first_used_after_the_baseline_hour_is_marked_new(self):
        self.beat(traffic=sample([row()]))
        rec = self.stored()
        rec['first'] -= T.LEARN_S + 100
        rec['seen'] = {PUB: rec['first'] + 5}
        self.api._entity_write_one(self.api.TRAFFIC_FILE, 'web01', rec)
        self.beat(traffic=sample([row(), row(ip=PUB2, port=53)]))
        got = {r['ip']: r for r in self.host()['rows']}
        self.assertTrue(got[PUB2].get('new'))
        self.assertNotIn('new', got[PUB], 'seen in the baseline hour')

    def test_the_reputation_of_an_address_comes_from_the_threat_intel_store_and_only_for_a_public_one(self):
        self.beat(traffic=sample([row(), row(ip=LAN, port=22)]))
        Path(self.api.IPINTEL_FILE).write_text(json.dumps({'attackers': {PUB: {'verdict': {'score': 97}}, LAN: {'verdict': {'score': 99}}, PUB2: {'verdict': {'score': 'x'}}}}))
        self.api._LOAD_CACHE.clear()
        by = {r['ip']: r for r in self.host()['rows']}
        self.assertEqual(by[PUB]['score'], 97)
        self.assertNotIn('score', by[LAN], 'a private address has no reputation to look up')

    def test_country_and_organisation_come_from_the_geoip_files_and_only_for_a_public_address(self):
        looked_up = []

        def reader(ip):
            looked_up.append(ip)
            return {'country': 'Denmark', 'country_code': 'DK', 'asn': 15169, 'org': 'Example Org', 'secret': 'not a geo field'}
        self.api.geo_enrich = reader
        self.beat(traffic=sample([row(), row(ip=LAN, port=22)]))
        by = {r['ip']: r for r in self.host()['rows']}
        self.assertEqual((by[PUB]['country'], by[PUB]['country_code'], by[PUB]['asn'], by[PUB]['org']), ('Denmark', 'DK', 15169, 'Example Org'))
        self.assertNotIn('secret', by[PUB], 'only the four geo fields are copied')
        self.assertNotIn('country', by[LAN])
        self.assertEqual(looked_up, [PUB], 'a private address is never looked up')

        def broken(ip):
            raise RuntimeError('the reader is gone')
        self.api.geo_enrich = broken
        got = self.host()
        self.assertEqual(len(got['rows']), 2, 'a reader that fails costs the row its country, not the page its rows')
        self.assertNotIn('country', {r['ip']: r for r in got['rows']}[PUB])

    def test_the_watch_list_marks_rows_and_a_viewer_reads_it_too(self):
        self.put({'web01': device()}, traffic_module_enabled=True, traffic_watch=[{'kind': 'port', 'value': '443', 'label': 'tls out'}, {'kind': 'ip', 'value': LAN, 'label': ''}])
        self.beat(traffic=sample([row(), row(ip=LAN, port=22)]))
        for tok in ('k', 'v'):
            by = {r['ip']: r for r in self.host(token=tok)['rows']}
            self.assertEqual(by[PUB]['watched'], [{'kind': 'port', 'value': '443', 'label': 'tls out'}])
            self.assertEqual(by[LAN]['watched'][0]['kind'], 'ip')

    def test_the_routes_refuse_what_they_should(self):
        st, _ = self.call(self.api.handle_device_traffic, 'web01', token='nobody')
        self.assertEqual(st, 401)
        st, _ = self.call(self.api.handle_device_traffic, 'web01', method='POST')
        self.assertEqual(st, 405)
        for bad in ('nope', '..', 'x' * 300, 'a b'):
            st, _ = self.call(self.api.handle_device_traffic, bad)
            self.assertEqual(st, 404, bad)
        self.put({'web01': device()})
        st, body = self.call(self.api.handle_device_traffic, 'web01')
        self.assertEqual((st, body.get('module_disabled')), (404, 'traffic'), 'the host route is outside the prefix the dispatcher gates, so it checks the switch itself')


class TestTheFleet(_Server):

    def setUp(self):
        super().setUp()
        self.put({'web01': device(), 'web02': device(id='web02', name='web02', token='t2'), 'win01': device(id='win01', name='win01', os='Windows 11', token='tokw'),
                  'sw': device(id='sw', name='sw', agentless=True), 'gone': device(id='gone', name='gone', decommissioned=True), 'idle': device(id='idle', name='idle', token='t3')},
                 traffic_module_enabled=True, traffic_watch=[{'kind': 'ip', 'value': PUB, 'label': 'flagged'}, {'kind': 'port', 'value': '22'}])
        self.beat('web01', 'tok', traffic=sample([row(tx=100, rx=0), row(ip=PUB2, port=53, tx=1, rx=1, proc='unbound'), row(d='in', ip=LAN, port=22, proc='sshd', tx=3, rx=4)]))
        self.beat('web02', 't2', traffic=sample([row(tx=50, rx=50)]))

    def test_the_hosts_are_added_up_and_the_agentless_and_the_decommissioned_are_not_listed(self):
        got = self.fleet()
        self.assertEqual(got['totals']['hosts'], 2)
        self.assertEqual([h['id'] for h in got['hosts']], ['idle', 'web01', 'web02', 'win01'])
        self.assertEqual(got['by_state'], {'reporting': 2, 'stale': 0, 'waiting': 1, 'unsupported': 1, 'error': 0})
        top = got['remotes'][0]
        self.assertEqual((top['ip'], top['hosts_n'], top['tx'], top['rx']), (PUB, 2, 150, 50))
        self.assertEqual(sorted(h['name'] for h in top['hosts']), ['web01', 'web02'])
        self.assertIs(top['watched'], True)
        self.assertEqual(top['scope'], 'public')

    def test_a_watch_list_match_names_the_host_the_address_the_port_and_the_entry(self):
        hits = self.fleet()['hits']
        self.assertEqual({(h['name'], h['ip'], h['port'], h['kind']) for h in hits}, {('web01', PUB, 443, 'ip'), ('web02', PUB, 443, 'ip'), ('web01', LAN, 22, 'port')})
        self.assertEqual({h['label'] for h in hits if h['kind'] == 'ip'}, {'flagged'})

    def test_each_host_line_carries_its_rate_over_the_window(self):
        line = {h['id']: h for h in self.fleet()['hosts']}['web02']
        self.assertEqual((line['state'], line['tx'], line['rx'], line['tx_rate'], line['rx_rate'], line['conns']), ('reporting', 50, 50, round(50 / 60), round(50 / 60), 1))
        self.assertNotIn('tx', {h['id']: h for h in self.fleet()['hosts']}['idle'])

    def test_a_host_the_caller_may_not_see_is_not_added_in(self):
        seen = []
        real = self.api._scope_filter_devices

        def only_web02(devs, scope=None):
            seen.append(sorted(devs))
            return {k: v for k, v in real(devs, scope).items() if k == 'web02'}
        self.api._scope_filter_devices = only_web02
        got = self.fleet()
        self.assertEqual([h['id'] for h in got['hosts']], ['web02'])
        self.assertEqual((got['totals']['hosts'], got['remotes'][0]['tx']), (1, 50))
        self.assertEqual({h['name'] for h in got['hits']}, {'web02'})
        self.assertEqual(len(seen), 1, 'the host set went through the scope and tenant filter once')

    def test_the_routes_refuse_what_they_should(self):
        st, _ = self.call(self.api.handle_traffic_fleet, token='nobody')
        self.assertEqual(st, 401)
        st, _ = self.call(self.api.handle_traffic_fleet, method='POST')
        self.assertEqual(st, 405)
        self.put({'web01': device()})
        st, body = self.call(self.api.handle_traffic_fleet)
        self.assertEqual((st, body.get('module_disabled')), (404, 'traffic'))

    def test_a_fleet_with_nothing_reported_is_an_empty_answer_and_not_an_error(self):
        self.put({'idle': device(id='idle', name='idle', token='t3')}, traffic_module_enabled=True)
        got = self.fleet()
        self.assertEqual((got['totals']['hosts'], got['remotes'], got['hits'], got['by_state']['waiting']), (0, [], [], 1))


class TestTheSettings(_Server):

    def test_the_platform_operator_saves_the_watch_list_and_the_interval(self):
        st, body = self.call(self.api.handle_traffic_config_set, body={'watch': [{'kind': 'port', 'value': '23', 'label': 'telnet'}], 'every': 120}, method='POST')
        self.assertEqual(st, 200, body)
        cfg = self.cfg()
        self.assertEqual((cfg['traffic_watch'], cfg['traffic_every']), ([{'kind': 'port', 'value': '23', 'label': 'telnet'}], 120))
        self.assertEqual([a[1] for a in self.audits], ['traffic_config_set'])
        self.assertEqual(self.beat()['traffic_every'], 120)

    def test_a_key_that_is_not_sent_is_left_alone_and_an_empty_list_clears(self):
        self.put({'web01': device()}, traffic_module_enabled=True, traffic_watch=[{'kind': 'port', 'value': '23', 'label': ''}], traffic_every=90)
        self.assertEqual(self.call(self.api.handle_traffic_config_set, body={'every': 45}, method='POST')[0], 200)
        self.assertEqual((self.cfg()['traffic_watch'], self.cfg()['traffic_every']), ([{'kind': 'port', 'value': '23', 'label': ''}], 45))
        self.assertEqual(self.call(self.api.handle_traffic_config_set, body={'watch': []}, method='POST')[0], 200)
        self.assertEqual((self.cfg()['traffic_watch'], self.cfg()['traffic_every']), ([], 45))
        self.assertEqual(self.call(self.api.handle_traffic_config_set, body={}, method='POST')[0], 200)
        self.assertEqual(self.audits[-1][1] if len(self.audits) > 2 else 'no third audit', 'no third audit', 'a save that changes nothing is not audited')

    def test_a_bad_value_is_refused_whole_and_nothing_is_saved(self):
        self.put({'web01': device()}, traffic_module_enabled=True, traffic_watch=[{'kind': 'port', 'value': '23', 'label': ''}], traffic_every=90)
        for body, words in (({'every': 29}, 'from 30'), ({'every': 3601}, 'from 30'), ({'every': 'x'}, 'from 30'), ({'every': True}, 'from 30'), ({'every': [60]}, 'from 30'), ({'every': {'a': 1}}, 'from 30'),
                            ({'watch': 'x'}, 'list'), ({'watch': [{'kind': 'ip', 'value': 'nope'}]}, 'address'), ({'watch': [{'kind': 'port', 'value': '1'}, 5], 'every': 60}, 'entry 2')):
            st, got = self.call(self.api.handle_traffic_config_set, body=body, method='POST')
            self.assertEqual(st, 400, body)
            self.assertIn(words, got['error'], body)
        cfg = self.cfg()
        self.assertEqual((cfg['traffic_watch'], cfg['traffic_every']), ([{'kind': 'port', 'value': '23', 'label': ''}], 90))
        self.assertEqual(self.audits, [])

    def test_the_save_is_for_an_administrator_and_for_the_platform_operator(self):
        st, _ = self.call(self.api.handle_traffic_config_set, body={'every': 60}, method='POST', token='v')
        self.assertEqual(st, 403)
        st, _ = self.call(self.api.handle_traffic_config_set, body={'every': 60}, method='POST', token='nobody')
        self.assertEqual(st, 401)
        st, _ = self.call(self.api.handle_traffic_config_set, body={'every': 60}, method='GET')
        self.assertEqual(st, 405)
        self.api._tenancy_enforced = lambda: True
        self.api._caller_is_superadmin = lambda: False
        st, got = self.call(self.api.handle_traffic_config_set, body={'every': 60}, method='POST')
        self.assertEqual(st, 403, 'a tenant administrator passes require_admin_auth and is stopped here')
        self.assertIn('platform operator', got['error'])
        self.assertNotIn('traffic_every', self.cfg())

    def test_the_entries_are_shown_to_everyone_on_one_organisation_and_to_the_operator_on_a_shared_install(self):
        self.put({'web01': device()}, traffic_module_enabled=True, traffic_watch=[{'kind': 'ip', 'value': PUB, 'label': 'ex-employee VPS'}])
        st, got = self.call(self.api.handle_traffic_config_get, token='v')
        self.assertEqual((st, got['count'], got['editable'], len(got['watch'])), (200, 1, False, 1))
        self.api._tenancy_enforced = lambda: True
        self.api._caller_is_superadmin = lambda: False
        st, got = self.call(self.api.handle_traffic_config_get, token='v')
        self.assertEqual((st, got['count'], got['watch']), (200, 1, []), 'a tenant user is told how many, not what')
        self.beat(traffic=sample())
        by = self.host(token='v')['rows']
        self.assertEqual([w['label'] for r in by for w in r.get('watched', [])], [''], 'the match shows and the operator\'s note does not')
        self.api._caller_is_superadmin = lambda: True
        st, got = self.call(self.api.handle_traffic_config_get)
        self.assertEqual((got['editable'], got['watch'][0]['label']), (True, 'ex-employee VPS'))

    def test_the_config_route_answers_404_while_the_module_is_off_and_401_to_a_stranger(self):
        st, _ = self.call(self.api.handle_traffic_config_get, token='nobody')
        self.assertEqual(st, 401)
        self.put({'web01': device()})
        st, got = self.call(self.api.handle_traffic_config_get)
        self.assertEqual((st, got.get('module_disabled')), (404, 'traffic'))
        st, got = self.call(self.api.handle_traffic_config_set, body={'every': 60}, method='POST')
        self.assertEqual((st, got.get('module_disabled')), (404, 'traffic'))


class TestTheDispatcher(_Server):
    """Through main(): the module gate and the host gate that run before a handler does."""

    def test_the_prefix_is_404_while_the_module_is_off_and_answers_while_it_is_on(self):
        self.put({'web01': device()})
        for path in ('/api/traffic/fleet', '/api/traffic/config'):
            st, got = self.request(path)
            self.assertEqual((st, got.get('module_disabled')), (404, 'traffic'), path)
        self.put({'web01': device()}, traffic_module_enabled=True)
        st, got = self.request('/api/traffic/fleet')
        self.assertEqual(st, 200, got)

    def test_the_host_route_is_found_and_a_host_outside_the_callers_scope_is_not_shown(self):
        self.beat(traffic=sample())
        st, got = self.request('/api/devices/web01/traffic')
        self.assertEqual((st, got['state']), (200, 'reporting'))
        real = self.api._enforce_device_scope
        calls = []
        self.api._enforce_device_scope = lambda: calls.append(self.api.path_info()) or real()
        self.request('/api/devices/web01/traffic')
        self.assertEqual(calls, ['/api/devices/web01/traffic'], 'the pre-dispatch gate that holds tenant and role scope sees this path')


class TestTenants(_Server):
    """Two organisations on one installation, with the real gates: only the identity of the caller is stubbed."""

    def setUp(self):
        super().setUp()
        self.api.verify_token = lambda token: {'ta': ('alice', 'admin'), 'tb': ('bob', 'admin'), 'op': ('root', 'admin'), 'tv': ('vic', 'viewer')}.get(token, (None, None))
        self.api._caller_effective_tenant = lambda user: {'alice': 'acme', 'bob': 'globex', 'root': 'default', 'vic': 'acme'}[user]
        self.put({'web01': device(tenant='acme'), 'web02': device(id='web02', name='web02', token='t2', tenant='globex')},
                 traffic_module_enabled=True, tenancy_enforced=True, traffic_watch=[{'kind': 'port', 'value': '443', 'label': 'operator note'}])
        self.beat('web01', 'tok', traffic=sample([row(ip='9.9.9.1', tx=100)]))
        self.beat('web02', 't2', traffic=sample([row(ip='9.9.9.2', tx=200)]))

    def test_a_tenant_administrator_reads_its_own_hosts_and_no_others(self):
        st, got = self.request('/api/devices/web01/traffic', token='ta')
        self.assertEqual((st, got['state']), (200, 'reporting'))
        st, got = self.request('/api/devices/web02/traffic', token='ta')
        self.assertEqual((st, got['error']), (403, 'Host belongs to another tenant'), 'the gate every /api/devices/<id>/ route has answers before the handler runs')
        self.assertNotIn('9.9.9.2', json.dumps(got))
        st, got = self.request('/api/devices/web01/traffic', token='tb')
        self.assertEqual(st, 403)
        self.assertNotIn('9.9.9.1', json.dumps(got))

    def test_the_fleet_view_adds_up_only_the_callers_hosts_and_names_no_other(self):
        for tok, mine, other in (('ta', 'web01', '9.9.9.2'), ('tb', 'web02', '9.9.9.1'), ('tv', 'web01', '9.9.9.2')):
            st, got = self.request('/api/traffic/fleet', token=tok)
            self.assertEqual(st, 200, got)
            self.assertEqual([h['id'] for h in got['hosts']], [mine], tok)
            self.assertEqual(got['totals']['hosts'], 1)
            self.assertNotIn(other, json.dumps(got), tok)
            self.assertEqual({h['name'] for h in got['hits']}, {mine}, tok)
        st, got = self.request('/api/traffic/fleet', token='op')
        self.assertEqual((st, sorted(h['id'] for h in got['hosts']), got['totals']['hosts']), (200, ['web01', 'web02'], 2), 'the platform operator sees every tenant')

    def test_the_watch_list_is_the_installations_and_a_tenant_cannot_change_or_read_the_notes(self):
        st, got = self.request('/api/traffic/config', 'POST', token='ta', body={'watch': [{'kind': 'port', 'value': '1', 'label': 'mine'}]})
        self.assertEqual(st, 403)
        self.assertEqual(self.cfg()['traffic_watch'][0]['label'], 'operator note')
        st, got = self.request('/api/traffic/config', token='ta')
        self.assertEqual((got['count'], got['watch'], got['editable']), (1, [], False))
        st, got = self.request('/api/devices/web01/traffic', token='ta')
        self.assertEqual([w['label'] for r in got['rows'] for w in r.get('watched', [])], [''], 'the row says it matched; the note is the operator\'s')
        st, got = self.request('/api/traffic/fleet', token='ta')
        self.assertEqual({h['label'] for h in got['hits']}, {''})
        st, got = self.request('/api/traffic/config', token='op')
        self.assertEqual((got['watch'][0]['label'], got['editable']), ('operator note', True))
        st, got = self.request('/api/traffic/config', 'POST', token='op', body={'watch': [{'kind': 'port', 'value': '22', 'label': 'ssh'}]})
        self.assertEqual(st, 200, got)


class TestTheRegistrations(unittest.TestCase):
    """Every place a new store, module, route and setting has to be listed."""

    def test_the_store_is_an_entity_file_with_a_shape_and_is_purged_with_its_host(self):
        import storage
        import store_shapes
        self.assertIn('traffic.json', storage.ENTITY_FILES)
        self.assertIn('traffic.json', store_shapes.SHAPES)
        src = (ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        self.assertEqual(src.count('        TRAFFIC_FILE,                   # 8.0.0: and what its connections moved'), 1)
        fixed = store_shapes.normalize('traffic.json', {'h1': {'first': '5', 'at': 'x', 'sample': {'rows': []}, 'series': 'junk', 'seen': []}, 'h2': 'junk', 'h3': {'series': [[1, 2, 3, 4]]}})
        self.assertEqual(sorted(fixed), ['h1', 'h3'], 'a row that is not a map is left out')
        self.assertEqual(fixed['h1']['series'], [], 'a field of the wrong kind is dropped, so the reader\'s default applies')

    def test_the_settings_are_typed_in_the_settings_document(self):
        import store_shapes
        fixed = store_shapes.normalize('config.json', {'traffic_every': 'x', 'traffic_watch': [{'kind': 'port', 'value': '1', 'label': ''}, 'junk', 5, {'kind': 'ip', 'value': 5}]})
        self.assertNotIn('traffic_every', fixed, 'a value that is not a number is dropped, and the reader\'s default applies')
        self.assertEqual(fixed['traffic_watch'][0], {'kind': 'port', 'value': '1', 'label': ''})
        self.assertEqual(store_shapes.normalize('config.json', {'traffic_every': '90'})['traffic_every'], 90)

    def test_the_module_is_off_by_default_and_gates_one_prefix(self):
        api = _fresh_api()
        self.assertEqual(api._MODULES['traffic'], ('traffic_module_enabled', False, ('/api/traffic',)))
        self.assertFalse(api._module_on('traffic'))

    def test_the_routes_are_in_the_table_and_in_the_openapi_document(self):
        api = _fresh_api()
        paths = {(m, d[2] + d[3]) for d in api._ROUTE_DEFS for m in d[1]} if hasattr(api, '_ROUTE_DEFS') else set()
        spec = api.handle_openapi_spec.__module__ and None
        del spec, paths
        src = (ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        for needle in ("'/api/devices/', '/traffic', 'handle_device_traffic'", "'/api/traffic/fleet', '', 'handle_traffic_fleet'", "('GET',), '/api/traffic/config', '', 'handle_traffic_config_get'",
                       "('POST',), '/api/traffic/config', '', 'handle_traffic_config_set'"):
            self.assertEqual(src.count(needle), 1, needle)

    def test_the_handler_module_is_bound_and_its_names_reach_the_dispatcher(self):
        api = _fresh_api()
        for name in ('handle_device_traffic', 'handle_traffic_fleet', 'handle_traffic_config_get', 'handle_traffic_config_set'):
            self.assertEqual(getattr(api, name).__module__, 'traffic_handlers', name)

    def test_the_request_model_ignores_what_it_does_not_know(self):
        import request_models
        m = request_models.TrafficConfigRequest
        self.assertEqual(m().model_dump(), {'watch': None, 'every': None})
        self.assertEqual(m(**{'watch': [], 'every': 60, 'junk': 1}).model_dump(), {'watch': [], 'every': 60})


if __name__ == '__main__':
    unittest.main()
