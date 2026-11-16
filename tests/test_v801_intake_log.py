"""What the hosts sent is kept, so a missing address can be traced (8.0.1).

One address that fail2ban, CrowdSec and the WAF had all acted on was never recorded, and nothing could say whether the host had sent it, the server had
dropped it or the sweep had lost it. Now the server keeps a line for each pass a host sent that carried anything (the host, how many addresses, how many
were queued, held back or set aside, and the first few), shown beside the requests RemotePower made, and the Linux agent writes a line to its own log
each time its sensor sends addresses and a warning when a send or a pass fails. The end-to-end proof, with the agent's own thread against the real stack,
is test_6 in tests/test_v720_threat_sensor_wire.py.
"""
import copy
import logging
import os
import re
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v801-intakelog-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))
import ipintel_store  # noqa: E402
from test_v720_threat_sensor_agent import load_agent  # noqa: E402
from test_v801_provider_down import MIN, T, _Sweep, waf_event  # noqa: E402

import store_shapes  # noqa: E402


class _Intake(_Sweep):
    def post(self, events, dev='d1', status=None, at=T):
        with mock.patch('time.time', return_value=at):
            res = self.api.ip_intel_note_evidence(dev, events, dict({'sources': [], 'ignored': {}, 'dropped': 0}, **(status or {})), at)
        self.api._LOAD_CACHE.clear()
        return res

    def log(self):
        self.api._LOAD_CACHE.clear()
        return list(ipintel_store.read_intake(self.api).get('log') or [])

    def lines(self):
        st, d = self.call(self.api.handle_ip_intel)
        self.assertEqual(st, 200, d)
        return d['requests']


class TestWhatIsKept(_Intake):
    def test_a_pass_that_carried_addresses_is_a_line_with_the_first_five(self):
        evs = [waf_event('185.220.101.%d' % (10 + i)) for i in range(7)]
        res = self.post(evs)
        self.assertEqual(res, {'queued': 7, 'throttled': 0})
        (line,) = self.log()
        self.assertEqual((line['device_id'], line['n'], line['queued'], line['throttled'], line['at']), ('d1', 7, 7, 0, T))
        self.assertEqual(line['ips'], ['185.220.101.%d' % (10 + i) for i in range(5)])

    def test_what_the_endpoint_set_aside_and_what_the_host_left_out_are_in_it(self):
        self.post([waf_event('185.220.101.10')], status={'ignored': {'cloudflare': 2, 'invalid': 1}, 'dropped': 4})
        (line,) = self.log()
        self.assertEqual((line['ignored'], line['dropped']), ({'cloudflare': 2, 'invalid': 1}, 4))

    def test_a_pass_that_carried_only_things_set_aside_is_still_a_line(self):
        self.post([], status={'ignored': {'cloudflare': 1, 'invalid': 1}})
        (line,) = self.log()
        self.assertEqual((line['n'], line['queued'], line['ips']), (0, 0, []))

    def test_a_status_with_nothing_in_it_is_not_a_line(self):
        self.post([], status={'sources': [{'kind': 'web', 'path': '/x', 'state': 'ok'}]})
        self.assertEqual(self.log(), [])

    def test_the_hourly_limit_is_said(self):
        with mock.patch.object(self.api.ip_intel_handlers_mod, 'SENSOR_EVENTS_PER_HOUR', 2):
            res = self.post([waf_event('185.220.101.%d' % (10 + i)) for i in range(5)])
        self.assertEqual(res, {'queued': 2, 'throttled': 3})
        (line,) = self.log()
        self.assertEqual((line['queued'], line['throttled']), (2, 3))

    def test_the_edge_feeds_are_not_hosts_and_leave_no_line(self):
        self.post([waf_event('185.220.101.10')], dev='edge:cloudflare')
        self.assertEqual(self.log(), [])

    def test_it_keeps_the_most_recent(self):
        keep = self.api.ip_intel_handlers_mod.INTAKE_LOG_KEEP
        for i in range(keep + 25):
            self.post([waf_event('185.220.%d.%d' % (i // 200, i % 200 + 1))], at=T + i)
        log = self.log()
        self.assertEqual(len(log), keep)
        self.assertEqual(log[-1]['at'], T + keep + 24)

    def test_the_stored_document_keeps_its_shape(self):
        store_shapes.drain_dropped()
        self.post([waf_event('185.220.101.10')])
        doc = copy.deepcopy(ipintel_store.read_intake(self.api))
        fixed = store_shapes.normalize('ip_intel_intake.json', copy.deepcopy(doc))
        self.assertEqual(fixed['log'], doc['log'])
        self.assertEqual(store_shapes.drain_dropped(), [])


def hostile(floats=True):
    """Rows a damaged or hand-edited store could hold: not maps, and maps whose fields are of the wrong kind."""
    bad = float('nan') if floats else 'nan'
    big = float('inf') if floats else 'inf'
    return ['junk', 5, None, ['x'],
            {'at': 'x', 'n': [], 'queued': {}, 'throttled': 'many', 'dropped': bad, 'ignored': [1], 'ips': 'abc', 'device_id': ['d1']},
            {'at': big, 'n': 3, 'queued': 2, 'ignored': {'cloudflare': big, 'x': 'y', 'k': bad}, 'ips': [1, None, '185.220.101.10'], 'device_id': {'a': 1}},
            {'at': T, 'device_id': 'd1', 'n': 1, 'queued': 1, 'throttled': 0, 'ignored': {}, 'dropped': 0, 'ips': ['185.220.101.99']}]


class TestADamagedLog(_Intake):
    """Two layers, each shown failing on its own: the view reads what it is handed with defaults, and the registry repairs the
    document where it is read, so a row of the wrong kind never reaches a reader that converts it."""

    def setUp(self):
        super().setUp()
        store_shapes.drain_dropped()
        self.addCleanup(store_shapes.drain_dropped)

    def test_the_view_does_not_raise_on_what_a_damaged_store_holds(self):
        mod = self.api.ip_intel_handlers_mod
        lines = mod._intake_log_view({'log': hostile()}, {'d1': 'web01'})
        self.assertEqual(len(lines), 3, 'the three rows that are maps; the others are not rows')
        (good,) = [r for r in lines if r['ip'] == '185.220.101.99']
        self.assertEqual((good['prov'], good['at'], good['note']), ('web01', T, 'queued 1 of 1: 185.220.101.99'))
        for not_a_list in ('junk', 5, None, {'a': 1}):
            self.assertEqual(mod._intake_log_view({'log': not_a_list}, {}), [])

    def test_the_registry_repairs_the_document_where_it_is_read(self):
        fixed = store_shapes.normalize('ip_intel_intake.json', {'queue': [], 'sensors': {}, 'cursors': {}, 'log': hostile()})
        rows = fixed['log']
        self.assertEqual(len(rows), 3, 'what is not a map is left out')
        for row in rows:
            for key in ('at', 'n', 'queued', 'throttled', 'dropped'):
                if key in row:
                    self.assertTrue(isinstance(row[key], (int, float)) and row[key] == row[key] and abs(row[key]) != float('inf'), (key, row))
            self.assertIsInstance(row.get('ignored', {}), dict)
            self.assertIsInstance(row.get('ips', []), list)
            self.assertIsInstance(row.get('device_id', ''), str)
        self.assertEqual(store_shapes.normalize('ip_intel_intake.json', {'log': 'garbage'})['log'], [])
        self.assertEqual(store_shapes.normalize('ip_intel_intake.json', {'log': {'a': 1}})['log'], [])

    def test_the_page_loads_with_a_damaged_log_in_the_store(self):
        self.api.save(self.api.IPINTEL_INTAKE_FILE, {'adopted': True, 'queue': [], 'sensors': {}, 'cursors': {}, 'log': hostile(floats=False)})
        self.api._LOAD_CACHE.clear()
        st, d = self.call(self.api.handle_ip_intel)
        self.assertEqual(st, 200, d)
        got = [r for r in d['requests'] if r['op'] == 'received']
        self.assertEqual(len(got), 3)
        self.assertEqual(got[0]['ip'], '185.220.101.99', 'the row that is whole is the newest and leads')


class TestDeletingAHost(_Intake):
    def test_its_lines_go_with_it_and_the_others_stay(self):
        import host_purge
        self.post([waf_event('185.220.101.10')], dev='d1', at=T)
        self.post([waf_event('185.220.101.11')], dev='d2', at=T + 1)
        self.post([waf_event('185.220.101.12')], dev='d1', at=T + 2)
        doc = ipintel_store.read_intake(self.api)
        self.assertEqual([r['device_id'] for r in doc['log']], ['d1', 'd2', 'd1'])
        self.assertEqual(host_purge.apply('ip_intel_intake.json', doc, 'd1'), 3, 'its two lines and its sensor record')
        self.assertEqual([(r['device_id'], r['ips']) for r in doc['log']], [('d2', ['185.220.101.11'])])
        self.assertNotIn('d1', doc['sensors'])


class TestWhatThePageIsSent(_Intake):
    def setUp(self):
        super().setUp()
        self.sniff_report = None
        self.policy(report_enabled=True, lookup_enabled=True, block_enabled=False)

    def test_a_received_line_has_the_shape_of_a_request_line_and_names_the_host(self):
        self.post([waf_event('185.220.101.10'), waf_event('185.220.101.11')], at=T)
        (line,) = [r for r in self.lines() if r['op'] == 'received']
        self.assertEqual((line['prov'], line['ip'], line['status'], line['ms'], line['result']),
                         ('web01', '185.220.101.10', 200, 0, 'ok'))
        self.assertEqual(line['note'], 'queued 2 of 2: 185.220.101.10, 185.220.101.11')
        self.assertEqual(set(line), {'at', 'prov', 'op', 'ip', 'status', 'ms', 'result', 'note'})

    def test_what_was_not_queued_says_why_and_is_a_refusal(self):
        with mock.patch.object(self.api.ip_intel_handlers_mod, 'SENSOR_EVENTS_PER_HOUR', 0):
            self.post([waf_event('185.220.101.10')], status={'ignored': {'cloudflare': 1}, 'dropped': 3})
        (line,) = [r for r in self.lines() if r['op'] == 'received']
        self.assertEqual(line['result'], 'refused')
        self.assertEqual(line['note'], "queued 0 of 1, 1 held back by the hour's limit, 1 set aside, 3 left out by the host: 185.220.101.10")

    def test_it_is_in_one_list_with_the_requests_made_newest_first(self):
        ipintel_store.update(self.api, reqlog=[
            {'at': T + 60, 'prov': 'abuseipdb', 'op': 'check', 'ip': '185.220.101.10', 'status': 200, 'ms': 90, 'result': 'ok', 'note': ''},
            {'at': T + 61, 'prov': 'sniffcat', 'op': 'report', 'ip': '185.220.101.10', 'status': 500, 'ms': 40, 'result': 'server error', 'note': 'x'}])
        self.post([waf_event('185.220.101.11')], at=T)             # older than both requests
        self.post([waf_event('185.220.101.99')], at=T + 5 * MIN)   # newer than both
        got = self.lines()
        self.assertEqual([r['op'] for r in got], ['received', 'report', 'check', 'received'])
        self.assertEqual([r['at'] for r in got], [T + 5 * MIN, T + 61, T + 60, T])

    def test_only_the_operator_is_sent_it(self):
        self.post([waf_event('185.220.101.10')])
        st, d = self.call(self.api.handle_ip_intel, role='viewer')
        self.assertEqual(st, 200)
        self.assertIsNone(d['requests'])
        self.assertNotIn('185.220.101.10', str({k: v for k, v in d.items() if k not in ('attackers', 'blocks')}))

    def test_clearing_the_table_leaves_it(self):
        self.post([waf_event('185.220.101.10')])
        before = self.log()
        st, d = self.call(self.api.handle_ip_intel_clear, 'POST', {})
        self.assertEqual(st, 200, d)
        self.assertEqual(self.log(), before)


class TestTheAgentSaysWhatItSent(unittest.TestCase):
    """The sensor thread, with the collector and the post replaced by stubs: only what it logs is under test."""

    @classmethod
    def setUpClass(cls):
        cls.agent = load_agent('agent_v801_log')

    def run_thread(self, passes, submit, collect=None):
        """Run the real thread until `passes` passes have gone by; return its log records."""
        agent = self.agent
        records = []
        handler = logging.Handler()
        handler.emit = records.append
        agent.log.addHandler(handler)
        previous = agent.log.level
        agent.log.setLevel(logging.DEBUG)
        stop, seen = threading.Event(), []
        real_wait, self.waits = stop.wait, []

        def recording_wait(timeout=None):
            self.waits.append(timeout)
            return real_wait(timeout)
        stop.wait = recording_wait

        def collector(cfg, state, now=None, budget_s=None):
            seen.append(1)
            if len(seen) >= passes:
                stop.set()
            return collect(len(seen)) if collect else ([], [{'kind': 'web', 'path': '/x', 'state': 'ok'}], 0, dict(state))
        patches = [mock.patch.object(agent, 'collect_threat_events', collector), mock.patch.object(agent, '_ts_submit', submit),
                   mock.patch.object(agent, '_ts_state_load', lambda: {}), mock.patch.object(agent, '_ts_state_save', lambda s: None)]
        try:
            for p in patches:
                p.start()
            t = threading.Thread(target=agent._threat_sensor_thread, args=({'server_url': 'x', 'device_id': 'd', 'token': 't'},
                                                                           {'cfg': {'enabled': True}}, stop, 0.01, 0), daemon=True)
            t.start()
            t.join(timeout=20)
            self.assertFalse(t.is_alive(), 'the thread did not stop')
        finally:
            for p in patches:
                p.stop()
            agent.log.removeHandler(handler)
            agent.log.setLevel(previous)
        return [(r.levelname, r.getMessage()) for r in records if 'threat sensor' in r.getMessage()]

    def events(self, n):
        return [{'ip': '185.220.101.%d' % (10 + i), 'src': {'waf': 1}} for i in range(n)]

    def test_it_says_how_many_addresses_and_what_became_of_the_post(self):
        out = self.run_thread(1, lambda *a: 'ok', lambda n: (self.events(2), [{'kind': 'waf', 'path': '/x', 'state': 'ok'}], 0, {}))
        self.assertIn(('INFO', 'threat sensor: 2 addresses sent (ok): 185.220.101.10, 185.220.101.11'), out)

    def test_it_names_three_and_counts_the_rest_and_says_one_in_the_singular(self):
        out = self.run_thread(1, lambda *a: 'ok', lambda n: (self.events(5), [{'kind': 'waf', 'path': '/x', 'state': 'ok'}], 0, {}))
        self.assertIn(('INFO', 'threat sensor: 5 addresses sent (ok): 185.220.101.10, 185.220.101.11, 185.220.101.12 and 2 more'), out)
        out = self.run_thread(1, lambda *a: 'ok', lambda n: (self.events(1), [{'kind': 'waf', 'path': '/x', 'state': 'ok'}], 0, {}))
        self.assertIn(('INFO', 'threat sensor: 1 address sent (ok): 185.220.101.10'), out)

    def test_a_post_that_will_be_tried_again_or_dropped_says_so(self):
        for outcome in ('retry', 'drop'):
            out = self.run_thread(1, lambda *a, o=outcome: o, lambda n: (self.events(1), [{'kind': 'waf', 'path': '/x', 'state': 'ok'}], 0, {}))
            self.assertIn(('INFO', 'threat sensor: 1 address sent (%s): 185.220.101.10' % outcome), out)

    def test_a_pass_with_no_addresses_says_nothing_about_sending(self):
        out = self.run_thread(2, lambda *a: 'ok')
        self.assertEqual([m for lvl, m in out if 'sent (' in m], [])

    def test_a_pass_that_fails_is_a_warning_with_its_wait_and_its_cause(self):
        def boom(n):
            raise OSError('disk went away')
        out = self.run_thread(2, lambda *a: 'ok', boom)
        warn = [m for lvl, m in out if lvl == 'WARNING']
        self.assertEqual(len(warn), 2, out)
        pattern = r'^threat sensor: pass failed, waiting ([\d.]+) s: OSError: disk went away$'
        first, second = re.match(pattern, warn[0]), re.match(pattern, warn[1])
        self.assertTrue(first and second, warn)
        self.assertEqual(float(first.group(1)), self.waits[1], 'the line gives the wait the thread then took, not another number')
        self.assertGreater(float(second.group(1)), float(first.group(1)), 'a second failure in a row waits longer')

    def test_a_send_that_could_not_reach_the_server_is_a_warning_not_a_debug_line(self):
        agent = self.agent
        records = []
        handler = logging.Handler()
        handler.emit = records.append
        agent.log.addHandler(handler)
        previous = agent.log.level
        agent.log.setLevel(logging.DEBUG)
        try:
            with mock.patch.object(agent, 'http_post', side_effect=OSError('unreachable')):
                outcome = agent._ts_submit({'server_url': 'https://x', 'device_id': 'd', 'token': 't'}, self.events(1), [], 0, 1)
        finally:
            agent.log.removeHandler(handler)
            agent.log.setLevel(previous)
        self.assertEqual(outcome, 'retry')
        got = [(r.levelname, r.getMessage()) for r in records]
        self.assertEqual(got, [('WARNING', 'threat sensor: submission failed, trying again: OSError: unreachable')])


if __name__ == '__main__':
    unittest.main()
