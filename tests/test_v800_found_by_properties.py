#!/usr/bin/env python3
"""8.0.0: what the generated properties found, kept as plain examples that CI runs too.

tests/test_v800_properties.py states promises of the new pure code and lets Hypothesis look for the input that breaks one; it is skipped where hypothesis is not installed. Each of
the defects it found is pinned here by the input it printed, so the fix does not depend on a tool CI does not have.

  * app_catalog.describe([]) raised: a list cannot be a dictionary key.
  * traffic.watched and traffic.fleet_summary raised on a stored row that is not a row, and so did the pages that read one: the SQL backends hand a record back as it was written, with no
    shape registry in between, so a host's page, the fleet's page, the Explorer and Fleet Query each answered 500 for every user until the row was deleted.
  * mcp_http: a tool that met an answer it did not expect raised out of handle() and the model's host got an HTTP 500 and no result.
  * the agent's `ss` reader trusted str.isdigit(), which is true for a superscript two (int() refuses it) and for a string of any length.
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-found-'))
_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS))
sys.path.insert(0, str(_TESTS.parent / 'server' / 'cgi-bin'))

import app_catalog  # noqa: E402
import mcp_http as M  # noqa: E402
import traffic as T  # noqa: E402
from test_v800_traffic import PUB, _Server, row, sample  # noqa: E402
from test_v800_traffic_agent import load_agent  # noqa: E402


class TestTheCatalog(unittest.TestCase):

    def test_a_value_that_is_not_an_id_is_no_app(self):
        for bad in ([], {}, None, 5, 1.5, True, ['jellyfin'], {'id': 'jellyfin'}):
            self.assertIsNone(app_catalog.describe(bad), repr(bad))
        self.assertEqual(app_catalog.describe('jellyfin')['id'], 'jellyfin', 'control: an id the catalog knows is still found')


class TestTheReadersOfAStoredSample(unittest.TestCase):
    DAMAGED = {'win': 60, 'tx': 'lots', 'rx': None, 'conns': [1], 'rows': [
        {'d': 'in', 'ip': '', 'port': 0, 'proc': [None], 'n': 0, 'tx': 0, 'rx': 0},        # what Hypothesis printed: a program that is a list
        'junk', None, 5, {}, {'d': 'sideways', 'ip': '8.8.8.8', 'port': 53, 'proc': '', 'n': 1, 'tx': 1, 'rx': 1},
        {'d': 'out', 'ip': '8.8.8.8', 'port': '53', 'proc': '', 'n': 1, 'tx': 1, 'rx': 1}, {'d': 'out', 'ip': '8.8.8.8', 'port': 53, 'proc': '', 'n': 1, 'tx': -1, 'rx': 1},
        {'d': 'out', 'ip': '9.9.9.9', 'port': 443, 'proc': 'curl', 'n': 2, 'tx': 7, 'rx': 9}]}

    def test_a_row_that_is_not_a_row_is_left_out_and_the_others_are_read(self):
        got = T.stored_rows(self.DAMAGED)
        self.assertEqual([(r['ip'], r['port']) for r in got], [('9.9.9.9', 443)])
        for bad in (None, 'x', [], {'rows': 'x'}, {'rows': None}):
            self.assertEqual(T.stored_rows(bad), [])

    def test_a_count_that_is_not_a_count_is_zero(self):
        self.assertEqual([T.num(v) for v in (5, 0, -1, True, 1.5, 'x', None, [1])], [5, 0, 0, 0, 0, 0, 0, 0])

    def test_a_match_against_what_is_not_a_row_or_not_an_entry_is_no_match(self):
        entry = {'kind': 'port', 'value': '443', 'label': ''}
        self.assertEqual(T.watched({}, [None]), [])
        self.assertEqual(T.watched('x', [entry]), [])
        self.assertEqual(T.watched({'port': 443, 'proc': ['x'], 'ip': ['y']}, [entry, 5, None, {'kind': 'proc', 'value': 'z'}]), [entry], 'a program that is a list is no program')
        self.assertEqual(T.watched({'port': 1}, 'not a list'), [])

    def test_the_fleet_adds_up_a_damaged_sample_without_raising_and_counts_only_what_it_can_read(self):
        out = T.fleet_summary([('h1', 'a', self.DAMAGED), ('h2', 'b', {'rows': 'x', 'tx': 5})], top=10)
        self.assertEqual([r['ip'] for r in out['remotes']], ['9.9.9.9'])
        self.assertEqual(out['totals'], {'tx': 5, 'rx': 0, 'conns': 0, 'hosts': 2})


class TestThePagesWithADamagedStore(_Server):

    def setUp(self):
        super().setUp()
        self.beat(traffic=sample([row(proc='curl'), row(ip='8.8.8.8', port=53)]))
        rec = self.stored()
        rec['sample']['rows'] = TestTheReadersOfAStoredSample.DAMAGED['rows'] + rec['sample']['rows']
        rec['sample']['tx'], rec['sample']['win'] = 'lots', 'long'
        rec['series'] = [[1, 2, 3, 4], ['x', 1, 2, 3], 'junk', [1, 2]]
        self.api._entity_write_one(self.api.TRAFFIC_FILE, 'web01', rec)

    def test_a_hosts_page_shows_the_rows_that_are_rows(self):
        got = self.host()
        self.assertEqual(sorted((r['ip'], r['port']) for r in got['rows']), sorted([(PUB, 443), ('8.8.8.8', 53), ('9.9.9.9', 443)]))
        self.assertEqual((got['tx'], got['win']), (0, 1.0), 'a total that is not a number is zero, a window that is not one is a second')
        self.assertEqual(got['series'], [[1, 2, 3, 4]], 'and the chart keeps the points that are points')

    def test_the_fleets_page_adds_up_what_it_can_read(self):
        got = self.fleet()
        self.assertEqual(got['by_state']['reporting'], 1)
        self.assertIn(PUB, [r['ip'] for r in got['remotes']])
        self.assertEqual({h['id']: h['tx_rate'] for h in got['hosts'] if h['state'] == 'reporting'}, {'web01': 0})

    def test_the_explorer_and_fleet_query_read_the_same_rows(self):
        st, out = self.request('/api/query', 'POST', body={'entity': 'traffic'})
        self.assertEqual(st, 200, out)
        self.assertEqual(sorted(r['address'] for r in out['rows']), sorted([PUB, '8.8.8.8', '9.9.9.9']))
        st, out = self.request('/api/fleet/query', query='talks=curl')
        self.assertEqual((st, [d['name'] for d in out['devices']]), (200, ['web01']))


class TestTheMcpEndpoint(unittest.TestCase):

    def call(self, name, upstream):
        def fetch(path, method='GET', body=None):
            if isinstance(upstream, M.FetchError):
                raise upstream
            return upstream
        return M.handle({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {'name': name, 'arguments': {}}}, fetch, '8.0.0')

    def test_a_tool_that_meets_an_answer_it_did_not_expect_is_a_failed_call_and_not_an_exception(self):
        for upstream in ('text', 5):
            status, answer = self.call('list_alerts', upstream)
            self.assertEqual(status, 200, repr(upstream))
            self.assertTrue(answer['result']['isError'], repr(upstream))
            self.assertIn('could not read the answer', answer['result']['content'][0]['text'])
            self.assertNotIn('Traceback', json.dumps(answer))

    def test_an_answer_of_another_shape_that_a_tool_can_read_is_still_read(self):
        for upstream in ([], None):
            status, answer = self.call('list_alerts', upstream)
            self.assertEqual((status, answer['result']['isError']), (200, False), repr(upstream))

    def test_a_good_answer_and_a_refused_one_are_what_they_were(self):
        status, answer = self.call('list_alerts', M.FetchError(403, 'Forbidden'))
        self.assertEqual((status, answer['result']['isError']), (200, True))
        self.assertIn('HTTP 403', answer['result']['content'][0]['text'])


class TestTheAgentsReaderOfSs(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.agent = load_agent()

    def test_a_port_is_ascii_digits_in_a_ports_own_range(self):
        for bad in ('10.0.0.1:²', '10.0.0.1:³', '10.0.0.1:١٢', '10.0.0.1:65536', '10.0.0.1:99999', '10.0.0.1:' + '9' * 40, '10.0.0.1:', '10.0.0.1:-1', '10.0.0.1:+1'):
            self.assertIsNone(self.agent._ss_ip_port(bad), bad)
            self.assertIsNone(self.agent._ss_port(bad), bad)
        self.assertEqual(self.agent._ss_ip_port('10.0.0.1:65535'), ('10.0.0.1', 65535))
        self.assertEqual(self.agent._ss_port('*:22'), 22)
        self.assertEqual(self.agent._ss_port('[::]:0'), 0)

    def test_a_line_with_such_a_port_is_skipped_and_the_next_socket_is_read(self):
        text = '0 0 10.0.0.1:² 203.0.113.7:443\n0 0 10.0.0.1:1000 203.0.113.7:80\n\t cubic bytes_acked:5 bytes_received:6\n'
        self.assertEqual(self.agent._ss_sockets(text)[0], [('10.0.0.1', 1000, '203.0.113.7', 80, '', 5, 6)])


if __name__ == '__main__':
    unittest.main()
