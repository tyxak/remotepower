"""The log of requests RemotePower sends to AbuseIPDB and SniffCat (8.0.1).

Asked for after a day when SniffCat answered every report with an HTTP 500: the page said "the daily report limit is used
up" and nothing said what the service had been asked or had answered. Each request to the two services is logged with the
address, the HTTP status, the time it took and the service's own sentence, and the operator's Threat Intel page shows the
last of them. The key, the headers and the body of a request are never in it.

These tests send the real requests through the real function and the real sweep; only the socket is replaced.
"""
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v801-reqlog-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))
import ipintel_store  # noqa: E402
from test_ip_intel import _Case  # noqa: E402
from test_v730_edge_blocklist_sync import _Lists  # noqa: E402
from test_v801_provider_down import DOWN_500, T, MIN, waf_event  # noqa: E402

import ip_intel  # noqa: E402

KEY_A, KEY_S = 'a' * 80, 's' * 40


class _Resp:
    def __init__(self, status, body):
        self.status, self._body = status, body

    def read(self, n=-1):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _Opener:
    """What the SSRF-guarded opener is replaced with: answers by URL, and raises what urllib raises."""
    def __init__(self, answers):
        self.answers, self.seen = answers, []

    def open(self, req, timeout=None):
        self.seen.append(req)
        a = self.answers(req.full_url, req.get_method())
        if isinstance(a, BaseException):
            raise a
        return _Resp(*a)


def http_error(status, body):
    return urllib.error.HTTPError('https://x', status, 'x', {}, io.BytesIO(json.dumps(body).encode()))


class TestWhatAnAnswerCameTo(unittest.TestCase):
    def test_each_answer_is_named_in_the_pages_words(self):
        cases = [
            ((0, {'message': 'unreachable: TimeoutError'}), ('no answer', 'unreachable: TimeoutError')),
            ((200, {'data': {}}), ('ok', '')),
            ((200, {'success': False, 'message': 'Nope'}), ('refused', 'Nope')),
            ((429, {'errors': [{'detail': 'You can only report the same IP once in 15 minutes.'}]}),
             ('already reported', 'You can only report the same IP once in 15 minutes.')),
            ((429, {'message': 'Too many requests'}), ('rate limited', 'Too many requests')),
            ((401, {'errors': [{'detail': 'Authentication failed.'}]}), ('key rejected', 'Authentication failed.')),
            ((403, {'message': 'Forbidden'}), ('refused', 'Forbidden')),
            ((500, {'message': 'Internal server error.'}), ('server error', 'Internal server error.')),
            ((503, None), ('server error', '')),
            ((404, {'message': 'Not found'}), ('HTTP 404', 'Not found')),
        ]
        for (status, body), want in cases:
            self.assertEqual(ip_intel.describe_answer(status, body), want, (status, body))

    def test_the_sentence_is_cut_and_cleaned(self):
        r, note = ip_intel.describe_answer(500, {'message': 'x' * 400 + '\x00\x1b'})
        self.assertEqual(len(note), 160)
        self.assertTrue(note.isprintable())


class _Real(_Case):
    """The real request function, and a socket that answers by script."""
    def setUp(self):
        super().setUp()
        api = self.api
        self.mod = api.ip_intel_handlers_mod
        self.mod._REQLOG_PENDING.clear()
        self.sniff_report = None
        self.answers = self._answers
        self.opener = _Opener(lambda url, method: self.answers(url, method))
        api._ssrf_safe_opener = lambda **kw: self.opener
        api._ip_intel_http = self.mod._ip_intel_http
        cfg = api.load(api.CONFIG_FILE)
        cfg['abuseipdb_api_key'], cfg['sniffcat_api_key'] = KEY_A, KEY_S
        api.save(api.CONFIG_FILE, cfg)
        self.policy(lookup_enabled=True, report_enabled=True, block_enabled=False, report_waf_after=1)
        api._LOAD_CACHE.clear()

    def _answers(self, url, method):
        if 'sniffcat' in url and method == 'POST' and self.sniff_report is not None:
            return http_error(*self.sniff_report)
        if method == 'POST':
            return 200, json.dumps({'success': True, 'data': {}}).encode()
        if 'abuseipdb' in url:
            return 200, json.dumps({'data': {'abuseConfidenceScore': 10, 'totalReports': 1,
                                             'countryCode': 'DE', 'isp': 'X'}}).encode()
        return 200, json.dumps({'success': True, 'status': 200, 'abuseConfidenceScore': 10}).encode()

    def call(self, fn, method='GET', body=None, role='admin'):
        api = self.api
        api.verify_token = lambda _t=None: ('alice', role)
        api.method = lambda: method
        api.get_json_obj = lambda: dict(body or {})
        self.cap.clear()
        try:
            fn()
        except api.HTTPError:
            pass
        api._LOAD_CACHE.clear()
        return self.cap.get('status'), self.cap.get('data') or {}

    def sweep_at(self, at):
        ipintel_store.update(self.api, last_sweep=0)
        with mock.patch('time.time', return_value=at):
            self.api.run_ip_intel_if_due()
        self.api._LOAD_CACHE.clear()
        return ipintel_store.read(self.api)

    def queue(self, n, start=0, now=T):
        events = [waf_event('185.220.101.%d' % (10 + start + i), now) for i in range(n)]
        with mock.patch('time.time', return_value=now):
            self.api.ip_intel_note_evidence('d1', events, {'sources': [], 'ignored': {}, 'dropped': 0}, now)
        self.api._LOAD_CACHE.clear()


class TestWhatIsLogged(_Real):
    def test_a_lookup_and_a_report_are_logged_with_the_address_and_the_answer(self):
        self.queue(1)
        st = self.sweep_at(T + MIN)
        rows = st['reqlog']
        self.assertEqual({(r['prov'], r['op']) for r in rows},
                         {('abuseipdb', 'check'), ('sniffcat', 'check'), ('abuseipdb', 'report'), ('sniffcat', 'report')})
        for r in rows:
            self.assertEqual((r['ip'], r['status'], r['result']), ('185.220.101.10', 200, 'ok'), r)
            self.assertIsInstance(r['ms'], int)
            self.assertGreater(r['at'], 0)

    def test_a_failure_says_what_the_service_said(self):
        self.sniff_report = DOWN_500
        self.queue(1)
        rows = [r for r in self.sweep_at(T + MIN)['reqlog'] if (r['prov'], r['op']) == ('sniffcat', 'report')]
        self.assertEqual([(r['status'], r['result']) for r in rows], [(500, 'server error')])
        self.assertIn('Internal server error', rows[0]['note'])

    def test_a_network_failure_is_logged_as_no_answer(self):
        self.answers = lambda url, method: (urllib.error.URLError('timed out') if 'sniffcat' in url and method == 'POST'
                                            else self._answers(url, method))
        self.queue(1)
        rows = [r for r in self.sweep_at(T + MIN)['reqlog'] if (r['prov'], r['op']) == ('sniffcat', 'report')]
        self.assertEqual([(r['status'], r['result'], r['note']) for r in rows], [(0, 'no answer', 'unreachable: URLError')])

    def test_no_key_header_or_body_is_in_the_log(self):
        self.queue(2)
        st = self.sweep_at(T + MIN)
        text = json.dumps(st['reqlog'])
        for secret in (KEY_A, KEY_S, 'categories', 'comment', 'X-Secret-Token', 'Key'):
            self.assertNotIn(secret, text)
        self.assertEqual(set(st['reqlog'][0]), {'at', 'prov', 'op', 'ip', 'status', 'ms', 'result', 'note'})

    def test_cloudflare_is_not_in_it(self):
        self.mod._ip_intel_http({'method': 'GET', 'url': 'https://api.cloudflare.com/client/v4/accounts/a/rules/lists',
                                 'headers': {'Authorization': 'Bearer secret'}, 'body': None})
        self.assertEqual(self.mod._REQLOG_PENDING, [])

    def test_a_log_line_that_cannot_be_made_does_not_fail_the_request(self):
        with mock.patch.object(self.mod, '_reqlog_note', side_effect=RuntimeError('boom')):
            status, body = self.mod._ip_intel_http(ip_intel.abuseipdb_check_request('185.220.101.10', KEY_A))
        self.assertEqual(status, 200)

    def test_it_is_kept_to_the_most_recent(self):
        for i in range(self.mod.REQLOG_KEEP + 50):
            self.mod._ip_intel_http(ip_intel.sniffcat_check_request('185.220.%d.%d' % (i // 200, i % 200 + 1), KEY_S))
        self.assertEqual(len(self.mod._REQLOG_PENDING), self.mod.REQLOG_KEEP)
        st = {}
        self.mod._reqlog_flush(st)
        self.assertEqual(len(st['reqlog']), self.mod.REQLOG_KEEP)
        self.assertEqual(self.mod._REQLOG_PENDING, [])
        self.mod._ip_intel_http(ip_intel.sniffcat_check_request('185.221.0.1', KEY_S))
        self.mod._reqlog_flush(st)
        self.assertEqual(len(st['reqlog']), self.mod.REQLOG_KEEP)
        self.assertEqual(st['reqlog'][-1]['ip'], '185.221.0.1')

    def test_the_manual_lookup_is_logged(self):
        st, d = self.call(self.api.handle_ip_intel_lookup, 'POST', {'ip': '185.220.101.77'})
        self.assertEqual(st, 200, d)
        rows = ipintel_store.read(self.api)['reqlog']
        self.assertEqual({(r['prov'], r['op'], r['ip']) for r in rows},
                         {('abuseipdb', 'check', '185.220.101.77'), ('sniffcat', 'check', '185.220.101.77')})


class TestWhoSeesIt(_Real):
    def setUp(self):
        super().setUp()
        self.queue(2)
        self.sweep_at(T + MIN)

    def test_the_operator_gets_it_newest_first(self):
        st, d = self.call(self.api.handle_ip_intel)
        self.assertEqual(st, 200, d)
        rows = d['requests']
        self.assertEqual(len(rows), 8)
        self.assertEqual([r['at'] for r in rows], sorted((r['at'] for r in rows), reverse=True))

    def test_nobody_else_does(self):
        st, d = self.call(self.api.handle_ip_intel, role='viewer')
        self.assertEqual(st, 200)
        self.assertIsNone(d['requests'])
        self.assertNotIn('185.220.101', json.dumps({k: v for k, v in d.items() if k not in ('attackers', 'blocks')}))

    def test_clearing_the_table_leaves_it(self):
        before = ipintel_store.read(self.api)['reqlog']
        st, d = self.call(self.api.handle_ip_intel_clear, 'POST', {})
        self.assertEqual(st, 200, d)
        self.assertEqual(ipintel_store.read(self.api)['reqlog'], before)


class TestBlocklistDownloadsAreLogged(_Lists):
    def test_a_download_is_a_line(self):
        api = self.api
        mod = api.ip_intel_handlers_mod
        mod._REQLOG_PENDING.clear()
        router = api._ip_intel_http
        mod._ip_intel_http_send = lambda req: router(req)
        api._ip_intel_http = mod._ip_intel_http
        self.policy(edgelist_abuseipdb=True, edgelist_sniffcat=True)
        cfg = api.load(api.CONFIG_FILE)
        cfg['abuseipdb_api_key'], cfg['sniffcat_api_key'] = KEY_A, KEY_S
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()
        self.tick(at=T)
        rows = ipintel_store.read(api).get('reqlog') or []
        self.assertEqual({(r['prov'], r['op'], r['status']) for r in rows},
                         {('abuseipdb', 'blacklist', 200), ('sniffcat', 'blacklist', 200)})
        self.assertTrue(all(r['ip'] == '' for r in rows))


if __name__ == '__main__':
    unittest.main()
