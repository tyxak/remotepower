#!/usr/bin/env python3
"""v7.3.0: a feed that cannot be read and a list sync that waits for a person say so.

Both stop the reporting and the blocklist without a word. The cause is a token or
a plan, not a host, so no host alert, check or page carried it: the Threat intel
card showed a red state to someone who had to be looking.

Driven for real, through `fire_webhook` -> `_record_alert` -> `_auto_resolve_alerts`,
because a hand-built payload skips the whitelist and the identity rules that make
an alert open, coalesce and close. The two things asked of every one of them:
it fires on the TRANSITION only (never once per poll), and the recover closes the
alert that was opened (and only that one).
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v730-health-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))

import edge_blocklist as eb  # noqa: E402
from test_v730_edge_blocklist_sync import T as LT, _Lists, ips  # noqa: E402
from test_v730_edge_intel import T as ET, _Edge  # noqa: E402


def _alerts(api, event=None):
    api._LOAD_CACHE.clear()
    rows = (api.load(api.ALERTS_FILE) or {}).get('alerts') or []
    out = [dict(a, status='resolved' if a.get('resolved_at') else 'open')
           for a in rows if event is None or a.get('event') == event]
    return out


class _Counting:
    """Count what is handed to fire_webhook while still running the real thing."""

    def install(self, api, real):
        """`real` is the genuine fire_webhook: the shared test case stubs it out."""
        self.sent = []

        def wrapped(event, payload=None, *a, **k):
            if event.startswith('edge_'):
                self.sent.append((event, dict(payload or {})))
            return real(event, payload, *a, **k)
        api.fire_webhook = wrapped
        # the handler modules reach it as A.fire_webhook, which is this attribute
        return self


class TestTheFeed(_Edge):
    def setUp(self):
        super().setUp()
        self.count = _Counting().install(self.api, self.real_fire_webhook)
        self.refuse_all = {'/graphql': (403, {'success': False, 'errors': [
            {'code': 10000, 'message': 'Authentication error'}]})}

    def _fail(self):
        self.refuse.update(self.refuse_all)

    def _mend(self):
        for k in self.refuse_all:
            self.refuse.pop(k, None)

    def test_one_failed_read_says_nothing_two_say_it_once(self):
        self._fail()
        self.poll(at=ET)
        self.assertEqual(self.count.sent, [], 'one bad read can be a bad minute at Cloudflare')
        self.poll(at=ET + 700)
        self.assertEqual([e for e, _ in self.count.sent], ['edge_feed_down'])
        self.poll(at=ET + 1400)
        self.poll(at=ET + 2100)
        self.assertEqual([e for e, _ in self.count.sent], ['edge_feed_down'],
                         'a feed that stays down is one alert, not one per poll')
        rows = _alerts(self.api, 'edge_feed_down')
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['status'], 'open')
        self.assertEqual(rows[0]['severity'], 'medium')
        self.assertIn('Cloudflare firewall events', rows[0]['title'])
        self.assertIn('token was refused', rows[0]['title'])

    def test_it_comes_back_and_the_alert_closes(self):
        self._fail()
        self.poll(at=ET)
        self.poll(at=ET + 700)
        self._mend()
        self.poll(at=ET + 1400)
        self.assertEqual([e for e, _ in self.count.sent], ['edge_feed_down', 'edge_feed_recovered'])
        self.assertEqual(_alerts(self.api, 'edge_feed_down')[0]['status'], 'resolved')

    def test_the_two_feeds_are_separate_alerts_and_close_separately(self):
        self._fail()
        self.refuse['/telemetry/'] = (0, {'message': 'unreachable: URLError'})
        self.poll(at=ET)
        self.poll(at=ET + 700)
        down = _alerts(self.api, 'edge_feed_down')
        self.assertEqual(len(down), 2, [a['title'] for a in down])
        self.assertEqual({a['status'] for a in down}, {'open'})
        # only Cloudflare is mended; the honeypot's alert must stay open
        self._mend()
        self.poll(at=ET + 1400)
        by_title = {('Cloudflare' in a['title']): a['status'] for a in _alerts(self.api, 'edge_feed_down')}
        self.assertEqual(by_title, {True: 'resolved', False: 'open'})

    def test_switching_a_feed_off_closes_its_alert(self):
        self._fail()
        self.poll(at=ET)
        self.poll(at=ET + 700)
        self.assertEqual(_alerts(self.api, 'edge_feed_down')[0]['status'], 'open')
        self.policy(edge_cf_events=False)
        self.poll(at=ET + 1400)
        self.assertEqual(_alerts(self.api, 'edge_feed_down')[0]['status'], 'resolved',
                         'an alert about a feed nobody reads any more would stay open for ever')

    def test_a_healthy_feed_fires_nothing(self):
        for i in range(3):
            self.poll(at=ET + i * 700)
        self.assertEqual(self.count.sent, [])


class TestTheList(_Lists):
    def setUp(self):
        super().setUp()
        self.count = _Counting().install(self.api, self.real_fire_webhook)
        cfg = self.api.load(self.api.CONFIG_FILE)
        cfg['abuseipdb_api_key'] = 'a' * 80
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.policy(edgelist_abuseipdb=True, edgelist_sniffcat=False)
        self.api._LOAD_CACHE.clear()
        self.big = ips('185.230', 1000)
        self.lid = self.new_list(description=eb.description('7.3.0', ['abuseipdb']), items=self.big)

    def test_a_held_sync_is_announced_once_and_closed_when_it_goes_through(self):
        self.abuse = self.big[:100]
        self.assertEqual(self.tick()['last']['state'], 'held')
        self.assertEqual([e for e, _ in self.count.sent], ['edge_list_held'])
        self.assertIn('shrink by more than half', self.count.sent[0][1]['detail'])
        self.tick(at=LT + 7 * 3600)
        self.assertEqual([e for e, _ in self.count.sent], ['edge_list_held'],
                         'still held is the same alert, not another one')
        rows = _alerts(self.api, 'edge_list_held')
        self.assertEqual((len(rows), rows[0]['status'], rows[0]['severity']), (1, 'open', 'medium'))
        st, d = self.call(self.api.handle_edge_list_sync, {'force': True}, at=LT + 8 * 3600)
        self.assertEqual(d['result']['state'], 'ok')
        self.assertEqual([e for e, _ in self.count.sent], ['edge_list_held', 'edge_list_synced'])
        self.assertEqual(_alerts(self.api, 'edge_list_held')[0]['status'], 'resolved')

    def test_a_preview_changes_no_alert(self):
        self.abuse = self.big[:100]
        self.call(self.api.handle_edge_list_preview, {}, at=LT)
        self.assertEqual(self.count.sent, [], 'looking is not a sync')

    def test_one_failed_apply_is_a_bad_hour_and_two_are_a_problem(self):
        with mock.patch.object(self.api.edge_blocklist_handlers_mod, '_sync',
                               side_effect=RuntimeError('boom')):
            self.tick(at=LT)
            self.assertEqual(self.count.sent, [])
            self.tick(at=LT + 7 * 3600)
        self.assertEqual([e for e, _ in self.count.sent], ['edge_list_held'])
        self.assertIn('RuntimeError', self.count.sent[0][1]['detail'])


if __name__ == '__main__':
    unittest.main()
