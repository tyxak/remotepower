#!/usr/bin/env python3
"""7.4.0: Threat Intel says so when it reports addresses.

Driven for real: the edge poll queues a finding, the report sweep sends it to SniffCat, and
`fire_webhook` -> `_record_alert` writes the inbox row, because a hand-built payload skips the
whitelist and the identity rules that decide what an operator can read.

What is asked of it: one event per sweep that reported something (never one per address), none for a
sweep that reported nothing, the addresses named in the row, and no page by default.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v740-ipreported-'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))

from test_v730_edge_intel import ATTACKER, _Edge, graphql, group  # noqa: E402

OTHER = '45.155.205.9'


def _rows(api):
    api._LOAD_CACHE.clear()
    return [a for a in (api.load(api.ALERTS_FILE) or {}).get('alerts') or [] if a.get('event') == 'ip_reported']


class TestReportsAreAnnounced(_Edge):
    def setUp(self):
        super().setUp()
        self.sent = []
        real = self.real_fire_webhook

        def wrapped(event, payload=None, *a, **k):
            if event == 'ip_reported':
                self.sent.append(dict(payload or {}))
            return real(event, payload, *a, **k)
        self.api.fire_webhook = wrapped

    def test_a_sweep_that_reports_says_so_once_and_names_the_address(self):
        self.graphql = graphql(group(ATTACKER, count=7))
        self.trap = {'success': True, 'result': {'events': []}}
        self.poll()
        self.sweep()
        self.assertEqual(len(self.sent), 1)
        self.assertIn(ATTACKER, self.sent[0]['detail'])
        self.assertIn('SniffCat', self.sent[0]['detail'])
        rows = _rows(self.api)
        self.assertEqual(len(rows), 1, 'the inbox holds the row')
        self.assertIn(ATTACKER, (rows[0].get('payload') or rows[0]).get('detail', ''))

    def test_two_addresses_in_one_sweep_are_one_event(self):
        self.graphql = graphql(group(ATTACKER, count=7), group(OTHER, count=9))
        self.trap = {'success': True, 'result': {'events': []}}
        self.poll()
        self.sweep()
        self.assertEqual(len(self.sent), 1, 'one line per sweep, not one per address')
        self.assertTrue(self.sent[0]['detail'].startswith('2 addresses reported'), self.sent[0]['detail'])

    def test_a_sweep_that_reports_nothing_is_silent(self):
        self.policy(report_min_count=10, edge_report_after=50)
        self.graphql = graphql(group(ATTACKER, count=1))
        self.trap = {'success': True, 'result': {'events': []}}
        self.poll()
        self.sweep()
        self.assertEqual(self.sent, [])

    def test_with_tenancy_on_nothing_is_announced(self):
        """A host-less alert is visible to every tenant, and this one names addresses."""
        from unittest import mock
        self.graphql = graphql(group(ATTACKER, count=7))
        self.trap = {'success': True, 'result': {'events': []}}
        self.poll()
        with mock.patch.object(self.api, '_tenancy_enforced', return_value=True):
            self.sweep()
        self.assertEqual(self.sent, [])
        self.assertEqual(_rows(self.api), [])

    def test_it_does_not_page_by_default(self):
        kind = self.api.EVENT_REGISTRY['ip_reported']['kind']
        slot = self.api._kind_default(kind)
        self.assertIs(slot['webhook'], False)
        self.assertIs(slot['needs_attention'], False)


if __name__ == '__main__':
    unittest.main()
