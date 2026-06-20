#!/usr/bin/env python3
"""
Tests for v2.4.8 — recent-activity feed de-duplication.

A noisy host repeating the same log_alert would fill all 8 feed
rows. The dashboard feed now collapses repeated (event, host,
subject) entries to their most-recent occurrence — a display
concern only; the server fleet event log still records every event.

These tests verify the de-dup logic is present and shaped correctly
by checking the rendered JS (the feed is client-side).
"""

import sys as _cj_sys
from pathlib import Path as _cj_Path
_cj_sys.path.insert(0, str(_cj_Path(__file__).resolve().parent))
from clientjs import client_js
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent


class TestActivityDedup(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.js = client_js()
        start = cls.js.find('function _renderHomeActivity')
        assert start > 0, '_renderHomeActivity not found'
        # v3.4.2: widened 3200→3600 — added image/health events to FLEET_EVENTS
        # lengthened the literal before the .slice() this test checks for.
        # v3.12.0: widened 3600→3800 — added db_integrity_failed to FLEET_EVENTS.
        # v3.14.0: widened 3800→4000 — added process_alert/process_recovered.
        # v3.14.0: widened 4000→4100 — added secret_exposed.
        # v4.7.0: widened 4200→4600 — added integration_down/integration_recovered.
        # v5.0.0: widened 4600→4800 — added vault_break_glass to FLEET_EVENTS.
        cls.chunk = cls.js[start:start + 4800]

    def test_dedup_runs_before_slice(self):
        # The de-dup filter must come before .slice(0, 8) — otherwise
        # 8 identical rows get sliced and dedup leaves one, wasting
        # the feed.
        dedup_pos = self.chunk.find('_seenActivity')
        slice_pos = self.chunk.find('.slice(0, 8)')
        self.assertGreater(dedup_pos, 0, 'de-dup logic missing')
        self.assertGreater(slice_pos, dedup_pos,
                           '.slice must come AFTER the de-dup filter')

    def test_dedup_key_includes_event_host_subject(self):
        # The key must combine the event, the host, and the subject —
        # so two different hosts, or two different subjects, stay
        # separate, but the same trio collapses.
        self.assertIn('e.event', self.chunk)
        # Host candidates
        for f in ('device_id', 'device_name'):
            self.assertIn(f, self.chunk)
        # Subject candidates (unit covers the postfix.service case)
        for f in ('p.unit', 'p.path', 'p.cve_id'):
            self.assertIn(f, self.chunk)

    def test_dedup_uses_a_set(self):
        # A Set keeps the dedup O(1) per row.
        self.assertIn('new Set()', self.chunk)

    def test_filter_still_present(self):
        # The FLEET_EVENTS allowlist filter must still run.
        self.assertIn('FLEET_EVENTS.has(e.event)', self.chunk)

    def test_dedup_logic_simulated(self):
        # Re-implement the key logic in Python and prove it collapses
        # the reported case (8x log_alert / pmg01 / postfix.service).
        events = [
            {'event': 'log_alert',
             'payload': {'host': 'pmg01.tvipper.com', 'unit': 'postfix.service'}}
            for _ in range(8)
        ]
        # Plus one genuinely different entry that must survive.
        events.append({'event': 'log_alert',
                        'payload': {'host': 'web01', 'unit': 'nginx.service'}})

        seen = set()
        kept = []
        for e in events:
            p = e.get('payload') or {}
            host = (p.get('device_id') or p.get('device_name')
                    or p.get('name') or p.get('host') or '')
            subject = (p.get('path') or p.get('unit') or p.get('metric')
                       or p.get('cve_id') or p.get('pattern')
                       or p.get('command') or '')
            key = f"{e['event']}|{host}|{subject}"
            if key in seen:
                continue
            seen.add(key)
            kept.append(e)

        # 8 identical → 1; the distinct one survives → 2 total.
        self.assertEqual(len(kept), 2)
        hosts = {(k.get('payload') or {}).get('host') for k in kept}
        self.assertEqual(hosts, {'pmg01.tvipper.com', 'web01'})


if __name__ == '__main__':
    unittest.main(verbosity=2)
