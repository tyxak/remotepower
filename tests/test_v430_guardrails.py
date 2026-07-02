#!/usr/bin/env python3
"""v4.3.0 "ImprovementMatters" — regression guardrails.

These tests don't exercise a feature; they lock two invariants that have been
violated by hand three+ times across releases:

  1. Every sysinfo field a server-side CHECK reads must be PERSISTED by the
     heartbeat sanitizer. proc_names (v4.1.0), mailq + pkg_scan_ts (v4.2.0
     sweep) were each read by a check but silently dropped by the sanitizer,
     so the check returned 'unknown'/never fired fleet-wide. The bug is
     invisible to feature tests because they inject sysinfo directly into
     dev['sysinfo'], bypassing the sanitizer.

  2. Every event in WEBHOOK_EVENTS must be wired through the alert + routing
     registries. The phantom service_recover (fired nowhere, mapped in the
     recover table) and any event missing from _ALERT_RULES / EVENT_KIND_MAP
     half-works in a way the UI and inbox silently swallow.

Both work by scanning api.py source — the same style as the existing
guardrail tests (test_jsload, the MCP-doc pins). A source scan stays current
without a running heartbeat.
"""
import importlib.util
import os
import re
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
import sys
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v430g", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_SRC = (_CGI / "api.py").read_text()


def _slice(src, start_marker, end_marker):
    a = src.index(start_marker)
    b = src.index(end_marker, a)
    return src[a:b]


def _func_body(src, defname):
    """Source of one top-level function (until the next top-level def/class)."""
    m = re.search(rf'^def {re.escape(defname)}\(', src, re.M)
    assert m, f'{defname} not found'
    start = m.start()
    nxt = re.search(r'^(def |class )', src[start + 1:], re.M)
    return src[start: start + 1 + (nxt.start() if nxt else len(src))]


class TestSanitizerPersistsEveryCheckField(unittest.TestCase):
    """Invariant #1 — reads ⊆ persisted, for the heartbeat sanitizer."""

    def _persisted_keys(self):
        # The sanitizer block: from `safe_si = {}` to `dev['sysinfo'] = safe_si`.
        block = _slice(_SRC, 'safe_si = {}', "dev['sysinfo'] = safe_si")
        keys = set(re.findall(r"safe_si\['([a-z_0-9]+)'\]", block))
        # Keys written through the metric loops (safe_si[metric_key]/[fkey]) —
        # the literal tuples that drive them.
        for m in re.finditer(r"for (?:metric_key|fkey) in \(([^)]*)\)", block):
            keys |= set(re.findall(r"'([a-z_0-9]+)'", m.group(1)))
        return keys

    def _read_keys(self, defname):
        body = _func_body(_SRC, defname)
        return set(re.findall(r"si\.get\('([a-z_0-9]+)'\)", body)) \
            | set(re.findall(r"si\['([a-z_0-9]+)'\]", body))

    def test_host_checks_reads_are_persisted(self):
        persisted = self._persisted_keys()
        reads = self._read_keys('_host_checks')
        missing = sorted(reads - persisted)
        self.assertEqual(missing, [], (
            "_host_checks reads sysinfo fields the heartbeat sanitizer never "
            f"persists (silently 'unknown' fleet-wide): {missing}. Add "
            "safe_si['<field>'] = ... in handle_heartbeat's sanitizer block."))

    def test_custom_check_reads_are_persisted(self):
        persisted = self._persisted_keys()
        reads = self._read_keys('_eval_custom_check')
        missing = sorted(reads - persisted)
        self.assertEqual(missing, [], (
            f"_eval_custom_check reads unpersisted sysinfo fields: {missing} "
            "(this is exactly the proc_names bug)."))

    def test_known_previously_broken_fields_now_persisted(self):
        # Explicit belt-and-braces for the three that actually shipped broken.
        persisted = self._persisted_keys()
        for field in ('proc_names', 'mailq', 'pkg_scan_ts', 'last_oom_proc'):
            self.assertIn(field, persisted,
                          f'{field} must stay persisted (regressed before)')


class TestWebhookEventRegistryCoverage(unittest.TestCase):
    """Invariant #2 — every WEBHOOK_EVENTS entry is fully wired."""

    def setUp(self):
        self.events = {e[0] for e in api.WEBHOOK_EVENTS}
        # Recover/up events and the two command-bookkeeping events deliberately
        # don't create an alert row.
        self.recover = set(api._ALERT_RECOVER) | {
            e for evs in api._ALERT_RECOVER_EXTRA.values() for e in evs}
        self.non_alerting = self.recover | {'command_queued', 'command_executed',
                                             'service_up'}

    def test_every_event_resolves_to_a_channel_kind(self):
        missing = sorted(self.events - set(api.EVENT_KIND_MAP))
        self.assertEqual(missing, [], (
            f"webhook events with no channel kind (no routing-matrix row): "
            f"{missing}"))

    def test_alertable_events_have_a_severity_rule(self):
        missing = sorted((self.events - self.non_alerting) - set(api._ALERT_RULES))
        self.assertEqual(missing, [], (
            f"alertable events missing from _ALERT_RULES — they fire a webhook "
            f"but never land in the Alerts inbox (silent): {missing}"))

    def test_every_recover_target_is_a_real_event(self):
        # The phantom-service_recover class: a recover mapping whose TARGET
        # (the firing event it resolves) isn't a real event.
        targets = set(api._ALERT_RECOVER.values())
        for evs in api._ALERT_RECOVER_EXTRA.values():
            targets |= set(evs) if isinstance(evs, (list, tuple, set)) else {evs}
        bogus = sorted(t for t in targets if t and t not in self.events)
        self.assertEqual(bogus, [], (
            f"_ALERT_RECOVER maps to firing events that aren't in "
            f"WEBHOOK_EVENTS: {bogus}"))

    def test_every_event_has_a_friendly_title(self):
        # _webhook_title has a generic fallback, but a missing entry means the
        # event shows as "RemotePower: raw_event_name" — flag them. Titles now
        # derive from EVENT_REGISTRY `title` fields into _WEBHOOK_TITLES.
        titled = set(api._WEBHOOK_TITLES)
        # Events that legitimately have no dedicated title (recover/up reuse the
        # base event's framing); only require titles for alertable firing events.
        need = (self.events - self.non_alerting)
        missing = sorted(need - titled)
        self.assertEqual(missing, [], (
            f"alertable events with no _webhook_title entry (generic fallback "
            f"title): {missing}"))


if __name__ == '__main__':
    unittest.main()
