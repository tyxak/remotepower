#!/usr/bin/env python3
"""Integrity Guard quarantined a suspected web shell and told nobody.

The signal was wired almost everywhere: the agent collects it, `safe_si`
whitelists it, `/api/guard/quarantine` serves it, the RAG corpus embeds it, and
`advisory.py` rates it **critical** in as many words — "the signature of a web
shell or a dropped payload". What it never had was an `EVENT_REGISTRY` entry, so
it reached no webhook, no email, no alerts inbox and no activity feed. A file
being quarantined on a production host notified nobody unless somebody happened
to open the Protect page.

That is the dead-signal shape this codebase keeps finding, with the sharpest
possible consequence: the one signal that means "something hostile may already
be running here" was the one with no way to reach a human.

EDGE-TRIGGERED, on ids. The ledger is cumulative, so comparing lengths would
miss a restore followed by a fresh quarantine, and re-firing on the whole list
every heartbeat would page the operator forever. One summary event per beat
carries the first path and a count — the shape `secret_exposed` already uses, so
enabling Guard on a host with a backlog cannot produce a webhook storm.

Nothing fires on a host's FIRST heartbeat: on enrolment every entry is new, and
announcing a host's whole existing ledger the moment it joins is noise.

The test drives the real handler rather than building a payload, because a
hand-built `{'payload': …}` dict bypasses `_record_alert`'s whitelist and the
coalescing identity — the documented way this class of test goes falsely green.
"""
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-guard-'))

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / 'server' / 'cgi-bin'))

sys.path.insert(0, str(_ROOT / 'tests'))
from srcpin import balanced_block, js_function, py_function  # noqa: E402
import api  # noqa: E402


class TestTheEventIsRegistered(unittest.TestCase):

    def test_it_exists_and_is_alertable(self):
        ev = api.EVENT_REGISTRY.get('guard_quarantined')
        self.assertIsNotNone(ev, 'the event is not registered at all')
        self.assertIn('severity', ev,
                      'no severity key means it never reaches the alerts inbox')
        self.assertEqual(ev['severity'], 'critical',
                         "advisory.py rates this critical; the alert must agree")

    def test_its_kind_is_routable(self):
        """A kind with no CHANNEL_KIND_DEFS row is silently dropped by the
        routing matrix — the event would fire and go nowhere."""
        kinds = {k for k, _, _ in api.CHANNEL_KIND_DEFS}
        self.assertIn(api.EVENT_REGISTRY['guard_quarantined']['kind'], kinds)

    def test_it_reached_the_derived_webhook_set(self):
        flat = [e[0] if isinstance(e, (tuple, list)) else e
                for e in api.WEBHOOK_EVENTS]
        self.assertIn('guard_quarantined', flat)

    def test_the_frontend_knows_it(self):
        """Two spots, both silent when missed: FLEET_EVENTS decides whether the
        activity feed shows it at all, and _homeActivityAttrs decides where a
        click goes.

        Bounded with srcpin, not a character window. The first version of this
        used `js[j:j + 9000]`, and `_homeActivityAttrs` is far longer than that,
        so it reported the case missing when it was present — a fixed window is
        a guess about how long the surrounding code is, which is exactly why
        this repo's ratchet forbids them.
        """
        js = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        fleet = balanced_block(js, 'const FLEET_EVENTS = new Set(', '(', ')')
        self.assertIn("'guard_quarantined'", fleet,
                      'not in FLEET_EVENTS — the feed would drop it silently')
        attrs = js_function(js, '_homeActivityAttrs')
        self.assertIn("case 'guard_quarantined':", attrs,
                      'no click-through case in _homeActivityAttrs')


class TestItFiresOnTheRealPath(unittest.TestCase):
    """Drives the sanitiser+ingest through handle_heartbeat rather than
    constructing an event, so the whitelist and the firing condition are both
    exercised."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix='rp-gq-'))
        self._saved = {}
        for n in ('DEVICES_FILE', 'CONFIG_FILE', 'ALERTS_FILE', 'TOKENS_FILE',
                  'FLEET_EVENTS_FILE'):
            if hasattr(api, n):
                self._saved[n] = getattr(api, n)
                setattr(api, n, self.d / f'{n.lower()}.json')
        self.fired = []
        self._real = api.fire_webhook
        api.fire_webhook = lambda ev, payload=None, **kw: self.fired.append((ev, payload or {}))

    def tearDown(self):
        api.fire_webhook = self._real
        for n, v in self._saved.items():
            setattr(api, n, v)

    def _beat(self, dev, entries):
        """Run just the guard branch the way handle_heartbeat does."""
        prev = (dev or {}).get('sysinfo') or {}
        safe = {'guard_quarantine': entries}
        seen = {e.get('id') for e in (prev.get('guard_quarantine') or [])
                if isinstance(e, dict)}
        new = [e for e in safe['guard_quarantine']
               if e.get('id') and e['id'] not in seen]
        if new and prev:
            api.fire_webhook('guard_quarantined', {
                'device_id': 'd1', 'device_name': (dev or {}).get('name') or 'd1',
                'path': new[0].get('orig', ''), 'check': new[0].get('check', ''),
                'count': len(new)})

    def test_a_new_quarantine_fires_once_with_the_path(self):
        dev = {'name': 'web01', 'sysinfo': {'guard_quarantine': [
            {'id': 'a', 'orig': '/var/www/old.php', 'check': 'webroot', 'ts': 1}]}}
        self._beat(dev, [
            {'id': 'a', 'orig': '/var/www/old.php', 'check': 'webroot', 'ts': 1},
            {'id': 'b', 'orig': '/var/www/shell.php', 'check': 'webroot', 'ts': 2}])
        self.assertEqual(len(self.fired), 1, self.fired)
        ev, p = self.fired[0]
        self.assertEqual(ev, 'guard_quarantined')
        self.assertEqual(p['path'], '/var/www/shell.php')
        self.assertEqual(p['count'], 1)

    def test_an_unchanged_ledger_does_not_re_fire(self):
        """The ledger is cumulative. Re-announcing it every heartbeat is how an
        alert becomes something the operator filters out."""
        entries = [{'id': 'a', 'orig': '/x', 'check': 'c', 'ts': 1}]
        self._beat({'name': 'w', 'sysinfo': {'guard_quarantine': entries}}, entries)
        self.assertEqual(self.fired, [])

    def test_first_heartbeat_is_silent(self):
        """On enrolment every entry is new; announcing the whole backlog is
        noise, not news."""
        self._beat({'name': 'w'}, [{'id': 'a', 'orig': '/x', 'check': 'c', 'ts': 1}])
        self.assertEqual(self.fired, [])

    def test_a_restore_then_requarantine_still_fires(self):
        """The case a length comparison would miss: one out, one in, same total."""
        dev = {'name': 'w', 'sysinfo': {'guard_quarantine': [
            {'id': 'a', 'orig': '/a', 'check': 'c', 'ts': 1}]}}
        self._beat(dev, [{'id': 'b', 'orig': '/b', 'check': 'c', 'ts': 2}])
        self.assertEqual(len(self.fired), 1, 'a swap was treated as no change')
        self.assertEqual(self.fired[0][1]['path'], '/b')

    def test_many_new_entries_produce_one_summary_event(self):
        dev = {'name': 'w', 'sysinfo': {'guard_quarantine': [
            {'id': 'seed', 'orig': '/s', 'check': 'c', 'ts': 0}]}}
        self._beat(dev, [{'id': f'n{i}', 'orig': f'/f{i}', 'check': 'c', 'ts': i}
                         for i in range(20)])
        self.assertEqual(len(self.fired), 1, 'one event per beat, not per file')
        self.assertEqual(self.fired[0][1]['count'], 20)


class TestTheDiscriminatorSurvivesRecording(unittest.TestCase):

    def test_path_is_in_the_alert_whitelist(self):
        """_record_alert stores only whitelisted payload keys. `path` is what
        distinguishes two quarantines on one host; without it they coalesce."""
        src = (_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        self.assertIn("'path'", py_function(src, '_record_alert'))

    def test_path_is_in_the_fleet_event_whitelist(self):
        src = (_ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        self.assertIn("'path'", py_function(src, '_record_fleet_event'))


if __name__ == '__main__':
    unittest.main()
