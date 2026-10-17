#!/usr/bin/env python3
"""7.4.0: every event reads as a sentence, not as an id.

130 of 219 events had no wording of their own, and the shared fallback produced "Smart failure:
web01" or "Ecc errors: web01": the event id with its underscores removed. It now says what the event
is, in the words the Settings page and the Alerts inbox already use for it (the registry label), and
adds up to three facts from the payload: "web01: ECC memory errors increased — 4 correctable · 1
uncorrectable". Three branches that returned the bare event id when no `detail` came with it use the
same text.

This renders every event through the real `_webhook_message`, with a payload taken from its own fire
sites. The population is the events whose payload can be read from the source (a literal dict, or a
local variable built from one): that subset gets the strict check, so a message that asks for a key
no fire site sends fails here. The rest get the checks that need no payload.
"""
import ast
import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v740-notiftext-'))

CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(CGI))
_spec = importlib.util.spec_from_file_location('api_v740_notiftext', CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)
import notify  # noqa: E402

FIRE = {'fire_webhook', '_fire', '_fire_service_webhook', '_fire_container_webhook'}

# Plausible values by key, so the message is judged on something like a real payload.
SAMPLES = {
    'unit': 'nginx.service', 'container': 'nginx', 'image': 'nginx:1.27', 'pool': 'tank', 'process': 'sshd',
    'iface': 'eth0', 'mount': '/var', 'path': '/srv/backup', 'target': 'example.com', 'disk': 'sda',
    'ups': 'apc1', 'domain': 'example.com', 'check_name': 'disk-health', 'rule': 'R1', 'rule_name': 'restart',
    'jail': 'sshd', 'label': 'nightly', 'package': 'openssl', 'cve_id': 'CVE-2025-1', 'user': 'alice',
    'ip': '203.0.113.5', 'mac': 'aa:bb:cc:dd:ee:ff', 'days_left': 5, 'eta_days': 12, 'age_hours': 30,
    'upgradable': 7, 'ce': 4, 'ue': 1, 'new_ce': 2, 'new_ue': 0, 'score': 61, 'grade': 'C', 'state': 'degraded',
    'status': 'down', 'reason': 'maintenance overdue', 'error': 'timeout', 'requester': 'bob',
    'vm_name': 'vm1', 'snap_name': 'daily-1', 'tunnel_name': 'office', 'client_name': 'laptop',
    'script_name': 'cleanup', 'site': 'hq', 'tag': 'prod', 'new_ip': '198.51.100.9', 'old_ip': '198.51.100.8',
    'source_ip': '192.0.2.4', 'level': 'high', 'value': 91, 'threshold': 80, 'issue': 'drift',
    'name': 'web01', 'device_name': 'web01', 'device_id': 'd-1', 'detail': 'the detail the fire site sends',
    'number': 42, 'priority': 2, 'last_seen': 1_700_000_000, 'ts': 1_700_000_000,
}
NUMBERS = re.compile(r'(count|total|size|hours|minutes|seconds|port|attempts|failures|load|used|free|pct|percent|_at|_ts|ttl|window_s)$', re.I)


def _keys(node):
    return {k.value for k in node.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)}


def fired_keys():
    """{event: set of keys} over every fire site whose payload can be read: a literal dict, or a
    local variable assigned one (and extended by `v['k'] = ...` or `v.update({...})`)."""
    out = {}
    for f in sorted(CGI.glob('*.py')):
        try:
            tree = ast.parse(f.read_text(encoding='utf-8'))
        except SyntaxError:                                   # pragma: no cover
            continue
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            local = {}
            for n in ast.walk(fn):
                if isinstance(n, ast.Assign) and len(n.targets) == 1:
                    t = n.targets[0]
                    if isinstance(t, ast.Name) and isinstance(n.value, ast.Dict):
                        local.setdefault(t.id, set()).update(_keys(n.value))
                    elif (isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name)
                          and isinstance(t.slice, ast.Constant) and isinstance(t.slice.value, str)):
                        local.setdefault(t.value.id, set()).add(t.slice.value)
                elif (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == 'update'
                      and isinstance(n.func.value, ast.Name) and n.args and isinstance(n.args[0], ast.Dict)):
                    local.setdefault(n.func.value.id, set()).update(_keys(n.args[0]))
            for n in ast.walk(fn):
                if not (isinstance(n, ast.Call) and len(n.args) >= 2):
                    continue
                g = n.func
                called = g.attr if isinstance(g, ast.Attribute) else getattr(g, 'id', '')
                if called not in FIRE:
                    continue
                if not (isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str)):
                    continue
                pl = n.args[1]
                if isinstance(pl, ast.Dict):
                    keys = _keys(pl)
                elif isinstance(pl, ast.Name) and pl.id in local:
                    keys = local[pl.id]
                else:
                    continue
                # the per-host wrappers stamp the host's name and id onto the payload they are given
                if called != 'fire_webhook':
                    keys = keys | {'name', 'device_id'}
                out.setdefault(n.args[0].value, set()).update(keys)
    return out


def payload_for(keys):
    return {k: SAMPLES.get(k, 3 if NUMBERS.search(k) else f'<{k}>') for k in keys}


def problems(event, message, strict):
    bad = []
    if not isinstance(message, str) or not message.strip():
        return ['empty']
    if event in message:
        bad.append('holds the raw event id')
    if re.search(r'\bNone\b|\{\}|\(\s*\)|\[\s*\]', message):
        bad.append('holds an empty field')
    if strict and '?' in message:
        bad.append('asks for a key no fire site sends')
    if strict and 'unknown' in message.lower():
        bad.append('says unknown')
    return bad


class TestEveryEventReadsAsASentence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fired = fired_keys()
        cls.events = [e for e, spec in api.EVENT_REGISTRY.items() if not spec.get('phantom')]

    def test_the_population_is_real(self):
        self.assertGreater(len(self.events), 200)
        self.assertGreater(len(self.fired), 90, 'the fire-site derivation found almost nothing')
        self.assertIn('device_offline', self.events)

    def test_every_event_has_words_of_its_own(self):
        missing = [e for e in self.events if not (api.EVENT_REGISTRY[e].get('label') or '').strip()]
        self.assertEqual(missing, [], 'an event with no registry label can only be announced by its id')

    def test_the_labels_reach_the_message_builder(self):
        self.assertEqual(api.notify_mod._label_fn('device_offline'), api.EVENT_REGISTRY['device_offline']['label'])

    def test_no_event_renders_as_an_id_or_an_empty_field(self):
        found = {}
        for e in self.events:
            keys = self.fired.get(e, set())
            payload = payload_for(keys)
            if not keys or keys & {'name', 'device_name', 'device_id'}:
                payload.setdefault('name', 'web01')
            msg = api._webhook_message(e, payload)
            bad = problems(e, msg, strict=bool(keys))
            if bad:
                found[e] = (bad, msg[:110])
        self.assertEqual(found, {}, 'these events read badly:\n  ' + '\n  '.join(
            f'{e}: {b} -> {m!r}' for e, (b, m) in list(found.items())[:15]))

    def test_the_strict_population_is_large(self):
        strict = [e for e in self.events if self.fired.get(e)]
        self.assertGreater(len(strict), 95)


class TestTheGenericMessage(unittest.TestCase):
    def setUp(self):
        self._orig = notify._label_fn
        notify._label_fn = lambda ev: {'ecc_errors': 'ECC memory errors increased',
                                       'pool_slow': 'A pool is slow'}.get(ev, '')

    def tearDown(self):
        notify._label_fn = self._orig

    def test_label_then_facts(self):
        msg = notify._webhook_message('ecc_errors', {'name': 'web01', 'ce': 4, 'ue': 0, 'pool': 'tank', 'reason': 'x'})
        self.assertEqual(msg, 'web01: ECC memory errors increased — pool tank · 4 correctable · 0 uncorrectable')

    def test_a_fleet_level_event_has_no_host_prefix_and_never_says_unknown(self):
        msg = notify._webhook_message('pool_slow', {'pool': 'tank'})
        self.assertEqual(msg, 'A pool is slow — pool tank')
        self.assertNotIn('unknown', msg)

    def test_at_most_three_facts_and_no_repeats(self):
        msg = notify._webhook_message('pool_slow', {'name': 'tank', 'pool': 'tank', 'disk': 'sda', 'iface': 'eth0',
                                                    'mount': '/', 'path': '/x'})
        self.assertEqual(msg.count(' · '), 2)                       # three facts
        self.assertNotIn('pool tank', msg)                          # the host name already says it

    def test_lists_are_shortened_and_empty_values_skipped(self):
        msg = notify._webhook_message('pool_slow', {'name': 'h', 'paths': ['/a', '/b', '/c', '/d'], 'disk': '', 'unit': None})
        self.assertEqual(msg, 'h: A pool is slow — /a, /b, /c…')

    def test_a_detail_still_wins(self):
        self.assertEqual(notify._webhook_message('pool_slow', {'name': 'h', 'detail': 'tank is at 91%'}), 'h: tank is at 91%')

    def test_an_unregistered_event_falls_back_to_its_id_made_readable(self):
        self.assertEqual(notify._webhook_message('made_up_event', {'name': 'h'}), 'h: Made up event')

    def test_the_checker_can_say_no(self):
        self.assertIn('holds the raw event id', problems('sweep_failing', 'sweep_failing', False))
        self.assertIn('asks for a key no fire site sends', problems('x', 'unit ? is down', True))
        self.assertIn('says unknown', problems('x', 'unknown: went offline', True))
        self.assertIn('holds an empty field', problems('x', 'web01 has None pending', False))
        self.assertEqual(problems('x', 'web01: all good', True), [])


if __name__ == '__main__':
    unittest.main()
