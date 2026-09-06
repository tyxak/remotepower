#!/usr/bin/env python3
"""An inbox row shows exactly what `_record_alert`'s whitelist stored.

Since v7.0.2 the Alerts page renders every whitelisted payload fact under the
alert, "so no stored context stays hidden". That makes the whitelist the sole
gate on what an operator sees — and twenty-seven inbox-bound events computed the
answer to their own question, sent it to the webhook, and dropped it here.

The worst were not obscure. `ecc_errors` shipped correctable and uncorrectable
counts and showed neither, so "watch this" and "replace the DIMM now" rendered
identically. `tls_expiry` showed no days remaining — and the fleet-events copy
has stored `days_left` since it shipped, so the activity feed had it and the
inbox did not. `vault_break_glass` recorded break-glass credential access with
no actor and no reason.

This gate derives both halves: the events that reach the inbox (an
EVENT_REGISTRY entry with a `severity` key) and the payload each one fires
(literal `fire_webhook(<event>, {...})` sites). Anything dropped has to be
listed as dropped ON PURPOSE, with a reason — hostnames the row already shows,
tick counters, content hashes.

The population is deliberately the literal-dict fire sites, which is a subset:
a payload built in a variable is invisible here. A subset that is checked beats
a superset that is asserted.
"""
import ast
import unittest
from pathlib import Path

_CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'

# Payload keys an inbox event fires and the row should NOT carry, with reasons.
DROPPED_ON_PURPOSE = {
    'hostname': 'the row already shows the device name',
    'name': 'the device name, under the key every alert uses for it',
    'device_name': 'same',
    'baseline_hash': 'a content hash is not readable, and the drift page has it',
    'current_hash': 'same',
    'exists': 'a boolean that only qualifies the fact next to it',
    'age_seconds': 'the row shows a relative time already',
    'age_minutes': 'same',
    'ttl_minutes': 'configuration, not an observation',
    'ttl_seconds': 'same',
    'reported_at': 'the row carries its own timestamp',
    'delta_seconds': 'the row shows how long the host has been offline',
    'last_seen': 'same',
    'period_minutes': 'the schedule, not what went wrong',
    'bytes': 'a size with no unit beside it reads as noise',
    'warning': 'a count already implied by the severity',
}


def _api_tree():
    return ast.parse((_CGI / 'api.py').read_text(encoding='utf-8'))


def whitelist_keys():
    """The tuple `_record_alert` iterates when projecting the payload."""
    rec = next(n for n in ast.walk(_api_tree())
               if isinstance(n, ast.FunctionDef) and n.name == '_record_alert')
    best = set()
    for node in ast.walk(rec):
        if isinstance(node, ast.For) and isinstance(node.iter, ast.Tuple):
            names = {e.value for e in node.iter.elts
                     if isinstance(e, ast.Constant) and isinstance(e.value, str)}
            if len(names) > len(best):
                best = names
    return best


def inbox_events():
    """Events with a `severity` in EVENT_REGISTRY reach the Alerts inbox."""
    reg = next(n.value for n in _api_tree().body
               if isinstance(n, ast.Assign)
               and any(getattr(t, 'id', None) == 'EVENT_REGISTRY'
                       for t in n.targets))
    return {k.value for k, v in zip(reg.keys, reg.values)
            if isinstance(k, ast.Constant) and 'severity' in ast.unparse(v)}


# Every way an event is fired. `fire_webhook` is the public one; `_fire` and
# its two siblings are thin per-device wrappers around it, and a scan that knows
# only the public name misses them — `ecc_errors`, `storage_degraded` and
# `mount_issue`, three of the events this gate exists for, all go through
# `_fire`.
_FIRE_NAMES = {'fire_webhook', '_fire', '_fire_service_webhook',
               '_fire_container_webhook'}


def fired_payload_keys():
    """{event: keys} for every literal `<fire>('x', {...})` call."""
    out = {}
    for f in sorted(_CGI.glob('*.py')):
        try:
            tree = ast.parse(f.read_text(encoding='utf-8'))
        except SyntaxError:                                # pragma: no cover
            continue
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and len(node.args) >= 2):
                continue
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, 'id', '')
            if name not in _FIRE_NAMES:
                continue
            ev, payload = node.args[0], node.args[1]
            if not (isinstance(ev, ast.Constant) and isinstance(ev.value, str)):
                continue
            if not isinstance(payload, ast.Dict):
                continue
            out.setdefault(ev.value, set()).update(
                k.value for k in payload.keys
                if isinstance(k, ast.Constant) and isinstance(k.value, str))
    return out


class TestNothingIsComputedAndHidden(unittest.TestCase):

    def test_every_fired_fact_is_stored_or_dropped_on_purpose(self):
        wl = whitelist_keys()
        inbox = inbox_events()
        gaps = {}
        for event, keys in fired_payload_keys().items():
            if event not in inbox:
                continue
            dropped = sorted(keys - wl - set(DROPPED_ON_PURPOSE))
            if dropped:
                gaps[event] = dropped
        self.assertEqual(
            gaps, {},
            "these inbox alerts compute a fact, send it to the webhook, and "
            "drop it before the row an operator reads. Add the key to "
            "_record_alert's whitelist, or list it in DROPPED_ON_PURPOSE with "
            f"the reason the row is better without it: {gaps}")

    def test_the_named_regressions_stay_fixed(self):
        """The ones worth naming, so a whitelist edit that loses them fails
        with a sentence rather than a diff."""
        wl = whitelist_keys()
        for key, why in (
                ('ce', 'correctable ECC count — the only number in that alert'),
                ('ue', 'uncorrectable ECC count — a different decision'),
                ('days_left', 'how long until the certificate expires'),
                ('requester', 'who took the break-glass credential'),
                ('reason', 'and why'),
                ('eta_days', 'the prediction, in a predictive alert'),
                ('package', 'which package violates the policy'),
                ('state', 'degraded vs faulted vs offline')):
            self.assertIn(key, wl, f'{key}: {why}')


class TestTheDerivationsAreHonest(unittest.TestCase):
    """Each check above is "this dict is empty", which is also what a broken
    derivation produces."""

    def test_the_whitelist_parses(self):
        wl = whitelist_keys()
        self.assertGreater(len(wl), 100, len(wl))
        for known in ('device_id', 'unit', 'pool'):
            self.assertIn(known, wl, 'the whitelist parse is broken')

    def test_the_inbox_set_is_a_real_subset_of_the_registry(self):
        inbox = inbox_events()
        self.assertGreater(len(inbox), 80, len(inbox))
        self.assertIn('device_offline', inbox)
        self.assertNotIn('service_recover', inbox,
                         'a phantom alias is not an inbox event')

    def test_the_fire_site_scan_finds_payloads(self):
        fires = fired_payload_keys()
        self.assertGreater(len(fires), 40, len(fires))
        for known in ('ecc_errors', 'tls_expiry', 'vault_break_glass',
                      'storage_degraded', 'mount_issue'):
            self.assertIn(known, fires,
                          f'the fire-site scan no longer sees {known}, one of '
                          'the calls this gate exists for')

    def test_every_deliberate_drop_is_still_fired_somewhere(self):
        """An exemption for a key nothing sends is dead weight that makes the
        list look considered when it is stale."""
        every = {k for keys in fired_payload_keys().values() for k in keys}
        stale = sorted(set(DROPPED_ON_PURPOSE) - every)
        self.assertEqual(stale, [],
                         f'exemption for a key no event fires: {stale}')


if __name__ == '__main__':
    unittest.main()
