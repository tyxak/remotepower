#!/usr/bin/env python3
"""EVENT_REGISTRY consistency guardrails.

EVENT_REGISTRY (api.py) is the single source of truth for every fleet/webhook
event: WEBHOOK_EVENTS, _ALERT_RULES, _ALERT_RECOVER(_EXTRA), the CHANNEL_KINDS
event lists, ALERT_SYMPTOM_EVENTS and the webhook title/priority/tags maps are
all DERIVED from it. These tests pin the internal-consistency rules a new
registry entry must satisfy — the cross-surface pins (frontend FLEET_EVENTS,
_homeActivityAttrs) stay in test_v223 / test_v225.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

_CGI_BIN = Path(__file__).parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI_BIN))

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())
os.environ.setdefault('REQUEST_METHOD', 'GET')
os.environ.setdefault('PATH_INFO', '/')
os.environ.setdefault('CONTENT_LENGTH', '0')

import importlib.util
_spec = importlib.util.spec_from_file_location('api_evreg', _CGI_BIN / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

SEVERITIES = {'critical', 'high', 'medium', 'low', None}
ALLOWED_FIELDS = {'label', 'kind', 'title', 'default', 'severity', 'resolves',
                  'priority', 'tags', 'symptom', 'phantom',
    # v6.3.1: how this alert CLEARS. 'point' = it records something that
    # happened, so nothing can observe it clearing and the operator confirms
    # it away. Absent = a state that some recover event resolves.
    'lifecycle',
}


class TestRegistryShape(unittest.TestCase):
    def test_every_entry_has_known_fields_only(self):
        for ev, spec in api.EVENT_REGISTRY.items():
            unknown = set(spec) - ALLOWED_FIELDS
            self.assertFalse(unknown, f'{ev}: unknown registry fields {unknown}')

    def test_labels_present_except_phantoms(self):
        for ev, spec in api.EVENT_REGISTRY.items():
            if spec.get('phantom'):
                self.assertNotIn('label', spec,
                                 f'{ev}: phantom entries must not carry a label')
            else:
                self.assertTrue(spec.get('label'), f'{ev}: missing label')

    def test_every_event_has_a_kind_in_channel_kind_defs(self):
        kinds = {k for k, _l, _g in api.CHANNEL_KIND_DEFS}
        for ev, spec in api.EVENT_REGISTRY.items():
            self.assertIn(spec.get('kind'), kinds,
                          f'{ev}: kind {spec.get("kind")!r} has no '
                          f'CHANNEL_KIND_DEFS row — the routing matrix would '
                          f'silently drop it')

    def test_severity_values(self):
        for ev, spec in api.EVENT_REGISTRY.items():
            if 'severity' in spec:
                self.assertIn(spec['severity'], SEVERITIES, f'{ev}')

    def test_priority_values(self):
        for ev, spec in api.EVENT_REGISTRY.items():
            if 'priority' in spec:
                self.assertIn(spec['priority'], (1, 2, 4, 5),
                              f'{ev}: priority 3 is the default — omit it')

    def test_test_event_not_in_registry(self):
        # 'test' is the Settings send-a-test button, not a real event.
        self.assertNotIn('test', api.EVENT_REGISTRY)


class TestResolveWiring(unittest.TestCase):
    def test_resolves_targets_are_alertable_events(self):
        """A recover event pointing at a non-alertable / unknown event would
        never resolve anything — catch it at the registry."""
        for ev, spec in api.EVENT_REGISTRY.items():
            for target in spec.get('resolves', ()):
                self.assertIn(target, api.EVENT_REGISTRY,
                              f'{ev} resolves unknown event {target!r}')
                self.assertIn('severity', api.EVENT_REGISTRY[target],
                              f'{ev} resolves {target!r}, which has no '
                              f'severity — it never lands in the inbox, so '
                              f'there is nothing to resolve')

    def test_recover_maps_derive_correctly(self):
        for ev, spec in api.EVENT_REGISTRY.items():
            res = spec.get('resolves', ())
            if res:
                self.assertEqual(api._ALERT_RECOVER[ev], res[0])
                if len(res) > 1:
                    self.assertEqual(api._ALERT_RECOVER_EXTRA[ev], tuple(res[1:]))
                else:
                    self.assertNotIn(ev, api._ALERT_RECOVER_EXTRA)


class TestDerivedStructures(unittest.TestCase):
    def test_webhook_events_excludes_phantoms(self):
        names = set(api.WEBHOOK_EVENT_NAMES)
        for ev, spec in api.EVENT_REGISTRY.items():
            if spec.get('phantom'):
                self.assertNotIn(ev, names)
            else:
                self.assertIn(ev, names)

    def test_event_kind_map_covers_registry(self):
        for ev, spec in api.EVENT_REGISTRY.items():
            self.assertEqual(api.EVENT_KIND_MAP.get(ev), spec['kind'], ev)

    def test_channel_kinds_rows_match_defs_order(self):
        self.assertEqual([(k, l, g) for k, l, g, _e in api.CHANNEL_KINDS],
                         list(api.CHANNEL_KIND_DEFS))

    def test_alert_rules_pair_shape(self):
        # Legacy consumers unpack (severity, None) pairs.
        for ev, pair in api._ALERT_RULES.items():
            self.assertEqual(len(pair), 2, ev)
            self.assertIsNone(pair[1], ev)

    def test_adapter_maps(self):
        self.assertEqual(api._webhook_title('device_offline'), 'Device Offline')
        self.assertEqual(api._webhook_title('no_such_event'),
                         'RemotePower: no_such_event')
        self.assertEqual(api._webhook_priority('cve_found'), 5)
        self.assertEqual(api._webhook_priority('no_such_event'), 3)
        self.assertEqual(api._webhook_tags('device_offline'), 'red_circle,computer')
        self.assertEqual(api._webhook_tags('no_such_event'), 'bell')
        # The Settings test button keeps its decoration.
        self.assertEqual(api._webhook_title('test'), 'Webhook Test')
        self.assertEqual(api._webhook_tags('test'), 'white_check_mark,bell')


if __name__ == '__main__':
    unittest.main()
