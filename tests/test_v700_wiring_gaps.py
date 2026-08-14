#!/usr/bin/env python3
"""Four wiring gaps, each generalised into a rule rather than pinned.

All four are this project's signature shape: a feature wired in most of the
registries it needs and missed in one, so it does nothing and nothing says so.
The existing guards for three of these classes each checked a hardcoded pair of
keys, which is why none of them fired.

  Quick links     /api/home read `cfg['links']` — a config key with no writer
                  anywhere — while every write goes to LINKS_FILE. The client
                  hides the card on an empty list, so the widget could never
                  appear, and the Documentation page promised it "automatically
                  appears" once a link is saved.
  patch threshold compliance read `cfg['thresholds']['patch_alert']`. There is
                  no top-level `thresholds` dict either, so it always fell back
                  to 50 and the Settings control did nothing to the verdict.
  ping_missed     fires per dead-man's-switch JOB and carries no device_id, so
                  its alert identity was ('ping_missed', '', ()) for every job:
                  all of them merged into one row and the per-job sub_match had
                  nothing to discriminate. Because it only fires on the
                  newly-late transition, a masked job then went silent for good.
  snapshot_old    same shape per Proxmox guest, on `vmid`.
  ssh_key         a Needs-Attention kind with no _NA_MUTE_EVENTS row, which by
                  that map's own rule is permanently unmuteable — so muting the
                  alert never lifted the item, and fleet health (derived purely
                  from NA items) stayed depressed with no recourse.

The tests below derive their expectations from the registries themselves, so a
future event or NA kind with the same defect fails without anyone editing this
file.
"""
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-wiring-'))

import importlib.util  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
_spec = importlib.util.spec_from_file_location('api', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules['api'] = api
_spec.loader.exec_module(api)

_SRC = (_CGI / 'api.py').read_text(encoding='utf-8')


class TestConfigReadsHaveAWriter(unittest.TestCase):
    """A `cfg.get('x')` whose key nothing ever writes is a constant wearing a
    setting's clothes — and reads to a reviewer as configurable."""

    # Keys the server legitimately reads but never writes through a handler:
    # deployment overrides set in the config file by hand. Listed with reasons
    # so the list cannot quietly absorb a real bug.
    KNOWN_READ_ONLY = {
        'links': 'FIXED — now read from LINKS_FILE; kept here to catch a revert',
    }

    def test_the_home_widget_reads_the_store_the_writes_go_to(self):
        fn = _SRC[_SRC.index('def handle_home('):]
        fn = fn[:fn.index('\ndef ', 10)]
        self.assertIn('_links_load()', fn,
                      'the Quick links widget reads a store nothing writes')
        self.assertNotIn("cfg.get('links')", fn)

    def test_compliance_reads_the_operator_facing_patch_key(self):
        self.assertNotIn("get('patch_alert', 50)", _SRC,
                         "compliance reads cfg['thresholds']['patch_alert'], a "
                         'key with no writer, instead of PATCH_ALERT_KEY')
        self.assertIn('PATCH_ALERT_KEY', _SRC)

    def test_there_is_still_no_top_level_thresholds_dict(self):
        """The premise of the fix. If a `thresholds` writer ever appears, the
        old read was not a bug and this file should be revisited."""
        self.assertNotIn("'thresholds':", _SRC.replace("'thresholds': {}", ''))


class TestPerResourceAlertsDoNotCoalesce(unittest.TestCase):
    """Derived from EVENT_REGISTRY, not from a list of today's offenders.

    An event whose recovery matches on some key K must carry K in
    _ALERT_IDENTITY_FIELDS, or two of them on one host merge into a single row
    and the per-resource recovery clears the wrong one.
    """

    def _sub_match_keys(self):
        """Every key a `sub_match` branch discriminates on."""
        fn = _SRC[_SRC.index('def _auto_resolve_alerts'):]
        fn = fn[:fn.index('\ndef ', 10)]
        return set(re.findall(r"sub_match\s*=\s*\{?\s*'(\w+)'", fn)) | \
            set(re.findall(r"sub_match\[['\"](\w+)['\"]\]", fn))

    def test_the_scan_finds_sub_match_branches(self):
        keys = self._sub_match_keys()
        self.assertGreater(len(keys), 5,
                           f'only found {keys} — the assertion below would be '
                           'reading almost nothing')

    def test_the_two_known_offenders_are_now_identity_fields(self):
        for k in ('job_id', 'vmid'):
            self.assertIn(k, api._ALERT_IDENTITY_FIELDS,
                          f'{k} discriminates a per-resource recovery but is '
                          'not an identity field, so the rows coalesce and the '
                          'recovery clears the wrong one')

    def test_every_sub_match_key_is_an_identity_field(self):
        missing = sorted(self._sub_match_keys()
                         - set(api._ALERT_IDENTITY_FIELDS)
                         - {'device_id'})     # the identity's own first term
        self.assertEqual(
            missing, [],
            'these keys discriminate a per-resource recovery but do not '
            'separate the alert rows in the first place, so two failing '
            'resources on one host merge and the recovery clears the wrong '
            f'one: {missing}')


class TestEveryMuteableNaKindCanActuallyBeMuted(unittest.TestCase):

    def _na_kinds(self):
        """(kind, severity) pairs the attention builder actually emits."""
        return set(re.findall(
            r"'severity':\s*'(\w+)',\s*'kind':\s*'(\w+)'", _SRC))

    def test_the_scan_finds_na_items(self):
        self.assertGreater(len(self._na_kinds()), 10,
                           'the emitted-item scan found almost nothing')

    def test_ssh_key_is_muteable(self):
        self.assertIn(('ssh_key', 'critical'), api._NA_MUTE_EVENTS,
                      'an NA kind with no row here is permanently unmuteable '
                      'by this map’s own rule, so muting the alert never lifts '
                      'the health-score penalty')

    def test_the_mapped_events_exist(self):
        """A row naming an event that is not in the registry mutes nothing —
        the same invented-name class that shipped four times before."""
        bad = []
        for pair, events in api._NA_MUTE_EVENTS.items():
            for ev in events:
                if ev not in api.EVENT_REGISTRY:
                    bad.append(f'{pair} -> {ev}')
        self.assertEqual(bad, [], 'mute rows naming non-existent events: '
                                  + ', '.join(bad))

    def test_the_mapped_events_are_alertable(self):
        """An event with no `severity` key never reaches the inbox, so muting
        it cannot lift anything either."""
        bad = [f'{pair} -> {ev}' for pair, events in api._NA_MUTE_EVENTS.items()
               for ev in events
               if ev in api.EVENT_REGISTRY
               and 'severity' not in api.EVENT_REGISTRY[ev]]
        self.assertEqual(bad, [], 'mute rows naming non-alertable events: '
                                  + ', '.join(bad))


class TestEveryPromptIsTunable(unittest.TestCase):
    """SYSTEM_PROMPTS and _AI_PROMPT_LABELS are a two-registry contract with no
    gate. handle_ai_params_get iterates the LABELS, so a prompt with no label
    never appears on the AI-parameters page and cannot be tuned — which is how
    report_summary ended up untunable twice over: no label, and a call site
    that never consulted _resolve_ai_params even if there had been one.
    """

    def test_the_registries_are_not_empty(self):
        self.assertGreater(len(api.ai_provider.SYSTEM_PROMPTS), 50)
        self.assertGreater(len(api._AI_PROMPT_LABELS), 50)

    def test_every_prompt_has_a_label(self):
        missing = sorted(set(api.ai_provider.SYSTEM_PROMPTS)
                         - set(api._AI_PROMPT_LABELS))
        self.assertEqual(missing, [],
                         'these prompts never appear on the AI-parameters '
                         f'page, so their overrides cannot be set: {missing}')

    def test_every_label_has_a_prompt(self):
        extra = sorted(set(api._AI_PROMPT_LABELS)
                       - set(api.ai_provider.SYSTEM_PROMPTS))
        self.assertEqual(extra, [],
                         f'labels for prompts that do not exist: {extra}')


if __name__ == '__main__':
    unittest.main()
