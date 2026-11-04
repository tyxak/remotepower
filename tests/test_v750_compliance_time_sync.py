#!/usr/bin/env python3
"""A fleet of drifting clocks passed the one requirement that is about clocks.

The Linux agent has reported whether the clock is synchronised, and by how much
it is off, since v4.1.0. The server stores one verdict per host (`clock.skewed`,
decided at ingest with the operator's offset limit), and the Checks row, the
clock_skew alert and the risk score all read it. No compliance control did, so
PCI DSS 10.6.1 had no evidence behind it.

WHAT THIS PINS, and why each one:

* The fact is ASSEMBLED. A control reading a key the facts builder never sets
  answers Not assessed forever and looks like a deliberate scope decision.
* Present-and-bad only. A host that never reported its clock is not a finding,
  and a record without a verdict is not one either.
* Not assessed when nobody reported, never Pass.
* The control reads the STORED verdict. It must not decide again, or the report
  and the Checks page can disagree about the same host.
* The mapping exists and points at this control, and the Fix link is wired.
"""
import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v750-ts-'))

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

_spec = importlib.util.spec_from_file_location('api_v750_ts', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import compliance  # noqa: E402


def _facts(devices):
    return api._compliance_facts(devices)


def _dev(name, clock):
    return {'name': name, 'sysinfo': {'clock': clock} if clock is not None else {}}


class TestTheFactIsAssembled(unittest.TestCase):

    def test_a_drifting_host_reaches_the_facts_with_the_reason(self):
        f = _facts({'d1': _dev('web01', {'synced': True, 'offset_ms': 2500.0,
                                         'skewed': True})})
        self.assertEqual(f['clock_data_devices'], 1)
        self.assertEqual(f['clock_off'], ['web01 (2.5 s off)'])

    def test_a_small_offset_is_shown_in_milliseconds(self):
        f = _facts({'d1': _dev('web01', {'synced': True, 'offset_ms': -420.0,
                                         'skewed': True})})
        self.assertEqual(f['clock_off'], ['web01 (420 ms off)'])

    def test_an_unsynchronised_host_says_so(self):
        f = _facts({'d1': _dev('web01', {'synced': False, 'skewed': True})})
        self.assertEqual(f['clock_off'], ['web01 (not synchronised)'])

    def test_a_skewed_host_with_no_figure_still_fails(self):
        f = _facts({'d1': _dev('web01', {'synced': True, 'skewed': True})})
        self.assertEqual(f['clock_off'], ['web01 (drifting)'])

    def test_a_synchronised_host_counts_as_reporting_but_not_as_a_finding(self):
        f = _facts({'d1': _dev('web01', {'synced': True, 'offset_ms': 3.0,
                                         'skewed': False})})
        self.assertEqual(f['clock_data_devices'], 1)
        self.assertEqual(f['clock_off'], [])

    def test_the_stored_verdict_decides_not_the_raw_numbers(self):
        """A 5 s offset with skewed False is the operator's own limit at work
        (Settings -> Alert parameters). The report must not second-guess it."""
        f = _facts({'d1': _dev('web01', {'synced': True, 'offset_ms': 5000.0,
                                         'skewed': False})})
        self.assertEqual(f['clock_off'], [])


class TestASilentHostIsNotAFinding(unittest.TestCase):

    def test_a_host_with_no_clock_report_is_neither_counted_nor_flagged(self):
        f = _facts({'d1': _dev('win01', None)})
        self.assertEqual(f['clock_data_devices'], 0)
        self.assertEqual(f['clock_off'], [])

    def test_a_record_without_a_verdict_is_not_counted(self):
        f = _facts({'d1': _dev('web01', {'synced': False})})
        self.assertEqual(f['clock_data_devices'], 0)
        self.assertEqual(f['clock_off'], [])

    def test_a_verdict_of_the_wrong_kind_is_not_counted(self):
        f = _facts({'d1': _dev('web01', {'synced': True, 'skewed': 'yes'})})
        self.assertEqual(f['clock_data_devices'], 0)

    def test_an_unmonitored_host_is_left_out(self):
        d = _dev('lab01', {'synced': False, 'skewed': True})
        d['monitored'] = False
        f = _facts({'d1': d})
        self.assertEqual(f['clock_data_devices'], 0)
        self.assertEqual(f['clock_off'], [])

    def test_a_mixed_fleet_reports_only_the_reporting_hosts(self):
        f = _facts({
            'd1': _dev('web01', {'synced': True, 'offset_ms': 9000.0, 'skewed': True}),
            'd2': _dev('win01', None),
            'd3': _dev('db01', {'synced': True, 'offset_ms': 1.0, 'skewed': False}),
        })
        self.assertEqual(f['clock_data_devices'], 2)
        self.assertEqual([h.split(' ')[0] for h in f['clock_off']], ['web01'])


class TestTheControlAnswersHonestly(unittest.TestCase):

    def test_drifting_hosts_fail_and_are_named(self):
        st, msg = compliance._time_sync_control(
            {'devices': 2, 'clock_data_devices': 2,
             'clock_off': ['web01 (2.5 s off)']})
        self.assertEqual(st, compliance.FAIL)
        self.assertIn('web01 (2.5 s off)', msg)
        self.assertIn('1 host', msg)

    def test_all_synchronised_passes_and_says_what_is_not_covered(self):
        st, msg = compliance._time_sync_control(
            {'devices': 3, 'clock_data_devices': 3, 'clock_off': []})
        self.assertEqual(st, compliance.PASS)
        self.assertIn('Windows', msg)

    def test_nobody_reporting_is_not_assessed_never_pass(self):
        st, _msg = compliance._time_sync_control(
            {'devices': 4, 'clock_data_devices': 0, 'clock_off': []})
        self.assertEqual(st, compliance.NOT_ASSESSED)

    def test_the_failure_list_is_capped(self):
        st, msg = compliance._time_sync_control(
            {'devices': 30, 'clock_data_devices': 30,
             'clock_off': [f'h{i} (drifting)' for i in range(30)]})
        self.assertEqual(st, compliance.FAIL)
        self.assertIn('30 hosts', msg)
        self.assertIn('h9 (drifting)', msg)
        self.assertNotIn('h10 (drifting)', msg)


class TestTheMappingAndTheFixLink(unittest.TestCase):

    def test_pci_10_6_1_points_at_the_control(self):
        rows = [c for c in compliance._CONTROLS
                if c[0] == 'pci' and c[1] == '10.6.1']
        self.assertEqual(len(rows), 1)
        self.assertIs(rows[0][3], compliance._time_sync_control)
        self.assertTrue(rows[0][4])

    def test_the_report_contains_the_control_with_its_verdict(self):
        f = _facts({'d1': _dev('web01', {'synced': True, 'offset_ms': 9000.0,
                                         'skewed': True})})
        rep = compliance.build_report(f, frameworks=['pci'])
        controls = rep['frameworks']['pci']['controls']
        mine = [c for c in controls if c['id'] == '10.6.1']
        self.assertEqual(len(mine), 1, [c['id'] for c in controls])
        self.assertEqual(mine[0]['status'], compliance.FAIL)
        self.assertEqual(mine[0].get('topic'), 'clock')

    def test_the_topic_has_a_page_to_open(self):
        js = (_ROOT / 'server/html/static/js/app.js').read_text()
        block = re.search(r'const _COMPLIANCE_FIX_PAGE = \{(.*?)\n\};', js, re.S).group(1)
        self.assertRegex(block, r"clock:\s*'checks'")
        html = (_ROOT / 'server/html/index.html').read_text()
        self.assertIn('data-page="checks"', html)


if __name__ == '__main__':
    unittest.main()
