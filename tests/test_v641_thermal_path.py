"""v6.4.1: board/CPU sensors reach the Thermal page and the risk score.

`_ingest_hardware` persists the agent's board sensors at
`hardware.json -> <dev_id> -> hardware -> temps`, one level deeper than
`smart` and `gpus`, which sit at the record's top level. Three readers
dereferenced the flat `<dev_id> -> temps` instead, so on every real
agent-reported host they saw an empty list: the Thermal page listed disks
and GPUs but never `coretemp/Package id 0`, and the `overheating` risk and
reliability signals could only ever fire on a hot disk or GPU.

The bug was invisible to the existing suite because the fixtures and the
demo seeder wrote the same flat shape the buggy readers expected, while the
one test that used the real agent shape (`test_v500_thermal`) only asserted
on the history store — the single code path that read the right level.

These tests drive the REAL ingest, then the REAL readers.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'server' / 'cgi-bin'))

import api  # noqa: E402


AGENT_BODY = {
    'smart': [{'device': '/dev/nvme0n1', 'health': 'PASSED', 'temperature_c': 44}],
    'gpus': [{'vendor': 'nvidia', 'name': 'RTX 4070 Ti SUPER', 'temp_c': 51}],
    'hardware': {'temps': [{'label': 'coretemp/Package id 0',
                            'current_c': 67, 'crit_c': 100},
                           {'label': 'k10temp/Tctl', 'current_c': 59}]},
}


class TestIngestKeepsCritC(unittest.TestCase):
    """`crit_c` used to be dropped by the sanitizer whitelist, so the Thermal
    page's Critical and Headroom columns were permanently blank."""

    def test_crit_c_survives_ingest(self):
        api._ingest_hardware('t-crit', 'host-crit', AGENT_BODY, int(api.time.time()))
        rec = (api.load(api.HARDWARE_FILE) or {}).get('t-crit') or {}
        temps = (rec.get('hardware') or {}).get('temps') or []
        by_label = {t['label']: t for t in temps}
        self.assertEqual(by_label['coretemp/Package id 0'].get('crit_c'), 100.0)
        # A sensor with no crit reading must not gain a null one.
        self.assertNotIn('crit_c', by_label['k10temp/Tctl'])


class TestHwTempsAcceptsBothShapes(unittest.TestCase):
    """The reader helper: nested is the real shape, flat is legacy/demo data."""

    def test_nested(self):
        self.assertEqual(
            api._hw_temps({'hardware': {'temps': [{'current_c': 40}]}}),
            [{'current_c': 40}])

    def test_flat_fallback(self):
        self.assertEqual(api._hw_temps({'temps': [{'current_c': 41}]}),
                         [{'current_c': 41}])

    def test_junk_shapes_are_empty_not_raising(self):
        for junk in (None, [], 'x', {}, {'hardware': 'x'}, {'hardware': {'temps': 'x'}}):
            self.assertEqual(api._hw_temps(junk), [], junk)


class TestThermalPageListsCpuSensors(unittest.TestCase):
    """The reported symptom: only disks and GPUs appeared on Thermal Health."""

    def setUp(self):
        # Identity only — the gate itself isn't what's under test here.
        # Restored in tearDown so the stub can't leak into a later module.
        self._orig = {k: getattr(api, k)
                      for k in ('require_auth', '_caller_scope', '_tenant_gate')}
        api.require_auth = lambda require_admin=False: 'tester'
        api._caller_scope = lambda: None
        api._tenant_gate = lambda: None
        # Shared stores — reset so a sibling module's rows can't skew the row
        # we assert on (the count/order-dependent false-green class).
        api.save(api.DEVICES_FILE, {'t-therm': {'name': 'host-therm',
                                                'last_seen': int(api.time.time())}})
        api.save(api.HARDWARE_FILE, {})
        api._invalidate_load_cache(api.DEVICES_FILE)
        api._invalidate_load_cache(api.HARDWARE_FILE)
        api._ingest_hardware('t-therm', 'host-therm', AGENT_BODY, int(api.time.time()))
        api._invalidate_load_cache(api.HARDWARE_FILE)

    def tearDown(self):
        for k, v in self._orig.items():
            setattr(api, k, v)

    def _rows(self):
        try:
            api.handle_fleet_thermal()
        except api.HTTPError as e:
            return (e.body or {}).get('hosts') or []
        return []

    def test_cpu_sensor_is_the_hottest_and_appears_in_detail(self):
        rows = [r for r in self._rows() if r.get('device_id') == 't-therm']
        self.assertEqual(len(rows), 1, 'expected exactly one row for the host')
        row = rows[0]
        labels = {d['label']: d for d in (row.get('detail') or [])}
        self.assertIn('coretemp/Package id 0', labels,
                      'board/CPU sensors missing from the thermal detail')
        self.assertIn('k10temp/Tctl', labels)
        self.assertIn('/dev/nvme0n1', labels)
        self.assertIn('RTX 4070 Ti SUPER', labels)
        self.assertEqual(labels['coretemp/Package id 0']['type'], 'sensor')
        # 67 C beats the disk (44) and the GPU (51) — the row's headline value.
        self.assertEqual(row.get('max_temp'), 67.0)
        self.assertEqual(row.get('sensor_label'), 'coretemp/Package id 0')
        self.assertEqual(row.get('sensors'), 4)

    def test_crit_reaches_the_row(self):
        rows = [r for r in self._rows() if r.get('device_id') == 't-therm']
        crit = {d['label']: d.get('crit') for d in (rows[0].get('detail') or [])}
        self.assertEqual(crit['coretemp/Package id 0'], 100.0)
        # Critical/headroom columns were permanently blank while crit_c was
        # dropped by the ingest whitelist.
        self.assertEqual(rows[0].get('crit_c'), 100.0)
        self.assertEqual(rows[0].get('headroom'), 33.0)


class TestOverheatingSignalsReadTheRightLevel(unittest.TestCase):
    """`overheating` in the risk score and the reliability signal both read the
    persisted record; both dereferenced the flat key."""

    def _hot_record(self):
        api._ingest_hardware(
            't-hot', 'host-hot',
            {'hardware': {'temps': [{'label': 'coretemp/Package id 0',
                                     'current_c': 96, 'crit_c': 100}]}},
            int(api.time.time()))
        api._invalidate_load_cache(api.HARDWARE_FILE)
        return (api.load(api.HARDWARE_FILE) or {}).get('t-hot') or {}

    def test_hottest_sensor_seen_by_reader_helper(self):
        rec = self._hot_record()
        temps = [t.get('current_c') for t in api._hw_temps(rec)]
        self.assertEqual(max(temps), 96.0)

    def test_source_no_longer_reads_temps_off_the_record_top_level(self):
        # Guardrail against the exact regression: no reader may go back to the
        # flat path. Ingest/local-variable sites use `hw.`/`safe.`, not `_rec.`.
        src = (ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        self.assertNotIn("hw_rec.get('temps')", src)
        self.assertNotIn("hw.get('temps') or []", src)


if __name__ == '__main__':
    unittest.main()
