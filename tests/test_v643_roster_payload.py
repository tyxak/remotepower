#!/usr/bin/env python3
"""The device roster stops shipping a field nothing reads.

`GET /api/devices` is re-fetched every 60 seconds by a GLOBAL timer — from
every page, not just Devices — and again on every tab refocus. On a 400-device
fleet `sysinfo.proc_names` alone is 31-45 % of that payload, and no client file
reads it: the only occurrences in server/html/static/js are a comment.

It stays STORED. The process custom-checks, `_eval_custom_check` and the RAG
corpus all read it from the device record, not from this response — so this
changes what is transmitted, not what is collected. That distinction is the
whole safety argument, and it is why the tests below assert the store still has
it.

WHY IT IS AN API BEHAVIOUR CHANGE and listed in the upgrade notes rather than
slipped in as a perf tweak: there is no plain `GET /api/devices/<id>` — every
route is `/api/devices/<id>/<subresource>` — so this removes HTTP access to
proc_names entirely. No shipped consumer wanted it; a third-party one might
have, and that deserves saying out loud.

The recon that found this ALSO claimed the top-level `listening_ports` was a
byte-for-byte duplicate of `sysinfo.listening_ports`. It is not: it prefers the
port-BASELINE store and only falls back to sysinfo, so the two differ whenever a
baseline exists. Removing it would have quietly changed what the field means.
Left alone, and asserted below so nobody "finishes the job" later.
"""
import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v643roster-'))

_spec = importlib.util.spec_from_file_location('api_v643_roster', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules.setdefault('api', api)
_spec.loader.exec_module(api)

_PROCS = ['systemd', 'sshd', 'nginx', 'postgres', 'python3'] * 12


class _Base(unittest.TestCase):
    def setUp(self):
        now = int(time.time())
        api.save(api.DEVICES_FILE, {'d1': {
            'id': 'd1', 'name': 'web01', 'last_seen': now, 'monitored': True,
            'sysinfo': {'proc_names': _PROCS, 'cpu': 12.5, 'mem_percent': 44.0,
                        'listening_ports': [{'port': 22, 'proto': 'tcp'}]}}})
        api._invalidate_load_cache(api.DEVICES_FILE)
        self.cap = {}
        self._orig = {k: getattr(api, k) for k in
                      ('require_auth', 'method', 'respond', '_env')}
        api.require_auth = lambda *a, **k: 'admin'
        api.method = lambda: 'GET'
        api._env = lambda k, d='': '' if k == 'QUERY_STRING' else d

        def _r(status, data=None, *a, **k):
            self.cap['s'], self.cap['d'] = status, data
            raise api.HTTPError(status, data)
        api.respond = _r

    def tearDown(self):
        for k, v in self._orig.items():
            setattr(api, k, v)

    def _rows(self):
        try:
            api.handle_devices_list()
        except (SystemExit, api.HTTPError):
            pass
        d = self.cap.get('d')
        return d if isinstance(d, list) else (d or {}).get('devices') or []


class TestTheWirePayload(_Base):
    def test_proc_names_is_not_transmitted(self):
        rows = self._rows()
        self.assertTrue(rows, 'the handler returned no devices')
        self.assertNotIn('proc_names', rows[0].get('sysinfo') or {},
                         'proc_names is ~a third of a 400-device roster and no '
                         'client reads it')

    def test_the_rest_of_sysinfo_survives(self):
        """The positive control. Dropping sysinfo wholesale would satisfy the
        test above and break every device card."""
        si = self._rows()[0].get('sysinfo') or {}
        self.assertEqual(si.get('cpu'), 12.5)
        self.assertEqual(si.get('mem_percent'), 44.0)
        self.assertTrue(si.get('listening_ports'))

    def test_the_saving_is_real(self):
        """Measured, not asserted in the abstract — if the omission list ever
        stops being applied this catches it as a size regression."""
        with_it = len(json.dumps(
            (api.load(api.DEVICES_FILE) or {})['d1']['sysinfo']))
        without = len(json.dumps(self._rows()[0].get('sysinfo') or {}))
        self.assertLess(without, with_it * 0.6,
                        f'roster sysinfo is {without}B vs {with_it}B stored — '
                        'the omission is not being applied')


class TestTheStoreIsUntouched(_Base):
    """The safety argument. Checks, RAG and _eval_custom_check read proc_names
    from the device RECORD; if this change had removed it from storage it would
    have silently disabled every process custom-check."""

    def test_proc_names_is_still_stored(self):
        self._rows()
        si = (api.load(api.DEVICES_FILE) or {})['d1']['sysinfo']
        self.assertEqual(si.get('proc_names'), _PROCS)

    def test_a_process_check_can_still_evaluate(self):
        """Drives the real consumer rather than trusting that the store looks
        right."""
        import checks
        fn = getattr(checks, '_eval_custom_check', None) or \
            getattr(api, '_eval_custom_check', None)
        if fn is None:
            self.skipTest('_eval_custom_check not exposed under either name')
        dev = (api.load(api.DEVICES_FILE) or {})['d1']
        status, _out = fn({'type': 'process', 'target': 'nginx'}, dev)
        self.assertEqual(status, 'ok', 'a process check stopped seeing '
                                       'proc_names after the roster trim')


class TestListeningPortsWasNotTouched(_Base):
    """The recon called the top-level field a duplicate of sysinfo's. It is
    not — it prefers the port-BASELINE store and only falls back to sysinfo, so
    the two differ whenever a baseline exists. Pinned so a later cleanup does
    not 'finish the job' and silently change what the field means."""

    def test_the_top_level_field_is_still_present(self):
        self.assertIn('listening_ports', self._rows()[0])

    def test_it_prefers_the_baseline_store(self):
        api.save(api.PORT_BASELINE_FILE, {'d1': [{'port': 9999, 'proto': 'tcp'}]})
        api._invalidate_load_cache(api.PORT_BASELINE_FILE)
        row = self._rows()[0]
        self.assertEqual(row['listening_ports'][0]['port'], 9999,
                         'the top-level field is NOT a copy of sysinfo — it is '
                         'the port baseline when one exists')
        self.assertEqual((row.get('sysinfo') or {})['listening_ports'][0]['port'], 22)


if __name__ == '__main__':
    unittest.main()
