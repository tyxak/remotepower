"""v6.4.0 field bug — "Clear this log line" did nothing for long lines.

_log_alert_evidence (and the NA-item / fleet-event sample) truncated the
clearable sample to [:200], but the eval path matches the FULL line (capped at
1024 at ingest; logsig.normalize reads up to 1000 chars). So for any log line
longer than ~200 chars, the operator cleared a 200-char-truncated line whose
signature differed from the raw line the rule kept matching — the clear stored,
resolved the open alert, then the very next batch re-fired. Reported live on
tviapp01 (dockerd ShouldRestart, ~260 chars). Fixed by keeping the clearable
sample at full signature fidelity (1024); display sites truncate separately.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(CGI))

LONG = ('2026-07-23T03:01:40+02:00 tviapp01.tvipper.com dockerd[1368]: '
        'time="2026-07-23T03:01:40.526366842+02:00" level=warning '
        'msg="ShouldRestart failed, container will not be restarted, giving up" '
        'container=9f8e7d6c5b4a3210fedcba98765432100fedcba987654321 daemon=true')


def _fresh_api():
    os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-v640-lc-')
    spec = importlib.util.spec_from_file_location('api_v640_lc', CGI / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestLongLineClear(unittest.TestCase):
    def setUp(self):
        self.api = _fresh_api()
        self.assertGreater(len(LONG), 200, 'fixture must exceed the old truncation')

    def test_evidence_sample_keeps_signature_fidelity(self):
        import logsig
        payload = {'device_id': 'd', 'unit': 'docker.service',
                   'pattern': 'ShouldRestart', 'sample': [LONG], 'ts': 0}
        samples, _ = self.api._log_alert_evidence(payload, [None])
        # the clearable sample must hash to the SAME signature as the full line
        self.assertEqual(logsig.signature(samples[0]), logsig.signature(LONG))

    def test_clearing_a_long_line_actually_suppresses_it(self):
        api = self.api
        dev, unit = 'tviapp01', 'docker.service'
        api.save(api.DEVICES_FILE, {dev: {'name': 'tviapp01', 'tenant': 'default', 'token': 't'}})
        api._LOAD_CACHE.clear()
        # the sample the UI would hand back (via _log_alert_evidence)
        samples, _ = api._log_alert_evidence(
            {'device_id': dev, 'unit': unit, 'pattern': 'ShouldRestart',
             'sample': [LONG], 'ts': 0}, [None])
        clearable = samples[0]

        api.verify_token = lambda tok=None: ('op', 'admin')
        api.get_token_from_request = lambda: 'x'
        api.require_write_role = lambda *a, **k: 'op'
        api.require_auth = lambda *a, **k: ('op', 'admin')
        api._caller_role = lambda: 'admin'
        api.method = lambda: 'POST'
        api.audit_log = lambda *a, **k: None

        def _r(s, d=None, headers=None):
            raise api.HTTPError(s, d)
        api.respond = _r
        api.get_json_obj = lambda: {'line': clearable, 'device_id': dev,
                                    'unit': unit, 'scope': 'device', 'days': 0}
        api._read_valid = lambda *a, **k: api.get_json_obj()
        try:
            api.handle_log_ack_add()
        except api.HTTPError:
            pass
        api._LOAD_CACHE.clear()
        kept, hits = api.filter_acked_lines(dev, unit, [LONG])
        self.assertEqual(hits, 1)
        self.assertEqual(kept, [])   # the full long line is now suppressed


if __name__ == '__main__':
    unittest.main()
