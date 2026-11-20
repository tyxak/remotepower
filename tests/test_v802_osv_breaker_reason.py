"""A host skipped while the OSV breaker is open says why the breaker opened (8.0.2)."""
import sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))
import cve_scanner as cs


class BreakerReason(unittest.TestCase):
    def test_skip_names_the_last_failure(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            for _ in range(cs.OSV_FAIL_THRESHOLD):
                cs.osv_breaker_record(d, ok=False, error=ValueError('an OSV answer is not a list of advisories'))
            self.assertTrue(cs.osv_breaker_open(d))
            r = cs.scan_device('h1', [{'name': 'bash', 'version': '5.1'}], 'Debian:12', d)
            self.assertTrue(r.get('skipped'))
            self.assertIn('circuit breaker open', r['error'])
            self.assertIn('ValueError: an OSV answer is not a list of advisories', r['error'])

    def test_success_clears_it(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            for _ in range(cs.OSV_FAIL_THRESHOLD):
                cs.osv_breaker_record(d, ok=False, error=OSError('timed out'))
            cs.osv_breaker_record(d, ok=True)
            self.assertFalse(cs.osv_breaker_open(d))
            self.assertNotIn('last_error', cs._load_json(cs._breaker_path(d)))


if __name__ == '__main__':
    unittest.main()
