"""A late OSV answer is asked once more before it counts as a failure, and a request holds 100 questions, not 500 (8.0.2)."""
import io, json, sys, unittest, urllib.error
from pathlib import Path
from unittest import mock
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))
import cve_scanner as cs


class _Resp(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): return False


class Retry(unittest.TestCase):
    def _opener(self, outcomes):
        calls = []
        class O:
            def open(self, req, timeout=None):
                calls.append(timeout)
                o = outcomes[len(calls) - 1]
                if isinstance(o, Exception):
                    raise o
                return _Resp(json.dumps({'results': o}).encode())
        return O(), calls

    def test_one_timeout_is_retried(self):
        o, calls = self._opener([TimeoutError('The read operation timed out'), [{'vulns': []}]])
        with mock.patch.object(cs, '_OPENER', o):
            self.assertEqual(cs._osv_querybatch([{}]), [{'vulns': []}])
        self.assertEqual(calls, [cs.OSV_TIMEOUT, cs.OSV_TIMEOUT])

    def test_two_timeouts_raise(self):
        o, calls = self._opener([TimeoutError('x'), TimeoutError('y')])
        with mock.patch.object(cs, '_OPENER', o), self.assertRaises(TimeoutError):
            cs._osv_querybatch([{}])
        self.assertEqual(len(calls), 2)

    def test_an_http_error_is_not_asked_again(self):
        err = urllib.error.HTTPError('u', 400, 'bad', {}, None)
        o, calls = self._opener([err, [{'vulns': []}]])
        with mock.patch.object(cs, '_OPENER', o), self.assertRaises(urllib.error.HTTPError):
            cs._osv_querybatch([{}])
        self.assertEqual(len(calls), 1)

    def test_request_size_and_time(self):
        self.assertLessEqual(cs.OSV_BATCH_SIZE, 100)
        self.assertGreaterEqual(cs.OSV_TIMEOUT, 60)


if __name__ == '__main__':
    unittest.main()
