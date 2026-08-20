#!/usr/bin/env python3
"""The portal CSP endpoint wrote attacker-controlled text to the journal.

`handle_portal_csp_report` did `sys.stdin.read(8192)` and wrote the raw body to
stderr — the server journal. Unauthenticated (it has to be; browsers send these
fire-and-forget), unthrottled, with no operator toggle and no filtering. Anyone
who could reach the portal could write to the journal as fast as they could
POST, and choose what appeared there.

Its sibling `handle_csp_report` had solved all of that in v3.0.6: a size cap,
the `csp_report_logging` toggle, a per-IP per-minute throttle, the
browser-extension noise filter, and a structured audit_log entry the Settings →
Security counter reads. Two handlers for the same W3C payload and only one was
hardened — the half-applied-rule shape, where the hardened one makes the file
read as though the rule is in force.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(_ROOT / 'tests'))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-pcsp-'))
_spec = importlib.util.spec_from_file_location('api_portal_csp', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import srcpin                                                    # noqa: E402


class TestItNoLongerWritesRawToTheJournal(unittest.TestCase):

    def setUp(self):
        import ast
        raw = srcpin.py_function((_CGI / 'api.py').read_text(),
                                 'handle_portal_csp_report')
        self.body = raw
        # Assert against CODE, not prose. The docstring below explains the fix
        # by quoting the very call it removed, so a plain substring search over
        # the function reports the bug as still present. Strip the docstring and
        # every comment line first.
        fd = ast.parse(raw).body[0]
        if (fd.body and isinstance(fd.body[0], ast.Expr)
                and isinstance(fd.body[0].value, ast.Constant)):
            fd.body = fd.body[1:]
        self.code = ast.unparse(ast.Module(body=[fd], type_ignores=[]))

    def test_the_docstring_still_explains_the_fix(self):
        """Control for the stripping above: if the docstring vanished, the two
        checks below would pass for the wrong reason."""
        self.assertIn('sys.stdin.read', self.body)
        self.assertNotIn('sys.stdin.read', self.code)

    def test_no_raw_stderr_write(self):
        self.assertNotIn('sys.stderr.write', self.code)

    def test_it_does_not_read_stdin_itself(self):
        """Reading the body outside the shared path skips the size accounting
        and the toggle that path performs first."""
        self.assertNotIn('sys.stdin.read', self.code)

    def test_it_delegates_to_the_hardened_handler(self):
        self.assertIn("handle_csp_report(source='portal')", self.code)


class TestBothEndpointsShareTheProtections(unittest.TestCase):
    """The point is not that the portal handler has SOME protection — it is
    that there is one implementation, so the two cannot diverge again."""

    def setUp(self):
        self.shared = srcpin.py_function((_CGI / 'api.py').read_text(),
                                         'handle_csp_report')

    def test_the_shared_path_still_has_each_protection(self):
        for marker, why in (
                ('_CSP_REPORT_MAX_BYTES', 'size cap'),
                ('csp_report_logging', 'operator toggle'),
                ('_csp_report_should_throttle', 'per-IP throttle'),
                ('_CSP_EXTENSION_SCHEMES', 'browser-extension noise filter'),
                ('audit_log(', 'structured audit entry')):
            with self.subTest(protection=why):
                self.assertIn(marker, self.shared)

    def test_the_shared_path_takes_a_source(self):
        self.assertIn("def handle_csp_report(source='app')", self.shared)

    def test_the_audit_detail_records_which_endpoint(self):
        """Otherwise portal and app reports are indistinguishable in the log,
        which matters because only one of them is reachable pre-auth."""
        self.assertIn("f'[{source}] ", self.shared)

    def test_the_action_stays_csp_report(self):
        """The Settings → Security counter scans for this action name. A new
        action for portal reports would leave them uncounted — the same
        write-to-the-wrong-store bug the v3.0.6 comment records."""
        self.assertIn("action='csp_report'", self.shared)


class TestItBehaves(unittest.TestCase):

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix='rp-pcsp-run-'))
        self._files = {n: getattr(api, n) for n in ('DATA_DIR', 'CONFIG_FILE')}
        api.DATA_DIR = self.dir
        api.CONFIG_FILE = self.dir / 'config.json'
        api.save(api.CONFIG_FILE, {})
        self.logged = []
        self._al = api.audit_log
        api.audit_log = lambda **kw: self.logged.append(kw)
        self.cap = {}
        self._resp = api.respond

        def _r(s, b=None):
            self.cap['s'] = s
            raise api.HTTPError(s, b)
        api.respond = _r
        self._env = api._env
        self._read = api._read_request_body

    def tearDown(self):
        for n, v in self._files.items():
            setattr(api, n, v)
        api.audit_log = self._al
        api.respond = self._resp
        api._env = self._env
        api._read_request_body = self._read

    def _post(self, raw, length=None, ip='203.0.113.9'):
        payload = raw.encode()
        env = {'CONTENT_LENGTH': str(length if length is not None else len(payload)),
               'REMOTE_ADDR': ip, 'HTTP_REFERER': 'https://portal.example.com/'}
        api._env = lambda k, d='': env.get(k, d)
        api._read_request_body = lambda n: payload
        api._invalidate_load_cache(api.CONFIG_FILE)
        self.cap.clear()
        try:
            api.handle_portal_csp_report()
        except (api.HTTPError, SystemExit):
            pass
        return self.cap.get('s')

    def test_a_report_is_acked_and_logged_as_portal(self):
        status = self._post('{"csp-report":{"violated-directive":"script-src",'
                            '"blocked-uri":"https://evil.example/x.js"}}')
        self.assertEqual(204, status)
        self.assertEqual(1, len(self.logged))
        self.assertEqual('csp_report', self.logged[0]['action'])
        self.assertIn('[portal]', self.logged[0]['detail'])
        self.assertIn('script-src', self.logged[0]['detail'])

    def test_an_oversized_body_is_dropped_without_logging(self):
        status = self._post('x' * 100, length=api._CSP_REPORT_MAX_BYTES + 1)
        self.assertEqual(204, status)
        self.assertEqual([], self.logged,
                         'an oversized body still reached the log')

    def test_the_operator_toggle_silences_it(self):
        api.save(api.CONFIG_FILE, {'csp_report_logging': False})
        status = self._post('{"csp-report":{"violated-directive":"img-src"}}')
        self.assertEqual(204, status)
        self.assertEqual([], self.logged)

    def test_a_flood_from_one_ip_is_throttled(self):
        api.save(api.CONFIG_FILE, {'csp_report_throttle_per_minute': 3})
        for _ in range(12):
            self._post('{"csp-report":{"violated-directive":"style-src"}}')
        self.assertLessEqual(len(self.logged), 3,
                             f'{len(self.logged)} entries written despite a '
                             f'cap of 3 — an unauthenticated caller can still '
                             f'flood the journal')

    def test_an_extension_violation_is_dropped(self):
        self._post('{"csp-report":{"violated-directive":"script-src",'
                   '"blocked-uri":"moz-extension://abc/inject.js"}}')
        self.assertEqual([], self.logged)

    def test_the_response_is_always_204(self):
        """Browsers send these fire-and-forget; anything else pollutes the
        user's console with a secondary failure."""
        for raw in ('', 'not json at all', '{"csp-report":{}}', '[]'):
            with self.subTest(body=raw[:20]):
                self.assertEqual(204, self._post(raw))


if __name__ == '__main__':
    unittest.main()
