#!/usr/bin/env python3
"""No outbound opener may keep urllib's file/ftp/data handlers.

`urllib.request.build_opener()` ALWAYS installs its default handler set, and
passing custom HTTP/HTTPS handlers replaces only those two. `FileHandler`,
`FTPHandler` and `DataHandler` survive. So every opener in this codebase — each
one built specifically to constrain where a request may go — would happily open
`file:///etc/shadow`.

That was found by DRIVING an opener of the same shape and reading the file back,
not by reading the code. The code looks right: each site passes exactly the
guarded handlers it means to use, and the extra three arrive from a default the
call does not mention.

Six sites had it, which is why the fix is one shared helper rather than a sixth
copy of the same three lines. A rule applied in five places and missed in one is
this project's most reliable source of security findings.

This is defence in depth and is described that way in the security review: the
callers run a pre-flight that rejects such URLs, so no reachable path is known.
It belongs at the opener because these objects are handed to connectors,
monitors and integrations that each decide what to fetch, and defence that
depends on every caller remembering a check is defence that eventually fails.
"""
import os
import ssl
import sys
import tempfile
import unittest
import urllib.request
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-opener-'))

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

import safe_opener  # noqa: E402

_LOCAL = ('file', 'ftp', 'data')


class TestTheHelperItself(unittest.TestCase):

    def test_a_plain_opener_really_does_carry_them(self):
        """POSITIVE CONTROL, and the whole reason this file exists. If urllib
        ever stops installing these by default, every assertion below becomes
        vacuously true and this test says so first."""
        plain = urllib.request.build_opener()
        self.assertTrue(
            any(s in plain.handle_open for s in _LOCAL),
            'urllib no longer installs file/ftp/data by default — the '
            'assertions in this file no longer prove anything')

    def test_the_helper_removes_them(self):
        op = safe_opener.strip_local_schemes(urllib.request.build_opener())
        for s in _LOCAL:
            self.assertNotIn(s, op.handle_open, s)

    def test_http_and_https_survive(self):
        """Removing too much would break every outbound feature in the product,
        and would also make the assertion above pass."""
        op = safe_opener.strip_local_schemes(urllib.request.build_opener())
        self.assertIn('http', op.handle_open)
        self.assertIn('https', op.handle_open)

    def test_opening_a_readable_local_file_is_refused(self):
        """Drive it. The control proves the file is readable, so the refusal is
        the guard working rather than the file being absent."""
        probe = '/etc/hostname'
        if not os.path.isfile(probe):
            self.skipTest('no /etc/hostname on this box')
        with open(probe) as fh:
            self.assertTrue(fh.read(), 'control file empty')
        op = safe_opener.strip_local_schemes(urllib.request.build_opener())
        with self.assertRaises(Exception):
            op.open(f'file://{probe}', timeout=3)


class TestEveryShippedOpenerIsStripped(unittest.TestCase):
    """Drives each real module's opener rather than grepping for the call."""

    def _openers(self):
        import importlib
        ctx = ssl.create_default_context()
        out = {}
        for mod in ('routeros', 'opnsense', 'proxmox_client', 'ai_provider',
                    'cve_scanner'):
            m = importlib.import_module(mod)
            op = getattr(m, '_OPENER', None)
            if op is None:
                factory = getattr(m, '_ssrf_opener', None)
                self.assertIsNotNone(
                    factory, f'{mod}: no opener found — cannot verify it')
                op = factory(ctx)
            out[mod] = op
        return out

    def test_all_five_refuse_local_schemes(self):
        openers = self._openers()
        self.assertEqual(len(openers), 5,
                         'not every module yielded an opener — a silent skip '
                         'here would report a clean sweep over nothing')
        for mod, op in openers.items():
            for s in _LOCAL:
                self.assertNotIn(s, op.handle_open, f'{mod} still opens {s}:')

    def test_all_five_still_do_http(self):
        for mod, op in self._openers().items():
            self.assertIn('https', op.handle_open, mod)

    def test_the_api_opener_is_stripped_too(self):
        import api
        op = api._ssrf_safe_opener()
        for s in _LOCAL:
            self.assertNotIn(s, op.handle_open, f'api.py opener opens {s}:')
        self.assertIn('https', op.handle_open)


if __name__ == '__main__':
    unittest.main()
