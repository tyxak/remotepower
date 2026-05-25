#!/usr/bin/env python3
"""
Tests for v2.4.11 — two CVE-ignore fixes.

  1. The CVE "Ignore" flow used prompt() + confirm() (two native
     dialogs). Browsers throttle repeated dialogs, so after a few
     ignores prompt() returned null, ignoreCVE() silently bailed and
     the UI appeared locked. Replaced with an in-page modal.
  2. Ignored CVEs still counted toward the Needs Attention digest.
     _compute_attention() now applies the ignore list.
"""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT    = Path(__file__).parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))


class TestAttentionExcludesIgnoredCVEs(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault('REQUEST_METHOD', 'GET')
        os.environ.setdefault('PATH_INFO', '/')
        os.environ.setdefault('CONTENT_LENGTH', '0')
        _s = importlib.util.spec_from_file_location("api_v2411", _CGI_BIN / "api.py")
        cls.api = importlib.util.module_from_spec(_s)
        _s.loader.exec_module(cls.api)

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        api = self.api
        api.DEVICES_FILE = self._tmp / 'devices.json'
        api.CVE_FINDINGS_FILE = self._tmp / 'cve.json'
        api.CVE_IGNORE_FILE = self._tmp / 'cve_ignore.json'
        # _compute_attention also touches these — keep them empty.
        for f in ('UPTIME_FILE',):
            setattr(api, f, self._tmp / (f.lower() + '.json'))
        import time
        now = int(time.time())
        api.save(api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'web01',
                                           'last_seen': now}})

    def _attention_cve_items(self):
        return [i for i in self.api._compute_attention()
                if i.get('kind') == 'cve']

    def test_unignored_cve_shows(self):
        api = self.api
        api.save(api.CVE_FINDINGS_FILE, {'d1': {'findings': [
            {'vuln_id': 'CVE-2026-1', 'severity': 'critical'}]}})
        api.save(api.CVE_IGNORE_FILE, {})
        self.assertEqual(len(self._attention_cve_items()), 1)

    def test_device_scoped_ignore_excluded(self):
        api = self.api
        api.save(api.CVE_FINDINGS_FILE, {'d1': {'findings': [
            {'vuln_id': 'CVE-2026-1', 'severity': 'critical'}]}})
        api.save(api.CVE_IGNORE_FILE, {
            'CVE-2026-1': {'scope': 'd1', 'reason': '', 'actor': 'admin'}})
        self.assertEqual(self._attention_cve_items(), [],
                         'device-scoped ignored CVE still in digest')

    def test_global_ignore_excluded(self):
        api = self.api
        api.save(api.CVE_FINDINGS_FILE, {'d1': {'findings': [
            {'vuln_id': 'CVE-2026-1', 'severity': 'critical'}]}})
        api.save(api.CVE_IGNORE_FILE, {
            'CVE-2026-1': {'scope': 'global', 'reason': '', 'actor': 'admin'}})
        self.assertEqual(self._attention_cve_items(), [],
                         'globally ignored CVE still in digest')

    def test_partial_ignore_keeps_rest(self):
        # One of two findings ignored — the other still raises.
        api = self.api
        api.save(api.CVE_FINDINGS_FILE, {'d1': {'findings': [
            {'vuln_id': 'CVE-2026-1', 'severity': 'critical'},
            {'vuln_id': 'CVE-2026-2', 'severity': 'critical'}]}})
        api.save(api.CVE_IGNORE_FILE, {
            'CVE-2026-1': {'scope': 'global', 'reason': '', 'actor': 'admin'}})
        items = self._attention_cve_items()
        self.assertEqual(len(items), 1)
        self.assertIn('1 critical', items[0]['summary'])


class TestCveIgnoreModal(unittest.TestCase):
    """The ignore flow must not use native prompt()/confirm()."""

    @classmethod
    def setUpClass(cls):
        cls.js   = (_ROOT / 'server/html/static/js/app.js').read_text()
        cls.html = (_ROOT / 'server/html/index.html').read_text()

    def test_ignorecve_has_no_native_dialogs(self):
        # Isolate the ignoreCVE + _confirmCveIgnore functions and make
        # sure no prompt(/confirm( call survives (comments are fine).
        start = self.js.find('function ignoreCVE(')
        end = self.js.find('function _confirmCveIgnore')
        body = self.js[start:end]
        # Strip // comment lines before checking for live calls.
        live = '\n'.join(l for l in body.splitlines()
                          if not l.strip().startswith('//'))
        self.assertNotIn('prompt(', live)
        self.assertNotIn('confirm(', live)

    def test_confirm_function_posts_ignore(self):
        idx = self.js.find('function _confirmCveIgnore')
        self.assertGreater(idx, 0)
        chunk = self.js[idx:idx + 900]
        self.assertIn("api('POST', '/cve/ignore'", chunk)

    def test_modal_markup_present(self):
        self.assertIn('id="cve-ignore-modal"', self.html)
        self.assertIn('id="cve-ignore-reason"', self.html)
        # Both scopes must be selectable in-page.
        self.assertIn('name="cve-ignore-scope"', self.html)
        self.assertIn('value="global"', self.html)
        self.assertIn('value="device"', self.html)

    def test_confirm_button_wired(self):
        # CSP L1 (v3.0.4): inline onclick became data-action delegation.
        self.assertIn('data-action="_confirmCveIgnore"', self.html)


if __name__ == '__main__':
    unittest.main(verbosity=2)
