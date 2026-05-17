#!/usr/bin/env python3
"""
Tests for v2.4.1 — stale-cache severity bug.

The bug: a `cve_details_cache.json` written by a pre-2.3.4
RemotePower carries a `severity` from the old buggy classifier and
NO `severity_source` field. The TTL-only refresh gate never
re-fetched such an entry while it was within TTL, so the stale
(wrong, often "critical") severity was re-served on every scan —
and `severity_source` came back "unknown".

The fix: an entry lacking `severity_source` is treated as stale
regardless of TTL and re-fetched + re-classified.

These tests drive scan_device with the network calls stubbed, so
no OSV traffic happens.
"""

import importlib.util
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT    = Path(__file__).parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

_sc = importlib.util.spec_from_file_location("cve_v241", _CGI_BIN / "cve_scanner.py")
cve = importlib.util.module_from_spec(_sc)
_sc.loader.exec_module(cve)


class TestStaleCacheRefetch(unittest.TestCase):

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        # Stub OSV: one package, one vuln id.
        self._fetched = []

        def fake_querybatch(batch):
            return [{'vulns': [{'id': 'DEBIAN-CVE-2024-36357'}]}
                    for _ in batch]

        def fake_details(vid):
            # Record that a network re-fetch happened, return a vuln
            # whose CVSS is genuinely MEDIUM.
            self._fetched.append(vid)
            return {
                'id': vid,
                'summary': 'fresh',
                'severity': [{'type': 'CVSS_V3',
                              'score': 'CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N'}],
            }

        cve._osv_querybatch = fake_querybatch
        cve._osv_vuln_details = fake_details

    def _scan(self):
        return cve.scan_device(
            'dev1',
            [{'name': 'amd64-microcode', 'version': '3.20250311.1~deb12u1'}],
            'Debian:12', self._tmp, cache_ttl=86400)

    def test_pre234_entry_is_refetched_despite_fresh_ttl(self):
        # Seed a cache entry as a PRE-2.3.4 version would: a stale
        # 'critical' severity, NO severity_source, cached_at = now
        # (well within TTL).
        cache = {'DEBIAN-CVE-2024-36357': {
            'summary': 'stale', 'details': '',
            'severity': 'critical',          # the old buggy value
            # NOTE: no 'severity_source' key — this is the tell
            'aliases': [], 'published': '', 'modified': '', 'refs': [],
            'cached_at': int(time.time()),   # FRESH — within TTL
            'fixed_versions': {},
        }}
        (self._tmp / 'cve_details_cache.json').write_text(json.dumps(cache))

        result = self._scan()

        # The stale entry must have been re-fetched despite being
        # within TTL...
        self.assertIn('DEBIAN-CVE-2024-36357', self._fetched,
                      'pre-2.3.4 cache entry was NOT re-fetched')
        # ...and re-classified to the correct severity + a real source.
        finding = result['findings'][0]
        self.assertNotEqual(finding['severity'], 'critical',
                            'stale critical severity was re-served')
        self.assertNotEqual(finding['severity_source'], 'unknown')
        self.assertEqual(finding['severity_source'], 'cvss_v3')

    def test_current_entry_with_source_is_kept(self):
        # A 2.3.4+ entry (HAS severity_source) that is fresh must NOT
        # be re-fetched — the fix must not defeat the cache entirely.
        cache = {'DEBIAN-CVE-2024-36357': {
            'summary': 'current', 'details': '',
            'severity': 'medium',
            'severity_source': 'cvss_v3',    # present → modern entry
            'aliases': [], 'published': '', 'modified': '', 'refs': [],
            'cached_at': int(time.time()),
            'fixed_versions': {},
        }}
        (self._tmp / 'cve_details_cache.json').write_text(json.dumps(cache))

        result = self._scan()

        self.assertNotIn('DEBIAN-CVE-2024-36357', self._fetched,
                         'a fresh modern cache entry was needlessly re-fetched')
        self.assertEqual(result['findings'][0]['severity'], 'medium')

    def test_expired_modern_entry_is_refetched(self):
        # A 2.3.4+ entry that HAS aged past the TTL is still refreshed.
        cache = {'DEBIAN-CVE-2024-36357': {
            'summary': 'old', 'details': '',
            'severity': 'medium', 'severity_source': 'cvss_v3',
            'aliases': [], 'published': '', 'modified': '', 'refs': [],
            'cached_at': int(time.time()) - 999999,   # long expired
            'fixed_versions': {},
        }}
        (self._tmp / 'cve_details_cache.json').write_text(json.dumps(cache))

        self._scan()
        self.assertIn('DEBIAN-CVE-2024-36357', self._fetched)


if __name__ == '__main__':
    unittest.main(verbosity=2)
