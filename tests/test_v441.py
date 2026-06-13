#!/usr/bin/env python3
"""Strict version-surface pins + regression guards for v4.4.1
"DocumentationMatters".

This is a documentation-and-triage release: it resolves the open CodeQL
code-scanning alerts (all false positives) and applies two no-behaviour
weak-hash annotations. The tests below pin the version surface strictly and
guard the cheap hardening + the doc-housekeeping invariants.

Loosen the TestVersionBumps strict pins to regex on the next bump (see
tests/test_v440.py for the pattern).
"""
import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v441", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestVersionBumps(unittest.TestCase):
    """v4.4.1 — loosened to regex on the v4.5.0 bump (the live strict pins moved
    to tests/test_v450.py); a later bump must not fail this file. The
    doc-housekeeping invariants below are version-agnostic and stay."""

    def test_server_version(self):
        self.assertRegex(api.SERVER_VERSION, r'^\d+\.\d+\.\d+$')

    def test_agent_versions(self):
        self.assertRegex((_ROOT / 'client/remotepower-agent.py').read_text(),
                         r"\nVERSION\s*=\s*'\d+\.\d+\.\d+'")
        for rel in ('client/remotepower-agent-win.py', 'client/remotepower-agent-mac.py'):
            self.assertRegex((_ROOT / rel).read_text(),
                             r"VERSION\s*=\s*'\d+\.\d+\.\d+'", rel)

    def test_agent_extensionless_in_sync(self):
        self.assertEqual((_ROOT / 'client/remotepower-agent.py').read_bytes(),
                         (_ROOT / 'client/remotepower-agent').read_bytes())

    def test_sw_and_cachebust(self):
        self.assertRegex((_ROOT / 'server/html/sw.js').read_text(),
                         r'remotepower-shell-v\d+\.\d+\.\d+')
        self.assertRegex((_ROOT / 'server/html/index.html').read_text(),
                         r'\?v=\d+\.\d+\.\d+')

    def test_doc_set_keeps_five_versions(self):
        vdocs = sorted(p.name for p in (_ROOT / 'docs').glob('v*.md'))
        self.assertEqual(len(vdocs), 5, f'expected exactly 5 version docs, got {vdocs}')

    def test_oldest_version_doc_rotated_out(self):
        self.assertFalse((_ROOT / 'docs/v4.0.0.md').exists(),
                         'v4.0.0.md should have rotated out of the kept set')

    def test_security_reviews_keep_three(self):
        revs = sorted(p.name for p in (_ROOT / 'docs').glob('security-review-*.md'))
        self.assertEqual(len(revs), 3, f'expected exactly 3 security reviews, got {revs}')

    def test_whats_new_cards_capped_at_five(self):
        idx = (_ROOT / 'server/html/index.html').read_text()
        cards = re.findall(r"What's new — v[0-9.]+", idx)
        self.assertEqual(len(cards), 5, f'expected exactly 5 What\'s-new cards, got {cards}')


class TestNoDanglingReviewLinks(unittest.TestCase):
    """Doc-housekeeping: nothing may link to the rotated-out v4.2.0 review or
    the rotated-out v4.0.0 version doc."""

    def _shipped_docs(self):
        for p in list((_ROOT / 'docs').rglob('*.md')) + \
                 list((_ROOT / 'docs').rglob('*.html')) + \
                 [_ROOT / 'README.md']:
            # the gitignored internal notes are not shipped
            if '-internal' in p.name:
                continue
            yield p

    def test_no_link_to_deleted_security_review(self):
        for p in self._shipped_docs():
            self.assertNotIn('security-review-4.2.0', p.read_text(),
                             f'{p} links the deleted 4.2.0 review')

    def test_no_link_to_deleted_version_doc(self):
        # CHANGELOG may keep historical "See docs/vX.md" pointers; everything
        # else must not link the rotated-out v4.0.0.md.
        for p in self._shipped_docs():
            if p.name == 'CHANGELOG.md':
                continue
            self.assertNotIn('v4.0.0.md', p.read_text(),
                             f'{p} links the rotated-out v4.0.0.md')


class TestWeakHashHardening(unittest.TestCase):
    """v4.4.1: every hashlib.md5 / hashlib.sha1 call in api.py is a non-security
    identity/cache hash and must carry usedforsecurity=False so CodeQL's
    weak-hash query agrees (the two MD5 fleet-checks fingerprints were the gap)."""

    def _hash_calls(self):
        src = (_CGI / 'api.py').read_text()
        # match a hashlib.md5(/sha1( call and the following ~6 lines (these
        # calls span several lines), capturing up to the closing ).hexdigest
        for m in re.finditer(r'hashlib\.(md5|sha1)\(', src):
            chunk = src[m.start():m.start() + 400]
            # cut at the first .hexdigest( after the open
            cut = chunk.find('.hexdigest(')
            yield chunk[:cut + 11] if cut != -1 else chunk

    def test_all_weak_hashes_marked_non_security(self):
        calls = list(self._hash_calls())
        self.assertGreaterEqual(len(calls), 4, 'expected to find the known weak-hash calls')
        for call in calls:
            self.assertIn('usedforsecurity=False', call,
                          f'weak-hash call missing usedforsecurity=False:\n{call}')


class TestSanitizersExist(unittest.TestCase):
    """The XSS CodeQL alerts are false positives because every innerHTML value
    goes through these sanitizers — guard that they still exist and neutralise
    the HTML-breaking characters."""

    def test_eschtml_and_escattr_defined(self):
        app = (_ROOT / 'server/html/static/js/app.js').read_text()
        self.assertIn('function escHtml(', app)
        self.assertIn('function escAttr(', app)
        # escHtml entity-encodes the angle brackets and quotes
        m = re.search(r'function escHtml\(s\)\s*\{[^}]*\}', app)
        self.assertIsNotNone(m)
        body = m.group(0)
        for needle in ('&lt;', '&gt;', '&quot;', '&amp;'):
            self.assertIn(needle, body)


if __name__ == '__main__':
    unittest.main()
