#!/usr/bin/env python3
"""Strict version-surface pins + regression guards for v4.6.1 (patch).

v4.6.1 is a stability/hardening patch on top of v4.6.0 "RepellantMatters",
bundling five fixes:
  1. SCGI worker: grant CAP_NET_RAW so agentless ICMP ping works under the
     persistent worker (NoNewPrivileges otherwise blocks ping's elevation).
  2. SCGI worker: Postgres connection fork-safety (PID-guarded reconnect) —
     fixes "consuming input failed: EOF detected" when a forked child inherits
     the parent's psycopg connection.
  3. Security: ReDoS in _valid_tls_host — label-by-label validation instead of
     a nested-quantifier regex that backtracked catastrophically.
  4. Security: coerce the package "upgradable" count to a number/'?' before it
     reaches innerHTML (CodeQL #42 — defence-in-depth against DOM XSS).
  5. UI: page subtitle no longer flashes as raw text on reload (FOUC) — hidden
     by default in CSS, revealed inline (old UI) via .subtitle-shown.

Loosen the TestVersionBumps strict pins to regex on the next bump (see
tests/test_v460.py for the pattern).
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
_spec = importlib.util.spec_from_file_location("api_v461", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_HTML = (_ROOT / "server/html/index.html").read_text()
_CSS = (_ROOT / "server/html/static/css/styles.css").read_text()
_JS = (_ROOT / "server/html/static/js/app.js").read_text()


class TestVersionBumps(unittest.TestCase):
    """v4.6.1 — loosened to regex on the v4.7.0 bump (live strict pins moved to
    tests/test_v470.py). The regression tests below stay version-agnostic."""

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
        self.assertRegex(_HTML, r'\?v=\d+\.\d+\.\d+')

    def test_doc_set_keeps_five_versions(self):
        vdocs = sorted(p.name for p in (_ROOT / 'docs').glob('v[0-9]*.md'))
        self.assertEqual(len(vdocs), 5, f'expected exactly 5 version docs, got {vdocs}')


class TestScgiWorkerCapNetRaw(unittest.TestCase):
    """Fix 1: the SCGI worker unit must grant CAP_NET_RAW ambiently so ping works."""

    def test_unit_grants_cap_net_raw(self):
        unit = (_ROOT / 'server/conf/remotepower-api.service').read_text()
        self.assertIn('AmbientCapabilities=CAP_NET_RAW', unit)
        # and still keeps the hardening it pairs with
        self.assertIn('NoNewPrivileges=true', unit)


class TestPostgresForkSafety(unittest.TestCase):
    """Fix 2: storage_pg must drop a connection inherited across fork (PID guard)."""

    def test_pid_guarded_reconnect(self):
        src = (_CGI / 'storage_pg.py').read_text()
        # v6.0.0: connections are cached per-thread (threading.local); both the
        # write and read paths still track the owning PID so a connection inherited
        # across fork is dropped + reopened in the child.
        self.assertIn('_LOCAL = threading.local()', src)
        self.assertIn('conn_pid', src)
        self.assertIn('read_pid', src)
        self.assertRegex(src, r"getattr\(_LOCAL, 'conn_pid', None\)\s*!=\s*os\.getpid\(\)")
        self.assertRegex(src, r"getattr\(_LOCAL, 'read_pid', None\)\s*!=\s*os\.getpid\(\)")


class TestTlsHostReDoS(unittest.TestCase):
    """Fix 3: _valid_tls_host validates label-by-label, no catastrophic backtracking."""

    def test_accepts_valid_hosts(self):
        for h in ('rp.internal', 'a.b.c.example.com', '10.0.0.5', 'host', 'h-1.dev', 'x.'):
            self.assertTrue(api._valid_tls_host(h), h)

    def test_rejects_bad_hosts(self):
        for h in ('bad;rm -rf /', 'a b', '', 'a..b', '-lead.com', 'trail-.com',
                  'a' * 64 + '.com'):
            self.assertFalse(api._valid_tls_host(h), h)

    def test_validates_label_by_label(self):
        # the linear replacement iterates labels with a fixed-shape per-label
        # regex (no whole-host nested quantifier).
        src = (_CGI / 'api.py').read_text()
        m = re.search(r'def _valid_tls_host\(.*?\):(.*?)\ndef ', src, re.S)
        self.assertIsNotNone(m)
        body = m.group(1)
        self.assertIn('split(', body)                       # iterates labels
        self.assertIn('{0,61}', body)                       # per-label matcher

    def test_no_catastrophic_backtracking(self):
        # a long all-hyphen string used to hang the old regex; it must return fast.
        import time
        evil = 'a' + '-' * 5000 + '!'
        t0 = time.time()
        self.assertFalse(api._valid_tls_host(evil))
        self.assertLess(time.time() - t0, 0.5, 'validation took too long (ReDoS?)')


class TestUpgradableCountCoerced(unittest.TestCase):
    """Fix 4: the package upgradable count is coerced before reaching innerHTML."""

    def test_upgradable_is_number_guarded(self):
        self.assertRegex(
            _JS, r"typeof\s+pkg\.upgradable\s*===\s*'number'\s*\)\s*\?\s*pkg\.upgradable\s*:\s*'\?'")


class TestSubtitleFoucFix(unittest.TestCase):
    """Fix 5: page subtitle hidden by default (no reload flash), revealed inline."""

    def test_css_hides_subtitle_by_default(self):
        flat = _CSS.replace(' ', '')
        self.assertIn('.page-subtitle{display:none;}', flat)
        self.assertIn('.page-subtitle.subtitle-shown{display:block;}', flat)

    def test_js_reveals_via_subtitle_shown(self):
        # v6.0.0: subtitles are ALWAYS revealed inline (the v4.6.0 fold-into-
        # info-icon path is gone), so the FOUC guarantee is now trivial: the
        # function unconditionally adds .subtitle-shown with no early return
        # before it (no title lookup exists any more).
        m = re.search(r'function _applyPageSubtitleInfo\(\)\s*\{(.*?)\n\}', _JS, re.S)
        self.assertIsNotNone(m)
        body = m.group(1)
        self.assertIn("classList.add('subtitle-shown')", body)
        self.assertNotIn('let titleEl', body)     # the fold path is gone
        self.assertNotIn('return', body.split("classList.add('subtitle-shown')")[0],
                         'nothing may return before visibility is set')


if __name__ == '__main__':
    unittest.main()
