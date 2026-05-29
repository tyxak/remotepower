#!/usr/bin/env python3
"""
Tests for v2.1.5 — silenced routine logs, additional AI system prompts.

The markdown renderer itself is JS and lives in app.js; we don't have a
JS test runner in this project so it's verified by manual inspection.
The Python-side changes (env-gated logging + new prompts) are tested
here.
"""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_CGI_BIN = Path(__file__).parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

import ai_provider


class TestNewSystemPrompts(unittest.TestCase):
    """v2.1.5 added 4 new system prompts for additional ✨ surfaces.
    These must exist with non-trivial content."""

    NEW_KEYS = ('diagnose_service', 'explain_tls', 'prioritise_patches',
                'explain_container_logs')

    def test_all_present(self):
        for key in self.NEW_KEYS:
            self.assertIn(key, ai_provider.SYSTEM_PROMPTS, f'missing {key}')

    def test_non_trivial(self):
        for key in self.NEW_KEYS:
            prompt = ai_provider.SYSTEM_PROMPTS[key]
            self.assertGreater(len(prompt), 100,
                               f'{key} prompt suspiciously short')
            # Must reference its domain
            domain_words = {
                'diagnose_service':         ['service', 'system'],
                'explain_tls':              ['cert', 'TLS'],
                'prioritise_patches':       ['update', 'package'],
                'explain_container_logs':   ['container', 'log'],
            }
            for word in domain_words[key]:
                # Case-insensitive match — prompts are prose
                self.assertIn(word.lower(), prompt.lower(),
                              f'{key} prompt should mention {word!r}')


class TestEnvGatedLogging(unittest.TestCase):
    """v2.1.5: routine heartbeat / lock_wait logs default silent.
    Reading api.py textually because the logging happens inside hot-path
    functions that are hard to unit-test in isolation; verifying the
    env-var gate exists in source is the cheapest signal."""

    def setUp(self):
        self.api_src = (_CGI_BIN / 'api.py').read_text()

    def test_heartbeat_log_is_env_gated(self):
        # The per-request heartbeat line must sit behind an env var check
        # so it's silent by default. Looking for the comment marker
        # and the os.environ check together.
        self.assertIn("RP_LOG_HEARTBEATS", self.api_src)
        # And the actual stderr.write for the per-request heartbeat
        # should not appear unconditionally — verify the env-gate is
        # in the same function. We grep for the gate near a stderr
        # write line containing "heartbeat dev=".
        idx = self.api_src.find('heartbeat dev=')
        self.assertGreater(idx, 0, '"heartbeat dev=" log not found')
        # 200 chars before that line should contain the env check
        preamble = self.api_src[max(0, idx - 200):idx]
        self.assertIn("RP_LOG_HEARTBEATS", preamble,
                      'heartbeat log not env-gated')

    def test_lock_wait_log_is_env_gated(self):
        self.assertIn("RP_LOG_LOCK_WAITS", self.api_src)
        # Both NB and blocking lock_wait sites should be gated. They
        # appear in different places so check the count.
        gate_count = self.api_src.count("RP_LOG_LOCK_WAITS")
        self.assertGreaterEqual(gate_count, 2,
                                'both NB + blocking lock_wait logs should be gated')

    def test_heartbeat_busy_log_is_env_gated(self):
        # The "heartbeat 202" busy-retry log should also be gated —
        # it's just as spammy as the regular heartbeat under load.
        # NB: search for the unique log-line marker, not the bare phrase
        # which also appears in the comment above.
        idx = self.api_src.find('[remotepower] heartbeat 202')
        self.assertGreater(idx, 0, '"[remotepower] heartbeat 202" log not found')
        preamble = self.api_src[max(0, idx - 400):idx]
        self.assertIn("RP_LOG_HEARTBEATS", preamble,
                      'heartbeat 202 log not env-gated')

    def test_offline_online_logs_unconditional(self):
        # State-change logs (OFFLINE / ONLINE transitions) are the
        # exception — those stay unconditional even after this change,
        # because they're rare and operationally important.
        offline_idx = self.api_src.find('OFFLINE dev=')
        self.assertGreater(offline_idx, 0)
        # The 200 chars before the OFFLINE line should NOT contain
        # an RP_LOG_HEARTBEATS gate — these are state changes, not
        # routine traffic.
        # (We look at the very-immediate preceding line context only,
        # because the env-gate for routine logs lives elsewhere in
        # the same file.)
        line_start = self.api_src.rfind('\n', 0, offline_idx)
        immediate = self.api_src[max(0, line_start - 50):offline_idx]
        self.assertNotIn("RP_LOG_HEARTBEATS", immediate)


class TestHtmlIdReferences(unittest.TestCase):
    """v2.1.5: defence against the openDevicePatchReport bug — a JS
    function called getElementById('device-patch-title') but the
    element itself was missing from index.html, so the button threw
    "can't access property textContent of null" at runtime. We didn't
    catch it because there's no JS test runner; this Python test
    grep-style scans for the same pattern.

    Strategy: find every getElementById(...) and openModal(...) / 
    closeModal(...) call in app.js, then verify each referenced ID
    exists in index.html — unless it's clearly dynamically created
    (those have ai-modal- and toast- prefixes)."""

    KNOWN_DYNAMIC_IDS = {
        # Created via document.createElement in _ensureAIModal()
        'ai-modal', 'ai-modal-body', 'ai-modal-title', 'ai-modal-meta',
        'ai-modal-copy', 'ai-modal-action', 'ai-modal-elapsed',
        # v2.4.0: Created via document.createElement in openSnapshots()
        'snapshot-modal', 'snapshot-modal-title',
        # v2.1.7: Created via document.createElement in _ensureRunbookModal()
        'runbook-modal', 'runbook-modal-body', 'runbook-modal-title',
        'runbook-modal-meta', 'runbook-modal-copy', 'runbook-modal-regen',
        # v2.9.0: Dynamically created by loadListeningPorts() expand
        'ports-table-body',
        'runbook-modal-elapsed', 'detail-runbook-section',
        # v2.2.0: Created via document.createElement in _ensureDriftModal()
        'drift-detail-modal', 'drift-detail-body', 'drift-detail-title',
        # v2.2.1: Created via document.createElement in _ensureDriftDiffModal()
        'drift-diff-modal', 'drift-diff-body', 'drift-diff-title',
        'drift-diff-path', 'drift-diff-fetch-btn', 'drift-diff-status',
        # Toast container created on first toast()
        'toast-container',
        # v3.3.4: RouterOS console Firewall + QoS sections, appended in
        # openRouterosConsole() via createElement/innerHTML.
        'ros-fw-body', 'ros-qos-body',
        # v3.4.0: OPNsense firewall body, rendered into the audit card.
        'opn-fw-body',
    }

    def test_modal_title_body_ids_all_exist_in_html(self):
        import re
        html_path = Path(__file__).parent.parent / 'server' / 'html' / 'index.html'
        js_path   = Path(__file__).parent.parent / 'server' / 'html' / 'static' / 'js' / 'app.js'
        html = html_path.read_text()
        js   = js_path.read_text()

        ids_used = set()
        for m in re.finditer(r"getElementById\(['\"]([a-z0-9_-]+)['\"]\)", js):
            ids_used.add(m.group(1))
        for m in re.finditer(r"(?:open|close)Modal\(['\"]([a-z0-9_-]+)['\"]\)", js):
            ids_used.add(m.group(1))

        ids_defined = set(re.findall(r'id=["\']([a-z0-9_-]+)["\']', html))

        # Restrict to the suspicious-shape IDs (those that look like
        # static elements rather than per-record IDs). A real-record
        # ID like 'dropdown-abc123' has the device ID interpolated in,
        # so it never matches verbatim — but those aren't the bug class
        # we're hunting.
        missing = ids_used - ids_defined - self.KNOWN_DYNAMIC_IDS
        suspect = [i for i in missing
                   if i.endswith('-modal') or i.endswith('-title') or i.endswith('-body')]
        self.assertEqual(suspect, [],
            f'JS references modal/title/body IDs not in index.html: {suspect}. '
            f'Either add them to the HTML or, if created dynamically, add to '
            f'KNOWN_DYNAMIC_IDS in this test.')


if __name__ == '__main__':
    unittest.main(verbosity=2)
