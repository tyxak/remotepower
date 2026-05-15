#!/usr/bin/env python3
"""
Tests for v2.1.9 — runbook hallucination fix.

Covers the three changes that together stopped Ollama 14B-coder
models from inventing service names and firewall rules:

1. ai_provider passes num_ctx=16384 to Ollama / LocalAI so the
   context window is large enough to actually contain the snapshot
2. generate_runbook system prompt is rewritten with explicit
   anti-hallucination rules + "use only the snapshot"
3. _build_runbook_snapshot caps the payload to ~8KB so it fits
   even in modest local-model context windows
"""

import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_CGI_BIN = Path(__file__).parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

_TMPDIR = tempfile.mkdtemp()
os.environ["RP_DATA_DIR"] = _TMPDIR
os.environ["REQUEST_METHOD"] = "GET"
os.environ["PATH_INFO"] = "/"
os.environ["CONTENT_LENGTH"] = "0"

_spec = importlib.util.spec_from_file_location("api_v219", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import ai_provider


# ── num_ctx wiring ────────────────────────────────────────────────────────


class TestNumCtxWiring(unittest.TestCase):
    """The Ollama default of num_ctx=2048 is the root cause of the
    runbook hallucination — any non-trivial snapshot got truncated
    mid-content. ai_provider must inject num_ctx for local providers,
    and must NOT inject it for Anthropic (different API shape).

    These tests call chat_openai_compatible directly (not the chat()
    dispatcher) because earlier test files monkey-patch
    ai_provider.chat for their own purposes and don't restore it.
    Going around the dispatcher keeps these tests robust to that."""

    def _run(self, cfg):
        sent = {}
        def fake_post(url, headers, body):
            sent['body'] = body
            return 200, {'choices': [{'message': {'content': 'ok'}}],
                         'usage': {'prompt_tokens': 1, 'completion_tokens': 1},
                         'model': cfg.get('model', '?')}
        original = ai_provider._http_post_json
        ai_provider._http_post_json = fake_post
        try:
            ai_provider.chat_openai_compatible(
                cfg,
                messages=[{'role': 'user', 'content': 'hi'}],
                system='sys', max_tokens=100,
            )
        finally:
            ai_provider._http_post_json = original
        return sent.get('body', {})

    def test_ollama_gets_num_ctx_in_body(self):
        body = self._run({
            'provider': ai_provider.PROVIDER_OLLAMA,
            'base_url': 'http://localhost:11434/v1',
            'api_key': '', 'model': 'qwen2.5-coder:14b',
        })
        self.assertIn('options', body,
                      'Ollama body must include options block')
        self.assertIn('num_ctx', body['options'])
        self.assertGreaterEqual(body['options']['num_ctx'], 8192,
                                'num_ctx must be large enough to fit a real snapshot')

    def test_localai_gets_num_ctx(self):
        body = self._run({
            'provider': ai_provider.PROVIDER_LOCALAI,
            'base_url': 'http://localhost:8080/v1',
            'api_key': '', 'model': 'gpt-3.5-turbo',
        })
        self.assertIn('options', body)

    def test_openai_does_not_get_num_ctx(self):
        """Real OpenAI ignores unknown body fields, but we still don't
        want to send Ollama-specific keys to cloud providers — keeps
        the wire format clean and prevents future provider validation
        from rejecting us."""
        body = self._run({
            'provider': ai_provider.PROVIDER_OPENAI,
            'api_key': 'sk-test', 'model': 'gpt-4o-mini',
        })
        self.assertNotIn('options', body,
                         'OpenAI body should not have Ollama options block')


# ── Anti-hallucination prompt ─────────────────────────────────────────────


class TestRunbookPromptAntiHallucination(unittest.TestCase):
    """The v2.1.7 prompt was too verbose and lacked explicit
    anti-fabrication instructions. The v2.1.9 rewrite must include
    them or smaller coder-tuned models keep inventing data."""

    def test_prompt_forbids_invention(self):
        p = ai_provider.SYSTEM_PROMPTS['generate_runbook']
        self.assertIn('CRITICAL RULES', p)
        # Strong wording: "do not invent" / "ONLY information from"
        lower = p.lower()
        self.assertTrue(
            'do not invent' in lower or 'do not fabricate' in lower,
            'prompt must explicitly forbid invention'
        )
        self.assertIn('ONLY', p,
                      'prompt should emphasise using ONLY snapshot data')

    def test_prompt_handles_missing_data(self):
        """If a section has no data in the snapshot, the model needs an
        explicit instruction for what to write — otherwise it improvises."""
        p = ai_provider.SYSTEM_PROMPTS['generate_runbook']
        self.assertIn('No data captured', p,
                      'prompt must give the model a fallback string for empty sections')

    def test_prompt_is_short_enough(self):
        """A 5-KB system prompt eats context budget on small models.
        Target under 3 KB."""
        p = ai_provider.SYSTEM_PROMPTS['generate_runbook']
        self.assertLess(len(p), 3000,
                        f'runbook prompt is {len(p)} chars — too long for small contexts')


# ── Snapshot size cap ─────────────────────────────────────────────────────


class TestSnapshotSizeCap(unittest.TestCase):
    """A 20-KB snapshot is fine for Anthropic Sonnet's 200K context but
    fatal for Ollama's default 2048-token cap. v2.1.9 caps the snapshot
    at ~8 KB / 2K tokens so it fits even on a tiny local model. This
    test simulates a heavily-populated device and checks the result is
    bounded."""

    def setUp(self):
        self._data_dir = Path(tempfile.mkdtemp())
        api.DATA_DIR        = self._data_dir
        api.DEVICES_FILE    = self._data_dir / 'devices.json'
        api.CMD_OUTPUT_FILE = self._data_dir / 'cmd_output.json'
        api.CVE_FINDINGS_FILE = self._data_dir / 'cve_findings.json'

    def test_busy_device_snapshot_under_10k(self):
        devices = {'dev1': {
            'id': 'dev1', 'name': 'busy-host',
            'os': 'Ubuntu 24.04 LTS',
            'sysinfo': {
                'uptime': '30 days', 'platform': 'x86_64',
                'memory': {'total': 8e9, 'used': 4e9},
                # 50 disks — should be trimmed to 5
                'disks': [{'mount': f'/d{i}', 'percent': 90 - i}
                          for i in range(50)],
                # Big junk field that we should NOT include
                'huge_random_extra': 'x' * 10000,
            },
            'journal': [f'line {i}' for i in range(200)],   # capped at 20
            'services_watched_state': [
                {'unit': f'svc{i}', 'active': 'active'} for i in range(30)
            ],
            'containers': [
                {'name': f'c{i}', 'image': 'img', 'state': 'running'}
                for i in range(50)
            ],   # capped at 10
            'notes': 'lorem ipsum ' * 200,   # capped at 500
            'tags': [f't{i}' for i in range(20)],
        }}
        cmd_outputs = {'dev1': {'outputs': [
            {'ts': i, 'cmd': f'cmd{i}', 'rc': 0,
             'output': 'x' * 2000}     # each output capped at 200
            for i in range(30)
        ]}}
        cve_findings = {'dev1': {'findings': [
            {'vuln_id': f'CVE-2024-{i:04d}', 'severity': 'high',
             'package': 'pkg', 'fixed_version': '1.0',
             'summary': 'long summary ' * 50}   # capped at 100
            for i in range(50)   # capped at 10
        ]}}
        api.save(api.DEVICES_FILE, devices)
        api.save(api.CMD_OUTPUT_FILE, cmd_outputs)
        api.save(api.CVE_FINDINGS_FILE, cve_findings)

        snap = api._build_runbook_snapshot('dev1', devices)
        as_json = json.dumps(snap, default=str)
        # Real cap target is ~8 KB; allow 10 KB ceiling for headroom
        self.assertLess(len(as_json), 10000,
                        f'snapshot is {len(as_json)} bytes — too big for small contexts')
        # Verify the trimming actually happened
        self.assertLessEqual(len(snap['recent_journal']), 20)
        self.assertLessEqual(len(snap['containers']), 10)
        self.assertLessEqual(len(snap['recent_commands']), 5)
        self.assertLessEqual(len(snap['cve_findings']), 10)
        self.assertLessEqual(len(snap['sysinfo'].get('disks', [])), 5)
        # The huge_random_extra field must NOT have been carried through
        self.assertNotIn('huge_random_extra', snap['sysinfo'])
        # Notes must be capped
        self.assertLessEqual(len(snap['notes']), 500)


# ── Demo URL ──────────────────────────────────────────────────────────────


class TestDemoUrl(unittest.TestCase):
    """Operator wanted the demo URL to be demoremote.tvipper.com
    everywhere, not demo.tvipper.com. Grep-style enforcement test."""

    def test_no_stale_demo_url_in_docs(self):
        """Any *active* reference to demo.tvipper.com is a bug — should
        be demoremote.tvipper.com. We deliberately exclude CHANGES.md
        and per-release docs/v2.1.*.md because those legitimately
        contain "demo.tvipper.com" when describing the fix ("URL was
        demo.tvipper.com, should be demoremote.tvipper.com"). What we
        want to catch is README.md or install.md or features.md still
        pointing users at the wrong URL."""
        repo_root = Path(__file__).parent.parent
        # Historical-mention files: changelog + per-release release notes
        excluded_names = {'CHANGES.md', 'CHANGELOG.md'}
        offenders = []
        for path in repo_root.rglob('*.md'):
            if path.name in excluded_names:
                continue
            # docs/v2.1.X.md release notes are historical too
            if path.parent.name == 'docs' and path.name.startswith('v2.'):
                continue
            text = path.read_text(errors='ignore')
            stripped = text.replace('demoremote.tvipper.com', '')
            if 'demo.tvipper.com' in stripped:
                offenders.append(str(path.relative_to(repo_root)))
        self.assertEqual(offenders, [],
                         f'These active-usage files still reference '
                         f'demo.tvipper.com instead of '
                         f'demoremote.tvipper.com: {offenders}')


if __name__ == '__main__':
    unittest.main(verbosity=2)
