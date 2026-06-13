#!/usr/bin/env python3
"""
Tests for v2.1.7 — ai_context module + runbook generation.

Two areas:
  - ai_context: project + fleet context blocks build correctly and
    plumb through to the AI request
  - runbooks: /api/devices/<id>/runbook/generate creates the right
    snapshot, calls the AI, stores the result; /runbook GET fetches
    it; /runbook DELETE removes it
"""

import importlib.util
import io
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_CGI_BIN = Path(__file__).parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

_TMPDIR = tempfile.mkdtemp()
os.environ["RP_DATA_DIR"] = _TMPDIR
os.environ["REQUEST_METHOD"] = "GET"
os.environ["PATH_INFO"] = "/"
os.environ["CONTENT_LENGTH"] = "0"

_spec = importlib.util.spec_from_file_location("api_v217", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import ai_context
import ai_provider


# ── Test scaffolding (shared with v213 tests) ────────────────────────────


class _Captured(SystemExit):
    def __init__(self, status, body):
        super().__init__(0)
        self.status = status
        self.body = body


def _capture_respond():
    def fake_respond(status, data):
        raise _Captured(status, data)
    api.respond = fake_respond


class _StdinShim:
    def __init__(self, data: bytes):
        self.buffer = io.BytesIO(data)


def _set_request(method='POST', body=None):
    os.environ['REQUEST_METHOD'] = method
    if body is not None:
        body_bytes = json.dumps(body).encode('utf-8')
        os.environ['CONTENT_LENGTH'] = str(len(body_bytes))
        api.sys.stdin = _StdinShim(body_bytes)
    else:
        os.environ['CONTENT_LENGTH'] = '0'
        api.sys.stdin = _StdinShim(b'')


def _stub_auth(username='admin'):
    api.require_auth = lambda **kw: username
    api.require_admin_auth = lambda: username


class _Base(unittest.TestCase):
    def setUp(self):
        self._data_dir = Path(tempfile.mkdtemp())
        api.DATA_DIR          = self._data_dir
        api.CONFIG_FILE       = self._data_dir / 'config.json'
        api.DEVICES_FILE      = self._data_dir / 'devices.json'
        api.CMD_OUTPUT_FILE   = self._data_dir / 'cmd_output.json'
        api.CVE_FINDINGS_FILE = self._data_dir / 'cve_findings.json'
        api.AI_USAGE_FILE     = self._data_dir / 'ai_usage.json'
        api.AUDIT_LOG_FILE    = self._data_dir / 'audit_log.json'
        api.RUNBOOKS_FILE     = self._data_dir / 'runbooks.json'
        _capture_respond()
        _stub_auth('admin')


# ── ai_context module ────────────────────────────────────────────────────


class TestProjectContext(unittest.TestCase):
    def test_is_non_trivial(self):
        ctx = ai_context.build_project_context()
        self.assertGreater(len(ctx), 200, 'project context suspiciously short')

    def test_mentions_remotepower(self):
        ctx = ai_context.build_project_context()
        self.assertIn('RemotePower', ctx)

    def test_mentions_key_concepts(self):
        """If the model doesn't know about heartbeats, scripts, or
        the JSON storage layer, it'll give generic advice. These are
        the things that make the AI 'know the project'."""
        ctx = ai_context.build_project_context()
        for word in ('heartbeat', 'script', 'JSON', 'agent'):
            self.assertIn(word.lower(), ctx.lower(),
                          f'project context missing key concept: {word}')


class TestFleetContext(unittest.TestCase):
    def test_empty_returns_empty(self):
        self.assertEqual(ai_context.build_fleet_context([]), '')
        self.assertEqual(ai_context.build_fleet_context(None), '')

    def test_single_device(self):
        import time as _t
        now = int(_t.time())
        ctx = ai_context.build_fleet_context([{
            'name': 'web01', 'os': 'Ubuntu 24.04', 'pkg_manager': 'apt',
            'last_seen': now - 30, 'group': 'web',
        }], now=now, ttl=300)
        self.assertIn('web01', ctx)
        self.assertIn('Ubuntu', ctx)
        self.assertIn('apt', ctx)
        self.assertIn('group=web', ctx)
        self.assertIn('online', ctx)

    def test_offline_device(self):
        ctx = ai_context.build_fleet_context([{
            'name': 'old-box',   # no last_seen at all
        }])
        self.assertIn('old-box', ctx)
        self.assertIn('offline', ctx)

    def test_recent_last_seen_is_online(self):
        """Regression: the v2.1.7 bug was reading d.get('online') directly,
        but `online` is a *derived* field not persisted in devices.json.
        Devices with a recent last_seen MUST report as online, since that's
        the canonical signal — even if the dict has no 'online' key."""
        import time as _t
        now = int(_t.time())
        ctx = ai_context.build_fleet_context(
            [{'name': 'web01', 'last_seen': now - 30}],
            now=now, ttl=300,
        )
        self.assertIn('online', ctx)
        self.assertNotIn('offline', ctx)

    def test_stale_last_seen_is_offline(self):
        import time as _t
        now = int(_t.time())
        ctx = ai_context.build_fleet_context(
            [{'name': 'old-box', 'last_seen': now - 1000}],
            now=now, ttl=300,
        )
        self.assertIn('offline', ctx)
        self.assertNotIn('online,', ctx)

    def test_no_last_seen_is_offline(self):
        """Device that's never checked in is offline."""
        ctx = ai_context.build_fleet_context(
            [{'name': 'never-seen'}],
            now=1000000, ttl=300,
        )
        self.assertIn('offline', ctx)

    def test_agentless_default_online(self):
        """Agentless devices have no heartbeat — operator sets state
        via manual_status, defaulting to True (online)."""
        ctx = ai_context.build_fleet_context(
            [{'name': 'switch01', 'agentless': True}],
            now=1000000, ttl=300,
        )
        self.assertIn('online', ctx)

    def test_agentless_manual_offline(self):
        ctx = ai_context.build_fleet_context(
            [{'name': 'old-switch', 'agentless': True, 'manual_status': False}],
            now=1000000, ttl=300,
        )
        self.assertIn('offline', ctx)

    def test_online_first(self):
        """Sort order matters under context-length pressure."""
        ctx = ai_context.build_fleet_context([
            {'name': 'aaa-offline', 'online': False},
            {'name': 'zzz-online',  'last_seen': 9999999999},
        ])
        # zzz-online should appear before aaa-offline
        self.assertLess(ctx.index('zzz-online'), ctx.index('aaa-offline'))

    def test_caps_at_max_devices(self):
        many = [{'name': f'dev-{i}', 'last_seen': 9999999999} for i in range(120)]
        ctx = ai_context.build_fleet_context(many, max_devices=80)
        # Should mention truncation
        self.assertIn('omitted', ctx)
        # Should contain exactly 80 device names plus the header + ellipsis
        # Count "- dev-" prefixes (each device line)
        device_lines = ctx.count('- dev-')
        self.assertEqual(device_lines, 80)

    def test_includes_notes_when_present(self):
        ctx = ai_context.build_fleet_context([{
            'name': 'pmg01', 'last_seen': 9999999999,
            'notes': 'Proxmox mail gateway — primary MX',
        }])
        self.assertIn('Proxmox mail gateway', ctx)

    def test_notes_truncated_at_first_line(self):
        ctx = ai_context.build_fleet_context([{
            'name': 'verbose', 'last_seen': 9999999999,
            'notes': 'first line\nsecond line should be cut\nand so on',
        }])
        self.assertIn('first line', ctx)
        self.assertNotIn('second line', ctx)


class TestCombinedSystemPrompt(unittest.TestCase):
    def test_no_context_returns_base(self):
        base = 'You are a helpful assistant.'
        combined = ai_context.build_combined_system_prompt(
            base, devices=None,
            include_project=False, include_fleet=False)
        self.assertEqual(combined, base)

    def test_project_only(self):
        base = 'You are a helpful assistant.'
        combined = ai_context.build_combined_system_prompt(
            base, devices=None,
            include_project=True, include_fleet=False)
        self.assertIn('RemotePower', combined)
        self.assertIn(base, combined)
        # Wrapping tag present
        self.assertIn('<system_context>', combined)

    def test_fleet_only(self):
        base = 'You are a helpful assistant.'
        combined = ai_context.build_combined_system_prompt(
            base, devices=[{'name': 'host1', 'last_seen': 9999999999}],
            include_project=False, include_fleet=True)
        self.assertIn('host1', combined)
        self.assertIn(base, combined)

    def test_base_after_context(self):
        """Operator's actual task framing should follow the context,
        not be hidden inside it."""
        base = 'TASK_MARKER_XYZ'
        combined = ai_context.build_combined_system_prompt(
            base, devices=[{'name': 'host1', 'last_seen': 9999999999}],
            include_project=True, include_fleet=True)
        # </system_context> must appear before TASK_MARKER_XYZ
        self.assertLess(combined.index('</system_context>'),
                        combined.index('TASK_MARKER_XYZ'))


# ── Context integration into /api/ai/chat ────────────────────────────────


class TestChatPrependsContext(_Base):
    def setUp(self):
        super().setUp()
        api.save(api.CONFIG_FILE, {'ai': {
            'enabled': True, 'provider': 'anthropic', 'api_key': 'k',
            'limits': {'max_tokens_per_response': 1000,
                       'max_requests_per_user_day': 5},
        }})
        # Seed the fleet so fleet context has something to render
        api.save(api.DEVICES_FILE, {
            'dev1': {'id': 'dev1', 'name': 'web01',
                     'os': 'Ubuntu 24.04', 'last_seen': 9999999999, 'group': 'web'},
            'dev2': {'id': 'dev2', 'name': 'mail01',
                     'os': 'Debian 12', 'last_seen': 9999999999, 'group': 'mail'},
        })
        self._captured_system = []
        def fake_chat(cfg, messages, system=None, max_tokens=None, model=None):
            self._captured_system.append(system)
            return {'ok': True, 'text': 'mocked', 'model': 'm',
                    'tokens_in': 1, 'tokens_out': 1}
        ai_provider.chat = fake_chat

    def _chat(self, body):
        _set_request('POST', body)
        try: api.handle_ai_chat()
        except _Captured as c: return c

    def test_default_prepends_project_and_fleet(self):
        self._chat({'messages': [{'role': 'user', 'content': 'hi'}]})
        sent = self._captured_system[0]
        self.assertIn('RemotePower', sent)        # project
        self.assertIn('web01', sent)               # fleet
        self.assertIn('mail01', sent)

    def test_context_off_passes_clean_prompt(self):
        api.save(api.CONFIG_FILE, {'ai': {
            'enabled': True, 'provider': 'anthropic', 'api_key': 'k',
            'context': {'include_project_context': False,
                        'include_fleet_context': False},
        }})
        self._chat({'messages': [{'role': 'user', 'content': 'hi'}],
                    'system': 'be terse'})
        sent = self._captured_system[0]
        self.assertEqual(sent, 'be terse')

    def test_fleet_off_keeps_project(self):
        api.save(api.CONFIG_FILE, {'ai': {
            'enabled': True, 'provider': 'anthropic', 'api_key': 'k',
            'context': {'include_project_context': True,
                        'include_fleet_context': False},
        }})
        self._chat({'messages': [{'role': 'user', 'content': 'hi'}]})
        sent = self._captured_system[0]
        self.assertIn('RemotePower', sent)
        self.assertNotIn('web01', sent)


# ── Runbook generation ───────────────────────────────────────────────────


class TestRunbookGenerate(_Base):
    def setUp(self):
        super().setUp()
        api.save(api.CONFIG_FILE, {'ai': {
            'enabled': True, 'provider': 'anthropic', 'api_key': 'k',
        }})
        api.save(api.DEVICES_FILE, {
            'dev1': {
                'id': 'dev1', 'name': 'web01',
                'os': 'Ubuntu 24.04 LTS', 'pkg_manager': 'apt',
                'last_seen': 9999999999, 'group': 'web',
                'sysinfo': {'uptime': '7 days', 'hostname': 'web01'},
                'journal': ['log line 1', 'log line 2'],
                'services_watched_state': [{'unit': 'nginx', 'active': 'active'}],
                'patch_status': 'fully_patched', 'upgradable': 0,
            },
        })
        # CMD_OUTPUT_FILE[dev_id] is a LIST of command records (the shape the
        # agent actually writes — see api.py heartbeat cmd_output handling), not
        # a {'outputs': [...]} dict. v4.6.0 fixed the snapshot reader to match.
        api.save(api.CMD_OUTPUT_FILE, {
            'dev1': [
                {'ts': 1700000000, 'cmd': 'df -h', 'rc': 0, 'output': 'usage data'},
            ],
        })
        # Capture AI calls
        self._calls = []
        def fake_chat(cfg, messages, system=None, max_tokens=None, model=None):
            self._calls.append({'messages': messages, 'system': system,
                                'max_tokens': max_tokens})
            return {'ok': True, 'text': '# Runbook\n\n## Purpose\n\nweb01 is a web server.',
                    'model': 'test-model', 'tokens_in': 100, 'tokens_out': 200}
        ai_provider.chat = fake_chat

    def _generate(self, dev_id='dev1'):
        _set_request('POST', {})
        try: api.handle_runbook_generate(dev_id)
        except _Captured as c: return c

    def test_generates_and_stores(self):
        r = self._generate()
        self.assertEqual(r.status, 200)
        self.assertTrue(r.body['ok'])
        self.assertIn('web01', r.body['content'])
        # Stored in runbooks.json
        rb = api.load(api.RUNBOOKS_FILE)
        self.assertIn('dev1', rb)
        self.assertEqual(rb['dev1']['model'], 'test-model')

    def test_404_unknown_device(self):
        r = self._generate('nonexistent')
        self.assertEqual(r.status, 404)

    def test_snapshot_includes_device_facts(self):
        self._generate()
        # The user message should be a JSON dump of the snapshot
        user_msg = self._calls[0]['messages'][0]['content']
        self.assertIn('web01', user_msg)
        self.assertIn('Ubuntu', user_msg)
        self.assertIn('nginx', user_msg)
        self.assertIn('df -h', user_msg)

    def test_snapshot_includes_fleet_context(self):
        """The runbook prompt should be wrapped with the same project +
        fleet context as regular AI chat — that's part of the value."""
        self._generate()
        sent_system = self._calls[0]['system']
        self.assertIn('RemotePower', sent_system)
        self.assertIn('web01', sent_system)   # fleet context lists this device

    def test_disabled_400(self):
        api.save(api.CONFIG_FILE, {'ai': {'enabled': False}})
        r = self._generate()
        self.assertEqual(r.status, 400)


class TestRunbookGet(_Base):
    def test_returns_exists_false_when_missing(self):
        _set_request('GET')
        try: api.handle_runbook_get('dev1')
        except _Captured as c: r = c
        self.assertEqual(r.status, 200)
        self.assertFalse(r.body['exists'])

    def test_returns_stored_runbook(self):
        api.save(api.RUNBOOKS_FILE, {'dev1': {
            'content': '# Test runbook\n\nHello.',
            'generated_at': 1700000000,
            'model': 'test',
            'tokens_in': 10, 'tokens_out': 20,
        }})
        _set_request('GET')
        try: api.handle_runbook_get('dev1')
        except _Captured as c: r = c
        self.assertEqual(r.status, 200)
        self.assertTrue(r.body['exists'])
        self.assertEqual(r.body['content'], '# Test runbook\n\nHello.')


class TestRunbookDelete(_Base):
    def test_delete_removes_entry(self):
        api.save(api.RUNBOOKS_FILE, {'dev1': {'content': 'x', 'generated_at': 1}})
        _set_request('DELETE')
        try: api.handle_runbook_delete('dev1')
        except _Captured as c: r = c
        self.assertEqual(r.status, 200)
        self.assertTrue(r.body['deleted'])
        # File no longer has dev1
        self.assertNotIn('dev1', api.load(api.RUNBOOKS_FILE))

    def test_delete_idempotent(self):
        _set_request('DELETE')
        try: api.handle_runbook_delete('nonexistent')
        except _Captured as c: r = c
        self.assertEqual(r.status, 200)
        self.assertFalse(r.body['deleted'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
