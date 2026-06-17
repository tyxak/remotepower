#!/usr/bin/env python3
"""
Tests for v2.2.0 — drift detection backend and MCP server.

Two main areas:
  - Drift: _ingest_drift_report builds baselines correctly, detects
    divergence, fires webhook, supports re-baselining + reset.
  - MCP: the stdio JSON-RPC loop handles initialize / tools/list /
    tools/call correctly, returns errors gracefully, tools resolve
    devices by name with prefix/substring matching.
"""

import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

_CGI_BIN = Path(__file__).parent.parent / "server" / "cgi-bin"
_MCP_BIN = Path(__file__).parent.parent / "mcp" / "remotepower-mcp.py"
sys.path.insert(0, str(_CGI_BIN))

_TMPDIR = tempfile.mkdtemp()
os.environ["RP_DATA_DIR"] = _TMPDIR
os.environ["REQUEST_METHOD"] = "GET"
os.environ["PATH_INFO"] = "/"
os.environ["CONTENT_LENGTH"] = "0"

_spec = importlib.util.spec_from_file_location("api_v220", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Captured(SystemExit):
    def __init__(self, status, body):
        super().__init__(0)
        self.status = status
        self.body = body


def _capture_respond():
    def fake_respond(status, data):
        raise _Captured(status, data)
    api.respond = fake_respond


def _stub_auth(username='admin'):
    api.require_auth = lambda **kw: username
    api.require_admin_auth = lambda: username
    api.require_perm = lambda *a, **k: username


class _DriftBase(unittest.TestCase):
    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        api.DATA_DIR        = self._tmp
        api.DEVICES_FILE    = self._tmp / 'devices.json'
        api.CONFIG_FILE     = self._tmp / 'config.json'
        api.DRIFT_STATE_FILE = self._tmp / 'drift_state.json'
        api.AUDIT_LOG_FILE  = self._tmp / 'audit_log.json'
        api.WEBHOOK_LOG_FILE = self._tmp / 'webhook_log.json'
        _capture_respond()
        _stub_auth('admin')
        # Capture fire_webhook calls
        self._webhook_calls = []
        api.fire_webhook = lambda ev, payload: self._webhook_calls.append((ev, payload))


# ── _ingest_drift_report ─────────────────────────────────────────────────


class TestDriftIngest(_DriftBase):
    def test_first_sighting_becomes_baseline(self):
        api.save(api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'web01'}})
        report = {
            '/etc/ssh/sshd_config': {
                'hash': 'sha256:abc', 'size': 100, 'mtime': 1700000000,
                'exists': True,
            },
        }
        api._ingest_drift_report('d1', report)
        state = api.load(api.DRIFT_STATE_FILE)
        files = state['d1']['files']
        self.assertEqual(files['/etc/ssh/sshd_config']['baseline_hash'], 'sha256:abc')
        self.assertEqual(files['/etc/ssh/sshd_config']['current_hash'], 'sha256:abc')
        self.assertEqual(files['/etc/ssh/sshd_config']['drift_count'], 0)
        self.assertEqual(self._webhook_calls, [],
                         'first sighting should not fire webhook')

    def test_unchanged_hash_does_nothing(self):
        api.save(api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'web01'}})
        api._ingest_drift_report('d1', {
            '/etc/fstab': {'hash': 'sha256:x', 'size': 50, 'mtime': 1, 'exists': True},
        })
        api._ingest_drift_report('d1', {
            '/etc/fstab': {'hash': 'sha256:x', 'size': 50, 'mtime': 2, 'exists': True},
        })
        self.assertEqual(self._webhook_calls, [])
        state = api.load(api.DRIFT_STATE_FILE)
        self.assertEqual(state['d1']['files']['/etc/fstab']['drift_count'], 0)

    def test_hash_change_fires_webhook(self):
        api.save(api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'web01'}})
        api._ingest_drift_report('d1', {
            '/etc/sudoers': {'hash': 'sha256:original', 'size': 100,
                              'mtime': 1, 'exists': True},
        })
        api._ingest_drift_report('d1', {
            '/etc/sudoers': {'hash': 'sha256:CHANGED', 'size': 105,
                              'mtime': 2, 'exists': True},
        })
        self.assertEqual(len(self._webhook_calls), 1)
        ev, payload = self._webhook_calls[0]
        self.assertEqual(ev, 'drift_detected')
        self.assertEqual(payload['path'], '/etc/sudoers')
        self.assertEqual(payload['baseline_hash'], 'sha256:original')
        self.assertEqual(payload['current_hash'], 'sha256:CHANGED')
        state = api.load(api.DRIFT_STATE_FILE)
        self.assertEqual(state['d1']['files']['/etc/sudoers']['drift_count'], 1)

    def test_repeated_same_change_doesnt_re_fire(self):
        """If the file changes once and then keeps reporting the same new
        hash, we should fire once — not on every heartbeat. (Otherwise
        a 60-second poll would generate webhook storms for a single
        config change.)"""
        api.save(api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'web01'}})
        api._ingest_drift_report('d1', {
            '/etc/hosts': {'hash': 'sha256:original', 'size': 1,
                            'mtime': 1, 'exists': True},
        })
        # Change to new hash — fires
        api._ingest_drift_report('d1', {
            '/etc/hosts': {'hash': 'sha256:new', 'size': 1,
                            'mtime': 2, 'exists': True},
        })
        # Reports new hash again — should NOT fire
        api._ingest_drift_report('d1', {
            '/etc/hosts': {'hash': 'sha256:new', 'size': 1,
                            'mtime': 3, 'exists': True},
        })
        api._ingest_drift_report('d1', {
            '/etc/hosts': {'hash': 'sha256:new', 'size': 1,
                            'mtime': 4, 'exists': True},
        })
        self.assertEqual(len(self._webhook_calls), 1,
                         'only the first change from baseline should fire')

    def test_missing_file_reported(self):
        # v2.2.6: a missing watched file no longer fires a drift webhook
        # on the first missing sighting — that nagged operators about
        # files simply not present. It now fires ONCE after
        # DRIFT_MISSING_DORMANT_AFTER consecutive missing reports, when
        # the file goes dormant. `exists` is still recorded immediately.
        api.save(api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'web01'}})
        api._ingest_drift_report('d1', {
            '/etc/optional': {'hash': 'sha256:x', 'size': 1,
                               'mtime': 1, 'exists': True},
        })
        # First missing report — exists flips, but no webhook yet
        api._ingest_drift_report('d1', {
            '/etc/optional': {'hash': None, 'size': 0,
                               'mtime': 0, 'exists': False},
        })
        state = api.load(api.DRIFT_STATE_FILE)
        self.assertFalse(state['d1']['files']['/etc/optional']['exists'])
        self.assertEqual(len(self._webhook_calls), 0,
                         'first missing sighting must not fire')
        # Two more missing reports — on the Nth it goes dormant + fires once
        for _ in range(api.DRIFT_MISSING_DORMANT_AFTER - 1):
            api._ingest_drift_report('d1', {
                '/etc/optional': {'hash': None, 'size': 0,
                                   'mtime': 0, 'exists': False},
            })
        state = api.load(api.DRIFT_STATE_FILE)
        self.assertTrue(state['d1']['files']['/etc/optional']['dormant'],
                        'file should be dormant after the threshold')
        self.assertEqual(len(self._webhook_calls), 1,
                         'exactly one webhook when the file goes dormant')
        # Further missing reports stay quiet — no re-fire
        api._ingest_drift_report('d1', {
            '/etc/optional': {'hash': None, 'size': 0,
                               'mtime': 0, 'exists': False},
        })
        self.assertEqual(len(self._webhook_calls), 1,
                         'dormant file must not keep firing')

    def test_history_capped(self):
        api.save(api.DEVICES_FILE, {'d1': {'id': 'd1', 'name': 'web01'}})
        api._ingest_drift_report('d1', {
            '/etc/hosts': {'hash': 'sha256:a', 'size': 1,
                            'mtime': 1, 'exists': True},
        })
        # Submit DRIFT_HISTORY_CAP+5 different hashes
        for i in range(api.DRIFT_HISTORY_CAP + 5):
            api._ingest_drift_report('d1', {
                '/etc/hosts': {'hash': f'sha256:h{i}', 'size': 1,
                                'mtime': i + 2, 'exists': True},
            })
        state = api.load(api.DRIFT_STATE_FILE)
        self.assertEqual(
            len(state['d1']['files']['/etc/hosts']['history']),
            api.DRIFT_HISTORY_CAP,
        )

    def test_invalid_payload_ignored(self):
        # Garbage shouldn't crash
        api._ingest_drift_report('d1', None)
        api._ingest_drift_report('d1', "not a dict")
        api._ingest_drift_report('d1', {'/path': 'not a dict'})
        # No state created from garbage submissions
        self.assertEqual(self._webhook_calls, [])


# ── Drift endpoints ──────────────────────────────────────────────────────


def _set_method(m='GET', body=None):
    os.environ['REQUEST_METHOD'] = m
    if body is not None:
        b = json.dumps(body).encode('utf-8')
        os.environ['CONTENT_LENGTH'] = str(len(b))
        class _Shim:
            def __init__(self, data): self.buffer = io.BytesIO(data)
        api.sys.stdin = _Shim(b)
    else:
        os.environ['CONTENT_LENGTH'] = '0'


class TestDriftEndpoints(_DriftBase):
    def setUp(self):
        super().setUp()
        api.save(api.DEVICES_FILE, {
            'd1': {'id': 'd1', 'name': 'web01', 'group': 'web'},
            'd2': {'id': 'd2', 'name': 'db01', 'group': 'data'},
        })
        api._ingest_drift_report('d1', {
            '/etc/fstab': {'hash': 'sha256:a', 'size': 1,
                            'mtime': 1, 'exists': True},
        })
        # Drift d1
        api._ingest_drift_report('d1', {
            '/etc/fstab': {'hash': 'sha256:CHANGED', 'size': 1,
                            'mtime': 2, 'exists': True},
        })
        # Baseline d2 (no drift)
        api._ingest_drift_report('d2', {
            '/etc/fstab': {'hash': 'sha256:b', 'size': 1,
                            'mtime': 1, 'exists': True},
        })

    def test_overview(self):
        _set_method('GET')
        try: api.handle_drift_overview()
        except _Captured as c: r = c
        rows = r.body['devices']
        by_name = {row['device_name']: row for row in rows}
        self.assertEqual(by_name['web01']['drifted'], 1)
        self.assertEqual(by_name['db01']['drifted'], 0)
        # Drifted devices sorted to top
        self.assertEqual(rows[0]['device_name'], 'web01')

    def test_get_device_drift(self):
        _set_method('GET')
        try: api.handle_device_drift_get('d1')
        except _Captured as c: r = c
        self.assertIn('/etc/fstab', r.body['files'])
        self.assertNotEqual(
            r.body['files']['/etc/fstab']['current_hash'],
            r.body['files']['/etc/fstab']['baseline_hash'],
        )

    def test_baseline_accept_specific_path(self):
        _set_method('POST', {'paths': ['/etc/fstab']})
        try: api.handle_device_drift_baseline('d1')
        except _Captured as c: r = c
        self.assertEqual(r.body['updated'], ['/etc/fstab'])
        # After acceptance, baseline_hash now matches current_hash
        state = api.load(api.DRIFT_STATE_FILE)
        e = state['d1']['files']['/etc/fstab']
        self.assertEqual(e['baseline_hash'], e['current_hash'])
        self.assertEqual(e['drift_count'], 0)

    def test_baseline_accept_all(self):
        _set_method('POST', {'all': True})
        try: api.handle_device_drift_baseline('d1')
        except _Captured as c: r = c
        self.assertIn('/etc/fstab', r.body['updated'])

    def test_reset(self):
        _set_method('DELETE')
        try: api.handle_device_drift_reset('d1')
        except _Captured as c: r = c
        self.assertTrue(r.body['deleted'])
        state = api.load(api.DRIFT_STATE_FILE)
        self.assertNotIn('d1', state)


# ── MCP server end-to-end (spawn the script, talk JSON-RPC) ─────────────


def _mcp_call(messages, env=None):
    """Spawn the MCP server as a subprocess, send a list of messages on
    stdin, return responses parsed from stdout. The server reads one
    JSON object per line and writes one response per line."""
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    # Default: pretend there's no server (so any tool call would fail).
    # Tests that need a working URL stub it via env or patch _api.
    full_env.setdefault('REMOTEPOWER_URL', 'http://127.0.0.1:9')
    full_env.setdefault('REMOTEPOWER_TOKEN', 'test')
    stdin_data = '\n'.join(json.dumps(m) for m in messages) + '\n'
    proc = subprocess.Popen(
        ['python3', str(_MCP_BIN)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=full_env, text=True,
    )
    try:
        out, err = proc.communicate(input=stdin_data, timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        raise
    responses = []
    for line in out.splitlines():
        line = line.strip()
        if line:
            responses.append(json.loads(line))
    return responses, err


class TestMcpProtocol(unittest.TestCase):
    def test_initialize(self):
        responses, _ = _mcp_call([
            {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {}},
        ])
        self.assertEqual(len(responses), 1)
        r = responses[0]
        self.assertEqual(r['id'], 1)
        self.assertIn('result', r)
        self.assertEqual(r['result']['serverInfo']['name'], 'remotepower')
        self.assertEqual(r['result']['protocolVersion'], '2024-11-05')

    def test_tools_list_has_expected_tools(self):
        responses, _ = _mcp_call([
            {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {}},
            {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list', 'params': {}},
        ])
        self.assertEqual(len(responses), 2)
        tools = {t['name'] for t in responses[1]['result']['tools']}
        # The bedrock read-only set
        for required in ('list_devices', 'get_device', 'get_journal',
                         'get_services', 'get_cves', 'get_drift',
                         'search_devices', 'get_runbook'):
            self.assertIn(required, tools, f'tool {required} missing')

    def test_tools_list_no_arbitrary_exec_tools(self):
        """v3.2.0 introduced a narrow set of write tools — reboot_device,
        run_saved_script, force_package_scan, force_acme_rescan. The
        critical security property is now that no *arbitrary* exec tool
        leaked in: an LLM still cannot supply free-form bash."""
        responses, _ = _mcp_call([
            {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list', 'params': {}},
        ])
        tools = {t['name'] for t in responses[0]['result']['tools']}
        forbidden = {'run_command', 'exec_command', 'run_arbitrary_script',
                     'restart_service', 'edit_device', 'delete_device',
                     'set_threshold'}
        for f in forbidden:
            self.assertNotIn(f, tools, f'arbitrary-exec tool {f} must not be exposed')

    def test_unknown_method_returns_error(self):
        responses, _ = _mcp_call([
            {'jsonrpc': '2.0', 'id': 1, 'method': 'wat/wat', 'params': {}},
        ])
        self.assertEqual(len(responses), 1)
        self.assertIn('error', responses[0])
        self.assertEqual(responses[0]['error']['code'], -32601)

    def test_notification_gets_no_response(self):
        """JSON-RPC notifications (no id) must not produce a response.
        The host sends notifications/initialized after the handshake."""
        responses, _ = _mcp_call([
            {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
        ])
        self.assertEqual(responses, [])

    def test_parse_error_handled(self):
        """Bad JSON should produce a parse-error response, not crash."""
        proc = subprocess.Popen(
            ['python3', str(_MCP_BIN)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={**os.environ, 'REMOTEPOWER_URL': 'http://x', 'REMOTEPOWER_TOKEN': 't'},
            text=True,
        )
        try:
            out, _ = proc.communicate(input='{not valid json\n', timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            raise
        # Should produce one parse-error response
        responses = [json.loads(l) for l in out.splitlines() if l.strip()]
        self.assertEqual(len(responses), 1)
        self.assertEqual(responses[0]['error']['code'], -32700)

    def test_tool_call_with_no_server_returns_error_gracefully(self):
        """A call to list_devices with no real REMOTEPOWER_URL configured
        should return an error in the tool result, not crash the server.
        The model needs to see a useful message it can act on."""
        responses, _ = _mcp_call([
            {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
             'params': {'name': 'list_devices', 'arguments': {}}},
        ])
        self.assertEqual(len(responses), 1)
        # Either a tool error in the content, or the call succeeded — but
        # importantly we should have gotten *a* response, not a crash.
        self.assertIn('result', responses[0])
        content = responses[0]['result'].get('content', [])
        self.assertGreater(len(content), 0)


# ── MCP tool resolution logic (unit tests via direct import) ────────────


# Load the MCP module so we can call the device-resolution helper directly.
_mcp_spec = importlib.util.spec_from_file_location("remotepower_mcp", _MCP_BIN)
mcp_mod = importlib.util.module_from_spec(_mcp_spec)
_mcp_spec.loader.exec_module(mcp_mod)


class TestMcpDeviceResolution(unittest.TestCase):
    """The _find_device_by_name helper does prefix + substring matching.
    Tested in isolation by stubbing the _api function."""

    def test_exact_match(self):
        mcp_mod._api = lambda *a, **kw: [
            {'name': 'web01'}, {'name': 'db01'},
        ]
        d = mcp_mod._find_device_by_name('web01')
        self.assertEqual(d['name'], 'web01')

    def test_prefix_match(self):
        mcp_mod._api = lambda *a, **kw: [
            {'name': 'tviweb01.tvipper.com'}, {'name': 'tvidb01.tvipper.com'},
        ]
        d = mcp_mod._find_device_by_name('tviweb01')
        self.assertEqual(d['name'], 'tviweb01.tvipper.com')

    def test_substring_match(self):
        mcp_mod._api = lambda *a, **kw: [
            {'name': 'foo.example.com'}, {'name': 'bar.example.com'},
        ]
        d = mcp_mod._find_device_by_name('foo')
        self.assertEqual(d['name'], 'foo.example.com')

    def test_ambiguous_substring_raises(self):
        mcp_mod._api = lambda *a, **kw: [
            {'name': 'web01.example.com'}, {'name': 'web02.example.com'},
        ]
        with self.assertRaises(RuntimeError) as cm:
            mcp_mod._find_device_by_name('web')
        self.assertIn('ambiguous', str(cm.exception).lower())

    def test_no_match_returns_none(self):
        mcp_mod._api = lambda *a, **kw: [{'name': 'foo'}]
        self.assertIsNone(mcp_mod._find_device_by_name('bar'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
