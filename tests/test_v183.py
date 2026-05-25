#!/usr/bin/env python3
"""
Unit tests for v1.8.3 additions:
- Calendar event sanitizer (validation, color clamping, ISO parsing, end-after-start)
- Task sanitizer (state validation, device linking, partial updates)
- Agent: _resolve_unit_alias semantics (mocked so tests don't need real systemd)
"""
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_CGI_BIN = Path(__file__).parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI_BIN))

_TMPDIR = tempfile.mkdtemp()
os.environ['RP_DATA_DIR'] = _TMPDIR
os.environ['REQUEST_METHOD'] = 'GET'
os.environ['PATH_INFO'] = '/'
os.environ['CONTENT_LENGTH'] = '0'

import importlib.util
_spec = importlib.util.spec_from_file_location('api_v183', _CGI_BIN / 'api.py')
api_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api_module)


class TestCalendarValidation(unittest.TestCase):

    def test_minimal_valid_event(self):
        ev, err = api_module._sanitize_event({
            'title': 'Backup prod DB',
            'start': '2026-05-01T03:00:00Z',
        })
        self.assertIsNone(err)
        self.assertEqual(ev['title'], 'Backup prod DB')
        self.assertEqual(ev['start'], '2026-05-01T03:00:00Z')
        self.assertEqual(ev['end'], '2026-05-01T03:00:00Z')  # defaulted to start
        self.assertEqual(ev['color'], 'blue')                 # default
        self.assertFalse(ev['all_day'])

    def test_full_valid_event(self):
        ev, err = api_module._sanitize_event({
            'title':       'Q3 review',
            'description': 'Quarterly business review',
            'start':       '2026-05-15T09:00:00Z',
            'end':         '2026-05-15T17:00:00Z',
            'all_day':     True,
            'color':       'purple',
        })
        self.assertIsNone(err)
        self.assertEqual(ev['color'], 'purple')
        self.assertTrue(ev['all_day'])

    def test_missing_title_rejected(self):
        ev, err = api_module._sanitize_event({'start': '2026-05-01T03:00:00Z'})
        self.assertIsNone(ev)
        self.assertIn('title is required', err)

    def test_missing_start_rejected(self):
        ev, err = api_module._sanitize_event({'title': 'X'})
        self.assertIsNone(ev)
        self.assertIn('start is required', err)

    def test_invalid_start_rejected(self):
        ev, err = api_module._sanitize_event({'title': 'X', 'start': 'bad-date'})
        self.assertIsNone(ev)
        self.assertIn('invalid start', err)

    def test_end_before_start_rejected(self):
        ev, err = api_module._sanitize_event({
            'title': 'X',
            'start': '2026-05-01T10:00:00Z',
            'end':   '2026-05-01T09:00:00Z',
        })
        self.assertIsNone(ev)
        self.assertIn('end must be', err)

    def test_unknown_color_falls_back_to_blue(self):
        ev, err = api_module._sanitize_event({
            'title': 'X',
            'start': '2026-05-01T03:00:00Z',
            'color': 'rainbow',  # not in allowed palette
        })
        self.assertIsNone(err)
        self.assertEqual(ev['color'], 'blue')

    def test_all_palette_colors_accepted(self):
        for color in api_module.ALLOWED_EVENT_COLORS:
            ev, err = api_module._sanitize_event({
                'title': 'X',
                'start': '2026-05-01T03:00:00Z',
                'color': color,
            })
            self.assertIsNone(err)
            self.assertEqual(ev['color'], color)


class TestTaskValidation(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._orig = api_module.DEVICES_FILE
        api_module.DEVICES_FILE = self.tmp / 'devices.json'
        api_module.save(api_module.DEVICES_FILE, {
            'dev-aaaaaaaaaaaaaa': {'name': 'web-1', 'group': ''},
        })

    def tearDown(self):
        api_module.DEVICES_FILE = self._orig

    def test_minimal_valid_task(self):
        t, err = api_module._sanitize_task({'title': 'Do something'})
        self.assertIsNone(err)
        self.assertEqual(t['title'], 'Do something')

    def test_default_state_upcoming(self):
        t, err = api_module._sanitize_task({'title': 'Do something'})
        self.assertIsNone(err)
        self.assertEqual(t.get('state'), 'upcoming')

    def test_all_states_accepted(self):
        for state in api_module.TASK_STATES:
            t, err = api_module._sanitize_task({'title': 'X', 'state': state})
            self.assertIsNone(err, f'state={state}: {err}')
            self.assertEqual(t['state'], state)

    def test_invalid_state_rejected(self):
        t, err = api_module._sanitize_task({'title': 'X', 'state': 'archived'})
        self.assertIsNone(t)
        self.assertIn('state must be', err)

    def test_missing_title_when_required(self):
        t, err = api_module._sanitize_task({}, require_all=True)
        self.assertIsNone(t)
        self.assertIn('title is required', err)

    def test_partial_update_allows_missing_title(self):
        t, err = api_module._sanitize_task({'state': 'closed'}, require_all=False)
        self.assertIsNone(err)
        self.assertNotIn('title', t)
        self.assertEqual(t['state'], 'closed')

    def test_valid_device_id_accepted(self):
        t, err = api_module._sanitize_task({
            'title': 'Reboot it',
            'device_id': 'dev-aaaaaaaaaaaaaa',
        })
        self.assertIsNone(err)
        self.assertEqual(t['device_id'], 'dev-aaaaaaaaaaaaaa')

    def test_unknown_device_rejected(self):
        t, err = api_module._sanitize_task({
            'title': 'X',
            'device_id': 'dev-NONEXISTENTID',
        })
        self.assertIsNone(t)
        self.assertIn('device_id not found', err)

    def test_empty_device_id_means_unlink(self):
        t, err = api_module._sanitize_task({'title': 'X', 'device_id': ''})
        self.assertIsNone(err)
        self.assertEqual(t['device_id'], '')


class TestHandlersExist(unittest.TestCase):

    def test_calendar_handlers(self):
        for fn in ('handle_calendar_list', 'handle_calendar_add',
                   'handle_calendar_update', 'handle_calendar_delete'):
            self.assertTrue(hasattr(api_module, fn), fn)

    def test_task_handlers(self):
        for fn in ('handle_tasks_list', 'handle_tasks_add',
                   'handle_tasks_update', 'handle_tasks_delete'):
            self.assertTrue(hasattr(api_module, fn), fn)

    def test_constants(self):
        self.assertTrue(hasattr(api_module, 'CALENDAR_FILE'))
        self.assertTrue(hasattr(api_module, 'TASKS_FILE'))
        self.assertEqual(api_module.TASK_STATES,
                          ('upcoming', 'ongoing', 'pending', 'closed'))

    def test_version_at_least_1_8_3(self):
        parts = api_module.SERVER_VERSION.split('.')
        self.assertGreaterEqual(
            (int(parts[0]), int(parts[1]), int(parts[2])),
            (1, 8, 3),
        )


class TestAgentAliasResolution(unittest.TestCase):
    """Test the agent's _resolve_unit_alias helper.

    We can't import the agent as a module (it's a bare script with a shebang
    and no .py extension), so we read its source and exec into a controlled
    namespace where subprocess.run is patched.
    """

    @classmethod
    def setUpClass(cls):
        agent_path = Path(__file__).parent.parent / 'client' / 'remotepower-agent'
        cls.agent_src = agent_path.read_text()

    def _exec_resolve_alias_with_mock(self, mock_stdout, mock_returncode=0):
        """Exec the _resolve_unit_alias function with a mocked subprocess."""
        # Build a minimal namespace with what the function needs
        import subprocess as _real_subprocess
        ns = {
            'subprocess': MagicMock(),
            'Path': Path,
            '__builtins__': __builtins__,
        }
        ns['subprocess'].run = MagicMock(return_value=MagicMock(
            stdout=mock_stdout, returncode=mock_returncode,
        ))
        # Also pull in the constants the function expects
        ns['subprocess'].TimeoutExpired = _real_subprocess.TimeoutExpired

        # Find and exec just the function definition
        func_marker = 'def _resolve_unit_alias('
        idx = self.agent_src.find(func_marker)
        self.assertGreater(idx, 0, 'function not found in agent source')
        # Read until end of function (next top-level def or end-of-section)
        end = self.agent_src.find('\ndef ', idx + 1)
        func_src = self.agent_src[idx:end]
        exec(func_src, ns)
        return ns['_resolve_unit_alias']

    def test_returns_canonical_when_different(self):
        resolve = self._exec_resolve_alias_with_mock('ssh.service\n')
        self.assertEqual(resolve('sshd.service'), 'ssh.service')

    def test_returns_input_when_same(self):
        resolve = self._exec_resolve_alias_with_mock('nginx.service\n')
        self.assertEqual(resolve('nginx.service'), 'nginx.service')

    def test_returns_input_when_systemctl_returns_empty(self):
        resolve = self._exec_resolve_alias_with_mock('')
        self.assertEqual(resolve('whatever.service'), 'whatever.service')


if __name__ == '__main__':
    unittest.main()
