#!/usr/bin/env python3
"""Integrity Guard directives must not be queued to a host that ignores them.

Both the Windows and macOS agents list `guard_actions` among the keys they
deliberately drop — their module docstrings say so in as many words. The server
queued the directive anyway, onto any device id the operator picked, and
answered 200. The operator clicked Restore on a quarantined file, saw
"Restore queued — the agent applies it on its next check-in", and nothing ever
happened: the directive rode out on the next heartbeat to an agent that reads
past it.

That is the success-toast-then-silence class. v6.4.3 closed seventeen other
Linux-only flags at `_command_block_reason`, the shared queue chokepoint — this
one never goes through that chokepoint. It is written straight onto the device
row by `_queue_guard_action`, so it needed its own gate, which is exactly how
`handle_uninstall_agent` slipped past the same sweep earlier in this release.

The fleet-scoped rebaseline case is the interesting one: it fans out to every
device a check applies to, so a mixed fleet must still rebaseline its Linux
hosts and SAY which ones it skipped — refusing the whole batch would make the
feature useless on any real fleet, and reporting an unqualified success would
be the original bug with extra steps.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v643guard-'))

_spec = importlib.util.spec_from_file_location('api_v643_guard', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules.setdefault('api', api)
_spec.loader.exec_module(api)

# NOT `import guard_handlers` — a bound module reaches api through the `A`
# namespace proxy, and that proxy is only populated when api.py execs the
# module and calls bind(). Imported standalone, `A` is None and every handler
# raises AttributeError on its first line. api.py re-imports the names, so the
# BOUND copy is the one hanging off `api`.


class _Base(unittest.TestCase):
    def setUp(self):
        self.cap = {}
        # `os` is TOP-LEVEL on the device row — that is what the heartbeat
        # writes (`dev['os'] = ...`) and what _device_os_family reads. The
        # first draft of this fixture nested it under `sysinfo`, where nothing
        # reads it, so every device resolved to the 'linux' default and all
        # five gate assertions passed against an ungated handler. A fixture
        # shape the code never matches makes a test agree with anything.
        api.save(api.DEVICES_FILE, {
            'lin1': {'name': 'web01', 'os': 'Debian GNU/Linux 12'},
            'win1': {'name': 'desk01', 'os': 'Windows 11 Pro'},
            'mac1': {'name': 'mbp01', 'os': 'macOS 14.5 (23F79)'},
        })
        api._invalidate_load_cache(api.DEVICES_FILE)
        self._orig = (api.require_write_role, api.method, api.get_json_obj,
                      api.respond, api.audit_log, api._scope_block_device)
        api.require_write_role = lambda *a, **k: 'admin'
        api.method = lambda: 'POST'
        api.audit_log = lambda *a, **k: None
        api._scope_block_device = lambda *a, **k: None

        def _respond(status, data=None, *a, **k):
            self.cap['s'] = status
            self.cap['d'] = data
            raise api.HTTPError(status, data)
        api.respond = _respond
        # guard_handlers reaches api through the A namespace proxy, which
        # resolves attributes live — so stubbing on `api` is enough.

    def tearDown(self):
        (api.require_write_role, api.method, api.get_json_obj,
         api.respond, api.audit_log, api._scope_block_device) = self._orig

    def _call(self, body):
        api.get_json_obj = lambda: body
        try:
            api.handle_guard_action()
        except (SystemExit, api.HTTPError):
            pass
        return self.cap

    def _queued(self, dev_id):
        devs = api.load(api.DEVICES_FILE) or {}
        return (devs.get(dev_id) or {}).get('guard_actions') or []


class TestSingleDeviceGate(_Base):
    def test_a_linux_host_still_works(self):
        """The positive control. Without it a gate that refused everything
        would satisfy every other test in this file."""
        r = self._call({'device_id': 'lin1', 'id': 'chk1', 'op': 'restore'})
        self.assertEqual(r.get('s'), 200)
        self.assertTrue(self._queued('lin1'),
                        'the directive must still reach a Linux host')

    def test_a_windows_host_is_refused(self):
        r = self._call({'device_id': 'win1', 'id': 'chk1', 'op': 'restore'})
        self.assertEqual(r.get('s'), 400)
        self.assertIn('Linux', str(r.get('d')))
        self.assertEqual(self._queued('win1'), [],
                         'nothing may be queued onto a host that drops it')

    def test_a_macos_host_is_refused(self):
        r = self._call({'device_id': 'mac1', 'id': 'chk1', 'op': 'delete'})
        self.assertEqual(r.get('s'), 400)
        self.assertEqual(self._queued('mac1'), [])

    def test_the_refusal_names_the_host(self):
        """An error that says only "unsupported" makes the operator guess which
        of their selected hosts was the problem."""
        r = self._call({'device_id': 'win1', 'id': 'chk1', 'op': 'restore'})
        self.assertIn('desk01', str(r.get('d')))


class TestFleetRebaselineIsPartialNotAllOrNothing(_Base):
    def setUp(self):
        super().setUp()
        api.save(api.CONFIG_FILE, {'custom_checks': [
            {'id': 'chk1', 'name': 'sshd config', 'type': 'file'}]})
        api._invalidate_load_cache(api.CONFIG_FILE)
        api._custom_check_applies = lambda cdef, d, dev: True

    def test_linux_hosts_are_rebaselined_and_the_rest_reported(self):
        r = self._call({'id': 'chk1', 'op': 'rebaseline'})
        self.assertEqual(r.get('s'), 200)
        self.assertEqual(r['d'].get('devices'), 1,
                         'only the Linux host should be queued')
        self.assertEqual(sorted(r['d'].get('skipped') or []),
                         ['desk01', 'mbp01'],
                         'the skipped hosts must be named, not silently dropped')
        self.assertTrue(self._queued('lin1'))
        self.assertEqual(self._queued('win1'), [])
        self.assertEqual(self._queued('mac1'), [])

    def test_an_all_linux_fleet_reports_no_skips(self):
        """The other direction: `skipped` must be empty rather than absent-ish,
        so the client's partial-success toast does not fire on a clean run."""
        api.save(api.DEVICES_FILE, {
            'lin1': {'name': 'web01', 'os': 'Debian GNU/Linux 12'}})
        api._invalidate_load_cache(api.DEVICES_FILE)
        r = self._call({'id': 'chk1', 'op': 'rebaseline'})
        self.assertEqual(r.get('s'), 200)
        self.assertEqual(r['d'].get('skipped'), [])
        self.assertEqual(r['d'].get('skipped_reason'), '')

    def test_a_fleet_with_no_linux_hosts_is_refused_outright(self):
        api.save(api.DEVICES_FILE, {
            'win1': {'name': 'desk01', 'os': 'Windows 11 Pro'}})
        api._invalidate_load_cache(api.DEVICES_FILE)
        r = self._call({'id': 'chk1', 'op': 'rebaseline'})
        self.assertEqual(r.get('s'), 400)


class TestTheAgentsReallyDoIgnoreIt(unittest.TestCase):
    """DERIVE the premise from the agent sources rather than trusting this
    file's own docstring. If Windows or macOS ever implements guard_actions,
    this fails and the gate above should be narrowed — the failure is the
    notification."""

    def test_only_the_linux_agent_honours_guard_actions(self):
        client = _ROOT / 'client'
        for name, expect in (('remotepower-agent.py', True),
                             ('remotepower-agent-win.py', False),
                             ('remotepower-agent-mac.py', False)):
            src = (client / name).read_text()
            honours = "resp.get('guard_actions')" in src
            self.assertEqual(honours, expect,
                             f'{name}: honours guard_actions={honours}, '
                             f'expected {expect}. If a platform gained '
                             'support, widen _split_targets_by_os_support in '
                             'guard_handlers.handle_guard_action.')


if __name__ == '__main__':
    unittest.main()
