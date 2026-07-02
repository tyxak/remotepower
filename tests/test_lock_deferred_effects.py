#!/usr/bin/env python3
"""Lock-deferred side-effects (the lock-nesting bug class, fixed by design).

fire_webhook / audit_log / log_command are self-locking recorders. Calling
one while a _LockedUpdate / _DeviceUpdate scope was open used to nest
transactions under the SQL backends (OperationalError, swallowed → the
alert/event/audit row silently vanished) and recurred at least five times
despite the collect-then-fire rule. The recorders now AUTO-DEFER: called
inside any lock scope they queue themselves and run right after the
outermost lock releases; a scope that raises (or respond()s) discards what
it queued — the aborted save's events must not fire.

These tests drive the REAL fire path (per CLAUDE.md webhook §7 — no
hand-built alert dicts) and run under both backends via make test-both.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_CGI_BIN = Path(__file__).parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI_BIN))

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())
os.environ.setdefault('REQUEST_METHOD', 'GET')
os.environ.setdefault('PATH_INFO', '/')
os.environ.setdefault('CONTENT_LENGTH', '0')

_spec = importlib.util.spec_from_file_location('api_lockdefer', _CGI_BIN / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _events():
    api._invalidate_load_cache(api.FLEET_EVENTS_FILE)
    return (api.load(api.FLEET_EVENTS_FILE) or {}).get('events', [])


def _alerts():
    api._invalidate_load_cache(api.ALERTS_FILE)
    return (api.load(api.ALERTS_FILE) or {}).get('alerts', [])


def _audit_entries():
    api._invalidate_load_cache(api.AUDIT_LOG_FILE)
    return (api.load(api.AUDIT_LOG_FILE) or {}).get('entries', [])


class LockDeferredBase(unittest.TestCase):
    def setUp(self):
        for f in (api.FLEET_EVENTS_FILE, api.ALERTS_FILE, api.AUDIT_LOG_FILE,
                  api.HISTORY_FILE):
            api.save(f, {})
        # A pathological earlier test could leave scope state behind — assert
        # the invariant instead of hiding a leak.
        self.assertFalse(api._locks_held(), 'lock-scope leak from another test')


class TestFireWebhookDeferral(LockDeferredBase):
    def test_immediate_when_no_lock_held(self):
        api.fire_webhook('device_offline', {'device_id': 'd1', 'name': 'host1'})
        self.assertEqual(len(_events()), 1)

    def test_deferred_until_lock_exit(self):
        with api._LockedUpdate(api.CONFIG_FILE) as cfg:
            api.fire_webhook('device_offline', {'device_id': 'd1', 'name': 'host1'})
            # Queued, not yet recorded (this is the exact call pattern that
            # used to silently lose the event under SQLite).
            self.assertEqual(len(_events()), 0)
            self.assertEqual(len(api._LOCK_SCOPES.pending), 1)
            cfg['_lockdefer_probe'] = 1
        ev = _events()
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0].get('event'), 'device_offline')
        # The real _record_alert path ran too (device_offline is alertable).
        self.assertTrue(any(a.get('event') == 'device_offline' for a in _alerts()))

    def test_aborted_scope_discards_queued_events(self):
        with self.assertRaises(ValueError):
            with api._LockedUpdate(api.CONFIG_FILE):
                api.fire_webhook('device_offline', {'device_id': 'd1'})
                raise ValueError('abort — save is skipped, events must not fire')
        self.assertEqual(len(_events()), 0)
        self.assertFalse(api._locks_held())

    def test_systemexit_scope_discards_queued_events(self):
        # respond() raises SystemExit; an aborted handler's events must die
        # with its aborted save.
        with self.assertRaises(SystemExit):
            with api._LockedUpdate(api.CONFIG_FILE):
                api.fire_webhook('device_offline', {'device_id': 'd1'})
                raise SystemExit(0)
        self.assertEqual(len(_events()), 0)

    def test_nested_scopes_flush_only_at_outermost_exit(self):
        # Two nested _LockedUpdate scopes are only possible under the JSON
        # backend (per-file flocks). Under SQLite/Postgres one shared
        # connection per directory means the inner BEGIN IMMEDIATE throws at
        # __enter__ — the very constraint this deferral mechanism exists to
        # route around — so nesting depth never exceeds 1 there.
        if api._dbmod() is not None:
            self.skipTest('nested lock scopes are impossible under DB backends')
        with api._LockedUpdate(api.CONFIG_FILE):
            with api._LockedUpdate(api.HISTORY_FILE):
                api.fire_webhook('device_offline', {'device_id': 'd1'})
            # inner scope closed cleanly — still one open lock, still queued
            self.assertEqual(len(_events()), 0)
        self.assertEqual(len(_events()), 1)

    def test_inner_abort_keeps_outer_scope_events(self):
        if api._dbmod() is not None:
            self.skipTest('nested lock scopes are impossible under DB backends')
        with api._LockedUpdate(api.CONFIG_FILE):
            api.fire_webhook('device_online', {'device_id': 'd1'})   # outer scope
            try:
                with api._LockedUpdate(api.HISTORY_FILE):
                    api.fire_webhook('device_offline', {'device_id': 'd2'})
                    raise ValueError('inner abort')
            except ValueError:
                pass
        ev = _events()
        self.assertEqual([e.get('event') for e in ev], ['device_online'])

    def test_payload_snapshot_at_defer_time(self):
        payload = {'device_id': 'd1', 'name': 'host1'}
        with api._LockedUpdate(api.CONFIG_FILE):
            api.fire_webhook('device_offline', payload)
            payload['name'] = 'mutated-after-call'
        ev = _events()
        self.assertEqual(ev[0]['payload'].get('name'), 'host1')

    def test_device_update_scope_defers_too(self):
        with api._DeviceUpdate('d1') as devs:
            devs['d1'] = {'name': 'host1'}
            api.fire_webhook('device_offline', {'device_id': 'd1'})
            self.assertEqual(len(_events()), 0)
        self.assertEqual(len(_events()), 1)


class TestAuditAndCommandDeferral(LockDeferredBase):
    def test_audit_log_deferred_and_recorded(self):
        with api._LockedUpdate(api.CONFIG_FILE):
            api.audit_log('tester', 'unit_test_action', 'detail-x')
            self.assertEqual(len(_audit_entries()), 0)
        entries = _audit_entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]['action'], 'unit_test_action')

    def test_log_command_deferred_and_recorded(self):
        with api._LockedUpdate(api.CONFIG_FILE):
            api.log_command('tester', 'd1', 'host1', 'uptime')
            api._invalidate_load_cache(api.HISTORY_FILE)
            self.assertEqual(
                len((api.load(api.HISTORY_FILE) or {}).get('entries', [])), 0)
        api._invalidate_load_cache(api.HISTORY_FILE)
        entries = (api.load(api.HISTORY_FILE) or {}).get('entries', [])
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]['command'], 'uptime')

    def test_flush_order_preserves_call_order(self):
        with api._LockedUpdate(api.CONFIG_FILE):
            api.fire_webhook('device_offline', {'device_id': 'd1'})
            api.fire_webhook('device_online', {'device_id': 'd1'})
        self.assertEqual([e.get('event') for e in _events()],
                         ['device_offline', 'device_online'])


if __name__ == '__main__':
    unittest.main()
