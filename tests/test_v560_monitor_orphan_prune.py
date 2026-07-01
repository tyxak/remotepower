#!/usr/bin/env python3
"""v5.6.x: a deleted/renamed monitor must not leave a phantom "down" behind.

The "monitors down" badge (``/api/nav-counts`` + the dashboard rollup) counts
the latest result of every *monitor_history key*, not the live ``cfg.monitors``.
So a monitor that was deleted while its last check had failed kept being
counted as down until it aged past the 1-hour recency window — the table showed
everything up, the sidebar showed "1 down".  Reproduced live: creating a "Test"
monitor, letting one check fail, then deleting it left ``monitor_fail_streak =
{'Test': 1}`` and a failing ``monitor_history['Test']`` entry, so the badge stuck
at 1.

The fix prunes every per-monitor state (history + the monitor_notified /
monitor_fail_streak flag maps) keyed to a label that's no longer configured,
at config-save time and on "Reset alerts".  Tag/group monitors fan out to
``<label> · <device>`` history keys, so a surviving monitor keeps all of those.
"""
import importlib.util
import os
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
import sys
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v560orphan", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _entry(ok, ts=None):
    return {'ts': ts if ts is not None else int(time.time()),
            'ok': ok, 'detail': 'x'}


class TestLabelMatcher(unittest.TestCase):
    def test_bare_and_fanout_and_orphan(self):
        live = {'Jellyfin', 'LAN'}
        # bare label of a configured monitor → live
        self.assertTrue(api._monitor_label_is_live('Jellyfin', live))
        # tag/group fan-out sub-key of a configured monitor → live
        self.assertTrue(api._monitor_label_is_live(f'LAN{api._MON_FANOUT_SEP}nas', live))
        # a label that no longer exists → orphan
        self.assertFalse(api._monitor_label_is_live('Test', live))
        # a fan-out sub-key whose base is gone → orphan
        self.assertFalse(api._monitor_label_is_live(f'Old{api._MON_FANOUT_SEP}nas', live))
        # substring-but-not-a-fanout must NOT count as live (no separator)
        self.assertFalse(api._monitor_label_is_live('JellyfinX', live))


class _Base(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._saved = {}
        for name in ('CONFIG_FILE', 'MON_HIST_FILE'):
            self._saved[name] = getattr(api, name)
            setattr(api, name, self.d / Path(getattr(api, name)).name)

    def tearDown(self):
        for name, v in self._saved.items():
            setattr(api, name, v)

    def _down_count(self):
        """Replicate the exact nav-counts / dashboard 'monitors down' loop."""
        cut = int(time.time()) - 3600
        down = 0
        for v in (api.load(api.MON_HIST_FILE) or {}).values():
            if (isinstance(v, list) and v and isinstance(v[-1], dict)
                    and (v[-1].get('ts') or 0) >= cut and not v[-1].get('ok')):
                down += 1
        return down


class TestPruneHelper(_Base):
    def test_prune_drops_orphans_keeps_live_and_fanout(self):
        sep = api._MON_FANOUT_SEP
        api.save(api.MON_HIST_FILE, {
            'Jellyfin':        [_entry(True)],
            f'LAN{sep}nas':    [_entry(True)],
            f'LAN{sep}router': [_entry(False)],   # a live fanned-out target down — KEEP
            'Test':            [_entry(False)],    # orphan, down — DROP
        })
        removed = api._prune_orphan_monitor_history({'Jellyfin', 'LAN'})
        self.assertEqual(removed, 1)
        mh = api.load(api.MON_HIST_FILE)
        self.assertIn('Jellyfin', mh)
        self.assertIn(f'LAN{sep}nas', mh)
        self.assertIn(f'LAN{sep}router', mh)   # still-configured monitor kept even though down
        self.assertNotIn('Test', mh)
        # the phantom "down" is gone; the real fan-out "down" remains
        self.assertEqual(self._down_count(), 1)

    def test_prune_noop_when_nothing_orphaned(self):
        api.save(api.MON_HIST_FILE, {'Jellyfin': [_entry(True)]})
        self.assertEqual(api._prune_orphan_monitor_history({'Jellyfin'}), 0)
        self.assertEqual(list(api.load(api.MON_HIST_FILE)), ['Jellyfin'])


class _HandlerBase(_Base):
    """Drive real handlers with stubbed auth/request/respond (v3120 pattern)."""
    def setUp(self):
        super().setUp()
        self._orig = {n: getattr(api, n) for n in
                      ('require_admin_auth', 'require_auth', 'method',
                       'get_json_body', 'audit_log', 'respond', '_caller_scope')}
        api.require_admin_auth = lambda: 'jakob'
        api.require_auth = lambda require_admin=False: 'jakob'
        api.audit_log = lambda *a, **k: None
        api._caller_scope = lambda: None
        self.cap = {}
        def _resp(s, b=None):
            self.cap['s'] = s; self.cap['b'] = b
            raise api.HTTPError(s, b)
        api.respond = _resp

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        super().tearDown()

    def _call(self, fn, *a):
        try:
            fn(*a)
        except api.HTTPError:
            pass
        return self.cap.get('b')


class TestConfigSaveDeletePrunes(_HandlerBase):
    def test_deleting_a_monitor_prunes_its_stranded_state(self):
        """The reported bug: create 'Test', it fails, delete it → badge stuck."""
        api.save(api.CONFIG_FILE, {
            'monitors': [
                {'label': 'Jellyfin', 'type': 'http', 'target': 'https://jelly'},
                {'label': 'Test', 'type': 'tcp', 'target': '10.0.0.9:22'},
            ],
            'monitor_fail_streak': {'Test': 1},
            'monitor_notified': {'Test': True},
        })
        api.save(api.MON_HIST_FILE, {
            'Jellyfin': [_entry(True)],
            'Test':     [_entry(False)],   # last check failed → counted down
        })
        self.assertEqual(self._down_count(), 1)   # badge shows 1 before delete

        # The UI deletes a monitor by POSTing the surviving list to /api/config.
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'monitors': [
            {'label': 'Jellyfin', 'type': 'http', 'target': 'https://jelly'},
        ]}
        self._call(api.handle_config_save)

        cfg = api.load(api.CONFIG_FILE)
        self.assertEqual([m['label'] for m in cfg['monitors']], ['Jellyfin'])
        # stranded flags pruned
        self.assertNotIn('Test', cfg.get('monitor_fail_streak', {}))
        self.assertNotIn('Test', cfg.get('monitor_notified', {}))
        # stranded history pruned → phantom "down" gone
        self.assertNotIn('Test', api.load(api.MON_HIST_FILE))
        self.assertEqual(self._down_count(), 0)

    def test_unrelated_settings_save_leaves_history_untouched(self):
        api.save(api.CONFIG_FILE, {'monitors': [
            {'label': 'Jellyfin', 'type': 'http', 'target': 'https://jelly'}]})
        api.save(api.MON_HIST_FILE, {'Jellyfin': [_entry(True)],
                                     'Test': [_entry(False)]})
        # a save that doesn't include 'monitors' must not prune anything
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {'online_ttl': 200}
        self._call(api.handle_config_save)
        self.assertIn('Test', api.load(api.MON_HIST_FILE))


class TestResetAlertsSweeps(_HandlerBase):
    def test_reset_alerts_prunes_orphan_history(self):
        api.save(api.CONFIG_FILE, {'monitors': [
            {'label': 'Jellyfin', 'type': 'http', 'target': 'https://jelly'}]})
        api.save(api.MON_HIST_FILE, {'Jellyfin': [_entry(True)],
                                     'Test': [_entry(False)]})
        self.assertEqual(self._down_count(), 1)
        api.method = lambda: 'DELETE'
        self._call(api.handle_monitor_alerts_clear)
        self.assertNotIn('Test', api.load(api.MON_HIST_FILE))
        self.assertEqual(self._down_count(), 0)


if __name__ == '__main__':
    unittest.main()
