"""v5.6.0 finalize-sweep fixes — regression pins.

Covers the bug-hunt + live-pentest fixes: the alert-mute must also suppress the
browser push channel, the mute-set is memoized, the top-bar pill reflects
RemotePower's OWN control-plane health, the terraform env-injection guard, and
the blueprint status write is lock-safe.
"""
import os
import tempfile
import unittest
import sys as _as_sys
from pathlib import Path as _as_Path
_as_sys.path.insert(0, str(_as_Path(__file__).resolve().parent))
from apisrc import api_source as _apisrc_combined   # api.py + *_handlers.py bound modules (decomposition-safe pins)
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-sweep-'))

_ROOT = Path(__file__).parent.parent
_API = _apisrc_combined()
_APPJS = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()


class TestMuteSuppressesWebpush(unittest.TestCase):
    def test_mute_computed_once_and_guards_webpush(self):
        seg = _API[_API.index('def fire_webhook'):
                   _API.index('def fire_webhook') + 6000]
        # the mute is computed once, before the delivery channels…
        self.assertIn('_muted = _alert_muted(event, payload)', seg)
        # …and the browser push is gated on it (was firing before the mute check)
        self.assertIn('if not _muted:', seg)
        wp = seg.index('_maybe_webpush(event, payload)')
        guard = seg.rindex('if not _muted:', 0, wp)
        self.assertLess(wp - guard, 200,
                        'the webpush call must sit under the `if not _muted:` guard')

    def test_delivery_gate_reuses_the_flag(self):
        seg = _API[_API.index('def fire_webhook'):
                   _API.index('def fire_webhook') + 8000]
        self.assertIn('if _muted:\n        return', seg)


class TestMuteSetMemoized(unittest.TestCase):
    def test_mute_set_uses_mtime_cache(self):
        seg = _API[_API.index('def _alert_mute_set'):
                   _API.index('def _alert_mute_set') + 900]
        self.assertIn('_ALERT_MUTE_SET_CACHE', seg)
        self.assertIn('backend_mtime(ALERT_MUTES_FILE)', seg)


class TestSiteHealthIsOwnInfra(unittest.TestCase):
    def test_nav_counts_carries_site_health(self):
        # v6.1.2: widened — the conditional-GET + _load_ro work pushed
        # out['site_health'] to ~6634 from the top of the handler.
        seg = _API[_API.index('def handle_nav_counts'):
                   _API.index('def handle_nav_counts') + 9000]
        self.assertIn("out['site_health']", seg)
        self.assertIn('disk_watchdog_pct', seg)   # own-infra disk headroom, not fleet
        self.assertIn('statvfs', seg)

    def test_pill_painted_from_site_health_not_fleet(self):
        # _paintSiteHealth now takes the own-infra object, fed from c.site_health
        self.assertIn('_paintSiteHealth(c.site_health)', _APPJS)
        self.assertIn('function _paintSiteHealth(sh)', _APPJS)
        # and no longer summed from offline/openAlerts/down
        self.assertNotIn('_paintSiteHealth(offline, openAlerts, down)', _APPJS)


class TestTerraformEnvGuard(unittest.TestCase):
    def test_protected_env_names_not_clobbered(self):
        self.assertIn('_TF_ENV_PROTECTED', _API)
        seg = _API[_API.index('def _terraform_run'):
                   _API.index('def _terraform_run') + 1500]
        self.assertIn('_TF_ENV_PROTECTED', seg)
        self.assertIn("startswith(('LD_', 'DYLD_'))", seg)


class TestBlueprintStatusLock(unittest.TestCase):
    def test_run_status_write_is_locked(self):
        seg = _API[_API.index('def handle_blueprint_run'):
                   _API.index('def handle_blueprint_run') + 4000]
        self.assertRegex(seg, r'(?:A\.)?_LockedUpdate\((?:A\.)?PROVISION_FILE\)')


if __name__ == '__main__':
    unittest.main()
