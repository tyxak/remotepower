#!/usr/bin/env python3
"""Regression tests for the seed-demo-data.py production-safety guard.

A miss here once clobbered a live /var/lib/remotepower with fake data. The
guard (_guard_demo_target) must refuse to --apply into anything that looks
like production. These tests load the script as a module and exercise the
guard directly.
"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_SCRIPT = Path(__file__).parent.parent / "packaging" / "seed-demo-data.py"


def _load():
    spec = importlib.util.spec_from_file_location("seed_demo_data", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)   # safe: main() is gated by __name__ guard
    return mod


class TestSeedGuard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = _load()

    def _tmp(self):
        return Path(tempfile.mkdtemp(prefix="rp_seedguard_"))

    def test_default_dir_is_demo_not_production(self):
        self.assertEqual(str(self.m.DEFAULT_DATA_DIR), "/var/lib/remotepower-demo")
        self.assertIn("/var/lib/remotepower", self.m.PROTECTED_DATA_DIRS)

    def test_empty_dir_is_allowed(self):
        d = self._tmp()
        (d / "x").rmdir() if (d / "x").exists() else None
        ok, _ = self.m._guard_demo_target(d)
        self.assertTrue(ok)

    def test_production_path_blocked(self):
        ok, reason = self.m._guard_demo_target(Path("/var/lib/remotepower"))
        self.assertFalse(ok)
        self.assertIn("production", reason.lower())

    def test_real_accounts_blocked_even_with_override_and_marker(self):
        d = self._tmp()
        (d / self.m.DEMO_MARKER).write_text("x")          # even if mismarked
        (d / "users.json").write_text(json.dumps({"jmo": {"role": "admin"}}))
        ok, reason = self.m._guard_demo_target(d, override=True)   # even with override
        self.assertFalse(ok)
        self.assertIn("non-demo", reason.lower())

    def test_default_admin_does_not_block_demo_seed(self):
        # The app auto-creates a never-used `admin` (must_change_password) on a
        # fresh demo instance; that must NOT block seeding (it used to).
        d = self._tmp()
        (d / self.m.DEMO_MARKER).write_text("x")
        (d / "users.json").write_text(json.dumps(
            {"admin": {"role": "admin", "must_change_password": True,
                       "password_hash": "x"}}))
        ok, _ = self.m._guard_demo_target(d)
        self.assertTrue(ok)
        # …but a real admin (password changed → no flag) still blocks.
        (d / "users.json").write_text(json.dumps(
            {"admin": {"role": "admin", "password_hash": "x"}}))
        ok2, reason2 = self.m._guard_demo_target(d)
        self.assertFalse(ok2)
        self.assertIn("non-demo", reason2.lower())

    def test_demo_accounts_only_not_treated_as_real(self):
        d = self._tmp()
        (d / "users.json").write_text(json.dumps({"demo": {}, "alice": {}, "bob": {}}))
        # demo accounts alone shouldn't trip the real-account check; but the dir
        # is non-empty without a marker, so it's still blocked by rule 3 …
        ok, reason = self.m._guard_demo_target(d)
        self.assertFalse(ok)
        self.assertIn(self.m.DEMO_MARKER, reason)
        # … and allowed once the marker is present.
        (d / self.m.DEMO_MARKER).write_text("x")
        ok2, _ = self.m._guard_demo_target(d)
        self.assertTrue(ok2)

    def test_nonempty_unmarked_dir_blocked(self):
        d = self._tmp()
        (d / "devices.json").write_text("{}")
        ok, reason = self.m._guard_demo_target(d)
        self.assertFalse(ok)
        self.assertIn(self.m.DEMO_MARKER, reason)

    def test_unreadable_users_json_blocked(self):
        d = self._tmp()
        (d / "users.json").write_text("{not valid json")
        ok, _ = self.m._guard_demo_target(d, override=True)
        self.assertFalse(ok)


class TestSeedNewData(unittest.TestCase):
    """The v5.0.0 demo additions seed valid, self-consistent data."""

    @classmethod
    def setUpClass(cls):
        cls.m = _load()

    def test_new_files_registered(self):
        for f in ('thermal_history.json', 'dmarc_targets.json',
                  'dmarc_results.json', 'ip_reputation_targets.json',
                  'ip_reputation_results.json', 'resolver_health_targets.json',
                  'resolver_health_results.json'):
            self.assertIn(f, self.m.BUILDERS, f)

    def test_monitor_target_result_ids_match(self):
        # A target with no matching result (or vice versa) renders broken rows.
        for base in ('dmarc', 'ip_reputation', 'resolver_health'):
            t = self.m.BUILDERS[f'{base}_targets.json']()
            r = self.m.BUILDERS[f'{base}_results.json']()
            self.assertEqual(set(t), set(r), base)

    def test_business_function_allowlist(self):
        allowed = {'', 'Application Operation', 'OS Operation', 'Server Camp'}
        cmdb = self.m.build_cmdb()
        vals = {v.get('business_function', '') for v in cmdb.values()}
        self.assertTrue(vals <= allowed, vals)
        self.assertTrue({'Application Operation', 'OS Operation', 'Server Camp'} & vals)

    def test_thermal_history_shape(self):
        th = self.m.build_thermal_history()
        self.assertTrue(th)
        for rec in th.values():
            self.assertTrue(rec['samples'])
            self.assertIn('temp', rec['samples'][0])
            self.assertIn('ts', rec['samples'][0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
