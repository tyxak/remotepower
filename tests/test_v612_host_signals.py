"""v6.1.2 — batch A: seven agent-side host signals.

1. **pacman kernel-mismatch.** get_kernel_status()'s comment always said "Arch:
   pacman linux" but no branch was ever written — and Arch has no
   /run/reboot-required either, so Arch boxes had NO kernel-reboot signal at all.
2. **ZFS/btrfs snapshot freshness.** Scrub recency has been checked since v3.11.0;
   snapshot recency never was — so a snapshot cron that quietly stopped stayed
   invisible until the day you needed to roll back.
3. **SMART self-test.** `-H -A -i` gives the drive's verdict and its attributes
   but never says whether a self-test has EVER run, so an untested disk looked
   identical to one tested last night. Plus NVMe available_spare.
4. **ECC/EDAC counters.** Homelabbers buy ECC precisely to catch failing DIMMs,
   then never look at the counters.
5. **zram.** Swap pressure on a Pi/Fedora box (where swap lives in compressed
   RAM) read as "this host is thrashing its disk", which is simply wrong.
6. **systemd unit flap.** A unit crash-looping under Restart=always is 'active'
   every time we sample it, so service_down NEVER fires — the host looks healthy
   while a service restarts all day.
7. **Auto-update posture.** A fleet where half the boxes silently auto-patch is
   one where "0 pending updates" means two different things.
"""

import importlib.util
import os
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v612-hs-"))
_spec = importlib.util.spec_from_file_location("api_v612_hs", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_AGENT = (_ROOT / "client/remotepower-agent.py").read_text()


class TestPacmanKernelBranch(unittest.TestCase):
    def test_the_arch_branch_finally_exists(self):
        i = _AGENT.index("def get_kernel_status")
        block = _AGENT[i : i + 4000]
        self.assertIn("_which('pacman')", block)
        self.assertIn("pkgbase", block)

    def test_it_reads_the_host_not_the_container(self):
        i = _AGENT.index("def get_kernel_status")
        block = _AGENT[i : i + 4000]
        self.assertIn("host_path(f'/usr/lib/modules/{run}')", block)

    def test_a_removed_modules_dir_means_reboot(self):
        # pacman deletes the running kernel's modules during an upgrade — that
        # alone unambiguously means a reboot is required.
        i = _AGENT.index("def get_kernel_status")
        block = _AGENT[i : i + 4000]
        self.assertIn("not os.path.isdir(mod_dir)", block)


class TestSnapshotFreshness(unittest.TestCase):
    def setUp(self):
        api.fire_webhook = lambda ev, pl=None: self.fired.append((ev, pl or {}))
        self.fired = []
        api.save(api.CONFIG_FILE, {"snapshot_stale_days": 7})
        api._LOAD_CACHE.clear()

    def _pool(self, snap, name="tank"):
        return {"storage_health": [{"name": name, "kind": "zfs",
                                    "state": "ONLINE", "last_snapshot": snap}]}

    def test_events_are_registered_with_a_recover(self):
        self.assertIn("snapshot_stale", api.EVENT_REGISTRY)
        self.assertEqual(
            api.EVENT_REGISTRY["snapshot_ok"]["resolves"], ("snapshot_stale",)
        )

    def test_a_stale_pool_fires_then_recovers(self):
        now = int(time.time())
        old, fresh = now - 30 * 86400, now - 86400
        api._ingest_posture_v3110("s1", "h", self._pool(old))   # first_seen: silent
        self.assertEqual(self.fired, [])
        api._ingest_posture_v3110("s1", "h", self._pool(old))
        self.assertEqual([e for e, _ in self.fired], ["snapshot_stale"])
        self.fired.clear()
        api._ingest_posture_v3110("s1", "h", self._pool(old))   # edge: no re-fire
        self.assertEqual(self.fired, [])
        api._ingest_posture_v3110("s1", "h", self._pool(fresh))
        self.assertEqual([e for e, _ in self.fired], ["snapshot_ok"])

    def test_an_already_stale_pool_still_alerts_after_first_seen(self):
        # The scrub check marks a pool as fired even on the first_seen pass,
        # which suppresses it FOREVER. That's wrong here: you turn this setting
        # on precisely when you suspect staleness, so the already-stale pool
        # (the common case) must alert on the very next heartbeat.
        now = int(time.time())
        old = now - 90 * 86400
        api._ingest_posture_v3110("s2", "h", self._pool(old))
        api._ingest_posture_v3110("s2", "h", self._pool(old))
        self.assertEqual([e for e, _ in self.fired], ["snapshot_stale"])

    def test_a_pool_with_no_snapshots_at_all_never_alerts(self):
        # Plenty of pools are legitimately not snapshotted.
        for _ in range(3):
            api._ingest_posture_v3110("s3", "h", self._pool(0))
        self.assertEqual(self.fired, [])

    def test_off_by_default(self):
        api.save(api.CONFIG_FILE, {})
        api._LOAD_CACHE.clear()
        now = int(time.time())
        for _ in range(3):
            api._ingest_posture_v3110("s4", "h", self._pool(now - 999 * 86400))
        self.assertEqual(self.fired, [])

    def test_recovery_is_per_pool(self):
        # A device-id-only recovery would clear a pool whose snapshots are still
        # stale (the v6.0.1 lesson).
        now = int(time.time())
        old, fresh = now - 30 * 86400, now - 86400
        two = lambda a, b: {"storage_health": [
            {"name": "tank", "kind": "zfs", "state": "ONLINE", "last_snapshot": a},
            {"name": "vault", "kind": "zfs", "state": "ONLINE", "last_snapshot": b}]}
        api._ingest_posture_v3110("s5", "h", two(old, old))
        api._ingest_posture_v3110("s5", "h", two(old, old))
        self.fired.clear()
        api._ingest_posture_v3110("s5", "h", two(fresh, old))
        self.assertEqual(self.fired[0][0], "snapshot_ok")
        self.assertEqual(self.fired[0][1]["pool"], "tank")
        self.assertEqual(len(self.fired), 1, "vault is still stale — must NOT recover")

    def test_snapshot_ok_matches_on_the_pool(self):
        src = (_CGI / "api.py").read_text()
        i = src.index("elif event == 'snapshot_ok':")
        self.assertIn("sub_match['pool']", src[i : i + 500])


class TestSmartSelfTest(unittest.TestCase):
    def test_the_agent_reads_the_selftest_log(self):
        i = _AGENT.index("def get_smart_status")
        block = _AGENT[i : i + 6000]
        self.assertIn("'-l', 'selftest'", block)
        self.assertIn("Available Spare", block)

    def test_the_server_persists_the_new_fields(self):
        # The SMART sanitizer is a whitelist.
        src = (_CGI / "api.py").read_text()
        i = src.index("entry['wear_pct'] = int(w)")
        block = src[i : i + 1200]
        for k in ("spare_pct", "selftest_result", "selftest_hours"):
            self.assertIn(k, block, f"{k} must be persisted")


class TestEccErrors(unittest.TestCase):
    def setUp(self):
        self.fired = []
        api.fire_webhook = lambda ev, pl=None: self.fired.append((ev, pl or {}))

    def _ecc(self, ce, ue):
        return {"ecc": {"ce": ce, "ue": ue, "controllers": 1}}

    def test_counters_are_cumulative_so_only_a_DELTA_fires(self):
        api._ingest_posture_v3110("e1", "h", self._ecc(5, 0))   # first_seen
        self.assertEqual(self.fired, [])
        api._ingest_posture_v3110("e1", "h", self._ecc(5, 0))   # unchanged
        self.assertEqual(self.fired, [])
        api._ingest_posture_v3110("e1", "h", self._ecc(9, 0))
        self.assertEqual(self.fired[0][0], "ecc_errors")
        self.assertEqual(self.fired[0][1]["new_ce"], 4)

    def test_uncorrectable_is_critical_correctable_is_medium(self):
        self.assertEqual(
            api._alert_severity("ecc_errors", {"new_ce": 3, "new_ue": 0}), "medium"
        )
        self.assertEqual(
            api._alert_severity("ecc_errors", {"new_ce": 0, "new_ue": 1}), "critical"
        )

    def test_a_counter_reset_is_a_new_baseline_not_a_negative_delta(self):
        # EDAC counters clear on reboot.
        api._ingest_posture_v3110("e2", "h", self._ecc(100, 0))
        api._ingest_posture_v3110("e2", "h", self._ecc(100, 0))
        self.fired.clear()
        api._ingest_posture_v3110("e2", "h", self._ecc(2, 0))   # rebooted
        self.assertEqual(self.fired[0][1]["new_ce"], 2)

    def test_hosts_without_edac_report_nothing(self):
        i = _AGENT.index("def get_ecc_errors")
        self.assertIn("if not os.path.isdir(base):", _AGENT[i : i + 900])


class TestUnitFlapping(unittest.TestCase):
    def setUp(self):
        self.fired = []
        api.fire_webhook = lambda ev, pl=None: self.fired.append((ev, pl or {}))
        api.save(api.DEVICES_FILE, {"f1": {"name": "h", "monitored": True}})
        api.save(api.CONFIG_FILE, {"unit_flap_restarts": 3})
        api._LOAD_CACHE.clear()

    def _svc(self, n):
        return [{"unit": "app.service", "active": "active", "sub": "running",
                 "since": 1, "restarts": n}]

    def test_nrestarts_rides_the_existing_batched_call(self):
        # No extra subprocess per unit.
        self.assertIn("ActiveEnterTimestamp,NRestarts", _AGENT)

    def test_a_flapping_unit_fires_while_never_looking_down(self):
        # This is the entire point: the unit is 'active' at every sample, so
        # service_down can never fire for it.
        api.process_service_report("f1", self._svc(0))
        api.process_service_report("f1", self._svc(1))
        self.assertEqual(self.fired, [], "1 restart is below the threshold")
        api.process_service_report("f1", self._svc(6))
        self.assertEqual(self.fired[0][0], "unit_flapping")
        self.assertEqual(self.fired[0][1]["restarts"], 5)
        self.assertFalse(any(e == "service_down" for e, _ in self.fired))

    def test_no_new_restarts_is_silent(self):
        api.process_service_report("f1", self._svc(6))
        api.process_service_report("f1", self._svc(6))
        self.fired.clear()
        api.process_service_report("f1", self._svc(6))
        self.assertEqual(self.fired, [])

    def test_off_by_default(self):
        api.save(api.CONFIG_FILE, {})
        api._LOAD_CACHE.clear()
        api.process_service_report("f1", self._svc(0))
        api.process_service_report("f1", self._svc(99))
        self.assertEqual(self.fired, [])

    def test_the_event_is_registered(self):
        self.assertIn("unit_flapping", api.EVENT_REGISTRY)
        self.assertEqual(api.EVENT_REGISTRY["unit_flapping"]["kind"], "service")


class TestZramAndAutoUpdate(unittest.TestCase):
    def test_zram_is_collected_and_persisted(self):
        self.assertIn("def get_zram", _AGENT)
        src = (_CGI / "api.py").read_text()
        self.assertIn("safe_si['zram']", src)

    def test_autoupdate_posture_is_collected_and_persisted(self):
        self.assertIn("def get_autoupdate_posture", _AGENT)
        src = (_CGI / "api.py").read_text()
        self.assertIn("safe_si['autoupdate'] = {", src)

    def test_debians_periodic_zero_means_it_does_NOT_actually_patch(self):
        # unattended-upgrades can be ENABLED while the periodic switch is 0,
        # which means it does not apply updates — reporting "patches itself"
        # then would be a lie.
        i = _AGENT.index("def get_autoupdate_posture")
        block = _AGENT[i : i + 2200]
        self.assertIn("APT::Periodic::Unattended-Upgrade", block)

    def test_the_drawer_says_when_swap_is_zram(self):
        app = (_ROOT / "server/html/static/js/app.js").read_text()
        self.assertIn("' (zram)'", app)


class TestAgentStaysInSync(unittest.TestCase):
    def test_extensionless_copy_matches(self):
        self.assertEqual(
            (_ROOT / "client/remotepower-agent.py").read_bytes(),
            (_ROOT / "client/remotepower-agent").read_bytes(),
        )


if __name__ == "__main__":
    unittest.main()
