"""
v7.0.2 — four hot-path costs that were paid on every request, each held here by
BEHAVIOUR (a counted read, a counted recompute) rather than only by a source
grep, because a grep proves a line exists and never that it works.

  1. ``_maybe_sample_compliance`` is a DAILY sampler whose gate is "has today's
     sample been appended?". When ``_compute_compliance()`` returns None — no
     device yields a single applicable check, i.e. an all-agentless or SNMP-only
     fleet, agents that have not reported yet, or an operator who turned every
     CIS check off — it returned from inside the write lock without writing
     anything, so the gate stayed open and the whole O(fleet) evaluation re-ran
     on EVERY request. Measured 42 ms/request at 400 devices, plus one
     re-serialise-and-fsync of the history store per read-only GET.
  2. The Checks page and the ``checksrollup`` widget read the fleet-checks
     cache — the whole unscoped check matrix, 2.9 MB at 400 hosts — through
     ``load()``, which deep-copies on every read, for purely read-only use.
     ``handle_fleet_checks`` deep-copied the fleet on top of that.
  3. ``require_perm`` deep-copied the entire fleet to look up two or three
     device ids. It sits on the RBAC gate of every write from a scoped role.
  4. ``_attention_fingerprint`` omitted the device key set that both of its
     documented mirrors (``_reliability_fingerprint``, ``_risk_fingerprint``)
     include, so enrolling or deleting a host was invisible to Needs Attention
     — and to fleet health, which is derived purely from those items — for the
     full 10 s TTL.

Pure stdlib ``unittest`` so it runs under ``python -m unittest discover`` (what
``make dist`` uses on the staged release tree) as well as pytest.
"""
import hashlib
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

# api.py runs ensure_default_user() at import, which WRITES — pin the data dir
# before the import or a targeted run of this module targets a live install.
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))
sys.path.insert(0, str(_ROOT / "tests"))

import api  # noqa: E402
import srcpin  # noqa: E402

_API_SRC = (_ROOT / "server" / "cgi-bin" / "api.py").read_text()


class _Base(unittest.TestCase):
    _FILES = ("DEVICES_FILE", "CONFIG_FILE", "COMPLIANCE_HIST_FILE",
              "HARDWARE_FILE", "ALERTS_FILE", "FLEET_EVENTS_FILE",
              "IGNORED_ITEMS_FILE", "ALERT_MUTES_FILE", "DRIFT_STATE_FILE",
              "USERS_FILE", "ROLES_FILE")
    _FUNCS = ("respond", "audit_log", "method", "get_token_from_request",
              "verify_token", "get_json_obj")

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._saved = {a: getattr(api, a) for a in self._FILES}
        for a in self._FILES:
            # The BASENAME is the storage key on the SQL backends.
            setattr(api, a, self.tmp / self._saved[a].name)
        self._saved_fns = {f: getattr(api, f) for f in self._FUNCS}
        api.respond = lambda status, body=None: (
            _ for _ in ()).throw(api.HTTPError(status, body))
        api.audit_log = lambda *a, **k: None
        api.method = lambda: "GET"
        api.get_json_obj = lambda: {}
        api.get_token_from_request = lambda: "tk"
        api.verify_token = lambda t: ("admin", "admin")
        api._RCTX.environ = {"QUERY_STRING": "", "REQUEST_METHOD": "GET"}
        api._LOAD_CACHE.clear()
        # The rollup caches are keyed off DATA_DIR, which the fixture does not
        # move; clear them so one test's warm cache is not another's answer.
        for f in (api._fleet_checks_cache_file(), api._attention_cache_file()):
            try:
                f.unlink()
            except OSError:
                pass

    def tearDown(self):
        for a, v in self._saved.items():
            setattr(api, a, v)
        for f, v in self._saved_fns.items():
            setattr(api, f, v)
        api._LOAD_CACHE.clear()

    def seed(self, n, sysinfo=True):
        now = int(time.time())
        api.save(api.DEVICES_FILE, {
            f"d{i}": {"name": f"h{i}", "last_seen": now, "monitored": True,
                      "group": "g", "os": "Linux",
                      "sysinfo": ({"cpu_percent": 10, "mem_percent": 20,
                                   "swap_percent": 1,
                                   "mounts": [{"path": "/", "percent": 40,
                                               "inode_percent": 5}]}
                                  if sysinfo else {})}
            for i in range(n)})
        api._LOAD_CACHE.clear()


class TestComplianceSamplerClaimsItsSlot(_Base):
    """The failure only shows when the score is None, which is a real and
    operator-reachable state — not an edge case."""

    def _count_calls(self, n_calls=3, sysinfo=True):
        self.seed(6, sysinfo=sysinfo)
        calls = []
        real = api._compute_compliance
        api._compute_compliance = lambda *a, **k: (calls.append(1),
                                                   real(*a, **k))[1]
        try:
            for _ in range(n_calls):
                api._maybe_sample_compliance()
                api._LOAD_CACHE.clear()
        finally:
            api._compute_compliance = real
        return len(calls)

    def test_a_none_score_still_claims_the_day(self):
        """An all-agentless fleet yields no applicable check, so the score is
        None. Before the fix nothing was written and the O(fleet) evaluation
        ran again on the next request, forever."""
        api.save(api.CONFIG_FILE, {})
        api._LOAD_CACHE.clear()
        # No sysinfo on any host → tot_w == 0 → score is None.
        self.assertIsNone(api._compute_compliance().get("score"))
        n = self._count_calls(n_calls=5, sysinfo=False)
        self.assertEqual(1, n,
                         "_compute_compliance re-ran on every call — the "
                         "daily slot was never claimed")
        store = api.load(api.COMPLIANCE_HIST_FILE) or {}
        day = time.strftime("%Y-%m-%d", time.gmtime())
        self.assertEqual(day, store.get("last_attempt"))
        self.assertEqual([], store.get("fleet") or [],
                         "a None score must not be recorded as a sample")

    def test_a_real_score_is_still_sampled_exactly_once(self):
        """Positive control: the claim must not swallow the success path."""
        api.save(api.CONFIG_FILE, {})
        api._LOAD_CACHE.clear()
        n = self._count_calls(n_calls=4, sysinfo=True)
        self.assertEqual(1, n)
        fleet = (api.load(api.COMPLIANCE_HIST_FILE) or {}).get("fleet") or []
        self.assertEqual(1, len(fleet))
        self.assertIsNotNone(fleet[0].get("score"))

    def test_the_o_fleet_compute_does_not_hold_the_write_lock(self):
        """On SQLite/Postgres that lock is a BEGIN IMMEDIATE which blocks every
        heartbeat for as long as it is open, so an O(fleet) evaluation must not
        run inside one. Asked of the RUNNING code via the lock scope stack, not
        of the source text."""
        self.seed(6)
        api.save(api.CONFIG_FILE, {})
        api._LOAD_CACHE.clear()
        held = []
        real = api._compute_compliance
        api._compute_compliance = lambda *a, **k: (held.append(api._locks_held()),
                                                   real(*a, **k))[1]
        try:
            api._maybe_sample_compliance()
        finally:
            api._compute_compliance = real
        self.assertEqual([False], held,
                         "_compute_compliance ran with a write lock open")
        # Control: the probe reports True when a lock really is open.
        with api._LockedUpdate(api.COMPLIANCE_HIST_FILE):
            self.assertTrue(api._locks_held())


class TestReadOnlyFleetReadsSkipTheDeepcopy(_Base):
    """`load()` deep-copies on every read, warm or cold. `_load_ro` hands back
    the shared cached object, so a caller that writes through it corrupts the
    cache for every later reader in the same request — the contract is
    load-bearing, and this asserts BOTH halves: the copy is skipped, and the
    shared store is byte-identical afterwards."""

    def _hash(self, obj):
        return hashlib.sha256(
            json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()

    def test_checks_path_does_not_deepcopy_the_matrix_or_the_fleet(self):
        self.seed(25)
        api.save(api.CONFIG_FILE, {})
        api._LOAD_CACHE.clear()
        seen = []
        real = api.load
        api.load = lambda p, *a, **k: (seen.append(getattr(p, "name", str(p))),
                                       real(p, *a, **k))[1]
        try:
            api._LOAD_CACHE.clear()
            try:
                api.handle_fleet_checks()
            except api.HTTPError:
                pass
        finally:
            api.load = real
        self.assertNotIn("fleet_checks_cache.json", seen)
        self.assertNotIn("devices.json", seen)
        # Control: the instrument does see a load() that is still there.
        self.assertIn("config.json", seen)

    def test_the_shared_objects_are_not_written_through(self):
        self.seed(25)
        api.save(api.CONFIG_FILE, {})
        api._LOAD_CACHE.clear()
        try:
            api.handle_fleet_checks()          # warm the file-backed cache
        except api.HTTPError:
            pass
        api._LOAD_CACHE.clear()
        shared_dev = api._load_ro(api.DEVICES_FILE)
        shared_cache = api._load_ro(api._fleet_checks_cache_file())
        before = (self._hash(shared_dev), self._hash(shared_cache))
        bodies = []
        for _ in range(2):
            try:
                api.handle_fleet_checks()
            except api.HTTPError as e:
                bodies.append(e.body)
        self.assertEqual((self._hash(shared_dev), self._hash(shared_cache)),
                         before, "a handler wrote through a _load_ro result")
        self.assertEqual(bodies[0], bodies[1])
        self.assertEqual(25, bodies[0]["total"])
        # Control: the hash instrument can see a write.
        shared_cache["hosts"][0]["name"] = "MUTATED"
        self.assertNotEqual(self._hash(shared_cache), before[1])

    def test_nav_counts_cache_read_is_shared(self):
        self.assertIn("_c = _load_ro(_nc_cache)", _API_SRC)


class TestRequirePermReadsOneDeviceAtATime(_Base):
    """The identical shape device_get() was fixed for in v6.4.3; the RBAC gate
    was not swept with it."""

    def test_no_whole_fleet_load_for_a_scope_check(self):
        self.seed(40)
        api.save(api.ROLES_FILE, {"roles": [
            {"name": "operator", "permissions": ["reboot"],
             "scope": {"type": "groups", "values": ["g"]}}]})
        api._LOAD_CACHE.clear()
        api.verify_token = lambda t: ("op", "operator")
        seen = []
        real = api.load
        api.load = lambda p, *a, **k: (seen.append(getattr(p, "name", str(p))),
                                       real(p, *a, **k))[1]
        try:
            api._LOAD_CACHE.clear()
            self.assertEqual("op", api.require_perm(
                "reboot", ["d0", "d7", "d14"]))
        finally:
            api.load = real
        self.assertNotIn("devices.json", seen)
        # Control: the roles read still goes through load(), so an empty `seen`
        # would have meant a broken instrument rather than a fixed handler.
        self.assertIn("roles.json", seen)

    def test_an_out_of_scope_target_is_still_refused(self):
        """The under-permissive direction — the cheap lookup must not become a
        lookup that always succeeds."""
        self.seed(4)
        devs = api.load(api.DEVICES_FILE)
        devs["d3"]["group"] = "other"
        api.save(api.DEVICES_FILE, devs)
        api.save(api.ROLES_FILE, {"roles": [
            {"name": "operator", "permissions": ["reboot"],
             "scope": {"type": "groups", "values": ["g"]}}]})
        api._LOAD_CACHE.clear()
        api.verify_token = lambda t: ("op", "operator")
        self.assertEqual("op", api.require_perm("reboot", ["d0", "d1"]))
        with self.assertRaises(api.HTTPError) as cm:
            api.require_perm("reboot", ["d0", "d3"])
        self.assertEqual(403, cm.exception.status)


class TestAttentionCacheSeesTheDeviceSet(_Base):
    """Three of the four short-TTL rollup caches fold the device key set into
    their fingerprint; this one did not, so an added or removed host was
    invisible to Needs Attention and to fleet health for the full TTL."""

    def test_fingerprint_moves_when_a_device_is_added(self):
        self.seed(3)
        api.save(api.CONFIG_FILE, {})
        api._LOAD_CACHE.clear()
        fp1 = api._attention_fingerprint()
        devs = api.load(api.DEVICES_FILE)
        devs["new"] = {"name": "new", "last_seen": 0, "monitored": True,
                       "sysinfo": {}}
        api.save(api.DEVICES_FILE, devs)
        api._LOAD_CACHE.clear()
        self.assertNotEqual(fp1, api._attention_fingerprint())

    def test_a_newly_offline_host_appears_inside_the_ttl(self):
        self.seed(3)
        api.save(api.CONFIG_FILE, {})
        api._LOAD_CACHE.clear()
        base = api._attention_payload()
        self.assertEqual(0, base["counts"]["critical"])
        devs = api.load(api.DEVICES_FILE)
        devs["ghost"] = {"name": "ghost", "last_seen": int(time.time()) - 99999,
                         "monitored": True, "sysinfo": {}}
        api.save(api.DEVICES_FILE, devs)
        api._LOAD_CACHE.clear()
        after = api._attention_payload()        # well inside the 10 s TTL
        self.assertGreater(after["total"], base["total"],
                           "the attention cache did not see the new device")

    def test_it_matches_its_two_documented_mirrors(self):
        for name in ("_attention_fingerprint", "_reliability_fingerprint",
                     "_risk_fingerprint"):
            body = srcpin.py_function(_API_SRC, name)
            self.assertIn("parts = [_device_set_fingerprint()]", body, name)


if __name__ == "__main__":
    unittest.main()
