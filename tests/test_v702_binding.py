"""
v7.0.2 — signals that were read from a key no producer writes, plus the two
device pins that had a reader and no writer.

Every case here shipped as a feature that looked wired end to end:

  1. **Config drift.** ``_ingest_drift_report`` writes DRIFT_STATE_FILE as
     ``{dev: {files: {path: {baseline_hash, current_hash, ignored, dormant,
     exists}}}}``. Ten consumers read ``dev['drift_state']`` — a key nothing
     writes — and looked for ``status == 'drifted'``, which no producer writes
     either. So the Checks row was absent (reading as "this host has no drift
     monitoring"), the ``config_drift`` risk factor could never fire,
     Needs-Attention had no drift item, ``?drift=1`` matched nothing, and the
     RAG could not answer "what has drifted?".
  2. **Autonomy blast radius.** ``containers`` is not in the safe_si whitelist
     and ``services.json`` has no ``watched`` key, so two of the four
     components scored zero on every host — in the function whose docstring
     says a safety input that fails open is worse than no safety input.
  3. **The AI runbook snapshot and the RAG live-state corpus** read
     ``dev['upgradable']`` / ``dev['patch_status']`` / ``dev['pkg_manager']`` /
     ``dev['services_watched_state']``. None of the four has a writer; the
     counts live under ``sysinfo.packages`` and unit state in SERVICES_FILE.
  4. **The autonomy catalog's FIFTH join.** ``_ladder_for`` reads its
     discriminator off the STORED alert, and ``_record_alert`` keeps only a
     whitelisted subset — ``kind`` was not on it, so every ``snapshot_stale``
     alert was dropped before the decision core and ``create_zfs_snapshot``
     could never fire.
  5. **``proxmox_guest`` / ``mtls_fingerprint``** — both documented as
     operator-settable, neither on any write path.
  6. Two refusals raised inside a ``try`` whose ``except Exception`` rewrote
     them to 500, and a read-only role appending to the billing ledger.

The drift and blast-radius cases drive the REAL heartbeat ingest rather than
hand-building a store: four existing test files seed ``drift_state`` straight
onto a device dict, which is why a dead feature passed review for releases.

Pure stdlib ``unittest`` so it runs under ``python -m unittest discover`` (what
``make dist`` uses on the staged release tree) as well as pytest.
"""
import os
import re
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
import advisory  # noqa: E402
import rag_index  # noqa: E402
import srcpin  # noqa: E402

_AOH = api.autonomy_ops_handlers_mod


class _Base(unittest.TestCase):
    """A private data dir, a stubbed responder that raises the real HTTPError,
    and an admin caller. Only verify_token is stubbed on the auth path — a
    stubbed require_auth would let an ungated handler pass."""

    _FILES = ("DEVICES_FILE", "CONFIG_FILE", "DRIFT_STATE_FILE", "ALERTS_FILE",
              "CONTAINERS_FILE", "SERVICES_FILE", "HARDWARE_FILE",
              "TIME_ENTRIES_FILE", "INBOUND_WEBHOOKS_FILE", "USERS_FILE",
              "ROLES_FILE", "IGNORED_ITEMS_FILE", "ALERT_MUTES_FILE",
              "FLEET_EVENTS_FILE", "LLDP_NEIGHBORS_FILE", "AUDIT_LOG_FILE")
    _FUNCS = ("respond", "audit_log", "fire_webhook", "log_command",
              "get_json_obj", "get_json_body", "method",
              "get_token_from_request", "verify_token")

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._saved = {a: getattr(api, a) for a in self._FILES}
        for a in self._FILES:
            # The BASENAME is the storage key: on SQLite/Postgres it picks the
            # TABLE, so an invented filename is not the store under test.
            setattr(api, a, self.tmp / self._saved[a].name)
        self._saved_fns = {f: getattr(api, f) for f in self._FUNCS}
        api.respond = lambda status, body=None: (
            _ for _ in ()).throw(api.HTTPError(status, body))
        api.audit_log = lambda *a, **k: None
        api.fire_webhook = lambda *a, **k: None
        api.log_command = lambda *a, **k: None
        api.get_json_obj = lambda: {}
        api.get_json_body = lambda: {}
        api.method = lambda: "GET"
        api.get_token_from_request = lambda: "tk"
        api.verify_token = lambda t: ("admin", "admin")
        api._RCTX.environ = {"QUERY_STRING": "", "REQUEST_METHOD": "GET"}
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for a, v in self._saved.items():
            setattr(api, a, v)
        for f, v in self._saved_fns.items():
            setattr(api, f, v)
        api._LOAD_CACHE.clear()

    # ── driving helpers ────────────────────────────────────────────────────
    def call(self, fn, *a, qs=""):
        api._RCTX.environ = {"QUERY_STRING": qs,
                             "REQUEST_METHOD": api.method()}
        try:
            fn(*a)
        except api.HTTPError as e:
            return e.status, e.body
        return None, None

    def heartbeat(self, body):
        api.method = lambda: "POST"
        api.get_json_obj = lambda: body
        st, _ = self.call(api.handle_heartbeat)
        api.method = lambda: "GET"
        api._LOAD_CACHE.clear()
        return st


class TestDriftIsBoundToItsStore(_Base):
    """Drive two real heartbeats — the first sets the baseline, the second
    changes the hash — then assert every consumer sees the drift."""

    DEV = "drifthost"
    PATH = "/etc/ssh/sshd_config"

    def setUp(self):
        super().setUp()
        now = int(time.time())
        api.save(api.DEVICES_FILE, {
            self.DEV: {"name": self.DEV, "hostname": self.DEV, "os": "Linux",
                       "token": "t", "last_seen": now, "enrolled": now,
                       "monitored": True, "tags": [], "group": "",
                       "sysinfo": {}},
            # A host with drift monitoring but NO drift: the control that
            # separates "the row appears" from "the row appears everywhere".
            "clean": {"name": "clean", "hostname": "clean", "os": "Linux",
                      "token": "t2", "last_seen": now, "enrolled": now,
                      "monitored": True, "tags": [], "group": "",
                      "sysinfo": {}},
        })
        api._LOAD_CACHE.clear()
        for h in ("aaa", "bbb"):
            self.assertEqual(200, self.heartbeat({
                "device_id": self.DEV, "token": "t",
                "sysinfo": {"hostname": self.DEV},
                "drift": {self.PATH: {"hash": h, "size": 10, "mtime": 1,
                                      "exists": True}}}))
        self.assertEqual(200, self.heartbeat({
            "device_id": "clean", "token": "t2",
            "sysinfo": {"hostname": "clean"},
            "drift": {"/etc/hosts": {"hash": "same", "size": 1, "mtime": 1,
                                     "exists": True}}}))

    def test_the_store_and_not_the_device_record_carries_drift(self):
        rec = api.load(api.DRIFT_STATE_FILE)[self.DEV]["files"][self.PATH]
        self.assertNotEqual(rec["baseline_hash"], rec["current_hash"])
        self.assertNotIn("status", rec)     # the shape the readers expected
        self.assertIsNone(api.load(api.DEVICES_FILE)[self.DEV].get("drift_state"))
        self.assertEqual([self.PATH], api._drifted_for(self.DEV))
        self.assertEqual([], api._drifted_for("clean"))

    def test_checks_page_row(self):
        st, body = self.call(api.handle_device_checks, self.DEV)
        self.assertEqual(200, st)
        row = [r for r in body["checks"] if r["key"] == "drift"]
        self.assertEqual(1, len(row), "the Config drift row is missing")
        self.assertEqual("warning", row[0]["status"])
        self.assertIn("1 file(s) drifted", row[0]["output"])

    def test_fleet_checks_matrix_and_the_clean_control(self):
        st, body = self.call(api.handle_fleet_checks)
        self.assertEqual(200, st)
        hosts = {h["device_id"]: h for h in body["hosts"]}
        drifted = [r for r in hosts[self.DEV]["checks"] if r["key"] == "drift"]
        clean = [r for r in hosts["clean"]["checks"] if r["key"] == "drift"]
        self.assertEqual("warning", drifted[0]["status"])
        # The clean host is TRACKED, so it gets a row — saying the baseline
        # matches, which is different information from having no row at all.
        self.assertEqual("ok", clean[0]["status"])

    def test_risk_factor_fires(self):
        rows = {r["device_id"]: r for r in api._compute_fleet_risk()}
        kinds = [f["kind"] for f in rows[self.DEV]["factors"]]
        self.assertIn("config_drift", kinds)
        self.assertNotIn("config_drift",
                         [f["kind"] for f in rows["clean"]["factors"]])

    def test_needs_attention_item(self):
        items = [i for i in api._compute_attention() if i["kind"] == "drift"]
        self.assertEqual([self.DEV], [i["device"] for i in items])

    def test_fleet_query_drift_filter(self):
        st, body = self.call(api.handle_fleet_query, qs="drift=1")
        self.assertEqual(200, st)
        self.assertEqual([self.DEV], [d["device_id"] for d in body["devices"]])
        # Control: with no filter both hosts come back, so an empty result
        # above would have been the filter and not an empty fleet.
        _, allrows = self.call(api.handle_fleet_query)
        self.assertEqual(2, allrows["total"])

    def test_smart_group_drift_facet(self):
        devs = api.load(api.DEVICES_FILE)
        self.assertTrue(api._smart_group_match(devs[self.DEV], {"drift": True},
                                               self.DEV))
        self.assertFalse(api._smart_group_match(devs["clean"], {"drift": True},
                                                "clean"))
        # A record with no id supplied still resolves, via name/hostname.
        self.assertTrue(api._smart_group_match(devs[self.DEV], {"drift": True}))

    def test_rag_corpus_can_answer_what_has_drifted(self):
        docs = api._rag_build_corpus(
            {"rag": {"sources": {"drift": True, "live_state": True}}})
        ids = {d["id"] for d in docs}
        self.assertIn(f"drift/{self.DEV}", ids)
        self.assertIn("drift/_fleet", ids)
        self.assertIn(f"live/{self.DEV}#drift", ids)
        body = next(d for d in docs if d["id"] == f"drift/{self.DEV}")["text"]
        self.assertIn(self.PATH, body)

    def test_advisory_names_the_drifted_file(self):
        devs = api.load(api.DEVICES_FILE)
        adv = advisory.build(
            devs, drift_by_dev={self.DEV: api._drifted_for(self.DEV)})
        drift = [g for g in adv["findings"] if g["id"] == "int.drift"]
        self.assertEqual(1, len(drift))
        self.assertIn(self.PATH, drift[0]["evidence"])

    def test_ignored_and_dormant_files_are_not_drift(self):
        """The definition lives in ONE helper; pin what it excludes."""
        base = {"baseline_hash": "a", "current_hash": "b", "exists": True}
        self.assertEqual(["/p"], api.drifted_files({"files": {"/p": base}}))
        for excl in ({"ignored": True}, {"dormant": True}, {"exists": False}):
            self.assertEqual([], api.drifted_files(
                {"files": {"/p": dict(base, **excl)}}), excl)
        self.assertEqual([], api.drifted_files(
            {"files": {"/p": {"baseline_hash": "a", "current_hash": "a"}}}))


class TestBlastRadiusCountsWhatIsThere(_Base):
    """`_blast_radius_for` gates every autonomous action. Two of its four
    components read stores that do not hold what they asked for."""

    DEV = "dockerhost"

    def setUp(self):
        super().setUp()
        now = int(time.time())
        api.save(api.DEVICES_FILE, {self.DEV: {
            "name": self.DEV, "hostname": self.DEV, "os": "Linux",
            "token": "t", "last_seen": now, "enrolled": now, "group": "",
            "sysinfo": {}}})
        api._LOAD_CACHE.clear()
        self.assertEqual(200, self.heartbeat({
            "device_id": self.DEV, "token": "t",
            "sysinfo": {"hostname": self.DEV},
            "containers": [{"name": f"c{i}", "image": "img", "state": "running"}
                           for i in range(12)],
            "services": [{"unit": "nginx.service", "active": "active"},
                         {"unit": "redis.service", "active": "failed"},
                         {"unit": "postgres.service", "active": "active"}]}))

    def test_the_ingest_puts_them_where_the_reader_must_look(self):
        dev = api.load(api.DEVICES_FILE)[self.DEV]
        self.assertIsNone((dev.get("sysinfo") or {}).get("containers"))
        self.assertEqual(12, len(api.load(api.CONTAINERS_FILE)[self.DEV]["items"]))
        svc = api.load(api.SERVICES_FILE)[self.DEV]
        self.assertNotIn("watched", svc)
        self.assertEqual(3, len(svc["services"]))

    def test_radius_counts_containers_and_units(self):
        devs = api.load(api.DEVICES_FILE)
        r = _AOH._blast_radius_for(self.DEV, devs[self.DEV], devs)
        self.assertEqual(12, r["containers"])
        self.assertEqual(3, r["status_services"])
        self.assertGreater(r["score"], 0)

    def test_a_bare_host_still_scores_zero(self):
        """Positive control: the count is the fleet's, not a constant."""
        api.save(api.DEVICES_FILE, dict(api.load(api.DEVICES_FILE),
                                        bare={"name": "bare", "group": ""}))
        api._LOAD_CACHE.clear()
        devs = api.load(api.DEVICES_FILE)
        r = _AOH._blast_radius_for("bare", devs["bare"], devs)
        self.assertEqual(0, r["containers"])
        self.assertEqual(0, r["status_services"])


class TestPatchAndServiceStateReachTheModel(_Base):
    """The runbook snapshot and the RAG live-state corpus both read four keys
    that have no writer. The counts are under sysinfo.packages; unit state is
    in SERVICES_FILE."""

    DEV = "pkghost"

    def setUp(self):
        super().setUp()
        now = int(time.time())
        api.save(api.DEVICES_FILE, {self.DEV: {
            "name": self.DEV, "hostname": self.DEV, "os": "Linux",
            "token": "t", "last_seen": now, "enrolled": now, "sysinfo": {}}})
        api._LOAD_CACHE.clear()
        self.assertEqual(200, self.heartbeat({
            "device_id": self.DEV, "token": "t",
            "sysinfo": {"hostname": self.DEV, "platform": "Debian 12",
                        "packages": {"manager": "apt", "upgradable": 41}},
            "services": [{"unit": "nginx.service", "active": "failed"},
                         {"unit": "sshd.service", "active": "active"}]}))

    def test_none_of_the_four_keys_exists_on_the_record(self):
        dev = api.load(api.DEVICES_FILE)[self.DEV]
        for dead in ("upgradable", "patch_status", "pkg_manager",
                     "services_watched_state"):
            self.assertIsNone(dev.get(dead), dead)

    def test_runbook_snapshot(self):
        # The 2nd arg is the whole devices store, not one record.
        snap = api._build_runbook_snapshot(self.DEV, api.load(api.DEVICES_FILE))
        self.assertEqual(41, snap["patch_status"]["upgradable"])
        self.assertEqual("apt", snap["pkg_manager"])
        units = {s.get("unit"): s.get("active") for s in snap["services"]}
        self.assertEqual("failed", units.get("nginx.service"))

    def test_rag_live_state_patch_count_and_unit_state(self):
        docs = {d["id"]: d for d in api._rag_build_corpus(
            {"rag": {"sources": {"live_state": True}}})}
        self.assertIn(f"live/{self.DEV}#patches", docs)
        self.assertIn("pending package updates: 41",
                      docs[f"live/{self.DEV}#patches"]["text"])
        # The fleet patch-backlog rollup is built from those counts, so it was
        # empty on every install while the count was read from a dead key.
        self.assertIn("live/_fleet#patches", docs)
        self.assertIn(self.DEV, docs["live/_fleet#patches"]["text"])
        self.assertIn(f"live/{self.DEV}#services", docs)
        self.assertIn("failed", docs[f"live/{self.DEV}#services"]["text"])


class TestAutonomyCatalogFifthJoin(_Base):
    """The catalog gate covers four joins. This is the fifth: the field
    `_ladder_for` reads off the STORED alert must survive `_record_alert`'s
    whitelist, and so must every parameter alias a template can fill."""

    @staticmethod
    def _record_alert_whitelist():
        """The literal key tuple inside _record_alert, taken from the source by
        balanced parens — a fixed character window breaks on the next edit."""
        body = srcpin.py_function(
            (Path(_ROOT) / "server" / "cgi-bin" / "api.py").read_text(),
            "_record_alert")
        start = body.index("(", body.index("for key in ("))
        depth = 0
        for i in range(start, len(body)):
            if body[i] == "(":
                depth += 1
            elif body[i] == ")":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        seg = re.sub(r"#.*", "", body[start:end + 1])
        return set(re.findall(r"'([A-Za-z_0-9]+)'", seg))

    def test_the_whitelist_extraction_is_not_empty(self):
        """Control: a broken extractor would make every assertion below pass."""
        wl = self._record_alert_whitelist()
        self.assertGreater(len(wl), 60, "the whitelist parse found almost "
                                        "nothing — fix the instrument first")
        self.assertIn("device_id", wl)

    def test_every_discriminator_survives_the_whitelist(self):
        wl = self._record_alert_whitelist()
        missing = [(ev, field) for ev, (field, _t)
                   in _AOH._EVENT_ACTIONS_BY.items() if field not in wl]
        self.assertEqual([], missing,
                         "a discriminator dropped by _record_alert makes every "
                         "alert of that event resolve to an empty ladder")

    def test_every_action_parameter_alias_survives_the_whitelist(self):
        wl = self._record_alert_whitelist()
        missing = [(slot, a) for slot, aliases in _AOH._ACTION_PARAMS.items()
                   for a in aliases if a not in wl]
        self.assertEqual([], missing)

    def test_snapshot_stale_round_trips_to_a_real_ladder(self):
        """Drive the real recorder. A hand-built {'payload': …} dict bypasses
        the whitelist and gives a false green."""
        api.save(api.DEVICES_FILE, {"d1": {"name": "nas01",
                                           "last_seen": int(time.time())}})
        api._LOAD_CACHE.clear()
        api._record_alert("snapshot_stale", {
            "device_id": "d1", "name": "nas01", "pool": "tank",
            "kind": "zfs", "age_days": 45})
        stored = (api.load(api.ALERTS_FILE) or {})["alerts"][-1]
        self.assertEqual("zfs", stored["payload"].get("kind"))
        self.assertEqual(("create_zfs_snapshot",), _AOH._ladder_for(stored))
        # …and the alert survives the candidate filter the loop applies.
        self.assertEqual(1, len(_AOH._candidate_alerts([stored])))


class TestDevicePinsHaveAWriter(_Base):
    """Both pins are documented as operator-settable and had one read site
    each and no write path anywhere."""

    def setUp(self):
        super().setUp()
        api.save(api.DEVICES_FILE, {"d1": {"name": "pve-vm",
                                           "last_seen": int(time.time())}})
        api._LOAD_CACHE.clear()
        self._ra = api.require_admin_auth
        self._rp = api.require_perm
        api.require_admin_auth = lambda *a, **k: "admin"
        api.require_perm = lambda *a, **k: "admin"
        api.method = lambda: "POST"

    def tearDown(self):
        api.require_admin_auth = self._ra
        api.require_perm = self._rp
        super().tearDown()

    def _save(self, body):
        api.get_json_obj = lambda: body
        return self.call(api.handle_device_save_bulk, "d1")

    def test_proxmox_guest_pin_round_trips_to_its_reader(self):
        st, _ = self._save({"proxmox_guest": "Web01"})
        self.assertEqual(200, st)
        api._LOAD_CACHE.clear()
        dev = api.load(api.DEVICES_FILE)["d1"]
        self.assertEqual("web01", dev["proxmox_guest"])
        self.assertEqual("web01", _AOH._proxmox_guest_for(dev))

    def test_mtls_fingerprint_pin_is_normalised_and_validated(self):
        st, _ = self._save({"mtls_fingerprint":
                            "SHA1:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"})
        self.assertEqual(200, st)
        api._LOAD_CACHE.clear()
        stored = api.load(api.DEVICES_FILE)["d1"]["mtls_fingerprint"]
        # Normalised exactly the way _client_cert_identity normalises what
        # nginx forwards, so the compare cannot fail on formatting.
        self.assertEqual("aabbccddeeff00112233445566778899", stored)
        st, body = self._save({"mtls_fingerprint": "not-a-fingerprint"})
        self.assertEqual(400, st)
        self.assertIn("hex", body["error"])


class TestReadOnlyRolesCannotAppendToTheLedger(_Base):
    """POST /api/time-entries writes the shared billing ledger. Its sibling
    path in tickets_handlers was moved to require_write_role in v5.8.0 with
    exactly this reasoning; this entry point kept a bare require_auth()."""

    BODY = {"hours": 4, "billable": False, "note": "x"}

    def setUp(self):
        super().setUp()
        self.BODY = dict(self.BODY, date=time.strftime("%Y-%m-%d"))
        api.method = lambda: "POST"
        api.save(api.ROLES_FILE, {"roles": [
            {"name": "operator", "permissions": ["reboot"],
             "scope": {"type": "all"}}]})
        api._LOAD_CACHE.clear()

    def _post(self, role, user):
        api.verify_token = lambda t: (user, role)
        api.get_json_obj = lambda: dict(self.BODY)
        return self.call(api.handle_time_entries)

    def test_the_four_read_only_roles_are_refused(self):
        for role in ("viewer", "mcp", "auditor", "finance"):
            st, body = self._post(role, role + "user")
            self.assertEqual(403, st, f"{role} appended to the ledger")
            self.assertIn("cannot", body["error"])
        self.assertEqual([], (api.load(api.TIME_ENTRIES_FILE) or {}).get(
            "entries") or [])

    def test_admin_and_a_scoped_operator_still_log_time(self):
        """The under-permissive direction: the gate must not lock out the
        roles that are supposed to work."""
        for role, user in (("admin", "root"), ("operator", "op")):
            st, body = self._post(role, user)
            self.assertEqual(200, st, f"{role} was refused")
            self.assertEqual(user, body["entry"]["user"])


class TestFourxxIsNotRewrittenTo500(_Base):
    """respond() raises HTTPError, which extends Exception — a refusal raised
    inside a try whose `except Exception` maps to 500 never reaches the client
    as itself. A test stub that raises SystemExit CANNOT see this (SystemExit
    is a BaseException and slips past `except Exception`), so these drive the
    real respond()."""

    def setUp(self):
        super().setUp()
        self._ra = api.require_admin_auth
        api.require_admin_auth = lambda *a, **k: "admin"
        self._rv = api._read_valid

    def tearDown(self):
        api.require_admin_auth = self._ra
        api._read_valid = self._rv
        super().tearDown()

    def test_inbound_webhook_toggle_rejects_a_bad_pin_as_400(self):
        api.save(api.INBOUND_WEBHOOKS_FILE,
                 {"tokens": [{"id": "t1", "enabled": True, "label": "x"}]})
        api._LOAD_CACHE.clear()
        api.method = lambda: "PATCH"
        body = {"scope_device_id": "!! not an id !!"}
        api.get_json_obj = lambda: body
        api._read_valid = lambda *a, **k: body
        st, out = self.call(api.handle_inbound_webhook_toggle, "t1")
        self.assertEqual(400, st)
        self.assertIn("scope_device_id", out["error"])
        # Control: the not-found path was always outside the try and honest.
        body2 = {"label": "y"}
        api.get_json_obj = lambda: body2
        api._read_valid = lambda *a, **k: body2
        self.assertEqual(404, self.call(
            api.handle_inbound_webhook_toggle, "nope")[0])

    def test_storage_migrate_reports_its_own_409(self):
        api.method = lambda: "POST"
        body = {"target": "postgres"}
        api.get_json_obj = lambda: body
        api._read_valid = lambda *a, **k: body
        _pg = api.storage_pg_available
        api.storage_pg_available = lambda: False
        try:
            st, out = self.call(api.handle_storage_backend_migrate)
        finally:
            api.storage_pg_available = _pg
        self.assertEqual(409, st)
        self.assertIn("psycopg", out["error"])


if __name__ == "__main__":
    unittest.main()
