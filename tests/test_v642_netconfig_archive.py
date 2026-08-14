"""v6.4.2 — the switch and the firewall get config backup, versioning and diff.

There was no network-appliance configuration backup, versioning or change diff
anywhere. The sole retrieval path was the RouterOS `export` action, which
returned text truncated at 256 KB straight into a `<pre>` in the drawer: not
stored, not versioned, not diffed against the previous export, not scheduled,
and raising no change event. It vanished when the drawer closed. OPNsense had
no config call at all.

Meanwhile Linux hosts get full hash-based config-drift detection. The devices
that most need it — the switch and the firewall — got nothing. "Who changed the
firewall rule at 3pm Friday, and what did it look like before?" is the
canonical network-ops question, and it is exactly what RANCID and Oxidized
exist for (and what LibreNMS, Unimus, Auvik and PRTG all ship).
"""

# A sibling from tests/ is imported inside a test method below.
# `unittest discover -s tests` puts this directory on sys.path for free;
# `python3 -m unittest tests.<this>` does not, and the method then fails
# with ModuleNotFoundError. See tests/test_modules_import_alone.py.
import sys as _rp_sys, pathlib as _rp_pl  # noqa: E402
_rp_sys.path.insert(0, str(_rp_pl.Path(__file__).resolve().parent))
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-netconf-"))

_spec = importlib.util.spec_from_file_location("api_netconf", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_CFG_A = "/ip firewall filter\nadd chain=input action=accept\n"
_CFG_B = "/ip firewall filter\nadd chain=input action=drop\n"


class _Base(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for attr in ("NETCONFIG_ARCHIVE_FILE", "NETCONFIG_STATE_FILE",
                     "DEVICES_FILE", "CONFIG_FILE"):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
            api._invalidate_load_cache(getattr(api, attr))
        self.cap = {}
        self.fired = []
        self._orig = {n: getattr(api, n) for n in
                      ("require_auth", "require_admin_auth", "audit_log",
                       "fire_webhook", "respond", "method", "get_json_body",
                       "_env", "_netconf_fetch", "_netconf_kind")}
        api.require_auth = lambda require_admin=False: "jakob"
        api.require_admin_auth = lambda: "jakob"
        api.audit_log = lambda *a, **k: None
        api.fire_webhook = lambda ev, p=None, **k: self.fired.append((ev, p or {}))
        self._qs = ""
        _real_env = self._orig["_env"]
        api._env = lambda k, d="": (self._qs if k == "QUERY_STRING"
                                    else _real_env(k, d))

        def _resp(s, b=None):
            self.cap["s"], self.cap["b"] = s, b
            raise api.HTTPError(s, b)
        api.respond = _resp
        api.method = lambda: "GET"
        api.save(api.DEVICES_FILE, {"sw1": {"name": "switch01"}})
        api._invalidate_load_cache(api.DEVICES_FILE)
        # The appliance API itself is out of scope here — these tests are about
        # the archive, so the fetch is stubbed and the KIND forced.
        api._netconf_kind = lambda dev: "routeros"
        self.next_cfg = _CFG_A
        api._netconf_fetch = lambda dev_id, dev: self.next_cfg

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for a, v in self._files.items():
            setattr(api, a, v)

    def call(self, fn, *a):
        try:
            fn(*a)
        except api.HTTPError:
            pass
        return self.cap.get("b")

    def revs(self, dev="sw1"):
        api._invalidate_load_cache(api.NETCONFIG_ARCHIVE_FILE)
        return (api.load(api.NETCONFIG_ARCHIVE_FILE) or {}).get(dev) or []


class TestTheArchive(_Base):
    def test_the_first_archive_is_a_baseline_not_a_change(self):
        """Firing `netconfig_changed` the first time a device is archived would
        alert on every appliance the day the feature is switched on."""
        rev, changed = api._netconf_store_revision("sw1", _CFG_A, "jakob")
        self.assertFalse(changed)
        self.assertEqual(len(self.revs()), 1)

    def test_an_identical_config_does_not_create_a_revision(self):
        """An archive that keeps a copy per poll is a disk-usage bug wearing a
        feature's clothes, and it buries the revisions that mean something."""
        first, _ = api._netconf_store_revision("sw1", _CFG_A)
        again, changed = api._netconf_store_revision("sw1", _CFG_A)
        self.assertFalse(changed)
        self.assertEqual(again["id"], first["id"])
        self.assertEqual(len(self.revs()), 1)

    def test_an_unchanged_check_still_updates_last_seen(self):
        """Otherwise "last backed up" reads as the date of the last CHANGE, and
        an operator cannot tell a healthy quiet device from a broken poll."""
        api._netconf_store_revision("sw1", _CFG_A)
        with api._LockedUpdate(api.NETCONFIG_ARCHIVE_FILE) as st:
            st["sw1"][0]["last_seen"] = 1
        api._invalidate_load_cache(api.NETCONFIG_ARCHIVE_FILE)
        api._netconf_store_revision("sw1", _CFG_A)
        self.assertGreater(self.revs()[0]["last_seen"], 1)

    def test_a_real_change_is_archived_and_reported(self):
        api._netconf_store_revision("sw1", _CFG_A)
        rev, changed = api._netconf_store_revision("sw1", _CFG_B)
        self.assertTrue(changed)
        self.assertEqual(len(self.revs()), 2)

    def test_revisions_are_capped(self):
        mod = api.netappliance_handlers_mod
        real = mod._NETCONF_MAX_REVISIONS
        try:
            mod._NETCONF_MAX_REVISIONS = 3
            for i in range(6):
                api._netconf_store_revision("sw1", f"config v{i}\n")
        finally:
            mod._NETCONF_MAX_REVISIONS = real
        revs = self.revs()
        self.assertEqual(len(revs), 3)
        self.assertIn("v5", revs[-1]["text"])

    def test_an_oversize_config_keeps_the_hash_but_not_the_body(self):
        """A TRUNCATED config in an archive is worse than none: it looks
        complete, and restoring from it restores a fragment. Change detection
        still works because the hash is of the whole document."""
        mod = api.netappliance_handlers_mod
        real = mod._NETCONF_MAX_BODY
        try:
            mod._NETCONF_MAX_BODY = 32
            rev, _ = api._netconf_store_revision("sw1", "x" * 500)
        finally:
            mod._NETCONF_MAX_BODY = real
        self.assertTrue(rev["oversize"])
        self.assertEqual(rev["text"], "")
        self.assertEqual(rev["bytes"], 500)
        self.assertTrue(rev["hash"])

    def test_two_devices_do_not_share_a_history(self):
        api._netconf_store_revision("sw1", _CFG_A)
        api._netconf_store_revision("fw1", _CFG_B)
        self.assertEqual(len(self.revs("sw1")), 1)
        self.assertEqual(len(self.revs("fw1")), 1)


class TestTheDiff(_Base):
    def test_it_shows_what_changed(self):
        lines, truncated = api._netconf_diff(_CFG_A, _CFG_B)
        body = [x for x in lines
                if x.startswith(("+", "-")) and not x.startswith(("+++", "---"))]
        self.assertIn("-add chain=input action=accept", body)
        self.assertIn("+add chain=input action=drop", body)
        self.assertFalse(truncated)

    def test_it_is_bounded(self):
        a = "\n".join(f"line {i}" for i in range(2000))
        b = "\n".join(f"changed {i}" for i in range(2000))
        lines, truncated = api._netconf_diff(a, b)
        self.assertTrue(truncated)
        self.assertLessEqual(len(lines), 400)

    def test_no_difference_produces_no_diff_lines(self):
        lines, _ = api._netconf_diff(_CFG_A, _CFG_A)
        self.assertEqual(lines, [])


class TestTheEndpoints(_Base):
    def test_listing_returns_metadata_without_bodies(self):
        """The config can embed appliance credentials; the list view is
        available to any authed reader, so it must never carry text."""
        api._netconf_store_revision("sw1", _CFG_A)
        r = self.call(api.handle_device_netconfig, "sw1")
        self.assertEqual(len(r["revisions"]), 1)
        self.assertNotIn("text", r["revisions"][0])
        self.assertEqual(r["kind"], "routeros")

    def test_listing_is_newest_first(self):
        api._netconf_store_revision("sw1", _CFG_A)
        api._netconf_store_revision("sw1", _CFG_B)
        r = self.call(api.handle_device_netconfig, "sw1")
        self.assertGreaterEqual(r["revisions"][0]["ts"], r["revisions"][1]["ts"])

    def test_a_device_with_no_appliance_api_says_so(self):
        api._netconf_kind = lambda dev: ""
        r = self.call(api.handle_device_netconfig, "sw1")
        self.assertEqual(r["kind"], "")
        self.assertEqual(r["revisions"], [])

    def test_backup_now_archives(self):
        api.method = lambda: "POST"
        r = self.call(api.handle_device_netconfig, "sw1")
        self.assertTrue(r["ok"])
        self.assertEqual(len(self.revs()), 1)

    def test_backup_now_reports_whether_anything_changed(self):
        """"Unchanged" is the useful answer most of the time; reporting
        "backed up" either way hides it."""
        api.method = lambda: "POST"
        self.assertFalse(self.call(api.handle_device_netconfig, "sw1")["changed"])
        self.next_cfg = _CFG_B
        self.assertTrue(self.call(api.handle_device_netconfig, "sw1")["changed"])

    def test_backup_needs_admin_reading_does_not(self):
        """A backup pulls the appliance's full config including embedded
        secrets — the same bar as reading its firewall rules."""
        admin, reader = [], []
        api.require_admin_auth = lambda: (admin.append(1), "j")[1]
        api.require_auth = lambda require_admin=False: (reader.append(1), "j")[1]
        self.call(api.handle_device_netconfig, "sw1")
        self.assertEqual((len(admin), len(reader)), (0, 1))
        api.method = lambda: "POST"
        self.call(api.handle_device_netconfig, "sw1")
        self.assertEqual(len(admin), 1)

    def test_an_empty_config_is_not_archived_as_a_change(self):
        """A silently-failing appliance returning '' would otherwise archive an
        empty revision and report the config as wiped."""
        api.method = lambda: "POST"
        self.next_cfg = ""
        self.call(api.handle_device_netconfig, "sw1")
        self.assertEqual(self.cap["s"], 502)
        self.assertEqual(self.revs(), [])

    def test_a_fetch_failure_is_502_not_500(self):
        api.method = lambda: "POST"
        api._netconf_fetch = lambda d, dev: (_ for _ in ()).throw(
            RuntimeError("connection refused"))
        self.call(api.handle_device_netconfig, "sw1")
        self.assertEqual(self.cap["s"], 502)

    def test_reading_one_revision_returns_its_body(self):
        rev, _ = api._netconf_store_revision("sw1", _CFG_A)
        r = self.call(api.handle_device_netconfig_revision, "sw1", rev["id"])
        self.assertEqual(r["text"], _CFG_A)

    def test_an_unknown_revision_404s(self):
        self.call(api.handle_device_netconfig_revision, "sw1", "nc-nope")
        self.assertEqual(self.cap["s"], 404)

    def test_the_diff_defaults_to_the_previous_revision(self):
        """The question is nearly always "what changed in THIS one?"."""
        api._netconf_store_revision("sw1", _CFG_A)
        rev, _ = api._netconf_store_revision("sw1", _CFG_B)
        self._qs = "format=diff"
        r = self.call(api.handle_device_netconfig_revision, "sw1", rev["id"])
        self.assertTrue(any("action=drop" in ln for ln in r["diff"]))

    def test_the_first_revision_has_nothing_to_diff_against(self):
        rev, _ = api._netconf_store_revision("sw1", _CFG_A)
        self._qs = "format=diff"
        self.call(api.handle_device_netconfig_revision, "sw1", rev["id"])
        self.assertEqual(self.cap["s"], 400)

    def test_an_oversize_revision_explains_itself(self):
        mod = api.netappliance_handlers_mod
        real = mod._NETCONF_MAX_BODY
        try:
            mod._NETCONF_MAX_BODY = 8
            rev, _ = api._netconf_store_revision("sw1", "x" * 200)
        finally:
            mod._NETCONF_MAX_BODY = real
        self.call(api.handle_device_netconfig_revision, "sw1", rev["id"])
        self.assertEqual(self.cap["s"], 400)
        self.assertIn("hash", self.cap["b"]["error"])

    def test_reading_a_revision_is_admin_only(self):
        """The list is readable by anyone authed; the BODY is the config."""
        from srcpin import py_function
        src = (_CGI / "netappliance_handlers.py").read_text()
        body = py_function(src, "handle_device_netconfig_revision")
        self.assertIn("A.require_admin_auth()", body)


class TestTheSweep(_Base):
    def _enable(self):
        api.save(api.CONFIG_FILE, {"netconfig_backup_enabled": True})
        for f in (api.CONFIG_FILE, api.NETCONFIG_STATE_FILE):
            api._invalidate_load_cache(f)

    def test_it_is_off_by_default(self):
        """It authenticates to every appliance in the fleet and stores its full
        configuration — an operator's decision, not something to inherit on
        upgrade."""
        api.save(api.CONFIG_FILE, {})
        api._invalidate_load_cache(api.CONFIG_FILE)
        api.run_netconfig_backup_if_due()
        self.assertEqual(self.revs(), [])

    def test_it_archives_when_enabled(self):
        self._enable()
        api.run_netconfig_backup_if_due()
        self.assertEqual(len(self.revs()), 1)

    def test_the_first_run_fires_nothing(self):
        self._enable()
        api.run_netconfig_backup_if_due()
        self.assertEqual(self.fired, [])

    def test_a_change_fires_netconfig_changed(self):
        self._enable()
        api.run_netconfig_backup_if_due()
        with api._LockedUpdate(api.NETCONFIG_STATE_FILE) as st:
            st["last_run"] = 0
        api._invalidate_load_cache(api.NETCONFIG_STATE_FILE)
        self.next_cfg = _CFG_B
        api.run_netconfig_backup_if_due()
        self.assertEqual([e for e, _ in self.fired], ["netconfig_changed"])
        self.assertEqual(self.fired[0][1]["device_id"], "sw1")

    def test_it_respects_its_interval(self):
        self._enable()
        api.run_netconfig_backup_if_due()
        self.next_cfg = _CFG_B
        api.run_netconfig_backup_if_due()     # same tick — must not re-poll
        self.assertEqual(len(self.revs()), 1)

    def test_one_unreachable_appliance_does_not_stop_the_others(self):
        self._enable()
        api.save(api.DEVICES_FILE, {"sw1": {"name": "sw1"}, "fw1": {"name": "fw1"}})
        api._invalidate_load_cache(api.DEVICES_FILE)

        def _fetch(dev_id, dev):
            if dev_id == "sw1":
                raise RuntimeError("unreachable")
            return _CFG_A
        api._netconf_fetch = _fetch
        api.run_netconfig_backup_if_due()
        self.assertEqual(self.revs("sw1"), [])
        self.assertEqual(len(self.revs("fw1")), 1)

    def test_a_quarantined_device_is_skipped(self):
        self._enable()
        api.save(api.DEVICES_FILE, {"sw1": {"name": "sw1", "quarantined": True}})
        api._invalidate_load_cache(api.DEVICES_FILE)
        api.run_netconfig_backup_if_due()
        self.assertEqual(self.revs(), [])

    def test_the_event_fires_outside_every_lock(self):
        """fire_webhook takes its own locks — nesting one inside _LockedUpdate
        is the recurring lock-nesting bug in this codebase."""
        from srcpin import py_function
        src = (_CGI / "netappliance_handlers.py").read_text()
        body = py_function(src, "run_netconfig_backup_if_due")
        self.assertLess(body.index("pending.append("), body.index("fire_webhook"))
        tail = body[body.index("for dev_id, dev, rev in pending:"):]
        self.assertNotIn("_LockedUpdate", tail)


class TestWiring(unittest.TestCase):
    def test_the_event_is_registered_everywhere(self):
        self.assertIn("netconfig_changed", api.EVENT_REGISTRY)
        self.assertIn("netconfig_changed", {e[0] for e in api.WEBHOOK_EVENTS})
        self.assertEqual(api._ALERT_RULES.get("netconfig_changed")[0], "medium")

    def test_the_sweep_is_in_both_cadence_registries(self):
        self.assertIn("_safe(run_netconfig_backup_if_due",
                      (_CGI / "api.py").read_text())
        self.assertIn("'run_netconfig_backup_if_due'",
                      (_CGI / "scheduler.py").read_text())

    def test_opnsense_can_export_at_all(self):
        """It had no config-retrieval call, so half the appliance fleet could
        not participate however good the archive was."""
        import opnsense
        self.assertIn("export", opnsense.ACTIONS)
        self.assertIn("export", opnsense._SYSTEM_OPS)
        self.assertIn("/core/backup/download/this",
                      (_CGI / "opnsense.py").read_text())

    def test_routeros_export_is_untouched(self):
        import routeros
        self.assertIn("export", routeros.ACTIONS)

    def test_the_toggle_persists(self):
        """A settings checkbox that is not in handle_config_save's whitelist
        appears to save and silently does nothing."""
        src = (_CGI / "api.py").read_text()
        from srcpin import py_function
        self.assertIn("cfg['netconfig_backup_enabled']",
                      py_function(src, "handle_config_save"))
        self.assertIn("safe.setdefault('netconfig_backup_enabled', False)", src)

    def test_the_model_knows_the_field(self):
        import request_models
        self.assertIn("netconfig_backup_enabled",
                      request_models.ConfigSaveRequest.model_fields)

    def test_the_ui_is_wired(self):
        html = ROOT / "server" / "html" / "index.html"
        if not html.exists():
            self.skipTest("excluded from this tree")
        s = html.read_text()
        js = (ROOT / "server" / "html" / "static" / "js" / "app.js").read_text()
        ints = (ROOT / "server" / "html" / "static" / "js"
                / "app-integrations.js").read_text()
        self.assertIn('id="cfg-netconfig-backup-enabled"', s)
        self.assertIn("payload.netconfig_backup_enabled", js)
        self.assertIn('id="netconf-body"', ints)
        for fn in ("loadNetconfig", "netconfigBackupNow", "netconfigView",
                   "netconfigDiff", "netconfigDownload"):
            with self.subTest(fn=fn):
                self.assertRegex(ints, rf"\bfunction {fn}\s*\(")

    def test_both_appliance_views_show_it(self):
        ints = (ROOT / "server" / "html" / "static" / "js"
                / "app-integrations.js")
        if not ints.exists():
            self.skipTest("excluded from this tree")
        s = ints.read_text()
        self.assertEqual(s.count('<div id="netconf-body"></div>'), 2,
                         "RouterOS and OPNsense both need the panel")
        # Each render tail must paint it — the panel is filled by element id,
        # so emitting the div without the call leaves an empty box forever.
        # (A third call lives in netconfigBackupNow, which refreshes the list;
        # counting every call site would have made this assert the wrong thing.)
        for fn in ("_renderRouterosCard", "_renderOpnsenseCard"):
            body = s[s.index(f"function {fn}("):]
            body = body[:body.index("\n}\n")]
            with self.subTest(view=fn):
                self.assertIn("loadNetconfig()", body)


if __name__ == "__main__":
    unittest.main()
