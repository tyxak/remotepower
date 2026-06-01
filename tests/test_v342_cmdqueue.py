"""
Command-queue viewer (Admin) + OpenSCAP datastream selection.

  * handle_command_queue lists devices with pending commands, humanizing each;
    handle_command_queue_clear cancels one (by index) or the whole queue.
  * the agent's _find_ssg_datastream picks the right SSG datastream by distro
    family (ID + ID_LIKE) and closest-not-over version, instead of the
    alphabetical first (the bug that put Debian 13 / Ubuntu on ssg-debian10).

Pure stdlib unittest.
"""
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))

import api  # noqa: E402


class _Base(unittest.TestCase):
    _FILES = ("DEVICES_FILE", "CMDS_FILE", "AUDIT_LOG_FILE")
    _FUNCS = ("get_token_from_request", "verify_token", "respond",
              "audit_log", "require_admin_auth")

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._saved = {a: getattr(api, a, None) for a in self._FILES}
        for a in self._FILES:
            setattr(api, a, self.tmp / (a.lower().replace("_file", "") + ".json"))
        self._fns = {f: getattr(api, f) for f in self._FUNCS}
        api.respond = lambda s, b=None: (_ for _ in ()).throw(api.HTTPError(s, b))
        api.audit_log = lambda *a, **k: None
        api.require_admin_auth = lambda *a, **k: "admin"
        api.get_token_from_request = lambda: "t"
        api.verify_token = lambda t: ("admin", "admin")
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for a, v in self._saved.items():
            setattr(api, a, v)
        for f, v in self._fns.items():
            setattr(api, f, v)
        api._LOAD_CACHE.clear()

    def call(self, fn, *a):
        try:
            fn(*a)
        except api.HTTPError as e:
            return e.status, e.body
        return None, None

    def seed(self, devices, cmds):
        api.save(api.DEVICES_FILE, devices)
        api.save(api.CMDS_FILE, cmds)
        api._LOAD_CACHE.clear()


class TestCommandQueueView(_Base):
    def test_lists_pending_with_humanized(self):
        import time
        self.seed(
            {"d1": {"name": "host1", "last_seen": int(time.time())}},
            {"d1": ["exec:systemctl restart nginx", "reboot", "poll_interval:120"]},
        )
        os.environ["REQUEST_METHOD"] = "GET"
        os.environ["QUERY_STRING"] = ""
        st, body = self.call(api.handle_command_queue)
        self.assertEqual(st, 200)
        dev = body["devices"][0]
        self.assertEqual(dev["count"], 3)
        kinds = [c["kind"] for c in dev["commands"]]
        self.assertEqual(kinds, ["exec", "reboot", "poll"])
        self.assertIn("restart nginx", dev["commands"][0]["summary"])

    def test_empty_when_no_queue(self):
        import time
        self.seed({"d1": {"name": "h", "last_seen": int(time.time())}}, {"d1": []})
        os.environ["REQUEST_METHOD"] = "GET"; os.environ["QUERY_STRING"] = ""
        st, body = self.call(api.handle_command_queue)
        self.assertEqual(st, 200)
        self.assertEqual(body["devices"], [])

    def test_cancel_one_by_index(self):
        self.seed({"d1": {"name": "h"}}, {"d1": ["reboot", "exec:foo", "shutdown"]})
        os.environ["REQUEST_METHOD"] = "DELETE"; os.environ["QUERY_STRING"] = "index=1"
        st, body = self.call(api.handle_command_queue_clear, "d1")
        self.assertEqual(st, 200)
        self.assertEqual(body["removed"], 1)
        self.assertEqual(api.load(api.CMDS_FILE)["d1"], ["reboot", "shutdown"])

    def test_clear_all(self):
        self.seed({"d1": {"name": "h"}}, {"d1": ["reboot", "exec:foo"]})
        os.environ["REQUEST_METHOD"] = "DELETE"; os.environ["QUERY_STRING"] = ""
        st, body = self.call(api.handle_command_queue_clear, "d1")
        self.assertEqual(st, 200)
        self.assertEqual(body["removed"], 2)
        self.assertEqual(api.load(api.CMDS_FILE)["d1"], [])

    def test_cancel_bad_index_404(self):
        self.seed({"d1": {"name": "h"}}, {"d1": ["reboot"]})
        os.environ["REQUEST_METHOD"] = "DELETE"; os.environ["QUERY_STRING"] = "index=9"
        st, body = self.call(api.handle_command_queue_clear, "d1")
        self.assertEqual(st, 404)


class TestScapProfileFiltering(_Base):
    """The scan-profile dropdown offers only profiles the fleet's datastreams
    actually contain (union of reported available_profiles)."""
    _FILES = ("DEVICES_FILE", "CMDS_FILE", "AUDIT_LOG_FILE", "SCAP_FILE")

    def setUp(self):
        super().setUp()
        api.require_auth = lambda *a, **k: "admin"
        self._fns2 = {"require_auth": self._fns.get("require_auth", api.require_auth)}

    def test_profiles_are_intersection_when_reported(self):
        api.save(api.DEVICES_FILE, {"d1": {"name": "h1"}, "d2": {"name": "h2"}})
        api.save(api.SCAP_FILE, {
            "d1": {"ts": 1, "available": True, "available_profiles": ["standard", "anssi_np_nt28_minimal"]},
            "d2": {"ts": 1, "available": False, "available_profiles": ["standard"]},
        })
        api._LOAD_CACHE.clear()
        os.environ["REQUEST_METHOD"] = "GET"; os.environ["QUERY_STRING"] = ""
        st, body = self.call(api.handle_scap_overview)
        self.assertEqual(st, 200)
        # union of reported, not the RHEL-centric built-in superset
        self.assertEqual(set(body["profiles"]), {"standard", "anssi_np_nt28_minimal"})
        self.assertNotIn("pci-dss", body["profiles"])

    def test_zero_applicable_coerced_to_not_available(self):
        # Old-agent record: available=True but pass=0/fail=0/score=0 → the
        # overview must present it as not-applicable, not a scary 0%.
        api.save(api.DEVICES_FILE, {"d1": {"name": "h1"}})
        api.save(api.SCAP_FILE, {"d1": {"ts": 1, "available": True, "score": 0.0,
                                        "pass": 0, "fail": 0, "profile": "standard",
                                        "datastream": "ssg-debian12-ds.xml"}})
        api._LOAD_CACHE.clear()
        os.environ["REQUEST_METHOD"] = "GET"; os.environ["QUERY_STRING"] = ""
        st, body = self.call(api.handle_scap_overview)
        self.assertEqual(st, 200)
        row = body["devices"][0]
        self.assertFalse(row["available"])
        self.assertIsNone(row["score"])
        self.assertIn("no applicable rules", row["reason"])
        self.assertIsNone(body["avg_score"])   # not counted in the fleet average

    def test_real_score_preserved(self):
        api.save(api.DEVICES_FILE, {"d1": {"name": "h1"}})
        api.save(api.SCAP_FILE, {"d1": {"ts": 1, "available": True, "score": 73.0,
                                        "pass": 40, "fail": 12, "profile": "anssi",
                                        "datastream": "ssg-debian12-ds.xml"}})
        api._LOAD_CACHE.clear()
        os.environ["REQUEST_METHOD"] = "GET"; os.environ["QUERY_STRING"] = ""
        st, body = self.call(api.handle_scap_overview)
        row = body["devices"][0]
        self.assertTrue(row["available"])
        self.assertEqual(row["score"], 73.0)
        self.assertEqual(body["avg_score"], 73.0)

    def test_falls_back_to_superset_before_any_report(self):
        api.save(api.DEVICES_FILE, {"d1": {"name": "h1"}})
        api.save(api.SCAP_FILE, {})
        api._LOAD_CACHE.clear()
        os.environ["REQUEST_METHOD"] = "GET"; os.environ["QUERY_STRING"] = ""
        st, body = self.call(api.handle_scap_overview)
        self.assertEqual(st, 200)
        self.assertIn("cis", body["profiles"])   # built-in fallback


class TestOscapProfileParsing(unittest.TestCase):
    """_oscap_profiles must parse BOTH oscap-info output formats — the modern
    'Title:/Id:' layout (real ssg-debian12 output) and the older 'Profile:' one."""

    def _make(self):
        src = (Path(__file__).resolve().parent.parent
               / "client" / "remotepower-agent.py").read_text()
        m = re.search(r"def _oscap_profiles.*?(?=\ndef )", src, re.S)
        ns = {"subprocess": __import__("subprocess")}
        exec(m.group(0), ns)
        return ns["_oscap_profiles"], ns

    def test_parses_modern_id_format(self):
        fn, ns = self._make()
        out = (
            "                Profiles:\n"
            "                        Title: ANSSI Minimal Level\n"
            "                                Id: xccdf_org.ssgproject.content_profile_anssi_np_nt28_minimal\n"
            "                        Title: ANSSI High Level\n"
            "                                Id: xccdf_org.ssgproject.content_profile_anssi_np_nt28_high\n"
            "                        Title: Standard\n"
            "                                Id: xccdf_org.ssgproject.content_profile_standard\n")

        class _R:
            stdout = out
            stderr = ""
        ns["subprocess"].run = lambda *a, **k: _R()
        got = fn("/x/ssg-debian12-ds.xml")
        self.assertIn("anssi_np_nt28_minimal", got)
        self.assertIn("anssi_np_nt28_high", got)
        self.assertIn("standard", got)
        self.assertNotIn("pci-dss", got)

    def test_parses_old_profile_format(self):
        fn, ns = self._make()

        class _R:
            stdout = ("Profile: xccdf_org.ssgproject.content_profile_cis\n"
                      "Profile: xccdf_org.ssgproject.content_profile_pci-dss\n")
            stderr = ""
        ns["subprocess"].run = lambda *a, **k: _R()
        got = fn("/x/ssg-rhel9-ds.xml")
        self.assertEqual(set(got), {"cis", "pci-dss"})


class TestSsgDatastreamSelection(unittest.TestCase):
    """Exercise the agent's _find_ssg_datastream logic in isolation."""

    def _make_picker(self, ssg_dir, osr):
        src = (Path(__file__).resolve().parent.parent
               / "client" / "remotepower-agent.py").read_text()
        m = re.search(r"def _find_ssg_datastream.*?(?=\ndef )", src, re.S)
        ns = {"os": os, "Path": Path, "get_os_release": lambda: osr}
        exec("_SSG_DIRS=(%r,)\n" % str(ssg_dir) + m.group(0), ns)
        return ns["_find_ssg_datastream"]

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        for v in (10, 11, 12):
            (self.d / f"ssg-debian{v}-ds.xml").write_text("")

    def test_debian13_picks_closest_lower(self):
        f = self._make_picker(self.d, {"ID": "debian", "VERSION_ID": "13"})
        self.assertIn("debian12", os.path.basename(f()))

    def test_ubuntu_falls_back_via_id_like(self):
        f = self._make_picker(self.d, {"ID": "ubuntu", "ID_LIKE": "debian",
                                       "VERSION_ID": "24.04"})
        self.assertIn("debian12", os.path.basename(f()))

    def test_exact_version_match(self):
        f = self._make_picker(self.d, {"ID": "debian", "VERSION_ID": "11"})
        self.assertIn("debian11", os.path.basename(f()))


if __name__ == "__main__":
    unittest.main()
