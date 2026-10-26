#!/usr/bin/env python3
"""v7.4.1, issue #39: a host's drift watch list can add to or remove from the list it
would otherwise get, instead of replacing it.

"On a host whose apt sources live only in /etc/apt/sources.list.d/, the default watch
on /etc/apt/sources.list covers nothing. The workaround is a per-host list naming each
.list file, but then the host no longer picks up additions to the default list in later
releases."

The syntax: `@defaults` in a host's or a profile's list stands for the list it would
otherwise get, and `-<entry>` removes an entry. Without either, the list replaces, as it
always did. The real handlers run here: the server resolves the list in one place for the
agent and for the Drift page, and one validator guards every way a list is entered.
"""
import json
import shutil
import subprocess
import sys as _rp_sys
import pathlib as _rp_pl
import tempfile
import re
import unittest

_rp_sys.path.insert(0, str(_rp_pl.Path(__file__).resolve().parent))
from test_v622_alert_params import _SaveBase, ROOT, api  # noqa: E402
import srcpin  # noqa: E402

APP = (ROOT / "server/html/static/js/app.js").read_text()
DRIFT_JS = (ROOT / "server/html/static/js/app-drift.js").read_text()
I18N = (ROOT / "server/html/static/js/i18n.js").read_text()
API_SRC = (ROOT / "server/cgi-bin/api.py").read_text()
_NODE = shutil.which("node")
LANGS = ("zh", "hi", "es", "ar", "de", "fr")

DEFAULTS = ["/etc/ssh/sshd_config", "/etc/hosts", "/etc/apt/sources.list"]


class TestResolveWatchList(unittest.TestCase):
    r = staticmethod(lambda entries, inherited=DEFAULTS: api._resolve_watch_list(entries, inherited))

    def test_a_list_without_the_marker_replaces_as_it_always_did(self):
        self.assertEqual(self.r(["/etc/motd"]), ["/etc/motd"])
        self.assertEqual(self.r([]), [])

    def test_the_marker_splices_the_inherited_list_where_it_stands(self):
        self.assertEqual(self.r(["/a", "@defaults", "/b"]), ["/a"] + DEFAULTS + ["/b"])

    def test_the_reporters_list(self):
        out = self.r(["@defaults", "-/etc/apt/sources.list", "/etc/apt/sources.list.d/*"])
        self.assertEqual(out, ["/etc/ssh/sshd_config", "/etc/hosts", "/etc/apt/sources.list.d/*"])

    def test_an_exclusion_removes_from_everything_not_only_the_inherited_part(self):
        self.assertEqual(self.r(["@defaults", "/extra", "-/extra", "-/etc/hosts"]),
                         ["/etc/ssh/sshd_config", "/etc/apt/sources.list"])

    def test_repeats_are_dropped_and_order_is_kept(self):
        self.assertEqual(self.r(["/etc/hosts", "@defaults"]),
                         ["/etc/hosts", "/etc/ssh/sshd_config", "/etc/apt/sources.list"])

    def test_without_the_marker_a_stray_exclusion_is_not_an_entry(self):
        self.assertEqual(self.r(["/a", "-/b"]), ["/a"])

    def test_two_markers_inherit_once(self):
        self.assertEqual(self.r(["@defaults", "@defaults"]), DEFAULTS)

    def test_nothing_inherited_is_fine(self):
        self.assertEqual(self.r(["@defaults", "/x"], inherited=[]), ["/x"])

    def test_junk_in_a_hand_edited_list_does_not_raise(self):
        self.assertEqual(self.r(["@defaults", 5, None, {"a": 1}], DEFAULTS), DEFAULTS)


class _Base(_SaveBase):
    def setUp(self):
        super().setUp()
        self._more = {}
        for attr in ("DEVICES_FILE", "DRIFT_STATE_FILE", "DEVICE_PROFILES_FILE"):
            self._more[attr] = getattr(api, attr)
            setattr(api, attr, self.d / self._more[attr].name)
        self._orig2 = {n: getattr(api, n) for n in ("require_instance_admin_auth", "_require_platform_operator",
                                                    "get_json_body")}
        api.require_instance_admin_auth = lambda *a, **k: "jakob"
        api._require_platform_operator = lambda *a, **k: None
        api.save(api.DEVICES_FILE, {})
        self.cfg()

    def tearDown(self):
        for n, v in self._orig2.items():
            setattr(api, n, v)
        for a, v in self._more.items():
            setattr(api, a, v)
        super().tearDown()

    def cfg(self, drift=None, **extra):
        api.save(api.CONFIG_FILE, dict(extra, drift=drift if drift is not None else {}))
        api._invalidate_load_cache(api.CONFIG_FILE)

    def devs(self, **hosts):
        api.save(api.DEVICES_FILE, {k: dict(dict(id=k, name=k), **v) for k, v in hosts.items()})
        api._invalidate_load_cache(api.DEVICES_FILE)

    def call(self, fn, body=None, method="POST", *args):
        self.cap.clear()
        api.method = lambda: method
        api.get_json_obj = lambda: dict(body or {})
        api.get_json_body = lambda: dict(body or {})
        try:
            fn(*args)
        except api.HTTPError:
            pass
        return self.cap.get("s"), self.cap.get("b")


class TestResolution(_Base):
    def test_the_default_applies_to_a_host_with_no_list(self):
        self.devs(a={})
        self.assertEqual(api.get_watched_files_for("a"), list(api.DEFAULT_WATCHED_FILES))

    def test_a_host_can_add_to_the_default_and_take_one_away(self):
        self.devs(a={"watched_files": ["@defaults", "-/etc/apt/sources.list", "/etc/apt/sources.list.d/*"]})
        want = [f for f in api.DEFAULT_WATCHED_FILES if f != "/etc/apt/sources.list"] + ["/etc/apt/sources.list.d/*"]
        self.assertEqual(api.get_watched_files_for("a"), want)

    def test_it_keeps_following_the_default_when_the_default_changes(self):
        # the reporter's second complaint: a per-host list froze the host
        self.cfg(drift={"default_watched_files": ["/etc/one"]})
        self.devs(a={"watched_files": ["@defaults", "/mine"]})
        self.assertEqual(api.get_watched_files_for("a"), ["/etc/one", "/mine"])
        self.cfg(drift={"default_watched_files": ["/etc/one", "/etc/two"]})
        self.assertEqual(api.get_watched_files_for("a"), ["/etc/one", "/etc/two", "/mine"])

    def test_a_plain_list_still_replaces(self):
        self.devs(a={"watched_files": ["/only"]})
        self.assertEqual(api.get_watched_files_for("a"), ["/only"])

    def test_an_empty_list_still_means_watch_nothing(self):
        self.devs(a={"watched_files": []})
        self.assertEqual(api.get_watched_files_for("a"), [])

    def test_a_profile_can_inherit_the_default(self):
        self.cfg(drift={"default_watched_files": ["/etc/one"],
                        "profiles": [{"id": "p1", "name": "web", "files": ["@defaults", "/etc/nginx/nginx.conf"]}],
                        "assignments": [{"scope_type": "group", "scope_value": "web", "profile_id": "p1"}]})
        self.devs(a={"group": "web"})
        self.assertEqual(api.get_watched_files_for("a"), ["/etc/one", "/etc/nginx/nginx.conf"])

    def test_a_host_inherits_what_its_profile_gives_it_not_the_bare_default(self):
        self.cfg(drift={"default_watched_files": ["/etc/one"],
                        "profiles": [{"id": "p1", "name": "web", "files": ["/etc/nginx/nginx.conf", "/etc/ssl"]}],
                        "assignments": [{"scope_type": "group", "scope_value": "web", "profile_id": "p1"}]})
        self.devs(a={"group": "web", "watched_files": ["@defaults", "-/etc/ssl", "/etc/extra"]})
        self.assertEqual(api.get_watched_files_for("a"), ["/etc/nginx/nginx.conf", "/etc/extra"])

    def test_drift_off_watches_nothing_whatever_the_list_says(self):
        self.cfg(drift={"enabled": False})
        self.devs(a={"watched_files": ["@defaults", "/x"]})
        self.assertEqual(api.get_watched_files_for("a"), [])

    def test_an_unknown_host_gets_the_default(self):
        self.devs()
        self.assertEqual(api.get_watched_files_for("ghost"), list(api.DEFAULT_WATCHED_FILES))

    def test_the_agents_list_and_the_drift_page_agree(self):
        # one resolver: they used to be two copies of the precedence
        self.cfg(drift={"default_watched_files": ["/etc/one"],
                        "profiles": [{"id": "p1", "name": "web", "files": ["@defaults", "/p"]}],
                        "assignments": [{"scope_type": "tag", "scope_value": "web", "profile_id": "p1"}]})
        self.devs(plain={}, tagged={"tags": ["web"]},
                  own={"tags": ["web"], "watched_files": ["@defaults", "/own", "-/p"]})
        for dev_id in ("plain", "tagged", "own"):
            dev = api.load(api.DEVICES_FILE)[dev_id]
            eff = api._drift_effective(dev_id, dev)
            self.assertEqual(eff["files"], api.get_watched_files_for(dev_id), dev_id)
        self.assertEqual(api._drift_effective("tagged", api.load(api.DEVICES_FILE)["tagged"])["source"],
                         "profile:tag")
        self.assertEqual(api._drift_effective("own", api.load(api.DEVICES_FILE)["own"])["files"],
                         ["/etc/one", "/own"])


class TestValidator(_Base):
    def v(self, raw, inherit=True):
        self.cap.clear()
        try:
            return api._validate_drift_files(raw, inherit=inherit)
        except api.HTTPError:
            return None

    def test_files_folders_and_patterns_are_accepted(self):
        got = self.v(["/etc/hosts", "/etc/apt/sources.list.d/", "/etc/apt/sources.list.d/*", "/home/*/.ssh/authorized_keys"])
        self.assertEqual(len(got), 4)

    def test_the_old_leniency_is_kept_for_junk(self):
        self.assertEqual(self.v(["relative/path", "", "  /ok  ", "/ok", "x" * 600], inherit=False), ["/ok"])

    def test_a_pattern_that_climbs_out_of_its_folder_is_dropped(self):
        self.assertEqual(self.v(["/etc/../*", "/etc/*/../shadow", "/etc/*"]), ["/etc/*"])

    def test_a_plain_path_with_dots_is_as_accepted_as_before(self):
        self.assertEqual(self.v(["/etc/../etc/hosts"]), ["/etc/../etc/hosts"])

    def test_the_marker_and_exclusions_need_a_list_that_can_inherit(self):
        for raw in (["@defaults"], ["-/etc/hosts"]):
            with self.subTest(raw=raw):
                self.assertIsNone(self.v(raw, inherit=False))
                self.assertEqual(self.cap["s"], 400)
                self.assertIn("host or a profile", self.cap["b"]["error"])

    def test_an_exclusion_without_the_marker_is_refused_with_the_reason(self):
        self.assertIsNone(self.v(["/a", "-/b"]))
        self.assertEqual(self.cap["s"], 400)
        self.assertIn("@defaults", self.cap["b"]["error"])

    def test_the_marker_and_exclusions_are_kept_in_order(self):
        self.assertEqual(self.v(["@defaults", "-/etc/hosts", "/x"]), ["@defaults", "-/etc/hosts", "/x"])

    def test_a_malformed_exclusion_is_dropped_like_other_junk(self):
        self.assertEqual(self.v(["@defaults", "- /etc/hosts", "-etc/hosts"]), ["@defaults"])

    def test_repeats_are_dropped_and_the_cap_holds(self):
        self.assertEqual(self.v(["/a", "/a", "@defaults", "@defaults"]), ["/a", "@defaults"])
        self.assertEqual(len(self.v(["/f%d" % i for i in range(80)])), 50)

    def test_not_a_list_is_nothing(self):
        for raw in (None, "x", {"a": 1}, 5):
            self.assertEqual(self.v(raw), [])


class TestEveryWayAListIsEntered(_Base):
    """Four doors, one validator."""

    def test_the_drawers_save_takes_the_syntax(self):
        self.devs(d1={})
        s, b = self.call(api.handle_device_save_bulk,
                         {"watched_files": ["@defaults", "-/etc/hosts", "/etc/apt/sources.list.d/*"]}, "POST", "d1")
        self.assertEqual(s, 200, b)
        api._invalidate_load_cache(api.DEVICES_FILE)
        self.assertEqual(api.load(api.DEVICES_FILE)["d1"]["watched_files"],
                         ["@defaults", "-/etc/hosts", "/etc/apt/sources.list.d/*"])

    def test_the_drawers_save_refuses_an_exclusion_with_nothing_to_remove_from(self):
        self.devs(d1={})
        s, b = self.call(api.handle_device_save_bulk, {"watched_files": ["-/etc/hosts"]}, "POST", "d1")
        self.assertEqual(s, 400)
        self.assertIn("@defaults", b["error"])
        api._invalidate_load_cache(api.DEVICES_FILE)
        self.assertNotIn("watched_files", api.load(api.DEVICES_FILE)["d1"])

    def test_the_drawers_save_now_dedupes_like_the_others(self):
        self.devs(d1={})
        self.call(api.handle_device_save_bulk, {"watched_files": ["/a", "/a", "/b"]}, "POST", "d1")
        api._invalidate_load_cache(api.DEVICES_FILE)
        self.assertEqual(api.load(api.DEVICES_FILE)["d1"]["watched_files"], ["/a", "/b"])

    def test_a_drift_profile_can_be_created_and_edited_with_the_syntax(self):
        s, b = self.call(api.handle_drift_profiles, {"name": "web", "files": ["@defaults", "-/etc/hosts", "/x/*"]})
        self.assertEqual(s, 201, b)
        pid = b["id"]
        s, b = self.call(api.handle_drift_profile_edit, {"files": ["@defaults", "/y/"]}, "PUT", pid)
        self.assertEqual(s, 200, b)
        api._invalidate_load_cache(api.CONFIG_FILE)
        prof = next(p for p in api.load(api.CONFIG_FILE)["drift"]["profiles"] if p["id"] == pid)
        self.assertEqual(prof["files"], ["@defaults", "/y/"])

    def test_a_drift_profile_refuses_an_exclusion_without_the_marker(self):
        s, _ = self.call(api.handle_drift_profiles, {"name": "web", "files": ["-/etc/hosts"]})
        self.assertEqual(s, 400)

    def test_a_host_profile_takes_the_syntax_and_refuses_the_misuse(self):
        ok = api._validate_device_profile({"name": "p", "drift_files": ["@defaults", "/x/*"]})
        self.assertEqual(ok["drift_files"], ["@defaults", "/x/*"])
        with self.assertRaises(api.HTTPError):
            api._validate_device_profile({"name": "p", "drift_files": ["-/etc/hosts"]})

    def test_the_four_doors_all_use_the_one_validator_and_none_keeps_a_copy(self):
        calls = []
        for m in re.finditer(r"_validate_drift_files\(", API_SRC):
            if API_SRC[max(0, m.start() - 4):m.start()] == "def ":
                continue
            depth, i = 1, m.end()
            while depth:
                depth += {"(": 1, ")": -1}.get(API_SRC[i], 0)
                i += 1
            calls.append(API_SRC[m.end():i - 1])
        self.assertEqual(len(calls), 5, calls)
        self.assertTrue(all("inherit=True" in c for c in calls),
                        "a place a host's or a profile's list is entered does not allow the syntax: %s" % calls)
        i = API_SRC.index("if 'watched_files' in body:")
        block = API_SRC[i:i + 700]
        self.assertNotIn("s.startswith('/')", block, "the drawer's save keeps its own copy of the validator again")

    def test_the_global_default_has_no_editor_that_could_take_the_marker(self):
        # nothing writes drift.default_watched_files; if something starts to, it must call the
        # validator with inherit=False. This finds the writer.
        writers = re.findall(r"['\"]default_watched_files['\"]\]\s*=|setdefault\(['\"]default_watched_files", API_SRC)
        self.assertEqual(writers, [], "something writes the global default list: validate it with inherit=False")


class TestApplyingAHostProfile(_Base):
    """A profile's drift list was stamped onto `drift_files`, a key nothing reads, so it never
    reached an agent."""

    def test_the_profiles_list_becomes_the_hosts_watch_list(self):
        out = api._apply_profile_to_device({"id": "d"}, {"drift_files": ["@defaults", "/x/*"]})
        self.assertEqual(out["watched_files"], ["@defaults", "/x/*"])
        self.devs(d=out)
        self.assertEqual(api.get_watched_files_for("d"), list(api.DEFAULT_WATCHED_FILES) + ["/x/*"])

    def test_a_profile_that_leaves_the_field_blank_does_not_switch_a_hosts_watching_off(self):
        host = {"id": "d", "watched_files": ["/mine"]}
        out = api._apply_profile_to_device(host, {"drift_files": [], "poll_interval": 30})
        self.assertEqual(out["watched_files"], ["/mine"])
        out = api._apply_profile_to_device({"id": "d"}, {"drift_files": []})
        self.assertNotIn("watched_files", out, "an empty list would mean 'watch nothing'")


class TestTheDrawersParser(unittest.TestCase):
    @unittest.skipUnless(_NODE, "node is not installed")
    def test_it_keeps_entries_the_marker_and_exclusions_and_drops_the_rest(self):
        code = srcpin.js_function(APP, "_parseWatchList") + """
console.log(JSON.stringify(_parseWatchList('@defaults\\n -/etc/hosts \\n/etc/apt/sources.list.d/*\\nnot a path\\n- /x\\n\\n/etc/ssh/\\n')));
console.log(JSON.stringify(_parseWatchList(null)));
"""
        with tempfile.TemporaryDirectory() as tmp:
            f = _rp_pl.Path(tmp) / "p.js"
            f.write_text(code)
            r = subprocess.run([_NODE, str(f)], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        first, second = r.stdout.strip().splitlines()
        self.assertEqual(json.loads(first), ["@defaults", "-/etc/hosts", "/etc/apt/sources.list.d/*", "/etc/ssh/"])
        self.assertEqual(json.loads(second), [])

    def test_the_drawer_uses_it(self):
        self.assertIn("const driftFiles = _parseWatchList(driftRaw);", APP)
        self.assertNotIn(".filter(s=>s.startsWith('/'))", APP[APP.index("const driftRaw"):APP.index("const driftRaw") + 400])


class TestStrings(unittest.TestCase):
    KEYS = (
        "Watched files — one entry per line",
        "An entry is a file, a folder ending in /, or a pattern such as /etc/apt/sources.list.d/*. Start with @defaults "
        "to add to the global default list, and use -/path to remove one of its entries.",
        "One entry per line: a file, a folder ending in /, or a pattern such as /etc/apt/sources.list.d/*. Start with "
        "@defaults to add to the list this host would otherwise get, and use -/path to remove one of its entries.",
        "Only a host or a profile list can use @defaults and - exclusions",
        "A - exclusion needs @defaults in the same list, to say what it removes from",
    )

    def test_every_string_is_a_dictionary_key_in_six_languages(self):
        for key in self.KEYS:
            with self.subTest(key=key[:40]):
                i = I18N.find('"%s"' % key)
                self.assertGreater(i, 0, "no dictionary entry")
                entry = I18N[i:I18N.index("},", i)]
                for lang in LANGS:
                    self.assertRegex(entry, r"""["']%s["']\s*:""" % lang)

    def test_the_text_on_screen_is_the_text_that_was_translated(self):
        self.assertIn("Watched files — one entry per line", DRIFT_JS)
        self.assertIn(self.KEYS[1], DRIFT_JS)
        self.assertIn(self.KEYS[2], APP)

    def test_the_server_sends_exactly_the_translated_sentences(self):
        self.assertIn(self.KEYS[3], API_SRC)
        self.assertIn(self.KEYS[4], API_SRC)

    def test_the_old_label_is_gone_from_both_the_screen_and_the_dictionary(self):
        old = "Watched files — one absolute path per line"
        self.assertNotIn(old, DRIFT_JS)
        self.assertNotIn('"%s"' % old, I18N, "a dictionary entry for text nothing shows")


if __name__ == "__main__":
    unittest.main()
