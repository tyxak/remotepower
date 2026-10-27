#!/usr/bin/env python3
"""v7.4.1, issue #39: folders and patterns in the drift watch.

"Accept a folder or wildcard as a watch entry, e.g. /etc/apt/sources.list.d/*, so new,
changed and removed files in it all count as drift."

An entry can now be a folder (a trailing slash: the regular files directly in it) or a
pattern (`*`, `?`, `[..]` in any segment). The agents expand it; the first report that lists
an entry is its baseline, so a file that appears in it later is drift ("added"), and a file
it used to list that goes missing is handled like any other missing file.

Four layers: the expansion on a real directory tree (in all three agents, held identical),
the report each agent builds, the server's ingest and matching, and an agent too old to
expand anything.
"""
import importlib.util
import os
import re
import sys as _rp_sys
import pathlib as _rp_pl
import tempfile
import unittest

_rp_sys.path.insert(0, str(_rp_pl.Path(__file__).resolve().parent))
from test_v622_alert_params import _SaveBase, ROOT, api  # noqa: E402

CLIENT = ROOT / "client"
AGENTS = {"linux": CLIENT / "remotepower-agent.py",
          "windows": CLIENT / "remotepower-agent-win.py",
          "macos": CLIENT / "remotepower-agent-mac.py"}
MARK = "# v7.4.1 (#39): a watch-list entry may be a folder"


def block_of(path):
    src = path.read_text()
    i = src.index(MARK)
    return src[i:src.index("\ndef compute_drift_report", i)].rstrip() + "\n"


def load_agent(name, path, host_root=None):
    old = os.environ.get("HOST_ROOT")
    if host_root is not None:
        os.environ["HOST_ROOT"] = host_root
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        if host_root is not None:
            if old is None:
                os.environ.pop("HOST_ROOT", None)
            else:
                os.environ["HOST_ROOT"] = old


class _Tree(unittest.TestCase):
    """A small host: apt sources, ssh keys under two homes, a symlink, a subfolder."""

    def setUp(self):
        self.root = _rp_pl.Path(tempfile.mkdtemp(prefix="rp-globs-"))
        self.addCleanup(__import__("shutil").rmtree, str(self.root), True)
        self.mk("etc/apt/sources.list.d/a.list", "deb a")
        self.mk("etc/apt/sources.list.d/b.sources", "Types: deb")
        self.mk("etc/apt/sources.list.d/.hidden.list", "deb h")
        self.mk("etc/apt/sources.list.d/sub/inner.list", "deb inner")
        self.mk("etc/apt/sources.list", "deb main")
        self.mk("home/alice/.ssh/authorized_keys", "ssh-ed25519 AAAA alice")
        self.mk("home/bob/.ssh/authorized_keys", "ssh-ed25519 AAAA bob")
        self.mk("home/carol/notes.txt", "x")
        os.symlink(self.root / "etc/apt/sources.list", self.root / "etc/apt/sources.list.d/link.list")
        os.symlink(self.root / "nope", self.root / "etc/apt/sources.list.d/broken.list")

    def mk(self, rel, text="x"):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    def real(self, p):
        return str(self.root) + p

    def clean(self, files):
        return [(f, v) for f, v in files]


class TestTheThreeAgentsAreOneImplementation(unittest.TestCase):
    def test_the_expansion_is_byte_identical_in_all_three(self):
        blocks = {k: block_of(p) for k, p in AGENTS.items()}
        self.assertEqual(blocks["windows"], blocks["macos"])
        self.assertEqual(blocks["linux"], blocks["windows"],
                         "the Linux agent's expansion has drifted from the others")
        self.assertIn("def expand_watch_entries", blocks["linux"])

    def test_the_extensionless_copy_carries_it_too(self):
        self.assertEqual(block_of(CLIENT / "remotepower-agent"), block_of(AGENTS["linux"]))

    def test_each_agent_reports_through_it(self):
        for k, p in AGENTS.items():
            src = p.read_text()
            with self.subTest(agent=k):
                self.assertIn("expand_watch_entries(paths, MAX_DRIFT_FILES", src)
                self.assertIn("drift_patterns", src)
                self.assertRegex(src, r"import fnmatch")


class TestExpansion(_Tree):
    def setUp(self):
        super().setUp()
        ns = {"os": os, "fnmatch": __import__("fnmatch")}
        exec(block_of(AGENTS["linux"]), ns)
        self.ex = lambda entries, limit=200: ns["expand_watch_entries"](entries, limit, real=self.real)
        self.ns = ns

    def paths(self, files):
        return [p for p, _ in files]

    def test_a_plain_path_is_itself_and_need_not_exist(self):
        files, info = self.ex(["/etc/hosts", "/etc/apt/sources.list"])
        self.assertEqual(files, [("/etc/hosts", ""), ("/etc/apt/sources.list", "")])
        self.assertEqual(info, {})

    def test_a_folder_is_the_regular_files_directly_in_it(self):
        files, info = self.ex(["/etc/apt/sources.list.d/"])
        got = self.paths(files)
        self.assertEqual(got, ["/etc/apt/sources.list.d/.hidden.list", "/etc/apt/sources.list.d/a.list",
                               "/etc/apt/sources.list.d/b.sources", "/etc/apt/sources.list.d/link.list"])
        self.assertTrue(all(v == "/etc/apt/sources.list.d/" for _, v in files))
        self.assertEqual(info, {"/etc/apt/sources.list.d/": {"count": 4, "truncated": False}})

    def test_dotfiles_are_included_subfolders_and_broken_links_are_not(self):
        got = self.paths(self.ex(["/etc/apt/sources.list.d/*"])[0])
        self.assertIn("/etc/apt/sources.list.d/.hidden.list", got)
        self.assertNotIn("/etc/apt/sources.list.d/sub", got)
        self.assertNotIn("/etc/apt/sources.list.d/sub/inner.list", got)
        self.assertNotIn("/etc/apt/sources.list.d/broken.list", got)
        self.assertIn("/etc/apt/sources.list.d/link.list", got, "a link to a file is the file")

    def test_a_wildcard_in_the_middle_of_the_path(self):
        files, info = self.ex(["/home/*/.ssh/authorized_keys"])
        self.assertEqual(self.paths(files), ["/home/alice/.ssh/authorized_keys", "/home/bob/.ssh/authorized_keys"])
        self.assertEqual(info["/home/*/.ssh/authorized_keys"]["count"], 2)

    def test_a_suffix_pattern_and_a_character_class(self):
        self.assertEqual(self.paths(self.ex(["/etc/apt/sources.list.d/*.list"])[0]),
                         ["/etc/apt/sources.list.d/.hidden.list", "/etc/apt/sources.list.d/a.list",
                          "/etc/apt/sources.list.d/link.list"])
        self.assertEqual(self.paths(self.ex(["/etc/apt/sources.list.d/[ab].*"])[0]),
                         ["/etc/apt/sources.list.d/a.list", "/etc/apt/sources.list.d/b.sources"])
        self.assertEqual(self.paths(self.ex(["/etc/apt/sources.list.d/?.list"])[0]),
                         ["/etc/apt/sources.list.d/a.list"])

    def test_a_pattern_that_matches_nothing_is_still_reported_as_looked_at(self):
        files, info = self.ex(["/etc/apt/sources.list.d/*.nothing", "/no/such/dir/*"])
        self.assertEqual(files, [])
        self.assertEqual(info["/etc/apt/sources.list.d/*.nothing"], {"count": 0, "truncated": False})
        self.assertEqual(info["/no/such/dir/*"], {"count": 0, "truncated": False})

    def test_a_pattern_that_climbs_out_matches_nothing(self):
        for entry in ("/etc/apt/../*", "/home/*/../../etc/*"):
            with self.subTest(entry=entry):
                self.assertEqual(self.ex([entry])[0], [])

    def test_the_same_file_from_two_entries_is_taken_once_by_the_first(self):
        files, _ = self.ex(["/etc/apt/sources.list.d/a.list", "/etc/apt/sources.list.d/*.list"])
        self.assertEqual([p for p, _ in files].count("/etc/apt/sources.list.d/a.list"), 1)
        self.assertEqual(dict(files)["/etc/apt/sources.list.d/a.list"], "")

    def test_entries_that_are_not_absolute_paths_are_skipped(self):
        self.assertEqual(self.ex(["etc/hosts", "", None, 5, {"path": "/x"}])[0], [])

    def test_the_file_limit_cuts_the_search_and_says_so(self):
        for i in range(30):
            self.mk("many/f%02d" % i)
        files, info = self.ex(["/many/*"], limit=10)
        self.assertEqual(len(files), 10)
        self.assertTrue(info["/many/*"]["truncated"])
        self.assertEqual(info["/many/*"]["count"], 30)

    def test_the_listing_budget_bounds_a_wide_pattern(self):
        for i in range(250):
            self.mk("wide/d%03d/f" % i)
        saved = self.ns["MAX_GLOB_LISTINGS"]
        self.assertLessEqual(saved, 200)
        # the first * lists /wide once; the second lists each of its 250 folders
        files, info = self.ex(["/wide/*/*"], limit=1000)
        self.assertTrue(info["/wide/*/*"]["truncated"], "250 folders is past the listing budget")
        self.assertLessEqual(len(files), saved)
        self.assertGreater(len(files), 0)

    def test_the_candidate_cap_bounds_a_wide_folder(self):
        for i in range(60):
            self.mk("cap/f%02d" % i)
        self.ns["MAX_GLOB_CANDIDATES"] = 25
        files, info = self.ex(["/cap/*"], limit=1000)
        self.assertEqual(len(files), 25)
        self.assertTrue(info["/cap/*"]["truncated"])

    def test_the_container_host_root_is_honoured(self):
        # entries are clean host paths; the listing happens under the host root
        files, _ = self.ex(["/home/carol/*"])
        self.assertEqual(self.paths(files), ["/home/carol/notes.txt"])


class TestEachAgentsReport(_Tree):
    """compute_drift_report on a real tree, in every agent."""

    def report(self, agent, entries):
        pats = {}
        out = agent.compute_drift_report(entries, pats)
        return out, pats

    def entries(self):
        base = str(self.root)
        return [base + "/etc/apt/sources.list", base + "/etc/apt/sources.list.d/", base + "/home/*/.ssh/authorized_keys"]

    def check(self, agent):
        out, pats = self.report(agent, self.entries())
        base = str(self.root)
        plain = out[base + "/etc/apt/sources.list"]
        self.assertTrue(plain["exists"])
        self.assertNotIn("via", plain, "a plain entry reports exactly what it always did")
        added = out[base + "/etc/apt/sources.list.d/a.list"]
        self.assertEqual(added["via"], base + "/etc/apt/sources.list.d/")
        self.assertTrue(added["hash"].startswith("sha256:"))
        self.assertEqual(out[base + "/home/bob/.ssh/authorized_keys"]["via"], base + "/home/*/.ssh/authorized_keys")
        self.assertEqual(set(pats), {base + "/etc/apt/sources.list.d/", base + "/home/*/.ssh/authorized_keys"})
        # a plain list gives no patterns and the same dict as before
        out2, pats2 = self.report(agent, [base + "/etc/apt/sources.list"])
        self.assertEqual(pats2, {})
        self.assertEqual(list(out2), [base + "/etc/apt/sources.list"])

    def test_the_linux_agent(self):
        self.check(load_agent("rp_globs_linux", AGENTS["linux"]))

    def test_the_windows_agent(self):
        self.check(load_agent("rp_globs_win", AGENTS["windows"]))

    def test_the_macos_agent(self):
        self.check(load_agent("rp_globs_mac", AGENTS["macos"]))

    def test_the_containerized_linux_agent_reads_the_host_root(self):
        agent = load_agent("rp_globs_ctr", AGENTS["linux"], host_root=str(self.root))
        pats = {}
        out = agent.compute_drift_report(["/etc/apt/sources.list.d/", "/etc/apt/sources.list"], pats)
        self.assertIn("/etc/apt/sources.list.d/a.list", out, "the report is keyed by the clean path")
        self.assertTrue(out["/etc/apt/sources.list.d/a.list"]["exists"])
        self.assertTrue(out["/etc/apt/sources.list"]["exists"])
        self.assertEqual(pats["/etc/apt/sources.list.d/"]["count"], 4)

    def test_the_old_calling_convention_still_works(self):
        agent = load_agent("rp_globs_old", AGENTS["linux"])
        out = agent.compute_drift_report([str(self.root / "etc/apt/sources.list")])
        self.assertEqual(len(out), 1)


class TestTheChangeDetectorNoticesAFolderChanging(_Tree):
    def test_a_new_file_in_a_watched_folder_is_a_change(self):
        agent = load_agent("rp_globs_det", AGENTS["linux"])
        wf = [str(self.root / "etc/apt/sources.list.d") + "/"]
        self.assertFalse(agent._watched_files_changed(wf), "the first look seeds")
        self.assertFalse(agent._watched_files_changed(wf), "nothing moved")
        self.mk("etc/apt/sources.list.d/new.list", "deb evil")
        self.assertTrue(agent._watched_files_changed(wf))
        self.assertFalse(agent._watched_files_changed(wf), "settled")

    def test_a_file_leaving_a_watched_folder_is_a_change(self):
        agent = load_agent("rp_globs_det2", AGENTS["linux"])
        wf = [str(self.root / "etc/apt/sources.list.d") + "/*.list"]
        agent._watched_files_changed(wf)
        os.unlink(self.root / "etc/apt/sources.list.d/a.list")
        self.assertTrue(agent._watched_files_changed(wf))

    def test_dict_entries_are_still_accepted(self):
        agent = load_agent("rp_globs_det3", AGENTS["linux"])
        wf = [{"path": str(self.root / "etc/apt/sources.list")}]
        self.assertFalse(agent._watched_files_changed(wf))


class TestServerMatching(unittest.TestCase):
    m = staticmethod(lambda path, entry: api._watch_matches(path, entry))

    def test_plain_folder_and_pattern(self):
        self.assertTrue(self.m("/etc/hosts", "/etc/hosts"))
        self.assertFalse(self.m("/etc/hosts2", "/etc/hosts"))
        self.assertTrue(self.m("/etc/apt/sources.list.d/a.list", "/etc/apt/sources.list.d/"))
        self.assertFalse(self.m("/etc/apt/sources.list.d/sub/a.list", "/etc/apt/sources.list.d/"),
                         "a folder is the files directly in it")
        self.assertTrue(self.m("/etc/apt/sources.list.d/a.list", "/etc/apt/sources.list.d/*.list"))
        self.assertFalse(self.m("/etc/apt/sources.list.d/a.sources", "/etc/apt/sources.list.d/*.list"))
        self.assertTrue(self.m("/home/bob/.ssh/authorized_keys", "/home/*/.ssh/authorized_keys"))
        self.assertFalse(self.m("/home/bob/x/.ssh/authorized_keys", "/home/*/.ssh/authorized_keys"),
                         "a wildcard is one path segment")
        self.assertTrue(self.m("/etc/apt/sources.list.d/.hidden", "/etc/apt/sources.list.d/*"))

    def test_nothing_with_dots_or_odd_segments_belongs_to_anything(self):
        for path in ("/etc/apt/sources.list.d/../../shadow", "/etc/apt/sources.list.d/./a", "/etc//apt/a",
                     "/etc/apt/sources.list.d//", "relative/path", "", None,
                     # these two have the right number of segments, and a * matches ".." and "."
                     "/etc/apt/sources.list.d/..", "/etc/apt/sources.list.d/."):
            with self.subTest(path=path):
                self.assertFalse(self.m(path, "/etc/apt/sources.list.d/*"))
                self.assertFalse(self.m(path, "/etc/apt/sources.list.d/"))
        self.assertFalse(self.m("/home/../.ssh/authorized_keys", "/home/*/.ssh/authorized_keys"))
        self.assertFalse(self.m("/home/./.ssh/authorized_keys", "/home/*/.ssh/authorized_keys"))

    def test_one_matcher_for_a_list(self):
        self.assertTrue(api._path_is_watched("/etc/hosts", ["/etc/x", "/etc/hosts"]))
        self.assertTrue(api._path_is_watched("/etc/apt/x.list", ["/etc/apt/*.list"]))
        self.assertFalse(api._path_is_watched("/etc/shadow", ["/etc/apt/*.list", "/etc/hosts"]))
        self.assertFalse(api._path_is_watched("/etc/hosts", []))

    def test_the_server_and_the_agents_agree_on_what_a_pattern_matches(self):
        # the agent expands on a tree; the server must call exactly those files watched
        import shutil
        root = _rp_pl.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, str(root), True)
        for rel in ("a/x.list", "a/y.sources", "a/.dot", "b/x.list", "b/c/x.list"):
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text("x")
        ns = {"os": os, "fnmatch": __import__("fnmatch")}
        exec(block_of(AGENTS["linux"]), ns)
        for entry in ("/a/", "/a/*", "/*/x.list", "/a/?.list", "/a/[xy].*", "/*/*", "/b/*"):
            with self.subTest(entry=entry):
                files, _ = ns["expand_watch_entries"]([entry], 100, real=lambda p: str(root) + p)
                expanded = {p for p, _ in files}
                universe = {"/" + str(f.relative_to(root)) for f in root.rglob("*") if f.is_file()}
                matched = {p for p in universe if api._watch_matches(p, entry)}
                self.assertEqual(matched, expanded, entry)


class _Base(_SaveBase):
    DEV = "d1"

    def setUp(self):
        super().setUp()
        self._more = {}
        for attr in ("DEVICES_FILE", "DRIFT_STATE_FILE", "CMDS_FILE"):
            self._more[attr] = getattr(api, attr)
            setattr(api, attr, self.d / self._more[attr].name)
        self.calls = []
        api.fire_webhook = lambda ev, payload: self.calls.append((ev, payload))
        api.save(api.DEVICES_FILE, {self.DEV: {"id": self.DEV, "name": "vaultbox", "version": "7.4.1"}})
        api._invalidate_load_cache(api.DEVICES_FILE)

    def tearDown(self):
        for a, v in self._more.items():
            setattr(api, a, v)
        super().tearDown()

    FOLDER = "/etc/apt/sources.list.d/"

    @staticmethod
    def f(path, h, via=FOLDER):
        d = {"hash": h, "size": 5, "mtime": 1, "exists": True}
        if via:
            d["via"] = via
        return d

    def report(self, files, patterns=None):
        api._ingest_drift_report(self.DEV, files, patterns=patterns)
        api._invalidate_load_cache(api.DRIFT_STATE_FILE)
        return api.load(api.DRIFT_STATE_FILE)[self.DEV]

    def pat(self, count, truncated=False, entry=FOLDER):
        return {entry: {"count": count, "truncated": truncated}}

    def titles(self):
        return [api._alert_title(e, dict(p, device_name="vaultbox")) for e, p in self.calls]


class TestTheFirstReportIsTheBaselineAndLaterFilesAreDrift(_Base):
    A = "/etc/apt/sources.list.d/a.list"
    B = "/etc/apt/sources.list.d/b.list"

    def test_the_first_report_for_a_folder_is_silent(self):
        st = self.report({self.A: self.f(self.A, "sha256:a")}, self.pat(1))
        self.assertEqual(self.calls, [])
        self.assertEqual(st["files"][self.A]["drift_count"], 0)
        self.assertEqual(st["files"][self.A]["via"], self.FOLDER)
        self.assertIn(self.FOLDER, st["patterns"])

    def test_a_file_that_appears_later_is_drift_and_says_added(self):
        self.report({self.A: self.f(self.A, "sha256:a")}, self.pat(1))
        st = self.report({self.A: self.f(self.A, "sha256:a"), self.B: self.f(self.B, "sha256:b")}, self.pat(2))
        self.assertEqual(self.titles(), ["Config drift on vaultbox: /etc/apt/sources.list.d/b.list added"])
        rec = st["files"][self.B]
        self.assertTrue(rec["added"])
        self.assertEqual(rec["drift_count"], 1)
        self.assertIsNone(rec["baseline_hash"])
        self.assertEqual(rec["current_hash"], "sha256:b")
        self.assertEqual(self.calls[0][1]["reason"], "file_added")
        self.assertIsNone(self.calls[0][1]["baseline_hash"])
        self.assertEqual(checks_drifted(st), [self.B], "it counts as drifted wherever drift is counted")

    def test_it_is_said_once(self):
        self.report({self.A: self.f(self.A, "sha256:a")}, self.pat(1))
        both = {self.A: self.f(self.A, "sha256:a"), self.B: self.f(self.B, "sha256:b")}
        self.report(both, self.pat(2))
        self.report(both, self.pat(2))
        self.report(both, self.pat(2))
        self.assertEqual(len(self.calls), 1)

    def test_an_added_file_that_then_changes_is_a_change(self):
        self.report({self.A: self.f(self.A, "sha256:a")}, self.pat(1))
        self.report({self.A: self.f(self.A, "sha256:a"), self.B: self.f(self.B, "sha256:b")}, self.pat(2))
        self.calls.clear()
        self.report({self.A: self.f(self.A, "sha256:a"), self.B: self.f(self.B, "sha256:b2")}, self.pat(2))
        self.assertEqual(self.titles(), ["Config drift on vaultbox: /etc/apt/sources.list.d/b.list changed"])

    def test_an_empty_folder_is_a_baseline_too(self):
        self.report({}, self.pat(0))
        self.assertEqual(self.calls, [])
        self.report({self.A: self.f(self.A, "sha256:a")}, self.pat(1))
        self.assertEqual(len(self.calls), 1, "the first file in a folder that was empty is the change")

    def test_a_folder_the_host_was_not_watching_before_is_not_alarming(self):
        # the operator adds the entry to a host that already has files there
        self.report({"/etc/hosts": self.f("/etc/hosts", "sha256:h", via="")})
        self.calls.clear()
        self.report({"/etc/hosts": self.f("/etc/hosts", "sha256:h", via=""),
                     self.A: self.f(self.A, "sha256:a"), self.B: self.f(self.B, "sha256:b")}, self.pat(2))
        self.assertEqual(self.calls, [])

    def test_accepting_the_baseline_clears_added(self):
        self.report({self.A: self.f(self.A, "sha256:a")}, self.pat(1))
        self.report({self.A: self.f(self.A, "sha256:a"), self.B: self.f(self.B, "sha256:b")}, self.pat(2))
        api.require_perm = lambda *a, **k: "jakob"
        self.call_baseline()
        api._invalidate_load_cache(api.DRIFT_STATE_FILE)
        rec = api.load(api.DRIFT_STATE_FILE)[self.DEV]["files"][self.B]
        self.assertNotIn("added", rec)
        self.assertEqual((rec["baseline_hash"], rec["drift_count"]), ("sha256:b", 0))

    def call_baseline(self):
        saved = api.require_perm
        api.require_perm = lambda *a, **k: "jakob"
        try:
            self.cap.clear()
            api.method = lambda: "POST"
            api.get_json_obj = lambda: {"all": True}
            try:
                api.handle_device_drift_baseline(self.DEV)
            except api.HTTPError:
                pass
        finally:
            api.require_perm = saved
        self.assertEqual(self.cap.get("s"), 200, self.cap.get("b"))

    def test_a_file_listed_then_gone_before_it_was_read_leaves_no_record(self):
        self.report({self.A: self.f(self.A, "sha256:a")}, self.pat(1))
        gone = dict(self.f(self.B, None), exists=False, hash=None)
        st = self.report({self.A: self.f(self.A, "sha256:a"), self.B: gone}, self.pat(2))
        self.assertNotIn(self.B, st["files"])
        self.assertEqual(self.calls, [])


class TestFilesLeavingAFolder(_Base):
    A = "/etc/apt/sources.list.d/a.list"
    B = "/etc/apt/sources.list.d/b.list"

    def both(self):
        return {self.A: self.f(self.A, "sha256:a"), self.B: self.f(self.B, "sha256:b")}

    def test_a_file_a_folder_stops_listing_is_removed_after_the_usual_three_sightings(self):
        self.report(self.both(), self.pat(2))
        only_a = {self.A: self.f(self.A, "sha256:a")}
        for _ in range(api.DRIFT_MISSING_DORMANT_AFTER - 1):
            self.report(only_a, self.pat(1))
        self.assertEqual(self.calls, [])
        st = self.report(only_a, self.pat(1))
        self.assertEqual(self.titles(), ["Config drift on vaultbox: /etc/apt/sources.list.d/b.list removed"])
        self.assertTrue(st["files"][self.B]["dormant"])
        self.report(only_a, self.pat(1))
        self.assertEqual(len(self.calls), 1, "said once")

    def test_a_cut_short_search_says_nothing_about_the_files_it_did_not_reach(self):
        self.report(self.both(), self.pat(2))
        for _ in range(api.DRIFT_MISSING_DORMANT_AFTER + 2):
            self.report({self.A: self.f(self.A, "sha256:a")}, self.pat(500, truncated=True))
        self.assertEqual(self.calls, [])

    def test_an_old_agent_that_sends_no_patterns_does_not_make_files_vanish(self):
        self.report(self.both(), self.pat(2))
        for _ in range(api.DRIFT_MISSING_DORMANT_AFTER + 2):
            self.report({self.A: self.f(self.A, "sha256:a")})
        self.assertEqual(self.calls, [])

    def test_a_file_that_comes_back_is_revived_not_added(self):
        self.report(self.both(), self.pat(2))
        for _ in range(api.DRIFT_MISSING_DORMANT_AFTER):
            self.report({self.A: self.f(self.A, "sha256:a")}, self.pat(1))
        self.calls.clear()
        st = self.report(self.both(), self.pat(2))
        self.assertFalse(st["files"][self.B].get("dormant"))
        self.assertEqual(self.calls, [], "back with the same hash: nothing changed")


class TestEntriesComeAndGo(_Base):
    A = "/etc/apt/sources.list.d/a.list"

    def test_an_entry_taken_off_the_list_is_forgotten_so_putting_it_back_starts_again(self):
        self.report({self.A: self.f(self.A, "sha256:a")}, self.pat(1))
        st = self.report({"/etc/hosts": self.f("/etc/hosts", "sha256:h", via="")})     # no patterns now
        self.assertNotIn("patterns", st)
        new = "/etc/apt/sources.list.d/new.list"
        self.calls.clear()
        self.report({"/etc/hosts": self.f("/etc/hosts", "sha256:h", via=""),
                     self.A: self.f(self.A, "sha256:a"), new: self.f(new, "sha256:n")}, self.pat(2))
        self.assertEqual(self.calls, [], "it was not being watched while that file arrived")

    def test_a_via_the_agent_never_listed_is_just_a_baseline(self):
        self.report({self.A: self.f(self.A, "sha256:a", via="/forged/")}, None)
        self.report({self.A: self.f(self.A, "sha256:a", via="/forged/"),
                     "/b": self.f("/b", "sha256:b", via="/forged/")}, None)
        self.assertEqual(self.calls, [])

    def test_junk_in_the_patterns_is_ignored(self):
        for junk in (None, [], "x", {"nope": 1}, {"/ok/": "x"}, {"/ok/": {"count": "many"}}, {5: {}}):
            with self.subTest(junk=junk):
                api._ingest_drift_report(self.DEV, {}, patterns=junk)


def checks_drifted(state):
    import checks
    return checks.drifted_files(state)


class TestTheListAnAgentIsSent(_Base):
    def sent(self, version):
        api.save(api.DEVICES_FILE, {self.DEV: {"id": self.DEV, "name": "n", "version": version,
                                               "watched_files": ["/etc/hosts", "/etc/apt/sources.list.d/",
                                                                 "/home/*/.ssh/authorized_keys"]}})
        api._invalidate_load_cache(api.DEVICES_FILE)
        dev = api.load(api.DEVICES_FILE)[self.DEV]
        return api._agent_watch_list(api.get_watched_files_for(self.DEV, {self.DEV: dev}), dev)

    def test_a_current_agent_gets_the_patterns(self):
        self.assertEqual(self.sent("7.4.1"),
                         ["/etc/hosts", "/etc/apt/sources.list.d/", "/home/*/.ssh/authorized_keys"])
        self.assertEqual(len(self.sent("7.5.0")), 3)

    def test_an_older_agent_gets_only_plain_paths(self):
        for v in ("7.4.0", "7.3.9", "6.9.9", "", None, "garbage"):
            with self.subTest(version=v):
                self.assertEqual(self.sent(v), ["/etc/hosts"])

    def test_the_drift_page_still_shows_the_whole_list(self):
        api.save(api.DEVICES_FILE, {self.DEV: {"id": self.DEV, "name": "n", "version": "7.4.0",
                                               "watched_files": ["/etc/hosts", "/etc/apt/sources.list.d/"]}})
        api._invalidate_load_cache(api.DEVICES_FILE)
        self.assertEqual(api.get_watched_files_for(self.DEV), ["/etc/hosts", "/etc/apt/sources.list.d/"])

    def test_the_gate_version_is_the_release_that_carries_the_expansion(self):
        """The gate names the release that first expanded patterns (7.4.1). An
        agent built later keeps the expansion, so it must be at or past the gate,
        never pinned to the gate's own release."""
        self.assertEqual(api.DRIFT_GLOB_MIN_AGENT, (7, 4, 1))
        for k, p in AGENTS.items():
            m = re.search(r"^VERSION\s*=\s*'(\d+)\.(\d+)\.(\d+)'", p.read_text(), re.M)
            self.assertTrue(m, k)
            self.assertGreaterEqual(tuple(int(x) for x in m.groups()), api.DRIFT_GLOB_MIN_AGENT, k)


class TestThroughTheRealHeartbeat(_Base):
    """From the agent's body to the stored state, the alert and the answer it gets back."""

    def beat(self, version, drift, patterns=None):
        api.save(api.DEVICES_FILE, {self.DEV: {"id": self.DEV, "name": "vaultbox", "token": "tok",
                                               "version": version, "monitored": True,
                                               "watched_files": ["/etc/hosts", "/etc/apt/sources.list.d/"]}})
        api._invalidate_load_cache(api.DEVICES_FILE)
        body = {"device_id": self.DEV, "token": "tok", "version": version, "drift": drift}
        if patterns is not None:
            body["drift_patterns"] = patterns
        api.get_json_body = lambda: body
        api.get_json_obj = lambda: body
        api.method = lambda: "POST"
        self.cap.clear()
        try:
            api.handle_heartbeat()
        except (api.HTTPError, SystemExit):
            pass
        return self.cap.get("b") or {}

    def test_a_current_agent_gets_patterns_back_and_its_report_is_ingested(self):
        a = "/etc/apt/sources.list.d/a.list"
        b = "/etc/apt/sources.list.d/b.list"
        resp = self.beat("7.4.1", {a: self.f(a, "sha256:a")}, self.pat(1))
        self.assertIn("/etc/apt/sources.list.d/", resp.get("watched_files", []), resp)
        self.beat("7.4.1", {a: self.f(a, "sha256:a"), b: self.f(b, "sha256:b")}, self.pat(2))
        self.assertEqual(self.titles(), ["Config drift on vaultbox: /etc/apt/sources.list.d/b.list added"])

    def test_an_old_agent_is_never_sent_a_pattern(self):
        resp = self.beat("7.4.0", {"/etc/hosts": self.f("/etc/hosts", "sha256:h", via="")})
        self.assertEqual(resp.get("watched_files"), ["/etc/hosts"])

    def test_an_empty_folder_report_still_reaches_the_ingest(self):
        self.beat("7.4.1", {}, self.pat(0))
        api._invalidate_load_cache(api.DRIFT_STATE_FILE)
        st = api.load(api.DRIFT_STATE_FILE).get(self.DEV) or {}
        self.assertIn("/etc/apt/sources.list.d/", st.get("patterns", {}))


class TestWhatTheOperatorMayFetch(_Base):
    """The content fetch is limited to files that are being watched; a folder or a pattern widens
    that to the files it matches, and never to a path that climbs."""

    def fetch(self, watched, paths):
        api.save(api.DEVICES_FILE, {self.DEV: {"id": self.DEV, "name": "n", "watched_files": watched}})
        api.save(api.CMDS_FILE, {})
        for f in (api.DEVICES_FILE, api.CMDS_FILE):
            api._invalidate_load_cache(f)
        api.require_perm = lambda *a, **k: "jakob"
        self.cap.clear()
        api.method = lambda: "POST"
        api.get_json_obj = lambda: {"paths": paths}
        try:
            api.handle_drift_fetch_content(self.DEV)
        except api.HTTPError:
            pass
        return self.cap.get("b") or {}

    def test_a_file_in_a_watched_folder_may_be_fetched(self):
        b = self.fetch(["/etc/apt/sources.list.d/"], ["/etc/apt/sources.list.d/new.list"])
        self.assertEqual(b.get("queued"), ["/etc/apt/sources.list.d/new.list"], b)

    def test_nothing_else_may(self):
        b = self.fetch(["/etc/apt/sources.list.d/", "/etc/hosts"],
                       ["/etc/passwd", "/etc/apt/sources.list.d/../../shadow", "/etc/apt/sources.list.d/sub/x",
                        "/etc/shadow"])
        self.assertEqual(b.get("queued"), [], b)

    def test_the_shadow_files_stay_denied_even_under_a_pattern(self):
        b = self.fetch(["/etc/*"], ["/etc/shadow", "/etc/gshadow"])
        self.assertEqual(b.get("queued"), [])
        self.assertEqual(sorted(b.get("denied", [])), ["/etc/gshadow", "/etc/shadow"])


class TestWordingAndUi(unittest.TestCase):
    def test_the_alert_and_the_notification_both_say_added(self):
        p = {"path": "/x/y", "exists": True, "reason": "file_added", "device_name": "h"}
        self.assertEqual(api._alert_title("drift_detected", p), "Config drift on h: /x/y added")
        self.assertEqual(api._alert_title("drift_detected", dict(p, reason=None)), "Config drift on h: /x/y changed")
        self.assertEqual(api._alert_title("drift_detected", dict(p, exists=False)), "Config drift on h: /x/y removed")
        import notify
        self.assertIn("added", notify._webhook_message("drift_detected", dict(p, name="h")))
        self.assertIn("changed", notify._webhook_message("drift_detected", dict(p, name="h", reason=None)))
        self.assertIn("removed", notify._webhook_message("drift_detected", dict(p, name="h", exists=False)))

    def test_the_drift_page_labels_an_added_file_and_names_the_entry_it_came_from(self):
        js = (ROOT / "server/html/static/js/app-drift.js").read_text()
        self.assertIn("} else if (drifted && f.added) {", js)
        self.assertIn("● Added", js)
        self.assertIn("f.via ?", js)
        i18n = (ROOT / "server/html/static/js/i18n.js").read_text()
        i = i18n.index('"● Added"')
        entry = i18n[i:i18n.index("},", i)]
        for lang in ("zh", "hi", "es", "ar", "de", "fr"):
            self.assertRegex(entry, r'"%s"\s*:' % lang)

    def test_the_webhook_carries_the_reason_when_there_is_one(self):
        src = (ROOT / "server/cgi-bin/api.py").read_text()
        self.assertIn("**({'reason': ev['reason']} if ev.get('reason') else {})", src)


if __name__ == "__main__":
    unittest.main()
