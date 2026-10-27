#!/usr/bin/env python3
"""7.4.2 (security review): the agent never waits on a file another user can turn into a FIFO.

The agent runs as root and reads files whose names other people choose: the files and folders an
operator asks it to watch for drift, the home directories its secret and PII scans walk, the trees its
loader check looks through, the logs it sweeps. A plain open() of a FIFO waits for a writer that never
comes, and a stat() that said "regular file" a microsecond earlier does not help: a local user who can
write the folder swaps the name for a FIFO in between. Reproduced on the 7.4.1 agent with a second
process doing exactly that: the drift report hung inside open() after 353 rounds. A FIFO simply left in
a tree the loader check walks needed no race at all.

The fix is one helper, `_open_regular`, which opens without blocking and asks the descriptor what it
really is. This holds: what the helper does; that the three agents carry the same helper; that each
read the sweep found goes through it (a swap is simulated by making stat() lie about a FIFO, which is
what the race amounts to); and, as the ratchet over the class, that no other read opens a path for
binary reading with a plain open() unless it is listed here with the reason it cannot be reached.

A hang is turned into a failure by an alarm, so a regression fails in seconds instead of hanging the
suite.
"""
import ast
import contextlib
import os
import signal
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v741_drift_globs import load_agent  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
CLIENT = ROOT / "client"
AGENTS = {
    "linux": CLIENT / "remotepower-agent.py",
    "windows": CLIENT / "remotepower-agent-win.py",
    "macos": CLIENT / "remotepower-agent-mac.py",
}
HAVE_FIFO = hasattr(os, "mkfifo") and hasattr(signal, "SIGALRM")


class Hung(Exception):
    pass


@contextlib.contextmanager
def within(seconds, what):
    def boom(_sig, _frm):
        raise Hung(f"{what} did not return in {seconds}s: it is waiting on a FIFO")
    old = signal.signal(signal.SIGALRM, boom)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


def function_source(path, name):
    src = Path(path).read_text(encoding="utf-8")
    for node in ast.parse(src).body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(src, node)
    raise AssertionError(f"{name} is not defined in {path}")


def helper(agent_key):
    ns = {"os": os, "stat": stat}
    exec(function_source(AGENTS[agent_key], "_open_regular"), ns)
    return ns["_open_regular"]


def plain_binary_opens(source):
    """[(function, first argument)] for every open(<x>, <a read-binary mode>) in `source`."""
    found = []

    class V(ast.NodeVisitor):
        def __init__(self):
            self.stack = []

        def visit_FunctionDef(self, n):
            self.stack.append(n.name)
            self.generic_visit(n)
            self.stack.pop()
        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Call(self, n):
            if isinstance(n.func, ast.Name) and n.func.id == "open":
                mode = None
                if len(n.args) > 1 and isinstance(n.args[1], ast.Constant):
                    mode = n.args[1].value
                for kw in n.keywords:
                    if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                        mode = kw.value.value
                if mode and "r" in str(mode) and "b" in str(mode):
                    found.append((self.stack[-1] if self.stack else "<module>", ast.unparse(n.args[0])))
            self.generic_visit(n)
    V().visit(ast.parse(source))
    return found


@unittest.skipUnless(HAVE_FIFO, "needs mkfifo and SIGALRM")
class TestTheHelper(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rp-v742-fifo-"))
        self.addCleanup(__import__("shutil").rmtree, str(self.tmp), True)
        self.reg = self.tmp / "regular"
        self.reg.write_bytes(b"hello\n")
        self.fifo = self.tmp / "fifo"
        os.mkfifo(self.fifo)

    def each(self):
        for k in AGENTS:
            yield k, helper(k)

    def test_a_regular_file_is_opened_and_read(self):
        for k, f in self.each():
            with self.subTest(agent=k):
                with f(str(self.reg)) as fh:
                    self.assertEqual(fh.read(), b"hello\n")

    def test_a_fifo_is_refused_at_once(self):
        for k, f in self.each():
            with self.subTest(agent=k):
                with within(5, "opening a FIFO"):
                    self.assertIsNone(f(str(self.fifo)))

    def test_a_fifo_with_a_writer_is_refused_too(self):
        fd = os.open(self.fifo, os.O_RDWR)          # holds both ends: a blocking open would return here
        self.addCleanup(os.close, fd)
        for k, f in self.each():
            with self.subTest(agent=k):
                with within(5, "opening a FIFO that has a writer"):
                    self.assertIsNone(f(str(self.fifo)))

    def test_a_link_to_a_regular_file_is_followed_and_a_link_to_a_fifo_is_not_read(self):
        os.symlink(self.reg, self.tmp / "to-reg")
        os.symlink(self.fifo, self.tmp / "to-fifo")
        for k, f in self.each():
            with self.subTest(agent=k):
                with f(str(self.tmp / "to-reg")) as fh:
                    self.assertEqual(fh.read(), b"hello\n")
                with within(5, "opening a link to a FIFO"):
                    self.assertIsNone(f(str(self.tmp / "to-fifo")))

    def test_a_missing_file_raises_as_open_does_and_a_directory_is_not_a_regular_file(self):
        for k, f in self.each():
            with self.subTest(agent=k):
                with self.assertRaises(FileNotFoundError):
                    f(str(self.tmp / "nope"))
                self.assertIsNone(f(str(self.tmp)))

    def test_nothing_is_left_open(self):
        def count():
            return len(os.listdir("/proc/self/fd")) if os.path.isdir("/proc/self/fd") else None
        before = count()
        if before is None:
            self.skipTest("no /proc/self/fd")
        with within(30, "opening a FIFO 180 times"):
            for _k, f in self.each():
                for _ in range(60):
                    self.assertIsNone(f(str(self.fifo)))
                    f(str(self.reg)).close()
        self.assertLessEqual(count(), before + 1)

    def test_the_control_a_plain_open_of_a_fifo_does_hang(self):
        """Without this the tests above could pass for a platform where nothing blocks."""
        with self.assertRaises(Hung):
            with within(1, "a plain open() of a FIFO"):
                open(self.fifo, "rb")


class TestTheThreeAgentsCarryTheSameHelper(unittest.TestCase):

    def test_the_helper_is_the_same_code_in_all_three(self):
        def norm(key):
            fn = ast.parse(function_source(AGENTS[key], "_open_regular"))
            node = fn.body[0]
            if node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant):
                node.body = node.body[1:]
            return ast.unparse(node)
        a = {k: norm(k) for k in AGENTS}
        self.assertEqual(a["linux"], a["windows"])
        self.assertEqual(a["linux"], a["macos"])

    def test_the_extensionless_copy_is_the_python_file(self):
        self.assertEqual((CLIENT / "remotepower-agent").read_bytes(), AGENTS["linux"].read_bytes())


@unittest.skipUnless(HAVE_FIFO, "needs mkfifo and SIGALRM")
class TestTheReadsTheSweepFound(unittest.TestCase):
    """A swap is simulated by making stat() say "regular file" for a FIFO, which is the state the
    microsecond between the stat and the open leaves. The agent must come back."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="rp-v742-fifo-"))
        self.addCleanup(__import__("shutil").rmtree, str(self.tmp), True)
        self.reg = self.tmp / "regular"
        self.reg.write_text("x" * 100)
        self.fifo = self.tmp / "authorized_keys"
        os.mkfifo(self.fifo)
        real_stat = os.stat
        fifo, reg = str(self.fifo), str(self.reg)

        def lying_stat(path, *a, **k):
            return real_stat(reg if os.fspath(path) == fifo else path, *a, **k)
        p = mock.patch.object(os, "stat", lying_stat)
        p.start()
        self.addCleanup(p.stop)

    def test_the_drift_report_in_every_agent(self):
        for key, path in AGENTS.items():
            with self.subTest(agent=key):
                agent = load_agent(f"rp_fifo_{key}", path)
                with within(10, f"the {key} agent's drift report"):
                    out = agent.compute_drift_report([str(self.fifo), str(self.reg)])
                self.assertEqual(out[str(self.fifo)]["note"], "not_regular_file")
                self.assertIsNone(out[str(self.fifo)]["hash"])
                self.assertTrue(out[str(self.reg)]["hash"].startswith("sha256:"), "the file beside it is still read")

    def test_the_guard_checksum(self):
        agent = load_agent("rp_fifo_guard", AGENTS["linux"])
        with within(10, "_guard_sha"):
            self.assertEqual(agent._guard_sha(str(self.fifo)), "")
        self.assertNotEqual(agent._guard_sha(str(self.reg)), "")

    def test_the_threat_log_tail(self):
        agent = load_agent("rp_fifo_threat", AGENTS["linux"])
        with within(10, "_ts_read_log"):
            lines, state, why = agent._ts_read_log(str(self.fifo), {}, audit=False)
        self.assertEqual((lines, why), ([], "unsupported"))

    def test_the_file_hash_check(self):
        agent = load_agent("rp_fifo_check", AGENTS["linux"])
        check = {"id": "c1", "type": "file_hash", "param": str(self.fifo)}
        with within(10, "the file_hash check"):
            status, detail = agent._eval_one_agent_check(check)[:2]
        self.assertEqual(status, "unknown", detail)

    def test_the_loader_check_over_a_tree_with_a_fifo_in_it(self):
        """No race here: a FIFO simply left in the tree. The check must read the loader beside it."""
        agent = load_agent("rp_fifo_loader", AGENTS["linux"])
        (self.tmp / "shell.php").write_text("<?php eval($_POST['x']); ?>")
        os.mkfifo(self.tmp / "planted.php")
        check = {"id": "c2", "type": "file_contains", "param": f"{self.tmp}::*.php", "pattern": r"eval\("}
        with within(15, "the loader check"):
            status, detail = agent._eval_one_agent_check(check)[:2]
        self.assertEqual(status, "critical", detail)
        self.assertIn("shell.php", detail)
        self.assertNotIn("planted.php", detail)


@unittest.skipUnless(HAVE_FIFO, "needs mkfifo and SIGALRM")
class TestTheStateFilesTrustOnlyTheirOwn(unittest.TestCase):
    """The agent looks for a state file in /tmp when STATE_DIR does not have it, and a poll interval
    is read there on every pass of its loop. /tmp is where any local user can leave things for a root
    process to find. A FIFO named /tmp/remotepower-poll-interval stopped the agent for good (found by
    running it: `mkfifo` was the whole attack), and a file of the user's own making was trusted: an
    interval of ten million seconds, a baseline, a scan time, a stashed command result."""

    def setUp(self):
        import secrets
        self.agent = load_agent("rp_state_files", AGENTS["linux"])
        self.state = Path(tempfile.mkdtemp(prefix="rp-v742-state-"))
        self.addCleanup(__import__("shutil").rmtree, str(self.state), True)
        self.agent.STATE_DIR = self.state                 # empty: the file is not there yet
        self.name = "rp-test-" + secrets.token_hex(6)
        self.tmp_file = Path("/tmp/remotepower-" + self.name)
        self.addCleanup(lambda: self.tmp_file.unlink() if os.path.lexists(self.tmp_file) else None)

    def plant(self, text="25", mode=0o600):
        fd = os.open(self.tmp_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        os.write(fd, text.encode())
        os.close(fd)
        os.chmod(self.tmp_file, mode)                     # the umask may have trimmed it

    def readers(self):
        yield "small", lambda: self.agent._safe_state_read(self.name)
        yield "big", lambda: self.agent._safe_state_read_big(self.name)

    def test_a_fifo_in_tmp_does_not_stop_the_read(self):
        os.mkfifo(self.tmp_file)
        for label, read in self.readers():
            with self.subTest(reader=label):
                with within(5, f"the {label} state read on a FIFO in /tmp"):
                    self.assertIsNone(read())

    def test_the_agents_own_file_is_read(self):
        self.plant("25")
        for label, read in self.readers():
            with self.subTest(reader=label):
                self.assertEqual(read(), "25")

    def test_the_state_directory_copy_is_read_first(self):
        (self.state / self.name).write_text("30")
        os.chmod(self.state / self.name, 0o600)
        self.plant("999")
        self.assertEqual(self.agent._safe_state_read(self.name), "30")

    def test_a_file_owned_by_someone_else_is_ignored(self):
        self.plant("10000000")
        with mock.patch.object(os, "geteuid", lambda: os.getuid() + 1):
            for label, read in self.readers():
                with self.subTest(reader=label):
                    self.assertIsNone(read())

    def test_a_file_anyone_can_write_is_ignored(self):
        for mode in (0o666, 0o662, 0o620):
            with self.subTest(mode=oct(mode)):
                if os.path.lexists(self.tmp_file):
                    self.tmp_file.unlink()
                self.plant("1", mode)
                self.assertIsNone(self.agent._safe_state_read(self.name))
        self.tmp_file.unlink()
        self.plant("25", 0o644)                            # readable by others is fine, as before
        self.assertEqual(self.agent._safe_state_read(self.name), "25")

    def test_a_link_is_still_refused(self):
        target = self.state / "elsewhere"
        target.write_text("25")
        os.symlink(target, self.tmp_file)
        self.assertIsNone(self.agent._safe_state_read(self.name))

    def test_no_state_candidate_is_opened_without_the_check(self):
        """The ratchet over the class: the three readers of the /tmp candidate share one helper, and the
        old idiom (open the candidate for reading, no look at what it is) is gone."""
        src = AGENTS["linux"].read_text(encoding="utf-8")
        self.assertNotIn("os.open(str(cand), os.O_RDONLY | os.O_NOFOLLOW)", src)
        self.assertEqual(src.count("fd = _open_state_file(cand)"), 3)


class TestNoOtherReadOpensAPathWithAPlainOpen(unittest.TestCase):
    """The ratchet over the class. Every open(<path>, 'rb') in an agent is either `_open_regular` or
    listed here with the reason nobody but root can reach it. A new one fails until it is one or the
    other, and an entry that no longer matches fails too, so the list can only shrink."""

    ALLOWED = {
        "linux": {
            "_attach_report_html": "the report file lynis or oscap just wrote, in a root-owned directory",
            "_parse_oscap_results": "the file oscap just wrote, in a root-owned directory",
            "_verify_restored_tree": "the restore drill's own scratch tree, which the agent has just made",
            "get_metrics": "a sysfs power-supply attribute",
            "_handle_file_archive": "the archive the agent has just written in its own scratch directory",
            "_safe_read_tail": "fixed system logs (antivirus, rkhunter, auth) under root-owned /var/log",
        },
        "windows": {
            "self_sha256": "the agent's own file",
            "_handle_file_op_win": "a file the admin asked for by name in the file manager, on a platform with no FIFOs in a directory tree",
        },
        "macos": {
            "self_sha256": "the agent's own file",
        },
    }

    def test_every_plain_open_is_listed(self):
        for key, path in AGENTS.items():
            with self.subTest(agent=key):
                sites = {fn for fn, _ in plain_binary_opens(path.read_text(encoding="utf-8"))}
                self.assertEqual(sites - set(self.ALLOWED[key]), set(),
                                 "these open a path for binary reading with a plain open(): use _open_regular, "
                                 "or list the function here with the reason it cannot be reached")

    def test_no_entry_is_stale(self):
        for key, path in AGENTS.items():
            with self.subTest(agent=key):
                sites = {fn for fn, _ in plain_binary_opens(path.read_text(encoding="utf-8"))}
                self.assertEqual(set(self.ALLOWED[key]) - sites, set(),
                                 "listed but no longer a plain open(): remove it from ALLOWED")

    def test_the_population_was_found(self):
        """The control on the scan itself: it must see the opens it exists to police."""
        sites = plain_binary_opens(AGENTS["linux"].read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(sites), 5)

    def test_the_ratchet_can_fail(self):
        src = "def collect_new_thing(p):\n    with open(p, 'rb') as fh:\n        return fh.read()\n"
        self.assertEqual(plain_binary_opens(src), [("collect_new_thing", "p")])
        src2 = "def ok(p):\n    fh = _open_regular(p)\n    return fh\n"
        self.assertEqual(plain_binary_opens(src2), [])


if __name__ == "__main__":
    unittest.main()
