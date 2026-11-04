#!/usr/bin/env python3
"""7.5.0 agent review: a self-update on a disk that fills up does not leave the host without an agent.

check_for_update() compared the downloaded bytes with the advertised sha256 in memory and then wrote them with one os.write(). That
call does not loop: on a file system that fills up it writes what fits and returns that count, and only the next call fails. The count
was ignored, so the first part of the agent was moved over the running one and a restart was asked for. Measured on a 300 KB file
system: a 768,041-byte agent became a 303,104-byte file, check_for_update() returned True, and the host had an agent that does not
start (systemd retries every 30 seconds, for ever). The update is something the agent does on a host that has just run out of room,
which is when it matters most. All of the bytes are written now, the system is asked to store them, and they are read back and
checked before anything is replaced; a failure removes the temporary file and keeps the old agent.

The same went for the other places that write with a bare os.write(): the file manager's write and upload (a configuration file stored
cut short and reported as written), a custom script (its first part would have run as root), the credentials, the state files and the
canary decoys. They go through `_write_all` now.

The Windows and macOS agents write with a buffered file object, which raises when the disk fills, so they never installed a
truncated file; they did leave the half-written `.rp-new` beside the agent, on a disk that was already short of room, and remove it now.

RP_TEST_AGENT, RP_TEST_WIN_AGENT and RP_TEST_MAC_AGENT point the tests at another copy (a `git show HEAD:` of the old file shows them fail).
"""
import errno
import hashlib
import importlib.machinery
import importlib.util
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-data-"))

ROOT = Path(__file__).resolve().parent.parent
AGENT = Path(os.environ.get("RP_TEST_AGENT") or ROOT / "client" / "remotepower-agent.py")
WIN = Path(os.environ.get("RP_TEST_WIN_AGENT") or ROOT / "client" / "remotepower-agent-win.py")
MAC = Path(os.environ.get("RP_TEST_MAC_AGENT") or ROOT / "client" / "remotepower-agent-mac.py")


def load_agent(name="agent_v750_update"):
    loader = importlib.machinery.SourceFileLoader(name, str(AGENT))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


agent = load_agent()

NEW = b"#!/usr/bin/env python3\nVERSION = '9.9.9'\n" + b"# a line of the new agent\n" * 30000      # about 800 KB
OLD = b"#!/usr/bin/env python3\nVERSION = '7.4.9'\nprint('old agent')\n"
SHA = hashlib.sha256(NEW).hexdigest()


class TestSelfUpdateOnAFillingDisk(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory(prefix="rp-v750-upd-")
        self.addCleanup(self._td.cleanup)
        self.dir = Path(self._td.name)
        self.binary = self.dir / "remotepower-agent"
        self.binary.write_bytes(OLD)
        self.restarts = []
        for target, value in (
                ("AGENT_BINARY", self.binary), ("IN_CONTAINER", False), ("_audit_mode", lambda: False),
                ("_release_pubkey", lambda: None), ("_require_signed_updates", lambda: False),
                ("http_get", lambda url, timeout=10: {"sha256": SHA, "version": "9.9.9"}),
                ("http_get_binary", lambda url, timeout=30: NEW)):
            p = mock.patch.object(agent, target, value)
            p.start()
            self.addCleanup(p.stop)
        p = mock.patch.object(agent.subprocess, "Popen", lambda *a, **k: self.restarts.append(a[0]))
        p.start()
        self.addCleanup(p.stop)

    def update(self, write=None):
        """Run the update; `write` replaces os.write for the big write only."""
        real = os.write
        if write is None:
            return agent.check_for_update("https://rp.example")

        def fake(fd, buf):
            if len(buf) > 100_000:
                return write(real, fd, buf)
            return real(fd, buf)
        with mock.patch.object(os, "write", fake):
            return agent.check_for_update("https://rp.example")

    def assertOldAgentKept(self):
        self.assertEqual(self.binary.read_bytes(), OLD, "the running agent was replaced")
        self.assertEqual(self.restarts, [], "a restart was asked for")
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ["remotepower-agent"], "a temporary file was left behind")

    def test_control_with_room_enough_the_new_agent_is_installed(self):
        self.assertTrue(self.update())
        self.assertEqual(self.binary.read_bytes(), NEW)
        self.assertEqual(stat.S_IMODE(self.binary.stat().st_mode), 0o755)
        self.assertEqual(len(self.restarts), 1)
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ["remotepower-agent"])

    def test_a_disk_that_fills_up_halfway_keeps_the_old_agent(self):
        # the first call is short; the loop that finishes the job meets ENOSPC on the next one
        calls = {"n": 0}

        def write(real, fd, buf):
            calls["n"] += 1
            if calls["n"] == 1:
                return real(fd, bytes(buf)[: len(buf) // 3])
            raise OSError(errno.ENOSPC, "No space left on device")
        self.assertFalse(self.update(write))
        self.assertOldAgentKept()

    def test_a_write_that_claims_all_but_stores_half_is_caught_by_reading_it_back(self):
        def lies(real, fd, buf):
            real(fd, bytes(buf)[: len(buf) // 2])
            return len(buf)                                     # delayed allocation, a failing disk: the count says everything
        self.assertFalse(self.update(lies))
        self.assertOldAgentKept()

    def test_a_short_write_that_is_followed_by_room_is_finished(self):
        calls = {"n": 0}

        def stutters(real, fd, buf):
            calls["n"] += 1
            return real(fd, bytes(buf)[:4096]) if calls["n"] < 500 else real(fd, buf)       # write(2) may return less, any time
        self.assertTrue(self.update(stutters))
        self.assertEqual(self.binary.read_bytes(), NEW)


class _ShortThenFull:
    """os.write that stores a third of a big buffer and reports that, then fails with ENOSPC, as a disk that fills up does."""

    def __init__(self, real, threshold=2000):
        self.real, self.threshold, self.n = real, threshold, 0

    def __call__(self, fd, buf):
        if len(buf) <= self.threshold:
            return self.real(fd, buf)
        self.n += 1
        if self.n == 1:
            return self.real(fd, bytes(buf)[: len(buf) // 3])
        raise OSError(errno.ENOSPC, "No space left on device")


class TestOtherWritesAreWholeToo(unittest.TestCase):
    BIG = "line of a configuration file\n" * 400                  # 12 KB

    def setUp(self):
        self._td = tempfile.TemporaryDirectory(prefix="rp-v750-wr-")
        self.addCleanup(self._td.cleanup)
        self.dir = Path(self._td.name).resolve()
        for target, value in (("_audit_mode", lambda: False), ("host_path", lambda p: p), ("unhost_path", lambda p: p),
                              ("_file_mgr_allowed", lambda p: True)):
            p = mock.patch.object(agent, target, value)
            p.start()
            self.addCleanup(p.stop)

    def files_op(self, op, path, payload):
        import base64
        b64 = lambda b: base64.urlsafe_b64encode(b).decode()          # noqa: E731
        cmd = "files:%s:%s:%s" % (op, b64(str(path).encode()), b64(payload))
        if op == "upload":
            cmd += ":1"
        with mock.patch.object(os, "write", _ShortThenFull(os.write)):
            return agent._handle_file_op(cmd)

    def test_a_file_written_through_the_manager_is_not_stored_cut_short(self):
        target = self.dir / "app.conf"
        target.write_text("old\n")
        out = self.files_op("write", target, self.BIG.encode())
        self.assertEqual(out["rc"], 1, out)
        self.assertEqual(target.read_text(), "old\n", "the file was replaced by a part of the new content")
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ["app.conf"], "a temporary file was left behind")

    def test_an_upload_is_not_stored_cut_short_either(self):
        target = self.dir / "blob.bin"
        target.write_bytes(b"old")
        out = self.files_op("upload", target, self.BIG.encode())
        self.assertEqual(out["rc"], 1, out)
        self.assertEqual(target.read_bytes(), b"old")
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ["blob.bin"])

    def test_a_custom_script_cut_short_is_not_run(self):
        ran = []
        with mock.patch.object(os, "write", _ShortThenFull(os.write)), \
                mock.patch.object(agent.subprocess, "run", lambda *a, **k: ran.append(a) or mock.Mock(returncode=0, stdout=b"")):
            res = agent.run_custom_scripts([{"id": "s1", "name": "cleanup", "body": "#!/bin/bash\n" + "echo step\n" * 400}])
        self.assertEqual(ran, [], "the first part of a script that did not fit on disk was run")
        self.assertFalse(res["s1"]["ok"])

    def test_credentials_that_do_not_fit_are_an_error_and_not_a_short_file(self):
        creds = self.dir / "credentials"
        with mock.patch.object(agent, "CREDS_FILE", creds), mock.patch.object(agent, "CONF_DIR", self.dir), \
                mock.patch.object(os, "write", _ShortThenFull(os.write, threshold=50)):
            with self.assertRaises(OSError):
                agent.save_credentials({"server_url": "https://rp.example", "device_id": "d", "token": "t" * 400})

    def test_control_everything_fits(self):
        import base64
        target = self.dir / "ok.conf"
        b64 = lambda b: base64.urlsafe_b64encode(b).decode()          # noqa: E731
        out = agent._handle_file_op("files:write:%s:%s" % (b64(str(target).encode()), b64(self.BIG.encode())))
        self.assertEqual(out["rc"], 0, out)
        self.assertEqual(target.read_text(), self.BIG)


class TestWindowsAndMacosLeaveNothingBehind(unittest.TestCase):
    """The agent file is the module's own __file__, so a copy of the module in a scratch directory is what gets 'updated'."""

    def run_update(self, which, src):
        td = tempfile.TemporaryDirectory(prefix="rp-v750-mw-")
        self.addCleanup(td.cleanup)
        copy = Path(td.name) / src.name
        copy.write_bytes(src.read_bytes())
        loader = importlib.machinery.SourceFileLoader("agent_v750_upd_" + which, str(copy))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)
        real_open = open

        class FullDisk:
            def __init__(self, fh):
                self.fh = fh

            def __enter__(self):
                return self

            def __exit__(self, *a):
                self.fh.close()

            def write(self, data):
                self.fh.write(data[: len(data) // 3])
                raise OSError(errno.ENOSPC, "No space left on device")

        def fake_open(path, mode="r", *a, **k):
            fh = real_open(path, mode, *a, **k)
            return FullDisk(fh) if str(path).endswith(".rp-new") else fh
        common = [mock.patch.object(mod, "_audit_mode", lambda: False),
                  mock.patch.object(mod, "load_creds", lambda: {"server_url": "https://rp.example"}),
                  mock.patch.object(mod, "self_sha256", lambda: "0" * 64)]
        if which == "windows":
            common += [mock.patch.object(mod, "_http_get_json_win", lambda url, timeout=15: {"sha256": SHA, "version": "9.9.9"}),
                       mock.patch.object(mod, "_http_get_bytes_win", lambda url, timeout=60: NEW),
                       mock.patch.object(mod, "_release_pubkey_win", lambda: None),
                       mock.patch.object(mod, "_require_signed_updates_win", lambda: False)]
        else:
            common += [mock.patch.object(mod, "_http_get_json", lambda url, timeout=15: {"sha256": SHA, "version": "9.9.9"}),
                       mock.patch.object(mod, "_http_get_bytes", lambda url, timeout=90: NEW),
                       mock.patch.object(mod, "_release_pubkey_mac", lambda: None),
                       mock.patch.object(mod, "_require_signed_updates_mac", lambda: False)]
        for p in common:
            p.start()
        try:
            with mock.patch("builtins.open", fake_open):
                result = mod._self_update()
        finally:
            for p in reversed(common):
                p.stop()
        return result, copy, sorted(p.name for p in copy.parent.iterdir() if p.name != "__pycache__")

    def test_a_full_disk_is_reported_and_leaves_no_half_written_copy(self):
        for which, src in (("windows", WIN), ("macos", MAC)):
            with self.subTest(agent=which):
                result, copy, names = self.run_update(which, src)
                self.assertEqual(result["rc"], 1, result)
                self.assertIn("install write failed", result["output"])
                self.assertEqual(names, [src.name], f"left behind: {names}")


if __name__ == "__main__":
    unittest.main()
