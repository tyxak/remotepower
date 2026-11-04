#!/usr/bin/env python3
"""7.5.0 agent review (NF-6): the Docker entrypoint does not write through a symbolic link in the data volume.

The entrypoint runs as root and writes config.json, users.json, satellites.json and the scanner token into the data volume, which
belongs to the app account. That account can leave a link where one of those files goes, and Python's write_text() follows it: the
JSON lands in whatever the link points at (a file of the attacker's choosing inside the container, so a denial of service rather than
code). Every read and write now goes through two functions that open the last path component with O_NOFOLLOW and stop with a message.

The functions are lifted out of the shipped script and run for real, and so is the shell wrapper that feeds them to python3.
"""
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENTRY = Path(os.environ.get("RP_TEST_ENTRYPOINT") or ROOT / "docker" / "entrypoint.sh")
SRC = ENTRY.read_text()


def prelude():
    m = re.search(r"^RP_SAFE_IO='(.*?)'\n", SRC, re.S | re.M)
    assert m, "RP_SAFE_IO not found in the entrypoint"
    return m.group(1)


def wrapper():
    m = re.search(r"^rp_py\(\) \{.*\}$", SRC, re.M)
    assert m, "rp_py not found in the entrypoint"
    return m.group(0)


class TestTheFunctions(unittest.TestCase):

    def setUp(self):
        self.td = Path(tempfile.mkdtemp(prefix="rp-v750-ep-"))
        self.addCleanup(shutil.rmtree, self.td, True)
        self.ns = {}
        exec(compile(prelude(), "RP_SAFE_IO", "exec"), self.ns)

    def test_a_missing_file_reads_as_none_and_a_regular_one_as_its_text(self):
        self.assertIsNone(self.ns["safe_read"](str(self.td / "none.json")))
        (self.td / "a.json").write_text("{}")
        self.assertEqual(self.ns["safe_read"](str(self.td / "a.json")), "{}")

    def test_write_creates_with_the_mode_and_replaces_the_text(self):
        p = self.td / "tok"
        self.ns["safe_write"](str(p), "secret", 0o600)
        self.assertEqual(p.read_text(), "secret")
        self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
        self.ns["safe_write"](str(p), "x")
        self.assertEqual(p.read_text(), "x")

    def test_write_refuses_a_link_and_leaves_its_target_alone(self):
        target = self.td / "victim"
        target.write_text("keep me")
        link = self.td / "config.json"
        link.symlink_to(target)
        with self.assertRaises(SystemExit) as cm:
            self.ns["safe_write"](str(link), "{}")
        self.assertIn("link", str(cm.exception))
        self.assertIn(str(link), str(cm.exception))
        self.assertEqual(target.read_text(), "keep me")

    def test_read_refuses_a_link_too(self):
        target = self.td / "victim"
        target.write_text('{"a": 1}')
        link = self.td / "satellites.json"
        link.symlink_to(target)
        with self.assertRaises(SystemExit):
            self.ns["safe_read"](str(link))

    def test_a_dangling_link_is_refused_not_created_through(self):
        link = self.td / "users.json"
        link.symlink_to(self.td / "does-not-exist")
        with self.assertRaises(SystemExit):
            self.ns["safe_write"](str(link), "{}")
        self.assertFalse((self.td / "does-not-exist").exists(), "the write must not create the link's target")

    def test_a_directory_in_the_way_is_refused_with_a_message(self):
        (self.td / "d").mkdir()
        with self.assertRaises(SystemExit):
            self.ns["safe_write"](str(self.td / "d"), "x")


@unittest.skipUnless(shutil.which("bash") and shutil.which("python3"), "needs bash and python3")
class TestTheWrapper(unittest.TestCase):
    """The shell function as the entrypoint uses it: a heredoc after `rp_py`, with variables set on the same line."""

    def setUp(self):
        self.td = Path(tempfile.mkdtemp(prefix="rp-v750-epw-"))
        self.addCleanup(shutil.rmtree, self.td, True)

    def sh(self, body):
        script = self.td / "t.sh"
        script.write_text("RP_SAFE_IO='" + prelude() + "'\n" + wrapper() + "\n" + body)
        return subprocess.run(["bash", str(script)], capture_output=True, text=True, timeout=60, env={**os.environ, "PATH": os.environ["PATH"]})

    def test_the_heredoc_gets_the_functions_and_the_environment(self):
        out = self.td / "out.json"
        r = self.sh(f"""FOO=bar OUT='{out}' rp_py <<'PYEOF'
import os
safe_write(os.environ['OUT'], '{{"foo": "' + os.environ['FOO'] + '"}}')
PYEOF
""")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(out.read_text(), '{"foo": "bar"}')

    def test_a_link_stops_the_script_before_anything_is_written(self):
        victim = self.td / "victim"
        victim.write_text("keep me")
        (self.td / "config.json").symlink_to(victim)
        r = self.sh(f"""set -e
rp_py <<'PYEOF'
safe_write('{self.td}/config.json', '{{}}')
PYEOF
echo not-reached
""")
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("not-reached", r.stdout)
        self.assertIn("cannot be written without following a link", r.stderr)
        self.assertEqual(victim.read_text(), "keep me")


class TestNoWriteBypassesTheFunctions(unittest.TestCase):

    def test_the_entrypoint_has_no_plain_write_of_a_volume_file(self):
        self.assertNotIn(".write_text(", SRC)
        # The two heredocs that still call python3 directly talk to Postgres (a read of the bootstrap users, and the migration through
        # the app's own code); neither writes a file. A third one would be a new writer that skipped the functions.
        direct = re.findall(r"python3 - <<'PYEOF'\n(.*?)\nPYEOF", SRC, re.S)
        self.assertEqual(len(direct), 2, "a python heredoc that does not go through rp_py: check what it writes")
        for body in direct:
            self.assertIn("storage_pg", body + "_migrate_storage_pg")
            self.assertNotRegex(body, r"write_text|open\(|\.write\(")
        self.assertEqual(len(re.findall(r"rp_py <<'PYEOF'", SRC)), 3)

    def test_the_volume_paths_are_written_through_safe_write(self):
        self.assertGreaterEqual(SRC.count("safe_write("), 5)          # the definition and its uses: config, users, sats, token
        for needle in ("safe_write(cfg_path", "safe_write(path, json.dumps(users", "safe_write(sats_path",
                       "safe_write(os.path.join(data_dir, '.scanner-token'), token, 0o600)"):     # the secret is created 0600, not chmod-ed later
            self.assertIn(needle, SRC)

    def test_the_script_is_valid_shell(self):
        r = subprocess.run(["bash", "-n", str(ENTRY)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
