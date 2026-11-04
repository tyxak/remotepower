#!/usr/bin/env python3
"""7.5.0 agent review: the macOS and Windows installers keep the agent and its data where an ordinary user cannot get at them.

* macOS. The LaunchDaemon runs the agent as root from /usr/local/bin. On a clean Mac that directory is root's, but on an Intel Mac
  Homebrew hands it to the person who installed Homebrew, so anything running as that person could put a program of its own where the
  agent is and be root at the next start. When the directory can be written by anyone but root the agent is installed into
  /Library/PrivilegedHelperTools, which is where macOS keeps the programs a LaunchDaemon runs.
* Windows. %ProgramData%\\RemotePower was created with the ACL it inherits (every local user may create files in it) and restricted
  only when the agent first saved its credentials, after the CA, the agent file and pip had been through it. It is restricted
  right after it is created, with the same SIDs the agent uses.

Neither installer can run here (Darwin, Windows). The macOS decision is cut out of the script and run under bash with a stub `stat`
that speaks the BSD flags; the Windows script is parsed by PowerShell's own parser when pwsh is there, and the order of its steps is
read from the source. RP_TEST_INSTALL_MACOS and RP_TEST_INSTALL_WINDOWS point the tests at another copy (the old files show them fail).
"""
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MACOS = Path(os.environ.get("RP_TEST_INSTALL_MACOS") or ROOT / "client" / "install-macos.sh")
WINDOWS = Path(os.environ.get("RP_TEST_INSTALL_WINDOWS") or ROOT / "client" / "install-windows.ps1")

PRIV = "/Library/PrivilegedHelperTools"


def decision_of(text):
    """The two functions that decide, cut out of the script."""
    m = re.search(r"^dir_is_roots\(\) \{.*?^AGENT_DIR=\"\$\(pick_agent_dir\)\"$", text, re.S | re.M)
    return m.group(0) if m else ""


class TestMacOsAgentDirectory(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory(prefix="rp-v750-mac-")
        self.addCleanup(self._td.cleanup)
        self.root = Path(self._td.name)
        self.text = MACOS.read_text()
        self.block = decision_of(self.text)

    def pick(self, bin_dir=None, local=None):
        """bin_dir, local: None (absent) or (owner uid, mode) for the fake /usr/local/bin and /usr/local."""
        base = self.root / "usr" / "local"
        for p in (base, base / "bin"):
            if p.exists():
                p.rmdir() if p.name == "bin" else None
        stat_table = []
        if local is not None:
            base.mkdir(parents=True, exist_ok=True)
            stat_table.append(f"{base}={local[0]}:{local[1]}")
        if bin_dir is not None:
            (base / "bin").mkdir(parents=True, exist_ok=True)
            stat_table.append(f"{base / 'bin'}={bin_dir[0]}:{bin_dir[1]}")
        block = self.block.replace("/usr/local", str(base)).replace(PRIV, "PRIV")
        script = f"""
stat() {{   # the BSD form the installer uses: stat -f FORMAT PATH
  local want="$3" entry
  for entry in {' '.join(repr(s) for s in stat_table) or "''"}; do
    if [ "${{entry%%=*}}" = "$want" ]; then
      case "$2" in %u) echo "${{entry#*=}}" | cut -d: -f1 ;; %Lp) echo "${{entry#*=}}" | cut -d: -f2 ;; esac
      return 0
    fi
  done
  return 1
}}
warn() {{ :; }}
{block}
echo "$AGENT_DIR"
"""
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = r.stdout.strip()
        return "PRIV" if out == "PRIV" else out.replace(str(base), "/usr/local")

    def test_the_decision_was_found_in_the_script(self):
        self.assertIn("pick_agent_dir", self.block, "the installer has no rule for where the agent goes")

    def test_a_directory_that_is_roots_alone_is_used(self):
        self.assertEqual(self.pick(bin_dir=(0, 755), local=(0, 755)), "/usr/local/bin")

    def test_a_directory_owned_by_the_homebrew_user_is_not(self):
        self.assertEqual(self.pick(bin_dir=(501, 755), local=(0, 755)), "PRIV")

    def test_a_directory_the_group_or_others_can_write_is_not(self):
        for mode in (775, 777, 757, 1777):
            with self.subTest(mode=mode):
                self.assertEqual(self.pick(bin_dir=(0, mode), local=(0, 755)), "PRIV")

    def test_a_directory_that_is_not_there_yet_is_made_as_roots_when_its_parent_is_roots(self):
        self.assertEqual(self.pick(bin_dir=None, local=(0, 755)), "/usr/local/bin")

    def test_a_directory_that_would_be_made_inside_a_users_directory_is_not(self):
        self.assertEqual(self.pick(bin_dir=None, local=(501, 755)), "PRIV")

    def test_nothing_at_all_is_a_clean_system(self):
        self.assertEqual(self.pick(bin_dir=None, local=None), "/usr/local/bin")

    def test_the_agent_the_plist_and_the_help_text_all_use_the_chosen_path(self):
        rest = self.text.split('AGENT_BIN="$AGENT_DIR/remotepower-agent-mac"', 1)[-1]
        # the one place the old fixed path may still be named: the removal of a copy an earlier install left there
        literal = [ln.strip() for ln in rest.splitlines()
                   if "/usr/local/bin/remotepower-agent-mac" in ln and "rm -f" not in ln and "-f /usr/local/bin" not in ln]
        self.assertEqual(literal, [], "the installer still names the fixed path in these places")
        self.assertGreaterEqual(rest.count("$AGENT_BIN"), 4)

    @unittest.skipUnless(shutil.which("shellcheck"), "shellcheck not installed")
    def test_shellcheck_is_clean(self):
        r = subprocess.run(["shellcheck", "-S", "style", str(MACOS)], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout)


class TestWindowsDataFolderIsRestrictedFirst(unittest.TestCase):
    def setUp(self):
        self.text = WINDOWS.read_text()

    def test_icacls_restricts_the_data_folder_before_anything_is_put_into_it(self):
        i = self.text.find("icacls.exe")
        self.assertGreater(i, 0, "the installer never restricts the data folder itself")
        line = self.text[self.text.rfind("\n", 0, i) + 1:self.text.find("\n", i)]
        for sid in ("*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "/inheritance:r"):
            self.assertIn(sid, line)
        self.assertIn("$dataDir", line)
        # the first things written into the data folder: the CA file, the agent's checksum download, the enrolment itself
        for later in ("$caPath", "Copy-Item $src $agent", "Invoke-WebRequest -Uri $Ca", "--enroll"):
            j = self.text.find(later)
            self.assertGreater(j, 0, f"{later!r} is not in the installer: the test measures nothing")
            self.assertLess(i, j, f"the data folder is restricted after {later!r}")

    def test_it_comes_right_after_the_folder_is_created(self):
        made = self.text.find("New-Item -ItemType Directory -Force -Path $installDir, $dataDir")
        i = self.text.find("icacls.exe")
        self.assertTrue(0 < made < i)
        self.assertNotIn("Install-PythonIfMissing\n", self.text[made:i])

    @unittest.skipUnless(shutil.which("pwsh"), "pwsh not installed")
    def test_the_script_still_parses(self):
        cmd = ("$e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]::ParseFile($env:RP_PS_FILE,[ref]$t,[ref]$e);"
               "if($e.Count){$e|ForEach-Object{$_.Message};exit 1}")
        r = subprocess.run(["pwsh", "-NoProfile", "-Command", cmd], capture_output=True, text=True, timeout=120,
                           env=dict(os.environ, RP_PS_FILE=str(WINDOWS)))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
