"""v6.1.3 — server-side support for the Windows agent parity buildout.

Covers the pieces that live in api.py rather than the agent:
  * the Windows agent self-update endpoints (version / download / signature)
  * OS-aware service-name validation (Windows names allow spaces/parens; the
    systemd regex would reject legitimate services)
  * the endpoints are auth-exempt like their Linux siblings (the agent polls
    them token-free during self-update)
"""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_CGI = Path(__file__).resolve().parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))


def _fresh_api():
    d = tempfile.mkdtemp(prefix="rp-v613-winsrv-")
    os.environ["RP_DATA_DIR"] = d
    spec = importlib.util.spec_from_file_location("api_v613_winsrv", _CGI / "api.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestServiceValidationIsOsAware(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = _fresh_api()

    def test_windows_service_names_with_spaces_and_parens_pass(self):
        win = {"os": "Windows 11 (Build 22631)"}
        for name in ("wuauserv", "MSSQL$SQLEXPRESS", "W3SVC",
                     "Windows Update", "SQL Server (MSSQLSERVER)"):
            self.assertTrue(self.api._valid_service_unit_for(name, win), name)

    def test_windows_rejects_shell_metacharacters(self):
        win = {"os": "Windows Server 2022"}
        # `;` `|` `&` backtick `>` `<` quotes are excluded. `$` and `()` are NOT —
        # they are needed for real names (MSSQL$INSTANCE, "SQL Server (X)") and are
        # harmless because the agent passes the name as a single-quoted PowerShell
        # literal (no interpolation), so `$(x)` is inert even though it validates.
        for bad in ("a;rm -rf", "a|b", "a&b", "a`b`", "a>b", "a<b", 'a"b', "a'b"):
            self.assertFalse(self.api._valid_service_unit_for(bad, win), bad)

    def test_linux_still_uses_the_systemd_validator(self):
        lin = {"os": "Ubuntu 22.04"}
        self.assertTrue(self.api._valid_service_unit_for("nginx.service", lin))
        # A space is legal in a Windows name but NOT a systemd unit.
        self.assertFalse(self.api._valid_service_unit_for("Windows Update", lin))


class TestWinAgentUpdateEndpoints(unittest.TestCase):
    def setUp(self):
        self.api = _fresh_api()
        self.captured = {}

        def _respond(status, data=None):
            self.captured = {"status": status, "data": data}
            raise self.api.HTTPError(status, data)

        self.api.respond = _respond
        self.api.require_auth = lambda *a, **k: "agent"

    def _call(self, fn):
        self.captured = {}
        try:
            fn()
        except self.api.HTTPError:
            pass
        return self.captured

    def test_version_returns_nulls_when_no_windows_agent_published(self):
        # A server that only ships Linux must not error the Windows agent's poll —
        # it just never updates.
        r = self._call(self.api.handle_win_agent_version)
        self.assertEqual(r["status"], 200)
        self.assertIsNone(r["data"]["sha256"])

    def test_version_advertises_sha_when_published(self):
        # Point the served-agent path at a temp file (the default /var/www path
        # isn't writable in the test env).
        tmp = Path(tempfile.mkdtemp()) / "remotepower-agent-win.py"
        tmp.write_text("VERSION = '6.1.3'\nprint('hi')\n")
        orig = self.api._AGENT_WIN_PATH
        self.api._AGENT_WIN_PATH = tmp
        try:
            r = self._call(self.api.handle_win_agent_version)
            self.assertEqual(r["status"], 200)
            self.assertTrue(r["data"]["sha256"])          # a real hash
            self.assertEqual(r["data"]["version"], "6.1.3")
        finally:
            self.api._AGENT_WIN_PATH = orig

    def test_signature_404s_when_unsigned(self):
        r = self._call(self.api.handle_win_agent_signature)
        self.assertEqual(r["status"], 404)

    def test_the_update_endpoints_are_auth_exempt_like_linux(self):
        # The agent polls these token-free during self-update, exactly like
        # /api/agent/version. Both must be in the IP-allowlist exempt set.
        exempt = self.api._IP_ALLOWLIST_EXEMPT_PATHS
        self.assertIn("/api/agent/win/version", exempt)
        self.assertIn("/api/agent/win/download", exempt)
        self.assertIn("/api/agent/version", exempt)       # sanity: the sibling


class TestWinUpgradeCommandRouting(unittest.TestCase):
    """The class that started all this: a Windows host must never be sent a bash
    upgrade script (fixed in the prior commit; re-assert it still holds)."""

    @classmethod
    def setUpClass(cls):
        cls.api = _fresh_api()

    def test_windows_gets_the_bare_upgrade_verb_not_a_bash_script(self):
        cmd = self.api._upgrade_command_for({"os": "Windows 11"})
        self.assertEqual(cmd, "upgrade")
        self.assertNotIn("exec:", cmd)

    def test_linux_gets_the_exec_script(self):
        cmd = self.api._upgrade_command_for({"os": "Ubuntu 22.04"})
        self.assertTrue(cmd.startswith("exec:"))


class TestWindowsOneLineInstaller(unittest.TestCase):
    """The Windows onboarding one-liner (parity with the Linux /install)."""

    @classmethod
    def setUpClass(cls):
        cls.api = _fresh_api()

    def test_render_bakes_server_and_token(self):
        env = {"HTTP_HOST": "rp.example.com", "HTTP_X_FORWARDED_PROTO": "https",
               "QUERY_STRING": "t=abc123DEF"}
        ps = self.api._render_win_install(env)
        self.assertIn("https://rp.example.com", ps)
        self.assertIn("$Token  = 'abc123DEF'", ps)

    def test_token_is_sanitized(self):
        # A hostile token must not break out of the PS single-quoted literal or
        # inject a command.
        env = {"HTTP_HOST": "rp.example.com", "QUERY_STRING": "t=a;rm -rf/ '"}
        ps = self.api._render_win_install(env)
        line = [l for l in ps.splitlines() if l.startswith("$Token")][0]
        self.assertNotIn(";", line)
        self.assertNotIn("'", line.split("=", 1)[1].strip()[1:-1])  # inner value clean

    def test_download_is_from_the_server(self):
        env = {"HTTP_HOST": "rp.example.com", "QUERY_STRING": ""}
        ps = self.api._render_win_install(env)
        self.assertIn("/api/agent/win/download", ps)
        self.assertIn("/api/agent/win/version", ps)   # checksum source
        self.assertIn("Get-FileHash", ps)             # verifies before install

    def test_requires_elevation(self):
        ps = self.api._render_win_install({"HTTP_HOST": "h", "QUERY_STRING": ""})
        self.assertIn("Administrator", ps)

    def test_installs_python_if_missing(self):
        # A bare Windows box (no Python) must not dead-end the one-liner — the
        # installer installs Python (winget, else the official silent installer).
        ps = self.api._render_win_install({"HTTP_HOST": "h", "QUERY_STRING": ""})
        self.assertIn("Install-PythonIfMissing", ps)
        self.assertIn("Python.Python.3.12", ps)          # winget path
        self.assertIn("python.org/ftp/python", ps)       # fallback path

    def test_scheduled_task_uses_a_system_launchable_python(self):
        # REGRESSION: the installer used `(Get-Command pythonw).Source`, which on
        # a box whose only python is the Microsoft Store / App-Execution-Alias
        # resolves to C:\Users\<u>\AppData\Local\Microsoft\WindowsApps\pythonw.exe
        # — a PER-USER path the SYSTEM scheduled task cannot launch (fails at boot
        # with 0x80070780, agent never runs). The task must be registered from a
        # machine-wide python the SYSTEM account can reach.
        ps = self.api._render_win_install({"HTTP_HOST": "h", "QUERY_STRING": ""})
        # It resolves a machine python and rejects per-user / Store paths.
        self.assertIn("Get-MachinePython", ps)
        self.assertIn("Test-SystemUsablePython", ps)
        self.assertIn("WindowsApps", ps)                 # the alias is explicitly rejected
        self.assertIn("Users", ps)                       # any per-user profile rejected
        # It must NOT bake the PATH-resolved alias straight into the task action.
        self.assertNotIn("$pyw = Get-Command pythonw", ps)
        self.assertNotIn("(Get-Command pythonw).Source", ps)
        # The task action + pip + enroll all use the resolved machine interpreter.
        self.assertIn("$exe = $pythonw", ps)
        self.assertIn("New-ScheduledTaskAction -Execute $exe", ps)
        self.assertIn("& $python -m pip install", ps)    # psutil into the machine python
        self.assertIn("& $python $agent --enroll", ps)
        # And it refuses to register a SYSTEM task with a path SYSTEM can't launch.
        self.assertIn("Refusing to register the service", ps)

    def test_route_is_auth_exempt(self):
        self.assertIn("/api/agent/win/install", self.api._IP_ALLOWLIST_EXEMPT_PATHS)
        self.assertTrue(hasattr(self.api, "handle_win_install"))


if __name__ == "__main__":
    unittest.main()
