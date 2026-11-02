#!/usr/bin/env python3
"""The macOS and Windows agents, the relay satellite and the Windows installers: the lower-severity items of the 7.4.9 agent review (U4 to U10).

* U4   the same downgrade check as the Linux agent in the macOS and Windows updaters (the version inside the signed bytes);
* U6   the Windows installers stopped when the agent's checksum could not be read (they went on without it), and check that the
       Python installer they run elevated carries the Python Software Foundation's signature;
* U7   the Windows agent ran the first `docker` on PATH as SYSTEM; only a program under Program Files or the Windows folder is used;
* U8   an operator's regex over the Event Log or the macOS log had no time limit;
* U9   the relay forwarded every `/api/*` path, so the whole administration API was reachable from the relay's address;
* U10 the macOS update mode (0o755, as the installer and the Linux agent set it).

The Windows and macOS code runs on Linux here as plain Python; PowerShell is not run (the scripts are read).
"""
import importlib.machinery
import importlib.util
import os
import re
import socket
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
CLIENT = ROOT / "client"


def load(path, name):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


win = load(CLIENT / "remotepower-agent-win.py", "agent_win_platforms")
mac = load(CLIENT / "remotepower-agent-mac.py", "agent_mac_platforms")
os.environ["RP_UPSTREAM"] = "http://127.0.0.1:1"
os.environ["RP_SATELLITE_TOKEN"] = "sat-token-for-the-test"
sat = load(CLIENT / "remotepower-satellite.py", "satellite_platforms")


class TestDowngradeCheckOnTheOtherAgents(unittest.TestCase):

    def test_the_helpers_agree_with_the_linux_agent(self):
        linux = load(CLIENT / "remotepower-agent.py", "agent_linux_platforms")
        cases = [("7.4.9", "7.4.2"), ("7.4.9", "7.4.9"), ("7.4.9", "7.5.0"), ("7.4.9", ""), ("7.4.9", "x.y")]
        for running, offered in cases:
            with self.subTest(running=running, offered=offered):
                want = linux._is_downgrade(running, offered)
                self.assertEqual(win._is_downgrade(running, offered), want)
                self.assertEqual(mac._is_downgrade(running, offered), want)
        data = b"#!/usr/bin/env python3\nVERSION = '7.4.2'\n"
        self.assertEqual(win._embedded_version(data), "7.4.2")
        self.assertEqual(mac._embedded_version(data), "7.4.2")

    def test_both_updaters_call_the_check_after_the_signature_and_name_the_override(self):
        for label, path, override in (("mac", CLIENT / "remotepower-agent-mac.py", "allow-downgrade"),
                                      ("windows", CLIENT / "remotepower-agent-win.py", "allow-downgrade")):
            text = path.read_text()
            body = text[text.index("def _self_update():"):]
            body = body[:body.index("\ndef ", 10)]
            with self.subTest(agent=label):
                self.assertLess(body.index("_verify_detached_sig"), body.index("_is_downgrade("), "the check comes after the signature")
                self.assertIn(override, body)
                self.assertLess(body.index("_is_downgrade("), body.index("self_path + '.rp-new'"), "and before anything is written")

    def test_the_macos_update_mode_is_the_one_the_installer_sets(self):
        text = (CLIENT / "remotepower-agent-mac.py").read_text()
        self.assertIn("os.chmod(tmp, 0o755)", text)
        self.assertNotIn("os.chmod(tmp, 0o700)", text)
        self.assertRegex((CLIENT / "install-macos.sh").read_text(), r"755")


class TestWindowsDockerLookup(unittest.TestCase):
    """U7"""

    def where(self, lines, roots):
        env = {"ProgramFiles": roots[0], "SystemRoot": roots[1]}
        run = mock.Mock(return_value=mock.Mock(stdout="\n".join(lines), returncode=0))
        with mock.patch.dict(os.environ, env, clear=False), \
                mock.patch.object(win.subprocess, "run", run), \
                mock.patch.object(win, "_system_bin", lambda n: n), \
                mock.patch.object(win.os.path, "exists", lambda p: True):
            return win._winshell_which("docker")

    def test_a_program_under_program_files_is_used(self):
        self.assertEqual(self.where(["/pf/Docker/bin/docker.exe"], ("/pf", "/win")), "/pf/Docker/bin/docker.exe")

    def test_a_program_in_a_folder_anyone_can_write_to_is_skipped_for_the_next_hit(self):
        got = self.where(["/Users/Public/tools/docker.exe", "/pf/Docker/bin/docker.exe"], ("/pf", "/win"))
        self.assertEqual(got, "/pf/Docker/bin/docker.exe")

    def test_only_an_unprotected_hit_means_no_docker(self):
        self.assertIsNone(self.where(["/Users/Public/tools/docker.exe"], ("/pf", "/win")))

    def test_a_folder_that_only_starts_with_the_same_letters_is_not_inside(self):
        self.assertIsNone(self.where(["/pf-evil/docker.exe"], ("/pf", "/win")))


class TestOperatorRegexBudgets(unittest.TestCase):
    """U8"""

    def test_the_mac_agent_interrupts_a_catastrophic_pattern(self):
        rx = re.compile(r"(a+)+$")
        line = "a" * 34 + "!"
        t0 = time.monotonic()
        # control: the pattern really is catastrophic on this interpreter (it would run for minutes)
        with self.assertRaises(mac._RegexBudgetExceeded):
            with mac._regex_budget(0.5):
                rx.search(line)
        self.assertLess(time.monotonic() - t0, 10)

    def test_the_mac_log_check_reports_a_slow_pattern_instead_of_hanging(self):
        out = mock.Mock(stdout=("a" * 34 + "!\n") * 3, returncode=0)
        with mock.patch.object(mac.subprocess, "run", return_value=out), mock.patch.object(mac, "LOG_ERRORS_BUDGET_S", 0.5):
            status, detail = mac._eval_one_agent_check_mac({"id": "c", "type": "log_errors", "param": r"(a+)+$"})[:2]
        self.assertEqual(status, "unknown")
        self.assertIn("too slow", detail)

    def test_the_windows_agent_refuses_the_nested_repetition_shape_and_keeps_ordinary_patterns(self):
        for bad in (r"(a+)+$", r"(x*)*", r"(.*a){9,}"):
            with self.subTest(pattern=bad):
                self.assertTrue(win._NESTED_REPETITION.search(bad))
        for ok in (r"error|fail", r"(Error|Failed) [0-9]+", r"^\d+(\.\d+)?$", r"(a+)"):
            with self.subTest(pattern=ok):
                self.assertFalse(win._NESTED_REPETITION.search(ok))


# Paths that appear in the agents' sources but are not calls the agent makes: prose about the admin API in a docstring, and the
# patterns the threat sensor looks for in other people's web traffic.
NOT_AGENT_CALLS = {"/api/enrollment-tokens", "/api/login", "/api/jsonws/invoke", "/api/"}


def agent_api_paths():
    found = set()
    for rel in ("client/remotepower-agent.py", "client/remotepower-agent-win.py", "client/remotepower-agent-mac.py",
                "install-client.sh", "client/install-macos.sh", "client/install-windows.ps1", "docker/agent-entrypoint.sh"):
        text = (ROOT / rel).read_text()
        for m in re.finditer(r"/api/[A-Za-z0-9_\-/{}.$]+", text):
            if m.group(0).count("{") != m.group(0).count("}"):
                continue                      # prose such as ".../mac/{version,download}", not a URL
            found.add(re.sub(r"\{[^}]*\}", "x", m.group(0)).rstrip("/."))
    return found - NOT_AGENT_CALLS


class TestTheRelayCarriesOnlyWhatAnAgentCalls(unittest.TestCase):
    """U9"""

    def test_every_path_an_agent_calls_is_relayed(self):
        found = agent_api_paths()
        self.assertGreater(len(found), 12, "the scan found almost no paths: the pattern no longer matches how the agents build URLs")
        missing = sorted(p for p in found if not sat.relayed(p))
        self.assertEqual(missing, [], "an agent calls a path the relay would refuse: add it to _AGENT_PATHS")

    def test_the_sign_in_and_the_administration_api_are_not(self):
        for p in ("/api/login", "/api/users", "/api/devices", "/api/devices/x/delete", "/api/config", "/api/tokens",
                  "/api/audit-log", "/api/heartbeat/x", "/api/exec", "/api/auth/oidc/start", "/api/"):
            with self.subTest(path=p):
                self.assertFalse(sat.relayed(p))

    def test_a_path_that_is_not_in_its_plain_form_is_not_relayed(self):
        for p in ("/api/heartbeat/../login", "/api/heartbeat//", "/api/%2e%2e/login", "/api/heartbeat/./x", "/api/heartbeat%2f..%2flogin",
                  "/api/devices/x/live-sample/../../login", "/api/devices/../users/live-sample"):
            with self.subTest(path=p):
                self.assertFalse(sat.relayed(p))

    def test_a_query_string_does_not_change_the_answer(self):
        self.assertTrue(sat.relayed("/api/heartbeat?x=1"))
        self.assertFalse(sat.relayed("/api/login?next=/api/heartbeat"))

    def test_the_per_host_uploads_are_matched_by_shape(self):
        self.assertTrue(sat.relayed("/api/devices/ng01/live-sample"))
        self.assertTrue(sat.relayed("/api/devices/abc-123_x/files/archive-chunk"))
        self.assertFalse(sat.relayed("/api/devices/ng01/files/archive-cancel"))
        self.assertFalse(sat.relayed("/api/devices/ng01"))

    def test_through_the_relay_an_agent_path_is_forwarded_and_the_login_is_answered_404(self):
        seen = []

        class Upstream(BaseHTTPRequestHandler):
            def do_POST(self):
                seen.append(self.path)
                n = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(n)
                out = b'{"ok": true}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, format, *args):
                pass

        up = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        threading.Thread(target=up.serve_forever, daemon=True).start()
        relay = ThreadingHTTPServer(("127.0.0.1", 0), sat.Relay)
        threading.Thread(target=relay.serve_forever, daemon=True).start()
        self.addCleanup(up.shutdown)
        self.addCleanup(relay.shutdown)
        with mock.patch.object(sat, "UPSTREAM", "http://127.0.0.1:%d" % up.server_address[1]):
            def post(path):
                s = socket.create_connection(("127.0.0.1", relay.server_address[1]), timeout=5)
                s.sendall(("POST %s HTTP/1.1\r\nHost: r\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}" % path).encode())
                data = b""
                while True:
                    part = s.recv(4096)
                    if not part:
                        break
                    data += part
                s.close()
                return int(data.split(b" ", 2)[1])
            self.assertEqual(post("/api/heartbeat"), 200)
            self.assertEqual(post("/api/login"), 404)
            self.assertEqual(post("/api/heartbeat/../login"), 404)
        self.assertEqual(seen, ["/api/heartbeat"], "only the agent path reached the server")


class TestWindowsInstallersFailClosed(unittest.TestCase):
    """U6"""

    @staticmethod
    def server_template():
        text = (ROOT / "server" / "cgi-bin" / "api.py").read_text()
        i = text.index("_AGENT_INSTALL_PS1 = r'''")
        return text[i:text.index("'''", i + 30)]

    def sources(self):
        return {"install-windows.ps1": (CLIENT / "install-windows.ps1").read_text(), "the server's /install.ps1": self.server_template()}

    def test_no_checksum_to_compare_with_is_a_stop(self):
        for label, text in self.sources().items():
            with self.subTest(script=label):
                self.assertRegex(text, r"if \(-not \$want\)")
                i = text.index("if (-not $want)")
                self.assertLess(i, text.index("Invoke-WebRequest -Uri \"$Server/api/agent/win/download\""),
                                "the checksum is required before the agent is downloaded")
                self.assertNotRegex(text, r"if \(\$want\) \{", "the verification is conditional on having a checksum again")

    def test_the_python_installer_is_checked_before_it_runs_elevated(self):
        for label, text in self.sources().items():
            with self.subTest(script=label):
                sig = text.index("Get-AuthenticodeSignature")
                self.assertIn("Python Software Foundation", text)
                self.assertLess(sig, text.index("Start-Process -FilePath $exe") if "Start-Process -FilePath $exe" in text
                                else text.index("Start-Process -FilePath $dl"))
                self.assertIn("'Valid'", text)


if __name__ == "__main__":
    unittest.main()
