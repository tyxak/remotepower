"""v6.4.2 — a Windows host gets an iterate-and-see prompt without OpenSSH.

The web terminal is an asyncssh client: the modal asks for host, SSH user,
port 22 and an SSH password, and the daemon opens a real SSH session. No agent
has any PTY/ConPTY concept. So a Windows host only gets an interactive prompt
if the operator separately installed and exposed OpenSSH Server with a local
password — which RemotePower's own Windows onboarding never does.

The drawer's "Web terminal" button therefore presented, on most Windows fleets,
a login form that could only ever fail to connect, with no hint as to why.

Meanwhile `POST /api/exec/wait` has returned command output SYNCHRONOUSLY
since v5.6.0, and the Windows agent reports through the same `cmd_output`
path — so the iterate-and-see loop existed on the wire with no UI on top of it.

**Not delivered, and deliberately so:** a true PTY/ConPTY relay. Each command
here is its own process, so there is no persistent shell state and no
interactive program. An always-on interactive channel to a SYSTEM-level agent
is a security design that deserves its own review, not a hurried one — and the
console covers the 2am case (run something, read it, run the next thing)
through a channel that is already admin-gated, allowlist-enforced and audited.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_JS = ROOT / "server" / "html" / "static" / "js"
_HTML = ROOT / "server" / "html" / "index.html"
_CGI = ROOT / "server" / "cgi-bin"


def _fn(js, name, kw="function"):
    i = js.index(f"{kw} {name}(")
    return js[i:js.index("\n}\n", i)]


class TestTheConsole(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not _HTML.exists():
            raise unittest.SkipTest("excluded from this tree")
        cls.html = _HTML.read_text()
        cls.js = (_JS / "app-remote.js").read_text()

    def test_it_exists_and_is_reachable_from_the_drawer(self):
        app = (_JS / "app.js").read_text()
        self.assertIn("openAgentConsole(id, name)", app)
        self.assertRegex(self.js, r"\bfunction openAgentConsole\s*\(")
        self.assertIn('id="agent-console-modal"', self.html)

    def test_it_uses_the_existing_run_and_wait_channel(self):
        """No new endpoint and no new channel — /api/exec/wait is already
        admin-gated, allowlist-enforced and audit-logged."""
        body = _fn(self.js, "agentConsoleRun", kw="async function")
        self.assertIn("'/exec/wait'", body)

    def test_windows_gets_powershell_and_cmd(self):
        i = self.js.index("_AGENT_CON_SHELLS")
        seg = self.js[i:i + 400]
        self.assertIn("'ps:'", seg)
        self.assertIn("'cmd:'", seg)

    def test_the_prefixes_are_the_ones_the_agent_actually_parses(self):
        """`ps:` and `cmd:` are dispatch prefixes in the Windows agent. A typo
        would queue a command the agent runs as a bare shell string."""
        agent = (ROOT / "client" / "remotepower-agent-win.py").read_text()
        self.assertIn("cmd.startswith('ps:')", agent)
        self.assertIn("cmd.startswith('cmd:')", agent)

    def test_output_is_read_out_of_the_record_the_agent_sends(self):
        """The response carries {cmd, output, rc} — `String(r.output)` would
        render "[object Object]" into the console an operator is reading."""
        body = _fn(self.js, "agentConsoleRun", kw="async function")
        self.assertIn("rec.output", body)
        self.assertIn("typeof r.output === 'object'", body)

    def test_a_non_zero_exit_is_shown(self):
        """A command that failed and one that printed nothing look identical
        otherwise."""
        body = _fn(self.js, "agentConsoleRun", kw="async function")
        self.assertIn("exit ${rc}", body)

    def test_a_timeout_says_the_command_may_still_be_running(self):
        """The agent may simply not have reported back yet — telling the
        operator it failed would invite them to run it twice."""
        body = _fn(self.js, "agentConsoleRun", kw="async function")
        self.assertIn("timeout", body)
        i = self.js.index("still be running")
        self.assertGreater(i, 0)

    def test_output_never_goes_through_innerHTML(self):
        """This is remote command output from a host that may be compromised —
        which is precisely when an operator runs it."""
        body = _fn(self.js, "_agentConAppend")
        # Comments stripped: the code's own comment says "never innerHTML", so
        # a raw search finds the string it is asserting the absence of. Same
        # trap as every other assert-against-comments case in this suite.
        code = re.sub(r"^\s*//.*$", "", body, flags=re.M)
        self.assertIn("textContent", code)
        self.assertNotIn("innerHTML", code)

    def test_enter_runs_the_command(self):
        self.assertIn("e.target.id === 'agentcon-input'", self.js)

    def test_the_output_pane_is_capped(self):
        i = self.html.index('id="agentcon-out"')
        self.assertIn("scroll-cap", self.html[i:i + 200])

    def test_the_modal_is_at_body_level(self):
        i = self.html.index('id="agent-console-modal"')
        self.assertIn("<!-- /app -->", self.html[:i])

    def test_no_inline_handlers_or_styles(self):
        i = self.html.index('id="agent-console-modal"')
        seg = self.html[i:i + 2200]
        self.assertNotIn("onclick", seg)
        self.assertNotIn('style="', seg)


class TestItDoesNotOverclaim(unittest.TestCase):
    """A console that let an operator believe it was a shell would be the
    UI-text-that-lies class this codebase keeps hunting."""

    @classmethod
    def setUpClass(cls):
        if not _HTML.exists():
            raise unittest.SkipTest("excluded from this tree")
        cls.html = _HTML.read_text()

    def test_it_says_there_is_no_persistent_shell(self):
        i = self.html.index('id="agent-console-modal"')
        seg = self.html[i:i + 2200]
        self.assertIn("no persistent shell", seg)
        self.assertIn("cd", seg)

    def test_it_warns_that_interactive_programs_will_hang(self):
        i = self.html.index('id="agent-console-modal"')
        self.assertIn("interactive programs will hang",
                      self.html[i:i + 2200])

    def test_it_says_the_command_is_audited(self):
        """An operator should know a console is not a back door around the
        controls the Run command button has."""
        i = self.html.index('id="agent-console-modal"')
        self.assertIn("audit-logged", self.html[i:i + 2200])


class TestTheWebTerminalStoppedFailingSilently(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p = _JS / "app-remote.js"
        if not p.exists():
            raise unittest.SkipTest("excluded from this tree")
        cls.js = p.read_text()

    def test_a_windows_host_is_told_what_ssh_needs(self):
        body = _fn(self.js, "openWebTerm")
        self.assertIn("/win/i.test", body)
        self.assertIn("OpenSSH", body)

    def test_it_offers_the_console_instead(self):
        body = _fn(self.js, "openWebTerm")
        self.assertIn("openAgentConsole(id, name)", body)

    def test_it_also_points_at_the_rdp_tunnel(self):
        """The shipped, deliberate Windows interactive path — a full desktop,
        including a prompt."""
        self.assertIn("RDP tunnel", _fn(self.js, "openWebTerm"))

    def test_an_operator_who_really_wants_ssh_can_still_have_it(self):
        """Some Windows fleets DO run OpenSSH Server. Blocking them would trade
        one wrong assumption for another."""
        body = _fn(self.js, "openWebTerm")
        self.assertIn("_openWebTermModal(id, name, dev)", body)
        self.assertIn("Use SSH anyway", body)

    def test_a_non_windows_host_is_unaffected(self):
        body = _fn(self.js, "openWebTerm")
        # The guard returns early; the last statement is the normal path.
        self.assertTrue(body.rstrip().endswith("_openWebTermModal(id, name, dev);"))

    def test_the_ssh_modal_itself_is_unchanged(self):
        """Only the entry point moved — the SSH flow keeps its ticket exchange
        and admin re-auth."""
        self.assertRegex(self.js, r"\bfunction _openWebTermModal\s*\(")
        self.assertIn("webterm-admin-pw", _fn(self.js, "_openWebTermModal"))


class TestTheServerSideIsUnchanged(unittest.TestCase):
    """This finding is a UI gap over an existing channel. Pin that nothing was
    loosened server-side to make the console work."""

    def test_exec_wait_is_still_admin_only(self):
        from srcpin import py_function
        src = (_CGI / "api.py").read_text()
        body = py_function(src, "handle_longpoll_exec")
        self.assertIn("require_admin_auth()", body)

    def test_it_still_scope_gates_the_body_device_id(self):
        """It resolves device_id from the BODY, so main()'s
        _enforce_device_scope never runs on it."""
        from srcpin import py_function
        src = (_CGI / "api.py").read_text()
        body = py_function(src, "handle_longpoll_exec")
        self.assertIn("_scope_block_device", body)

    def test_the_command_length_cap_is_intact(self):
        from srcpin import py_function
        src = (_CGI / "api.py").read_text()
        self.assertIn("cmd too long", py_function(src, "handle_longpoll_exec"))


if __name__ == "__main__":
    unittest.main()
