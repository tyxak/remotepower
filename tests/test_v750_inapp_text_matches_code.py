#!/usr/bin/env python3
"""v7.5.0 (docs cross-check, finding W2-F7): statements in the web interface that said something the code does not do.

Each one was found by reading the text against the code, and each is held here by comparing the two where the code can give the
answer, so the next change to either side fails a test and not a reader:

* the Online TTL form (the floor, the default and the fallback) against `MIN_ONLINE_TTL` and `DEFAULT_ONLINE_TTL`;
* where the status token is made, against the Settings tab that holds the Status endpoint section;
* the evidence pack hint against the permission the handler asks for;
* the health gate hint against the state a halt leaves the rollout in, and whether the interface can resume that state;
* the host-config text against how the agent reports (on request, not on a cadence);
* the Files page, which has no per-server switch, and the RDP dialog, which names a program RemotePower does not ship.
"""
import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
_JS = _ROOT / "server" / "html" / "static" / "js"
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-text-"))
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import srcpin  # noqa: E402

_spec = importlib.util.spec_from_file_location("api_v750_text", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

HTML = (_ROOT / "server" / "html" / "index.html").read_text(encoding="utf-8")
APP = (_JS / "app.js").read_text(encoding="utf-8")


class TestOnlineTtl(unittest.TestCase):

    def test_the_form_uses_the_servers_floor_and_default(self):
        tag = re.search(r'<input[^>]*id="cfg-online-ttl"[^>]*>', HTML).group(0)
        self.assertEqual(int(re.search(r'min="(\d+)"', tag).group(1)), api.MIN_ONLINE_TTL)
        self.assertEqual(int(re.search(r'placeholder="(\d+)"', tag).group(1)), api.DEFAULT_ONLINE_TTL)
        hint = re.search(r'id="cfg-online-ttl-hint"[^>]*>([^<]*)<', HTML).group(1)
        self.assertEqual(hint, f"{api.MIN_ONLINE_TTL}–7200 (default {api.DEFAULT_ONLINE_TTL})")

    def test_the_script_falls_back_to_the_servers_default(self):
        self.assertEqual(re.findall(r"cfg-online-ttl'\)\.value(?:\) \|\| |\s*=\s*data\.online_ttl \|\| )(\d+)", APP),
                         [str(api.DEFAULT_ONLINE_TTL)] * 2)
        self.assertIn(f"(default {api.DEFAULT_ONLINE_TTL})", APP)
        self.assertNotIn("(default 180)", APP)

    def test_a_value_below_the_floor_is_a_400_so_the_form_must_not_offer_it(self):
        self.assertGreater(api.MIN_ONLINE_TTL, 90, "control: the old form's minimum was below the server's floor")


class TestTheStatusEndpointIsWhereTheTextSays(unittest.TestCase):

    def test_the_settings_tab_that_holds_the_section_is_the_one_named(self):
        i = HTML.index('<div class="section-title">Status endpoint</div>')
        pane = re.findall(r'id="settings-pane-([a-z0-9]+)"', HTML[:i])[-1]
        label = re.search(r'data-tab="%s"[^>]*>([^<]+)<' % pane, HTML).group(1).strip()
        self.assertEqual(label, "Integrations")
        doc = re.search(r"Generate a <strong>status token</strong> under (Settings → [^.]*?)\. The endpoint", HTML).group(1)
        self.assertEqual(doc, f"Settings → {label} → Status endpoint")


class TestTheEvidencePackHint(unittest.TestCase):

    def test_the_hint_names_the_roles_the_handler_allows(self):
        body = srcpin.py_function((_CGI / "reports_handlers.py").read_text(), "handle_evidence_pack")
        self.assertIn("require_admin_or_auditor_auth", body)
        self.assertIn("Admins and auditors only; generating it is itself audit-logged.", HTML)
        self.assertNotIn("Admin only; generating it is itself audit-logged.", HTML)
        self.assertNotIn("(admin-only)", body.split('"""')[1])


class TestTheHealthGateHint(unittest.TestCase):

    def test_a_halt_leaves_the_rollout_failed_and_the_hint_does_not_promise_a_resume(self):
        advance = srcpin.py_function((_CGI / "provisioning_handlers.py").read_text(), "_rollout_advance")
        self.assertRegex(advance, r"roll\['state'\] = 'failed'[\s\S]{0,400}rollout_halted")
        js = (_JS / "app-rollouts.js").read_text()
        self.assertIn("canResume = roll.state === 'paused'", js, "control: only a paused rollout has a Resume button")
        self.assertNotIn("You resume or cancel", HTML)
        self.assertIn("the rollout halts (it ends as failed)", HTML)


class TestHostConfigText(unittest.TestCase):

    def test_no_text_claims_a_reporting_cadence(self):
        for text in (HTML, (_JS / "app-hostconfig.js").read_text()):
            self.assertNotIn("reports current state every 15 minutes", text)
            self.assertNotIn("agent reports every 15 min", text)
            self.assertNotIn("Save & push to agent", text)
        self.assertIn("Collect all current", (_JS / "app-hostconfig.js").read_text())

    def test_the_dead_constants_say_so(self):
        agent = (_ROOT / "client" / "remotepower-agent.py").read_text()
        self.assertRegex(agent, r"HOST_CONFIG_COLLECT_EVERY = 15  # not used")
        self.assertRegex((_CGI / "api.py").read_text(), r"HOST_CONFIG_AUDIT_EVERY\s+= 15\s+# not used")
        self.assertEqual((_ROOT / "client" / "remotepower-agent").read_bytes(), (_ROOT / "client" / "remotepower-agent.py").read_bytes())


class TestFilesAndRdp(unittest.TestCase):

    def test_the_files_page_offers_no_switch_that_does_not_exist(self):
        self.assertNotIn("Enable per-server under Settings", HTML)

    def test_the_rdp_dialog_does_not_present_a_bridge_as_part_of_the_product(self):
        js = (_JS / "app-remote.js").read_text()
        self.assertIn("RemotePower does not include one", js)
        shipped = [p for p in _ROOT.rglob("remotepower-rdp-bridge*") if ".git" not in p.parts]
        self.assertEqual(shipped, [], "control: if a bridge ships, the dialog's wording has to change")


class TestSweepCount(unittest.TestCase):

    def test_the_installer_help_quotes_the_real_number(self):
        import scheduler
        n = len(scheduler.CADENCE)
        self.assertIn(f"Run the ~{n} maintenance sweeps", (_ROOT / "install-server.sh").read_text())


if __name__ == "__main__":
    unittest.main()
