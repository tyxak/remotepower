#!/usr/bin/env python3
"""Regression: /api/agent/version must advertise the version of the SERVED
binary, not a stale config value. A drift here showed up as a confusing
"upgrading v3.14.0 -> v3.12.0" in the agent's self-update log."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())

import importlib.util

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestAgentVersionFromBinary(unittest.TestCase):
    def test_parse_version_constant(self):
        d = Path(tempfile.mkdtemp())
        p = d / "remotepower-agent"
        p.write_text("#!/usr/bin/env python3\nVERSION      = '4.0.0'\n# rest...\n")
        self.assertEqual(api._read_agent_version(p), "4.0.0")
        # missing / unparseable -> None (caller falls back to config)
        (d / "blank").write_text("no version here\n")
        self.assertIsNone(api._read_agent_version(d / "blank"))
        self.assertIsNone(api._read_agent_version(d / "does-not-exist"))

    def test_real_agent_binary_parses_to_semver(self):
        ver = api._read_agent_version(_ROOT / "client" / "remotepower-agent")
        self.assertRegex(ver or "", r"^\d+\.\d+\.\d+$")

    def test_handler_prefers_binary_over_stale_config(self):
        d = Path(tempfile.mkdtemp())
        binp = d / "remotepower-agent"
        binp.write_text("VERSION      = '4.0.0'\n")
        cap = {}
        orig_bin = api._AGENT_BINARY_PATH
        orig_resp = api.respond
        orig_auth = getattr(api, "require_auth", None)
        try:
            api._AGENT_BINARY_PATH = binp
            api.save(api.CONFIG_FILE, {"agent_version": "3.12.0"})   # stale!
            api.respond = lambda s, b=None: cap.update(s=s, b=b)
            api._resolve_agent_channel = lambda: "stable"
            api._get_agent_sha256 = lambda: "a" * 64
            api.handle_agent_version()
        finally:
            api._AGENT_BINARY_PATH = orig_bin
            api.respond = orig_resp
            if orig_auth:
                api.require_auth = orig_auth
        self.assertEqual(cap["b"]["version"], "4.0.0",
                         "advertised version must come from the served binary, not config")


if __name__ == "__main__":
    unittest.main()
