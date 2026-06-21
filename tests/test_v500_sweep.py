"""v5.0.0 finalize-sweep regressions:
  - per-device patch report no longer 500s (security_updates NameError)
  - distro security-update count surfaced in the Checks engine + patch payload
  - admin handlers coerce a non-dict JSON body to {} instead of 500ing
  - SNMP / LDAP outbound targets reject loopback / cloud-metadata (SSRF)
  - the agent's audit (read-only) mode refuses server-pushed custom scripts
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

_DATA = tempfile.mkdtemp(prefix="rp-v500sweep-")
os.environ["RP_DATA_DIR"] = _DATA
_spec = importlib.util.spec_from_file_location("api_v500sweep", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

AGENT_SRC = (_ROOT / "client" / "remotepower-agent.py").read_text()
PROXMOX_SRC = (_CGI / "proxmox_client.py").read_text()


class _Stop(Exception):
    pass


def _capture_respond():
    box = {}

    def _cap(status, body=None):
        box["status"], box["body"] = status, body
        raise _Stop()

    api.respond = _cap
    return box


class TestPatchReportDevice(unittest.TestCase):
    """P1: handle_patch_report_device used an unbound `security_updates` →
    NameError → 500 for every device. Now bound from sysinfo.packages."""

    def setUp(self):
        self._auth = api.require_auth
        self._scope = api._scope_block_device
        api.require_auth = lambda *a, **k: "tester"
        api._scope_block_device = lambda *a, **k: None
        api.save(api.DEVICES_FILE, {"d1": {
            "name": "web01", "last_seen": 0,
            "sysinfo": {"packages": {"manager": "apt", "upgradable": 12,
                                     "security_updates": 3}},
        }})
        api.save(api.CMD_OUTPUT_FILE, {})
        api.save(api.METRICS_FILE, {})

    def tearDown(self):
        api.require_auth = self._auth
        api._scope_block_device = self._scope

    def test_report_does_not_500_and_carries_security_count(self):
        box = _capture_respond()
        with self.assertRaises(_Stop):
            api.handle_patch_report_device("d1")
        self.assertEqual(box["status"], 200)
        self.assertEqual(box["body"]["upgradable"], 12)
        self.assertEqual(box["body"]["security_updates"], 3)


class TestSecurityUpdatesCheck(unittest.TestCase):
    """The distro's own security-flagged count is surfaced on the Checks page:
    a host with pending security updates is a warning even if the total is low."""

    def _patches_row(self, pkgs):
        dev = {"name": "h", "last_seen": 0, "sysinfo": {"packages": pkgs}}
        rows = api._host_checks("d1", dev, now=0)
        return next((r for r in rows if r.get("key") == "patches"), None)

    def test_security_count_shown_and_warns(self):
        row = self._patches_row({"upgradable": 2, "security_updates": 1})
        self.assertIsNotNone(row)
        self.assertEqual(row["status"], "warning")
        self.assertIn("security", row["output"])

    def test_no_security_count_is_plain(self):
        row = self._patches_row({"upgradable": 0})
        self.assertIsNotNone(row)
        self.assertEqual(row["status"], "ok")
        self.assertNotIn("security", row["output"])


class TestJsonBodyCoercion(unittest.TestCase):
    """A top-level JSON array body must not 500 the admin bulk handlers."""

    def setUp(self):
        self._admin = api.require_admin_auth
        self._method = api.method
        self._body = api.get_body
        api.require_admin_auth = lambda *a, **k: "admin"
        api.method = lambda: "POST"
        api.get_body = lambda: "[1,2,3]"

    def tearDown(self):
        api.require_admin_auth = self._admin
        api.method = self._method
        api.get_body = self._body

    def test_bulk_delete_array_body_is_400_not_500(self):
        box = _capture_respond()
        with self.assertRaises(_Stop):
            api.handle_devices_bulk_delete()
        self.assertEqual(box["status"], 400)


class TestSnmpSsrf(unittest.TestCase):
    """_device_snmp_target rejects link-local / cloud-metadata so a device IP
    can't be used as a blind UDP:161 oracle. Loopback is allowed on purpose
    (monitoring the server host's own snmpd is legitimate)."""

    def test_link_local_metadata_refused(self):
        dev = {"id": "d1", "ip": "169.254.169.254",
               "snmp": {"enabled": True, "community": "public"}}
        self.assertIsNone(api._device_snmp_target(dev))

    def test_unspecified_refused(self):
        dev = {"id": "d1", "ip": "0.0.0.0",
               "snmp": {"enabled": True, "community": "public"}}
        self.assertIsNone(api._device_snmp_target(dev))

    def test_loopback_allowed(self):
        # snmpd on the server box (127.0.0.1) is a legitimate monitor target.
        dev = {"id": "d1", "ip": "127.0.0.1",
               "snmp": {"enabled": True, "community": "public"}}
        self.assertEqual(api._device_snmp_target(dev),
                         ("127.0.0.1", "public", 161))

    def test_lan_target_allowed(self):
        dev = {"id": "d1", "ip": "10.0.0.5",
               "snmp": {"enabled": True, "community": "public"}}
        self.assertEqual(api._device_snmp_target(dev),
                         ("10.0.0.5", "public", 161))


class TestSourceGuards(unittest.TestCase):
    """Source-level guards that are awkward to exercise at runtime."""

    def test_agent_audit_mode_guards_custom_scripts(self):
        # run_custom_scripts must early-return under audit (read-only) mode.
        idx = AGENT_SRC.index("def run_custom_scripts(")
        end = AGENT_SRC.index("\ndef ", idx + 1)
        body = AGENT_SRC[idx:end]
        self.assertIn("_audit_mode()", body,
                      "run_custom_scripts must check audit mode")

    def test_proxmox_runtime_uses_connect_time_ssrf_guard(self):
        self.assertIn("_ssrf_opener(ctx)", PROXMOX_SRC)
        self.assertIn("_SSRFGuardHTTPSConnection", PROXMOX_SRC)


if __name__ == "__main__":
    unittest.main()
