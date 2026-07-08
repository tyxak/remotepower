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
import time
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


class TestScheduledBackupGate(unittest.TestCase):
    """CRITICAL: the daily scheduled-backup gate must read its PERSISTED last_run
    so it runs at most once per 24h. The bug: it used Path.exists() to decide
    whether to load the state, but under the SQLite/Postgres backend the state is
    a DB row (no file) → exists() was always False → last_run never read → a full
    backup ran on EVERY heartbeat (runaway). This test fails under the SQLite leg
    of `make test-both` without the backend_exists() fix."""

    def setUp(self):
        api.save(api.CONFIG_FILE, {"backup": {"enabled": True}})
        # clear any stale in-progress sentinel (a real file)
        try:
            (api.DATA_DIR / ".backup_in_progress").unlink()
        except OSError:
            pass
        self._orig = api._run_data_backup
        self.calls = []

        def _fake(triggered_by="scheduled"):
            self.calls.append(triggered_by)
            api.save(api.DATA_DIR / "self_backup_state.json",
                     {"last_run": int(time.time())})
            return {"ok": True}

        api._run_data_backup = _fake

    def tearDown(self):
        api._run_data_backup = self._orig

    def test_recent_run_suppresses_backup(self):
        # last_run = now (persisted via the storage layer, exactly as the real
        # backup does). The gate must read it back and NOT run again.
        api.save(api.DATA_DIR / "self_backup_state.json",
                 {"last_run": int(time.time())})
        api._maybe_run_scheduled_backup()
        self.assertEqual(self.calls, [],
                         "a backup ran despite a recent persisted last_run "
                         "(the SQLite runaway bug)")

    def test_stale_run_allows_one_backup(self):
        api.save(api.DATA_DIR / "self_backup_state.json",
                 {"last_run": int(time.time()) - 90000})  # >24h ago
        api._maybe_run_scheduled_backup()
        self.assertEqual(len(self.calls), 1)
        # and a second immediate call must now be suppressed (the fake persisted
        # a fresh last_run) — i.e. it does not loop.
        api._maybe_run_scheduled_backup()
        self.assertEqual(len(self.calls), 1, "scheduled backup looped")


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


class TestAlertCoalescing(unittest.TestCase):
    """A repeat firing of the same condition must coalesce into the existing
    OPEN alert, not stack a duplicate row (the duplicate integration_down rows
    that appeared after an upgrade restart purged the flap flag)."""

    def setUp(self):
        api.save(api.ALERTS_FILE, {'alerts': []})
        api.save(api.CONFIG_FILE, {})

    def _open_alerts(self, event=None):
        rows = api.load(api.ALERTS_FILE).get('alerts', [])
        return [a for a in rows if not a.get('resolved_at')
                and (event is None or a.get('event') == event)]

    def test_duplicate_integration_down_coalesces(self):
        payload = {'label': 'Radarr', 'type': 'servarr', 'detail': 'unhealthy',
                   'severity': 'medium', 'integration_id': 'radarr-1'}
        a1 = api._record_alert('integration_down', dict(payload))
        a2 = api._record_alert('integration_down', dict(payload))
        self.assertIsNotNone(a1)
        self.assertIsNotNone(a2)
        opens = self._open_alerts('integration_down')
        self.assertEqual(len(opens), 1, 'duplicate integration_down must coalesce')
        self.assertEqual(opens[0].get('count'), 2, 'occurrence counter must bump')
        self.assertEqual(a1['id'], a2['id'], 'second firing returns the same row')

    def test_distinct_integrations_do_not_coalesce(self):
        api._record_alert('integration_down', {'label': 'Radarr', 'severity': 'medium',
                                               'integration_id': 'radarr-1'})
        api._record_alert('integration_down', {'label': 'Sonarr', 'severity': 'medium',
                                               'integration_id': 'sonarr-1'})
        self.assertEqual(len(self._open_alerts('integration_down')), 2,
                         'different integrations are different conditions')

    def test_resolved_alert_does_not_absorb_new_firing(self):
        a1 = api._record_alert('integration_down', {'label': 'Radarr', 'severity': 'medium',
                                                    'integration_id': 'radarr-1'})
        rows = api.load(api.ALERTS_FILE)
        rows['alerts'][0]['resolved_at'] = int(time.time())
        api.save(api.ALERTS_FILE, rows)
        api._record_alert('integration_down', {'label': 'Radarr', 'severity': 'medium',
                                              'integration_id': 'radarr-1'})
        self.assertEqual(len(self._open_alerts('integration_down')), 1,
                         'a new firing after resolution opens a fresh alert')


class TestAgentLifecycleDefaultOff(unittest.TestCase):
    """agent_stopped/started must NOT alert or webhook by default — they are
    expected upgrade churn. Recent Activity stays on as an audit trail."""

    def setUp(self):
        api.save(api.CONFIG_FILE, {})   # no saved channel_routing → defaults apply

    def test_agentlifecycle_alerts_and_webhook_off_by_default(self):
        self.assertFalse(api._channel_allowed('agent_stopped', 'alerts'))
        self.assertFalse(api._channel_allowed('agent_stopped', 'webhook'))
        self.assertFalse(api._channel_allowed('agent_started', 'alerts'))
        self.assertFalse(api._channel_allowed('agent_started', 'webhook'))

    def test_agentlifecycle_recent_activity_on_by_default(self):
        self.assertTrue(api._channel_allowed('agent_stopped', 'recent_activity'))

    def test_agent_stopped_records_no_alert_by_default(self):
        api.save(api.ALERTS_FILE, {'alerts': []})
        result = api._record_alert('agent_stopped', {'device_id': 'd', 'name': 'h'})
        self.assertIsNone(result, 'agent_stopped must not create an inbox alert by default')


class TestApiUnitEnvironmentFile(unittest.TestCase):
    """The app-server unit must read operator env/secrets from an external file.

    install-server.sh overwrites the unit on every redeploy, so an inline
    `Environment=RP_BACKUP_PASSPHRASE=...` edit is silently wiped on the next
    update. An optional EnvironmentFile keeps the operator's passphrase (and
    other secrets) in a file the deploy never touches — mirrors the agent unit's
    `EnvironmentFile=-/etc/remotepower/agent.env`.
    """

    def test_unit_loads_operator_env_file(self):
        unit = (_ROOT / "server" / "conf" / "remotepower-wsgi.service").read_text()
        # `-` prefix → optional, no boot failure when the file is absent.
        self.assertIn("EnvironmentFile=-/etc/remotepower/api.env", unit)


if __name__ == "__main__":
    unittest.main()
