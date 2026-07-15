"""v6.2.2 (SECURITY): fleet-aggregate GET/action handlers must scope- AND
tenant-filter the device set they read/act on.

A cluster of fleet-wide handlers loaded `load(DEVICES_FILE)` (or a cached
digest) with no filter, so:

  * a GROUP/TAG-scoped operator saw every group's device data, and
  * a TENANT admin (role 'admin', so `_caller_scope()` is None) saw every
    OTHER tenant's device data — the scope-only gates miss them entirely.

The fix routes each handler's device set through `_scope_filter_devices()`
(which folds in BOTH role scope and `_tenant_filter_devices`) and is a NO-OP
for a single-org admin (scope None, tenant None) — that caller still sees the
whole fleet.

This bug class SURVIVES a source-text test and SURVIVES a test that stubs
`require_auth`/`require_admin_auth` (such a stub would pass a handler that has
NO gate at all). So this test stubs ONLY `verify_token` (identity) and drives
each real handler end to end, asserting the out-of-scope / other-tenant device
is ABSENT from the response — and that a plain admin still sees BOTH devices,
proving single-org deployments are unaffected.
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

CGI = Path(__file__).resolve().parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(CGI))

# Distinctive, collision-free tokens so a substring check over the JSON response
# is unambiguous.
IN_ID, IN_NAME = "devalpha", "ALPHAHOST"
OUT_ID, OUT_NAME = "devbravo", "BRAVOHOST"


def _fresh_api():
    os.environ["RP_DATA_DIR"] = tempfile.mkdtemp(prefix="rp-v622-scope-")
    spec = importlib.util.spec_from_file_location("api_v622_scope", CGI / "api.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Base(unittest.TestCase):
    def setUp(self):
        api = self.api = _fresh_api()

        # Two devices in different groups/tags AND different tenants, both with
        # rich sysinfo + a stale last_seen (→ an offline NA item per host).
        def _dev(tenant, name, tag):
            return {
                "name": name, "tenant": tenant, "token": "tok-" + name,
                "version": "1.0", "group": tag, "tags": [tag],
                "last_seen": 1,  # long offline → NA 'offline' item
                "monitored": True,
                "custom_script_results": {
                    "s1": {"ok": False, "output": "boom", "rc": 1, "ran_at": 2}
                },
                "mailbox_paths": ["/var/mail/root"],
                "mailbox_state": {"counts": {"total": 5}, "reported_at": 2},
                "sysinfo": {
                    "packages": {"upgradable": 3},
                    "firewall": {"active": True, "backends": [
                        {"name": "nftables", "present": True, "active": True,
                         "rules": 4, "rule_list": ["rule-" + name]}]},
                    "fail2ban": {"available": True, "jails": [
                        {"name": "sshd", "banned_count": 1, "banned": ["1.2.3.4"]}]},
                    "cron": {"crontabs": [{"user": "root",
                                           "lines": ["* * * * * echo " + name]}]},
                },
            }

        api.save(api.DEVICES_FILE, {
            IN_ID: _dev("tenantA", IN_NAME, "teamx"),
            OUT_ID: _dev("tenantB", OUT_NAME, "teamy"),
        })
        # Sidecar stores keyed by device id.
        api.save(api.SERVICES_FILE, {
            IN_ID: {"services": [{"name": "sshd", "active": "active"}], "updated_at": 2},
            OUT_ID: {"services": [{"name": "sshd", "active": "failed"}], "updated_at": 2},
        })
        api.save(api.LOG_WATCH_FILE, {
            IN_ID: {"units": {"sshd": [{"ts": 2, "line": "needle in " + IN_NAME}]}},
            OUT_ID: {"units": {"sshd": [{"ts": 2, "line": "needle in " + OUT_NAME}]}},
        })
        api.save(api.ACME_STATE_FILE, {
            IN_ID: {"available": True, "certs": [{"cn": IN_NAME}], "updated_at": 2},
            OUT_ID: {"available": True, "certs": [{"cn": OUT_NAME}], "updated_at": 2},
        })
        api.save(api.CVE_FINDINGS_FILE, {
            IN_ID: {"findings": [{"vuln_id": "CVE-A", "severity": "critical",
                                  "package": "openssl"}]},
            OUT_ID: {"findings": [{"vuln_id": "CVE-B", "severity": "critical",
                                   "package": "openssl"}]},
        })

        # Tenant registry + a user in tenantA (for the tenant-admin case).
        api.save(api.TENANTS_FILE, {
            "tenantA": {"name": "Tenant A", "status": "active"},
            "tenantB": {"name": "Tenant B", "status": "active"},
        })
        api.save(api.USERS_FILE, {
            "alice": {"tenant_id": "tenantA", "role": "admin"},
            "root": {"tenant_id": "default", "role": "admin"},
        })
        # A group/tag-scoped, non-admin custom role that can only see teamx.
        api.save(api.ROLES_FILE, {"roles": [
            {"name": "scopedx", "permissions": [],
             "scope": {"type": "tags", "values": ["teamx"]}},
        ]})

        # Don't let side-effecting recorders / AI / webhook toggles interfere.
        api.audit_log = lambda *a, **k: None
        api.fire_webhook = lambda *a, **k: None
        api.is_webhook_event_enabled = lambda ev: True
        api._ai_run = lambda *a, **k: ({"text": ""}, 0, 100)
        api.get_token_from_request = lambda: "x"

        self.cap = {}

        def _respond(status, data=None, headers=None):
            self.cap["status"], self.cap["data"] = status, data
            raise api.HTTPError(status, data)
        api.respond = _respond

        api._LOAD_CACHE.clear()

    # ── identity helpers — stub ONLY verify_token (never require_*) ──────────
    def _as_admin(self):
        """Plain single-org admin: scope None, tenant default. Sees everything."""
        self.api.save(self.api.CONFIG_FILE, {})  # tenancy OFF
        self.api._LOAD_CACHE.clear()
        self.api.verify_token = lambda tok=None: ("root", "admin")

    def _as_scoped(self):
        """Group/tag-scoped non-admin operator. Sees only teamx (= IN_ID)."""
        self.api.save(self.api.CONFIG_FILE, {})  # tenancy OFF; scope does the work
        self.api._LOAD_CACHE.clear()
        self.api.verify_token = lambda tok=None: ("bob", "scopedx")

    def _as_tenant_admin(self):
        """Tenant admin: role 'admin' (scope None) but confined to tenantA."""
        self.api.save(self.api.CONFIG_FILE, {"tenancy_enforced": True})
        self.api._LOAD_CACHE.clear()
        self.api.verify_token = lambda tok=None: ("alice", "admin")

    def _qs(self, query=""):
        self.api._env = lambda key, default=None, _q=query: \
            _q if key == "QUERY_STRING" else default

    def _drive(self, fn, *args):
        """Run a handler, returning its response body as a JSON string."""
        self.cap.clear()
        try:
            fn(*args)
        except (self.api.HTTPError, SystemExit):
            pass
        return json.dumps(self.cap.get("data"), default=str)

    def _assert_hidden(self, body, ctx=""):
        self.assertNotIn(OUT_ID, body, f"{ctx}: out-of-scope id leaked")
        self.assertNotIn(OUT_NAME, body, f"{ctx}: out-of-scope name leaked")
        self.assertIn(IN_ID, body, f"{ctx}: in-scope id missing (over-filtered?)")

    def _assert_both(self, body, ctx=""):
        self.assertIn(IN_ID, body, f"{ctx}: single-org admin lost in-scope device")
        self.assertIn(OUT_ID, body, f"{ctx}: single-org admin lost the other device")


# Each handler, driven under all three identities. GET/require_auth handlers get
# the full scoped + tenant + admin matrix; require_admin_auth handlers (which a
# scoped non-admin can't reach) get tenant + admin only.
class TestFleetScopeIsolation(_Base):

    def test_home_scoped(self):
        self._as_scoped(); self._qs()
        self._assert_hidden(self._drive(self.api.handle_home), "home/scoped")

    def test_home_tenant(self):
        self._as_tenant_admin(); self._qs()
        self._assert_hidden(self._drive(self.api.handle_home), "home/tenant")

    def test_home_admin_sees_both(self):
        self._as_admin(); self._qs()
        self._assert_both(self._drive(self.api.handle_home), "home/admin")

    def test_attention_scoped(self):
        self._as_scoped()
        self._assert_hidden(self._drive(self.api.handle_attention), "attention/scoped")

    def test_attention_tenant(self):
        self._as_tenant_admin()
        self._assert_hidden(self._drive(self.api.handle_attention), "attention/tenant")

    def test_attention_admin_sees_both(self):
        self._as_admin()
        body = self._drive(self.api.handle_attention)
        self.assertIn(IN_NAME, body); self.assertIn(OUT_NAME, body)

    def test_log_search_scoped(self):
        self._as_scoped(); self._qs("q=needle")
        self._assert_hidden(self._drive(self.api.handle_log_search), "logs/scoped")

    def test_log_search_tenant(self):
        self._as_tenant_admin(); self._qs("q=needle")
        self._assert_hidden(self._drive(self.api.handle_log_search), "logs/tenant")

    def test_log_search_out_of_scope_device_param_empty(self):
        # ?device=<out-of-scope id> must not return that host's log lines.
        self._as_scoped(); self._qs("q=needle&device=" + OUT_ID)
        self._drive(self.api.handle_log_search)
        self.assertNotIn(OUT_NAME, json.dumps(self.cap["data"]["results"]))
        self.assertEqual(self.cap["data"]["count"], 0)  # no results at all

    def test_log_search_admin_sees_both(self):
        self._as_admin(); self._qs("q=needle")
        self._assert_both(self._drive(self.api.handle_log_search), "logs/admin")

    def test_firewall_scoped(self):
        self._as_scoped(); self._qs()
        self._assert_hidden(self._drive(self.api.handle_firewall_overview), "fw/scoped")

    def test_firewall_tenant(self):
        self._as_tenant_admin(); self._qs()
        self._assert_hidden(self._drive(self.api.handle_firewall_overview), "fw/tenant")

    def test_firewall_detail_out_of_scope(self):
        self._as_scoped(); self._qs("device=" + OUT_ID)
        body = self._drive(self.api.handle_firewall_overview)
        self.assertNotIn(OUT_NAME, body)

    def test_firewall_admin_sees_both(self):
        self._as_admin(); self._qs()
        self._assert_both(self._drive(self.api.handle_firewall_overview), "fw/admin")

    def test_cron_scoped(self):
        self._as_scoped(); self._qs()
        self._assert_hidden(self._drive(self.api.handle_cron_overview), "cron/scoped")

    def test_cron_tenant(self):
        self._as_tenant_admin(); self._qs()
        self._assert_hidden(self._drive(self.api.handle_cron_overview), "cron/tenant")

    def test_cron_admin_sees_both(self):
        self._as_admin(); self._qs()
        self._assert_both(self._drive(self.api.handle_cron_overview), "cron/admin")

    def test_fail2ban_scoped(self):
        self._as_scoped(); self._qs()
        self._assert_hidden(self._drive(self.api.handle_fail2ban_overview), "f2b/scoped")

    def test_fail2ban_tenant(self):
        self._as_tenant_admin(); self._qs()
        self._assert_hidden(self._drive(self.api.handle_fail2ban_overview), "f2b/tenant")

    def test_fail2ban_admin_sees_both(self):
        self._as_admin(); self._qs()
        self._assert_both(self._drive(self.api.handle_fail2ban_overview), "f2b/admin")

    def test_custom_scripts_scoped(self):
        self._as_scoped()
        self._assert_hidden(self._drive(self.api.handle_custom_scripts_results), "cs/scoped")

    def test_custom_scripts_tenant(self):
        self._as_tenant_admin()
        self._assert_hidden(self._drive(self.api.handle_custom_scripts_results), "cs/tenant")

    def test_custom_scripts_admin_sees_both(self):
        self._as_admin()
        self._assert_both(self._drive(self.api.handle_custom_scripts_results), "cs/admin")

    def test_services_scoped(self):
        self._as_scoped()
        self._assert_hidden(self._drive(self.api.handle_services_get), "svc/scoped")

    def test_services_tenant(self):
        self._as_tenant_admin()
        self._assert_hidden(self._drive(self.api.handle_services_get), "svc/tenant")

    def test_services_admin_sees_both(self):
        self._as_admin()
        self._assert_both(self._drive(self.api.handle_services_get), "svc/admin")

    def test_acme_scoped(self):
        self._as_scoped()
        self._assert_hidden(self._drive(self.api.handle_acme_list), "acme/scoped")

    def test_acme_tenant(self):
        self._as_tenant_admin()
        self._assert_hidden(self._drive(self.api.handle_acme_list), "acme/tenant")

    def test_acme_admin_sees_both(self):
        self._as_admin()
        self._assert_both(self._drive(self.api.handle_acme_list), "acme/admin")

    # ── AI anomaly: the leak is the PROMPT, not the body — assert the scanned
    #    device count reflects only visible hosts. ────────────────────────────
    def test_ai_anomaly_scoped_scans_one(self):
        self._as_scoped()
        self.api.method = lambda: "POST"
        self.api.get_json_obj = lambda: {}
        self._drive(self.api.handle_ai_anomaly)
        self.assertEqual(self.cap["data"]["scanned"], 1)

    def test_ai_anomaly_admin_scans_both(self):
        self._as_admin()
        self.api.method = lambda: "POST"
        self.api.get_json_obj = lambda: {}
        self._drive(self.api.handle_ai_anomaly)
        self.assertEqual(self.cap["data"]["scanned"], 2)

    # ── cve_realert: require_admin_auth → a TENANT admin passes (scope None).
    #    The fix must gate BOTH the returned count AND the alert side effect. ──
    def test_cve_realert_tenant_only_fires_own(self):
        fired = []
        self._as_tenant_admin()
        self.api.fire_webhook = lambda ev, payload, *a, **k: fired.append(payload.get("device_id"))
        self.api.method = lambda: "POST"
        self.api.get_json_obj = lambda: {}
        self._drive(self.api.handle_cve_realert)
        self.assertEqual(self.cap["data"]["devices"], 1, "should re-alert only its own tenant")
        self.assertEqual(fired, [IN_ID], "must not fire cve_found for another tenant's host")

    def test_cve_realert_admin_fires_both(self):
        fired = []
        self._as_admin()
        self.api.fire_webhook = lambda ev, payload, *a, **k: fired.append(payload.get("device_id"))
        self.api.method = lambda: "POST"
        self.api.get_json_obj = lambda: {}
        self._drive(self.api.handle_cve_realert)
        self.assertEqual(self.cap["data"]["devices"], 2)
        self.assertEqual(sorted(fired), [IN_ID, OUT_ID])


if __name__ == "__main__":
    unittest.main()
