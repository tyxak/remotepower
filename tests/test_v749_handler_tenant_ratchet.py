#!/usr/bin/env python3
"""A route either names a tenant or scope helper in its handler, sits in one of the two tenant tables, or has been read and listed.

The authorization matrix of 7.4.9 finds what the seeded data holds. A second look, from the code, found what it could not: handlers
that ask for an administrator and nothing more, so an administrator of any tenant passed. One of them handed the operator's DNS
credentials to a tenant's host, others restarted the service, moved the data store to another backend, powered off the operator's
hypervisors and read the audit trail's archive. This test is the second look as a ratchet over the whole class (the same shape as
the users-file lock ratchet): the population is every routed handler, found the way the application finds it, and what is left
after the two tenant tables and the vocabulary of the tenant helpers is a frozen, reviewed list in tests/data/tenant_gate_reviewed.txt.

A route that appears outside that list fails. Gate the handler (`_scope_filter_devices`, `_tenant_gate`, `_confined_host_ids`,
`require_instance_admin_auth`, ...), add the route to `_PLATFORM_ROUTES` (only the platform operator) or `_OPERATOR_ORG_ROUTES` (the
organisation that runs the installation), or read it and list it with the reason. A listed route that has been gated fails too, so
the list only shrinks.
"""
import importlib.util
import inspect
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v749-ratchet-"))
_spec = importlib.util.spec_from_file_location("api_v749_ratchet", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")

# What a handler may name to show it knows about tenants or scopes. `tenant` is broad on purpose: a handler that mentions the word
# is read by a person, a handler that does not is on the list.
GATE = re.compile(
    r"require_instance_admin_auth|_require_instance|_scope_filter_devices|_tenant_visible|_tenant_gate|_confined_host_ids|"
    r"_caller_in_operator_org|_visible_devices|_scope_block_device|_device_in_scope|_user_tenant_visible|_tenant_filter_devices|"
    r"require_superadmin_auth|_require_platform_operator|_visible_scripts|_visible_windows|_rule_visible|_ignore_entry_visible|"
    r"_alert_tenant_visible|_filter_alerts_for_caller|_caller_reach|_mute_reachable|_enforce_device_scope|_resolve_targets|"
    r"_caller_effective_tenant|_caller_tenant|_caller_scope|tenant|_scope_check|_in_scope|_visible_ids|_owner_gate|_device_tenant|"
    r"_filter_by_scope"
)

# Routes that no signed-in tenant user is the subject of: a host, a daemon or a provider authenticates with its own token, the
# caller's own session and profile, and the sign-in flows. /api/devices/<id>/... is covered by the pre-dispatch device gate.
SKIP = (
    "/api/devices/", "/api/heartbeat", "/api/enroll", "/api/auth/", "/api/login", "/api/logout", "/api/scim", "/api/webhook/in",
    "/api/syslog", "/api/snmp/trap", "/api/flow", "/api/portal/", "/api/kmip", "/api/ping", "/api/public", "/api/ha", "/api/agent",
    "/api/webterm", "/api/me", "/api/totp", "/api/webauthn", "/api/passkeys", "/api/csp-report", "/api/alerts/act", "/api/ui-prefs",
    "/api/favorites", "/api/push", "/api/users/passwd", "/api/activity/clear", "/api/itsm/in", "/api/internal", "/api/satellite",
    "/api/scans/", "/api/threat-events", "/api/status", "/api/version", "/api/setup-status",
)


def _routes():
    """{(method, path template, handler name)} of every route the application registers with a handler of its own."""
    out = set()
    for (method, path), fn in api._build_exact_routes().items():
        for m in [method] if method else METHODS:
            out.add((m, path, fn.__name__))
    for kind, methods, a, b, name, _src in api._PATTERN_ROUTE_DEFS:
        if kind == "eq":
            path = a
        elif kind == "pat":
            path = a + "{}" + b
        else:
            continue
        for m in methods or METHODS:
            out.add((m, path, name))
    return out


def _listing():
    """(routes considered, [(method, path, handler)] that name no tenant helper and sit in neither table)."""
    considered, listed = 0, []
    for m, p, h in sorted(_routes(), key=lambda r: (r[1], r[0], r[2])):
        if p.startswith(SKIP):
            continue
        probe = p.replace("{}", "x")
        if api._platform_route(probe, m) is not None or api._operator_org_route(probe) is not None:
            continue
        considered += 1
        fn = getattr(api, h, None)
        try:
            body = inspect.getsource(fn)
        except (OSError, TypeError):
            body = ""
        if not body:
            listed.append((m, p, h + " (no source)"))
        elif not GATE.search(body):
            listed.append((m, p, h))
    return considered, listed


def _reviewed():
    out = set()
    for line in (_ROOT / "tests" / "data" / "tenant_gate_reviewed.txt").read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            m, p, h = line.split()
            out.add((m, p, h))
    return out


class TestEveryRouteIsGatedTabledOrReviewed(unittest.TestCase):

    def test_the_scan_looks_at_a_real_population(self):
        """A control that fails when the scan measures nothing: it must see most of the application's routes, both tables must take
        routes out of it, and a handler known to be gated must not be on its list."""
        routes = _routes()
        self.assertGreater(len(routes), 800, "the route population shrank: the scan no longer finds the application's routes")
        considered, listed = _listing()
        self.assertGreater(considered, 300)
        self.assertGreater(len(listed), 40, "the list of ungated routes is nearly empty: the vocabulary matches too much")
        listed_paths = {p for _m, p, _h in listed}
        for covered in ("/api/dns/records", "/api/server/restart", "/api/integrations", "/api/deadman", "/api/na-suppress"):
            self.assertNotIn(covered, listed_paths, f"{covered} is in a tenant table and must not be listed")
        self.assertIn("/api/health", listed_paths, "control: a route with no gate and no table must be listed")

    def test_a_route_outside_the_list_fails(self):
        considered, listed = _listing()
        new = sorted(set(listed) - _reviewed())
        self.assertEqual(
            new, [],
            "These routes name no tenant or scope helper in their handler and sit in neither _PLATFORM_ROUTES nor "
            "_OPERATOR_ORG_ROUTES. Gate the handler, add the route to a table, or read it and add it to "
            "tests/data/tenant_gate_reviewed.txt under the reason that fits:\n" + "\n".join(" ".join(r) for r in new))

    def test_a_listed_route_that_is_gated_now_comes_off_the_list(self):
        considered, listed = _listing()
        stale = sorted(_reviewed() - set(listed))
        self.assertEqual(
            stale, [],
            "These routes are on tests/data/tenant_gate_reviewed.txt and are gated now (or gone). Take them off the list:\n"
            + "\n".join(" ".join(r) for r in stale))

    def test_the_list_has_a_reason_for_every_group(self):
        text = (_ROOT / "tests" / "data" / "tenant_gate_reviewed.txt").read_text()
        groups = [b for b in text.split("\n\n") if b.strip() and not b.strip().startswith("# Routes whose handler")]
        self.assertGreaterEqual(len(groups), 4)
        for block in groups:
            first = block.strip().splitlines()[0]
            self.assertTrue(first.startswith("# "), "each group opens with the reason its routes need no gate in the handler:\n" + block[:120])


if __name__ == "__main__":
    unittest.main()
