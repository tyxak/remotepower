#!/usr/bin/env python3
"""v7.4.5, issue #55: the heartbeat grades the listeners of a host marked internal.

Everything here goes through the real heartbeat and the real port audit. A direct call to the helper
would skip the two places the feature can go wrong: where in the ingest the grade is applied (after the
merge of the fields an agent leaves out as unchanged, before the record is stored and audited), and which
record it reads the switch from.
"""
import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v742_container_recovery import DEV, _Base, _Captured, _Stdin, api  # noqa: E402

PRIVATE = ["192.168.1.20", "172.17.0.1"]
WITH_PUBLIC = ["192.168.1.20", "172.17.0.1", "203.0.113.9"]
WITH_V6 = ["192.168.1.20", "2a01:4f8::5"]


def ports(*extra):
    return [
        {"proto": "tcp", "port": 443, "process": "nginx", "addr": "0.0.0.0", "scope": "world"},
        {"proto": "tcp", "port": 22, "process": "sshd", "addr": "::", "scope": "world"},
        {"proto": "tcp", "port": 5432, "process": "postgres", "addr": "127.0.0.1", "scope": "local"},
        {"proto": "udp", "port": 53, "process": "adguard", "addr": "10.0.0.2", "scope": "lan"},
        *extra,
    ]


class _Internal(_Base):

    def setUp(self):
        super().setUp()
        api.save(api.PORT_BASELINE_FILE, {})
        api.save(api.CONFIG_FILE, {"port_audit_enabled": True})
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for f, empty in ((api.PORT_BASELINE_FILE, {}), (api.CONFIG_FILE, {}), (api.DEVICES_FILE, {}),
                         (api.ALERTS_FILE, {"alerts": []})):
            api.save(f, empty)
        api._LOAD_CACHE.clear()
        super().tearDown()

    def switch(self, on):
        with api._LockedUpdate(api.DEVICES_FILE) as devs:
            if on is None:
                devs[DEV].pop("exposure_internal", None)
            else:
                devs[DEV]["exposure_internal"] = on
        api._LOAD_CACHE.clear()

    def report(self, sysinfo, **body):
        """One heartbeat carrying this sysinfo, through the real handler."""
        raw = json.dumps(dict({"device_id": DEV, "token": "tok", "sysinfo": sysinfo}, **body)).encode()
        os.environ.update({"REQUEST_METHOD": "POST", "PATH_INFO": "/api/heartbeat", "QUERY_STRING": "",
                           "CONTENT_LENGTH": str(len(raw))})
        for k in ("HTTP_X_TOKEN", "HTTP_X_RP_VAULT_KEY"):
            os.environ.pop(k, None)
        api.sys.stdin = _Stdin(raw)
        api._LOAD_CACHE.clear()
        try:
            api.handle_heartbeat()
        except _Captured as c:
            self.assertEqual(c.status, 200, c.body)
            return c.body
        self.fail("the heartbeat did not answer")

    def stored(self):
        api._LOAD_CACHE.clear()
        return (api.load(api.DEVICES_FILE) or {})[DEV].get("sysinfo") or {}

    def rows(self):
        return {(r["proto"], r["port"]): r for r in self.stored().get("listening_ports") or []}

    def grades(self):
        return {k[1]: (r["scope"], bool(r.get("assumed"))) for k, r in self.rows().items()}

    def fired(self, event):
        return sorted(p.get("port") for e, p in self.events if e == event)


class TestTheGradeInTheStoredRecord(_Internal):

    def test_a_host_that_is_not_marked_keeps_what_the_agent_sent(self):
        self.report({"listening_ports": ports(), "host_addresses": PRIVATE})
        self.assertEqual(self.grades(), {443: ("world", False), 22: ("world", False), 5432: ("local", False),
                                         53: ("lan", False)})

    def test_a_marked_host_with_private_addresses_is_assumed_internal(self):
        self.switch(True)
        self.report({"listening_ports": ports(), "host_addresses": PRIVATE})
        self.assertEqual(self.grades(), {443: ("lan", True), 22: ("lan", True), 5432: ("local", False),
                                         53: ("lan", False)})
        self.assertEqual(self.stored()["host_addresses"], PRIVATE)

    def test_what_the_agent_graded_lan_or_local_is_never_called_an_assumption(self):
        self.switch(True)
        self.report({"listening_ports": ports(), "host_addresses": PRIVATE})
        self.assertNotIn("assumed", self.rows()[("tcp", 5432)])
        self.assertNotIn("assumed", self.rows()[("udp", 53)])

    def test_a_public_ipv4_address_keeps_the_listeners_world(self):
        self.switch(True)
        self.report({"listening_ports": ports(), "host_addresses": WITH_PUBLIC})
        self.assertEqual(self.grades()[443], ("world", False))
        self.assertEqual(self.grades()[22], ("world", False))

    def test_a_global_ipv6_address_keeps_the_listeners_world(self):
        self.switch(True)
        self.report({"listening_ports": ports(), "host_addresses": WITH_V6})
        self.assertEqual(self.grades()[443], ("world", False))

    def test_an_agent_that_does_not_report_addresses_keeps_them_world(self):
        """An older agent, or a Windows or macOS host: the switch has nothing to check, so it does nothing."""
        self.switch(True)
        self.report({"listening_ports": ports()})
        self.assertEqual(self.grades()[443], ("world", False))
        self.assertNotIn("host_addresses", self.stored())

    def test_junk_in_the_address_list_is_unknown_not_private(self):
        self.switch(True)
        for junk in ("10.0.0.5", {"a": "10.0.0.5"}, ["10.0.0.5", "nonsense"], ["10.0.0.5", None], [], 5, True,
                     ["10.0.0.5"] * 3 + [f"10.1.{i // 250}.{i % 250 + 1}" for i in range(80)]):
            self.report({"listening_ports": ports(), "host_addresses": junk})
            self.assertNotIn("host_addresses", self.stored() if junk != [] else {}, repr(junk)[:40])
            self.assertEqual(self.grades()[443], ("world", False), repr(junk)[:40])

    def test_the_switch_is_read_from_the_stored_host(self):
        """Not from the report: a body that claims it is internal changes nothing."""
        self.report({"listening_ports": ports(), "host_addresses": PRIVATE, "exposure_internal": True},
                    exposure_internal=True)
        self.assertEqual(self.grades()[443], ("world", False))
        api._LOAD_CACHE.clear()
        self.assertNotIn("exposure_internal", (api.load(api.DEVICES_FILE) or {})[DEV])

    def test_only_a_real_true_counts(self):
        for odd in ("true", 1, "yes", [1]):
            self.switch(odd)
            self.report({"listening_ports": ports(), "host_addresses": PRIVATE})
            self.assertEqual(self.grades()[443], ("world", False), repr(odd))


class TestWhenSomethingChangesBetweenReports(_Internal):

    def test_a_public_address_that_appears_puts_the_listeners_back_and_raises_the_alarm(self):
        self.switch(True)
        self.report({"listening_ports": ports(), "host_addresses": PRIVATE})      # the baseline
        self.assertEqual(self.fired("port_exposed_world"), [], "nothing is world-exposed on first contact")
        self.events.clear()
        self.report({"listening_ports": ports(), "host_addresses": WITH_PUBLIC})
        self.assertEqual(self.grades()[443], ("world", False))
        self.assertTrue(all("assumed" not in r for r in self.rows().values()))
        self.assertEqual(self.fired("port_exposed_world"), [22, 443],
                         "the host is now reachable from outside: each wildcard listener is a new exposure")

    def test_the_agent_going_quiet_about_addresses_puts_them_back_too(self):
        self.switch(True)
        self.report({"listening_ports": ports(), "host_addresses": PRIVATE})
        self.assertEqual(self.grades()[443], ("lan", True))
        self.report({"listening_ports": ports()})
        self.assertEqual(self.grades()[443], ("world", False))

    def test_a_host_that_stays_internal_raises_no_world_alarm_and_still_sees_a_new_port(self):
        """The reporter's condition: new-listener detection stays on for an internal host."""
        self.switch(True)
        self.report({"listening_ports": ports(), "host_addresses": PRIVATE})
        self.events.clear()          # first contact reports every port as new; the baseline is what is wanted
        new = {"proto": "tcp", "port": 8080, "process": "docker-proxy", "addr": "0.0.0.0", "scope": "world"}
        self.report({"listening_ports": ports(new), "host_addresses": PRIVATE})
        self.assertEqual(self.grades()[8080], ("lan", True))
        self.assertEqual(self.fired("new_port_detected"), [8080])
        self.assertEqual(self.fired("port_exposed_world"), [], "assumed internal is not a world exposure")

    def test_the_same_new_port_on_a_host_that_is_not_marked_raises_both(self):
        """The control: with the switch off the new wildcard port is both new and world."""
        self.report({"listening_ports": ports(), "host_addresses": PRIVATE})
        self.events.clear()
        new = {"proto": "tcp", "port": 8080, "process": "docker-proxy", "addr": "0.0.0.0", "scope": "world"}
        self.report({"listening_ports": ports(new), "host_addresses": PRIVATE})
        self.assertEqual(self.fired("new_port_detected"), [8080])
        self.assertEqual(self.fired("port_exposed_world"), [8080])

    def test_turning_the_switch_on_closes_the_world_exposures_at_the_next_report(self):
        self.report({"listening_ports": ports(), "host_addresses": PRIVATE})
        self.events.clear()
        self.switch(True)
        self.report({"listening_ports": ports(), "host_addresses": PRIVATE})
        self.assertEqual(self.fired("port_unexposed"), [22, 443])

    def test_turning_it_off_again_makes_them_world_exposures_again(self):
        self.switch(True)
        self.report({"listening_ports": ports(), "host_addresses": PRIVATE})
        self.events.clear()
        self.switch(False)
        self.report({"listening_ports": ports(), "host_addresses": PRIVATE})
        self.assertEqual(self.grades()[443], ("world", False))
        self.assertEqual(self.fired("port_exposed_world"), [22, 443])


class TestTheFieldsAnAgentLeavesOut(_Internal):
    """A host that has not changed its ports sends none, and the server hands its stored rows back. The
    grade has to be applied to those rows too, or it would be frozen at whatever it was when they arrived."""

    def test_stored_rows_are_graded_again_when_the_agent_leaves_them_out(self):
        self.report({"listening_ports": ports(), "host_addresses": PRIVATE})
        self.switch(True)
        self.report({"host_addresses": PRIVATE}, sysinfo_omitted={"listening_ports": "h1"})
        self.assertEqual(self.grades()[443], ("lan", True), "the rows came from the store and were graded")

    def test_and_put_back_when_the_switch_is_turned_off(self):
        self.switch(True)
        self.report({"listening_ports": ports(), "host_addresses": PRIVATE})
        self.assertEqual(self.grades()[443], ("lan", True))
        self.switch(False)
        self.report({"host_addresses": PRIVATE}, sysinfo_omitted={"listening_ports": "h1"})
        self.assertEqual(self.grades(), {443: ("world", False), 22: ("world", False), 5432: ("local", False),
                                         53: ("lan", False)}, "exactly what the agent first sent")

    def test_a_partial_report_that_has_no_ports_keeps_the_stored_grade(self):
        self.switch(True)
        self.report({"listening_ports": ports(), "host_addresses": PRIVATE})
        self.report({"uptime": "up 3 days"}, sysinfo_partial=True)
        self.assertEqual(self.grades()[443], ("lan", True))
        self.assertEqual(self.stored()["host_addresses"], PRIVATE, "the addresses stay with the rows they vouch for")

    def test_the_addresses_are_not_among_the_fields_that_may_be_left_out(self):
        self.assertNotIn("host_addresses", api._DELTA_SYSINFO_FIELDS)


class TestTheOrderInTheIngest(unittest.TestCase):
    """A source pin on the one thing the behavioural tests above cannot name: the grade is applied after
    both merges and before the record is stored. Moving it fails them as well; this says why."""

    def test_the_grade_comes_after_the_merges_and_before_the_record_is_stored(self):
        from srcpin import py_function
        body = py_function(api_source(), "handle_heartbeat")
        merged = body.index("safe_si = _merged")
        graded = body.index("exposure_scope_mod.apply(dev.get('exposure_internal'), safe_si)")
        stored = body.index("dev['sysinfo'] = safe_si")
        omitted = body.index("_omit = body.get('sysinfo_omitted')")
        self.assertLess(omitted, graded)
        self.assertLess(merged, graded)
        self.assertLess(graded, stored)

    def test_nothing_else_writes_a_scope_onto_a_listening_port(self):
        """The grade has one writer. A second would be the half-applied rule this was built to avoid: the
        agent's rows are stored as sent, and only exposure_scope turns one into 'lan'. Every function of
        api.py that handles listening_ports is read, and none may assign a 'scope' subscript."""
        import ast
        tree = ast.parse((Path(api.__file__)).read_text())
        handling = []
        for fn in ast.walk(tree):
            if not isinstance(fn, ast.FunctionDef):
                continue
            mentions = any(isinstance(n, ast.Constant) and n.value == "listening_ports" for n in ast.walk(fn))
            if not mentions:
                continue
            handling.append(fn.name)
            for n in ast.walk(fn):
                targets = n.targets if isinstance(n, ast.Assign) else [n.target] if isinstance(n, ast.AugAssign) else []
                for t in targets:
                    self.assertFalse(isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant)
                                     and t.slice.value == "scope",
                                     f"{fn.name} assigns a 'scope'; go through exposure_scope.regrade")
        self.assertIn("handle_heartbeat", handling, "the population is not empty and holds the ingest")
        self.assertGreaterEqual(len(handling), 8, handling)


def api_source():
    from apisrc import api_source as _src
    return _src()


if __name__ == "__main__":
    unittest.main()
