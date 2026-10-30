#!/usr/bin/env python3
"""v7.4.6, issue #58: a server is not the client of its own clients.

The Linux agent reported every established TCP connection as an outbound peer. A connection the host
accepted shows the client's address and the client's source port, so the suggested dependencies pointed
the wrong way: the database "depended on" the app that queries it, on port 35192.

Three places are held here, each through the real code and not through a copy of its rule:
  * the agent's collector, on both of its branches (psutil and `ss`), with the sockets of that case;
  * the heartbeat: an empty list replaces the last sample, no list keeps it;
  * the server's suggestions, for what an agent from before 7.4.6 still reports.
"""
import ast
import collections
import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v742_container_recovery import DEV, _Base, _Captured, _Stdin, api  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server" / "cgi-bin"))
import peer_direction  # noqa: E402


def _load_agent():
    spec = importlib.util.spec_from_file_location("rpagent_v746_peers", ROOT / "client" / "remotepower-agent.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── the sockets of the reporter's case ─────────────────────────────────────────────────────────────────
# This host (10.0.0.1) is a database server: it listens on 22 and 5432. An app (10.0.0.9) and a laptop
# (10.0.0.77) are connected to it. It is itself a client of a cache (10.0.0.2:6379) and of a public host.

Addr = collections.namedtuple("Addr", "ip port")
Conn = collections.namedtuple("Conn", "status laddr raddr")


def sock(status, lport, rip=None, rport=None):
    return Conn(status, Addr("10.0.0.1", lport), Addr(rip, rport) if rip else ())


PSUTIL_SOCKETS = [
    sock("LISTEN", 22),
    sock("LISTEN", 5432),
    sock("ESTABLISHED", 5432, "10.0.0.9", 35192),  # the app, accepted
    sock("ESTABLISHED", 5432, "10.0.0.9", 35193),  # the app, accepted
    sock("ESTABLISHED", 22, "10.0.0.77", 50122),  # the laptop, accepted
    sock("ESTABLISHED", 41000, "10.0.0.2", 6379),  # to the cache, opened here
    sock("ESTABLISHED", 41001, "10.0.0.2", 6379),  # to the cache, opened here
    sock("ESTABLISHED", 41002, "8.8.8.8", 443),  # to a public host: never reported
    sock("TIME_WAIT", 41003, "10.0.0.2", 6379),
]

SS_LISTENING = """State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
LISTEN 0      128          0.0.0.0:22         0.0.0.0:*
LISTEN 0      128             [::]:22            [::]:*
LISTEN 0      244          0.0.0.0:5432       0.0.0.0:*
LISTEN 0      128                *:9100             *:*
"""

SS_ESTABLISHED = """Recv-Q Send-Q Local Address:Port Peer Address:Port Process
0      0          10.0.0.1:5432      10.0.0.9:35192
0      0          10.0.0.1:5432      10.0.0.9:35193
0      0          10.0.0.1:22        10.0.0.77:50122
0      0          10.0.0.1:41000     10.0.0.2:6379
0      0          10.0.0.1:41001     10.0.0.2:6379
0      0          10.0.0.1:41002     8.8.8.8:443
0      0  [::ffff:10.0.0.1]:5432 [::ffff:10.0.0.9]:35194
"""

OUTBOUND_ONLY = [{"ip": "10.0.0.2", "port": 6379, "count": 2}]


def ss_runner(listening=SS_LISTENING, established=SS_ESTABLISHED):
    def run(cmd, *a, **k):
        if cmd == ["ss", "-tln"]:
            return listening
        if cmd == ["ss", "-tn", "state", "established"]:
            return established
        raise AssertionError(f"the collector asked for {cmd}")

    return run


class TestTheAgentLeavesOutWhatItAccepted(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.agent = _load_agent()

    def psutil_peers(self, sockets=PSUTIL_SOCKETS, **kw):
        fake = mock.Mock()
        fake.net_connections.return_value = list(sockets)
        with mock.patch.object(self.agent, "_PSUTIL", True), mock.patch.object(self.agent, "_psutil", fake, create=True):
            return self.agent.collect_peer_connections(**kw)

    def ss_peers(self, **kw):
        runner = kw.pop("runner", None) or ss_runner()
        with mock.patch.object(self.agent, "_PSUTIL", False), mock.patch.object(
            self.agent.subprocess, "check_output", runner
        ):
            return self.agent.collect_peer_connections(**kw)

    def test_psutil_branch_reports_only_the_connections_the_host_opened(self):
        self.assertEqual(self.psutil_peers(), OUTBOUND_ONLY)

    def test_ss_branch_reports_only_the_connections_the_host_opened(self):
        self.assertEqual(self.ss_peers(), OUTBOUND_ONLY)

    def test_both_branches_agree(self):
        self.assertEqual(self.psutil_peers(), self.ss_peers())

    def test_a_connection_to_the_hosts_own_address_is_still_reported_once(self):
        """The host connecting to a service of its own is outbound here (the server drops a peer that
        is the host itself); its accepted half is the one left out."""
        socks = [
            sock("LISTEN", 5432),
            sock("ESTABLISHED", 41000, "10.0.0.1", 5432),
            sock("ESTABLISHED", 5432, "10.0.0.1", 41000),
        ]
        self.assertEqual(self.psutil_peers(socks), [{"ip": "10.0.0.1", "port": 5432, "count": 1}])

    def test_the_limit_still_applies(self):
        socks = [sock("ESTABLISHED", 40000 + i, f"10.0.1.{i}", 80) for i in range(1, 6)]
        self.assertEqual(len(self.psutil_peers(socks, limit=3)), 3)

    def test_most_connected_peer_first(self):
        socks = [sock("ESTABLISHED", 40000, "10.0.0.2", 80)] + [
            sock("ESTABLISHED", 40001 + i, "10.0.0.3", 443) for i in range(3)
        ]
        self.assertEqual([r["ip"] for r in self.psutil_peers(socks)], ["10.0.0.3", "10.0.0.2"])

    def test_a_successful_read_with_no_outbound_connection_is_an_empty_list(self):
        """An answer, not a failure: it has to reach the server, which would otherwise keep the clients an
        older agent reported for this host."""
        only_listening = [sock("LISTEN", 22), sock("ESTABLISHED", 22, "10.0.0.77", 50122)]
        self.assertEqual(self.psutil_peers(only_listening), [])
        self.assertEqual(self.ss_peers(runner=ss_runner(established=SS_ESTABLISHED.split("\n")[0] + "\n0 0 10.0.0.1:22 10.0.0.77:50122\n")), [])

    def test_a_read_that_fails_is_none_and_not_an_empty_list(self):
        def boom(*a, **k):
            raise FileNotFoundError("ss")

        self.assertIsNone(self.ss_peers(runner=boom))
        fake = mock.Mock()
        fake.net_connections.side_effect = RuntimeError("denied")
        with mock.patch.object(self.agent, "_PSUTIL", True), mock.patch.object(self.agent, "_psutil", fake, create=True):
            self.assertIsNone(self.agent.collect_peer_connections())

    def test_a_listening_read_that_fails_is_none_too(self):
        """Without the listening ports there is no telling accepted from opened, so nothing is reported."""
        def only_established(cmd, *a, **k):
            if cmd == ["ss", "-tln"]:
                raise OSError("no")
            return SS_ESTABLISHED

        self.assertIsNone(self.ss_peers(runner=only_established))

    def test_the_heartbeat_sends_an_empty_answer_and_nothing_for_a_failed_read(self):
        """The decision lives in the agent's main loop, which is too large to run here, so this reads its
        syntax: the branch that stores the sample is guarded by `is not None`, not by truthiness."""
        tree = ast.parse((ROOT / "client" / "remotepower-agent.py").read_text())
        guards = []
        for node in ast.walk(tree):
            if isinstance(node, ast.If) and any(
                isinstance(n, ast.Assign)
                and any(
                    isinstance(t, ast.Subscript)
                    and isinstance(t.slice, ast.Constant)
                    and t.slice.value == "peer_conns"
                    for t in n.targets
                )
                for n in node.body
            ):
                guards.append(ast.unparse(node.test))
        self.assertEqual(guards, ["_peers is not None"])


class TestTheTwinStaysInStep(unittest.TestCase):
    def test_the_extensionless_agent_matches(self):
        self.assertEqual((ROOT / "client/remotepower-agent.py").read_bytes(), (ROOT / "client/remotepower-agent").read_bytes())


# ── the server's rule ─────────────────────────────────────────────────────────────────────────────────

def tcp_rows(*ports, udp=()):
    return [{"proto": "tcp", "port": p, "process": "x", "addr": "0.0.0.0", "scope": "lan"} for p in ports] + [
        {"proto": "udp", "port": p, "process": "x", "addr": "0.0.0.0", "scope": "lan"} for p in udp
    ]


class TestWhichPortsAreASourcePort(unittest.TestCase):
    """The rule, as a table. The cases that must NOT fire matter as much as the one that must."""

    def host(self, rows):
        return {"sysinfo": {"listening_ports": rows}}

    def test_an_ephemeral_port_the_host_does_not_list_is_a_source_port(self):
        self.assertTrue(peer_direction.is_client_source_port(self.host(tcp_rows(22, 8080)), 35192))

    def test_a_port_the_host_lists_is_a_service(self):
        self.assertFalse(peer_direction.is_client_source_port(self.host(tcp_rows(22, 35192)), 35192))

    def test_a_udp_listener_does_not_make_a_tcp_port_a_service(self):
        self.assertTrue(peer_direction.is_client_source_port(self.host(tcp_rows(22, udp=(35192,))), 35192))

    def test_a_tcp6_row_counts_as_tcp(self):
        rows = [{"proto": "tcp6", "port": 35192}, {"proto": "tcp", "port": 22}]
        self.assertFalse(peer_direction.is_client_source_port(self.host(rows), 35192))

    def test_a_low_port_is_never_taken_for_a_source_port(self):
        """A published container port or a port forward has no listening socket on the host."""
        self.assertFalse(peer_direction.is_client_source_port(self.host(tcp_rows(22)), 8443))
        self.assertFalse(peer_direction.is_client_source_port(self.host(tcp_rows(22)), 443))

    def test_the_boundary_is_the_start_of_the_linux_ephemeral_range(self):
        rows = self.host(tcp_rows(22))
        self.assertFalse(peer_direction.is_client_source_port(rows, 32767))
        self.assertTrue(peer_direction.is_client_source_port(rows, 32768))
        self.assertTrue(peer_direction.is_client_source_port(rows, 65535))
        self.assertFalse(peer_direction.is_client_source_port(rows, 65536))

    def test_what_is_not_known_is_never_a_source_port(self):
        for device in (None, {}, {"sysinfo": None}, {"sysinfo": {}}, {"sysinfo": {"listening_ports": None}},
                       {"sysinfo": {"listening_ports": "junk"}}, {"sysinfo": {"listening_ports": []}}, "host", 5):
            self.assertFalse(peer_direction.is_client_source_port(device, 35192), device)

    def test_a_list_that_may_have_been_cut_is_not_trusted(self):
        """The agent keeps the 80 lowest ports. 79 are a whole list and 80 may be a cut one."""
        self.assertTrue(peer_direction.is_client_source_port(self.host(tcp_rows(*range(1, 80))), 35192))
        self.assertFalse(peer_direction.is_client_source_port(self.host(tcp_rows(*range(1, 81))), 35192))

    def test_a_row_that_cannot_be_read_makes_the_whole_list_unknown(self):
        """A list with a hole in it cannot say that a port is absent. Each of these is one bad row among
        good ones, and each must neither raise nor decide."""
        good = {"proto": "tcp", "port": 22}
        for bad in (None, 3, "x", {"proto": "tcp"}, {"proto": "tcp", "port": "nope"}, {"proto": None, "port": 5},
                    {"port": 5}, {"proto": "tcp", "port": float("inf")}, {"proto": "tcp", "port": 0},
                    {"proto": "tcp", "port": 70000}, {"proto": "tcp", "port": -1}):
            rows = self.host([good, bad])
            self.assertIsNone(peer_direction.listening_tcp_ports(rows), bad)
            self.assertFalse(peer_direction.is_client_source_port(rows, 35192), bad)

    def test_other_spellings_of_a_valid_row_are_read(self):
        rows = [{"proto": "TCP", "port": 22}, {"proto": "tcp6", "port": "8080"}, {"proto": "udp", "port": 53.0}]
        self.assertEqual(peer_direction.listening_tcp_ports(self.host(rows)), {22, 8080})

    def test_a_port_that_is_not_a_number_is_not_a_source_port(self):
        for port in (None, "", "abc", float("nan"), float("inf"), [], {}):
            self.assertFalse(peer_direction.is_client_source_port(self.host(tcp_rows(22)), port), port)


class _Suggestions(_Base):
    """The real suggestion function over a small fleet. The caller is an administrator."""

    def setUp(self):
        super().setUp()
        self._saved = {n: getattr(api, n) for n in ("verify_token", "get_token_from_request")}
        api.verify_token = lambda t: ("jakob", "admin")
        api.get_token_from_request = lambda: "t"
        api.save(api.DEP_DISMISS_FILE, {})
        api.save(api.PEER_CONNS_FILE, {})

    def tearDown(self):
        for n, v in self._saved.items():
            setattr(api, n, v)
        for f in (api.PEER_CONNS_FILE, api.DEVICES_FILE, api.DEP_DISMISS_FILE):
            api.save(f, {})
        api._LOAD_CACHE.clear()
        super().tearDown()

    def fleet(self, hosts):
        api.save(api.DEVICES_FILE, hosts)
        api._LOAD_CACHE.clear()

    def peers(self, who, *rows):
        with api._LockedUpdate(api.PEER_CONNS_FILE) as store:
            store[who] = {"ts": 1, "peers": [{"ip": ip, "port": port, "count": n} for ip, port, n in rows]}
        api._LOAD_CACHE.clear()

    def edges(self):
        return sorted((s["device_id"], s["upstream_id"], tuple(s["ports"]), s["connections"])
                      for s in api._dependency_suggestions())


def host(name, ip, tcp=None, **extra):
    d = {"name": name, "ip": ip}
    if tcp is not None:
        d["sysinfo"] = {"listening_ports": tcp_rows(*tcp)}
    d.update(extra)
    return d


class TestTheSuggestionsPointTheRightWay(_Suggestions):

    def setUp(self):
        super().setUp()
        # db listens on 22 and 5432; app on 22 and 8080. The app queries the database.
        self.fleet({"db": host("db", "10.0.0.1", [22, 5432]), "app": host("app", "10.0.0.9", [22, 8080])})

    def test_the_reporters_case_the_database_is_not_the_apps_client(self):
        self.peers("db", ("10.0.0.9", 35192, 2))  # the app's connection, as an older agent reported it
        self.peers("app", ("10.0.0.1", 5432, 3))  # what the app really depends on
        self.assertEqual(self.edges(), [("app", "db", (5432,), 3)])

    def test_the_same_data_reads_the_other_way_without_the_rule(self):
        """The control. Remove the rule and the database appears as the app's client again."""
        self.peers("db", ("10.0.0.9", 35192, 2))
        self.peers("app", ("10.0.0.1", 5432, 3))
        with mock.patch.object(api.peer_direction_mod, "is_client_source_port", lambda d, p: False):
            self.assertEqual(self.edges(), [("app", "db", (5432,), 3), ("db", "app", (35192,), 2)])

    def test_only_the_artifact_goes_when_a_real_port_comes_from_the_same_host(self):
        """db really uses a service of the app (8080) and also has the app's clients' ports in its list."""
        self.peers("db", ("10.0.0.9", 35192, 2), ("10.0.0.9", 8080, 4))
        self.assertEqual(self.edges(), [("db", "app", (8080,), 4)])

    def test_a_host_that_sent_no_listing_keeps_the_suggestion(self):
        """An agentless host or an older agent: nothing says which way it ran, so the operator is asked."""
        self.fleet({"db": host("db", "10.0.0.1", [22, 5432]), "app": host("app", "10.0.0.9")})
        self.peers("db", ("10.0.0.9", 35192, 2))
        self.assertEqual(self.edges(), [("db", "app", (35192,), 2)])

    def test_a_cut_listing_keeps_the_suggestion(self):
        self.fleet({"db": host("db", "10.0.0.1", [22]), "app": host("app", "10.0.0.9", list(range(1, 81)))})
        self.peers("db", ("10.0.0.9", 35192, 2))
        self.assertEqual(self.edges(), [("db", "app", (35192,), 2)])

    def test_a_service_on_a_high_port_that_the_host_lists_stays(self):
        self.fleet({"db": host("db", "10.0.0.1", [22]), "app": host("app", "10.0.0.9", [22, 35192])})
        self.peers("db", ("10.0.0.9", 35192, 2))
        self.assertEqual(self.edges(), [("db", "app", (35192,), 2)])

    def test_a_low_port_the_host_does_not_list_stays(self):
        """A published container port or a port forward: no listening socket, still a real service."""
        self.peers("db", ("10.0.0.9", 8443, 2))
        self.assertEqual(self.edges(), [("db", "app", (8443,), 2)])

    def test_a_udp_listener_on_that_port_does_not_save_it(self):
        api.save(api.DEVICES_FILE, {"db": host("db", "10.0.0.1", [22]),
                                    "app": {"name": "app", "ip": "10.0.0.9",
                                            "sysinfo": {"listening_ports": tcp_rows(22, udp=(35192,))}}})
        api._LOAD_CACHE.clear()
        self.peers("db", ("10.0.0.9", 35192, 2))
        self.assertEqual(self.edges(), [])

    def test_junk_listing_does_not_break_the_page(self):
        for junk in ("junk", [None, 3, {"proto": "tcp", "port": "x"}], {"a": 1}):
            self.fleet({"db": host("db", "10.0.0.1", [22]),
                        "app": {"name": "app", "ip": "10.0.0.9", "sysinfo": {"listening_ports": junk}}})
            self.peers("db", ("10.0.0.9", 35192, 2))
            self.assertEqual(self.edges(), [("db", "app", (35192,), 2)], junk)

    def test_an_accepted_edge_and_a_dismissed_one_behave_as_before(self):
        self.fleet({"db": host("db", "10.0.0.1", [22, 5432], depends_on=["app"]), "app": host("app", "10.0.0.9", [22])})
        self.peers("db", ("10.0.0.9", 8080, 1))
        self.assertEqual(self.edges(), [])


class TestTheHeartbeatKeepsOrReplacesTheSample(_Suggestions):
    """The contract the agent relies on: a list replaces the stored sample, an absent field keeps it."""

    def report(self, **body):
        raw = json.dumps(dict({"device_id": DEV, "token": "tok"}, **body)).encode()
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
            return
        self.fail("the heartbeat did not answer")

    def stored(self):
        api._LOAD_CACHE.clear()
        return [(p["ip"], p["port"]) for p in ((api.load(api.PEER_CONNS_FILE) or {}).get(DEV) or {}).get("peers") or []]

    def test_a_list_replaces_the_sample_and_an_empty_list_clears_it(self):
        self.report(peer_conns=[{"ip": "10.0.0.9", "port": 35192, "count": 2}])
        self.assertEqual(self.stored(), [("10.0.0.9", 35192)])
        self.report(peer_conns=[])
        self.assertEqual(self.stored(), [])

    def test_a_report_without_the_field_keeps_the_last_sample(self):
        self.report(peer_conns=[{"ip": "10.0.0.2", "port": 6379, "count": 2}])
        self.report()
        self.assertEqual(self.stored(), [("10.0.0.2", 6379)])


class TestFromTheAgentToTheSuggestion(_Suggestions):
    """The reporter's two hosts, end to end: the real collector on each host's sockets, the real heartbeat,
    the real suggestions. The server's own host is DEV; the app and the cache are the hosts it meets."""

    def setUp(self):
        super().setUp()
        self.agent = _load_agent()
        # DEV is the database host of PSUTIL_SOCKETS; it keeps the record the base class made for it.
        with api._LockedUpdate(api.DEVICES_FILE) as devs:
            devs[DEV] = dict(host("serverbox", "10.0.0.1", [22, 5432]), token="tok", last_seen=2**31,
                             enrolled=1, monitored=True, tags=[], group="")
            devs["app"] = host("app", "10.0.0.9", [22, 8080])
            devs["cache"] = host("cache", "10.0.0.2", [22, 6379])
        api._LOAD_CACHE.clear()

    def collect(self):
        fake = mock.Mock()
        fake.net_connections.return_value = list(PSUTIL_SOCKETS)
        with mock.patch.object(self.agent, "_PSUTIL", True), mock.patch.object(self.agent, "_psutil", fake, create=True):
            return self.agent.collect_peer_connections(50)

    def send(self, rows):
        raw = json.dumps({"device_id": DEV, "token": "tok", "peer_conns": rows}).encode()
        os.environ.update({"REQUEST_METHOD": "POST", "PATH_INFO": "/api/heartbeat", "QUERY_STRING": "",
                           "CONTENT_LENGTH": str(len(raw))})
        api.sys.stdin = _Stdin(raw)
        api._LOAD_CACHE.clear()
        try:
            api.handle_heartbeat()
        except _Captured as c:
            self.assertEqual(c.status, 200, c.body)
            return
        self.fail("the heartbeat did not answer")

    def test_an_updated_agent_gives_one_suggestion_the_right_way(self):
        self.send(self.collect())
        self.assertEqual([(s["device_id"], s["upstream_id"]) for s in api._dependency_suggestions()], [(DEV, "cache")])

    def test_an_older_agent_gives_the_same_suggestion_through_the_servers_rule(self):
        """What the collector sent before 7.4.6: every established connection, the accepted ones too."""
        older = [{"ip": "10.0.0.9", "port": 35192, "count": 1}, {"ip": "10.0.0.9", "port": 35193, "count": 1},
                 {"ip": "10.0.0.2", "port": 6379, "count": 2}]
        self.send(older)
        self.assertEqual([(s["device_id"], s["upstream_id"]) for s in api._dependency_suggestions()], [(DEV, "cache")])


if __name__ == "__main__":
    unittest.main()
