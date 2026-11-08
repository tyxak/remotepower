#!/usr/bin/env python3
"""8.0.0: properties of the new pure code, generated.

The new modules take what a host, a person or a model sends, and they promise things: never raise, keep what you keep inside a bound, give back what you were given. An example
test states one input and one answer. A property states the promise and Hypothesis looks for the input that breaks it: a number of three hundred digits (`float()` of it raises),
a string for which `isdigit()` is true and `int()` raises, a list nested ten deep. It found the two defects listed at the end of each class below.

  * traffic.py: the cleaners of a host's sample and of the watch list, the merge into a host's record, which matches are due an alert, the fleet's sum.
  * the agent's `ss` reader (client/remotepower-agent.py): what it does with text it was never meant to read.
  * app_catalog: what an agent says it found, and the round trip from what the agent sends to what the server keeps.
  * image_autoupdate: the stored policy and the policy a request asks for, the fingerprint, the plan.
  * protocol_probes.run: a monitor of any shape is a result and never an exception, and nothing is connected to when nothing resolves.
  * mcp_http: any JSON-RPC message, and the tools with any arguments, whatever the server answers.

CI does not install hypothesis (see test_hypothesis_props.py), so this skips there and runs where the property tools are.
"""
import importlib.machinery
import importlib.util
import ipaddress
import json
import os
import socket
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-props-"))
_TESTS = Path(__file__).resolve().parent
_ROOT = _TESTS.parent
sys.path.insert(0, str(_ROOT / "server" / "cgi-bin"))

try:
    from hypothesis import HealthCheck, given, settings
    from hypothesis import strategies as st
except ImportError:                                           # pragma: no cover
    raise unittest.SkipTest("hypothesis is not installed")

import app_catalog  # noqa: E402
import image_autoupdate as IA  # noqa: E402
import mcp_http as M  # noqa: E402
import protocol_probes as PP  # noqa: E402
import traffic as T  # noqa: E402

FAST = settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])

# any JSON a client could send, including numbers a float cannot hold and keys that are not words
SCALARS = st.none() | st.booleans() | st.integers() | st.floats() | st.text(max_size=60)
JSON = st.recursive(SCALARS, lambda c: st.lists(c, max_size=6) | st.dictionaries(st.text(max_size=10), c, max_size=6), max_leaves=30)

IPS = st.one_of(st.ip_addresses(v=4).map(str), st.ip_addresses(v=6).map(str), st.text(max_size=30))
ROW = st.fixed_dictionaries(
    {"d": st.sampled_from(["in", "out"]) | JSON, "ip": IPS | JSON, "port": st.integers(-5, 70000) | JSON, "proc": st.text(max_size=80) | JSON,
     "n": st.integers(-5, 10**8) | JSON, "tx": st.integers(-5, 2**52) | JSON, "rx": st.integers(-5, 2**52) | JSON}
)
SAMPLE = st.one_of(
    JSON,
    st.fixed_dictionaries({"win": st.floats(-10, 5000) | JSON, "rows": st.lists(ROW | JSON, max_size=40) | JSON},
                          optional={"other": JSON, "conns": JSON, "trunc": JSON, "err": st.sampled_from(list(T.ERRORS)) | JSON}),
)
GOOD_ROW = ROW.map(T.clean_row).filter(lambda r: r is not None)
WATCH_ENTRY = st.fixed_dictionaries({"kind": st.sampled_from(list(T.WATCH_KINDS)) | JSON, "value": st.text(max_size=40) | st.integers() | JSON, "label": st.text(max_size=80) | JSON})
GOOD_WATCH = st.lists(WATCH_ENTRY, max_size=12).map(lambda w: T.clean_watch(w)[0])
# digits of other scripts and the superscripts, which str.isdigit() accepts and int() may refuse: random text almost never makes a port of them, so a strategy builds one
DIGITISH = st.text(alphabet=list("0123456789\u00b2\u00b3\u0661\u0663\uff11"), max_size=7)


class TestTrafficRules(unittest.TestCase):

    @FAST
    @given(JSON)
    def test_a_row_is_a_row_or_nothing_and_a_row_is_its_own_clean_form(self, raw):
        got = T.clean_row(raw)
        if got is None:
            return
        self.assertEqual(sorted(got), ["d", "ip", "n", "port", "proc", "rx", "tx"])
        self.assertIn(got["d"], ("in", "out"))
        a = ipaddress.ip_address(got["ip"])
        self.assertFalse(a.is_loopback or a.is_unspecified or a.is_multicast)
        self.assertTrue(0 < got["port"] < 65536 and got["n"] >= 1 and got["tx"] >= 0 and got["rx"] >= 0)
        self.assertTrue(all(32 <= ord(c) < 127 for c in got["proc"]) and len(got["proc"]) <= 48)
        self.assertEqual(T.clean_row(got), got, "cleaning twice is cleaning once")

    @FAST
    @given(SAMPLE, st.integers(0, 4 * 10**9))
    def test_a_sample_is_bounded_and_adds_up_whatever_the_host_sent(self, raw, now):
        got = T.clean_sample(raw, now)
        if got is None:
            return
        self.assertLessEqual(len(got["rows"]), T.MAX_ROWS)
        self.assertTrue(all(T.clean_row(r) == r for r in got["rows"]))
        self.assertEqual(got["tx"], sum(r["tx"] for r in got["rows"]) + got["other"]["tx"])
        self.assertEqual(got["rx"], sum(r["rx"] for r in got["rows"]) + got["other"]["rx"])
        self.assertTrue(all(isinstance(v, int) and v >= 0 for v in got["other"].values()))
        self.assertTrue(1 <= got["win"] <= 3600 and got["at"] == now)
        self.assertTrue("err" not in got or got["err"] in T.ERRORS)
        rows = [(-(r["tx"] + r["rx"]), -r["n"]) for r in got["rows"]]
        self.assertEqual(rows, sorted(rows), "the busiest first")

    @FAST
    @given(JSON, SAMPLE, st.integers(1, 4 * 10**9))
    def test_a_record_stays_inside_its_bounds_whatever_it_started_as(self, prev, raw, now):
        sample = T.clean_sample(raw, now)
        if sample is None:
            return
        rec = T.merge(prev, sample, now)
        self.assertTrue(len(rec["series"]) <= T.SERIES_MAX and all(isinstance(p, list) and len(p) == 4 for p in rec["series"]))
        self.assertTrue(len(rec["seen"]) <= T.SEEN_MAX and all(isinstance(k, str) and isinstance(v, int) for k, v in rec["seen"].items()))
        self.assertTrue(isinstance(rec["first"], int) and rec["at"] == now and rec["sample"] is sample)
        again = T.merge(rec, sample, now)
        self.assertTrue(len(again["series"]) <= T.SERIES_MAX and len(again["seen"]) <= T.SEEN_MAX, "and a record made from a record")

    @FAST
    @given(JSON)
    def test_a_watch_list_is_refused_whole_or_kept_whole_and_in_its_clean_form(self, raw):
        entries, err = T.clean_watch(raw)
        self.assertTrue(entries == [] or err == "", "nothing is kept when there is a message")
        self.assertLessEqual(len(entries), T.MAX_WATCH)
        for e in entries:
            self.assertIn(e["kind"], T.WATCH_KINDS)
            self.assertTrue(e["value"] and len(e["label"]) <= 60)
        self.assertEqual(T.clean_watch(entries), (entries, ""), "cleaning twice is cleaning once")

    @FAST
    @given(st.lists(st.fixed_dictionaries({"kind": st.just("port"), "value": DIGITISH}), max_size=6))
    def test_a_port_entry_made_of_digit_like_characters_is_a_port_or_a_message(self, raw):
        entries, err = T.clean_watch(raw)
        for e in entries:
            self.assertTrue(e["value"].isascii() and 0 < int(e["value"]) < 65536, e)
        self.assertTrue(entries == [] or err == "")

    @FAST
    @given(JSON, JSON)
    def test_a_match_is_never_an_exception_and_is_always_from_the_list(self, row, watch):
        got = T.watched(row, watch) if isinstance(watch, list) else T.watched(row, [])
        self.assertTrue(isinstance(got, list) and all(h in (watch if isinstance(watch, list) else []) for h in got))

    @FAST
    @given(JSON, st.lists(GOOD_ROW, max_size=30), GOOD_WATCH, st.integers(0, 4 * 10**9))
    def test_what_is_due_an_alert_is_bounded_matches_and_is_due_once(self, alerted, rows, watch, now):
        hits, keep = T.due_hits(alerted, rows, watch, now)
        self.assertLessEqual(len(hits), T.ALERT_MAX)
        self.assertLessEqual(len(keep), T.ALERTED_MAX)
        for row, entry in hits:
            self.assertIn(entry, T.watched(row, watch))
        again, _ = T.due_hits(keep, rows, watch, now)
        self.assertEqual(again, [], "what was just raised is not raised again with the same rows at the same time")

    @FAST
    @given(st.lists(st.tuples(st.text(max_size=8), st.text(max_size=8), SAMPLE.map(lambda s: T.clean_sample(s, 1) or s)), max_size=12), st.integers(0, 80))
    def test_the_fleet_sum_is_never_an_exception_and_respects_its_top(self, entries, top):
        got = T.fleet_summary(entries, top)
        self.assertTrue(len(got["remotes"]) <= top and len(got["programs"]) <= top and len(got["ports"]) <= top)
        self.assertTrue(all(v >= 0 for v in got["totals"].values()))

    @FAST
    @given(JSON)
    def test_a_name_and_a_scope_are_always_text_from_a_known_set(self, x):
        self.assertIsInstance(T.service_of(x), str)
        self.assertIn(T.scope_of(x), ("public", "private", "link-local", "multicast", "loopback", "unknown"))


def _agent():
    loader = importlib.machinery.SourceFileLoader("rp_agent_props", str(_ROOT / "client" / "remotepower-agent.py"))
    spec = importlib.util.spec_from_loader("rp_agent_props", loader)
    mod = importlib.util.module_from_spec(spec)               # type: ignore[arg-type]
    loader.exec_module(mod)
    return mod


# the characters that make a line of `ss` output, the digits of other scripts that str.isdigit() accepts and int() may refuse, and the words the reader looks for
SS_PIECES = st.sampled_from(list("0123456789:[]%.abcdefABCDEF /*\t\n-,\"()=_") + ["²", "³", "١", "٣", "ESTAB", "LISTEN", "users:((", "bytes_acked:", "bytes_received:", "::ffff:", "fe80::"])
SS_TEXT = st.lists(SS_PIECES, max_size=90).map("".join)
# a column that is an address and then a port made of characters str.isdigit() accepts: the reader reaches int(port) only after the address parsed, which random text almost never builds
PORTISH = st.text(alphabet=list("0123456789²³١٣"), max_size=7)
ADDR_COL = st.builds(lambda ip, port, bracket: ("[%s]:%s" % (ip, port)) if bracket else "%s:%s" % (ip, port), st.ip_addresses().map(str), PORTISH, st.booleans())


class TestTheAgentsReaderOfSs(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.agent = _agent()

    @FAST
    @given(ADDR_COL | SS_TEXT | st.text(max_size=120))
    def test_an_address_column_is_an_address_and_a_port_or_nothing(self, text):
        got = self.agent._ss_ip_port(text)
        if got is None:
            return
        ip, port = got
        ipaddress.ip_address(ip)
        self.assertTrue(isinstance(port, int) and 0 <= port <= 65535)

    @FAST
    @given(SS_TEXT | st.text(max_size=600) | st.lists(st.tuples(ADDR_COL, ADDR_COL, st.integers(0, 10**6)), max_size=8).map(
        lambda rows: "".join("0 0 %s %s\n\t cubic bytes_acked:%d\n" % (a, b, n) for a, b, n in rows)))
    def test_text_that_is_no_ss_output_is_read_without_an_exception(self, text):
        socks, trunc = self.agent._ss_sockets(text)
        self.assertTrue(isinstance(socks, list) and isinstance(trunc, bool))
        for lip, lport, rip, rport, prog, acked, _received in socks:
            ipaddress.ip_address(lip)
            ipaddress.ip_address(rip)
            self.assertTrue(0 <= lport <= 65535 and 0 <= rport <= 65535 and len(prog) <= 48)
            self.assertTrue(acked is None or acked >= 0)
        self.assertTrue(all(isinstance(p, int) and 0 <= p <= 65535 for p in self.agent._ss_listening(text)))

    @FAST
    @given(st.lists(st.tuples(st.sampled_from(["", "ESTAB ", "LISTEN "]), st.integers(0, 70000), st.integers(0, 70000), st.text(max_size=20), st.text(max_size=20)), max_size=20))
    def test_a_line_shaped_like_ss_never_gives_a_port_out_of_range(self, parts):
        text = "".join("%s0 0 %s:%d %s:%d\n\t cubic bytes_acked:%d\n" % (s, a, p, b, q, p) for s, p, q, a, b in parts)
        for _lip, lport, _rip, rport, _prog, _a, _r in self.agent._ss_sockets(text)[0]:
            self.assertTrue(0 <= lport <= 65535 and 0 <= rport <= 65535)


class TestTheCatalogAndTheRoundTrip(unittest.TestCase):

    @FAST
    @given(JSON)
    def test_what_an_agent_says_is_kept_only_if_the_catalog_knows_it_and_in_its_clean_form(self, raw):
        got = app_catalog.clean_found(raw)
        self.assertIsInstance(got, list)
        for f in got:
            self.assertIsNotNone(app_catalog.describe(f["id"]), "an id the catalog does not know is not kept")
        self.assertEqual(app_catalog.clean_found(got), got, "cleaning twice is cleaning once")

    @FAST
    @given(JSON, JSON, JSON)
    def test_discovery_never_raises_and_the_server_keeps_everything_the_agent_would_send(self, ports, containers, units):
        found = app_catalog.discover(ports, containers, units)
        self.assertIsInstance(found, list)
        self.assertEqual(app_catalog.clean_found(found), found, "the agent's own finding is accepted whole by the server's cleaner")

    @FAST
    @given(st.lists(st.builds(lambda a, p, c: "%s:%s->%s/tcp" % (a, p, c), st.sampled_from(["0.0.0.0", "::", ""]), DIGITISH, DIGITISH), max_size=4),
           st.sampled_from(["jellyfin/jellyfin", "nginx", "x"]))
    def test_a_published_port_made_of_digit_like_characters_is_a_port_or_nothing(self, ports, image):
        found = app_catalog.discover([], [{"name": "c", "image": image, "status": "Up", "ports": ports}], [])
        self.assertIsInstance(found, list)
        for f in found:
            self.assertTrue(f["port"] is None or 0 < f["port"] < 65536, f)

    @FAST
    @given(JSON)
    def test_describing_any_id_is_an_entry_or_none(self, app_id):
        d = app_catalog.describe(app_id)
        self.assertTrue(d is None or d["id"] == app_id)


class TestTheImageUpdatePolicy(unittest.TestCase):

    @FAST
    @given(JSON)
    def test_a_stored_policy_is_read_without_an_exception_and_is_its_own_reading(self, raw):
        got = IA.stored_policy(raw)
        self.assertIsInstance(got, dict)
        self.assertEqual(IA.stored_policy(got), got)
        if got.get("mode") == "on":
            self.assertTrue(got.get("images"), "on without a list reads as off: the loop never acts on half a policy")

    @FAST
    @given(JSON, JSON)
    def test_a_policy_a_request_asks_for_is_stored_as_it_will_be_read(self, raw, stored):
        """The base is the policy as stored, which the handler reads with stored_policy: a document with a key nobody defined never reaches clean_policy."""
        policy, err = IA.clean_policy(raw, IA.stored_policy(stored))
        self.assertTrue((policy is None) == bool(err) or isinstance(policy, dict))
        if isinstance(policy, dict) and not err:
            self.assertEqual(IA.stored_policy(policy), policy, "what is saved is what is read back")

    @FAST
    @given(JSON, st.lists(st.text(max_size=20), max_size=5))
    def test_matching_an_image_never_raises(self, ref, patterns):
        """The patterns are the policy's, which clean_policy and stored_policy have made lists of text; the reference is whatever a registry row held."""
        self.assertIsInstance(IA.match(ref, patterns), bool)

    @FAST
    @given(st.dictionaries(st.text(max_size=20), st.text(max_size=20), max_size=8), st.randoms())
    def test_the_fingerprint_does_not_depend_on_the_order_of_the_images(self, digests, rnd):
        items = list(digests.items())
        rnd.shuffle(items)
        self.assertEqual(IA.fingerprint(digests), IA.fingerprint(dict(items)))

    @FAST
    @given(JSON, JSON, JSON, JSON, st.booleans())
    def test_a_plan_over_any_state_is_a_list_and_never_an_exception(self, rows, devices, policy, receipts, active):
        got = IA.plan(rows if isinstance(rows, list) else [], devices if isinstance(devices, dict) else {}, IA.stored_policy(policy),
                      receipts if isinstance(receipts, dict) else {}, active)
        self.assertIsInstance(got, list)

    @FAST
    @given(JSON, JSON, st.integers(0, 4 * 10**9))
    def test_a_verdict_is_a_known_state_for_any_receipt_and_any_report(self, receipt, rec, now):
        state, detail = IA.verify(receipt if isinstance(receipt, dict) else {}, rec if isinstance(rec, dict) else {}, now)
        self.assertIsInstance(state, str)
        self.assertIsInstance(detail, str)
        state, detail = IA.verify_rollback(receipt if isinstance(receipt, dict) else {}, rec if isinstance(rec, dict) else {}, now)
        self.assertIsInstance(state, str)


class TestTheProbeRunner(unittest.TestCase):

    @FAST
    @given(st.sampled_from(list(PP.TYPES) + ["nope"]) | JSON, JSON, JSON, st.dictionaries(st.text(max_size=8), JSON, max_size=6))
    def test_a_monitor_of_any_shape_is_a_result_and_nothing_is_connected_to_when_nothing_resolves(self, mtype, host, port, m):
        used = []
        real = (socket.getaddrinfo, socket.create_connection, socket.socket)

        def refuse(*a, **k):
            used.append(a)
            raise socket.gaierror("no resolver in this test")
        socket.getaddrinfo, socket.create_connection, socket.socket = refuse, refuse, refuse
        try:
            ok, detail = PP.run(mtype, host, port, m, peer_ok=lambda a: False, timeout=1)
        finally:
            socket.getaddrinfo, socket.create_connection, socket.socket = real
        self.assertIs(ok, False)
        self.assertIsInstance(detail, str)


def _fetch_with(answer):
    def fetch(path, method="GET", body=None):
        if isinstance(answer, M.FetchError):
            raise answer
        return answer
    return fetch


class TestTheHostedMcpEndpoint(unittest.TestCase):
    TOOLS = [t["name"] for t in M.tool_listing()]

    @FAST
    @given(JSON)
    def test_a_protocol_version_asked_for_is_always_one_the_server_speaks(self, requested):
        self.assertIn(M.negotiate(requested), M.PROTOCOL_VERSIONS)

    @FAST
    @given(JSON, st.sampled_from([{}, [], {"devices": [], "alerts": [], "items": None}, "text", None]))
    def test_any_message_gets_a_status_and_an_answer_that_is_json(self, message, upstream):
        status, answer = M.handle(message, _fetch_with(upstream), "8.0.0")
        self.assertTrue(isinstance(status, int) and 200 <= status < 600)
        if answer is not None:
            json.dumps(answer)
            self.assertIsInstance(answer, (dict, list))

    @FAST
    @given(st.sampled_from(TOOLS), st.dictionaries(st.text(max_size=12), JSON, max_size=6) | JSON,
           st.sampled_from([{}, [], {"devices": [{"id": 1}], "alerts": None}, "text", None, M.FetchError(404, "gone"), M.FetchError(500, "boom")]))
    def test_a_tool_with_any_arguments_over_any_answer_is_an_answer_and_not_an_exception(self, name, args, upstream):
        msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}}
        status, answer = M.handle(msg, _fetch_with(upstream), "8.0.0")
        self.assertTrue(isinstance(status, int) and 200 <= status < 600)
        json.dumps(answer)


if __name__ == "__main__":
    unittest.main()
