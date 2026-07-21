"""v6.3.1 — agentless NetFlow/IPFIX flow receiver.

Parser (pure, both protocol families) + server ingest/read + the token/route
wiring, mirroring the syslog-receiver shape.
"""

import importlib.util
import ipaddress
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
_FLOW = _ROOT / "server" / "flow"
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(_FLOW))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-flow-"))

import flow_parse   # noqa: E402


def _v9_datagram(src, dst, sport, dport, proto, byts, pkts, source_id=7,
                 with_template=True):
    tfields = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 4), (2, 4)]
    tbody = struct.pack("!HH", 256, len(tfields))
    for ft, fl in tfields:
        tbody += struct.pack("!HH", ft, fl)
    tset = struct.pack("!HH", 0, 4 + len(tbody)) + tbody
    dbody = (ipaddress.IPv4Address(src).packed + ipaddress.IPv4Address(dst).packed
             + struct.pack("!HH", sport, dport) + struct.pack("!B", proto)
             + struct.pack("!II", byts, pkts))
    dset = struct.pack("!HH", 256, 4 + len(dbody)) + dbody
    hdr = struct.pack("!HHIIII", 9, 2, 0, 0, 1, source_id)
    return hdr + (tset + dset if with_template else dset)


class TestParser(unittest.TestCase):
    def test_netflow_v5(self):
        dg = flow_parse.build_v5([
            ("10.0.0.5", "8.8.8.8", 44321, 443, 6, 15000, 20),
            ("10.0.0.6", "1.1.1.1", 5353, 53, 17, 900, 3)])
        recs = flow_parse.parse(dg, "10.0.0.1", flow_parse.TemplateCache())
        self.assertEqual(len(recs), 2)
        self.assertEqual(recs[0], {"src": "10.0.0.5", "dst": "8.8.8.8",
                                   "sport": 44321, "dport": 443, "proto": 6,
                                   "bytes": 15000, "packets": 20})
        self.assertEqual(recs[1]["proto"], 17)

    def test_netflow_v9_template_then_data(self):
        recs = flow_parse.parse(
            _v9_datagram("192.168.1.10", "93.184.216.34", 51000, 443, 6, 54321, 42),
            "192.168.1.1", flow_parse.TemplateCache())
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["src"], "192.168.1.10")
        self.assertEqual(recs[0]["dport"], 443)
        self.assertEqual(recs[0]["bytes"], 54321)

    def test_v9_data_before_template_is_skipped_then_learned(self):
        tc = flow_parse.TemplateCache()
        # data-only (no template cached yet) → nothing
        data_only = _v9_datagram("10.1.1.2", "10.1.1.3", 1, 2, 6, 1, 1,
                                 with_template=False)
        self.assertEqual(flow_parse.parse(data_only, "10.1.1.1", tc), [])
        # a full datagram teaches the template
        flow_parse.parse(_v9_datagram("10.1.1.2", "10.1.1.3", 1, 2, 6, 1, 1),
                         "10.1.1.1", tc)
        # now the data-only datagram parses
        self.assertEqual(len(flow_parse.parse(data_only, "10.1.1.1", tc)), 1)

    def test_ipfix_v10(self):
        # IPFIX: template FlowSet id = 2 (not v9's 0); header is 16 bytes.
        tfields = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 4), (2, 4)]
        tbody = struct.pack("!HH", 256, len(tfields))
        for ft, fl in tfields:
            tbody += struct.pack("!HH", ft, fl)
        tset = struct.pack("!HH", 2, 4 + len(tbody)) + tbody   # set id 2 = template
        dbody = (ipaddress.IPv4Address("172.16.0.9").packed
                 + ipaddress.IPv4Address("8.8.4.4").packed
                 + struct.pack("!HH", 3000, 53) + struct.pack("!B", 17)
                 + struct.pack("!II", 200, 2))
        dset = struct.pack("!HH", 256, 4 + len(dbody)) + dbody
        body = tset + dset
        total = 16 + len(body)
        hdr = struct.pack("!HHIII", 10, total, 0, 1, 0)   # version 10, length, ...
        recs = flow_parse.parse(hdr + body, "172.16.0.1", flow_parse.TemplateCache())
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["dst"], "8.8.4.4")
        self.assertEqual(recs[0]["proto"], 17)

    def test_malformed_never_raises(self):
        tc = flow_parse.TemplateCache()
        for junk in (b"", b"\x00", b"\x00\x63short", b"\xff" * 40,
                     b"\x00\x09" + b"\x00" * 3):
            self.assertEqual(flow_parse.parse(junk, "x", tc), [])


class TestDaemonAggregate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "flowd", _FLOW / "remotepower-flowd.py")
        cls.flowd = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.flowd)

    def test_aggregate_top_talkers_and_protos(self):
        recs = [
            {"src": "10.0.0.5", "dst": "8.8.8.8", "sport": 4, "dport": 443,
             "proto": 6, "bytes": 15000, "packets": 20},
            {"src": "10.0.0.5", "dst": "1.1.1.1", "sport": 5, "dport": 53,
             "proto": 17, "bytes": 900, "packets": 3},
            {"src": "10.0.0.9", "dst": "8.8.8.8", "sport": 6, "dport": 443,
             "proto": 6, "bytes": 5000, "packets": 8}]
        agg = self.flowd._aggregate(recs)
        self.assertEqual(agg["total_bytes"], 20900)
        self.assertEqual(agg["flows"], 3)
        self.assertEqual(agg["talkers"][0]["ip"], "8.8.8.8")   # 20000 both flows
        self.assertEqual(agg["protos"]["tcp"], 20000)
        self.assertEqual(agg["protos"]["udp"], 900)
        self.assertEqual(agg["conversations"][0]["dport"], 443)


class TestServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("api_flow", _CGI / "api.py")
        cls.api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.api)

    def setUp(self):
        api = self.api
        api.save(api.DEVICES_FILE, {"d1": {"name": "router1", "ip": "10.0.0.1"}})
        api.save(api.FLOW_FILE, {})

    def _agg(self):
        return {"total_bytes": 20900, "total_packets": 31, "flows": 3,
                "talkers": [{"ip": "8.8.8.8", "bytes": 20000, "pkts": 28}],
                "conversations": [{"src": "10.0.0.5", "dst": "8.8.8.8",
                                   "dport": 443, "proto": 6, "bytes": 15000,
                                   "pkts": 20}],
                "protos": {"tcp": 20000, "udp": 900}}

    def test_ingest_caps_and_stores(self):
        self.api._ingest_flow("d1", self._agg())
        rec = self.api.load(self.api.FLOW_FILE)["d1"]
        self.assertEqual(rec["latest"]["total_bytes"], 20900)
        self.assertEqual(rec["latest"]["talkers"][0]["ip"], "8.8.8.8")
        self.assertEqual(len(rec["history"]), 1)

    def test_ingest_reclamps_hostile_sizes(self):
        big = {"talkers": [{"ip": "x" * 500, "bytes": -5}] * 100,
               "conversations": [{"src": "a", "dst": "b", "dport": 999999,
                                  "proto": 999, "bytes": 1}] * 100,
               "flows": -1, "total_bytes": -9}
        self.api._ingest_flow("d1", big)
        rec = self.api.load(self.api.FLOW_FILE)["d1"]["latest"]
        self.assertLessEqual(len(rec["talkers"]), 30)
        self.assertLessEqual(len(rec["conversations"]), 30)
        self.assertEqual(rec["talkers"][0]["bytes"], 0)      # negative clamped
        self.assertLessEqual(rec["conversations"][0]["dport"], 65535)
        self.assertLessEqual(rec["conversations"][0]["proto"], 255)
        self.assertLessEqual(len(rec["talkers"][0]["ip"]), 64)

    def test_ingest_garbage_shapes_dont_raise(self):
        for junk in (None, [], "x", {"talkers": "no"}, {"talkers": [1, "x"]}):
            self.api._ingest_flow("d1", junk)   # must not raise

    def test_routes_present(self):
        rows = [r for r in self.api._PATTERN_ROUTE_DEFS
                if "flow/in" in str(r) or "/flows" in str(r)]
        self.assertEqual(len(rows), 2, rows)

    def test_flow_token_kind_accepted(self):
        from tests import apisrc
        src = apisrc.api_source()
        self.assertIn("'alert', 'syslog', 'snmp_trap', 'flow'", src)

    def test_module_bound(self):
        self.assertEqual(self.api.handle_flow_in.__module__, "flow_handlers")
        self.assertEqual(self.api.handle_device_flows.__module__, "flow_handlers")


if __name__ == "__main__":
    unittest.main()
