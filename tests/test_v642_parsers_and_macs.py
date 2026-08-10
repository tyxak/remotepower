"""Three round-1 sweep findings whose common shape is "the data is collected,
stored, and read by nobody — or read wrongly".

  * the nftables parser's rule/header discriminator was `'{' not in line`, on a
    stated assumption that is false for anonymous sets;
  * two append-only logs were read from the START, so the parse froze on ancient
    content once the file grew past its cap;
  * duplicate-MAC detection read a device key that no device record has.
"""

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
_CLIENT = ROOT / "client"
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v642-parse-"))

_spec = importlib.util.spec_from_file_location("agent_v642_parse",
                                               _CLIENT / "remotepower-agent.py")
agent = importlib.util.module_from_spec(_spec)
sys.modules["agent_v642_parse"] = agent
_spec.loader.exec_module(agent)

# A firewalld-shaped ruleset: three of the five rules carry an anonymous set,
# and they are exactly the ones that open a port or allow a source.
NFT = """table inet filter {
\tchain input {
\t\ttype filter hook input priority 0; policy drop;
\t\tct state established,related accept # handle 3
\t\tiif "lo" accept # handle 4
\t\ttcp dport { 22, 80, 443 } accept # handle 6
\t\tip saddr { 10.0.0.0/8, 192.168.0.0/16 } accept # handle 7
\t\tmeta l4proto { icmp, ipv6-icmp } accept # handle 8
\t}
}"""


class TestNftAnonymousSets(unittest.TestCase):
    """`tcp dport { 22, 80, 443 } accept # handle 6` is a RULE that contains
    braces. The old discriminator dropped it from the inventory, from the
    deletable rule list, and from the `rules` count that `active` and the
    per-asset risk score derive from — so an operator auditing "what is open on
    this box" saw only the established/loopback rules and concluded nothing was
    exposed. Every firewalld host generates rules in this form."""

    def test_every_rule_is_parsed(self):
        got = agent._parse_nft_rules(NFT)
        self.assertEqual(len(got), 5, [r['text'] for r in got])
        for want in ('tcp dport { 22, 80, 443 } accept',
                     'ip saddr { 10.0.0.0/8, 192.168.0.0/16 } accept',
                     'meta l4proto { icmp, ipv6-icmp } accept'):
            self.assertIn(want, [r['text'] for r in got])

    def test_refs_are_still_exact(self):
        """The ref feeds `nft delete rule <ref>`; a wrong one deletes the wrong
        rule, so parsing more must not mean parsing loosely."""
        got = {r['text']: r['ref'] for r in agent._parse_nft_rules(NFT)}
        self.assertEqual(got['tcp dport { 22, 80, 443 } accept'],
                         'inet filter input handle 6')

    def test_container_headers_are_still_excluded(self):
        for header in ('table inet filter {', 'chain input {',
                       'set blocklist { # handle 2'):
            self.assertTrue(agent._nft_is_header(header.strip()), header)

    def test_rules_with_braces_are_not_headers(self):
        for rule in ('tcp dport { 22, 80, 443 } accept # handle 6',
                     'ct state { established, related } accept # handle 9'):
            self.assertFalse(agent._nft_is_header(rule.strip()), rule)

    def test_the_count_matches_the_parse(self):
        counted = sum(1 for l in NFT.splitlines()
                      if '# handle ' in l and not agent._nft_is_header(l.strip()))
        self.assertEqual(counted, len(agent._parse_nft_rules(NFT)))


class TestAppendOnlyLogsAreReadFromTheEnd(unittest.TestCase):
    """`_safe_read` returns the FIRST max_bytes — the OLDEST content. clamscan
    APPENDS a summary block per run, so once scan.log passed 40 KB the agent
    reported a frozen infected count and scan time forever. That is not just a
    stale display: `av_infected` is edge-triggered on the count RISING between
    heartbeats, so a frozen count can never rise and a genuine new detection
    never fires the critical alert, while a host cleaned months ago stays
    permanently dirty in the drawer, the attention items and the RAG corpus."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="rp-v642-tail-"))
        self.f = self.d / "scan.log"

    def test_tail_reads_the_end_and_safe_read_still_reads_the_start(self):
        self.f.write_text("OLDEST\n" + ("x" * 50_000) + "\nNEWEST\n")
        self.assertIn("NEWEST", agent._safe_read_tail(str(self.f), 40_000))
        self.assertNotIn("OLDEST", agent._safe_read_tail(str(self.f), 40_000))
        # _safe_read keeps its head semantics — /proc reads depend on them.
        self.assertIn("OLDEST", agent._safe_read(str(self.f), 40_000))

    def test_a_short_file_is_returned_whole(self):
        self.f.write_text("only line\n")
        self.assertEqual(agent._safe_read_tail(str(self.f), 40_000), "only line\n")

    def test_a_missing_file_is_empty_not_an_error(self):
        self.assertEqual(agent._safe_read_tail(str(self.d / "nope.log")), '')

    def test_the_clamav_and_rkhunter_reads_use_it(self):
        import ast
        import srcpin
        src = (_CLIENT / "remotepower-agent.py").read_text()
        body = srcpin.py_function(src, "get_av_status")
        tree = ast.parse(body)
        heads = [ast.unparse(n) for n in ast.walk(tree)
                 if isinstance(n, ast.Call) and getattr(n.func, 'id', '') == '_safe_read']
        self.assertEqual(heads, [],
                         "an append-only log read from the head freezes on ancient "
                         "content: " + "; ".join(heads))


class TestDuplicateMacSeesSecondaryNics(unittest.TestCase):
    """`dev['interfaces']` is a CMDB record field, not a device field — and the
    CMDB row spec has no `mac` at all, so the comprehension was structurally
    always empty and the check collapsed to the single primary MAC captured once
    at enrolment. A multi-NIC clone, the exact case the feature exists to catch,
    carries its duplicate on a secondary interface. The agent reports every
    NIC's MAC and the server persists them under `sysinfo.network` — collected,
    stored, read by nobody."""

    def test_the_sweep_reads_sysinfo_network(self):
        import ast
        import srcpin
        src = (_CGI / "rack_ipam_handlers.py").read_text()
        body = srcpin.py_function(src, "run_ipam_conflicts_if_due")
        tree = ast.parse(body)
        src_txt = ast.unparse(tree)
        self.assertIn("'network'", src_txt,
                      "per-NIC MACs come from sysinfo.network")
        self.assertNotIn("dev.get('interfaces')", src_txt,
                         "device records never carry an `interfaces` key")

    def test_the_cmdb_interface_spec_still_has_no_mac(self):
        """If a `mac` field is ever added to the CMDB interface rows, that is a
        second source worth folding in — this fails to say so."""
        import srcpin
        spec_src = (_CGI / "api.py").read_text()
        specs = srcpin.balanced_block(spec_src, "_CMDB_LIST_SPECS = ", "{", "}")
        row = srcpin.balanced_block(specs, "'interfaces':", "{", "}")
        self.assertNotIn("'mac'", row,
                         "CMDB interface rows now carry a MAC — fold it into the "
                         "duplicate-MAC sweep alongside sysinfo.network")


if __name__ == '__main__':
    unittest.main()
