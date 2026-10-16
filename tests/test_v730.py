#!/usr/bin/env python3
"""v7.3.0 "Edg3Matters" — release pins.

The CURRENT release carries the strict version pins; older test_vXYZ.py files
have theirs loosened to shape checks. Headline: threat intel reads the edge
(Cloudflare's firewall events and a honeypot Worker's log) and the host
firewall's log, and reports what they show. The behaviour lives in the
per-feature test files, each guard demonstrated failing before it was trusted;
what is here is that the release actually contains them, and that the
documentation's numbers are the code's.
"""

import ast
import importlib.util
import os
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v730-pins-"))
_spec = importlib.util.spec_from_file_location("api_v730_pins", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import edge_evidence as ee  # noqa: E402
import ip_intel  # noqa: E402
import threat_evidence as te  # noqa: E402

V = "7.3.0"
CODENAME = "Edg3Matters"


def _html():
    return (_ROOT / "server/html/index.html").read_text()


def _flat(path):
    """A document with its line breaks and runs of spaces folded to one space, so
    a sentence wrapped at 78 columns can be searched for as one string."""
    return " ".join((_ROOT / path).read_text().split())


class TestVersionBumps(unittest.TestCase):
    """Loosened at the v7.4.0 bump. The STRICT pins for the current release
    live in tests/test_v740.py; what stays here is the shape — the surfaces
    must still agree with each other, whatever version they carry."""

    def test_server_version_shape(self):
        self.assertRegex(api.SERVER_VERSION, r"^\d+\.\d+\.\d+$")

    def test_agents_match_the_server(self):
        v = api.SERVER_VERSION
        self.assertIn(f"VERSION      = '{v}'",
                      (_ROOT / "client/remotepower-agent.py").read_text())
        for rel in ("client/remotepower-agent-win.py",
                    "client/remotepower-agent-mac.py"):
            self.assertIn(f"VERSION = '{v}'", (_ROOT / rel).read_text(), rel)

    def test_agent_extensionless_in_sync(self):
        self.assertEqual((_ROOT / "client/remotepower-agent.py").read_bytes(),
                         (_ROOT / "client/remotepower-agent").read_bytes())

    def test_sw_and_cachebust_agree(self):
        sw = (_ROOT / "server/html/sw.js").read_text()
        m = re.search(r"remotepower-shell-v([0-9.]+-\d+)", sw)
        self.assertTrue(m, "CACHE_NAME not found")
        stamps = set(re.findall(r"\?v=([0-9.]+-\d+)", _html()))
        self.assertEqual(stamps, {m.group(1)},
                         "every ?v= must equal CACHE_NAME's stamp")

    def test_every_static_page_carries_the_same_stamp(self):
        sw = (_ROOT / "server/html/sw.js").read_text()
        stamp = re.search(r"remotepower-shell-v([0-9.]+-\d+)", sw).group(1)
        for p in sorted((_ROOT / "server/html").glob("*.html")):
            found = set(re.findall(r"\?v=([0-9.]+-\d+)", p.read_text()))
            self.assertIn(found, ({stamp}, set()), f"{p.name}: {found}")

    def test_readme_badge_matches_the_server(self):
        self.assertIn(f"version-{api.SERVER_VERSION}-blue",
                      (_ROOT / "README.md").read_text())

    def test_changelog_newest_header_is_the_server_version(self):
        first = [l for l in (_ROOT / "CHANGELOG.md").read_text().splitlines()
                 if l.startswith("## v")][0]
        self.assertTrue(first.startswith(f'## v{api.SERVER_VERSION} — "'), first)

    def test_version_doc_still_exists_inside_the_keep_three_window(self):
        p = _ROOT / f"docs/v{V}.md"
        self.assertTrue(p.exists(), f"docs/v{V}.md missing")
        self.assertIn(f'# RemotePower v{V} — "{CODENAME}"', p.read_text())

    def test_version_doc_has_no_template_left(self):
        body = (_ROOT / f"docs/v{V}.md").read_text()
        for stub in ("CODENAME", "One-paragraph release summary",
                     "## Section", "- **Change.**"):
            self.assertNotIn(stub, body, f"unfilled template stub: {stub}")

    def test_gen_wiki_carries_a_codename(self):
        """gen-wiki.py's Home line hardcodes the codename. Which one it is
        belongs to the current release's pins; that it is not this older one
        belongs here."""
        p = _ROOT / "tools/gen-wiki.py"
        if not p.exists():
            self.skipTest("excluded from dist tree")
        self.assertNotIn(CODENAME, p.read_text())

    def test_doc_set_keeps_three_versions(self):
        vers = sorted(p.stem for p in (_ROOT / "docs").glob("v*.md")
                      if re.fullmatch(r"v\d+\.\d+\.\d+", p.stem))
        self.assertEqual(len(vers), 3, f"keep exactly 3 version docs: {vers}")
        self.assertIn(f"v{V}", vers)

    def test_readme_recent_releases_capped_at_five(self):
        readme = (_ROOT / "README.md").read_text()
        block = readme[readme.index("### Recent releases"):]
        block = block[:block.index("\n## ")] if "\n## " in block else block
        bullets = re.findall(r"^- \*\*v(\d+\.\d+\.\d+)", block, re.M)
        self.assertLessEqual(len(bullets), 5, bullets)
        self.assertEqual(bullets[0], api.SERVER_VERSION, "the new release leads")
        self.assertIn(V, bullets)

    def test_whats_new_cards_capped_at_three(self):
        html = _html()
        cards = re.findall(r"What's new — v(\d+\.\d+\.\d+)", html)
        self.assertEqual(len(cards), 3, f"cap the cards at 3: {cards}")
        self.assertEqual(cards[0], api.SERVER_VERSION, "the new release leads")
        self.assertIn(V, cards)
        head = html[:html.index(f"What's new — v{V}")]
        kw = head[head.rindex('data-keywords="'):]
        self.assertIn(CODENAME.lower(), kw.lower(),
                      "data-keywords must carry the codename for doc search")

    def test_no_dangling_links_to_the_dropped_docs(self):
        for dropped in ("v7.0.3.md", "security-review-7.0.3.md"):
            for rel in ("README.md", "docs/README.md", "docs/security.md",
                        "server/html/index.html", "docs/features.md"):
                p = _ROOT / rel
                if p.exists():
                    self.assertNotIn(dropped, p.read_text(),
                                     f"{rel} still links the deleted {dropped}")
            self.assertFalse((_ROOT / "docs" / dropped).exists(), dropped)

class TestTheReleaseContainsItsGuards(unittest.TestCase):
    """A release pin, not a behavioural one: each file carries its own proof.
    This asserts the release ships them, so a bump without the feature fails here."""

    FILES = (
        "tests/test_v730_edge_vocabulary.py",
        "tests/test_v730_edge_evidence.py",
        "tests/test_v730_edge_intel.py",
        "tests/test_v730_edge_page.py",
        "tests/test_v730_firewall_log.py",
    )

    def test_every_guard_file_exists(self):
        for rel in self.FILES:
            self.assertTrue((_ROOT / rel).exists(), rel)

    def test_the_new_modules_are_where_the_tools_look(self):
        for rel in ("server/cgi-bin/edge_evidence.py", "server/cgi-bin/edge_intel_handlers.py"):
            self.assertTrue((_ROOT / rel).exists(), rel)
        mk = (_ROOT / "Makefile").read_text()
        self.assertEqual(mk.count("server/cgi-bin/edge_evidence.py"), 2,
                         "a new pure module joins both the lint and the type-check list at creation")

    def test_the_handlers_are_bound_not_appended_to_api(self):
        src = (_ROOT / "server/cgi-bin/api.py").read_text()
        self.assertIn("edge_intel_handlers_mod.bind(globals())", src)
        self.assertNotIn("def handle_ip_intel_edge_test", src)

    def test_the_sweep_is_in_both_cadence_lists(self):
        self.assertIn("run_edge_intel_if_due", (_ROOT / "server/cgi-bin/scheduler.py").read_text())
        self.assertIn("_safe(run_edge_intel_if_due", (_ROOT / "server/cgi-bin/api.py").read_text())

    def test_the_security_review_is_published_and_indexed(self):
        self.assertTrue((_ROOT / "docs/security-review-7.3.0.md").exists())
        self.assertIn("security-review-7.3.0.md", (_ROOT / "docs/README.md").read_text())
        self.assertIn("security-review-7.3.0.md", (_ROOT / "docs/security.md").read_text())

    def test_the_review_says_what_it_did_not_cover(self):
        """A review that implied more than it did would be worse than none. This
        one covers the whole project, so it must say what that did not include:
        that it is the project's own work and not an independent audit, and that
        the live Cloudflare API was not part of it."""
        text = _flat("docs/security-review-7.3.0.md")
        self.assertIn("What this review did not cover", text)
        self.assertIn("not an independent audit", text)
        self.assertIn("The live Cloudflare API", text)
        self.assertIn("How it was done", text)

    def test_only_three_security_reviews_are_kept(self):
        reviews = sorted(p.name for p in (_ROOT / "docs").glob("security-review-*.md"))
        self.assertEqual(len(reviews), 3, reviews)


class TestTheDocumentationIsTheCode(unittest.TestCase):
    """Every number the guide states is checked against the code that enforces
    it, and the example reports are the ones the code writes. The project's rule
    is that a number written down is a number somebody will believe."""

    _ARITHMETIC = (ast.Expression, ast.Constant, ast.BinOp, ast.UnaryOp, ast.Mult, ast.Add, ast.Sub, ast.USub)

    @classmethod
    def setUpClass(cls):
        cls.guide = _flat("docs/ip-intel.md")
        cls.agent_tree = ast.parse((_ROOT / "client/remotepower-agent.py").read_text())

    def says(self, sentence):
        self.assertTrue(sentence in self.guide, f"docs/ip-intel.md does not say: {sentence!r}")

    def const(self, name):
        for node in self.agent_tree.body:
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
                expr = ast.Expression(node.value)
                self.assertTrue(all(isinstance(n, self._ARITHMETIC) for n in ast.walk(expr)), f"{name} is not a plain number")
                return eval(compile(expr, name, "eval"), {"__builtins__": {}})
        self.fail(f"{name} is not assigned at the top level of the agent")

    def test_the_firewall_log_thresholds(self):
        self.assertEqual(self.const("THREAT_FW_PORTS"), 4)
        self.says("tried **four different ports**")
        self.assertEqual(self.const("THREAT_FW_PACKETS"), 15)
        self.says("had **fifteen packets** refused")
        self.says("within one minute")
        self.assertEqual(self.const("THREAT_EVERY_S"), 60)

    def test_the_edge_numbers(self):
        h = api.edge_intel_handlers_mod
        self.assertEqual(ip_intel.DEFAULTS["edge_poll_minutes"], 10)
        self.says("RemotePower reads every ten minutes (every five at the fastest)")
        self.assertEqual(h.POLL_MIN_S, 5 * 60)
        self.assertEqual(h.LOOKBACK_S, 6 * 3600)
        self.says("A read never goes back further than six hours")
        self.assertEqual(te.WAF_MIN_BLOCKS, 3)
        self.assertEqual(ip_intel.DEFAULTS["edge_report_after"], 1)
        self.says("An address is reported after **Report after Cloudflare refusals** refusals by")
        self.assertEqual(ee.MAX_ZONES, 50)

    def test_the_documented_mechanisms_are_the_counted_ones(self):
        counted = {"waf", "custom", "ratelimit", "ddos", "bot", "ua"}
        self.assertEqual(set(ee._CF_SOURCES.values()), counted)
        self.assertEqual(set(te.CF_KINDS), counted)
        for word in ("Managed rules", "custom rules", "rate limiting rules", "HTTP DDoS protection",
                     "Bot Fight Mode", "Bot Management", "Browser Integrity Check", "user-agent block rules"):
            self.says(word)
        self.assertEqual(set(ee._CF_REFUSALS), {"block", "connectionclose", "forceconnectionclose"})
        for word in ("Challenges and log-only actions", "country and ASN rules", "the security level",
                     "IP access rules", "rules that also block an IP list"):
            self.says(word)

    def test_the_example_reports_are_what_the_code_writes(self):
        now = int(time.time())
        canary = ee.trap_events([{"kind": "canary_use", "ip": "185.220.101.7", "action": "banned", "at": now - 30}], now)[0][0]
        text = ip_intel.evidence_comment(canary)
        self.assertEqual(text, "using a credential planted in a decoy file: 1 attempt within 1 minute, "
                               "seen by edge honeypot (reported by RemotePower)")
        cf, _ = ee.cf_events([{"zone": "7" * 32, "ip": "185.220.101.7", "action": "block", "source": "firewallcustom",
                               "rule": "b" * 32, "count": 8}],
                             {"7" * 32: {"b" * 32: {"d": "probes", "c": "probe", "k": False}}},
                             now, now - 600, now)
        text2 = ip_intel.evidence_comment(cf[0])
        self.assertEqual(text2, "probing for exposed files and admin pages: 8 attempts within 10 minutes, "
                                "seen by Cloudflare WAF (reported by RemotePower)")
        for t in (text, text2):
            self.assertTrue(t in _flat("docs/ip-intel.md"), f"docs/ip-intel.md does not show: {t!r}")
        self.assertTrue(text in _flat("docs/v7.3.0.md") or "1 attempt within 1 minute" in _flat("docs/v7.3.0.md"))
        self.assertIn("1 attempt within 1 minute", _flat("CHANGELOG.md"))

    def test_the_trap_table_is_the_registry(self):
        """The guide's honeypot table names five groups; every trap kind the
        vocabulary knows must land in one of them."""
        groups = {"probe", "bad_bot", "canary", "decoy_login"}
        self.assertEqual({c for c in te.TRAP_KINDS.values() if c}, groups)
        self.says("Probing for exposed files and admin pages")
        self.says("Unwanted web crawling")
        self.says("Using a credential planted in a decoy file")
        self.says("Signing in to a decoy service")

    def test_the_review_numbers_match_its_table(self):
        raw = (_ROOT / "docs/security-review-7.3.0.md").read_text()
        rows = re.findall(r"^\| (\d+) \|", raw, re.M)
        words = {6: "six", 9: "nine", 10: "ten", 22: "twenty-two", 23: "twenty-three"}
        n = len(rows)
        self.assertIn(n, words, "extend the word map for a new count")
        self.assertIn("**%s** issues" % words[n], raw)
        self.assertIn("%s issues" % words[n], (_ROOT / "docs/security.md").read_text())
        self.assertIn("%s issues" % words[n].capitalize(), (_ROOT / "docs/README.md").read_text())


if __name__ == "__main__":
    unittest.main()
