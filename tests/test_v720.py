#!/usr/bin/env python3
"""v7.2.0 "Ev1denceMatters" — release pins.

The CURRENT release carries the strict version pins; older test_vXYZ.py files
have theirs loosened to shape checks. Headline: threat intel reads the logs on a
Linux host (web server, WAF, fail2ban, CrowdSec) and reports what an address
actually did. The behaviour lives in the per-feature test files, each guard
demonstrated failing before it was trusted; what is here is that the release
actually contains them, and that the documentation's numbers are the code's.
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
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v720-pins-"))
_spec = importlib.util.spec_from_file_location("api_v720_pins", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import ip_intel  # noqa: E402
import threat_evidence as te  # noqa: E402

V = "7.2.0"
CODENAME = "Ev1denceMatters"


def _html():
    return (_ROOT / "server/html/index.html").read_text()


def _flat(path):
    """A document with its line breaks and runs of spaces folded to one space, so
    a sentence wrapped at 78 columns can be searched for as one string."""
    return " ".join((_ROOT / path).read_text().split())


class TestVersionBumps(unittest.TestCase):

    def test_server_version(self):
        self.assertEqual(api.SERVER_VERSION, V)

    def test_agent_versions(self):
        self.assertIn(f"VERSION      = '{V}'",
                      (_ROOT / "client/remotepower-agent.py").read_text())
        for rel in ("client/remotepower-agent-win.py",
                    "client/remotepower-agent-mac.py"):
            self.assertIn(f"VERSION = '{V}'", (_ROOT / rel).read_text(), rel)

    def test_agent_extensionless_in_sync(self):
        self.assertEqual((_ROOT / "client/remotepower-agent.py").read_bytes(),
                         (_ROOT / "client/remotepower-agent").read_bytes())

    def test_sw_and_cachebust_agree(self):
        sw = (_ROOT / "server/html/sw.js").read_text()
        m = re.search(r"remotepower-shell-v([0-9.]+-\d+)", sw)
        self.assertTrue(m, "CACHE_NAME not found")
        self.assertTrue(m.group(1).startswith(V + "-"), m.group(1))
        stamps = set(re.findall(r"\?v=([0-9.]+-\d+)", _html()))
        self.assertEqual(stamps, {m.group(1)},
                         "every ?v= must equal CACHE_NAME's stamp")

    def test_every_static_page_carries_the_same_stamp(self):
        sw = (_ROOT / "server/html/sw.js").read_text()
        stamp = re.search(r"remotepower-shell-v([0-9.]+-\d+)", sw).group(1)
        for p in sorted((_ROOT / "server/html").glob("*.html")):
            found = set(re.findall(r"\?v=([0-9.]+-\d+)", p.read_text()))
            self.assertIn(found, ({stamp}, set()), f"{p.name}: {found}")

    def test_readme_badge(self):
        self.assertIn(f"version-{V}-blue", (_ROOT / "README.md").read_text())

    def test_changelog_header_is_newest(self):
        first = [l for l in (_ROOT / "CHANGELOG.md").read_text().splitlines()
                 if l.startswith("## v")][0]
        self.assertTrue(first.startswith(f'## v{V} — "{CODENAME}"'), first)

    def test_version_doc_exists_and_is_titled(self):
        p = _ROOT / f"docs/v{V}.md"
        self.assertTrue(p.exists(), f"docs/v{V}.md missing")
        self.assertIn(f'# RemotePower v{V} — "{CODENAME}"', p.read_text())

    def test_version_doc_has_no_template_left(self):
        body = (_ROOT / f"docs/v{V}.md").read_text()
        for stub in ("CODENAME", "One-paragraph release summary",
                     "## Section", "- **Change.**"):
            self.assertNotIn(stub, body, f"unfilled template stub: {stub}")
        changelog = (_ROOT / "CHANGELOG.md").read_text()
        top = changelog[changelog.index(f"## v{V}"):changelog.index("\n## v7.1.0")]
        for stub in ("CODENAME", "YYYY-MM-DD", "One-paragraph release summary", "Headline change"):
            self.assertNotIn(stub, top, f"unfilled changelog stub: {stub}")

    def test_gen_wiki_codename(self):
        """gen-wiki.py's Home line hardcodes the codename — bump it or the
        wiki ships the previous release's name."""
        p = _ROOT / "tools/gen-wiki.py"
        if not p.exists():
            self.skipTest("excluded from dist tree")
        self.assertIn(CODENAME, p.read_text())

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
        self.assertEqual(bullets[0], V, "the new release leads")

    def test_whats_new_cards_capped_at_three(self):
        html = _html()
        cards = re.findall(r"What's new — v(\d+\.\d+\.\d+)", html)
        self.assertEqual(len(cards), 3, f"cap the cards at 3: {cards}")
        self.assertEqual(cards[0], V, "the new release leads")
        # The sneaky non-visible surface: the doc-search keyword attribute. A
        # visible-text rename never touches it, so doc search stops matching.
        head = html[:html.index(f"What's new — v{V}")]
        kw = head[head.rindex('data-keywords="'):]
        self.assertIn(CODENAME.lower(), kw.lower(),
                      "data-keywords must carry the codename for doc search")

    def test_no_dangling_links_to_the_dropped_docs(self):
        for dropped in ("v7.0.2.md", "security-review-7.0.2.md"):
            for rel in ("README.md", "docs/README.md", "docs/security.md",
                        "server/html/index.html", "docs/features.md"):
                p = _ROOT / rel
                if p.exists():
                    self.assertNotIn(dropped, p.read_text(),
                                     f"{rel} still links the deleted {dropped}")


class TestTheReleaseContainsItsGuards(unittest.TestCase):
    """A release pin, not a behavioural one: each file carries its own proof.
    This asserts the release ships them, so a bump without the feature fails here."""

    FILES = (
        "tests/test_v720_threat_evidence.py",
        "tests/test_v720_ip_intel_reports.py",
        "tests/test_v720_threat_sensor_agent.py",
        "tests/test_v720_threat_sensor_cycle.py",
        "tests/test_v720_threat_intake.py",
        "tests/test_v720_threat_report_engine.py",
        "tests/test_v720_ipintel_page.py",
        "tests/test_v720_threat_sensor_wire.py",
    )

    def test_every_guard_file_exists(self):
        for rel in self.FILES:
            self.assertTrue((_ROOT / rel).exists(), rel)

    def test_the_new_modules_are_where_the_tools_look(self):
        for rel in ("server/cgi-bin/threat_evidence.py", "server/cgi-bin/threat_sensor_handlers.py"):
            self.assertTrue((_ROOT / rel).exists(), rel)
        mk = (_ROOT / "Makefile").read_text()
        self.assertEqual(mk.count("server/cgi-bin/threat_evidence.py"), 2,
                         "a new pure module joins both the lint and the type-check list at creation")

    def test_the_security_review_is_published_and_indexed(self):
        self.assertTrue((_ROOT / "docs/security-review-7.2.0.md").exists())
        self.assertIn("security-review-7.2.0.md", (_ROOT / "docs/README.md").read_text())
        self.assertIn("security-review-7.2.0.md", (_ROOT / "docs/security.md").read_text())

    def test_the_review_says_what_it_did_not_cover(self):
        """A review that implied it covered the whole project would be worse
        than none: this one is scoped to the log sensor and must say so."""
        text = _flat("docs/security-review-7.2.0.md")
        self.assertIn("does not", text)
        self.assertIn("What this review did not cover", text)
        self.assertIn("A production host's real logs", text)

    def test_only_three_security_reviews_are_kept(self):
        reviews = sorted(p.name for p in (_ROOT / "docs").glob("security-review-*.md"))
        self.assertEqual(len(reviews), 3, reviews)


class TestTheDocumentationIsTheCode(unittest.TestCase):
    """Every number the guide states is checked against the code that enforces
    it, and the example report is the one the code writes. The project's rule is
    that a number written down is a number somebody will believe."""

    _ARITHMETIC = (ast.Expression, ast.Constant, ast.BinOp, ast.UnaryOp, ast.Mult, ast.Add, ast.Sub, ast.USub)

    @classmethod
    def setUpClass(cls):
        cls.guide = _flat("docs/ip-intel.md")
        cls.agent_tree = ast.parse((_ROOT / "client/remotepower-agent.py").read_text())

    def says(self, sentence):
        """assertIn against the guide, without printing the whole guide when it fails."""
        self.assertTrue(sentence in self.guide, f"docs/ip-intel.md does not say: {sentence!r}")

    def const(self, name):
        """The value of a module-level constant in the agent, read from its source.
        Only plain arithmetic on numbers is evaluated (`6 * 3600`), nothing else."""
        for node in self.agent_tree.body:
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
                expr = ast.Expression(node.value)
                self.assertTrue(all(isinstance(n, self._ARITHMETIC) for n in ast.walk(expr)), f"{name} is not a plain number")
                return eval(compile(expr, name, "eval"), {"__builtins__": {}})
        self.fail(f"{name} is not assigned at the top level of the agent")

    def test_the_thresholds(self):
        self.assertEqual(te.WAF_MIN_BLOCKS, 3)
        self.says("the WAF refused its requests three times")
        self.assertEqual(ip_intel.DEFAULTS["report_min_count"], 10)
        self.says("(10 by default)")
        self.assertEqual(self.const("THREAT_MIN_HITS"), 3)
        self.says("after 3 hostile requests in a pass")

    def test_the_limits(self):
        h = api.ip_intel_handlers_mod
        self.assertEqual(self.const("THREAT_MAX_EVENTS"), 300)
        self.says("at most 300 addresses at a time")
        self.assertEqual(h.SENSOR_EVENTS_PER_HOUR, 3000)
        self.says("at most 3,000 an hour")
        self.assertEqual(self.const("THREAT_READ_CAP"), 8_000_000)
        self.says("Each pass reads at most 8 MB of a log")
        self.assertEqual(self.const("THREAT_FIRST_READ"), 2_000_000)
        self.says("from its last 2 MB")
        self.assertEqual(self.const("THREAT_LOOKBACK_S"), 6 * 3600)
        self.says("nothing older than six hours counts")
        self.assertEqual(h.NET_PER_SWEEP, 25)
        self.says("limited to 25 addresses a sweep")
        self.assertEqual(ip_intel.SENSOR_PATH_MAX, 20)
        self.says("up to 20")
        self.assertEqual(self.const("THREAT_EVERY_S"), 60)
        self.says("once a minute")

    def test_the_category_table_is_the_registry(self):
        rows = {
            "SSH brute force": "ssh_brute", "Login brute force (web)": "login_brute",
            "SQL injection": "sqli", "Path traversal": "traversal",
            "Code execution attempts": "rce", "Probing for exposed files": "probe",
            "Attack tools and scanners": "scanner",
        }
        raw = (_ROOT / "docs/ip-intel.md").read_text()
        for label, cls in rows.items():
            ab = ", ".join(str(c) for c in te.CLASSES[cls]["abuseipdb"])
            sc = ", ".join(str(c) for c in te.CLASSES[cls]["sniffcat"])
            self.assertIn(f"| {label} | {ab} | {sc} |", raw, label)
        # The table shows the seven web and SSH rows; the other classes (mail, FTP,
        # other services, flooding, port scans) are named in the sentence under it.
        # Nothing may be in the table that this test does not check.
        listed = re.findall(r"^\| ([^|]+) \| [\d, ]+ \| [\d, ]+ \|$", raw, re.M)
        self.assertEqual(sorted(listed), sorted(rows), "a row in the guide's table that the test does not know")
        self.assertLess(len(rows), len(te.CLASSES))
        self.assertIn("Mail, FTP, other services, request flooding and port scans have their own", " ".join(raw.split()))
        for cls in ("mail_brute", "ftp_brute", "service_brute", "flood", "port_scan"):
            self.assertIn(cls, te.CLASSES)

    def test_the_example_report_is_what_the_code_writes(self):
        now = int(time.time())
        ev = te.normalize_event({
            "ip": "185.220.101.7", "first": now - 600, "last": now, "src": {"web": 41, "waf": 12},
            "tok": {"web": {"req:sqli": 30, "req:traversal": 11}, "waf": {"crs:942100": 12}}}, now=now)
        text = ip_intel.evidence_comment(ev)
        self.assertEqual(text, "SQL injection and path traversal: 41 attempts within 10 minutes, "
                               "seen by web server log and WAF (reported by RemotePower)")
        for doc in ("docs/ip-intel.md", "docs/v7.2.0.md", "CHANGELOG.md"):
            self.assertTrue(text in _flat(doc), f"{doc} does not show the report the code writes: {text!r}")

    def test_the_older_default_is_still_what_the_guide_says(self):
        self.says(ip_intel.report_comment("ssh", 42, 600))

    def test_the_placeholders_the_guide_names_exist(self):
        for ph in ip_intel.COMMENT_PLACEHOLDERS:
            self.says("{" + ph + "}")

    def test_the_services_windows(self):
        self.assertGreater(ip_intel.REPORT_RETRY_S["abuseipdb"], 15 * 60)
        self.assertGreater(ip_intel.REPORT_RETRY_S["sniffcat"], 20 * 60)
        self.says("within 15 minutes (AbuseIPDB) or 20 minutes (SniffCat)")
        self.says("a little over 20 minutes")


if __name__ == "__main__":
    unittest.main()
