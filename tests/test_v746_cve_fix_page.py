#!/usr/bin/env python3
"""7.4.6, issue #57: the CVE page and the demo data agree with the scanner about what "fixable" is.

Two things the server tests cannot see:

  * the page counts a finding in a tile with its own function (`_cveFixKey` in app-cve.js), and the
    server counts it with `cve_fixes.summarize`. A table of findings is fed to both, the JavaScript run
    under node, and the answers must be the same, or a tile and the host view would disagree about which
    findings are fixable;
  * the demo seeder is a producer under contract: a finding that is not fixed in the host's release
    names no version to install, and one that is fixed only in a newer release says where.

Self-skips the node check without node, like the other engine checks.
"""
import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import srcpin  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server" / "cgi-bin"))
import cve_fixes  # noqa: E402

CVE_JS = ROOT / "server/html/static/js/app-cve.js"

# One finding for each way a stored finding can look: every status, a status with and without a version,
# and the findings a scan before 7.4.6 wrote, which carry no status at all.
TABLE = (
    {"vuln_id": "a", "fix_status": "fixed", "fixed_version": "1"},
    {"vuln_id": "b", "fix_status": "fixed", "fixed_version": ""},
    {"vuln_id": "c", "fix_status": "newer_release", "fixed_version": "", "fixed_elsewhere": {"Debian:13": "2"}},
    {"vuln_id": "d", "fix_status": "newer_release", "fixed_version": "9"},
    {"vuln_id": "e", "fix_status": "none", "fixed_version": ""},
    {"vuln_id": "f", "fix_status": "unknown", "fixed_version": "3"},
    {"vuln_id": "g", "fix_status": "unknown", "fixed_version": ""},
    {"vuln_id": "h", "fixed_version": "4"},
    {"vuln_id": "i", "fixed_version": ""},
    {"vuln_id": "j"},
)


def page_bucket(findings):
    """What the page's own function says each finding is, run under node. None without node."""
    node = shutil.which("node")
    if node is None:
        return None
    src = srcpin.js_function(CVE_JS.read_text(), "_cveFixKey")
    script = src + "\nconst rows = JSON.parse(process.argv[1]);\nconsole.log(JSON.stringify(rows.map(_cveFixKey)));\n"
    done = subprocess.run([node, "-e", script, json.dumps(findings)], capture_output=True, text=True, timeout=30)
    if done.returncode != 0:
        raise AssertionError(done.stderr)
    return json.loads(done.stdout)


class TestThePageAndTheServerCountAlike(unittest.TestCase):

    def test_every_finding_lands_in_the_tile_the_server_counts_it_in(self):
        got = page_bucket(list(TABLE))
        if got is None:
            self.skipTest("node is not installed")
        for finding, key in zip(TABLE, got):
            # the server's count of this one finding, by itself
            server = cve_fixes.summarize([finding], set())
            self.assertEqual([k for k, n in server.items() if n], [key], finding)

    def test_the_tiles_are_the_four_the_server_counts(self):
        got = page_bucket(list(TABLE))
        if got is None:
            self.skipTest("node is not installed")
        self.assertEqual(sorted(set(got)), sorted(cve_fixes.summarize([], set())))

    def test_the_check_can_fail(self):
        """The control: a finding the server counts as fixable and the page puts elsewhere must show up."""
        got = page_bucket([{"vuln_id": "x", "fix_status": "newer_release", "fixed_version": "9"}])
        if got is None:
            self.skipTest("node is not installed")
        self.assertNotEqual(got, ["fixable"])


class TestTheDemoDataKeepsTheContract(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        import importlib.util
        spec = importlib.util.spec_from_file_location("seed_v746", ROOT / "packaging" / "seed-demo-data.py")
        if spec is None or spec.loader is None:
            raise unittest.SkipTest("demo seeder not in this tree")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        cls.findings = [f for rec in mod.build_cve_findings().values() for f in rec["findings"]]

    def test_the_demo_has_findings_in_every_status(self):
        self.assertGreater(len(self.findings), 10)
        self.assertEqual({f["fix_status"] for f in self.findings}, set(cve_fixes.STATUSES))

    def test_only_a_fixed_or_unknown_finding_names_a_version_to_install(self):
        for f in self.findings:
            if f["fix_status"] in ("newer_release", "none"):
                self.assertEqual(f["fixed_version"], "", f)
            if f["fix_status"] == "fixed":
                self.assertTrue(f["fixed_version"], f)

    def test_a_finding_fixed_in_a_newer_release_says_where(self):
        for f in self.findings:
            if f["fix_status"] == "newer_release":
                self.assertTrue(f.get("fixed_elsewhere"), f)
            else:
                self.assertNotIn("fixed_elsewhere", f)

    def test_the_server_counts_the_demo_the_way_the_page_will(self):
        counts = cve_fixes.summarize(self.findings, set())
        self.assertEqual(sum(counts.values()), len(self.findings))
        self.assertTrue(all(counts[k] > 0 for k in ("fixable", "newer_release", "none")), counts)


if __name__ == "__main__":
    unittest.main()
