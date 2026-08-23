"""v7.0.2 "Prec3dentMatters" — release pins.

The CURRENT release carries the strict version pins; older test_vXYZ.py files
have theirs loosened to shape checks. Headline: the autonomy loop refused every
single thing it looked at, and each reason was a gate naming a cause it did not
have. The behaviour lives in tests/test_v702_autonomy.py, where each guard was
demonstrated to fail before it was trusted; what is here is that the release
actually contains them.
"""

import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v702-pins-"))
_spec = importlib.util.spec_from_file_location("api_v702_pins", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

V = "7.0.2"
CODENAME = "Prec3dentMatters"

_JS = _ROOT / "server/html/static/js"


def _html():
    return (_ROOT / "server/html/index.html").read_text()


def _js(name):
    return (_JS / name).read_text()


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
        """index.html is not the only page with cache-busted assets — the
        portal, the status page, the report renderer, fleet-query and swagger
        all load the same bundles, and a page left behind serves a stale one."""
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

    def test_no_dangling_links_to_the_dropped_version_doc(self):
        dropped = "v6.4.2.md"
        for rel in ("README.md", "docs/README.md", "server/html/index.html",
                    "docs/features.md"):
            p = _ROOT / rel
            if p.exists():
                self.assertNotIn(dropped, p.read_text(),
                                 f"{rel} still links the deleted {dropped}")

    def test_the_all_pages_map_count_is_derived_from_the_sidebar(self):
        """The product map is built from the sidebar DOM, so the number quoted
        in features.md is checkable. Nothing checked it: the row shipped 89,
        a correction pass changed it to 77 — which is the doc-POINTER ratio
        from a different measurement — and the sidebar holds 81. Two wrong
        numbers in a row is what an unpinned count looks like."""
        html = _html()
        nav = html[html.index('<nav class="sidebar"'):]
        nav = nav[:nav.index("app-content")]
        pages = set(re.findall(r'data-page="([a-z0-9-]+)"', nav))
        groups = set(re.findall(r'data-group="([a-z0-9-]+)"', nav))
        self.assertGreater(len(pages), 40, "sidebar derivation collapsed")
        self.assertGreater(len(groups), 5, "group derivation collapsed")
        feats = (_ROOT / "docs/features.md").read_text()
        m = re.search(r"\*\*(\d+) pages across (\d+) domains\*\*", feats)
        self.assertTrue(m, "features.md no longer states the map's size")
        self.assertEqual((int(m.group(1)), int(m.group(2))),
                         (len(pages), len(groups)),
                         "features.md disagrees with the sidebar it describes")

    def test_the_aur_packages_stay_on_the_last_shipped_release(self):
        """The AUR cannot carry this version until its tarball is published —
        `update.sh` derives the sha256 from the released file. So between the
        CHANGELOG date flip and the AUR push, `test_v643_aur_tracks_release`
        is red on purpose; that red is the reminder to push, not a defect.
        This pin only holds the other direction: never fake the version here
        ahead of a tarball to exist."""
        p = _ROOT / "packaging/aur/remotepower-server/PKGBUILD"
        if not p.exists():
            self.skipTest("excluded from dist tree")
        self.assertNotIn(f"pkgver={V}", p.read_text())


class TestTheFixesAreInThisRelease(unittest.TestCase):
    """Release pins, not behavioural ones — the proofs live in
    tests/test_v702_autonomy.py. This asserts the release contains them, so a
    bump that shipped without one fails here."""

    def test_precedent_reads_more_than_the_ai_field(self):
        import autonomy
        rows = [{"source": "operator", "resolution": "closed",
                 "root_cause": "restarted nginx", "recommended_action": ""}] * 2
        self.assertEqual(autonomy.precedent_confidence(rows)[0], 1.0)

    def test_the_backup_precondition_is_its_own_column(self):
        import autonomy
        self.assertFalse(autonomy.ACTION_CLASSES["restart_networking"]["requires_backup"])
        self.assertTrue(autonomy.ACTION_CLASSES["patch"]["requires_backup"])

    def test_the_window_gate_calls_something_that_exists(self):
        """Comments stripped first: the fix's own explanatory comment names the
        helper it replaced, and a raw substring search fails on that."""
        import inspect
        import autonomy_ops_handlers as _ops
        src = (inspect.getsource(api.run_autonomy_if_due)
               + inspect.getsource(_ops._change_window_open))
        code = "\n".join(l.split("#", 1)[0] for l in src.splitlines())
        self.assertNotIn("_in_maintenance_window", code)
        self.assertIn("_exec_gated", code)

    def test_the_precedent_waiver_is_a_real_policy_field(self):
        import autonomy
        self.assertIs(autonomy.default_policy()["require_precedent"], True)
        self.assertIs(
            autonomy.normalize_policy({"require_precedent": False})["require_precedent"],
            False)
        self.assertIn("autonomy-require-precedent", _html())
        self.assertIn("require_precedent", _js("app-autonomy.js"))

    def test_the_new_actions_shipped(self):
        import autonomy
        for name in ("enable_av_realtime", "enable_gatekeeper"):
            self.assertIn(name, autonomy.ACTION_CLASSES, name)
        self.assertEqual(len(autonomy.ACTION_CLASSES), 26)

    def test_the_actions_that_could_never_fire_are_gone(self):
        """Each failed one of two questions: does the alert that triggers it
        name a host, and can the command fix the state that fired it."""
        import autonomy
        import autonomy_ops_handlers as _ops
        for name in ("restart_resolver", "flush_dns_cache", "enable_autoupdates",
                     "remount_all", "shutdown_host"):
            self.assertNotIn(name, autonomy.ACTION_CLASSES, name)
        for event in ("resolver_unhealthy", "mailflow_delayed", "wan_down",
                      "server_disk_low", "ups_critical", "oom_detected",
                      "mount_issue", "autoupdate_disabled"):
            self.assertNotIn(event, _ops._EVENT_ACTIONS, event)

    def test_the_disk_ladder_moved_to_the_per_host_signal(self):
        import autonomy_ops_handlers as _ops
        self.assertEqual(len(_ops._EVENT_ACTIONS["disk_predict_fail"]), 6)

    def test_receipts_can_be_cleared_from_the_page(self):
        self.assertIn("clearAutonomyReceipts", _html())
        self.assertIn("deleteAutonomyReceipt", _js("app-autonomy.js"))
        self.assertIn(("DELETE", "/api/autonomy/receipts"),
                      api._build_exact_routes())


if __name__ == "__main__":
    unittest.main()
