"""v7.0.0 "Aut0nomyMatters" — release pins.

The CURRENT release carries the strict version pins; older test_vXYZ.py files
have theirs loosened to shape checks. Headline: six guardrails that were
reporting success while measuring nothing, and the surfaces that were telling
the operator something untrue. Behaviour for each lives in its own file —
test_ci_green_parity (Postgres in the gate), test_ruff_f821_gate,
test_srcpin_ratchet, test_api_resolves_not_throws, test_notify_header_ascii,
test_a11y_axe (the seeded class), test_v430_i18n_gate (the widened categories).
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
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v700-"))
_spec = importlib.util.spec_from_file_location("api_v700_pins", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

V = "7.0.0"
CODENAME = "Aut0nomyMatters"

_JS = _ROOT / "server/html/static/js"


def _html():
    return (_ROOT / "server/html/index.html").read_text()


def _js(name):
    return (_JS / name).read_text()


class TestVersionBumps(unittest.TestCase):
    """Loosened at the v7.0.1 bump. The STRICT pins for the current release
    live in tests/test_v701.py; what stays here is the shape — the surfaces
    must still agree with each other, whatever version they carry. Pinning
    7.0.0 literals past its release would fail on every later bump and teach
    nothing."""

    VER = re.compile(r"\d+\.\d+\.\d+")

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

    def test_readme_badge_matches_the_server(self):
        self.assertIn(f"version-{api.SERVER_VERSION}-blue",
                      (_ROOT / "README.md").read_text())

    def test_changelog_newest_header_is_the_server_version(self):
        first = [l for l in (_ROOT / "CHANGELOG.md").read_text().splitlines()
                 if l.startswith("## v")][0]
        self.assertTrue(first.startswith(f'## v{api.SERVER_VERSION} — "'), first)

    def test_doc_set_keeps_three_versions(self):
        vers = sorted(p.stem for p in (_ROOT / "docs").glob("v*.md")
                      if re.fullmatch(r"v\d+\.\d+\.\d+", p.stem))
        self.assertEqual(len(vers), 3, f"keep exactly 3 version docs: {vers}")

    def test_readme_recent_releases_capped_at_five(self):
        readme = (_ROOT / "README.md").read_text()
        block = readme[readme.index("### Recent releases"):]
        block = block[:block.index("\n## ")] if "\n## " in block else block
        bullets = re.findall(r"^- \*\*v(\d+\.\d+\.\d+)", block, re.M)
        self.assertLessEqual(len(bullets), 5, bullets)

    def test_whats_new_cards_capped_at_three(self):
        cards = re.findall(r"What's new — v(\d+\.\d+\.\d+)", _html())
        self.assertEqual(len(cards), 3, f"cap the cards at 3: {cards}")


class TestGuardrailsAreWired(unittest.TestCase):
    """The release IS the guardrails, so pin that each one exists and is
    reachable. Each file carries its own behavioural proof; this is the
    "did the release actually ship" check."""

    GATES = (
        "tests/test_ruff_f821_gate.py",
        "tests/test_srcpin_ratchet.py",
        "tests/test_api_resolves_not_throws.py",
        "tests/test_notify_header_ascii.py",
    )

    def test_every_new_gate_file_exists(self):
        missing = [g for g in self.GATES if not (_ROOT / g).exists()]
        self.assertEqual(missing, [], f"release gates missing: {missing}")

    def test_postgres_is_in_the_ci_gate(self):
        ci = _ROOT / ".github/workflows/ci.yml"
        if not ci.exists():
            self.skipTest("excluded from dist tree")
        text = ci.read_text()
        self.assertIn("image: postgres:", text)
        self.assertRegex(text, r'RP_PG_REQUIRE:\s*"?1"?')

    def test_the_f821_exemption_is_generated_not_handwritten(self):
        self.assertTrue((_ROOT / "tools/gen_ruff_builtins.py").exists())
        self.assertTrue((_ROOT / "tools/ruff-api-builtins.toml").exists())

    def test_the_seeded_a11y_class_exists(self):
        p = _ROOT / "tests/test_a11y_axe.py"
        self.assertIn("class TestAccessibilityAxeSeeded", p.read_text())

    def test_the_i18n_gate_covers_more_than_chrome(self):
        p = _ROOT / "tests/test_v430_i18n_gate.py"
        self.assertIn("_DELIBERATE_ENGLISH", p.read_text())


