#!/usr/bin/env python3
"""v4.10.0: 20 new AI features (the AI Insights hub). Each is a SYSTEM_PROMPTS
key with a label and a hub descriptor — this pins all three in lockstep."""
import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

_spec = importlib.util.spec_from_file_location("ai_provider_v4100", _CGI / "ai_provider.py")
ai = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ai)

_API_SRC = (_CGI / "api.py").read_text()
_APP_JS = (_ROOT / "server" / "html" / "static" / "js" / "app.js").read_text()
_HTML = (_ROOT / "server" / "html" / "index.html").read_text()

NEW_KEYS = [
    "ai_briefing", "log_anomaly", "alert_tuning", "predict_maintenance",
    "incident_rca", "alert_group", "change_risk", "nl_fleet_query", "nl_monitor",
    "reverse_iac", "cve_patch_plan", "compliance_plan", "capacity_forecast",
    "dr_readiness", "firewall_audit", "dns_hygiene", "email_deliverability",
    "integration_assist", "supply_chain", "host_profile",
]


class TestPrompts(unittest.TestCase):
    def test_all_20_prompts_registered_and_nonempty(self):
        for k in NEW_KEYS:
            self.assertIn(k, ai.SYSTEM_PROMPTS, k)
            self.assertGreater(len(ai.SYSTEM_PROMPTS[k]), 60, f"{k} prompt too short")

    def test_structured_prompts_demand_json_or_markers(self):
        # NL->config prompts must constrain output so it can be parsed/used.
        self.assertIn("ONLY a JSON object", ai.SYSTEM_PROMPTS["nl_fleet_query"])
        self.assertIn("ONLY a JSON object", ai.SYSTEM_PROMPTS["nl_monitor"])
        self.assertIn("BEGIN_IAC", ai.SYSTEM_PROMPTS["reverse_iac"])


class TestLabels(unittest.TestCase):
    def test_all_20_labelled(self):
        for k in NEW_KEYS:
            self.assertIn(f"'{k}':", _API_SRC, f"{k} missing from _AI_PROMPT_LABELS")


class TestHub(unittest.TestCase):
    def _hub_keys(self):
        block = _APP_JS[_APP_JS.index("const AI_INSIGHTS ="):_APP_JS.index("function _renderAIInsights")]
        return set(re.findall(r"key:\s*'([a-z_]+)'", block))

    def test_hub_covers_every_key(self):
        self.assertEqual(self._hub_keys(), set(NEW_KEYS),
                         "AI_INSIGHTS descriptors must match the 20 prompt keys exactly")

    def test_dispatcher_and_render_defined(self):
        self.assertIn("async function aiInsight(key)", _APP_JS)
        self.assertIn("function _renderAIInsights()", _APP_JS)
        self.assertIn("_renderAIInsights();", _APP_JS)  # wired in loadAIPage

    def test_every_card_categorised(self):
        block = _APP_JS[_APP_JS.index("const AI_INSIGHTS ="):_APP_JS.index("const _AI_CATS")]
        cats = re.findall(r"cat:\s*'([a-z]+)'", block)
        self.assertEqual(len(cats), 20, "every card must carry a category")
        self.assertLessEqual(set(cats),
                             {"proactive", "incident", "planning", "nlconfig", "advisors"})

    def test_page_container_present(self):
        self.assertIn('id="ai-insights-grid"', _HTML)
        self.assertIn('id="ai-insights-wrap"', _HTML)

    def test_input_driven_use_placeholder(self):
        # every descriptor with an `input:` must fold it into msg via %s
        block = _APP_JS[_APP_JS.index("const AI_INSIGHTS ="):_APP_JS.index("function _renderAIInsights")]
        for m in re.finditer(r"\{[^}]*input:[^}]*\}", block):
            self.assertIn("%s", m.group(0), "input-driven insight must use %s in msg")


if __name__ == "__main__":
    unittest.main()
