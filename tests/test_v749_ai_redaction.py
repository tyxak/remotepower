#!/usr/bin/env python3
"""Every AI call is redacted before it leaves the server (7.4.9).

`ai_provider.chat` redacts what it sends: bearer tokens, AWS keys and long hex strings always, addresses and host names unless the
operator opted in to sending them. `_call_ai_with_prompts`, behind the mitigate step, alert triage, the log-sweep root-cause
analysis and the AI exec proposal, called the provider adapters directly and skipped all of it. Those four features send log lines
and command output, which is where a bearer token or an access key is most likely to be, and with a cloud provider they went off
the server as they were. Found by the documentation cross-check (docs3), confirmed with a fake provider.

The helper now calls `ai_provider.chat`. The ratchet counts every call of an adapter outside ai_provider.py, which is the shape of
the miss: seven callers used `chat`, the eighth did not, and the file read as though the rule was applied.
"""
import ast
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v749-airedact-"))
_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v749_airedact", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)                      # type: ignore[arg-type]
_spec.loader.exec_module(api)                                     # type: ignore[union-attr]
import ai_provider  # noqa: E402

HOST = "web01.corp.example.com"
IP = "10.20.30.40"
BEARER = "abcdef0123456789abcdef"
AWS = "AKIAQ3XK7ZP2MNB4VTWR"
HEX = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
USER_PROMPT = (f"journal line: {HOST} ({IP}) sent Authorization: Bearer {BEARER} and key {AWS}; digest {HEX}")
SYSTEM_PROMPT = "You are the on-call assistant for 192.0.2.9."
ADAPTERS = {"chat_anthropic", "chat_openai_compatible", "chat_opencode", "chat_openclaw"}


class TestTheHelperRedacts(unittest.TestCase):

    def setUp(self):
        self.sent = []
        self._saved = {n: getattr(ai_provider, n) for n in ADAPTERS | {"redact", "redact_messages"}}

        def record(cfg, messages, system=None, *a, **k):
            self.sent.append({"messages": messages, "system": system})
            return {"ok": True, "text": "fine", "model": "m", "tokens_in": 1, "tokens_out": 1}
        for n in ADAPTERS:
            setattr(ai_provider, n, record)

    def tearDown(self):
        for n, f in self._saved.items():
            setattr(ai_provider, n, f)

    def configure(self, provider, privacy=None):
        api.save(api.CONFIG_FILE, {"ai": {"enabled": True, "provider": provider, "model": "m", "api_key": "k",
                                          "base_url": "http://127.0.0.1:11434", "privacy": privacy or {}}})
        api._LOAD_CACHE.clear()

    def call(self):
        res = api._call_ai_with_prompts(SYSTEM_PROMPT, USER_PROMPT, "alert_triage")
        self.assertTrue(res.get("ok"), res)
        self.assertEqual(len(self.sent), 1)
        return self.sent[0]

    def test_nothing_that_identifies_a_host_or_a_secret_is_sent_by_default(self):
        for provider in ("anthropic", "ollama", "openai"):
            with self.subTest(provider=provider):
                self.sent.clear()
                self.configure(provider)
                out = self.call()
                text = out["messages"][0]["content"]
                for leak in (HOST, IP, BEARER, AWS, HEX):
                    self.assertNotIn(leak, text)
                for marker in ("<HOST>", "<IP>", "<REDACTED>", "<REDACTED-AWS>", "<REDACTED-HEX>"):
                    self.assertIn(marker, text)
                self.assertNotIn("192.0.2.9", out["system"], "the system prompt is redacted too")

    def test_an_operator_who_opted_in_still_never_sends_a_secret(self):
        self.configure("anthropic", {"send_ips": True, "send_hostnames": True})
        text = self.call()["messages"][0]["content"]
        self.assertIn(HOST, text)
        self.assertIn(IP, text)
        for secret in (BEARER, AWS, HEX):
            self.assertNotIn(secret, text, "bearer tokens, AWS keys and long hex are redacted whatever the toggles say")

    def test_control_without_the_redactor_it_all_goes_out(self):
        self.configure("anthropic")
        ai_provider.redact_messages = lambda messages, privacy: messages
        ai_provider.redact = lambda text, privacy: text
        text = self.call()["messages"][0]["content"]
        for leak in (HOST, IP, BEARER, AWS, HEX):
            self.assertIn(leak, text)


class TestNoCallerSkipsTheDispatcher(unittest.TestCase):

    def test_no_adapter_is_called_outside_ai_provider(self):
        offenders = []
        files = sorted(p for p in _CGI.glob("*.py") if p.name != "ai_provider.py")
        self.assertGreater(len(files), 40, "the population is the server's modules")
        for f in files:
            for node in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
                if isinstance(node, ast.Call):
                    fn = node.func
                    name = fn.attr if isinstance(fn, ast.Attribute) else fn.id if isinstance(fn, ast.Name) else ""
                    if name in ADAPTERS:
                        offenders.append(f"{f.name}:{node.lineno} {name}")
        self.assertEqual(offenders, [], "call ai_provider.chat, which redacts, not an adapter")

    def test_the_ratchet_sees_a_direct_call(self):
        tree = ast.parse("def f(cfg, m):\n    return ai_provider.chat_anthropic(cfg, m, None, 10)\n")
        names = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
        self.assertTrue(names & ADAPTERS)

    def test_the_dispatcher_is_what_the_helper_calls(self):
        src = (_CGI / "api.py").read_text(encoding="utf-8")
        body = src[src.index("def _call_ai_with_prompts"):src.index("if __name__ == '__main__':")]
        self.assertIn("ai_provider.chat(", body)


if __name__ == "__main__":
    unittest.main()
