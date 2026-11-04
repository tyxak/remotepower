#!/usr/bin/env python3
"""A model server on the same machine as RemotePower is reachable out of the box (7.5.0 docs review).

The defaults for Ollama, LocalAI, opencode and openclaw are all loopback addresses, and the save-time check lets those providers point at
loopback. The connect-time check (v5.5.0) refused a loopback peer for every provider unless `insecure_ssl` was set, a switch the Settings
page does not have, and the model list and status calls did not pass it at all. A default install answered "SSRF guard: AI endpoint peer
127.0.0.1 is a blocked address" and the model picker stayed empty.

Run against a real loopback server: the helpers connect to it for real, so the guard is the one that decides.
"""
import http.server
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v750-ailocal-"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server" / "cgi-bin"))
import ai_provider as ai  # noqa: E402


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj):
        raw = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path.endswith("/api/tags"):
            return self._send({"models": [{"name": "llama3:8b", "size": 123, "details": {"family": "llama"}}]})
        if self.path.endswith("/api/version"):
            return self._send({"version": "0.5.0"})
        if self.path.endswith("/api/ps"):
            return self._send({"models": []})
        if self.path.endswith("/models"):
            return self._send({"data": [{"id": "m1", "created": 1}]})
        self.send_error(404)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        if self.path.endswith("/chat/completions"):
            return self._send({"choices": [{"message": {"content": "hello from the local model"}}],
                               "usage": {"prompt_tokens": 3, "completion_tokens": 5}, "model": "llama3:8b"})
        if self.path.endswith("/embeddings"):
            return self._send({"data": [{"index": 0, "embedding": [0.1, 0.2]}], "model": "e1"})
        if self.path.endswith("/session"):
            return self._send({"id": "ses_1"})
        if "/session/" in self.path and self.path.endswith("/message"):
            return self._send({"parts": [{"type": "text", "text": "opencode says hi"}]})
        self.send_error(404)


class _Server:
    def __enter__(self):
        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *a):
        self.srv.shutdown()
        self.srv.server_close()


def cfg(provider, port, **kw):
    return {"enabled": True, "provider": provider, "model": "llama3:8b", "base_url": f"http://127.0.0.1:{port}" +
            ("/v1" if provider in (ai.PROVIDER_OLLAMA, ai.PROVIDER_LOCALAI, "openai") else ""), **kw}


class TestTheDecision(unittest.TestCase):

    def test_the_local_providers_are_the_four_that_default_to_loopback(self):
        self.assertEqual(set(ai.LOCAL_PROVIDERS), {"ollama", "localai", "opencode", "openclaw"})
        for p in ai.LOCAL_PROVIDERS:
            self.assertIn("localhost", ai.DEFAULT_BASE_URLS[p], p)
        for p in set(ai.VALID_PROVIDERS) - set(ai.LOCAL_PROVIDERS):
            self.assertNotIn("localhost", ai.DEFAULT_BASE_URLS[p], p)

    def test_loopback_is_allowed_for_a_local_provider_or_the_switch_only(self):
        for p in ai.LOCAL_PROVIDERS:
            self.assertTrue(ai.loopback_allowed({"provider": p}), p)
        for p in ("openai", "deepseek", "anthropic"):
            self.assertFalse(ai.loopback_allowed({"provider": p}), p)
            self.assertTrue(ai.loopback_allowed({"provider": p, "insecure_ssl": True}), p)
        for junk in (None, [], "x", {}, {"provider": None}, {"provider": ["ollama"]}):
            self.assertFalse(ai.loopback_allowed(junk), junk)

    def test_metadata_and_link_local_stay_blocked_for_every_provider(self):
        for ip in ("169.254.169.254", "169.254.1.1", "fd00:ec2::254", "100.100.100.200"):
            self.assertTrue(ai._peer_ip_blocked(ip, allow_loopback=True), ip)
        self.assertFalse(ai._peer_ip_blocked("127.0.0.1", allow_loopback=True))
        self.assertTrue(ai._peer_ip_blocked("127.0.0.1", allow_loopback=False))


class TestAgainstARealLoopbackServer(unittest.TestCase):

    def test_an_ollama_chat_works_without_the_switch(self):
        with _Server() as s:
            r = ai.chat(cfg("ollama", s.port), [{"role": "user", "content": "hi"}])
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["text"], "hello from the local model")

    def test_localai_and_opencode_work_too(self):
        with _Server() as s:
            r = ai.chat(cfg("localai", s.port), [{"role": "user", "content": "hi"}])
            self.assertTrue(r["ok"], r)
            r = ai.chat(cfg("opencode", s.port), [{"role": "user", "content": "hi"}])
            self.assertTrue(r["ok"], r)
            self.assertEqual(r["text"], "opencode says hi")

    def test_the_model_list_and_the_status_work(self):
        with _Server() as s:
            m = ai.list_models(cfg("ollama", s.port))
            st = ai.provider_stats(cfg("ollama", s.port))
            la = ai.provider_stats(cfg("localai", s.port))
            lm = ai.list_models(cfg("localai", s.port))
        self.assertEqual([x["name"] for x in m["models"]], ["llama3:8b"], m)
        self.assertEqual((st["reachable"], st.get("version")), (True, "0.5.0"), st)
        self.assertTrue(la["reachable"], la)
        self.assertEqual([x["name"] for x in lm["models"]], ["m1"], lm)

    def test_embeddings_through_a_local_provider_work(self):
        with _Server() as s:
            c = cfg("ollama", s.port)
            c["rag"] = {"embedding_model": "e1"}
            r = ai.embed(c, ["a text"])
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["vectors"], [[0.1, 0.2]])

    def test_a_cloud_provider_still_cannot_reach_loopback(self):
        """A saved cloud base_url that now resolves to loopback is the rebinding case the guard exists for."""
        with _Server() as s:
            r = ai.chat(cfg("openai", s.port, api_key="sk-x"), [{"role": "user", "content": "hi"}])
            m = ai.list_models(cfg("openai", s.port, api_key="sk-x"))
        self.assertFalse(r["ok"])
        self.assertIn("SSRF guard", r["error"], r)
        self.assertIn("127.0.0.1", r["error"], r)
        self.assertNotIn("sk-x", json.dumps(r) + json.dumps(m))

    def test_the_switch_still_opens_it_for_a_cloud_provider(self):
        with _Server() as s:
            r = ai.chat(cfg("openai", s.port, api_key="sk-x", insecure_ssl=True), [{"role": "user", "content": "hi"}])
        self.assertTrue(r["ok"], r)

    def test_the_certificate_check_is_not_loosened_by_being_local(self):
        """Allowing loopback must not switch off certificate checking: that stays the switch's job."""
        import ssl
        seen = {}
        real = ssl.create_default_context

        def spy(*a, **k):
            ctx = real(*a, **k)
            seen["ctx"] = ctx
            return ctx
        ssl.create_default_context = spy
        try:
            with _Server() as s:
                ai.chat(cfg("ollama", s.port), [{"role": "user", "content": "hi"}])
        finally:
            ssl.create_default_context = real
        self.assertEqual(seen["ctx"].verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(seen["ctx"].check_hostname)


class TestTheWebSocketPath(unittest.TestCase):
    """openclaw talks WebSocket. The server here only accepts the connection, so the handshake fails after the guard has decided."""

    def error(self, port, **kw):
        try:
            ai._ws_rpc(f"ws://127.0.0.1:{port}/", [{"id": 1}], timeout=1, **kw)
        except Exception as e:                                       # noqa: BLE001
            return str(e)
        return ""

    def test_the_guard_decides_before_the_handshake(self):
        import socket
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)
        port = srv.getsockname()[1]
        try:
            self.assertIn("blocked peer", self.error(port))                       # default: loopback refused
            self.assertNotIn("blocked peer", self.error(port, allow_loopback=True))
            self.assertNotIn("blocked peer", self.error(port, insecure_ssl=True))  # the old switch still works
        finally:
            srv.close()


class TestSaveTimeAndConnectTimeAgree(unittest.TestCase):

    def test_the_save_check_uses_the_same_set(self):
        src = (ROOT / "server/cgi-bin/api.py").read_text()
        self.assertIn("_local_ai = _prov in ai_provider.LOCAL_PROVIDERS", src)

    def test_every_call_to_a_helper_passes_the_decision(self):
        """The class: a call site that forgets is the one that stays broken for local providers."""
        import ast
        tree = ast.parse((ROOT / "server/cgi-bin/ai_provider.py").read_text())
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                 and n.func.id in ("_http_post_json", "_http_get_json", "_ws_rpc")]
        self.assertGreaterEqual(len(calls), 10, "the call sites were not found: this check would measure nothing")
        for c in calls:
            self.assertIn("allow_loopback", [k.arg for k in c.keywords], f"{c.func.id} at line {c.lineno} does not pass the decision")


if __name__ == "__main__":
    unittest.main()
