#!/usr/bin/env python3
"""v3.4.0: RAG over your infrastructure.

Two layers of coverage:

  * Pure-module tests of rag_index.py — tokeniser, markdown chunking,
    BM25 ranking, RRF fusion, the corpus builders (incl. the hard
    requirement that the credentials vault is never indexed), embedding
    cache / persistence round-trip.

  * Integration through api.py — corpus gather across all sources, the
    lexical retrieval that feeds handle_ai_chat, embedding incremental
    caching + semantic rerank (provider stubbed — network-free), and the
    three /api/ai/rag/* endpoints incl. their auth requirements.

Network-free throughout: ai_provider.embed is stubbed so no test ever
reaches a real embeddings endpoint.
"""
import hashlib
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_CGI_BIN = Path(__file__).parent.parent / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

import rag_index  # noqa: E402  (pure module, safe to import directly)


# ── Pure-module tests ────────────────────────────────────────────────────────

class TestTokenizer(unittest.TestCase):
    def test_preserves_technical_tokens(self):
        toks = rag_index.tokenize(
            "The nginx-1.25.3 host has CVE-2024-3094 at 192.168.1.10")
        self.assertIn("cve-2024-3094", toks)   # whole id searchable
        self.assertIn("3094", toks)            # ... and its pieces
        self.assertIn("nginx-1.25.3", toks)
        self.assertIn("nginx", toks)
        self.assertIn("192.168.1.10", toks)

    def test_drops_stopwords_but_keeps_signal(self):
        toks = rag_index.tokenize("the service is down and has an error")
        self.assertNotIn("the", toks)
        self.assertNotIn("is", toks)
        self.assertNotIn("has", toks)
        # ops-relevant words must survive the (deliberately small) stoplist
        self.assertIn("down", toks)
        self.assertIn("error", toks)
        self.assertIn("service", toks)

    def test_empty(self):
        self.assertEqual(rag_index.tokenize(""), [])
        self.assertEqual(rag_index.tokenize(None), [])


class TestMarkdownChunking(unittest.TestCase):
    def test_splits_on_headings_with_breadcrumb(self):
        md = "# Install\nintro\n## Debian\napt install foo\n## RHEL\ndnf install foo"
        chunks = rag_index.chunk_markdown(md)
        paths = [p for p, _ in chunks]
        self.assertTrue(any("Debian" in p for p in paths))
        self.assertTrue(any("RHEL" in p for p in paths))
        # breadcrumb includes the parent heading
        self.assertTrue(any(p.startswith("Install >") for p in paths))

    def test_oversize_section_is_split(self):
        body = "\n\n".join(["para %d %s" % (i, "x" * 200) for i in range(20)])
        md = "# Big\n" + body
        chunks = rag_index.chunk_markdown(md, max_chars=500)
        self.assertGreater(len(chunks), 1)
        self.assertTrue(all(len(c) <= 1200 for _, c in chunks))

    def test_no_headings_yields_one_chunk(self):
        chunks = rag_index.chunk_markdown("just some text with no heading")
        self.assertEqual(len(chunks), 1)

    def test_empty(self):
        self.assertEqual(rag_index.chunk_markdown(""), [])


class TestBM25(unittest.TestCase):
    def _idx(self):
        docs = rag_index.build_docs_corpus([
            ("nginx", "# Nginx\nrestart the nginx web server using systemctl"),
            ("pg", "# Postgres\nvacuum and back up the postgres database daily"),
            ("ssh", "# SSH\nharden sshd and disable password auth"),
        ])
        return rag_index.InfraIndex().build(docs)

    def test_top1_is_relevant(self):
        idx = self._idx()
        hits = idx.search("restart nginx", top_n=1)
        self.assertTrue(hits)
        self.assertIn("nginx", hits[0]["id"])

    def test_irrelevant_query_returns_nothing(self):
        idx = self._idx()
        self.assertEqual(idx.search("kubernetes helm istio", top_n=3), [])

    def test_persistence_roundtrip(self):
        idx = self._idx()
        idx2 = rag_index.InfraIndex.from_dict(idx.to_dict())
        self.assertEqual(idx2.stats()["docs"], idx.stats()["docs"])
        hits = idx2.search("postgres backup", top_n=1)
        self.assertIn("pg", hits[0]["id"])


class TestRRF(unittest.TestCase):
    def test_fusion_rewards_agreement(self):
        # 'a' is rank-1 in both lists; it should outrank items that appear
        # high in only one list.
        fused = rag_index.rrf_fuse([["a", "b", "c"], ["a", "c", "d"]])
        self.assertEqual(max(fused, key=fused.get), "a")
        self.assertGreater(fused["a"], fused["b"])
        self.assertGreater(fused["c"], fused["d"])  # c in both > d in one

    def test_cosine_bounds(self):
        self.assertAlmostEqual(rag_index.cosine([1, 0], [1, 0]), 1.0)
        self.assertAlmostEqual(rag_index.cosine([1, 0], [0, 1]), 0.0)
        self.assertEqual(rag_index.cosine([], [1]), 0.0)        # degenerate
        self.assertEqual(rag_index.cosine([0, 0], [1, 1]), 0.0)  # zero vector


class TestCorpusBuilders(unittest.TestCase):
    def test_cmdb_never_indexes_credentials(self):
        store = {
            "web01": {
                "name": "web01", "role": "prod web",
                "credentials": {"root_pw": "SECRET-HUNTER2",
                                "api_token": "tok_abc123"},
                "docs": [{"id": "d1", "title": "Failover",
                          "body": "# Failover\nPromote db02 then restart nginx."}],
            }
        }
        docs = rag_index.build_cmdb_corpus(store)
        blob = "\n".join(d["text"] for d in docs)
        self.assertNotIn("SECRET-HUNTER2", blob)
        self.assertNotIn("tok_abc123", blob)
        # but the asset metadata + doc body ARE indexed
        self.assertIn("prod web", blob)
        self.assertIn("Promote db02", blob)

    def test_live_state_facets(self):
        devs = [{"id": "web01", "name": "web01", "os": "Debian 13",
                 "sysinfo": {"kernel": "6.1.0", "disks": [{"mount": "/", "percent": 91}]},
                 "services": [{"name": "nginx", "state": "running"}]}]
        docs = rag_index.build_live_state_corpus(
            devs, facets={"web01": {"cves": [{"id": "CVE-2024-3094"}]}})
        ids = {d["id"] for d in docs}
        self.assertIn("live/web01#summary", ids)
        self.assertIn("live/web01#hardware", ids)
        self.assertIn("live/web01#services", ids)
        self.assertIn("live/web01#cves", ids)

    def test_history_redactor_applied(self):
        # redactor that scrubs IPs, mimicking ai_provider.redact behaviour
        def redactor(t):
            import re
            return re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<IP>", t)
        docs = rag_index.build_history_corpus(
            commands={"web01": [{"cmd": "curl 10.0.0.5", "rc": 0, "ts": 100}]},
            now=100, redactor=redactor)
        blob = "\n".join(d["text"] for d in docs)
        self.assertIn("<IP>", blob)
        self.assertNotIn("10.0.0.5", blob)


class TestEmbeddingCache(unittest.TestCase):
    def test_incremental_and_persist(self):
        idx = rag_index.InfraIndex().build(rag_index.build_docs_corpus([
            ("a", "# A\nalpha bravo charlie"),
            ("b", "# B\ndelta echo foxtrot"),
        ]))
        missing = idx.missing_embeddings()
        self.assertEqual(len(missing), 2)
        idx.set_embeddings({h: [1.0, 0.0] for h, _ in missing}, model="stub")
        self.assertTrue(idx.has_embeddings())
        # nothing missing now
        self.assertEqual(idx.missing_embeddings(), [])
        # survives a persistence round-trip
        idx2 = rag_index.InfraIndex.from_dict(idx.to_dict())
        self.assertEqual(idx2.stats()["embedded"], 2)
        self.assertEqual(idx2.emb_model, "stub")

    def test_rebuild_drops_stale_cache_entries(self):
        idx = rag_index.InfraIndex().build(rag_index.build_docs_corpus(
            [("a", "# A\nalpha bravo")]))
        m = idx.missing_embeddings()
        idx.set_embeddings({h: [1.0] for h, _ in m})
        self.assertEqual(idx.stats()["embedded"], 1)
        # rebuild with entirely different content -> old hash pruned
        idx.build(rag_index.build_docs_corpus([("a", "# A\ncompletely different")]))
        self.assertEqual(idx.stats()["embedded"], 0)


# ── Integration via api.py ───────────────────────────────────────────────────

_TMPDIR = tempfile.mkdtemp()
_DOCSDIR = tempfile.mkdtemp()
os.environ["RP_DATA_DIR"] = _TMPDIR
os.environ["RP_DOCS_DIR"] = _DOCSDIR
os.environ.setdefault("REQUEST_METHOD", "GET")
os.environ.setdefault("PATH_INFO", "/")
os.environ.setdefault("CONTENT_LENGTH", "0")

_spec = importlib.util.spec_from_file_location("api_rag", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import ai_provider  # noqa: E402


class _Captured(Exception):
    def __init__(self, status, body):
        super().__init__(f"HTTP {status}")
        self.status = status
        self.body = body


def _patch_respond():
    def fake(status, data):
        raise _Captured(status, data)
    api.respond = fake


def _stub_embed():
    """Deterministic 8-dim embedding from a sha256 of the text. Counts calls
    so tests can assert incremental behaviour."""
    state = {"calls": 0}

    def embed(cfg, texts, model=None):
        state["calls"] += 1
        vecs = []
        for t in texts:
            h = hashlib.sha256(t.encode()).digest()[:8]
            vecs.append([b / 255.0 for b in h])
        return {"ok": True, "vectors": vecs, "model": "stub-embed", "dim": 8}
    api_provider_embed = ai_provider.embed
    ai_provider.embed = embed
    ai_provider.supports_embeddings = lambda cfg: cfg.get("provider") in (
        "ollama", "localai", "openai")
    return state, api_provider_embed


def _seed_fleet():
    # Use a current timestamp so history (which keeps only the last N days)
    # isn't filtered out by the max_age cutoff.
    import time as _t
    now = int(_t.time())
    api.save(api.DEVICES_FILE, {"web01": {
        "id": "web01", "name": "web01", "os": "Debian 13",
        "sysinfo": {"kernel": "6.1.0-21", "disks": [{"mount": "/", "percent": 92}]},
        "services": [{"name": "nginx", "state": "running"}], "last_seen": now}})
    api.save(api.CVE_FINDINGS_FILE, {"web01": {"findings": [
        {"id": "CVE-2024-3094", "severity": "critical", "pkg": "xz"}]}})
    api.save(api.CONTAINERS_FILE, {"web01": {"ts": now, "items": [
        {"name": "app", "image": "nginx:1.25", "state": "running"}]}})
    api.save(api.CMDB_FILE, {"web01": {
        "name": "web01", "role": "prod web",
        "credentials": {"root_pw": "SECRET-HUNTER2"},
        "docs": [{"id": "d1", "title": "Failover",
                  "body": "# Failover\nPromote db02 then restart nginx."}]}})
    api.save(api.RUNBOOKS_FILE, {"web01": {
        "content": "# Web01 runbook\nThis host runs nginx behind HAProxy.",
        "generated_at": now}})
    api.save(api.CMD_OUTPUT_FILE, {"web01": [
        {"cmd": "systemctl status nginx", "rc": 0, "ts": now}]})
    api.save(api.ALERTS_FILE, {"alerts": [
        {"type": "cve_found", "severity": "critical", "device": "web01",
         "message": "xz CVE", "ts": now}]})
    api.save(api.FLEET_EVENTS_FILE, {"events": [
        {"event": "device_online", "device": "web01", "ts": now}]})


def _enable_rag(provider="anthropic", embeddings=False):
    cfg = api.load(api.CONFIG_FILE) or {}
    ai = cfg.get("ai") or {}
    ai["enabled"] = True
    ai["provider"] = provider
    ai["rag"] = {"enabled": True, "embeddings_enabled": embeddings}
    cfg["ai"] = ai
    api.save(api.CONFIG_FILE, cfg)


class TestApiCorpus(unittest.TestCase):
    def setUp(self):
        _patch_respond()
        _seed_fleet()
        _enable_rag()

    def test_reindex_covers_all_sources(self):
        cfg = api._ai_cfg()
        stats = api._rag_reindex(cfg)
        self.assertGreater(stats["docs"], 0)
        self.assertEqual(set(stats["by_source"]),
                         {"docs", "live_state", "cmdb", "history"})

    def test_vault_secret_never_in_corpus(self):
        api._rag_reindex(api._ai_cfg())
        blob = "\n".join(d["text"] for d in api._rag_load_index().docs)
        self.assertNotIn("SECRET-HUNTER2", blob)

    def test_retrieval_finds_relevant_chunks(self):
        cfg = api._ai_cfg()
        api._rag_reindex(cfg)
        hits = api._rag_retrieve(cfg, "how do I restart nginx")
        self.assertTrue(any("nginx" in h["id"] or "runbook" in h["id"]
                            for h in hits))
        cve_hits = api._rag_retrieve(cfg, "critical CVE on web01")
        self.assertTrue(any("cve" in h["id"] or "alert" in h["id"]
                            for h in cve_hits))

    def test_lexical_works_without_embeddings(self):
        # Anthropic provider => embeddings inactive, retrieval still works.
        cfg = api._ai_cfg()
        self.assertFalse(api._rag_embeddings_active(cfg))
        api._rag_reindex(cfg)
        self.assertTrue(api._rag_retrieve(cfg, "nginx"))


class TestApiEmbeddings(unittest.TestCase):
    def setUp(self):
        _patch_respond()
        _seed_fleet()
        _enable_rag(provider="ollama", embeddings=True)
        self.state, self._orig = _stub_embed()

    def tearDown(self):
        ai_provider.embed = self._orig

    def test_incremental_embedding(self):
        cfg = api._ai_cfg()
        self.assertTrue(api._rag_embeddings_active(cfg))
        s1 = api._rag_reindex(cfg)
        self.assertEqual(s1["embedded"], s1["docs"])
        # second reindex, no source change: zero new embedding calls
        self.state["calls"] = 0
        api._rag_reindex(cfg)
        self.assertEqual(self.state["calls"], 0)

    def test_semantic_path_used(self):
        cfg = api._ai_cfg()
        api._rag_reindex(cfg)
        self.state["calls"] = 0
        hits = api._rag_retrieve(cfg, "disk almost full")
        # one call to embed the query, and semantic recall surfaces hardware
        self.assertEqual(self.state["calls"], 1)
        self.assertTrue(hits)


class TestApiEndpoints(unittest.TestCase):
    def setUp(self):
        _patch_respond()
        _seed_fleet()
        _enable_rag()
        api.require_auth = lambda **kw: "user1"
        api.require_admin_auth = lambda: "admin1"

    def _call(self, fn):
        try:
            fn()
        except _Captured as c:
            return c.status, c.body
        return None, None

    def test_status_endpoint(self):
        st, body = self._call(api.handle_ai_rag_status)
        self.assertEqual(st, 200)
        self.assertTrue(body["enabled"])
        self.assertIn("docs", body)

    def test_reindex_requires_admin(self):
        denied = {"hit": False}

        def deny():
            denied["hit"] = True
            raise _Captured(403, {"error": "admin required"})
        api.require_admin_auth = deny
        st, _ = self._call(api.handle_ai_rag_reindex)
        self.assertTrue(denied["hit"])
        self.assertEqual(st, 403)

    def test_reindex_then_search(self):
        os.environ["REQUEST_METHOD"] = "POST"
        st, body = self._call(api.handle_ai_rag_reindex)
        self.assertEqual(st, 200)
        self.assertTrue(body["ok"])
        self.assertGreater(body["docs"], 0)

        api.get_json_body = lambda: {"query": "restart nginx"}
        st, body = self._call(api.handle_ai_rag_search)
        self.assertEqual(st, 200)
        self.assertTrue(body["ok"])
        self.assertTrue(body["results"])
        # excerpt must be present and credentials must never leak via search
        blob = "\n".join(r["excerpt"] for r in body["results"])
        self.assertNotIn("SECRET-HUNTER2", blob)

    def test_search_rejects_empty_query(self):
        os.environ["REQUEST_METHOD"] = "POST"
        api.get_json_body = lambda: {"query": "  "}
        st, body = self._call(api.handle_ai_rag_search)
        self.assertEqual(st, 400)


if __name__ == "__main__":
    unittest.main()
