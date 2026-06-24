"""Regression: the RAG embedding cache must be invalidated when the embedding
space (provider / base_url / model) changes.

It was keyed only by chunk content hash and never compared against the active
model, so switching the embedding model left old-model vectors in the cache.
missing_embeddings() then reported nothing to embed, the new-model query was
compared against the stale vectors, and on a dimension mismatch cosine()
silently returns 0.0 (rag_index: `len(a)!=len(b) -> 0.0`) -- semantic ranking
collapses to lexical-only with no error surfaced.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())
_CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, _CGI / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


rag_index = _load('rag_index_emb', 'rag_index.py')
ai_provider = _load('ai_provider_emb', 'ai_provider.py')


def _one_chunk_index(text='nginx on web host'):
    idx = rag_index.InfraIndex()
    idx.build([{'id': 'c1', 'hash': 'h1', 'text': text, 'device': 'd1'}], built_at=1)
    return idx


class TestEmbeddingFingerprint(unittest.TestCase):
    def test_fingerprint_tracks_model(self):
        small = {'provider': 'openai', 'rag': {'embedding_model': 'text-embedding-3-small'}}
        large = {'provider': 'openai', 'rag': {'embedding_model': 'text-embedding-3-large'}}
        fp_small = ai_provider.embedding_fingerprint(small)
        self.assertTrue(fp_small)
        self.assertNotEqual(fp_small, ai_provider.embedding_fingerprint(large))

    def test_fingerprint_tracks_base_url(self):
        a = {'provider': 'openai', 'base_url': 'https://api.openai.com/v1',
             'rag': {'embedding_model': 'm'}}
        b = {'provider': 'openai', 'base_url': 'http://ollama.local:11434/v1',
             'rag': {'embedding_model': 'm'}}
        self.assertNotEqual(ai_provider.embedding_fingerprint(a),
                            ai_provider.embedding_fingerprint(b))

    def test_cache_invalidated_when_fingerprint_changes(self):
        idx = _one_chunk_index()
        # First embed under fingerprint A.
        self.assertEqual(len(idx.missing_embeddings('openai|url|small')), 1)
        idx.set_embeddings({'h1': [0.1, 0.2, 0.3]}, model='small')
        # Same fingerprint -> cache hit, nothing missing.
        self.assertEqual(idx.missing_embeddings('openai|url|small'), [])
        # Model swap -> whole cache dropped, chunk needs re-embedding.
        missing = idx.missing_embeddings('openai|url|large')
        self.assertEqual([h for h, _ in missing], ['h1'])
        self.assertEqual(idx.emb_cache, {})

    def test_fingerprint_persisted_across_roundtrip(self):
        idx = _one_chunk_index()
        idx.missing_embeddings('openai|url|small')
        idx.set_embeddings({'h1': [0.1, 0.2, 0.3]}, model='small')
        reloaded = rag_index.InfraIndex.from_dict(idx.to_dict())
        self.assertEqual(reloaded.emb_fingerprint, 'openai|url|small')
        # A model change after reload still busts the restored cache.
        self.assertEqual(len(reloaded.missing_embeddings('openai|url|large')), 1)

    def test_no_fingerprint_keeps_old_behaviour(self):
        # Called without a fingerprint (e.g. embeddings not configured), the
        # cache is untouched -- backward compatible.
        idx = _one_chunk_index()
        idx.set_embeddings({'h1': [0.1, 0.2, 0.3]}, model='small')
        self.assertEqual(idx.missing_embeddings(), [])
        self.assertEqual(idx.emb_cache, {'h1': {'v': [0.1, 0.2, 0.3]}})


if __name__ == '__main__':
    unittest.main()
