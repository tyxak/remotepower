"""v5.6.0 finalize-sweep guardrail: the CMDB/facet RAG corpus must never embed a
secret-named free-form field.

Regression for the Medium found in the sweep: `_CMDB_SECRET_KEYS` was an *exact*
name set (credentials/secrets/vault/password) that missed api_key/token/passphrase/
private_key/community/… so an operator-added plaintext field could be embedded into
the vector store (and sent to a cloud embedding provider). The fix is a
case-insensitive substring matcher (`_is_secret_key`) applied to both the CMDB
metadata loop and the generic `_format_facet`.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'))
import rag_index  # noqa: E402


class TestRagSecretExclusion(unittest.TestCase):

    def _corpus_text(self, store):
        return '\n'.join(d['text'] for d in rag_index.build_cmdb_corpus(store))

    def test_secret_named_fields_excluded(self):
        store = {'dev1': {
            'name': 'web01', 'os': 'Debian 12',
            'api_key': 'FAKEKEYVAL_should_not_leak',
            'snmp_community': 'private-community-str',
            'bearer_token': 'BEARER_LEAK',
            'db_passphrase': 'hunter2',
            'ssh_private_key': 'KEYLEAK',
            'bmc': {'token': 'NESTED_TOKEN', 'ip': '10.0.0.9'},
        }}
        blob = self._corpus_text(store)
        for leak in ('FAKEKEYVAL_should_not_leak', 'private-community-str', 'BEARER_LEAK',
                     'hunter2', 'KEYLEAK', 'NESTED_TOKEN'):
            self.assertNotIn(leak, blob, f"secret leaked into RAG corpus: {leak}")
        # non-secret fields are still indexed
        self.assertIn('web01', blob)
        self.assertIn('Debian 12', blob)
        self.assertIn('10.0.0.9', blob)

    def test_list_of_dicts_subkeys_filtered(self):
        # v5.8.0 bughunt: the metadata-loop LIST branch must secret-filter its
        # item sub-keys too (it used to str(x) the whole dict, embedding them
        # verbatim). A license/activation key and a nested token in a custom
        # list must not reach the corpus; non-secret siblings stay searchable.
        store = {'dev2': {
            'name': 'db01',
            'licenses': [{'product': 'Widgets Pro', 'key': 'LICENSE-KEY-LEAK-123',
                          'seats': 10, 'expiry': '2030-01-01'}],
            'custom_things': [{'label': 'thing', 'token': 'LIST_TOKEN_LEAK'}],
        }}
        blob = self._corpus_text(store)
        self.assertNotIn('LICENSE-KEY-LEAK-123', blob)
        self.assertNotIn('LIST_TOKEN_LEAK', blob)
        self.assertIn('Widgets Pro', blob)   # non-secret sibling fields kept
        self.assertIn('thing', blob)

    def test_is_secret_key_matches_substrings(self):
        for k in ('api_key', 'API_KEY', 'x-token', 'db_passphrase',
                  'ssh_private_key', 'snmp_community', 'bearer', 'webhook_url', 'vault'):
            self.assertTrue(rag_index._is_secret_key(k), k)
        for k in ('name', 'os', 'ip', 'hostname', 'owner', 'location', 'serial'):
            self.assertFalse(rag_index._is_secret_key(k), k)

    def test_format_facet_drops_secret_keys(self):
        out = rag_index._format_facet({'ok_field': 'shown', 'api_key': 'HIDE_ME'})
        self.assertIn('shown', out)
        self.assertNotIn('HIDE_ME', out)


if __name__ == '__main__':
    unittest.main()
