#!/usr/bin/env python3
"""8.0.2 review (ST-06): with RP_CONFIG_KEY armed, the settings that carry a credential are sealed at rest, wherever they are kept.

The matcher of `_config_secrets_outbound` knew names (password, secret, token, ...). The address of a Slack, Discord or Teams hook has its token in the path, a header value
is the credential of an `Authorization` header, and the health-check, SIEM, audit-forward and OTLP addresses can carry one: six of the seven fields of the repro were stored in
plain text beside a sealed `smtp_password`. The list of those fields is one function now (`_nonname_config_secret_sites`), used by the exports' redaction and by the sealing.
The same document was also kept, decrypted, in every settings revision (the last ten saves), and the failed-delivery queue kept its destinations whole.

Each case runs in a child process per backend, since the master key and the backend are read at import.
"""
import json
import os
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CGI = ROOT / 'server' / 'cgi-bin'

PROBE = textwrap.dedent('''
    import os, sys, json, tempfile, importlib.util
    os.environ['RP_CONFIG_KEY'] = 'operator-master-key'
    os.environ['RP_DATA_DIR'] = tempfile.mkdtemp()
    os.environ['RP_STORAGE_BACKEND'] = sys.argv[1]
    sys.path.insert(0, sys.argv[2])
    spec = importlib.util.spec_from_file_location('api', sys.argv[2] + '/api.py')
    api = importlib.util.module_from_spec(spec)
    sys.modules['api'] = api
    spec.loader.exec_module(api)

    HOOK = 'https://hooks.example.invalid/services/T00/B00/HOOKTOKEN-77'
    HDR = 'Bearer HEADER-SECRET-31'
    DOC = {'server_name': 'rp', 'smtp_password': 'SMTP-hunter2',
           'webhook_urls': [{'id': 'wh1', 'label': 'ops', 'url': HOOK, 'headers': {'Authorization': HDR}, 'pushover_user': 'PUSHUSER-9',
                             'hmac_secret': 'HMAC-1'}],
           'healthchecks_url': 'https://hc.example.invalid/ping/PINGKEY-5', 'siem_url': 'https://siem.example.invalid/in/SIEMKEY-6',
           'audit_forward_url': 'https://af.example.invalid/AFKEY-7', 'otlp_endpoint': 'https://otlp.example.invalid/OTLPKEY-8'}
    MARKS = ['HOOKTOKEN-77', 'HEADER-SECRET-31', 'PUSHUSER-9', 'HMAC-1', 'SMTP-hunter2', 'PINGKEY-5', 'SIEMKEY-6', 'AFKEY-7', 'OTLPKEY-8']

    def raw(path):
        mod = api._dbmod()
        if mod is not None:
            api._invalidate_load_cache(path)
            return json.dumps(mod.load(path) or {})
        return Path(path).read_text() if Path(path).exists() else '{}'

    from pathlib import Path
    out = {}
    api.save(api.CONFIG_FILE, json.loads(json.dumps(DOC)))
    text = raw(api.CONFIG_FILE)
    out['config_plain'] = [m for m in MARKS if m in text]
    api._LOAD_CACHE.clear()
    out['config_reads_back'] = api.load(api.CONFIG_FILE)['webhook_urls'][0]['url'] == HOOK

    api.record_config_revision(json.loads(json.dumps(DOC)), dict(DOC, server_name='changed'), 'tester')
    text = raw(api.CONFIG_REVS_FILE)
    out['revisions_plain'] = [m for m in MARKS if m in text]

    api._dlq_record('server_disk_low', json.loads(json.dumps(DOC['webhook_urls'][0])), {'name': 'x'}, 'm', 't', 3, 'boom')
    text = raw(api.WEBHOOK_DLQ_FILE)
    out['dlq_plain'] = [m for m in MARKS if m in text]
    api._LOAD_CACHE.clear()
    entry = api.load(api.WEBHOOK_DLQ_FILE)['entries'][0]
    dest = api._unseal_dest(entry['dest'])
    out['dlq_unseals'] = dest['url'] == HOOK and dest['headers']['Authorization'] == HDR and dest['hmac_secret'] == 'HMAC-1'
    out['dlq_top_url'] = entry['url']
    print(json.dumps(out))
''')


def run_probe(backend):
    p = subprocess.run([sys.executable, '-c', PROBE, backend, str(CGI)], capture_output=True, text=True, timeout=300,
                       env={**os.environ, 'PYTHONPATH': ''})
    assert p.returncode == 0, p.stderr[-2000:]
    return json.loads(p.stdout.strip().splitlines()[-1])


class _Cases(unittest.TestCase):
    backend = ''

    @classmethod
    def setUpClass(cls):
        if not cls.backend:
            raise unittest.SkipTest('the base of the two backend classes')
        cls.out = run_probe(cls.backend)

    def test_the_settings_hold_no_credential_in_plain_text(self):
        self.assertEqual(self.out['config_plain'], [])
        self.assertTrue(self.out['config_reads_back'], 'control: the sealed settings read back whole')

    def test_the_revisions_hold_none_either(self):
        self.assertEqual(self.out['revisions_plain'], [])

    def test_the_failed_delivery_queue_holds_none_and_a_retry_can_open_it(self):
        self.assertEqual(self.out['dlq_plain'], [])
        self.assertTrue(self.out['dlq_unseals'])
        self.assertEqual(self.out['dlq_top_url'], 'https://hooks.example.invalid', 'the queue keeps the host of the address, which is what the page shows')


class TestJson(_Cases):
    backend = 'json'


class TestSqlite(_Cases):
    backend = 'sqlite'


class TestOneListOfTheFieldsTheMatcherDoesNotKnow(unittest.TestCase):
    def test_the_exports_and_the_sealing_share_it(self):
        src = (CGI / 'api.py').read_text()
        self.assertIn('def _nonname_config_secret_sites(', src)
        self.assertEqual(src.count('_nonname_config_secret_sites(cfg)'), 3, 'the definition, the redaction and the sealing: both read the one list')
        self.assertIn('_seal_nonname_config_secrets(out)', src)


if __name__ == '__main__':
    unittest.main()
