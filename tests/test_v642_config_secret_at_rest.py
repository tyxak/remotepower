"""Config-secret encryption must survive a write through the LOCK, on every backend.

`save()` runs `_config_secrets_outbound()`; `_save_held()` — which
`_JsonLockedUpdate.__exit__` uses — did not. `load()` decrypts in place, so the
lock yielded plaintext and wrote that plaintext straight back: one write through
`_LockedUpdate(CONFIG_FILE)` stripped encryption from the WHOLE document, not
just the key being touched.

That was latent while most config writes still went through `save()` (a Settings
save re-encrypted whatever a lock had stripped). Moving every config write onto
the lock — the v6.4.2 race fix — made it automatic: `_claim_cadence_slot()` fires
from `main()` on ordinary traffic, so an install with `RP_CONFIG_KEY` set lost
at-rest encryption of `smtp_password`, `oidc_client_secret`, `ldap_bind_password`
and every `webhook_url` (which embeds a Slack/Discord/Teams token) within one
cadence interval, with no operator action and nothing reported.

The DB backends had the mirror-image defect: `_DbLockedUpdate.__enter__` bypasses
`api.load()`, so a config lock yielded `enc:v2:…` CIPHERTEXT — a handler reading
a secret inside the lock got the marker string, and a secret assigned inside the
lock was stored in the clear.

The whole gate stayed green through both because no existing test sets
`RP_CONFIG_KEY` anywhere near the lock path. These run each case in a child
process per backend, since the master key and the backend are read at import.
"""

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"

_PROBE = textwrap.dedent(
    """
    import os, sys, json, time, tempfile, importlib.util
    os.environ['RP_CONFIG_KEY'] = 'operator-master-key'
    os.environ['RP_DATA_DIR'] = tempfile.mkdtemp()
    os.environ['RP_STORAGE_BACKEND'] = sys.argv[1]
    sys.path.insert(0, sys.argv[2])
    spec = importlib.util.spec_from_file_location('api', sys.argv[2] + '/api.py')
    api = importlib.util.module_from_spec(spec)
    sys.modules['api'] = api
    spec.loader.exec_module(api)

    CFG = api.CONFIG_FILE
    SECRETS = {'smtp_password': 'SMTP-hunter2',
               'oidc_client_secret': 'oidc-abc123',
               'webhook_url': 'https://hooks.slack.com/services/T00/B00/TOKEN'}

    def stored():
        '''The document as it sits at rest, without load()'s decrypt.'''
        mod = api._dbmod()
        if mod is not None:
            api._invalidate_load_cache(CFG)
            return mod.load(CFG) or {}
        return json.loads(CFG.read_text())

    api.save(CFG, dict(SECRETS, server_name='rp'))
    out = {'encrypted_after_save':
               all(str(stored()[k]).startswith('enc:v') for k in SECRETS)}

    # Exactly what every cadence sweep does now.
    api._claim_cadence_slot('last_snmp_poll', int(time.time()))
    out['encrypted_after_cadence_claim'] = \\
        all(str(stored()[k]).startswith('enc:v') for k in SECRETS)

    with api._LockedUpdate(CFG) as cfg:
        out['read_inside_lock'] = cfg.get('smtp_password')
        cfg['oidc_client_secret'] = 'rotated-secret'
    out['written_inside_lock_encrypted'] = \\
        str(stored()['oidc_client_secret']).startswith('enc:v')
    api._invalidate_load_cache(CFG)
    out['round_trips_to_plaintext'] = \\
        api.load(CFG).get('oidc_client_secret') == 'rotated-secret'
    print('RESULT ' + json.dumps(out))
    """
)


def _probe(backend):
    with tempfile.NamedTemporaryFile('w', suffix='.py', delete=False) as fh:
        fh.write(_PROBE)
        script = fh.name
    try:
        proc = subprocess.run([sys.executable, script, backend, str(_CGI)],
                              capture_output=True, text=True, timeout=180)
    finally:
        os.unlink(script)
    line = next((l for l in proc.stdout.splitlines() if l.startswith('RESULT ')), None)
    if line is None:
        raise AssertionError(f"probe failed on {backend}:\n"
                             f"{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}")
    return json.loads(line[len('RESULT '):])


class TestConfigSecretsSurviveTheLock(unittest.TestCase):

    def _check(self, backend):
        r = _probe(backend)
        self.assertTrue(r['encrypted_after_save'],
                        f'[{backend}] save() did not encrypt at rest — fixture is wrong')
        self.assertTrue(r['encrypted_after_cadence_claim'],
                        f'[{backend}] a cadence due-marker write stripped encryption from '
                        'the whole config; _save_held must run _config_secrets_outbound')
        self.assertEqual(r['read_inside_lock'], 'SMTP-hunter2',
                         f'[{backend}] a secret read inside the config lock must be '
                         'plaintext on every backend, not the enc: marker')
        self.assertTrue(r['written_inside_lock_encrypted'],
                        f'[{backend}] a secret assigned inside the lock was stored in '
                        'the clear')
        self.assertTrue(r['round_trips_to_plaintext'],
                        f'[{backend}] the re-encrypted value does not decrypt back')

    def test_json_backend(self):
        self._check('json')

    def test_sqlite_backend(self):
        self._check('sqlite')


class TestSaveHeldMirrorsSave(unittest.TestCase):
    """Source-level pin so the two writers cannot drift apart again."""

    def test_both_writers_encrypt(self):
        import ast
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        tree = ast.parse((_CGI / "api.py").read_text())
        for name in ("save", "_save_held"):
            fn = next(n for n in ast.walk(tree)
                      if isinstance(n, ast.FunctionDef) and n.name == name)
            self.assertIn("_config_secrets_outbound", ast.dump(fn),
                          f"{name}() writes CONFIG_FILE without encrypting its "
                          "secrets at rest")



class TestDbLockYieldsTheObjectItSaves(unittest.TestCase):
    """`_DbLockedUpdate.__exit__` re-encrypts by mutating the yielded document
    IN PLACE before delegating — there is no way to hand the backend a
    different object. That is only correct because both DB backends' own
    LockedUpdate yields `self._data` and saves that same reference on exit.

    Pinned because it cannot be executed here: `test_pg.py` skips without
    `RP_PG_TEST_DSN`, so `make test` + `make test-sqlite` cover two of the three
    backends — which is exactly how a Postgres-only regression shipped earlier
    in this same sweep.
    """

    def test_both_backends_save_the_yielded_reference(self):
        import ast
        for mod in ("storage.py", "storage_pg.py"):
            tree = ast.parse((_CGI / mod).read_text())
            cls = next((n for n in ast.walk(tree)
                        if isinstance(n, ast.ClassDef) and n.name == "LockedUpdate"), None)
            self.assertIsNotNone(cls, f"{mod} lost its LockedUpdate")
            enter = next(n for n in cls.body
                         if isinstance(n, ast.FunctionDef) and n.name == "__enter__")
            exit_ = next(n for n in cls.body
                         if isinstance(n, ast.FunctionDef) and n.name == "__exit__")
            self.assertIn("return self._data", ast.unparse(enter),
                          f"{mod}: __enter__ must yield the same object __exit__ saves")
            self.assertIn("save(self.path, self._data)", ast.unparse(exit_),
                          f"{mod}: __exit__ must save the yielded object, or the "
                          "in-place re-encryption in _DbLockedUpdate is lost")

if __name__ == '__main__':
    unittest.main()
