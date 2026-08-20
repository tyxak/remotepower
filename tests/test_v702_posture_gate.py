#!/usr/bin/env python3
"""FileVault off on a Mac without psutil was silent forever.

The heartbeat runs `_ingest_posture_v3110` only if the report carries at least
one of a set of sysinfo keys. That set was a hand-written tuple at the call
site, and five of the keys the function reads were missing from it:
`mac_posture`, `ecc`, `ssh_config`, `autoupdate`, `ssh_hostkeys`.

The macOS agent collects `mac_posture` OUTSIDE its psutil block, while `mounts`,
`network_io` and `listening_ports` are all inside it. So a Mac reporting
`psutil: False` — a supported state, whitelisted by safe_si — sent
`mac_posture` and not one key in the gate. `mac_filevault_off`,
`mac_firewall_off`, `mac_gatekeeper_off` and `mac_sip_disabled` could never
fire on that host.

The Windows twin escaped only because `win_posture` happened to be listed, and
the comment beside the tuple already admitted `ssh_hostkeys` "rides in only
because virtually every host also reports mounts; that is luck, not design".

`_POSTURE_INGEST_KEYS` is the set now, and this parses the function to check it
— in BOTH directions, since a key listed but never read is dead weight that
reads like coverage.
"""
import ast
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(_ROOT / 'tests'))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-posture-'))
_spec = importlib.util.spec_from_file_location('api_posture_gate', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import srcpin                                                    # noqa: E402


def _keys_the_function_reads():
    body = srcpin.py_function((_CGI / 'api.py').read_text(),
                              '_ingest_posture_v3110')
    fd = ast.parse(body).body[0]
    param = fd.args.args[2].arg
    keys = set()
    for n in ast.walk(fd):
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr == 'get'
                and isinstance(n.func.value, ast.Name)
                and n.func.value.id == param and n.args
                and isinstance(n.args[0], ast.Constant)):
            keys.add(n.args[0].value)
        if (isinstance(n, ast.Subscript) and isinstance(n.value, ast.Name)
                and n.value.id == param and isinstance(n.slice, ast.Constant)):
            keys.add(n.slice.value)
    return keys


class TestTheGateCoversWhatTheFunctionReads(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.read = _keys_the_function_reads()
        cls.gate = set(api._POSTURE_INGEST_KEYS)

    def test_the_parser_found_a_plausible_key_set(self):
        """Positive control. An empty set makes both directions below pass."""
        self.assertGreaterEqual(len(self.read), 10, sorted(self.read))
        self.assertIn('mac_posture', self.read)
        self.assertIn('win_posture', self.read)

    def test_no_key_is_read_without_being_in_the_gate(self):
        missing = sorted(self.read - self.gate - {'modules_visible'})
        self.assertEqual([], missing,
                         f'the ingest reads these and the gate does not admit '
                         f'them, so a host that sends ONLY one of them is '
                         f'never ingested: {missing}')

    def test_no_key_is_in_the_gate_without_being_read(self):
        """The other direction: a listed key the function never reads is dead
        weight that reads like coverage."""
        extra = sorted(self.gate - self.read)
        self.assertEqual([], extra, f'gate keys nothing reads: {extra}')

    def test_modules_visible_is_excluded_on_purpose(self):
        """Its meaningful value is False, which a truthiness gate skips — so it
        is presence-tested at the call site instead. Putting it in the tuple
        would silently re-break the case the v6.2.2 comment describes."""
        self.assertNotIn('modules_visible', self.gate)
        src = (_CGI / 'api.py').read_text()
        self.assertIn("_si.get('modules_visible') is not None", src)

    def test_the_call_site_uses_the_tuple(self):
        src = (_CGI / 'api.py').read_text()
        self.assertIn('for k in _POSTURE_INGEST_KEYS', src)


class TestAMacWithoutPsutilIsCovered(unittest.TestCase):
    """The specific host that was silent. Named because a generic set-equality
    check would go green again the day someone trims the tuple to match a
    trimmed function."""

    def test_mac_posture_alone_admits_the_report(self):
        si = {'mac_posture': {'filevault': False}}
        self.assertTrue(any(si.get(k) for k in api._POSTURE_INGEST_KEYS),
                        'a Mac sending only mac_posture is still not ingested')

    def test_the_keys_a_psutil_less_mac_cannot_send_are_not_required(self):
        """mounts / network_io / listening_ports live inside the agent's psutil
        block. The gate must not depend on them."""
        for k in ('mounts', 'network_io', 'listening_ports'):
            si = {'mac_posture': {'filevault': False}}
            self.assertNotIn(k, si)
        self.assertTrue(any({'mac_posture': {'x': 1}}.get(k)
                            for k in api._POSTURE_INGEST_KEYS))

    def test_an_empty_report_is_still_skipped(self):
        """The negative half — a gate that admitted everything would satisfy
        both tests above and run the ingest on every heartbeat."""
        self.assertFalse(any({}.get(k) for k in api._POSTURE_INGEST_KEYS))


if __name__ == '__main__':
    unittest.main()
