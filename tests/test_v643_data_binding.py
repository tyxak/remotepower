#!/usr/bin/env python3
"""Signals the product collects and then throws away.

`safe_si` is a WHITELIST: a field the agent sends that it does not name is
dropped silently, and everything downstream behaves as though the agent never
sent it. CLAUDE.md documents that trap. These are the reverse-facing cases —
fields that survive the whitelist (or should) and then have no reader.

  hostname        sent by all three agents on every heartbeat, dropped, so
                  `dev['hostname']` stayed whatever the host was called at
                  ENROLMENT. LLDP and dependency topology resolve neighbours
                  BY hostname, so a rename quietly stopped them matching.
  psutil          Windows and macOS send `psutil: false` — an explicit "my
                  metrics are limited" — dropped, so three empty states could
                  only guess and told the operator to check a dependency the
                  agent had already reported on.
  x11_forwarding  collected AND whitelisted since the sshd collector shipped,
                  read by nothing. It existed end to end and meant nothing.
  sudo target     parsed, sanitised, stored and returned by both endpoints;
                  neither table rendered it, so `sudo -u backup` and `sudo -i`
                  were indistinguishable in an access review.

Each assertion below has a positive control, because "the field is absent" is
trivially true against a fixture the code never matches.
"""
import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
_JS = _ROOT / 'server' / 'html' / 'static' / 'js'
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v643bind-'))

_spec = importlib.util.spec_from_file_location('api_v643_bind', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules.setdefault('api', api)
_spec.loader.exec_module(api)

import checks as checks_mod          # noqa: E402
import rag_index                     # noqa: E402


class TestSafeSiKeepsWhatItNowNeeds(unittest.TestCase):
    """Drive the REAL heartbeat and read back what was stored.

    There is no `api.safe_si` to call — the whitelist is built inline in
    handle_heartbeat — so a source grep is the tempting shortcut and would
    prove only that a line exists. This posts an actual heartbeat and inspects
    the persisted device, which is the thing every consumer reads.
    """

    def setUp(self):
        api.save(api.DEVICES_FILE, {'d1': {
            'id': 'd1', 'name': 'operator-chosen-name', 'token': 'tok',
            'hostname': 'name-at-enrolment', 'poll_interval': 60}})
        api._invalidate_load_cache(api.DEVICES_FILE)

    def _beat(self, sysinfo):
        """POST one heartbeat carrying `sysinfo`; return the stored device."""
        _real_method, _real_body = api.method, api.get_json_body
        api.method = lambda: 'POST'
        api.get_json_body = lambda: {
            'device_id': 'd1', 'token': 'tok', 'version': '6.4.3',
            'sysinfo': sysinfo}
        api._RCTX.environ = {'REQUEST_METHOD': 'POST', 'PATH_INFO': '/api/heartbeat',
                             'QUERY_STRING': '', 'REMOTE_ADDR': '127.0.0.1'}
        try:
            api.handle_heartbeat()
        except (SystemExit, api.HTTPError):
            pass
        finally:
            # Restore, or these stubs leak into every later module in the
            # process — the second false-green class CLAUDE.md names.
            api.method, api.get_json_body = _real_method, _real_body
        api._invalidate_load_cache(api.DEVICES_FILE)
        return (api.load(api.DEVICES_FILE) or {}).get('d1') or {}

    def test_the_driver_actually_stores_a_heartbeat(self):
        """Guard the guard. If the heartbeat does not run, every assertion
        below reads {} and `assertNotIn` passes against nothing."""
        dev = self._beat({'cpu_percent': 12})
        self.assertEqual((dev.get('sysinfo') or {}).get('cpu_percent'), 12,
                         'the heartbeat did not persist — this file is '
                         'asserting against an empty device record')

    def test_hostname_reaches_the_store(self):
        dev = self._beat({'hostname': 'web-07.corp.example'})
        self.assertEqual((dev.get('sysinfo') or {}).get('hostname'),
                         'web-07.corp.example')

    def test_a_renamed_host_updates_the_device_hostname(self):
        """The actual bug: dev['hostname'] was captured at enrolment and never
        again, so a rename left the old name on the drawer, in alert payloads,
        and in the LLDP/dependency matching that resolves BY hostname."""
        dev = self._beat({'hostname': 'renamed-host'})
        self.assertEqual(dev.get('hostname'), 'renamed-host')

    def test_the_operator_chosen_name_is_never_overwritten(self):
        """The other half of the contract, and the more important one: `name`
        is the operator's field. A host must not be able to rename itself in
        the UI by changing its own hostname."""
        dev = self._beat({'hostname': 'renamed-host'})
        self.assertEqual(dev.get('name'), 'operator-chosen-name')

    def test_an_empty_hostname_does_not_wipe_the_stored_one(self):
        dev = self._beat({'hostname': ''})
        self.assertEqual(dev.get('hostname'), 'name-at-enrolment')

    def test_psutil_false_reaches_the_store_as_a_boolean(self):
        dev = self._beat({'psutil': False})
        si = dev.get('sysinfo') or {}
        self.assertIn('psutil', si, 'the honest "no psutil" signal is dropped '
                                    'again — the empty states go back to guessing')
        self.assertIs(si['psutil'], False)

    def test_psutil_true_reaches_it_too(self):
        self.assertIs((self._beat({'psutil': True}).get('sysinfo') or {}).get('psutil'),
                      True)

    def test_a_non_boolean_psutil_is_ignored(self):
        self.assertNotIn('psutil', self._beat({'psutil': 'yes'}).get('sysinfo') or {})

    def test_an_unknown_field_is_still_dropped(self):
        """safe_si must still BE a whitelist. Without this, a change that made
        it pass everything through would satisfy every test above."""
        si = self._beat({'totally_new_field': 'x'}).get('sysinfo') or {}
        self.assertNotIn('totally_new_field', si)


class TestSshHardeningReadsX11Forwarding(unittest.TestCase):
    """Run the real check rather than reading its source. A source pin would
    prove the string is present; only running it proves the field is consulted
    and lands in the operator-visible output."""

    def _row(self, ssh_config):
        rows = checks_mod._host_checks(
            'd1', {'name': 'h', 'sysinfo': {'ssh_config': ssh_config}},
            security_hardening=True)
        return next((r for r in rows if r['key'] == 'linux_ssh_hardening'), None)

    def test_the_check_renders_at_all(self):
        """Positive control — it is opt-in behind security hardening, so a
        wrong flag would make every assertion below vacuously true."""
        self.assertIsNotNone(self._row({'permit_root_login': 'no'}))

    def test_x11_forwarding_yes_is_reported(self):
        row = self._row({'permit_root_login': 'no', 'x11_forwarding': 'yes'})
        self.assertIn('X11', row['output'])
        self.assertEqual(row['status'], 'warning')

    def test_x11_forwarding_no_is_not_reported(self):
        row = self._row({'permit_root_login': 'no', 'x11_forwarding': 'no'})
        self.assertNotIn('X11', row['output'])
        self.assertEqual(row['status'], 'ok')

    def test_it_does_not_escalate_the_severity(self):
        """X11 forwarding is a real lateral-movement path but a deliberate
        choice on plenty of workstations. If it could raise the check to
        critical the row becomes noise, gets muted, and takes the other three
        findings with it."""
        row = self._row({'x11_forwarding': 'yes'})
        self.assertEqual(row['status'], 'warning')
        crit = self._row({'permit_empty_passwords': 'yes', 'x11_forwarding': 'yes'})
        self.assertEqual(crit['status'], 'critical',
                         'empty passwords must still be the critical trigger')


class TestSudoTrailNamesTheEffectiveUser(unittest.TestCase):
    def test_both_tables_render_the_target(self):
        js = (_JS / 'app.js').read_text()
        js = re.sub(r'//[^\n]*', '', js)          # code, not comments
        for fn in ('loadSudoLog', 'runSudoSearch'):
            with self.subTest(fn=fn):
                body = js[js.index(f'function {fn}('):]
                body = body[:body.index('\n}\n')]
                self.assertIn('Ran as', body, f'{fn} does not show who the '
                                              'command actually ran AS')
                self.assertRegex(body, r"e\.target\s*\|\|\s*'root'",
                                 'empty target means bare sudo, i.e. root — '
                                 'rendering it blank loses the whole point')

    def test_the_rag_line_names_it_too(self):
        docs = rag_index.build_sudo_corpus(
            {'d1': [{'ts': 1, 'user': 'alice', 'target': 'postgres',
                     'command': 'psql -c "drop table x"'}]},
            devices={'d1': {'name': 'db-01'}}, now=1)
        self.assertTrue(docs, 'the corpus builder produced nothing — every '
                              'assertion below would pass vacuously')
        text = docs[0]['text']
        self.assertIn('postgres', text)
        self.assertIn('alice', text)

    def test_a_bare_sudo_is_reported_as_root_in_the_corpus(self):
        docs = rag_index.build_sudo_corpus(
            {'d1': [{'ts': 1, 'user': 'bob', 'command': 'systemctl restart nginx'}]},
            devices={'d1': {'name': 'web-01'}}, now=1)
        self.assertIn('as root', docs[0]['text'])


class TestLldpSaysWhyItIsEmpty(unittest.TestCase):
    def test_the_builder_returns_a_count_of_unresolved_neighbours(self):
        self.assertEqual(
            api._lldp_suggestions.__code__.co_argcount, 0)
        src = (_CGI / 'api.py').read_text()
        i = src.index('def _lldp_suggestions(')
        body = src[i:src.index('\ndef ', i + 10)]
        self.assertIn('unresolved', body)
        self.assertIn('return out, unresolved', body)

    def test_the_page_no_longer_tells_you_to_install_what_is_installed(self):
        js = (_JS / 'app-network.js').read_text()
        body = js[js.index('async function loadLldpSuggestions('):]
        body = body[:body.index('\n}\n')]
        self.assertIn('r.unresolved', body)
        # the old unconditional advice must not be the only thing shown
        self.assertIn('none of which is an enrolled device', body)


if __name__ == '__main__':
    unittest.main()
