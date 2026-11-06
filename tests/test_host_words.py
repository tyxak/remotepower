#!/usr/bin/env python3
"""The product says host, never device (v7.4.0): the words a person reads for a stored token.

`tests/test_v740_host_terminology.py` reads the source, so it cannot see a word that is built at run time from a
stored token. Seven pages showed one: the Timeline's filter chips read `device offline` (the kind token with its
underscores removed), Home's activity feed did the same, a Drift assignment read `device: nc01`, Data Explorer listed
the entity `devices`, a Maintenance window's scope read `device`, and the demo seeder's fleet-wide commands named their
target `all devices`.

This file holds the two helpers that word them (`hostWord`, `kindWords` in app.js, run under node) and the server half
(`_timeline_kind_labels`: the registry's translated title for a kind that is an event). The rendered half, every
sidebar page read for the word, is in test_sidebar_pages_rendered_e2e.py.
"""
import importlib.util
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
_JS = _ROOT / 'server' / 'html' / 'static' / 'js'
sys.path.insert(0, str(pathlib.Path(__file__).parent))
sys.path.insert(0, str(_CGI))
import srcpin  # noqa: E402

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-host-words-'))
_spec = importlib.util.spec_from_file_location('api_host_words', _CGI / 'api.py')
assert _spec is not None and _spec.loader is not None
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_NODE = shutil.which('node')
_APP = (_JS / 'app.js').read_text(encoding='utf-8')


@unittest.skipUnless(_NODE, 'node not installed')
class TestTheWordingHelpers(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        acronyms = re.search(r'^const _KIND_ACRONYMS = \{.*?\};$', _APP, re.S | re.M)
        assert acronyms is not None
        cls.script = '\n'.join([acronyms.group(0), srcpin.js_function(_APP, 'hostWord'), srcpin.js_function(_APP, 'kindWords')])

    def _run(self, calls):
        driver = 'const out = [];\n' + '\n'.join(f'out.push({c});' for c in calls) + '\nconsole.log(JSON.stringify(out));'
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / 'run.js'
            p.write_text(self.script + '\n' + driver)
            r = subprocess.run([str(_NODE), str(p)], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    def test_a_stored_token_reads_host_not_device(self):
        got = self._run(["hostWord('device')", "hostWord('devices')", "hostWord('tag')", "hostWord(null)", "hostWord('a device and 2 devices')",
                         "hostWord('device_id')"])
        # a token that is one word with an underscore is a name, not a sentence: it is worded by kindWords, not here
        self.assertEqual(got, ['host', 'hosts', 'tag', '', 'a host and 2 hosts', 'device_id'])

    def test_an_event_kind_the_server_has_no_words_for_is_worded_here(self):
        got = self._run(["kindWords('device_offline')", "kindWords('device_online')", "kindWords('cve_found')", "kindWords('snmp_unreachable')",
                         "kindWords('mcp_confirmation_expired')", "kindWords('ssh_key_added')", "kindWords('command_queued')", "kindWords('')", "kindWords(null)"])
        self.assertEqual(got, ['Host offline', 'Host online', 'CVE found', 'SNMP unreachable', 'MCP confirmation expired', 'SSH key added',
                               'Command queued', '', ''])

    def test_the_servers_words_win_when_it_sends_them(self):
        got = self._run(["kindWords('device_offline', {device_offline: 'Host Offline'})", "kindWords('cve', {device_offline: 'Host Offline'})",
                         "kindWords('x', {x: 7})"])
        self.assertEqual(got, ['Host Offline', 'CVE', '7'])


class TestTheServerWords(unittest.TestCase):

    def test_an_event_kind_gets_the_registrys_short_title(self):
        got = api._timeline_kind_labels(['device_offline', 'device_online', 'cve_found'])
        self.assertEqual(got['device_offline'], 'Host Offline')
        self.assertEqual(got['device_online'], 'Host Online')
        self.assertTrue(got['cve_found'])

    def test_a_kind_that_is_not_an_event_has_none(self):
        self.assertEqual(api._timeline_kind_labels(['no_such_kind', 'cve']), {})

    def test_no_title_the_timeline_can_send_says_device(self):
        # the words go to a person: one stray `device` in a title would put the word back on the chips
        kinds = [k for k, spec in api.EVENT_REGISTRY.items() if isinstance(spec, dict)]
        said = api._timeline_kind_labels(kinds)
        self.assertGreater(len(said), 100)                  # control: the registry has some 200 events
        # a USB device is a device (the one right use among the titles; see PROTECT in tests/host_terms.py)
        self.assertEqual([k for k, w in said.items() if re.search(r'(?<!USB )\bdevices?\b', w, re.I)], [])


class TestTheSourcesThatWordAToken(unittest.TestCase):
    """The display sites go through the helpers: the places that printed the token itself."""

    def test_the_timeline_home_drift_maintenance_and_explorer_use_the_helpers(self):
        drift = (_JS / 'app-drift.js').read_text(encoding='utf-8')
        self.assertIn('hostWord(a.scope_type)', drift)
        self.assertIn('hostWord(w.scope)', _APP)
        self.assertIn('hostWord(t.entity)', _APP)
        self.assertIn('kindWords(k, _timelineKindLabels)', _APP)
        self.assertIn('kindWords(ev.event', _APP)
        self.assertNotIn("(ev.event || '').replace(/_/g, ' ')", _APP)

    def test_the_demo_seeder_names_a_fleet_wide_command_target_a_host_word(self):
        seeder = (_ROOT / 'packaging' / 'seed-demo-data.py').read_text(encoding='utf-8')
        self.assertNotIn('all devices', seeder)


if __name__ == '__main__':
    unittest.main()
