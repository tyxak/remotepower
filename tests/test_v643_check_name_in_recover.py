#!/usr/bin/env python3
"""`Custom Check Recovered tviweb01.tvipper.com: check "?" recovered`

Reported from production, over Pushover. The notification builders render
`payload.get("check_name", "?")`, so any fire site that omits that key reaches
the operator as a literal question mark where the check's name belongs — an
alert that cannot be acted on, because it does not say what recovered.

Three sites fire custom_check_recovered. The heartbeat ingest path sent
check_name. The two OPERATOR-TRIGGERED paths did not:

    api.handle_*            disabling a failing check resolves its open alert
    guard_handlers          accepting a baseline change resolves its open alert

Which is why it never showed up in testing: the routine recover — the one a
test drives — was correct. The broken ones only fire just after a human has
done something, and the notification lands seconds later while they are still
looking.

The general rule this pins: a recover event's payload must carry every field
its message reads. The failing message and the recovering message for the same
event are written in different places, and they drift.
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
sys.path.insert(0, str(_CGI))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v643cc-'))
_spec = importlib.util.spec_from_file_location('api_v643_cc', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
sys.modules.setdefault('api', api)
_spec.loader.exec_module(api)
import notify  # noqa: E402

EVENT = 'custom_check_recovered'


class TestTheMessageNamesTheCheck(unittest.TestCase):
    def setUp(self):
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg['custom_checks'] = [{'id': 'abc123', 'name': 'nginx is running',
                                 'type': 'process'}]
        api.save(api.CONFIG_FILE, cfg)
        api._LOAD_CACHE.clear()

    def test_the_reported_bug_reproduces_without_the_field(self):
        """Positive control, and the exact string from the report. If this ever
        stops producing '?', the builder changed and the rest of this file is
        asserting against something else."""
        msg = notify._webhook_message(EVENT, {
            'device_id': 'd1', 'name': 'tviweb01.tvipper.com',
            'check_id': 'abc123'})
        self.assertIn('check "?" recovered', msg)

    def test_the_resolver_returns_the_operator_facing_name(self):
        self.assertEqual(api._custom_check_name('abc123'), 'nginx is running')

    def test_an_unknown_id_falls_back_to_the_id_not_a_question_mark(self):
        """A deleted check still has to produce an actionable message. The id
        identifies something; '?' identifies nothing."""
        self.assertEqual(api._custom_check_name('gone'), 'gone')
        msg = notify._webhook_message(EVENT, {
            'name': 'h1', 'check_id': 'gone',
            'check_name': api._custom_check_name('gone')})
        self.assertIn('"gone"', msg)
        self.assertNotIn('"?"', msg)

    def test_the_resolver_survives_a_missing_config(self):
        api.save(api.CONFIG_FILE, {})
        api._LOAD_CACHE.clear()
        self.assertEqual(api._custom_check_name('abc123'), 'abc123')


class TestEveryFireSiteCarriesTheField(unittest.TestCase):
    """The durable half. A fourth site added later must carry check_name too."""

    def _fire_payloads(self, src):
        out = []
        for m in re.finditer(
                r"fire_webhook\(\s*'%s'\s*,\s*(\{.*?\})\s*\)" % EVENT, src, re.S):
            out.append(m.group(1))
        for m in re.finditer(
                r"append\(\(\s*'%s'\s*,\s*(\{.*?\})\s*\)\)" % EVENT, src, re.S):
            out.append(m.group(1))
        return out

    def test_the_scan_finds_the_known_sites(self):
        """Positive control: an empty result would make the assertion below
        vacuous, which is how this class of bug survives a green suite."""
        total = sum(len(self._fire_payloads(p.read_text()))
                    for p in _CGI.glob('*.py'))
        self.assertGreaterEqual(total, 3,
                                'fire-site scan found fewer sites than exist')

    def test_every_site_includes_check_name(self):
        missing = []
        for p in sorted(_CGI.glob('*.py')):
            for payload in self._fire_payloads(p.read_text()):
                if 'check_name' not in payload:
                    missing.append(f'{p.name}: {" ".join(payload.split())[:90]}')
        self.assertEqual(missing, [], '\n'.join([
            f'These {EVENT} payloads omit check_name, so the notification '
            'reads: check "?" recovered —',
            *('  ' + m for m in missing),
            '',
            'Add check_name (api._custom_check_name(<id>) resolves it from the '
            'check definition).']))

    def test_the_match_key_is_still_whitelisted_by_record_alert(self):
        """CLAUDE.md rule 3: a recover event resolves its open alert by a
        sub_match key, and _record_alert only stores WHITELISTED payload keys.
        check_id is that key here — if it ever left the whitelist the alert
        would never resolve, silently."""
        src = (_CGI / 'api.py').read_text()
        m = re.search(r'def _record_alert\(.*?\n(?=def |class )', src, re.S)
        self.assertIn("'check_id'", m.group(0))


if __name__ == '__main__':
    unittest.main()
