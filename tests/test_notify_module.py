#!/usr/bin/env python3
"""notify.py — the carved-out notification-channel payload builders.

Pins the carve's contract: notify.py stays PURE (no storage / request /
network imports), api.py re-exports the builder names unchanged (15 test
files and the delivery path reference them through api), and configure()
is what wires the registry-derived lookups in.
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_CGI_BIN = Path(__file__).parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI_BIN))

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())
os.environ.setdefault('REQUEST_METHOD', 'GET')
os.environ.setdefault('PATH_INFO', '/')
os.environ.setdefault('CONTENT_LENGTH', '0')

import notify  # noqa: E402

_spec = importlib.util.spec_from_file_location('api_notify', _CGI_BIN / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

NOTIFY_SRC = (_CGI_BIN / 'notify.py').read_text()


class TestPurity(unittest.TestCase):
    def test_no_storage_or_request_coupling(self):
        # The whole point of the carve: builders never touch storage, the
        # request env, or the network. Delivery stays in api.py.
        for forbidden in ('import os', 'load(', 'save(', 'respond(',
                          'require_auth', 'urllib.request', 'socket',
                          '_LockedUpdate', 'DATA_DIR'):
            self.assertNotIn(forbidden, NOTIFY_SRC,
                             f'notify.py must stay pure — found {forbidden!r}')

    def test_api_configures_notify_at_import(self):
        self.assertEqual(notify.SERVER_VERSION, api.SERVER_VERSION)
        self.assertEqual(notify.WEBHOOK_SCHEMA_VERSION, api.WEBHOOK_SCHEMA_VERSION)
        self.assertEqual(notify._RECOVER_EVENTS, frozenset(api._ALERT_RECOVER))
        self.assertEqual(notify._tags_fn('device_offline'), 'red_circle,computer')

    def test_api_reexports_builders(self):
        for name in ('ITSM_FORMATS', '_auto_detect_format', '_webhook_message',
                     '_build_discord_body', '_build_slack_body', '_build_teams_body',
                     '_build_ntfy_body', '_build_github_body', '_build_pagerduty_body',
                     '_build_opsgenie_body', '_build_pushover_body', '_build_jira_body',
                     '_build_servicenow_body', '_build_zendesk_body',
                     '_build_generic_body', '_build_telegram_body',
                     '_build_matrix_body', '_parse_itsm_response', '_ts_fmt'):
            self.assertIs(getattr(api, name), getattr(notify, name),
                          f'api.{name} must be the notify.py implementation')


class TestBuilders(unittest.TestCase):
    def test_generic_body_carries_schema_version_and_tags(self):
        body, headers, ctype = notify._build_generic_body(
            'device_offline', 'T', 'M', 4, {'device_id': 'd1'})
        data = json.loads(body)
        self.assertEqual(data['schema_version'], api.WEBHOOK_SCHEMA_VERSION)
        self.assertEqual(headers['X-Tags'], 'red_circle,computer')
        self.assertEqual(ctype, 'application/json')

    def test_pagerduty_resolve_action_uses_recover_events(self):
        trig, _h, _c = notify._build_pagerduty_body(
            'device_offline', 'T', 'M', 4, {'routing_key': 'k'}, {})
        res, _h, _c = notify._build_pagerduty_body(
            'device_online', 'T', 'M', 3, {'routing_key': 'k'}, {})
        self.assertEqual(json.loads(trig)['event_action'], 'trigger')
        self.assertEqual(json.loads(res)['event_action'], 'resolve')

    def test_discord_embeds_server_version(self):
        body, _h, _c = notify._build_discord_body('device_offline', 'T', 'M')
        self.assertIn(api.SERVER_VERSION, body.decode())

    def test_configure_is_injectable_for_tests(self):
        orig = (notify.SERVER_VERSION, notify.WEBHOOK_SCHEMA_VERSION,
                notify._RECOVER_EVENTS, notify._tags_fn)
        try:
            notify.configure('9.9.9', '2', {'x_recovered'}, lambda e: 'zap')
            body, headers, _ = notify._build_generic_body('e', 'T', 'M', 3, {})
            self.assertEqual(json.loads(body)['schema_version'], '2')
            self.assertEqual(headers['X-Tags'], 'zap')
        finally:
            notify.configure(*orig)


if __name__ == '__main__':
    unittest.main()
