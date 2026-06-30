"""v5.6.0 — Automation engine: the three new actions.

The event-driven automation engine (RULES_FILE, _run_automation_rules, fired
from fire_webhook) already shipped with run_script + notify. v5.6.0 adds
open_ticket / add_tag / mute_alert, composing the ticket, tag and mute
subsystems. These pin that the validator accepts them, the runner handles them,
and the editor UI exposes them.
"""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-auto-test-"))

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
_spec = importlib.util.spec_from_file_location('api_auto', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)
_SRC = (_CGI / 'api.py').read_text()


class TestValidator(unittest.TestCase):
    def _rule(self, action):
        body = {'name': 'r', 'match': {'events': ['disk_full']}, 'actions': [action]}
        return api._validate_rule(body)

    def test_open_ticket_accepted_with_priority(self):
        rule, err = self._rule({'type': 'open_ticket', 'priority': 2, 'subject': 'x', 'group': 'g'})
        self.assertIsNone(err)
        self.assertEqual(rule['actions'][0]['type'], 'open_ticket')
        self.assertEqual(rule['actions'][0]['priority'], 2)

    def test_open_ticket_priority_clamped(self):
        rule, _ = self._rule({'type': 'open_ticket', 'priority': 99})
        self.assertEqual(rule['actions'][0]['priority'], 4)

    def test_add_tag_requires_tag(self):
        rule, err = self._rule({'type': 'add_tag', 'tag': 'auto-noisy'})
        self.assertIsNone(err)
        self.assertEqual(rule['actions'][0], {'type': 'add_tag', 'tag': 'auto-noisy'})
        # empty tag → not a valid action → rejected (no actions)
        _, err2 = self._rule({'type': 'add_tag', 'tag': '  '})
        self.assertIsNotNone(err2)

    def test_mute_alert_accepted(self):
        rule, err = self._rule({'type': 'mute_alert'})
        self.assertIsNone(err)
        self.assertEqual(rule['actions'][0], {'type': 'mute_alert'})

    def test_unknown_action_rejected(self):
        _, err = self._rule({'type': 'launch_missiles'})
        self.assertIsNotNone(err)


class TestRunnerBranches(unittest.TestCase):
    def test_runner_has_new_branches(self):
        seg = _SRC[_SRC.index('def _run_automation_action'):
                   _SRC.index('def _run_automation_rules')]
        for atype in ("atype == 'open_ticket'", "atype == 'add_tag'",
                      "atype == 'mute_alert'"):
            self.assertIn(atype, seg, f'runner missing {atype}')
        # ticket action is gated on the ticket system being enabled
        self.assertIn('_tickets_enabled()', seg)
        # each action audit-logs
        self.assertIn("'rule_open_ticket'", seg)
        self.assertIn("'rule_add_tag'", seg)
        self.assertIn("'rule_mute_alert'", seg)


class TestFrontend(unittest.TestCase):
    def test_editor_exposes_new_actions(self):
        index = (_ROOT / 'server' / 'html' / 'index.html').read_text()
        for el in ('auto-act-ticket', 'auto-ticket-priority', 'auto-act-tag', 'auto-act-mute'):
            self.assertIn(f'id="{el}"', index)
        appjs = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js').read_text()
        self.assertIn("type: 'open_ticket'", appjs)
        self.assertIn("type: 'add_tag'", appjs)
        self.assertIn("type: 'mute_alert'", appjs)


if __name__ == '__main__':
    unittest.main()
