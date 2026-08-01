"""Every event name the docs teach must exist in EVENT_REGISTRY.

`docs/automations.md` built its single end-to-end worked example on `disk_full`,
an event that has never existed. `_validate_rule` accepts any non-empty string
as a match event, so the rule saved cleanly, showed up enabled, and was skipped
for all 183 real events — its `fire_count` stayed 0 forever, which is exactly
what a correctly-configured rule looks like on a healthy fleet. The same defect
had `docs/agent-commands.md` naming `backup_verify_passed` (the real recover
event is `backup_verified`), and the invented name had spread into an api.py
comment, a remediation_handlers.py comment, and — worst — the `automation_suggest`
AI system prompt, from which the model would confidently teach operators to
build a rule that can never fire.

Documentation naming a thing that does not exist is not a typo; it is a feature
that silently does nothing, and nothing was checking.
"""

import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
_DOCS = ROOT / "docs"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v642-docev-"))

_spec = importlib.util.spec_from_file_location("api_v642_docev", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

# Backticked snake_case tokens that look like event names but are not: config
# keys, field names, file names, CLI words. Kept explicit and small — the point
# is to force a decision on each new one, not to let the filter grow until it
# swallows a real miss.
_NOT_EVENTS = {
    'device_id', 'last_seen', 'fire_count', 'match_event', 'sub_match',
    'created_at', 'updated_at', 'poll_interval', 'online_ttl', 'severity',
    'device_name', 'source_ip', 'schema_version', 'rule_id', 'event_type',
    'backup_monitors',   # an agent CONFIG key, not an event
}

# A doc token shaped like an event: lower_snake_case, at least one underscore.
# Digits ARE allowed — `fail2ban_ban` is a real event, and excluding them made
# this blind to exactly the events whose names carry one.
_EVENT_SHAPED = re.compile(r'^[a-z][a-z0-9]*(?:_[a-z0-9]+){1,4}$')


def _candidates(text):
    for tok in re.findall(r'`([a-z][a-z0-9_]*)`', text):
        if _EVENT_SHAPED.match(tok) and tok not in _NOT_EVENTS:
            yield tok


class TestDocsOnlyNameRealEvents(unittest.TestCase):

    def test_automations_and_agent_commands_examples_are_real(self):
        """The two files that TEACH rule-building, checked strictly: an operator
        copies these verbatim."""
        registry = set(api.EVENT_REGISTRY)
        for name in ('automations.md', 'agent-commands.md'):
            path = _DOCS / name
            if not path.exists():
                self.skipTest(f'{name} excluded from this tree')
            bad = []
            for tok in _candidates(path.read_text()):
                # Only flag tokens that look like OUR events: the doc also
                # backticks generic words. Require a near-miss against the
                # registry's vocabulary to avoid false alarms on prose.
                if tok in registry:
                    continue
                head = tok.split('_')[0]
                if any(e.split('_')[0] == head for e in registry):
                    bad.append(tok)
            self.assertEqual(sorted(set(bad)), [],
                             f'{name} names events that are not in EVENT_REGISTRY '
                             '— a rule built on one saves, enables, and never fires')

    def test_the_invented_names_are_gone_everywhere(self):
        """They had spread from the doc into three comments and an AI prompt."""
        for dead, real in (('disk_full', 'readonly_fs'),
                           ('backup_verify_passed', 'backup_verified')):
            self.assertNotIn(dead, api.EVENT_REGISTRY,
                             f'{dead} now exists — drop it from this test')
            self.assertIn(real, api.EVENT_REGISTRY)
            hits = []
            for base in (_DOCS, _CGI):
                if not base.exists():
                    continue
                for f in sorted(base.rglob('*.md')) + sorted(base.rglob('*.py')):
                    try:
                        if dead in f.read_text():
                            hits.append(str(f.relative_to(ROOT)))
                    except (OSError, UnicodeDecodeError):
                        pass
            self.assertEqual(hits, [],
                             f'`{dead}` is not a real event; use `{real}`')

    def test_the_ai_prompt_only_names_real_events(self):
        """`automation_suggest` told the model the engine fires `disk_full`, so
        the model taught operators to build a rule that can never fire. A
        system prompt is user-facing surface, not a comment."""
        import ai_provider
        prompt = ai_provider.SYSTEM_PROMPTS.get('automation_suggest', '')
        self.assertTrue(prompt, 'automation_suggest prompt vanished')
        m = re.search(r'\(e\.g\.\s*([a-z0-9_,\s]+?)\)', prompt)
        self.assertIsNotNone(m, 'the prompt no longer lists example events')
        named = [t.strip() for t in m.group(1).split(',') if t.strip()]
        self.assertTrue(named, 'no example events parsed')
        for tok in named:
            self.assertIn(tok, api.EVENT_REGISTRY,
                          f'the AI prompt offers `{tok}`, which does not exist')


if __name__ == '__main__':
    unittest.main()
