"""v6.3.0 (UX): the command palette is an ACTION runner, not just a jump list.

The palette is DOM-driven, so this is a source-level guard: the per-device verbs
are present, gated to agent-backed hosts, and reuse the SAME safe entry points the
device drawer uses (so a palette action goes through the normal confirm/modal flow,
never an unguarded destructive call).
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from srcpin import js_function  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
_APP = (_ROOT / 'server/html/static/js/app.js').read_text()


class TestPaletteActionRunner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fn = js_function(_APP, '_palBuildIndex')

    def test_verbs_present(self):
        for verb in ('Run command on ', 'Web terminal — ', 'Reboot ', 'Shut down '):
            self.assertIn(verb, self.fn, f'palette missing verb {verb!r}')

    def test_verbs_gated_to_agent_backed(self):
        # The verb block must be inside `if (!d.agentless)`.
        i = self.fn.index('if (!d.agentless)')
        block = self.fn[i:i + 1400]
        for verb in ('Run command on ', 'Reboot ', 'Shut down ', 'Web terminal'):
            self.assertIn(verb, block, f'{verb!r} not gated on !agentless')

    def test_verbs_reuse_safe_flows(self):
        # Reuse the drawer's confirm/modal entry points, not raw API calls.
        self.assertIn('openExecModal(', self.fn)
        self.assertIn('openWebTerm(', self.fn)
        self.assertIn("openModal('reboot-modal')", self.fn)
        self.assertIn("openModal('shutdown-modal')", self.fn)

    def test_verbs_are_action_kind(self):
        # kind:'action' so they don't crowd the default view and `>` scopes to them.
        i = self.fn.index('Run command on ')
        self.assertIn("kind: 'action'", self.fn[i - 120:i + 120])


if __name__ == '__main__':
    unittest.main()
