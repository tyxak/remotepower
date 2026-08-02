"""Guard: every modal in app-drift.js / app-ai.js opens through openModal().

Six dialogs used to activate themselves with a bare
`el.classList.add('active')`. That skips app.js's `_modalStack`, which is the
single thing that provides Escape-to-close, the Tab focus trap and focus
restore to the element that opened the dialog — while `_raiseModalZ` injected a
close button whose tooltip advertised "Close (Esc)" that did nothing. The AI and
runbook dialogs sit in front of an operator for 30-120s during an incident, so
"Escape does nothing" is not a cosmetic gap.

The interesting half of this file DRIVES the real functions: the client bundle
is evaluated in V8 (same harness as test_jsload), `openModal`/`closeModal` are
swapped for recorders, and each entry point is called for real. A source grep
alone would only prove a string moved.

The static pins below stop the class from coming back, and catch the new failure
mode the fix introduces: `openModal('typo-modal')` silently does nothing, since
openModal bails on a missing element.
"""

import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from py_mini_racer import MiniRacer
    _HAVE_V8 = True
except Exception:
    _HAVE_V8 = False

import _jsload_harness as H  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
_JS = _ROOT / "server" / "html" / "static" / "js"
_INDEX = _ROOT / "server" / "html" / "index.html"
_OWNED = ("app-drift.js", "app-ai.js")

# A modal element toggling its own .active class — the exact bypass this fix
# removed. Scoped to modal-ish receivers so a future tab/page `.active` toggle
# in these files doesn't false-fire.
_SELF_ACTIVATE = re.compile(
    r"""[A-Za-z0-9_$.\[\]'"()-]*[Mm]odal[A-Za-z0-9_$.\[\]'"()-]*"""
    r"""\.classList\.(?:add|remove)\(\s*['"]active['"]\s*\)"""
)
_MODAL_CALL = re.compile(r"\b(?:open|close)Modal\(\s*'([A-Za-z0-9_-]+)'\s*\)")


def _src(name):
    return (_JS / name).read_text()


# ── The V8 driver ────────────────────────────────────────────────────────────
# Every open entry point, called for real. `_ensure*Modal()` early-returns on a
# pre-seeded element, so the fakes below stand in for the built DOM; `contains`
# answers whether the dialog is already on screen, which is what the
# re-entrancy guards read.
_DRIVER = r"""
(function(){
  var opened = [], closed = [], errs = [];
  openModal  = function(id){ opened.push(id); };
  closeModal = function(id){ closed.push(id); };
  function fake(isOpen){ return { classList: { contains: function(){ return isOpen; },
                                               add: function(){}, remove: function(){} },
                                  querySelector: function(){ return null; }, style: {} }; }
  _driftDeviceModal = fake(__OPEN__); _driftDiffModal = fake(__OPEN__);
  _aiModalEl = fake(__OPEN__); _runbookModalEl = fake(__OPEN__); _lsModalEl = fake(__OPEN__);
  function run(label, fn){ try { fn(); } catch(e){ errs.push(label + ': ' + e); } }
  run('openDriftDetail',   function(){ openDriftDetail('d1', 'host'); });
  run('openDriftDiff',     function(){ openDriftDiff('d1', '/etc/hosts'); });
  run('openAIModal',       function(){ openAIModal({title:'t', system:'s', userMsg:'m', context:'c'}); });
  run('_aiRunDebug',       function(){ _aiRunDebug({title:'t', system:'s', userMsg:'m', context:'c'}); });
  run('aiGenerateRunbook', function(){ aiGenerateRunbook('d1', 'host'); });
  run('aiViewRunbook',     function(){ aiViewRunbook('d1', 'host'); });
  run('openLogSweep',      function(){ openLogSweep('d1', 'host'); });
  run('closeDriftDetail',  function(){ closeDriftDetail(); });
  run('closeDriftDiff',    function(){ closeDriftDiff(); });
  run('closeAIModal',      function(){ closeAIModal(); });
  run('closeRunbookModal', function(){ closeRunbookModal(); });
  run('closeLogSweepModal',function(){ closeLogSweepModal(); });
  return JSON.stringify({opened: opened, closed: closed, errs: errs});
})()
"""


def _drive(already_open):
    ctx = MiniRacer()
    ctx.eval(H.concat())
    return json.loads(ctx.eval(_DRIVER.replace("__OPEN__", "true" if already_open else "false")))


@unittest.skipUnless(_HAVE_V8, "py_mini_racer (V8) not installed")
class TestModalsDriveTheSharedManager(unittest.TestCase):
    """Call the real entry points and watch which manager calls they make."""

    @classmethod
    def setUpClass(cls):
        cls.closed_dialog = _drive(already_open=False)
        cls.open_dialog = _drive(already_open=True)

    def test_no_entry_point_throws(self):
        self.assertEqual(self.closed_dialog["errs"], [])

    def test_every_open_entry_point_goes_through_open_modal(self):
        # Seven call sites, five dialogs — the AI and runbook modals each have
        # two entry points and BOTH must be routed, not just the obvious one.
        self.assertEqual(self.closed_dialog["opened"], [
            "drift-detail-modal",   # openDriftDetail
            "drift-diff-modal",     # openDriftDiff (nested over the detail modal)
            "ai-modal",             # openAIModal
            "ai-modal",             # _aiRunDebug ("What was sent?")
            "runbook-modal",        # aiGenerateRunbook
            "runbook-modal",        # aiViewRunbook
            "log-sweep-modal",      # openLogSweep
        ])

    def test_every_close_path_goes_through_close_modal(self):
        # A push with no matching pop is worse than neither: body keeps the
        # `modal-open` scroll lock and the stack keeps a stale entry.
        # closeRunbookModal lives in app.js and is wrapped from app-ai.js —
        # this asserts the wrapper is actually in force.
        self.assertEqual(self.closed_dialog["closed"], [
            "drift-detail-modal",
            "drift-diff-modal",
            "ai-modal",
            "runbook-modal",
            "log-sweep-modal",
        ])

    def test_reopening_an_already_open_dialog_does_not_re_push(self):
        # "What was sent?" and Regenerate are buttons INSIDE the open dialog.
        # A second openModal would overwrite the focus-restore target with a
        # node that is hidden by the time the dialog closes.
        self.assertEqual(self.open_dialog["opened"], [
            "drift-diff-modal",   # only ever opened from the detail modal
            "log-sweep-modal",    # single entry point, no re-entrant button
        ])


class TestNoModalActivatesItself(unittest.TestCase):
    """Source pins — cheap, and they run without V8."""

    def test_no_self_activated_modal(self):
        hits = []
        for name in _OWNED:
            for i, line in enumerate(_src(name).splitlines(), 1):
                if _SELF_ACTIVATE.search(line):
                    hits.append(f"{name}:{i}: {line.strip()}")
        self.assertEqual(hits, [], "a modal toggling its own .active class skips "
                                   "app.js's _modalStack — no Escape, no focus trap, "
                                   "no focus restore. Call openModal(id)/closeModal(id):\n  "
                                   + "\n  ".join(hits))

    def test_every_modal_id_actually_exists(self):
        """openModal() bails silently on an unknown id — a typo is invisible."""
        known = set(re.findall(r"""\bid=["']([A-Za-z0-9_-]+)["']""", _INDEX.read_text()))
        for f in sorted(_JS.glob("*.js")):
            known |= set(re.findall(r"""\.id\s*=\s*['"]([A-Za-z0-9_-]+)['"]""", f.read_text()))
        missing = sorted({
            mid for name in _OWNED for mid in _MODAL_CALL.findall(_src(name))
            if mid not in known
        })
        self.assertEqual(missing, [], f"open/closeModal ids with no element: {missing}")


if __name__ == "__main__":
    unittest.main()
