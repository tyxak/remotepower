#!/usr/bin/env python3
"""Every signal the sanitizer PERSISTS must be visible somewhere.

The sanitizer's whitelist is the product's contract with the agent: a field it
keeps is one the server promised to carry. A field it keeps that nothing then
renders, checks, scores or indexes was collected for nothing — the agent paid
for it, the heartbeat carried it, the store holds it, and no operator will ever
see it. CLAUDE.md calls this the prize, and it keeps recurring because each
individual file reads as correct.

The population is taken from `handle_heartbeat`'s `safe_*[...] = ` assignments
rather than from a hand-kept list, so a signal added next release is in scope
the day it is persisted.

Everything else is an EXEMPT entry with a reason, on purpose: an exempt list is
visible and gets re-read, while a clever population filter is read once and
thereafter looks like an implementation detail. That is how nine body-device
handlers became invisible to their own scope guard.

What this found when it was written: the drawer rendered four of the eight
Windows posture fields and four of the five macOS ones — tamper protection, UAC,
pending reboot and macOS auto-updates were evaluated by the Checks engine and
the advisory, and shown to nobody. Secure Boot had just been added for Linux and
read only the top-level key, so it was blank on Windows, where the same fact
arrives under win_posture. `dm_count` and `encrypted_mounts` were persisted and
read by nothing an operator sees.
"""
import pathlib
import re
import sys
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
_JS = _ROOT / 'server' / 'html' / 'static' / 'js'
sys.path.insert(0, str(pathlib.Path(__file__).parent))
import srcpin  # noqa: E402

# Signals with no operator-facing surface, each for a stated reason. Anything
# not listed here must be readable somewhere a person looks.
_EXEMPT = {
    '_batt_low':
        'edge-detection state the sanitizer keeps for ITSELF — it compares the '
        'previous beat to decide whether a battery just crossed the threshold. '
        'Internal by the leading underscore.',
    'custom_check_results':
        'rendered AS the custom check rows on the Checks page; the raw dict is '
        'the transport, the rows are the surface.',
    'guard_quarantine':
        'the Integrity Guard page renders the quarantine LEDGER from its own '
        'endpoint. This copy exists so the advisory can score it without a '
        'second store read.',
    'proc_names':
        'the input to the server-side `process` custom check — a set of names, '
        'not a reading. The drawer shows top_processes, which has the names an '
        'operator would want.',
    'upgradable_names':
        'feeds the fleet patch CATALOG page (api.py builds it into '
        'package -> hosts), which is where package names belong rather than on '
        'one host row.',
    'modules_visible':
        'the ProtectKernelModules sandbox signal. Its home is a Checks row — it '
        'answers "can this agent see the module tree", which is a check result, '
        'not a fact about the host worth a drawer pill.',
}

_UI_FILES = sorted(_JS.glob('app*.js')) + [_ROOT / 'server/html/index.html']
_LOGIC_FILES = [_CGI / n for n in ('checks.py', 'advisory.py', 'rag_index.py',
                                   'api.py', 'attention_handlers.py')]


def _persisted():
    """{key: container} for every field handle_heartbeat's sanitizer keeps."""
    hb = srcpin.py_function((_CGI / 'api.py').read_text(), 'handle_heartbeat')
    out = {}
    for m in re.finditer(r"\b(safe_\w+)\['([a-z0-9_]+)'\]\s*=", hb):
        out.setdefault(m.group(2), m.group(1))
    for m in re.finditer(r"\b(safe_\w+)\.setdefault\('([a-z0-9_]+)'", hb):
        out.setdefault(m.group(2), m.group(1))
    for m in re.finditer(
            r"for\s+\w+\s+in\s+\(([^)]*?)\)\s*:\s*\n\s+if[^\n]*\n\s+(safe_\w+)\[", hb):
        for k in re.findall(r"'([a-z0-9_]+)'", m.group(1)):
            out.setdefault(k, m.group(2))
    return out, hb


def _readers(key, hb):
    """Files referencing this key outside the sanitizer.

    `.key` property access is how the frontend reads nearly everything —
    `(si.platform_health || {}).throttle`. A first version of this matched only
    `si.<key>` and called throttle, wifi, fans and governor invisible when all
    four are drawer rows.
    """
    pats = [rf"\.\s*{key}\b", rf"\.get\('{key}'\)", rf"\['{key}'\]",
            rf'"{key}"', rf"'{key}'"]
    ui, logic = [], []
    for p in _UI_FILES:
        text = p.read_text()
        if any(re.search(pt, text) for pt in pats):
            ui.append(p.name)
    for p in _LOGIC_FILES:
        if not p.exists():
            continue
        text = p.read_text()
        if p.name == 'api.py':
            text = text.replace(hb, '')     # the sanitizer's own write
        if any(re.search(pt, text) for pt in pats):
            logic.append(p.name)
    return ui, logic


class TestTheInstrumentWorks(unittest.TestCase):
    """Checked FIRST. Every number below is produced by the same scanner, so a
    broken scanner reports a clean codebase."""

    def test_the_population_is_not_empty(self):
        persisted, _ = _persisted()
        self.assertGreater(len(persisted), 60,
                           f'only {len(persisted)} persisted signals found — '
                           f'the sanitizer moved or the extraction broke')

    def test_signals_known_to_render_are_found(self):
        """Read the rendering code for each of these by hand. If one reports as
        invisible the scanner is wrong, not the product."""
        persisted, hb = _persisted()
        for key in ('throttle', 'wifi', 'fans', 'governor', 'secure_boot',
                    'listening_ports', 'tamper_protection', 'uac_enabled'):
            self.assertIn(key, persisted, f'{key} is not even persisted')
            ui, _logic = _readers(key, hb)
            self.assertTrue(ui, f'{key} renders in the drawer but the scanner '
                                f'did not find it')

    def test_a_signal_nothing_reads_would_be_caught(self):
        """Positive control for the assertion that matters."""
        _persisted_, hb = _persisted()
        ui, logic = _readers('rp_no_such_signal_xyz', hb)
        self.assertEqual((ui, logic), ([], []))


class TestEveryPersistedSignalIsVisible(unittest.TestCase):

    def test_no_signal_is_collected_for_nothing(self):
        persisted, hb = _persisted()
        orphans = []
        for key in sorted(persisted):
            if key in _EXEMPT:
                continue
            ui, logic = _readers(key, hb)
            if not ui and not logic:
                orphans.append(f'{key} (under {persisted[key]})')
        self.assertEqual(orphans, [],
                         'the sanitizer keeps these and nothing reads them — '
                         'render them, score them, or add an EXEMPT entry '
                         'saying why they are server-side:\n  '
                         + '\n  '.join(orphans))

    def test_the_exempt_list_has_not_gone_stale(self):
        """An exemption for a signal that no longer exists is a claim about
        nothing, and it hides the next one that inherits the name."""
        persisted, _ = _persisted()
        gone = sorted(set(_EXEMPT) - set(persisted))
        self.assertEqual(gone, [], f'exempt but no longer persisted: {gone}')

    def test_every_exemption_gives_a_reason(self):
        for key, why in _EXEMPT.items():
            self.assertGreater(len(why), 40, f'{key}: say why, not that')


class TestThePostureFieldsAllHaveAPill(unittest.TestCase):
    """The specific gap this file was written for. Windows and macOS posture are
    the platform equivalents of controls Linux hosts show in the drawer, and the
    sanitizer keeps every field of them — so 'the Checks engine covers it' is
    not an answer to 'the drawer shows four of eight'."""

    _WIN = ('bitlocker', 'defender_realtime', 'firewall', 'wu_service',
            'tamper_protection', 'secure_boot', 'uac_enabled', 'pending_reboot')
    _MAC = ('filevault', 'firewall', 'gatekeeper', 'sip', 'auto_security_update')

    def test_every_windows_posture_field_reaches_the_drawer(self):
        js = (_JS / 'app.js').read_text()
        missing = [k for k in self._WIN
                   if not re.search(rf'win_posture\.\s*{k}\b', js)]
        self.assertEqual(missing, [],
                         f'evaluated by Checks, shown nowhere: {missing}')

    def test_every_macos_posture_field_reaches_the_drawer(self):
        js = (_JS / 'app.js').read_text()
        missing = [k for k in self._MAC
                   if not re.search(rf'mac_posture\.\s*{k}\b', js)]
        self.assertEqual(missing, [], f'{missing}')

    def test_the_sanitizer_keeps_both_producers_too(self):
        """The population above is keyed by LEAF NAME, so `secure_boot` stays in
        it as long as EITHER producer is persisted — deleting the Linux leg
        changed nothing and every assertion still passed. Found by reverting the
        fix and watching the gate stay green. Both writes are pinned by name.
        """
        hb = srcpin.py_function((_CGI / 'api.py').read_text(), 'handle_heartbeat')
        code = '\n'.join(ln for ln in hb.splitlines()
                         if not ln.lstrip().startswith('#'))
        self.assertRegex(code, r"safe_si\['secure_boot'\]\s*=",
                         'the Linux (top-level) leg is no longer persisted, and '
                         'nothing else notices because Windows still is')
        self.assertRegex(code, r"'tamper_protection',\s*'secure_boot'",
                         'the Windows leg left the win_posture whitelist')

    def test_secure_boot_reads_both_producers(self):
        """The Linux agent reports it top-level, the Windows agent under
        win_posture. A row reading one leaves the other platform blank with the
        answer sitting in the record."""
        js = (_JS / 'app.js').read_text()
        m = re.search(r"\['Secure Boot'.{0,900}", js, re.S)
        self.assertTrue(m, 'the Secure Boot row is gone')
        seg = m.group(0)
        self.assertIn('si.secure_boot', seg)
        self.assertIn('win_posture.secure_boot', seg)


if __name__ == '__main__':
    unittest.main()
