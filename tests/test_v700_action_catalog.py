#!/usr/bin/env python3
"""The autonomy action catalog has to agree with four things it does not own.

The catalog is three tables in two files — `ACTION_CLASSES` in autonomy.py,
`_EVENT_ACTIONS` and `_ACTION_COMMANDS` in autonomy_ops_handlers.py — and every
one of them refers to something defined somewhere else entirely: event names
live in api.py's `EVENT_REGISTRY`, the payload keys a template can read are
fixed by `_record_alert`'s whitelist, and which command verbs a platform's
agent actually implements is `_VERB_OS_SUPPORT`. Nothing links them, so each
pairing is a place the tables can quietly stop being true.

They already had. The first version of `_EVENT_ACTIONS` had six rows and FOUR
of the event names did not exist — `unit_failed`, `container_down`, `disk_low`,
`inode_low` are not in the registry, so those rows could never match an alert.
The loop looked six-wide and was two-wide, and no test noticed, because a map
whose keys are never looked up produces no error at all. That is the same
invented-name class CLAUDE.md records for the chart annotations, reached again
by the same route: writing a plausible name instead of reading one.

What each check here buys, and the failure it prevents:

* **Event names are real.** Otherwise a mapping is decoration.
* **Actions are known and reachable.** An action class no event maps to is a
  checkbox in the allow-list that can never do anything — the mirror image of
  the above, and it looks like a feature.
* **Every parameter can actually arrive.** `_record_alert` stores a whitelisted
  subset of the payload, so a template reading `{pool}` when no whitelisted
  alias carries a pool would refuse on every alert forever. The refusal is
  correct and the action is still dead.
* **Templates match the platform column.** `svc:` is Linux and Windows; `ps:`
  is Windows only. An action declaring `darwin` while its command is `svc:`
  would send macOS a verb its agent ignores — which returns success, so the
  receipt would say it acted.
"""
import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-acat-'))

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

_spec = importlib.util.spec_from_file_location('api_acat', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import autonomy  # noqa: E402

_OPS = _CGI / 'autonomy_ops_handlers.py'
_ops_src = _OPS.read_text(encoding='utf-8')
_ops_spec = importlib.util.spec_from_file_location('autonomy_ops_acat', _OPS)
ops = importlib.util.module_from_spec(_ops_spec)
_ops_spec.loader.exec_module(ops)
# The module reaches api globals through the `A.` proxy, which is None until
# bound. Without this every helper below raises AttributeError on None, which
# reads as a broken helper rather than an unbound module.
ops.bind(vars(api))

_FAMILIES = ('linux', 'windows', 'darwin')


def _alert_payload_whitelist():
    """The keys `_record_alert` copies onto a stored alert.

    Read out of the source because it is a literal tuple inside the function —
    there is no runtime accessor, and hand-copying it here is how it would go
    stale the first time somebody whitelists a new field.

    Paren-matched rather than regex-bounded: the tuple runs to ~60 lines with
    explanatory comments in it, several containing a `)`, so a non-greedy
    `\\((.*?)\\):` stops two thirds of the way through and silently returns a
    SHORTER whitelist — which would make the alias check below pass for keys
    that are on it and fail for keys that are, too.
    """
    import inspect
    src = inspect.getsource(api._record_alert)
    i = src.index('for key in (')
    j = i + len('for key in (') - 1
    depth = 0
    for k in range(j, len(src)):
        if src[k] == '(':
            depth += 1
        elif src[k] == ')':
            depth -= 1
            if depth == 0:
                return set(re.findall(r"'([a-z_0-9]+)'", src[j:k]))
    raise AssertionError('the _record_alert whitelist tuple did not close')


def _templates_for(action):
    """(family, template) for every family this action declares."""
    out = []
    for fam in autonomy.ACTION_CLASSES[action].get('platforms') or ():
        out.append((fam, ops._command_for(action, fam)))
    return out


def _verb_of(tmpl):
    """The command verb a template will send, in _VERB_OS_SUPPORT's terms."""
    s = tmpl[5:] if tmpl.startswith('exec:') else tmpl
    if tmpl.startswith('exec:'):
        return 'exec:'
    verb = next((k for k in api._VERB_OS_SUPPORT
                 if k.endswith(':') and s.startswith(k)), None)
    if verb:
        return verb
    base = s.split(':', 1)[0]
    return base if base in api._VERB_OS_SUPPORT else base


class TestTheInstrumentsWork(unittest.TestCase):
    """Every assertion below is "this set is empty". A parse that returns
    nothing produces the same result and means the opposite."""

    def test_the_registry_loaded(self):
        self.assertGreater(len(api.EVENT_REGISTRY), 100)

    def test_the_tables_loaded(self):
        self.assertGreater(len(autonomy.ACTION_CLASSES), 15)
        self.assertGreater(len(ops._EVENT_ACTIONS), 15)
        self.assertGreater(len(ops._ACTION_COMMANDS), 15)

    def test_the_payload_whitelist_parsed(self):
        wl = _alert_payload_whitelist()
        self.assertGreater(len(wl), 40, f'whitelist parse returned {len(wl)}')
        for known in ('unit', 'container', 'name', 'path'):
            self.assertIn(known, wl)

    def test_the_verb_table_is_there(self):
        self.assertIn('svc:', api._VERB_OS_SUPPORT)
        self.assertEqual(_verb_of('svc:restart:{unit}'), 'svc:')
        self.assertEqual(_verb_of('exec:journalctl --vacuum-time=3d'), 'exec:')
        self.assertEqual(_verb_of('reboot'), 'reboot')


class TestEveryEventNameIsReal(unittest.TestCase):

    def test_no_invented_events(self):
        bad = sorted(e for e in ops._EVENT_ACTIONS if e not in api.EVENT_REGISTRY)
        self.assertEqual(
            bad, [],
            'these are not EVENT_REGISTRY names, so no alert will ever carry '
            'them and the mapping is decoration:\n'
            + '\n'.join('  ' + b for b in bad))

    def test_the_mapped_events_can_reach_the_alert_inbox(self):
        """An event with no `severity` in the registry never becomes an alert
        row, and the loop only reads open alerts — so mapping it is the same
        dead end one layer down."""
        unreachable = sorted(
            e for e in ops._EVENT_ACTIONS
            if 'severity' not in (api.EVENT_REGISTRY.get(e) or {}))
        self.assertEqual(
            unreachable, [],
            'these events never land in the alerts store, so the autonomy '
            'sweep cannot see them:\n' + '\n'.join('  ' + u for u in unreachable))


class TestEveryActionIsKnownAndReachable(unittest.TestCase):

    def test_mapped_actions_exist(self):
        bad = sorted({a for ladder in ops._EVENT_ACTIONS.values() for a in ladder
                      if a not in autonomy.ACTION_CLASSES})
        self.assertEqual(bad, [], f'unknown action classes: {bad}')

    def test_every_action_class_is_reachable_from_some_event(self):
        used = {a for ladder in ops._EVENT_ACTIONS.values() for a in ladder}
        orphans = sorted(set(autonomy.ACTION_CLASSES) - used)
        self.assertEqual(
            orphans, [],
            'these action classes appear in the allow-list UI but no event '
            'maps to them, so ticking the box can never do anything:\n'
            + '\n'.join('  ' + o for o in orphans))

    def test_ladders_have_no_duplicates(self):
        for event, ladder in ops._EVENT_ACTIONS.items():
            self.assertEqual(len(set(ladder)), len(ladder), event)

    def test_every_class_declares_its_platforms(self):
        for name, spec in autonomy.ACTION_CLASSES.items():
            plats = spec.get('platforms')
            self.assertTrue(plats, f'{name} declares no platforms')
            for p in plats:
                self.assertIn(p, _FAMILIES, f'{name}: unknown family {p}')

    def test_every_class_has_a_label(self):
        for name, spec in autonomy.ACTION_CLASSES.items():
            self.assertTrue((spec.get('label') or '').strip(),
                            f'{name} has no label for the allow-list')


class TestEveryTemplateCanBeFilled(unittest.TestCase):

    def test_each_parameter_has_an_alias_the_alert_can_carry(self):
        wl = _alert_payload_whitelist()
        bad = []
        for action in autonomy.ACTION_CLASSES:
            for _fam, tmpl in _templates_for(action):
                for field in re.findall(r'\{(\w+)\}', tmpl):
                    if field == 'runtime':
                        continue          # resolved from the containers store
                    aliases = ops._ACTION_PARAMS.get(field, (field,))
                    if not any(a in wl for a in aliases):
                        bad.append(f'{action}: {{{field}}} <- {aliases}')
        self.assertEqual(
            sorted(set(bad)), [],
            'no alias for these parameters survives _record_alert\'s payload '
            'whitelist, so the action refuses with missing_parameter on every '
            'alert, forever:\n' + '\n'.join('  ' + b for b in sorted(set(bad))))

    def test_the_only_template_less_action_is_the_documented_one(self):
        missing = sorted(a for a in autonomy.ACTION_CLASSES
                         if not ops._ACTION_COMMANDS.get(a))
        self.assertEqual(
            missing, ['rotate_credential'],
            'an action with no command template refuses with '
            'no_command_template on every alert. rotate_credential does so '
            'deliberately (rotation is a server-side vault operation, not a '
            'host command); anything else here is an oversight.')

    def test_the_upgrade_sentinel_resolves(self):
        """`patch` on Linux defers to api.py's vetted upgrade script rather
        than carrying its own copy. If the sentinel stopped resolving, the
        command would be the literal string '@upgrade'."""
        cmd = ops._command_for('patch', 'linux')
        self.assertTrue(cmd.startswith('exec:'), cmd[:40])
        self.assertNotIn('@upgrade', cmd)
        self.assertGreater(len(cmd), 60, 'the upgrade script did not resolve')


class TestTemplatesMatchTheDeclaredPlatforms(unittest.TestCase):

    def test_every_declared_platform_has_a_template(self):
        for action in autonomy.ACTION_CLASSES:
            if action == 'rotate_credential':
                continue
            for fam, tmpl in _templates_for(action):
                self.assertTrue(
                    tmpl, f'{action} claims to support {fam} but has no '
                          f'command template for it')

    def test_no_template_uses_a_verb_that_platform_lacks(self):
        bad = []
        for action in autonomy.ACTION_CLASSES:
            for fam, tmpl in _templates_for(action):
                if not tmpl:
                    continue
                verb = _verb_of(tmpl)
                sup = api._VERB_OS_SUPPORT.get(verb)
                if sup is not None and fam not in sup:
                    bad.append(f'{action} on {fam}: {verb} is {sup}')
        self.assertEqual(
            sorted(bad), [],
            'the agent on that platform does not implement the verb, and an '
            'unknown verb comes back as success having done nothing:\n'
            + '\n'.join('  ' + b for b in sorted(bad)))

    def test_no_template_is_a_bare_shell_line(self):
        """Everything must go through the command grammar. A raw shell string
        is what the first version shipped, and it bypasses both the platform
        table and _command_block_reason's maintenance/quarantine/audit gates."""
        known = tuple(sorted(api._VERB_OS_SUPPORT)) + ('exec:', 'reboot',
                                                       'shutdown', 'upgrade')
        for action in autonomy.ACTION_CLASSES:
            for fam, tmpl in _templates_for(action):
                if not tmpl:
                    continue
                self.assertTrue(
                    tmpl.startswith(known),
                    f'{action} on {fam} is a raw shell line, not a command '
                    f'verb: {tmpl[:60]!r}')


class TestTheRefusalsAreDeclared(unittest.TestCase):
    """decide() asserts its reason is in REASONS, so an undeclared one is an
    AssertionError at runtime rather than a bad receipt — but only on the path
    that hits it. Pin them here instead."""

    def test_the_new_reasons_exist(self):
        for r in ('unsupported_platform', 'missing_parameter',
                  'no_command_template'):
            self.assertIn(r, autonomy.REASONS)

    def test_an_unsupported_platform_refuses(self):
        pol = autonomy.normalize_policy({'mode': 'enabled',
                                         'allowed_actions': ['restart_timer'],
                                         'max_blast_radius': 99})
        d = autonomy.decide(action='restart_timer', policy=pol,
                            module_enabled=True, tenant_ok=True,
                            radius={'score': 0}, precedent_samples=9,
                            precedent_conf=1.0, os_family='darwin')
        self.assertEqual(d.verdict, autonomy.REFUSE)
        self.assertEqual(d['reason'], 'unsupported_platform')

    def test_a_supported_platform_does_not(self):
        """Control: without this, the assertion above would also pass if
        decide() refused everything."""
        pol = autonomy.normalize_policy({'mode': 'enabled',
                                         'allowed_actions': ['restart_timer'],
                                         'max_blast_radius': 99,
                                         'require_window': False})
        d = autonomy.decide(action='restart_timer', policy=pol,
                            module_enabled=True, tenant_ok=True,
                            radius={'score': 0}, precedent_samples=9,
                            precedent_conf=1.0, os_family='linux')
        self.assertEqual(d.verdict, autonomy.ACT)

    def test_a_plan_problem_refuses_with_its_own_reason(self):
        pol = autonomy.normalize_policy({'mode': 'enabled',
                                         'allowed_actions': ['restart_service'],
                                         'max_blast_radius': 99})
        d = autonomy.decide(action='restart_service', policy=pol,
                            module_enabled=True, tenant_ok=True,
                            radius={'score': 0}, precedent_samples=9,
                            precedent_conf=1.0, os_family='linux',
                            plan_problem='missing_parameter')
        self.assertEqual(d.verdict, autonomy.REFUSE)
        self.assertEqual(d['reason'], 'missing_parameter')


class TestParameterResolution(unittest.TestCase):

    def test_a_unit_comes_out_of_the_payload(self):
        cmd, prob = ops._resolve_params('svc:restart:{unit}',
                                        {'unit': 'nginx.service'}, 'd1')
        self.assertIsNone(prob)
        self.assertEqual(cmd, 'svc:restart:nginx.service')

    def test_an_alias_is_used_when_the_first_choice_is_absent(self):
        cmd, prob = ops._resolve_params('svc:restart:{unit}',
                                        {'name': 'redis'}, 'd1')
        self.assertIsNone(prob)
        self.assertEqual(cmd, 'svc:restart:redis')

    def test_a_missing_name_refuses_instead_of_emitting_a_stub(self):
        """The bug this replaces: an empty unit produced `svc:restart:` — a
        malformed command the agent rejects, reported as an action taken."""
        cmd, prob = ops._resolve_params('svc:restart:{unit}', {}, 'd1')
        self.assertEqual(prob, 'missing_parameter')
        self.assertEqual(cmd, '')

    def test_a_colon_in_a_name_refuses(self):
        """The wire format is colon-delimited, so a name containing one would
        re-split into a different action."""
        cmd, prob = ops._resolve_params('svc:restart:{unit}',
                                        {'unit': 'a:stop:b'}, 'd1')
        self.assertEqual(prob, 'missing_parameter')
        self.assertEqual(cmd, '')

    def test_no_template_says_so(self):
        cmd, prob = ops._resolve_params('', {'unit': 'x'}, 'd1')
        self.assertEqual(prob, 'no_command_template')
        self.assertEqual(cmd, '')

    def test_a_parameterless_template_passes_through(self):
        cmd, prob = ops._resolve_params('exec:fstrim -av', {}, 'd1')
        self.assertIsNone(prob)
        self.assertEqual(cmd, 'exec:fstrim -av')


class TestTheLadderRespectsTheAllowList(unittest.TestCase):

    def test_it_takes_the_first_permitted_rung(self):
        ladder = ('clear_journal', 'rotate_logs', 'trim_filesystem')
        pol = {'allowed_actions': ['trim_filesystem', 'rotate_logs']}
        self.assertEqual(ops._pick_action(ladder, pol), 'rotate_logs')

    def test_with_nothing_permitted_it_still_names_one(self):
        """So the receipt refuses against a concrete action rather than the
        candidate vanishing and the page reading as 'nothing to do'."""
        ladder = ('clear_journal', 'rotate_logs')
        self.assertEqual(ops._pick_action(ladder, {'allowed_actions': []}),
                         'clear_journal')


if __name__ == '__main__':
    unittest.main()
