#!/usr/bin/env python3
"""A Windows registry value is a check: one HKLM value read against an expected one.

The type is `registry`. Its definition is five fields (hive, path, value, op, expect); the Windows agent reads the
value with winreg, read-only, and reports {status, output} in sysinfo.custom_check_results like every agent check;
the server validates the definition when it is saved and says what it refused. Six baseline templates ship with it.

What is held here, and how:

  * the rules (HKLM only, SOFTWARE and SYSTEM only, at most 12 parts, a closed set of characters) are written twice,
    in checks.validate_registry_check and in the agent's _reg_clean, because the agent does not trust the server.
    A differential test feeds both the same inputs, so the two cannot drift apart;
  * the agent is driven with a fake winreg that records every call and raises on any attribute the agent should not
    need: a check that wrote, or asked for write access, fails here;
  * the whole chain is run once with the real pieces: the server picks the check, the real agent stores and evaluates
    it, the real heartbeat handler ingests the result and the Checks engine reads a status;
  * the handler is driven as a tenant administrator, a read-only user and the platform operator, with only
    verify_token replaced.

Nothing here runs on a real Windows host: the registry is a fake with the types and the errors winreg raises.
"""
import importlib.util
import os
import random
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-regcheck-'))

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import checks  # noqa: E402
from i18n_engine import LANGS, dict_rows  # noqa: E402

_spec = importlib.util.spec_from_file_location('api_registry_check', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

_wspec = importlib.util.spec_from_file_location('rp_win_registry_check', _ROOT / 'client' / 'remotepower-agent-win.py')
win = importlib.util.module_from_spec(_wspec)
_wspec.loader.exec_module(win)


# ── a registry that records what it is asked ─────────────────────────────────
class FakeWinreg:
    """The part of winreg a check may use, with the values and errors the real module has.

    Anything else is a write or a surprise: it is recorded in `touched` and raises, so a check that
    reached for it fails whichever way the agent catches errors.
    """
    HKEY_LOCAL_MACHINE = 0x80000002
    KEY_READ = 0x20019
    KEY_WOW64_64KEY = 0x100
    KEY_WOW64_32KEY = 0x200
    REG_NONE, REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_MULTI_SZ, REG_QWORD = 0, 1, 2, 3, 4, 7, 11

    def __init__(self, values=None, deny=(), broken=()):
        self.values = {}
        self.keys = set()
        for (path, name), (data, typ) in (values or {}).items():
            self.values[(path.lower(), name.lower())] = (data, typ)
            self.keys.add(path.lower())
        self.deny = {d.lower() for d in deny}
        self.broken = {b.lower() for b in broken}
        self.calls = []
        self.touched = []

    def OpenKey(self, hive, path, reserved=0, access=KEY_READ):
        self.calls.append(('OpenKey', hive, path, reserved, access))
        if path.lower() in self.deny:
            raise PermissionError(5, 'Access is denied')
        if path.lower() in self.broken:
            raise OSError(1450, 'Insufficient system resources')
        if path.lower() not in self.keys:
            raise FileNotFoundError(2, 'The system cannot find the file specified')
        return ('hkey', path.lower())

    def QueryValueEx(self, key, name):
        self.calls.append(('QueryValueEx', key, name))
        try:
            return self.values[(key[1], name.lower())]
        except KeyError:
            raise FileNotFoundError(2, 'The system cannot find the file specified') from None

    def CloseKey(self, key):
        self.calls.append(('CloseKey', key))

    def __getattr__(self, name):
        if not name.startswith('__'):          # the import machinery looks up __spec__ on a module it finds in sys.modules
            self.touched.append(name)
        raise AttributeError('a registry check used winreg.%s' % name)


def _template(cid):
    return next(t for t in checks.CHECK_BASELINE_CATALOG if t['id'] == cid)


def _pushed(cid, rid='ck_00001'):
    """The check as the heartbeat pushes it to the agent: the template's own fields."""
    t = _template(cid)
    return dict({'id': rid, 'type': t['type'], 'param': t['param']}, **t['extras'])


def _run(fake, check):
    with mock.patch.dict(sys.modules, {'winreg': fake}):
        return win._eval_one_agent_check_win(check)


REGISTRY_TEMPLATES = [t for t in checks.CHECK_BASELINE_CATALOG if t['type'] == 'registry']
S, E, D = FakeWinreg.REG_SZ, FakeWinreg.REG_EXPAND_SZ, FakeWinreg.REG_DWORD

# What a hardened host and a loose one hold for each baseline, written from what Windows stores
# (the value, its type), not from what the template says.
_P_SMB = r'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
_P_LSA = r'SYSTEM\CurrentControlSet\Control\Lsa'
_P_UAC = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
_P_DEF = r'SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
_P_RDP = r'SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
_P_WL = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
STATES = {
    'win_smb1_server_off':          ({(_P_SMB, 'SMB1'): (0, D)}, {(_P_SMB, 'SMB1'): (1, D)}),
    'win_ntlm_level_5':             ({(_P_LSA, 'LmCompatibilityLevel'): (5, D)}, {(_P_LSA, 'LmCompatibilityLevel'): (3, D)}),
    'win_uac_enabled':              ({(_P_UAC, 'EnableLUA'): (1, D)}, {(_P_UAC, 'EnableLUA'): (0, D)}),
    'win_defender_realtime_policy': ({(_P_DEF, 'DisableRealtimeMonitoring'): (0, D)}, {(_P_DEF, 'DisableRealtimeMonitoring'): (1, D)}),
    'win_rdp_nla_required':         ({(_P_RDP, 'UserAuthentication'): (1, D)}, {(_P_RDP, 'UserAuthentication'): (0, D)}),
    'win_cached_logons_max_4':      ({(_P_WL, 'CachedLogonsCount'): ('2', S)}, {(_P_WL, 'CachedLogonsCount'): ('10', S)}),
}


class TestTheBaselineTemplates(unittest.TestCase):
    def test_the_population_is_the_six_the_brief_names(self):
        self.assertEqual(sorted(t['id'] for t in REGISTRY_TEMPLATES), sorted(STATES))
        self.assertEqual(len(REGISTRY_TEMPLATES), 6)

    def test_each_template_is_a_valid_definition_and_its_param_is_the_one_line_form(self):
        for t in REGISTRY_TEMPLATES:
            with self.subTest(t['id']):
                clean, why = checks.validate_registry_check(t['extras'])
                self.assertEqual((clean, why), (t['extras'], ''))
                self.assertEqual(checks.registry_param(clean), t['param'])

    def test_each_description_names_the_registry_fact_it_reads(self):
        for t in REGISTRY_TEMPLATES:
            with self.subTest(t['id']):
                x = t['extras']
                self.assertIn('%s\\%s\\%s' % (x['hive'], x['path'], x['value']), t['desc'])

    def test_a_template_is_in_the_protect_picker_and_in_its_own_category(self):
        for t in REGISTRY_TEMPLATES:
            self.assertEqual(t['cat'], 'Hardening — Windows registry')
            self.assertEqual(checks.baseline_kind(t['cat']), 'protect')

    def test_a_hardened_host_passes_and_a_loose_one_fails(self):
        for t in REGISTRY_TEMPLATES:
            good, bad = STATES[t['id']]
            with self.subTest(t['id'], host='hardened'):
                status, out = _run(FakeWinreg(good), _pushed(t['id']))
                self.assertEqual(status, 'ok', out)
            with self.subTest(t['id'], host='loose'):
                status, out = _run(FakeWinreg(bad), _pushed(t['id']))
                self.assertEqual(status, 'critical', out)

    def test_a_value_that_is_not_set_follows_the_rule_in_the_description(self):
        # not_equals passes on no value; the other conditions fail on it
        for t in REGISTRY_TEMPLATES:
            with self.subTest(t['id']):
                status, out = _run(FakeWinreg({}), _pushed(t['id']))
                self.assertEqual(status, 'ok' if t['extras']['op'] == 'not_equals' else 'critical', out)
                self.assertIn('not set', out)

    def test_apply_lands_the_check_with_all_its_fields_and_the_catalog_marks_it_applied(self):
        d = Path(tempfile.mkdtemp(prefix='rp-regapply-'))
        saved = {n: getattr(api, n) for n in ('CONFIG_FILE', 'DEVICES_FILE')}
        fns = {n: getattr(api, n) for n in ('respond', 'require_admin_auth', 'require_auth', 'audit_log', 'method',
                                            'get_json_obj', 'get_json_body', '_require_platform_operator')}
        cap = {}

        def respond(status, data=None):
            cap['s'], cap['d'] = status, data
            raise api.HTTPError(status, data)
        try:
            for n in saved:
                setattr(api, n, d / saved[n].name)
            api.respond = respond
            api.require_admin_auth = lambda: 'admin'
            api.require_auth = lambda: 'admin'
            api._require_platform_operator = lambda *_a, **_k: None
            api.audit_log = lambda *a, **k: None
            api.method = lambda: 'POST'
            api.save(api.CONFIG_FILE, {})
            api.save(api.DEVICES_FILE, {})
            ids = [t['id'] for t in REGISTRY_TEMPLATES]
            api.get_json_obj = api.get_json_body = lambda: {'ids': ids, 'target_kind': 'all', 'target': ''}
            api._invalidate_load_cache(api.CONFIG_FILE)
            with self.assertRaises(api.HTTPError):
                api.handle_check_baselines_apply()
            self.assertEqual((cap['s'], cap['d']['added']), (200, 6))
            rows = [c for c in api.load(api.CONFIG_FILE)['custom_checks'] if c['type'] == 'registry']
            self.assertEqual(len(rows), 6)
            for row in rows:
                t = next(t for t in REGISTRY_TEMPLATES if t['param'] == row['param'])
                for k, v in t['extras'].items():
                    self.assertEqual(row[k], v, (t['id'], k))
                self.assertEqual(row['kind'], 'protect')
            # the same apply again adds nothing, and the catalog says where each one is applied
            api._invalidate_load_cache(api.CONFIG_FILE)
            with self.assertRaises(api.HTTPError):
                api.handle_check_baselines_apply()
            self.assertEqual(cap['d']['added'], 0)
            api.method = lambda: 'GET'
            api._invalidate_load_cache(api.CONFIG_FILE)
            with self.assertRaises(api.HTTPError):
                api.handle_check_baseline_catalog()
            applied = {t['id']: t['applied_count'] for t in cap['d']['catalog'] if t['type'] == 'registry'}
            self.assertEqual(applied, {i: 1 for i in ids})
        finally:
            for n, v in saved.items():
                setattr(api, n, v)
            for n, v in fns.items():
                setattr(api, n, v)
            api._LOAD_CACHE.clear()


class TestTheAgentReadsOnly(unittest.TestCase):
    def test_a_check_only_opens_for_reading_queries_one_value_and_closes(self):
        for cid in STATES:
            good, bad = STATES[cid]
            for st in (good, bad, {}):
                fake = FakeWinreg(st)
                _run(fake, _pushed(cid))
                with self.subTest(cid, state=len(st)):
                    self.assertEqual([c[0] for c in fake.calls if c[0] not in ('OpenKey', 'QueryValueEx', 'CloseKey')], [])
                    self.assertEqual(fake.touched, [], 'a registry check reached for winreg.%s' % fake.touched)
                    opens = [c for c in fake.calls if c[0] == 'OpenKey']
                    self.assertEqual(len(opens), 1)
                    access = opens[0][4]
                    self.assertEqual(access & ~(FakeWinreg.KEY_READ | FakeWinreg.KEY_WOW64_64KEY), 0,
                                     'the key was opened with more than read access: %#x' % access)
                    self.assertTrue(access & FakeWinreg.KEY_WOW64_64KEY, 'the native 64-bit view was not asked for')
                    self.assertEqual(opens[0][1], FakeWinreg.HKEY_LOCAL_MACHINE)

    def test_every_key_that_was_opened_is_closed(self):
        fake = FakeWinreg(STATES['win_uac_enabled'][0])
        _run(fake, _pushed('win_uac_enabled'))
        self.assertEqual([c[0] for c in fake.calls], ['OpenKey', 'QueryValueEx', 'CloseKey'])

    def test_the_agent_source_names_no_function_that_writes(self):
        src = (_ROOT / 'client' / 'remotepower-agent-win.py').read_text(encoding='utf-8')
        start = src.index('def _reg_read(')
        body = src[start:src.index('def _eval_one_agent_check_win')]
        for writer in ('SetValue', 'SetValueEx', 'CreateKey', 'CreateKeyEx', 'DeleteKey', 'DeleteValue', 'KEY_ALL_ACCESS',
                       'KEY_SET_VALUE', 'KEY_WRITE', 'KEY_CREATE_SUB_KEY', 'SaveKey', 'LoadKey', 'ConnectRegistry'):
            self.assertNotIn(writer, body)


class TestWhatTheAgentReports(unittest.TestCase):
    def _one(self, name, data, typ, op='exists', expect=None, path=_P_UAC):
        c = {'id': 'x', 'type': 'registry', 'hive': 'HKLM', 'path': path, 'value': name, 'op': op}
        if expect is not None:
            c['expect'] = expect
        return _run(FakeWinreg({(path, name): (data, typ)}), c)

    def test_a_binary_value_is_reported_as_its_size_never_as_bytes(self):
        raw = b'\x00\x01\xfe\xffsecret-looking-bytes'
        status, out = self._one('Blob', raw, FakeWinreg.REG_BINARY)
        self.assertEqual((status, out), ('ok', 'Blob = binary, %d bytes' % len(raw)))
        self.assertNotIn('secret', out)
        status, out = self._one('Blob', raw, FakeWinreg.REG_BINARY, 'equals', 'anything')
        self.assertEqual(status, 'critical')
        self.assertNotIn('secret', out)
        self.assertEqual(self._one('Nothing', None, FakeWinreg.REG_NONE)[1], 'Nothing = binary, 0 bytes')

    def test_a_number_is_an_integer_and_a_text_number_compares_as_a_number(self):
        self.assertEqual(self._one('N', 7, D, 'equals', 7)[0], 'ok')
        self.assertEqual(self._one('N', '7', S, 'equals', 7)[0], 'ok')
        self.assertEqual(self._one('N', '7', S, 'equals', '0x7')[0], 'ok')
        self.assertEqual(self._one('N', 2 ** 40, FakeWinreg.REG_QWORD, 'at_least', 2 ** 39)[0], 'ok')
        self.assertEqual(self._one('N', '12', S, 'at_most', 4)[0], 'critical')
        self.assertEqual(self._one('N', 'twelve', S, 'at_most', 4)[0], 'critical')

    def test_a_text_is_compared_without_regard_to_case_and_is_not_expanded(self):
        self.assertEqual(self._one('T', 'Enabled', S, 'equals', 'ENABLED')[0], 'ok')
        self.assertEqual(self._one('T', 'Enabled', S, 'not_equals', 'enabled')[0], 'critical')
        status, out = self._one('T', r'%SystemRoot%\system32', E, 'exists')
        self.assertEqual(out, r'T = %SystemRoot%\system32')

    def test_a_multi_string_is_one_text(self):
        status, out = self._one('M', ['one', 'two', 'three'], FakeWinreg.REG_MULTI_SZ, 'equals', 'one | two | three')
        self.assertEqual(status, 'ok')

    def test_a_long_text_is_cut_at_200_characters_and_control_characters_are_gone(self):
        status, out = self._one('Long', 'x' * 5000, S)
        self.assertLessEqual(len(out), 200)
        status, out = self._one('Ctl', 'a\x1b[31mred\x00\nline\u2028two\x9f', S)
        self.assertEqual(out, 'Ctl = a [31mred  line two ')
        self.assertFalse([c for c in out if ord(c) < 32 or 0x7f <= ord(c) <= 0x9f or c in '\u2028\u2029'])

    def test_a_text_value_named_like_a_secret_is_not_read_but_a_number_with_such_a_name_is(self):
        for name in ('DefaultPassword', 'ProxyPasswd', 'ClientSecret', 'AccessToken', 'PrivateKey', 'ApiKey', 'Credentials'):
            with self.subTest(name):
                status, out = self._one(name, 'hunter2-the-real-password', S, 'exists')
                self.assertEqual(status, 'unknown')
                self.assertNotIn('hunter2', out)
                self.assertTrue(out.startswith('refused'))
        # a policy flag that happens to hold the word is a number, and a check on it is the point
        status, out = self._one('LocalAccountTokenFilterPolicy', 0, D, 'equals', 0)
        self.assertEqual((status, out), ('ok', 'LocalAccountTokenFilterPolicy = 0'))

    def test_what_the_registry_refuses_is_unknown_not_a_failure_and_never_raises(self):
        c = _pushed('win_uac_enabled')
        status, out = _run(FakeWinreg({}, deny=[_P_UAC]), c)
        self.assertEqual((status, out), ('unknown', 'access denied'))
        status, out = _run(FakeWinreg({(_P_UAC, 'EnableLUA'): (1, D)}, broken=[_P_UAC]), c)
        self.assertEqual(status, 'unknown')

    def test_a_host_without_winreg_answers_unknown(self):
        with mock.patch.dict(sys.modules, {'winreg': None}):
            status, out = win._eval_one_agent_check_win(_pushed('win_uac_enabled'))
        self.assertEqual((status, out), ('unknown', 'the registry is only on Windows'))

    def test_it_comes_back_through_eval_agent_checks_in_the_shape_the_server_reads(self):
        fake = FakeWinreg(STATES['win_ntlm_level_5'][1])
        with mock.patch.dict(sys.modules, {'winreg': fake}):
            res = win.eval_agent_checks([_pushed('win_ntlm_level_5', 'ck_77')])
        self.assertEqual(res, {'ck_77': {'status': 'critical', 'output': 'LmCompatibilityLevel = 3, expected at least 5'}})


# ── the rules, held twice ────────────────────────────────────────────────────
def _body(**kw):
    base = {'hive': 'HKLM', 'path': r'SOFTWARE\Vendor\Product', 'value': 'Setting', 'op': 'equals', 'expect': '1'}
    base.update(kw)
    return base


def _refusals():
    """(label, body) for each way a definition is refused. The label is what the case is about."""
    deep = 'SOFTWARE' + '\\a' * 12             # 13 parts
    return [
        ('hive hkcu', _body(hive='HKCU')),
        ('hive hkey_local_machine', _body(hive='HKEY_LOCAL_MACHINE')),
        ('hive hku', _body(hive='HKU')),
        ('root sam', _body(path=r'SAM\SAM\Domains')),
        ('root security', _body(path=r'SECURITY\Policy')),
        ('root hardware', _body(path=r'HARDWARE\DESCRIPTION')),
        ('root bcd', _body(path=r'BCD00000000\Objects')),
        ('root lookalike', _body(path=r'SOFTWAREX\Vendor')),
        ('no path', _body(path='')),
        ('13 parts', _body(path=deep)),
        ('parent part', _body(path=r'SOFTWARE\..\SAM')),
        ('dot part', _body(path=r'SOFTWARE\.\Vendor')),
        ('empty part', _body(path='SOFTWARE\\\\Vendor')),
        ('trailing backslash', _body(path='SOFTWARE\\Vendor\\')),
        ('leading backslash', _body(path='\\SOFTWARE\\Vendor')),
        ('forward slash', _body(path='SOFTWARE/Vendor')),
        ('quote in path', _body(path='SOFTWARE\\Ven"dor')),
        ('semicolon in path', _body(path='SOFTWARE\\Ven;dor')),
        ('ampersand in path', _body(path='SOFTWARE\\Ven&dor')),
        ('dollar in path', _body(path='SOFTWARE\\$Recycle')),
        ('percent in path', _body(path='SOFTWARE\\%TEMP%')),
        ('colon in path', _body(path='HKLM:\\SOFTWARE\\Vendor')),
        ('newline in path', _body(path='SOFTWARE\\Vendor\nSAM')),
        ('nul in path', _body(path='SOFTWARE\\Vendor\x00')),
        ('tab in path', _body(path='SOFTWARE\\Ven\tdor')),
        ('unicode in path', _body(path='SOFTWARE\\Vendör')),
        ('fullwidth backslash', _body(path='SOFTWARE＼Vendor')),
        ('201 characters', _body(path='SOFTWARE\\' + 'a' * 192)),
        ('no value name', _body(value='')),
        ('value with a backslash', _body(value='a\\b')),
        ('value with a quote', _body(value='a"b')),
        ('value with a slash', _body(value='a/b')),
        ('value 65 characters', _body(value='v' * 65)),
        ('value with a newline', _body(value='a\nb')),
        ('no condition', _body(op='')),
        ('unknown condition', _body(op='greater')),
        ('condition with a typo', _body(op='atleast')),
        ('equals without expect', _body(expect='')),
        ('at_least without a number', _body(op='at_least', expect='high')),
        ('at_most with text', _body(op='at_most', expect='4x')),
        ('at_most with a float', _body(op='at_most', expect='4.5')),
        ('expect 101 characters', _body(expect='e' * 101)),
        ('expect with a control character', _body(expect='a\x07b')),
        ('expect with a newline', _body(expect='a\nb')),
        ('number out of range', _body(op='at_least', expect='9' * 25)),
    ]


def _accepted():
    return [
        ('plain', _body()),
        ('lower case hive and root', _body(hive='hklm', path='software\\Vendor')),
        ('12 parts', _body(path='SOFTWARE' + '\\a' * 11)),
        ('one part', _body(path='SYSTEM')),
        ('spaces and braces and parens', _body(path='SOFTWARE\\Microsoft\\Windows NT\\(x86)\\{GUID-1}\\a.b_c-d')),
        ('hex expect', _body(op='at_least', expect='0x1F')),
        ('negative number', _body(expect='-1')),
        ('text expect', _body(expect='Enabled')),
        ('exists needs no expect', _body(op='exists', expect='')),
        ('missing ignores expect', _body(op='missing', expect='whatever')),
        ('upper case op', _body(op='NOT_EQUALS')),
        ('dword max', _body(op='at_most', expect=str(2 ** 32 - 1))),
        ('qword max', _body(op='at_most', expect=str(2 ** 64 - 1))),
        ('expect exactly 100', _body(expect='e' * 100)),
        ('value exactly 64', _body(value='v' * 64)),
        ('path exactly 200', _body(path='SOFTWARE\\' + 'a' * 191)),
        ('whitespace trimmed', _body(path='  SOFTWARE\\Vendor  ', value='  Setting  ', op=' equals ', expect=' 1 ')),
        ('no hive means HKLM', {k: v for k, v in _body().items() if k != 'hive'}),
        ('int expect', _body(expect=1)),
    ]


class TestTheRulesAreHeldTwice(unittest.TestCase):
    def test_the_server_refuses_each_case_with_a_sentence_from_its_list(self):
        for label, body in _refusals():
            with self.subTest(label):
                clean, why = checks.validate_registry_check(body)
                self.assertIsNone(clean)
                self.assertIn(why, checks.REGISTRY_REFUSALS)

    def test_the_agent_refuses_the_same_cases_and_reads_nothing(self):
        for label, body in _refusals():
            with self.subTest(label):
                fake = FakeWinreg({(r'SOFTWARE\Vendor\Product', 'Setting'): (1, D)})
                status, out = _run(fake, dict(body, id='x', type='registry'))
                self.assertEqual(status, 'unknown')
                self.assertTrue(out.startswith('refused'), out)
                self.assertEqual(fake.calls, [], 'a refused definition still touched the registry')

    def test_both_accept_the_same_cases_and_agree_on_what_they_mean(self):
        for label, body in _accepted():
            with self.subTest(label):
                clean, why = checks.validate_registry_check(body)
                self.assertEqual(why, '')
                aclean, awhy = win._reg_clean(dict(body))
                self.assertEqual((aclean, awhy), (clean, ''))
                for k in ('hive', 'path', 'value', 'op'):
                    self.assertIsInstance(clean[k], str)
                if 'expect' in clean:
                    self.assertIn(type(clean['expect']), (int, str))

    def test_a_hundred_thousand_random_definitions_get_one_verdict_from_both(self):
        rng = random.Random(20260901)
        alphabet = ['SOFTWARE', 'SYSTEM', 'software', 'SAM', 'a', 'B1', 'x y', '.', '..', '', ' ', '(x86)', '{g}', 'é', '$', '%', '/', ';', '"', "'", '\t', '\n',
                    '\x00', '-', '_', 'HKLM', 'HKCU', '＼', 'ＳＯＦＴ']
        ops = ['equals', 'not_equals', 'at_least', 'at_most', 'exists', 'missing', 'EQUALS', 'gt', '', ' at_most ']
        expects = ['', '0', '1', '-1', '0x10', '0XfF', 'abc', 'a b', '1.5', '9' * 22, '1e5', ' 7 ', 'é', '\x07', 'x' * 101, 5, 0]
        values = ['', 'a', 'Setting', 'a b', 'a\\b', 'v' * 65, '.', '..', 'é', '{x}']
        both_accept = both_refuse = 0
        for _ in range(100000):
            parts = [rng.choice(alphabet) for _ in range(rng.choice([0, 1, 1, 2, 3, 4, 12, 13, 14]))]
            if rng.random() < 0.6 and parts:
                parts[0] = rng.choice(['SOFTWARE', 'SYSTEM', 'software'])
            body = {'hive': rng.choice(['HKLM', 'HKLM', 'hklm', 'HKCU', '', None, ' HKLM ']), 'path': '\\'.join(parts),
                    'value': rng.choice(values), 'op': rng.choice(ops), 'expect': rng.choice(expects)}
            clean, _why = checks.validate_registry_check(body)
            aclean, _awhy = win._reg_clean(dict(body))
            self.assertEqual(clean, aclean, body)
            if clean is None:
                both_refuse += 1
            else:
                both_accept += 1
        # controls on the generator: it must produce both verdicts in numbers, or agreement means nothing
        self.assertGreater(both_accept, 1000)
        self.assertGreater(both_refuse, 1000)

    def test_every_refusal_sentence_is_reached_by_some_input(self):
        reached = {checks.validate_registry_check(b)[1] for _l, b in _refusals()}
        reached |= {checks.validate_registry_check(None)[1]}
        self.assertEqual(sorted(set(checks.REGISTRY_REFUSALS) - reached), [], 'a refusal sentence nothing produces')

    def test_the_limits_in_the_two_places_are_the_same_numbers(self):
        self.assertEqual(
            (checks.REGISTRY_MAX_SEGMENTS, checks.REGISTRY_MAX_PATH, checks.REGISTRY_MAX_VALUE_NAME, checks.REGISTRY_MAX_EXPECT),
            (win._REG_MAX_SEGMENTS, win._REG_MAX_PATH, win._REG_MAX_VALUE_NAME, win._REG_MAX_EXPECT))
        self.assertEqual((checks.REGISTRY_HIVES, checks.REGISTRY_ROOTS, checks.REGISTRY_OPS),
                         (win._REG_HIVES, win._REG_ROOTS, win._REG_OPS))

    def test_the_refusal_that_names_a_limit_names_the_real_one(self):
        self.assertIn('%d parts' % checks.REGISTRY_MAX_SEGMENTS, checks.validate_registry_check(_body(path='SOFTWARE' + '\\a' * 12))[1])
        self.assertIn('%d characters' % checks.REGISTRY_MAX_PATH, checks.validate_registry_check(_body(path='SOFTWARE\\' + 'a' * 192))[1])
        self.assertIn('%d characters' % checks.REGISTRY_MAX_VALUE_NAME, checks.validate_registry_check(_body(value='v' * 65))[1])
        self.assertIn('%d characters' % checks.REGISTRY_MAX_EXPECT, checks.validate_registry_check(_body(expect='e' * 101))[1])


# ── the server: save, scope, push ────────────────────────────────────────────
class _Server(unittest.TestCase):
    STORES = ('CONFIG_FILE', 'USERS_FILE', 'TENANTS_FILE', 'AUDIT_LOG_FILE', 'TOKENS_FILE', 'DEVICES_FILE', 'ALERTS_FILE',
              'FLEET_EVENTS_FILE')
    FNS = ('respond', 'method', 'get_json_obj', 'get_json_body', 'audit_log', 'get_token_from_request', 'verify_token')

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix='rp-regsrv-'))
        self.addCleanup(lambda: __import__('shutil').rmtree(self.d, ignore_errors=True))
        self._saved = {n: getattr(api, n) for n in self.STORES}
        for n in self.STORES:
            setattr(api, n, self.d / self._saved[n].name)
        self._fns = {n: getattr(api, n) for n in self.FNS}
        self.cap, self.body, self.m, self.who = {}, {}, 'POST', 'platform'

        def _respond(status, data=None):
            self.cap['status'], self.cap['data'] = status, data
            raise api.HTTPError(status, data)
        api.respond = _respond
        api.method = lambda: self.m
        api.get_json_obj = lambda: dict(self.body)
        api.get_json_body = lambda: dict(self.body)
        api.audit_log = lambda *a, **k: None
        api.get_token_from_request = lambda: 'tok'
        api.verify_token = lambda _t=None: (
            (self.who, (api._load_ro(api.USERS_FILE) or {}).get(self.who, {}).get('role')) if self.who else (None, None))
        api.save(api.TENANTS_FILE, {'default': {'name': 'Default', 'status': 'active', 'builtin': True},
                                    'tenantB': {'name': 'B', 'status': 'active'}})
        api.save(api.USERS_FILE, {'platform': {'role': 'admin', 'tenant_id': 'default'},
                                  'badmin': {'role': 'admin', 'tenant_id': 'tenantB'},
                                  'viewer1': {'role': 'viewer', 'tenant_id': 'default'}})
        api.save(api.DEVICES_FILE, {})
        api.save(api.CONFIG_FILE, {'tenancy_enforced': True})
        api._LOAD_CACHE.clear()

    def tearDown(self):
        for n, v in self._saved.items():
            setattr(api, n, v)
        for n, v in self._fns.items():
            setattr(api, n, v)
        api._LOAD_CACHE.clear()

    def call(self, fn, body=None, m='POST', who='platform'):
        self.who, self.body, self.m = who, dict(body or {}), m
        self.cap.clear()
        api._LOAD_CACHE.clear()
        try:
            fn()
        except (api.HTTPError, SystemExit):
            pass
        api._LOAD_CACHE.clear()
        data = self.cap.get('data')
        return self.cap.get('status'), ({} if data is None else data)

    def stored(self):
        return [c for c in (api.load(api.CONFIG_FILE) or {}).get('custom_checks', []) if c.get('type') == 'registry']


class TestSavingADefinition(_Server):
    BODY = {'type': 'registry', 'name': 'NTLMv2 only', 'hive': 'HKLM', 'path': _P_LSA, 'value': 'LmCompatibilityLevel',
            'op': 'at_least', 'expect': '5', 'target_kind': 'all', 'target': ''}

    def test_a_valid_definition_is_saved_with_its_one_line_param_and_typed_fields(self):
        st, d = self.call(api.handle_custom_checks_save, self.BODY)
        self.assertEqual(st, 200, d)
        row = self.stored()[0]
        self.assertEqual(row['param'], 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel at_least 5')
        self.assertEqual((row['hive'], row['path'], row['value'], row['op'], row['expect']),
                         ('HKLM', _P_LSA, 'LmCompatibilityLevel', 'at_least', 5))
        self.assertIsInstance(row['expect'], int)

    def test_the_json_number_and_the_text_number_save_the_same_thing(self):
        self.call(api.handle_custom_checks_save, dict(self.BODY, expect=5))
        self.call(api.handle_custom_checks_save, dict(self.BODY, expect='0x5', id='ck_00002'))
        a, b = self.stored()
        self.assertEqual((a['expect'], b['expect']), (5, 5))

    def test_every_way_of_being_refused_is_a_400_that_says_what_and_stores_nothing(self):
        for label, bad in _refusals():
            with self.subTest(label):
                st, d = self.call(api.handle_custom_checks_save, dict(self.BODY, **{k: bad[k] for k in bad}))
                self.assertEqual(st, 400, d)
                self.assertIn(d['error'], checks.REGISTRY_REFUSALS)
                self.assertEqual(self.stored(), [])

    def test_a_param_in_the_request_does_not_stand_in_for_the_fields(self):
        st, d = self.call(api.handle_custom_checks_save, {'type': 'registry', 'param': 'HKLM\\SYSTEM\\x\\y equals 1'})
        self.assertEqual(st, 400)
        self.assertEqual(self.stored(), [])

    def test_a_param_in_the_request_is_replaced_by_the_one_built_from_the_fields(self):
        st, d = self.call(api.handle_custom_checks_save, dict(self.BODY, param='HKLM\\SOFTWARE\\somewhere\\else exists'))
        self.assertEqual(st, 200)
        self.assertEqual(self.stored()[0]['param'], checks.registry_param(self.stored()[0]))

    def test_saving_again_with_the_same_id_replaces_the_definition(self):
        self.call(api.handle_custom_checks_save, self.BODY)
        cid = self.stored()[0]['id']
        self.call(api.handle_custom_checks_save, dict(self.BODY, id=cid, op='equals', expect='5'))
        rows = self.stored()
        self.assertEqual((len(rows), rows[0]['op'], rows[0]['param'].endswith('equals 5')), (1, 'equals', True))

    def test_exists_keeps_no_expected_value(self):
        self.call(api.handle_custom_checks_save, dict(self.BODY, op='exists', expect='5'))
        self.assertNotIn('expect', self.stored()[0])

    def test_the_other_types_save_as_before(self):
        st, d = self.call(api.handle_custom_checks_save, {'type': 'file_present', 'param': '/etc/hosts'})
        self.assertEqual(st, 200, d)
        row = (api.load(api.CONFIG_FILE)['custom_checks'])[0]
        self.assertNotIn('hive', row)
        st, d = self.call(api.handle_custom_checks_save, {'type': 'file_present', 'param': ''})
        self.assertEqual((st, d['error']), (400, 'param is required'))

    def test_registry_is_one_of_the_types_the_list_offers(self):
        st, d = self.call(api.handle_custom_checks_list, m='GET')
        self.assertIn('registry', d['types'])


class TestWhoMaySave(_Server):
    BODY = TestSavingADefinition.BODY

    def test_a_tenant_administrator_is_refused(self):
        st, d = self.call(api.handle_custom_checks_save, self.BODY, who='badmin')
        self.assertEqual(st, 403, d)
        self.assertIn('platform operator', d['error'])
        self.assertEqual(self.stored(), [])

    def test_a_read_only_user_is_refused(self):
        st, d = self.call(api.handle_custom_checks_save, self.BODY, who='viewer1')
        self.assertEqual(st, 403, d)
        self.assertEqual(self.stored(), [])

    def test_the_platform_operator_may_and_so_may_the_administrator_of_a_single_tenant_install(self):
        self.assertEqual(self.call(api.handle_custom_checks_save, self.BODY, who='platform')[0], 200)
        api.save(api.CONFIG_FILE, {'tenancy_enforced': False})
        api._LOAD_CACHE.clear()
        self.assertEqual(self.call(api.handle_custom_checks_save, dict(self.BODY, id='ck_00009'), who='badmin')[0], 200)

    def test_a_tenant_reads_the_checks_aimed_at_its_own_hosts_and_at_everyone(self):
        api.save(api.DEVICES_FILE, {'devB': {'name': 'b1', 'tenant': 'tenantB', 'os': 'Windows 11', 'tags': ['wb']},
                                    'devA': {'name': 'a1', 'tenant': 'default', 'os': 'Windows 11', 'tags': ['wa']}})
        base = dict(self.BODY)
        self.call(api.handle_custom_checks_save, dict(base, name='all', target_kind='all'))
        self.call(api.handle_custom_checks_save, dict(base, name='mine', target_kind='host', target='devB', op='equals'))
        self.call(api.handle_custom_checks_save, dict(base, name='theirs', target_kind='host', target='devA', op='equals', expect='4'))
        st, d = self.call(api.handle_custom_checks_list, m='GET', who='badmin')
        self.assertEqual(st, 200)
        self.assertEqual(sorted(c['name'] for c in d['checks']), ['all', 'mine'])
        st, d = self.call(api.handle_custom_checks_list, m='GET', who='platform')
        self.assertEqual(sorted(c['name'] for c in d['checks']), ['all', 'mine', 'theirs'])


class TestOnlyAWindowsHostIsGivenTheCheck(_Server):
    HOSTS = {'win': {'name': 'desk', 'os': 'Windows 11 Pro'}, 'srv': {'name': 'dc', 'os': 'Windows Server 2022 Datacenter'},
             'lin': {'name': 'web', 'os': 'Debian GNU/Linux 12'}, 'mac': {'name': 'mbp', 'os': 'macOS 14.5'},
             'none': {'name': 'new'}, 'empty': {'name': 'e', 'os': ''}}

    def test_applies_is_true_for_windows_only(self):
        c = {'id': 'k', 'type': 'registry', 'target_kind': 'all'}
        got = {h: checks._custom_check_applies(c, h, d) for h, d in self.HOSTS.items()}
        self.assertEqual(got, {'win': True, 'srv': True, 'lin': False, 'mac': False, 'none': False, 'empty': False})

    def test_the_other_types_are_not_gated_by_os(self):
        for t in ('file_present', 'systemd_unit', 'windows_service', 'log_errors', 'process'):
            c = {'id': 'k', 'type': t, 'target_kind': 'all'}
            self.assertTrue(all(checks._custom_check_applies(c, h, d) for h, d in self.HOSTS.items()), t)

    def test_a_non_windows_host_shows_no_row_for_it(self):
        c = {'id': 'k', 'type': 'registry', 'name': 'x', 'target_kind': 'all', 'op': 'exists'}
        self.assertEqual(checks._custom_checks_for('lin', self.HOSTS['lin'], [c], set()), [])
        rows = checks._custom_checks_for('win', self.HOSTS['win'], [c], set())
        self.assertEqual([(r['key'], r['status']) for r in rows], [('custom:k', 'unknown')])


class TestThePushAndTheChain(_Server):
    """The real pieces end to end: the server picks, the real agent stores and evaluates, the real handler ingests."""

    def setUp(self):
        super().setUp()
        api.save(api.CONFIG_FILE, {})
        self.now = int(time.time())
        mk = lambda os_: {'name': os_, 'hostname': os_, 'os': os_, 'token': 'tok-' + os_.split()[0], 'last_seen': self.now,
                          'enrolled': self.now, 'tags': [], 'group': '', 'sysinfo': {}, 'agentless': False}
        api.save(api.DEVICES_FILE, {'winhost': mk('Windows 11 Pro'), 'linhost': mk('Debian 12')})
        api.save(api.CONFIG_FILE, {'custom_checks': [
            dict({'id': 'ck_reg', 'name': 'NTLMv2', 'type': 'registry', 'param': _template('win_ntlm_level_5')['param'],
                  'target_kind': 'all', 'target': ''}, **_template('win_ntlm_level_5')['extras']),
            {'id': 'ck_file', 'name': 'hosts', 'type': 'file_present', 'param': '/etc/hosts', 'target_kind': 'all', 'target': ''}]})
        api._LOAD_CACHE.clear()
        self._agent = (win._watched_agent_checks,)
        self.addCleanup(lambda: setattr(win, '_watched_agent_checks', self._agent[0]))
        win._watched_agent_checks = []

    def _beat(self, dev_id, body):
        self.body = dict(body, device_id=dev_id)
        self.cap.clear()
        api._LOAD_CACHE.clear()
        self.m = 'POST'
        try:
            api.handle_heartbeat()
        except (api.HTTPError, SystemExit):
            pass
        return self.cap.get('status'), self.cap.get('data') or {}

    def test_a_windows_host_is_pushed_the_check_with_its_five_fields_and_a_linux_host_is_not(self):
        st, resp = self._beat('winhost', {'token': 'tok-Windows', 'sysinfo': {}})
        self.assertEqual(st, 200, resp)
        pushed = {c['id']: c for c in resp['agent_checks']}
        self.assertEqual(set(pushed), {'ck_reg', 'ck_file'})
        x = _template('win_ntlm_level_5')['extras']
        self.assertEqual({k: pushed['ck_reg'][k] for k in ('hive', 'path', 'value', 'op', 'expect')}, x)
        st, resp = self._beat('linhost', {'token': 'tok-Debian', 'sysinfo': {}})
        self.assertEqual(st, 200, resp)
        self.assertEqual([c['id'] for c in resp['agent_checks']], ['ck_file'])

    def test_a_loose_host_goes_critical_and_a_hardened_one_ok_through_every_piece(self):
        for label, state, want in (('loose', STATES['win_ntlm_level_5'][1], 'critical'), ('hardened', STATES['win_ntlm_level_5'][0], 'ok')):
            with self.subTest(label):
                st, resp = self._beat('winhost', {'token': 'tok-Windows', 'sysinfo': {}})
                # the real agent takes the pushed set the way its heartbeat loop does
                orig = win._post_json
                try:
                    win._post_json = lambda *a, **k: dict(resp, ok=True)
                    try:
                        win.heartbeat_once({'server_url': 'http://x', 'device_id': 'winhost', 'token': 'tok-Windows'}, 2)
                    except Exception:
                        pass
                finally:
                    win._post_json = orig
                self.assertEqual([c['id'] for c in win._watched_agent_checks], ['ck_reg', 'ck_file'])
                # ...evaluates them in its sysinfo, with the registry it finds...
                with mock.patch.dict(sys.modules, {'winreg': FakeWinreg(state)}):
                    payload = win.build_heartbeat({'device_id': 'winhost', 'token': 'tok-Windows'}, 1)
                results = payload['sysinfo']['custom_check_results']
                self.assertEqual(results['ck_reg']['status'], want, results)
                # ...and the real handler stores it and the Checks engine reads it.
                st, _resp = self._beat('winhost', {'token': 'tok-Windows', 'sysinfo': {'custom_check_results': results, 'os': 'Windows 11 Pro'}})
                self.assertEqual(st, 200)
                dev = api.load(api.DEVICES_FILE)['winhost']
                stored = dev['sysinfo']['custom_check_results']['ck_reg']
                self.assertEqual(stored['status'], want)
                row = [r for r in checks._custom_checks_for('winhost', dev, api.load(api.CONFIG_FILE)['custom_checks'], set())
                       if r['key'] == 'custom:ck_reg'][0]
                self.assertEqual((row['status'], row['ctype']), (want, 'registry'))
                self.assertIn('LmCompatibilityLevel', row['output'])

    def test_the_check_that_fails_raises_the_usual_custom_check_alert_once_it_has_been_seen_ok_or_twice(self):
        st, resp = self._beat('winhost', {'token': 'tok-Windows', 'sysinfo': {'custom_check_results': {
            'ck_reg': {'status': 'critical', 'output': 'LmCompatibilityLevel = 3, expected at least 5'}}}})
        st, resp = self._beat('winhost', {'token': 'tok-Windows', 'sysinfo': {'custom_check_results': {
            'ck_reg': {'status': 'critical', 'output': 'LmCompatibilityLevel = 3, expected at least 5'}}}})
        alerts = (api.load(api.ALERTS_FILE) or {}).get('alerts', [])
        mine = [a for a in alerts if a.get('event') == 'custom_check_failed' and (a.get('payload') or {}).get('check_id') == 'ck_reg']
        self.assertEqual(len(mine), 1, alerts)
        self.assertEqual(mine[0]['payload']['check_type'], 'registry')


# ── what a person reads ──────────────────────────────────────────────────────
class TestSixLanguages(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = dict_rows()

    def _strings(self):
        out = ['Windows registry value', 'Registry path (under HKLM)', 'Value name', 'Condition', 'Expected value',
               'equals', 'does not equal', 'is at least', 'is at most', 'is set', 'is not set',
               'The agent reads one value under HKLM\\SOFTWARE or HKLM\\SYSTEM on Windows hosts, and never changes it. Write a number as 5 or 0x5. '
               'A text is compared without regard to case. A value that is not set passes “is not set” and “does not equal”, '
               'and fails the other conditions.']
        out += list(checks.REGISTRY_REFUSALS)
        for t in REGISTRY_TEMPLATES:
            out += [t['cat'], t['name'], t['desc']]
        return out

    def test_every_string_the_dialog_and_the_catalog_show_has_all_six_languages(self):
        missing = {s: sorted(set(LANGS) - self.rows.get(s, set())) for s in self._strings()
                   if not set(LANGS) <= self.rows.get(s, set())}
        self.assertEqual(missing, {})

    def test_the_markup_holds_exactly_the_strings_the_dictionary_is_keyed_on(self):
        html = (_ROOT / 'server' / 'html' / 'index.html').read_text(encoding='utf-8')
        for s in ('Windows registry value', 'Registry path (under HKLM)', 'Value name', 'Condition', 'Expected value', 'does not equal',
                  'is at least', 'is at most', 'is set', 'is not set'):
            self.assertIn('>%s<' % s, html, s)
        hint = self._strings()[11]
        self.assertIn('>%s<' % hint, html)

    def test_no_word_the_house_style_drops_is_in_what_was_added(self):
        banned = ('genu' + 'ine', 'verba' + 'tim', 'delib' + 'erate')      # written in two parts so that this file does not hold the words it checks for
        for s in self._strings():
            for w in banned:
                self.assertNotIn(w, s.lower())
        server = (_CGI / 'checks.py').read_text(encoding='utf-8')
        agent = (_ROOT / 'client' / 'remotepower-agent-win.py').read_text(encoding='utf-8')
        regions = (server[server.index('# ── registry value checks'):server.index('# v6.2.3: a shipped catalog')],
                   agent[agent.index('# ── registry value checks'):agent.index('def _eval_one_agent_check_win')])
        self.assertTrue(all(len(r) > 3000 for r in regions), 'the region found is too small to be what was added')
        for region in regions:
            for w in banned:
                self.assertNotIn(w, region.lower())


class TestTheDialog(unittest.TestCase):
    """Source-level wiring only; the rendered module measures what a person sees."""

    @classmethod
    def setUpClass(cls):
        cls.html = (_ROOT / 'server' / 'html' / 'index.html').read_text(encoding='utf-8')
        cls.js = (_ROOT / 'server' / 'html' / 'static' / 'js' / 'app-checks.js').read_text(encoding='utf-8')

    def test_the_type_and_its_fields_are_in_the_dialog(self):
        for needle in ('<option value="registry">', 'id="cc-reg-grp"', 'id="cc-reg-path"', 'id="cc-reg-value"', 'id="cc-reg-op"',
                       'id="cc-reg-expect"', 'id="cc-param-grp"', 'data-change="ccRegOpChanged"'):
            self.assertIn(needle, self.html)
        for op in checks.REGISTRY_OPS:
            self.assertIn('<option value="%s">' % op, self.html)

    def test_the_script_handles_the_fields(self):
        for needle in ('function ccRegOpChanged', "body.type === 'registry'", "'cc-reg-path'", 'cc-reg-expect-grp'):
            self.assertIn(needle, self.js)


if __name__ == '__main__':
    unittest.main()
