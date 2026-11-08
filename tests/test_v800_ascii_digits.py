#!/usr/bin/env python3
"""8.0.0: a text is checked for ASCII digits before it is given to int().

`str.isdigit()` is true for a superscript two and for the digits of other scripts, and `int()` refuses the first of those, so `if s.isdigit() and int(s) < 10` raises ValueError
for the text '²'. The generated tests found it twice in the new Traffic code, and enumerating the code found it at 12 more places that take text from outside: a watch list entry, the
port a container publishes, an SMTP greeting, a cidr, a query value, an object id, a cron field. A page answered 500 where it should have said 400, and one reader of an agent's
report made three views of the fleet answer 500 for everybody.

The population is read from the code: every function in the server and the agents that tests `.isdigit()` on some text and later gives the same text to int() or float() with
no try that catches ValueError. Each is either guarded with `.isascii()` or listed in EXEMPT with the reason its text can only be ASCII.
"""

import ast
import importlib.util
import os
import socket
import sys
import tempfile
import threading
import unittest
import urllib.parse
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-asciidigits-'))
_TESTS = Path(__file__).resolve().parent
ROOT = _TESTS.parent
sys.path.insert(0, str(_TESTS))
sys.path.insert(0, str(ROOT / 'server' / 'cgi-bin'))

import app_catalog  # noqa: E402
import proxmox_client  # noqa: E402
import protocol_probes  # noqa: E402
import snmp_device_handlers  # noqa: E402
import traffic  # noqa: E402
from test_ip_intel import _fresh_api  # noqa: E402
from test_v800_push_mark import _run  # noqa: E402

CHARS = ('²', '²²²', '٤٤٣', '１２')  # a superscript two, three of them, Arabic-Indic digits, full-width digits

# (file, function) -> why the text can only be ASCII there
EXEMPT = {
    ('remotepower-agent.py', 'get_zfs_arc'): 'a number the kernel writes to /proc/spl/kstat/zfs/arcstats',
    ('remotepower-agent.py', 'get_zfs_datasets'): 'a number `zfs list -p` prints',
    ('remotepower-agent.py', '_n'): 'a number `zfs list -p` prints (the helper inside get_zfs_datasets)',
    ('remotepower-agent.py', 'get_smart_status'): 'the attribute number, the first column of the table smartctl prints',
    ('remotepower-agent.py', '_kernel_ver_key'): 'a kernel or package version, which the package tools keep to ASCII',
    ('remotepower-agent.py', 'run_netscan'): 'an octet of an address that nmap or arp-scan printed',
    ('remotepower-agent.py', '_ts_scan_modsec_native'): 'the status of the response line, which the web server writes',
    ('snmp.py', 'poll_interfaces'): 'the last part of an object id, which the SNMP library builds from integers',
    ('snmp.py', 'poll_hr_storage'): 'the last part of an object id, which the SNMP library builds from integers',
    ('snmp.py', 'poll_processors'): 'the last part of an object id, which the SNMP library builds from integers',
    ('snmp_device_handlers.py', 'handle_device_snmp_walk'): 'sorts rows by object ids the SNMP library built from integers',
}


def sites(sources):
    """[(file, function, line, text)] for each `X.isdigit()` whose X is later given to int() or float() in the same function, with no try that catches ValueError around the
    conversion and no `X.isascii()` in the function. `sources` is {file name: source text}."""
    out = []
    for name, src in sources.items():
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        parent = {c: p for p in ast.walk(tree) for c in ast.iter_child_nodes(p)}

        def protected(node):
            cur = node
            while cur in parent:
                par = parent[cur]
                if isinstance(par, ast.Try) and cur in par.body:
                    for h in par.handlers:
                        t = ast.unparse(h.type) if h.type is not None else 'BaseException'
                        if any(x in t for x in ('ValueError', 'Exception', 'BaseException')):
                            return True
                if isinstance(par, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    return False
                cur = par
            return False

        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            calls = [n for n in ast.walk(fn) if isinstance(n, ast.Call)]
            ascii_of = {ast.unparse(c.func.value).replace(' ', '') for c in calls if isinstance(c.func, ast.Attribute) and c.func.attr == 'isascii'}
            for d in calls:
                if not (isinstance(d.func, ast.Attribute) and d.func.attr in ('isdigit', 'isnumeric', 'isdecimal')):
                    continue
                recv = ast.unparse(d.func.value).replace(' ', '')
                conv = [n for n in calls if isinstance(n.func, ast.Name) and n.func.id in ('int', 'float') and n.args and ast.unparse(n.args[0]).replace(' ', '') == recv]
                if conv and not all(protected(c) for c in conv) and recv not in ascii_of:
                    out.append((name, fn.name, d.lineno, recv))
    return out


def tree_sources():
    files = sorted((ROOT / 'server' / 'cgi-bin').glob('*.py')) + sorted((ROOT / 'client').glob('*.py'))
    return {p.name: p.read_text() for p in files}


class TestTheScan(unittest.TestCase):

    def test_it_sees_an_unguarded_site_and_passes_a_guarded_one(self):
        bad = 'def f(s):\n    if s.isdigit() and int(s) < 10:\n        return 1\n'
        good = 'def f(s):\n    if s.isascii() and s.isdigit() and int(s) < 10:\n        return 1\n'
        caught = 'def f(s):\n    try:\n        if s.isdigit() and int(s) < 10:\n            return 1\n    except ValueError:\n        return 0\n'
        elsewhere = 'def f(s, t):\n    if s.isdigit():\n        return int(t)\n'
        self.assertEqual(sites({'x.py': bad}), [('x.py', 'f', 2, 's')])
        self.assertEqual(sites({'x.py': good}), [], 'control: the guard is seen')
        self.assertEqual(sites({'x.py': caught}), [], 'control: a try that catches ValueError is seen')
        self.assertEqual(sites({'x.py': elsewhere}), [], 'control: another text is not this text')

    def test_the_population_is_not_empty_and_holds_the_cases_that_were_found(self):
        src = tree_sources()
        every = sum(s.count('.isdigit()') for s in src.values())
        self.assertGreaterEqual(every, 60, 'control: the sources were read')
        for needle in ('def _smtp_reply', 'def clean_watch', 'def _published_ports'):
            self.assertTrue(any(needle in s for s in src.values()), needle)


class TestTheRule(unittest.TestCase):

    def test_every_site_is_guarded_or_has_a_reason(self):
        found = sites(tree_sources())
        left = sorted(s for s in found if (s[0], s[1]) not in EXEMPT)
        self.assertEqual(left, [], '%d unguarded sites, %d of them listed with a reason; these are not: %s' % (len(found), len(found) - len(left), left))

    def test_an_exemption_names_a_site_that_is_still_there_and_still_unguarded(self):
        found = {(s[0], s[1]) for s in sites(tree_sources())}
        for key in EXEMPT:
            self.assertIn(key, found, '%s is listed as exempt and is guarded or gone: delete the entry' % (key,))


class TestTheFunctionsRefuseWithoutRaising(unittest.TestCase):

    def test_a_port_of_the_watch_list(self):
        for ch in CHARS:
            rows, err = traffic.clean_watch([{'kind': 'port', 'value': ch}])
            self.assertEqual((rows, err), ([], 'entry 1: a port is a number from 1 to 65535'), repr(ch))
        self.assertEqual(traffic.clean_watch([{'kind': 'port', 'value': '443'}])[0][0]['value'], '443', 'control: a real port is kept')

    def test_a_port_a_container_publishes(self):
        for ch in CHARS:
            self.assertEqual(app_catalog._published_ports(['0.0.0.0:%s->80/tcp' % ch]), [], repr(ch))
            found = app_catalog.discover([], [{'name': 'x', 'image': 'jellyfin/jellyfin', 'status': 'Up', 'ports': ['0.0.0.0:%s->8096/tcp' % ch]}], [])
            self.assertIsInstance(found, list, repr(ch))
        self.assertEqual(app_catalog._published_ports(['0.0.0.0:8096->8096/tcp']), [8096], 'control')

    def test_an_smtp_greeting_is_not_smtp(self):
        class Conn:
            def __init__(self, line):
                self.line = line

            def readline(self):
                return self.line

        for ch in CHARS:
            with self.assertRaises(protocol_probes.ProbeError) as raised:
                protocol_probes._smtp_reply(Conn('%s hello' % (ch * 3)[:3]))
            self.assertTrue(str(raised.exception).startswith('not SMTP'), str(raised.exception))
        self.assertEqual(protocol_probes._smtp_reply(Conn('220 hello'))[0], 220, 'control')

    def test_a_server_that_greets_with_such_digits_is_reported_as_not_smtp(self):
        srv = socket.socket()
        srv.bind(('127.0.0.1', 0))
        srv.listen(1)

        def serve():
            conn, _ = srv.accept()
            conn.sendall('²²² hello\r\n'.encode('latin-1'))
            conn.recv(64)
            conn.close()

        threading.Thread(target=serve, daemon=True).start()
        try:
            ok, detail = protocol_probes.run('smtp', '127.0.0.1', srv.getsockname()[1], {}, peer_ok=None, timeout=3)
        finally:
            srv.close()
        self.assertFalse(ok)
        self.assertTrue(detail.startswith('not SMTP'), 'the verdict was right and the detail said "error": %r' % detail)

    def test_a_cidr_a_walk_oid_a_cron_field_and_a_json_path(self):
        api = _fresh_api()
        for ch in CHARS:
            self.assertFalse(proxmox_client._valid_ipv4_cidr('10.0.0.1/%s' % ch), repr(ch))
            self.assertIsNone(snmp_device_handlers._validate_walk_oid('1.3.%s' % ch), repr(ch))
            self.assertIsNone(api._cron_to_ics('%s 3 * * *' % ch, 1_700_000_000), repr(ch))
            self.assertIsNone(api._cron_to_ics('5 %s * * *' % ch, 1_700_000_000), repr(ch))
            self.assertIsNone(api._cron_to_ics('5 3 * * %s' % ch, 1_700_000_000), repr(ch))
            self.assertIsNone(api._cron_to_ics('5 3 %s * *' % ch, 1_700_000_000), repr(ch))
            api._monitor_json_path({'a': [1, 2]}, 'a.%s' % ch)
        self.assertTrue(proxmox_client._valid_ipv4_cidr('10.0.0.1/24'), 'control')
        self.assertEqual(snmp_device_handlers._validate_walk_oid('1.3.6.1'), '1.3.6.1', 'control')

    def test_a_query_value_is_a_400_and_not_a_500(self):
        api = _fresh_api()
        api.verify_token = lambda t: ('admin', 'admin') if t == 'k' else (None, None)
        for ch in CHARS:
            status, body = _run(api, api.handle_proxmox_snapshots_list, None, method='GET',
                                env={'HTTP_AUTHORIZATION': 'Bearer k', 'QUERY_STRING': 'type=qemu&vmid=' + urllib.parse.quote(ch)})
            self.assertEqual(status, 400, '%r: %r' % (ch, body))
            self.assertIn('numeric vmid', body['error'], 'refused by the check of the value and not by a later one: %r' % (body,))

    def test_the_agent_refuses_a_log_length_of_such_digits(self):
        spec = importlib.util.spec_from_file_location('rp_agent_ascii', ROOT / 'client' / 'remotepower-agent.py')
        agent = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(agent)
        for ch in CHARS:
            out = agent._run_container_action('container:docker:logs:abc123:%s' % ch)
            self.assertEqual(out['output'], 'invalid tail size', repr(ch))
        self.assertNotEqual(agent._run_container_action('container:docker:logs:abc123:50')['output'], 'invalid tail size', 'control: 50 is a length')


if __name__ == '__main__':
    unittest.main()
