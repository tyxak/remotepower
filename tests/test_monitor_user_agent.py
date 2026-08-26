"""Every monitor probe must send a real User-Agent.

Without one, urllib sends `Python-urllib/3.x`. Cloudflare's Browser Integrity
Check — and most other WAFs — block that with a 403 that never reaches the
origin, so a monitor on any WAF-fronted host reads as permanently down and the
origin's access log has nothing in it to explain why. Reproduced against a live
Cloudflare zone: `Python-urllib/3.12` -> 403, `RemotePower/<ver>` -> 200 for the
same URL, same method.

The probes are listed by name rather than matched by a regex over function
names. A name pattern is read once and then looks like an implementation
detail; a written list gets re-read when someone adds a probe. Both directions
are asserted: the listed functions must exist, and each must build at least one
Request, so a rename cannot empty the population and leave the test green.
"""
import ast
import pathlib
import unittest

_API = pathlib.Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin' / 'api.py'

# Functions that probe an operator-supplied URL over HTTP. Add new ones here.
MONITOR_PROBES = (
    '_run_one_monitor_check',   # single-step http monitor (HEAD, or GET for body match)
    '_run_http_flow',           # multi-step synthetic flow monitor
)


def _funcs(tree):
    out = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.setdefault(node.name, node)
    return out


def _requests_in(fn_node):
    """Every urllib.request.Request(...) constructed inside this function."""
    return [n for n in ast.walk(fn_node)
            if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and n.func.attr == 'Request']


def _sets_user_agent(call, fn_node):
    """True if this Request gets a User-Agent, by kwarg or a later add_header."""
    for kw in call.keywords:
        if kw.arg != 'headers' or not isinstance(kw.value, ast.Dict):
            continue
        for k in kw.value.keys:
            if isinstance(k, ast.Constant) and str(k.value).lower() == 'user-agent':
                return True
    # or an explicit req.add_header('User-Agent', ...) anywhere in the function
    for n in ast.walk(fn_node):
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr == 'add_header' and n.args
                and isinstance(n.args[0], ast.Constant)
                and str(n.args[0].value).lower() == 'user-agent'):
            return True
    return False


class TestMonitorUserAgent(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.src = _API.read_text(encoding='utf-8')
        cls.tree = ast.parse(cls.src)
        cls.funcs = _funcs(cls.tree)

    def test_probe_list_is_not_stale(self):
        """A renamed probe must fail loudly, not silently empty the population."""
        missing = [n for n in MONITOR_PROBES if n not in self.funcs]
        self.assertFalse(
            missing,
            f'MONITOR_PROBES names functions that no longer exist in api.py: '
            f'{missing}. Rename them here or the check below inspects nothing.')

    def test_every_monitor_probe_builds_a_request(self):
        """Control: if a probe stops constructing a Request, this test is blind."""
        for name in MONITOR_PROBES:
            with self.subTest(probe=name):
                calls = _requests_in(self.funcs[name])
                self.assertGreater(
                    len(calls), 0,
                    f'{name}() builds no urllib Request — either it changed shape '
                    f'or MONITOR_PROBES is pointing at the wrong function.')

    def test_every_monitor_probe_sends_a_user_agent(self):
        for name in MONITOR_PROBES:
            fn = self.funcs[name]
            for call in _requests_in(fn):
                with self.subTest(probe=name, line=call.lineno):
                    self.assertTrue(
                        _sets_user_agent(call, fn),
                        f'{name}() at api.py:{call.lineno} builds a Request with no '
                        f'User-Agent. urllib will send "Python-urllib/3.x", which '
                        f'Cloudflare Browser Integrity Check 403s before the origin '
                        f'sees it — the monitor reads as down with an empty access '
                        f'log. Pass headers={{"User-Agent": f"RemotePower/{{SERVER_VERSION}}"}}.')

    def test_user_agent_is_the_canonical_string(self):
        """One UA spelling across the codebase, version included."""
        for name in MONITOR_PROBES:
            fn = self.funcs[name]
            seg = ast.get_source_segment(self.src, fn) or ''
            with self.subTest(probe=name):
                self.assertRegex(
                    seg, r"'User-Agent':\s*f'RemotePower/\{SERVER_VERSION\}'",
                    f'{name}() should use the same UA as every other outbound '
                    f"call in api.py: f'RemotePower/{{SERVER_VERSION}}'.")


if __name__ == '__main__':
    unittest.main()
