#!/usr/bin/env python3
"""7.4.9 agent security pass: a web request must not be able to freeze the agent.

The log sensor (7.2.0) reads the web server's access and error logs and classifies every request line it finds. The text it
classifies is chosen by whoever sent the request: any client on the internet that can reach the web server. `_TS_RE_SQLI` held
two copies of `(?:\\s|\\+|/\\*.{0,40}?\\*/)+`, a repeat over a choice whose third branch can swallow the next comment as well as
its own. After `union` followed by a run of `/**/`, every extra `/**/` multiplies the work by about twelve: measured on Python
3.14, 24 of them (107 bytes) took 1.3 seconds and 28 (123 bytes) took 17, so a target under 200 bytes keeps the sensor's thread
busy for days. Python's `re` does not let go of the interpreter lock while it matches, so the heartbeat loop stalls for exactly
as long: the host stops reporting and stops taking commands, on the strength of one GET.

The comment branch is now `/\\*(?:(?!\\*/).){0,40}\\*/`: a comment ends at its first `*/`, which is how SQL reads it, so there
is one way to split any run of comments and the match is linear.

The checks run in a child process with a hard time limit. A regex that has gone wrong cannot be interrupted from inside the
interpreter that is running it, and a test that hung would take the whole gate with it.
"""
import json
import os
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# RP_TEST_AGENT lets the same checks run against another copy of the agent (the one from before the fix, for the fail-demo).
AGENT = Path(os.environ.get('RP_TEST_AGENT') or ROOT / 'client' / 'remotepower-agent.py')

_PRELUDE = textwrap.dedent('''
    import importlib.machinery, importlib.util, json, sys, time
    loader = importlib.machinery.SourceFileLoader("agent_under_test", sys.argv[1])
    spec = importlib.util.spec_from_loader("agent_under_test", loader)
    agent = importlib.util.module_from_spec(spec)
    loader.exec_module(agent)
''')


def run_child(body, timeout, *args):
    """Run `body` in a fresh interpreter that has the agent loaded as `agent`. Returns (stdout, timed_out)."""
    code = _PRELUDE + textwrap.dedent(body)
    try:
        r = subprocess.run([sys.executable, '-I', '-c', code, str(AGENT), *args], capture_output=True, text=True,
                           timeout=timeout)
    except subprocess.TimeoutExpired:
        return '', True
    if r.returncode != 0:
        raise AssertionError('child failed: ' + r.stderr[-800:])
    return r.stdout, False


class TestOneRequestCannotFreezeTheSensor(unittest.TestCase):

    def test_a_run_of_sql_comments_is_classified_at_once(self):
        # 60 comments is 240 bytes. The old pattern needs longer than the age of the machine for this; the new one, microseconds.
        out, timed_out = run_child('''
            uri = "/q?x=union" + "/**/" * 60 + "x"
            t = time.perf_counter()
            kinds = agent._ts_classify("GET", uri, 200)
            print(json.dumps({"seconds": time.perf_counter() - t, "kinds": list(kinds)}))
        ''', timeout=20)
        self.assertFalse(timed_out, "classifying one 240-byte request target did not finish in 20 s: the pattern backtracks "
                                    "exponentially, and the sensor's thread holds the interpreter lock the whole time")
        res = json.loads(out)
        self.assertLess(res['seconds'], 1.0, res)

    def test_the_same_request_in_a_log_line_goes_through_the_whole_reader(self):
        # The real path: an nginx "combined" line -> the line parser the sensor builds -> _ts_scan_access.
        out, timed_out = run_child('''
            uri = "/q?x=union" + "/**/" * 60 + "x"
            line = ('203.0.113.9 - - [05/Oct/2026:12:00:00 +0000] "GET ' + uri + ' HTTP/1.1" 200 5 "-" "curl/8"')
            name, parse = agent._ts_access_parser({"kind": "nginx", "format": agent._TS_NGX_COMBINED, "json": False})
            agg = agent._TsAgg(1790000000)
            t = time.perf_counter()
            n, parsed = agent._ts_scan_access([line], parse, agg, "/var/log/nginx/access.log", 1790000000)
            print(json.dumps({"seconds": time.perf_counter() - t, "lines": n, "parsed": parsed}))
        ''', timeout=20)
        self.assertFalse(timed_out, "one log line froze the log reader")
        res = json.loads(out)
        self.assertEqual((res['lines'], res['parsed']), (1, 1), res)
        self.assertLess(res['seconds'], 1.0, res)

    def test_the_request_is_the_same_whichever_way_it_is_written(self):
        # Percent-encoded, doubled up, and inside the other places a request line is logged: all go through _ts_classify.
        out, timed_out = run_child('''
            enc = "%2f%2a%2a%2f" * 60
            cases = {
                "encoded":  "/q?x=union" + enc + "x",
                "select":   "/q?x=select" + "/**/" * 60 + "x",
                "union_all": "/q?x=union" + "/**/" * 30 + "all" + "/**/" * 60 + "x",
                "spaces":   "/q?x=union" + "+" * 400 + "x",
                "mixed":    "/q?x=union" + "/* */ +" * 60 + "x",
            }
            res = {}
            for name, uri in cases.items():
                t = time.perf_counter()
                agent._ts_classify("GET", uri, 200)
                res[name] = time.perf_counter() - t
            print(json.dumps(res))
        ''', timeout=30)
        self.assertFalse(timed_out, "a variant of the request still backtracks")
        for name, seconds in json.loads(out).items():
            self.assertLess(seconds, 1.0, name)


class TestEveryPatternOfTheSensorIsFastOnHostileText(unittest.TestCase):
    """The class, not the one pattern: every `_TS_RE_*` is run over a battery built from its own words, repeated and
    interleaved, at the longest length `_ts_decode` lets through (2048)."""

    BATTERY = '''
        import random
        names = sorted(n for n in dir(agent) if n.startswith("_TS_RE_"))
        toks = ["union", "select", "/**/", "/*", "*/", "+", " ", "${", "a:", "or", "1", "=", "'", "/", ".", "..", "../", "%",
                "x", "/phpunit/", "/solr/", "dataimport", "/wp-content/plugins/", "/readme.txt", "<", ">", "alert(", ";",
                "wget", "sh", "|", "cmd", ".exe", "base64", "-d", "eval", "(", "into", "outfile", "drop", "@@", "version",
                "admin", "login", ".php", "/cgi-bin/", "sqlmap", "/autodiscover/autodiscover.json?", "@", "a", "0"]
        random.seed(11)
        inputs = [t * (2048 // len(t)) for t in toks]
        for a in toks[:24]:
            for b in toks[:24]:
                inputs.append((a + b) * (2048 // len(a + b)))
        for pre in ("union", "union all", "select", "x union", "' or", "or ", "/solr/", "${a:", "/autodiscover/autodiscover.json?"):
            for t in ("/**/", " ", "+", "/*", "*/", "a:", "/", "a"):
                inputs.append((pre + t * 700)[:2048])
                inputs.append((pre + t * 700 + "x")[:2048])
        for _ in range(150):
            inputs.append("".join(random.choice(toks) for _ in range(random.randint(10, 600)))[:2048])
        worst = {}
        for n in names:
            rx = getattr(agent, n)
            w = 0.0
            for s in inputs:
                t = time.perf_counter()
                rx.search(s)
                w = max(w, time.perf_counter() - t)
            worst[n] = w
        print(json.dumps({"worst": worst, "inputs": len(inputs)}))
    '''

    def test_no_pattern_takes_longer_than_a_quarter_of_a_second_on_any_of_them(self):
        out, timed_out = run_child(self.BATTERY, timeout=120)
        self.assertFalse(timed_out, "a pattern did not finish the battery in 120 s (a backtracking pattern)")
        res = json.loads(out)
        # A control against measuring nothing: the population is the patterns the sensor has, and the battery is not empty.
        self.assertGreaterEqual(len(res['worst']), 8, res['worst'])
        self.assertIn('_TS_RE_SQLI', res['worst'])
        self.assertGreater(res['inputs'], 800)
        for name, seconds in res['worst'].items():
            self.assertLess(seconds, 0.25, f'{name} took {seconds:.2f}s on one request target')


class TestTheFixStillDetectsWhatItDid(unittest.TestCase):
    """A fix that makes the pattern fast by making it blind is no fix: these requests must still be classified as before."""

    def test_sql_injection_written_the_usual_ways_is_still_sqli(self):
        out, timed_out = run_child('''
            uris = [
                "/?id=1 union select 1,2,3",
                "/?id=1+union+select+null",
                "/?id=1+union/**/select/**/1",
                "/?id=1+UnIoN+aLl+SeLeCt+@@version",
                "/?id=1+union/*x*/all/*y*/select/**/user(),2",
                "/?q=select+*+from+users",
                "/?q=select/*!50000*/+*",
                "/?x=1' or '1'='1",
                "/?x=1 or 1=1",
                "/?s=sleep(5)",
                "/?x=1;drop table users",
                "/?x=information_schema.tables",
                "/?x=load_file('/etc/passwd')",
            ]
            print(json.dumps([list(agent._ts_classify("GET", u, 200)) for u in uris]))
        ''', timeout=30)
        self.assertFalse(timed_out)
        kinds = json.loads(out)
        self.assertEqual(len(kinds), 13)
        for i, k in enumerate(kinds):
            self.assertIn('sqli', k, f'case {i}: {k}')

    def test_what_is_not_sql_is_still_left_alone(self):
        out, timed_out = run_child('''
            uris = ["/", "/index.html", "/search?q=union+station", "/blog/how-to-select-a-chair", "/a/b/c.css?v=3",
                    "/?note=a/**/b", "/union/select"]
            print(json.dumps([list(agent._ts_classify("GET", u, 200)) for u in uris]))
        ''', timeout=30)
        self.assertFalse(timed_out)
        for k in json.loads(out):
            self.assertNotIn('sqli', k)


if __name__ == '__main__':
    unittest.main()
