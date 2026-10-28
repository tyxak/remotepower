#!/usr/bin/env python3
"""v7.4.3, issue #46: an integration that reads Prometheus.

"Many homelab boxes already export metrics in Prometheus format, and some hosts can only be monitored
that way. My OPNsense firewall runs node_exporter (port 9100), which reports its real memory correctly
[...] RemotePower can't read any of it. The custom HTTP probe doesn't bridge the gap: exporters answer in
the Prometheus text format, not JSON, and Prometheus's HTTP API returns results as lists
(data.result[0].value[1]), which the probe's dotted JSON path can't index into."

Two connectors, because one instance has one URL: a PromQL query against a Prometheus server, and a scrape
of an exporter's /metrics page. Each reads named values, which become the instance's metrics, so the
"Alert on a metric" thresholds, the host card ("Integrations on this host") and its trend treat them like
any other connector's numbers.

Four layers, each driven for real: the pure parsers; the two connectors against a fake client; the real
HTTP client against a real HTTP server (only the address guard, which has its own tests, is lifted); and
the server's own handlers, from saving an instance to the alert and the host card.

It also holds the fix for what this item's thresholds depended on: an instance's own fields (a probe's
path, the Prometheus lines) and its metric thresholds were saved and never read back, so a form that was
opened and saved again wiped them.
"""
import json
import random
import string
import sys
import threading
import time
import unittest
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v742_container_recovery import DEV, _Base, api  # noqa: E402

I = api.integrations_mod
IE = I.IntegrationError


# ── fixtures: what the real things say ─────────────────────────────────────────────────────────────────

NODE_EXPORTER = """\
# HELP node_memory_active_bytes Memory information field Active_bytes.
# TYPE node_memory_active_bytes gauge
node_memory_active_bytes 1.840291840e+09
# HELP node_filesystem_avail_bytes Filesystem space available to non-root users in bytes.
# TYPE node_filesystem_avail_bytes gauge
node_filesystem_avail_bytes{device="/dev/ada0p2",fstype="ufs",mountpoint="/"} 4.1234e+10
node_filesystem_avail_bytes{device="tmpfs",fstype="tmpfs",mountpoint="/tmp"} 9.9e+08
# HELP node_load1 1m load average.
# TYPE node_load1 gauge
node_load1 0.42
# TYPE node_network_receive_bytes_total counter
node_network_receive_bytes_total{device="igb0"} 1.2345678901e+11
# TYPE http_request_duration_seconds histogram
http_request_duration_seconds_bucket{le="0.1"} 24054
http_request_duration_seconds_bucket{le="+Inf"} 144320
http_request_duration_seconds_sum 53423
http_request_duration_seconds_count 144320
node_hwmon_temp_celsius{chip="platform_coretemp_0",sensor="temp1"} 54 1700000000000
node_unset_gauge NaN
# EOF
"""


def vector(*values):
    return {"status": "success", "data": {"resultType": "vector", "result": [
        {"metric": {"__name__": "x", "instance": "192.168.0.1:9100"}, "value": [1700000000.781, str(v)]}
        for v in values]}}


SCALAR = {"status": "success", "data": {"resultType": "scalar", "result": [1700000000.781, "3"]}}
EMPTY = {"status": "success", "data": {"resultType": "vector", "result": []}}
MATRIX = {"status": "success", "data": {"resultType": "matrix", "result": [
    {"metric": {}, "values": [[1700000000, "1"], [1700000015, "2"]]}]}}
BAD = {"status": "error", "errorType": "bad_data", "error": "1:5: parse error: unexpected end of input"}


class FakeClient(I.HTTPClient):
    """The client the connectors are written against, with the network taken out. A route is a
    Resp, or a function of (params, headers) that returns one."""

    def __init__(self, routes, base="http://prom.lab:9090"):
        super().__init__(base)
        self.routes = routes
        self.calls = []

    def request(self, method, path, headers=None, params=None, body=None):
        self.calls.append((method, path, dict(params or {}), dict(headers or {})))
        route = self.routes.get(path)
        if route is None:
            return I.Resp(404, "not found")
        return route(params or {}, headers or {}) if callable(route) else route


def json_resp(doc, status=200):
    return I.Resp(status, json.dumps(doc), {"Content-Type": "application/json"})


def by_query(table):
    """A /api/v1/query route that answers each expression with its own document."""
    def route(params, headers):
        doc = table.get(params.get("query"))
        return json_resp(doc if doc is not None else EMPTY)
    return route


# ── the pure parts ─────────────────────────────────────────────────────────────────────────────────────

class TestTheLines(unittest.TestCase):

    def test_blank_lines_and_comments_are_skipped(self):
        got = I.parse_query_lines("\n# the memory\nmem = up\n\n   \n  # another\nload = node_load1\n")
        self.assertEqual(got, [("mem", "up"), ("load", "node_load1")])

    def test_a_query_line_needs_a_name(self):
        for bad in ("up", "up == 1", "up =~ 'a.*'", "= up", "1abc = up"):
            with self.subTest(line=bad):
                with self.assertRaises(IE):
                    I.parse_query_lines(bad)

    def test_an_expression_may_hold_equals_signs_and_quotes(self):
        got = I.parse_query_lines('cpu = 100 - avg(rate(node_cpu_seconds_total{mode="idle", instance="a:9100"}[5m])) * 100')
        self.assertEqual(got[0][0], "cpu")
        self.assertIn('mode="idle"', got[0][1])
        self.assertEqual(I.parse_query_lines("down = count(up == 0) or vector(0)"),
                         [("down", "count(up == 0) or vector(0)")])

    def test_the_error_names_the_line(self):
        with self.assertRaises(IE) as cm:
            I.parse_query_lines("ok = up\n\nbroken line\n")
        self.assertIn("line 3", str(cm.exception))

    def test_a_name_is_used_once(self):
        with self.assertRaises(IE) as cm:
            I.parse_query_lines("a = up\nb = up\na = node_load1")
        self.assertIn("line 3", str(cm.exception))
        self.assertIn("used twice", str(cm.exception))

    def test_at_most_twelve_values_and_five_hundred_characters(self):
        I.parse_query_lines("\n".join(f"v{i} = up" for i in range(12)))
        with self.assertRaises(IE):
            I.parse_query_lines("\n".join(f"v{i} = up" for i in range(13)))
        with self.assertRaises(IE):
            I.parse_query_lines("a = " + "x" * 500)

    def test_control_characters_are_dropped(self):
        got = I.parse_query_lines("a\x00b = up\x07\r")
        self.assertEqual(got, [("ab", "up")])

    def test_a_non_string_is_no_lines(self):
        for junk in (None, 5, [], {"a": 1}):
            self.assertEqual(I.parse_prom_lines(junk if isinstance(junk, str) else None), [])


class TestTheSelector(unittest.TestCase):

    def test_a_bare_name(self):
        self.assertEqual(I.parse_selector("node_load1"), ("node_load1", []))
        self.assertEqual(I.parse_selector("job:requests:rate5m"), ("job:requests:rate5m", []))

    def test_matchers(self):
        got = I.parse_selector('node_filesystem_avail_bytes{mountpoint="/", fstype!="tmpfs"}')
        self.assertEqual(got, ("node_filesystem_avail_bytes", [("mountpoint", "=", "/"), ("fstype", "!=", "tmpfs")]))

    def test_single_quotes_spaces_and_a_trailing_comma(self):
        got = I.parse_selector("m{ a = 'x y' ,b='z', }")
        self.assertEqual(got, ("m", [("a", "=", "x y"), ("b", "=", "z")]))

    def test_escapes(self):
        got = I.parse_selector(r'm{a="say \"hi\"", b="back\\slash", c="line\nbreak"}')
        self.assertEqual(got[1], [("a", "=", 'say "hi"'), ("b", "=", "back\\slash"), ("c", "=", "line\nbreak")])

    def test_a_brace_or_a_comma_inside_a_value_is_part_of_it(self):
        self.assertEqual(I.parse_selector('m{a="x},{y", b="1,2"}')[1], [("a", "=", "x},{y"), ("b", "=", "1,2")])

    def test_regular_expressions_are_refused_with_the_way_out(self):
        for op in ("=~", "!~"):
            with self.subTest(op=op):
                with self.assertRaises(IE) as cm:
                    I.parse_selector(f'm{{a{op}"x.*"}}')
                self.assertIn("query form", str(cm.exception))

    def test_malformed_selectors(self):
        for bad in ('m{a="x"', 'm{a=x}', 'm{a=xbx}', 'm{a="x}', 'm{="x"}', 'm{a>"x"}', 'm{a="x"} == 1', "1m", "a b", "",
                    "m{a=\"x\"}junk", 'm{a "x"}', 'm{a="x"k', "m{a='x\"}"):
            with self.subTest(sel=bad):
                with self.assertRaises(IE):
                    I.parse_selector(bad)

    def test_too_many_matchers(self):
        many = ",".join(f'l{i}="v"' for i in range(17))
        with self.assertRaises(IE):
            I.parse_selector("m{" + many + "}")
        I.parse_selector("m{" + ",".join(f'l{i}="v"' for i in range(16)) + "}")

    def test_scrape_lines_take_the_metric_name_when_none_is_given(self):
        got = I.parse_scrape_lines('node_load1\nroot = node_filesystem_avail_bytes{mountpoint="/"}')
        self.assertEqual(got, [("node_load1", "node_load1", []),
                               ("root", "node_filesystem_avail_bytes", [("mountpoint", "=", "/")])])

    def test_scrape_lines_do_not_repeat_a_name_and_say_which_line(self):
        with self.assertRaises(IE) as cm:
            I.parse_scrape_lines('node_load1\nx = node_load5\nnode_load1')
        self.assertIn("line 3", str(cm.exception))
        with self.assertRaises(IE) as cm:
            I.parse_scrape_lines('ok = node_load1\nbad = m{a=~"x"}')
        self.assertIn("line 2", str(cm.exception))


class TestThePage(unittest.TestCase):

    def samples(self, text):
        return list(I.iter_samples(text))

    def test_a_real_page(self):
        got = {(m, tuple(sorted(l.items()))): v for m, l, v in self.samples(NODE_EXPORTER) if v == v}
        self.assertEqual(got[("node_memory_active_bytes", ())], 1840291840.0)
        self.assertEqual(got[("node_load1", ())], 0.42)
        self.assertEqual(got[("node_filesystem_avail_bytes",
                              (("device", "/dev/ada0p2"), ("fstype", "ufs"), ("mountpoint", "/")))], 4.1234e10)
        self.assertEqual(got[("http_request_duration_seconds_bucket", (("le", "+Inf"),))], 144320.0)
        self.assertEqual(got[("node_hwmon_temp_celsius", (("chip", "platform_coretemp_0"), ("sensor", "temp1")))], 54.0,
                         "a timestamp after the value is not the value")

    def test_comments_help_type_and_eof_are_not_samples(self):
        names = {m for m, _l, _v in self.samples(NODE_EXPORTER)}
        self.assertNotIn("HELP", names)
        self.assertNotIn("TYPE", names)
        self.assertNotIn("EOF", names)

    def test_nan_and_infinity_are_read_as_they_are(self):
        got = {m: v for m, _l, v in self.samples("a NaN\nb +Inf\nc -Inf\nd Inf\n")}
        self.assertTrue(got["a"] != got["a"])
        self.assertEqual((got["b"], got["c"], got["d"]), (float("inf"), float("-inf"), float("inf")))

    def test_lines_that_do_not_read_are_skipped_not_fatal(self):
        text = "good 1\n9bad 2\nnovalue\nbad{ 3\nbad{a=\"x\" 4\nbad{a=\"x\"}\nbad{a=x} 5\ntext notanumber\ngood2 2\n"
        self.assertEqual([m for m, _l, _v in self.samples(text)], ["good", "good2"])

    def test_escapes_in_a_label_value(self):
        text = 'm{a="say \\"hi\\"",b="back\\\\slash",c="x\\ny",d="k}v"} 1\n'
        labels = self.samples(text)[0][1]
        self.assertEqual(labels, {"a": 'say "hi"', "b": "back\\slash", "c": "x\ny", "d": "k}v"})

    def test_a_label_value_is_cut_and_a_flood_of_labels_is_refused(self):
        long = "m{a=\"" + "x" * 5000 + "\"} 1\n"
        self.assertEqual(len(self.samples(long)[0][1]["a"]), I._PROM_MAX_LABEL_VALUE)
        flood = "m{" + ",".join(f'l{i}="v"' for i in range(I._PROM_MAX_LABELS + 1)) + "} 1\nok 2\n"
        self.assertEqual([m for m, _l, _v in self.samples(flood)], ["ok"])

    def test_a_page_is_read_to_a_limit(self):
        saved = I._PROM_MAX_SAMPLES
        I._PROM_MAX_SAMPLES = 3
        try:
            self.assertEqual(len(self.samples("a 1\nb 2\nc 3\nd 4\ne 5\n")), 3)
        finally:
            I._PROM_MAX_SAMPLES = saved

    def test_comments_do_not_count_toward_the_read_limit(self):
        saved = I._PROM_MAX_SAMPLES
        I._PROM_MAX_SAMPLES = 3
        try:
            page = "# HELP a\n# TYPE a gauge\n# HELP b\n# TYPE b gauge\n# EOF\na 1\nb 2\nc 3\n"
            self.assertEqual([m for m, _l, _v in self.samples(page)], ["a", "b", "c"])
        finally:
            I._PROM_MAX_SAMPLES = saved

    def test_a_value_that_never_closes_ends_the_line(self):
        self.assertEqual(self.samples('m{a="abc'), [])
        self.assertEqual(self.samples('m{a="abc"'), [])

    def test_html_and_empty_pages_have_no_samples(self):
        self.assertEqual(self.samples("<html><body>Login</body></html>"), [])
        self.assertEqual(self.samples(""), [])
        self.assertEqual(self.samples(None), [])


class TestThePrometheusAnswer(unittest.TestCase):

    def test_the_first_sample_of_a_vector(self):
        self.assertEqual(I.prom_query_value(vector(1840291840, 5)), (1840291840, None, 2))
        self.assertEqual(I.prom_query_value(vector("0.37")), (0.37, None, 1))

    def test_a_scalar(self):
        self.assertEqual(I.prom_query_value(SCALAR), (3, None, 1))

    def test_nothing_returned(self):
        value, why, series = I.prom_query_value(EMPTY)
        self.assertIsNone(value)
        self.assertIn("no data", why)
        self.assertEqual(series, 0)

    def test_a_range_says_how_to_make_it_a_value(self):
        value, why, _n = I.prom_query_value(MATRIX)
        self.assertIsNone(value)
        self.assertIn("avg_over_time", why)

    def test_a_value_that_is_not_a_finite_number(self):
        for text in ("NaN", "+Inf", "-Inf", "abc", ""):
            with self.subTest(v=text):
                value, why, _n = I.prom_query_value(vector(text))
                self.assertIsNone(value)
                self.assertTrue(why)

    def test_answers_that_are_not_what_prometheus_sends(self):
        for doc in ({}, {"data": 5}, {"data": {}}, {"data": {"resultType": "string", "result": [1, "x"]}},
                    {"data": {"resultType": "vector", "result": [5]}},
                    {"data": {"resultType": "vector", "result": [{"value": "nope"}]}},
                    {"data": {"resultType": "vector", "result": [{"value": [1]}]}}, [], None):
            with self.subTest(doc=doc):
                value, why, _n = I.prom_query_value(doc)
                self.assertIsNone(value)
                self.assertTrue(why)

    def test_a_whole_number_is_an_int_and_a_fraction_is_not(self):
        self.assertIsInstance(I.prom_query_value(vector("6200000000"))[0], int)
        self.assertIsInstance(I.prom_query_value(vector("0.5"))[0], float)


class TestHostileInput(unittest.TestCase):
    """The page is text a remote host chose and the lines are text an operator typed. Whatever the parsers
    are given, the only thing that may come out of them is a refusal, and none of it may be slow."""

    ALPHABET = string.ascii_letters + string.digits + ' \t{}()="\'\\,#=!~:_.-+\n\x00\x07\u00e9\u20ac'

    def test_random_text_raises_nothing_but_a_refusal(self):
        rng = random.Random(743)
        for _ in range(3000):
            s = "".join(rng.choice(self.ALPHABET) for _ in range(rng.randint(0, 120)))
            for fn in (I.parse_selector, I.parse_prom_lines, I.parse_query_lines, I.parse_scrape_lines):
                try:
                    fn(s)
                except IE:
                    pass
            list(I.iter_samples(s))
            kind = rng.choice(["vector", "scalar", "matrix", s])
            I.prom_query_value({"data": {"resultType": kind, "result": rng.choice([[], [1, s], [{"value": [1, s]}], s, None])}})

    def test_shapes_built_to_be_slow_are_not(self):
        started = time.monotonic()
        list(I.iter_samples(('m{a="' + '\\"' * 50000 + '"} 1\n') * 5))
        with self.assertRaises(IE):
            I.parse_selector("m" + "{" * 50000)
        self.assertEqual(len(list(I.iter_samples('a_metric{label="value",other="x"} 1.5\n' * 20000))), 20000)
        self.assertLess(time.monotonic() - started, 5.0)


class TestTheCredentials(unittest.TestCase):

    def test_basic_bearer_or_nothing(self):
        import base64
        self.assertEqual(I._prom_auth({}), {})
        self.assertEqual(I._prom_auth({"secret": "tok"}), {"Authorization": "Bearer tok"})
        self.assertEqual(I._prom_auth({"username": "bob", "secret": "pw"}),
                         {"Authorization": "Basic " + base64.b64encode(b"bob:pw").decode()})
        self.assertEqual(I._prom_auth({"username": "bob"}), {}, "a user name alone is no credential")


# ── the connectors ─────────────────────────────────────────────────────────────────────────────────────

class TestThePromQLConnector(unittest.TestCase):

    def poll(self, lines, routes, **inst):
        client = FakeClient({"/api/v1/query": routes} if not isinstance(routes, dict) else routes)
        return I.poll_instance(dict(type="prometheus", prom_lines=lines, **inst), client), client

    def test_every_value_is_read_and_each_expression_is_sent_as_it_was_written(self):
        expr = 'node_memory_active_bytes{instance="192.168.0.1:9100"}'
        res, client = self.poll(f"mem = {expr}\nload = node_load1",
                                by_query({expr: vector(1840291840), "node_load1": vector("0.42")}))
        self.assertEqual(res["status"], I.OK)
        self.assertEqual(res["metrics"], {"mem": 1840291840, "load": 0.42})
        self.assertEqual(res["detail"], "2 values read")
        self.assertEqual([c[2] for c in client.calls], [{"query": expr}, {"query": "node_load1"}])
        self.assertTrue(all(c[0] == "GET" and c[1] == "/api/v1/query" for c in client.calls))

    def test_credentials_ride_on_every_request(self):
        _res, client = self.poll("a = up\nb = up", by_query({}), username="bob", secret="pw")
        self.assertTrue(all(c[3]["Authorization"].startswith("Basic ") for c in client.calls))
        _res, client = self.poll("a = up", by_query({}), secret="tok")
        self.assertEqual(client.calls[0][3], {"Authorization": "Bearer tok"})
        _res, client = self.poll("a = up", by_query({}))
        self.assertEqual(client.calls[0][3], {})

    def test_a_query_that_returns_nothing_is_a_warning_that_names_it(self):
        res, _c = self.poll("a = up\nb = nothing_here", by_query({"up": vector(1)}))
        self.assertEqual(res["status"], I.WARN)
        self.assertIn("b: no data", res["detail"])
        self.assertEqual(res["metrics"], {"a": 1}, "what was read is still a metric")

    def test_when_nothing_could_be_read_it_is_critical(self):
        res, _c = self.poll("a = nothing\nb = nothing", by_query({}))
        self.assertEqual(res["status"], I.CRIT)
        self.assertEqual(res["metrics"], {})

    def test_prometheus_own_complaint_about_a_query_is_the_detail(self):
        res, _c = self.poll("a = up{", lambda p, h: json_resp(BAD, 400))
        self.assertEqual(res["status"], I.CRIT)
        self.assertIn("parse error", res["detail"])

    def test_one_bad_expression_does_not_hide_the_others(self):
        def route(params, headers):
            return json_resp(BAD, 400) if params["query"] == "bad{" else json_resp(vector(7))
        res, _c = self.poll("good = up\nbad = bad{", route)
        self.assertEqual(res["status"], I.WARN)
        self.assertEqual(res["metrics"], {"good": 7})
        self.assertIn("bad:", res["detail"])

    def test_refused_credentials_are_one_clear_message(self):
        for status in (401, 403):
            with self.subTest(status=status):
                res, _c = self.poll("a = up", lambda p, h: I.Resp(status, "Unauthorized"))
                self.assertEqual(res["status"], I.CRIT)
                self.assertIn("refused the credentials", res["detail"])
                self.assertIn(str(status), res["detail"])

    def test_a_server_that_is_not_prometheus_says_what_it_sent(self):
        res, _c = self.poll("a = up", lambda p, h: I.Resp(200, "<html><body>Welcome</body></html>"))
        self.assertEqual(res["status"], I.CRIT)
        self.assertIn("HTML", res["detail"])

    def test_nan_is_no_value_and_a_range_says_why(self):
        res, _c = self.poll("a = up\nb = rate(x[5m])\nc = up",
                            by_query({"up": vector("NaN"), "rate(x[5m])": MATRIX}))
        self.assertEqual(res["status"], I.CRIT)
        self.assertIn("a: the value is NaN", res["detail"])
        self.assertIn("avg_over_time", res["detail"])

    def test_several_series_are_noted_and_the_first_is_used(self):
        res, _c = self.poll("a = up", by_query({"up": vector(1, 2, 3)}))
        self.assertEqual(res["metrics"], {"a": 1})
        self.assertEqual(res["status"], I.OK)
        self.assertIn("several series answered for a", res["detail"])

    def test_a_slow_server_is_not_asked_all_day(self):
        """Every query has its own timeout; the poll as a whole has a budget."""
        saved = I._PROM_BUDGET_S
        I._PROM_BUDGET_S = -1.0
        try:
            res, client = self.poll("a = up\nb = up\nc = up", by_query({"up": vector(1)}))
        finally:
            I._PROM_BUDGET_S = saved
        self.assertEqual(len(client.calls), 1, "the first is always asked, the rest wait")
        self.assertEqual(res["status"], I.WARN)
        self.assertEqual(res["metrics"], {"a": 1})
        self.assertIn("b: not asked", res["detail"])

    def test_no_lines_is_a_message_not_a_pass(self):
        res, client = self.poll("# nothing yet\n", by_query({}))
        self.assertEqual(res["status"], I.CRIT)
        self.assertIn("nothing to read", res["detail"])
        self.assertEqual(client.calls, [])

    def test_a_line_that_cannot_be_read_names_itself(self):
        res, client = self.poll("fine = up\nwhat is this", by_query({}))
        self.assertEqual(res["status"], I.CRIT)
        self.assertIn("line 2", res["detail"])
        self.assertEqual(client.calls, [], "nothing is sent for a form that is wrong")

    def test_a_scalar_is_a_value(self):
        res, _c = self.poll("n = scalar(up)", by_query({"scalar(up)": SCALAR}))
        self.assertEqual(res["metrics"], {"n": 3})


class TestTheExporterConnector(unittest.TestCase):

    def poll(self, lines, page=NODE_EXPORTER, status=200, path="/metrics", **inst):
        client = FakeClient({path: I.Resp(status, page)}, base="http://10.0.0.1:9100")
        return I.poll_instance(dict(type="prometheus_exporter", prom_lines=lines, **inst), client), client

    def test_values_by_name_and_by_labels(self):
        res, client = self.poll('mem = node_memory_active_bytes\n'
                                'root = node_filesystem_avail_bytes{mountpoint="/"}\n'
                                'tmp = node_filesystem_avail_bytes{mountpoint="/tmp"}\n'
                                'node_load1')
        self.assertEqual(res["status"], I.OK, res)
        self.assertEqual(res["metrics"], {"mem": 1840291840, "root": 41234000000, "tmp": 990000000, "node_load1": 0.42})
        self.assertEqual([c[1] for c in client.calls], ["/metrics"], "one page, however many values")

    def test_not_equal_and_the_first_match_wins(self):
        res, _c = self.poll('fs = node_filesystem_avail_bytes{fstype!="tmpfs"}\n'
                            'any = node_filesystem_avail_bytes')
        self.assertEqual(res["metrics"], {"fs": 41234000000, "any": 41234000000})
        self.assertIn("several series match any", res["detail"])
        self.assertNotIn("fs", res["detail"].split("match")[-1], "one series matched fs")

    def test_a_label_that_is_not_there_matches_the_empty_string(self):
        res, _c = self.poll('a = node_load1{nothing=""}\nb = node_load1{nothing!=""}')
        self.assertEqual(res["metrics"], {"a": 0.42})
        self.assertIn("b: not found", res["detail"])

    def test_a_missing_metric_is_a_warning_that_names_it(self):
        res, _c = self.poll("mem = node_memory_active_bytes\ngone = node_nothing_like_this")
        self.assertEqual(res["status"], I.WARN)
        self.assertEqual(res["metrics"], {"mem": 1840291840})
        self.assertIn("gone: not found on the page", res["detail"])

    def test_a_nan_gauge_is_no_value(self):
        res, _c = self.poll("unset = node_unset_gauge\nok = node_load1")
        self.assertEqual(res["status"], I.WARN)
        self.assertEqual(res["metrics"], {"ok": 0.42})
        self.assertIn("unset: the value is not a number", res["detail"])

    def test_histogram_pieces_and_a_timestamp_line(self):
        res, _c = self.poll('inf = http_request_duration_seconds_bucket{le="+Inf"}\n'
                            't = node_hwmon_temp_celsius{chip="platform_coretemp_0"}')
        self.assertEqual(res["metrics"], {"inf": 144320, "t": 54})

    def test_the_path_and_its_leading_slash(self):
        for given, used in (("", "/metrics"), ("/stats/prom", "/stats/prom"), ("stats/prom", "/stats/prom")):
            with self.subTest(path=given):
                res, client = self.poll("node_load1", path=used, prom_path=given)
                self.assertEqual(res["status"], I.OK, res)
                self.assertEqual(client.calls[0][1], used)

    def test_an_absolute_address_cannot_be_the_path(self):
        client = FakeClient({}, base="http://10.0.0.1:9100")
        res = I.poll_instance(dict(type="prometheus_exporter", prom_lines="node_load1",
                                   prom_path="http://169.254.169.254/latest"), client)
        self.assertEqual(res["status"], I.CRIT, "the client refuses a path that is not under the instance's own address")

    def test_a_page_that_is_not_an_exporter(self):
        res, _c = self.poll("node_load1", page="<html><body>Welcome to nginx</body></html>")
        self.assertEqual(res["status"], I.CRIT)
        self.assertIn("holds no Prometheus samples", res["detail"])

    def test_http_errors_and_refused_credentials(self):
        res, _c = self.poll("node_load1", page="boom", status=500)
        self.assertEqual((res["status"], res["detail"]), (I.CRIT, "HTTP 500 from /metrics"))
        res, _c = self.poll("node_load1", page="no", status=401)
        self.assertIn("refused the credentials", res["detail"])

    def test_a_page_too_big_to_read_is_said_so(self):
        client = FakeClient({"/metrics": I.Resp(200, "x 1\n", truncated=True)}, base="http://10.0.0.1:9100")
        res = I.poll_instance(dict(type="prometheus_exporter", prom_lines="x"), client)
        self.assertEqual(res["status"], I.CRIT)
        self.assertIn("larger than 2 MB", res["detail"])

    def test_credentials(self):
        _res, client = self.poll("node_load1", username="bob", secret="pw")
        self.assertTrue(client.calls[0][3]["Authorization"].startswith("Basic "))

    def test_regular_expressions_and_empty_forms_are_refused_before_anything_is_sent(self):
        res, client = self.poll('x = node_load1{a=~"b"}')
        self.assertEqual(res["status"], I.CRIT)
        self.assertIn("query form", res["detail"])
        res, client = self.poll("")
        self.assertIn("nothing to read", res["detail"])
        self.assertEqual(client.calls, [])


class TestTheCatalog(unittest.TestCase):

    def test_both_are_registered_with_what_the_form_needs(self):
        for typ in ("prometheus", "prometheus_exporter"):
            spec = I.CONNECTORS[typ]
            keys = {f["key"]: f for f in spec["fields"]}
            self.assertEqual(keys["prom_lines"]["kind"], I.TEXTAREA)
            self.assertEqual(keys["secret"]["kind"], I.PASSWORD)
            self.assertTrue(keys["prom_lines"]["placeholder"])
            self.assertEqual(spec["category"], "observability")
        self.assertIn("prom_path", {f["key"] for f in I.CONNECTORS["prometheus_exporter"]["fields"]})

    def test_the_chips_show_every_number_under_the_name_the_operator_chose(self):
        chips = I.format_stats("prometheus_exporter", {"mem_active": 1840291840, "load": 0.42, "ok": True, "s": "x"})
        self.assertEqual(chips, [{"label": "mem_active", "value": "1,840,291,840"}, {"label": "load", "value": "0.42"}])
        self.assertEqual(I.format_stats("prometheus", {}), [])
        self.assertEqual(len(I.format_stats("prometheus", {f"v{i}": i for i in range(30)})), I.PROM_MAX_VALUES)


# ── the real HTTP client, against a real server ────────────────────────────────────────────────────────

class _Server(BaseHTTPRequestHandler):
    seen = []
    pages = {}

    def log_message(self, *a):
        pass

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        self.seen.append({"path": url.path, "query": urllib.parse.parse_qs(url.query),
                          "auth": self.headers.get("Authorization")})
        page = self.pages.get(url.path)
        if page is None:
            self.send_response(404)
            self.end_headers()
            return
        status, ctype, body = page(urllib.parse.parse_qs(url.query)) if callable(page) else page
        raw = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class TestAgainstAServer(unittest.TestCase):
    """The real client builds the address, encodes the query, adds the credentials and reads the answer.
    Only the guard against loopback addresses is lifted, because the server is on loopback."""

    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Server)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        cls._guard = staticmethod(api._url_targets_local_or_meta)
        api._url_targets_local_or_meta = lambda *a, **k: False

    @classmethod
    def tearDownClass(cls):
        api._url_targets_local_or_meta = cls._guard
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def setUp(self):
        _Server.seen = []
        _Server.pages = {}

    def client(self):
        c = api._SSRFIntegrationClient(self.base, verify_tls=True, timeout=5)
        c._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))      # no guard, no proxy
        return c

    def test_a_promql_expression_with_braces_quotes_and_brackets_arrives_intact(self):
        expr = '100 - avg(rate(node_cpu_seconds_total{mode="idle",instance="192.168.0.1:9100"}[5m])) * 100'
        _Server.pages["/api/v1/query"] = lambda q: (200, "application/json", json.dumps(
            vector(23.4) if q.get("query") == [expr] else BAD))
        res = I.poll_instance({"type": "prometheus", "prom_lines": f"cpu = {expr}", "secret": "tok"}, self.client())
        self.assertEqual(res["status"], I.OK, res)
        self.assertEqual(res["metrics"], {"cpu": 23.4})
        self.assertEqual(_Server.seen[0]["query"], {"query": [expr]})
        self.assertEqual(_Server.seen[0]["auth"], "Bearer tok")

    def test_a_scrape_of_a_real_page_and_its_credentials(self):
        _Server.pages["/metrics"] = (200, "text/plain; version=0.0.4; charset=utf-8", NODE_EXPORTER)
        res = I.poll_instance({"type": "prometheus_exporter", "username": "u", "secret": "p",
                               "prom_lines": 'mem = node_memory_active_bytes\nroot = node_filesystem_avail_bytes{mountpoint="/"}'},
                              self.client())
        self.assertEqual(res["status"], I.OK, res)
        self.assertEqual(res["metrics"], {"mem": 1840291840, "root": 41234000000})
        self.assertTrue(_Server.seen[0]["auth"].startswith("Basic "))

    def test_the_servers_own_error_status_still_reaches_the_connector(self):
        _Server.pages["/api/v1/query"] = (400, "application/json", json.dumps(BAD))
        res = I.poll_instance({"type": "prometheus", "prom_lines": "a = up{"}, self.client())
        self.assertIn("parse error", res["detail"])
        _Server.pages["/metrics"] = (401, "text/plain", "no")
        res = I.poll_instance({"type": "prometheus_exporter", "prom_lines": "x"}, self.client())
        self.assertIn("refused the credentials", res["detail"])

    def test_a_page_over_the_cap_is_not_parsed_from_half_of_it(self):
        body = "x 1\n" + "# pad\n" * (I.MAX_RESPONSE_BYTES // 6 + 100)
        _Server.pages["/metrics"] = (200, "text/plain", body)
        res = I.poll_instance({"type": "prometheus_exporter", "prom_lines": "x"}, self.client())
        self.assertEqual(res["status"], I.CRIT)
        self.assertIn("larger than 2 MB", res["detail"])

    def test_an_address_the_guard_refuses_is_refused(self):
        api._url_targets_local_or_meta = self._guard
        try:
            res = I.poll_instance({"type": "prometheus_exporter", "prom_lines": "x"},
                                  api._SSRFIntegrationClient(self.base, verify_tls=True, timeout=5))
        finally:
            api._url_targets_local_or_meta = lambda *a, **k: False
        self.assertEqual(res["status"], I.CRIT)
        self.assertIn("blocked address", res["detail"])
        self.assertEqual(_Server.seen, [], "nothing was sent to a loopback address")


# ── the server's handlers ──────────────────────────────────────────────────────────────────────────────

def _call(handler, body=None, *path, role="admin", verb="POST"):
    names = ("verify_token", "get_token_from_request", "method", "get_json_body", "get_json_obj", "audit_log",
             "respond", "require_admin_auth", "require_instance_admin_auth", "require_auth")
    saved = {n: getattr(api, n) for n in names}
    box = {}
    api.require_admin_auth = lambda: "alice"
    api.require_instance_admin_auth = lambda *a, **k: "alice"
    api.verify_token = lambda t: ("alice", role)
    api.get_token_from_request = lambda: "t"
    api.method = lambda: verb
    api.get_json_body = lambda: json.loads(json.dumps(body))
    api.get_json_obj = api.get_json_body
    api.audit_log = lambda *a, **k: None

    def _resp(status, data=None):
        box["status"], box["body"] = status, data
        raise api.HTTPError(status, data)
    api.respond = _resp
    try:
        try:
            handler(*path)
        except api.HTTPError:
            pass
    finally:
        for n, v in saved.items():
            setattr(api, n, v)
    api._LOAD_CACHE.clear()
    return box


EXPORTER = {"type": "prometheus_exporter", "label": "node_exporter OPNsense", "url": "http://192.168.0.1:9100",
            "enabled": True, "prom_path": "", "prom_lines": "mem_active = node_memory_active_bytes\nnode_load1"}


class _Integ(_Base):

    def setUp(self):
        super().setUp()
        api.save(api.INTEG_STATE_FILE, {})
        self._client = api._integration_client
        self.fired = []
        self._fire = api.fire_webhook
        api.fire_webhook = lambda ev, p=None, **k: self.fired.append((ev, dict(p or {})))
        api._LOAD_CACHE.clear()

    def tearDown(self):
        api._integration_client = self._client
        api.fire_webhook = self._fire
        super().tearDown()

    def save(self, *insts, **kw):
        return _call(api.handle_integrations_save, {"integrations": list(insts)}, **kw)

    def listing(self, role="admin"):
        return _call(api.handle_integrations_list, None, role=role, verb="GET")["body"]["integrations"]


class TestSavingAnInstance(_Integ):

    def test_the_lines_and_the_path_are_kept(self):
        box = self.save(dict(EXPORTER, prom_path="/stats/prom"))
        self.assertEqual(box["status"], 200, box)
        inst = api._get_integrations()[0]
        self.assertEqual(inst["prom_lines"], EXPORTER["prom_lines"])
        self.assertEqual(inst["prom_path"], "/stats/prom")

    def test_a_line_that_cannot_be_read_is_a_400_that_names_it(self):
        box = self.save(dict(EXPORTER, prom_lines="ok = node_load1\nbad = m{a=~\"x\"}"))
        self.assertEqual(box["status"], 400, box)
        self.assertIn("line 2", box["body"]["error"])
        self.assertIn(EXPORTER["label"], box["body"]["error"])
        self.assertEqual(api._get_integrations(), [], "a refused save changes nothing")

    def test_a_query_line_without_a_name_is_refused_too(self):
        box = self.save({"type": "prometheus", "label": "P", "url": "http://prom.lab:9090", "enabled": True,
                         "prom_lines": "up"})
        self.assertEqual(box["status"], 400)

    def test_an_empty_form_is_allowed_to_be_saved(self):
        box = self.save(dict(EXPORTER, prom_lines=""))
        self.assertEqual(box["status"], 200, box)

    def test_control_characters_are_dropped_and_the_size_is_bounded(self):
        body = "a\x00 = node_load1\n" + "\n".join(f"# {i}" for i in range(500))
        box = self.save(dict(EXPORTER, prom_lines=body, prom_path="/m\x01etrics"))
        self.assertEqual(box["status"], 200, box)
        inst = api._get_integrations()[0]
        self.assertTrue(inst["prom_lines"].startswith("a = node_load1\n"))
        self.assertEqual(len(inst["prom_lines"].splitlines()), 50)
        self.assertEqual(inst["prom_path"], "/metrics")
        long = self.save(dict(EXPORTER, prom_lines="\n".join("# " + "x" * 400 for _ in range(50))))
        self.assertEqual(long["status"], 200)
        self.assertEqual(len(api._get_integrations()[0]["prom_lines"]), 6000)

    def test_another_type_keeps_none_of_it(self):
        self.save({"type": "pihole", "label": "P", "url": "http://192.168.0.2", "enabled": True,
                   "prom_lines": "a = up", "prom_path": "/x"})
        inst = api._get_integrations()[0]
        self.assertNotIn("prom_lines", inst)
        self.assertNotIn("prom_path", inst)

    def test_an_address_the_server_may_not_call_is_still_refused(self):
        box = self.save(dict(EXPORTER, url="http://127.0.0.1:9100"))
        self.assertEqual(box["status"], 400)
        box = self.save(dict(EXPORTER, url="http://169.254.169.254/"))
        self.assertEqual(box["status"], 400)


class TestWhatTheFormGetsBack(_Integ):
    """The fix this item stands on. The instance list is a read whitelist (INTEGRATION_FIELDS), and a
    probe's path, a connector's own fields and the metric thresholds were not on it, so the form came
    back empty and the next save from it wiped them."""

    THRESHOLDS = [{"metric": "mem_active", "op": "gt", "value": 2000000000, "severity": "high"}]

    def configure(self):
        self.save(dict(EXPORTER, metric_thresholds=self.THRESHOLDS, prom_path="/stats/prom"),
                  {"type": "custom_probe", "label": "probe", "url": "http://192.168.0.5:8080", "enabled": True,
                   "probe_path": "/health", "probe_expect": "204", "probe_json_field": "data.ok",
                   "probe_json_op": "eq", "probe_json_value": "yes",
                   "metric_thresholds": [{"metric": "http_status", "op": "gt", "value": 300}]})

    def test_the_fields_and_the_thresholds_come_back_for_an_administrator(self):
        self.configure()
        by_type = {i["type"]: i for i in self.listing()}
        prom = by_type["prometheus_exporter"]
        self.assertEqual(prom["prom_lines"], EXPORTER["prom_lines"])
        self.assertEqual(prom["prom_path"], "/stats/prom")
        self.assertEqual(prom["metric_thresholds"], self.THRESHOLDS)
        probe = by_type["custom_probe"]
        self.assertEqual({k: probe[k] for k in ("probe_path", "probe_expect", "probe_json_field", "probe_json_op",
                                                "probe_json_value")},
                         {"probe_path": "/health", "probe_expect": "204", "probe_json_field": "data.ok",
                          "probe_json_op": "eq", "probe_json_value": "yes"})
        self.assertEqual(probe["metric_thresholds"][0]["metric"], "http_status")

    def test_saving_what_the_form_was_given_changes_nothing(self):
        """The round trip the browser makes: read the list, save the list."""
        self.configure()
        before = api._get_integrations()
        listed = self.listing()
        self.assertEqual(self.save(*listed)["status"], 200)
        after = api._get_integrations()
        for b, a in zip(sorted(before, key=lambda i: i["type"]), sorted(after, key=lambda i: i["type"])):
            for key in ("prom_lines", "prom_path", "probe_path", "probe_expect", "probe_json_field",
                        "metric_thresholds"):
                self.assertEqual(a.get(key), b.get(key), f"{b['type']}.{key}")

    def test_a_reader_who_cannot_edit_does_not_get_them(self):
        self.configure()
        for inst in self.listing(role="viewer"):
            for key in ("prom_lines", "prom_path", "probe_path", "probe_json_field", "metric_thresholds", "url"):
                self.assertNotIn(key, inst, f"{inst['type']}.{key} reached a viewer")

    def test_a_secret_never_comes_back_whatever_kind_the_field_has(self):
        self.save(dict(EXPORTER, secret="hunter2", username="bob"))
        for role in ("admin", "viewer"):
            text = json.dumps(self.listing(role=role))
            self.assertNotIn("hunter2", text)
        inst = self.listing()[0]
        self.assertTrue(inst["secret_set"])
        self.assertNotIn("secret", inst)
        self.assertEqual(inst["username"], "bob")

    def test_a_password_field_under_any_name_stays_in_the_server(self):
        """A connector from connectors.d/ may call its credential something other than `secret`."""
        I.CONNECTORS["_pw_test"] = {"type": "_pw_test", "label": "t", "category": "custom", "notes": "",
                                    "fields": [I._field("api_token", "Token", I.PASSWORD),
                                               I._field("note", "Note", I.TEXT)],
                                    "health": lambda inst, c: {}}
        try:
            got = api._redact_integration({"id": "i", "type": "_pw_test", "label": "t", "url": "http://192.168.0.9",
                                           "api_token": "hunter2", "note": "visible"}, admin=True)
        finally:
            del I.CONNECTORS["_pw_test"]
        self.assertNotIn("hunter2", json.dumps(got))
        self.assertEqual(got["note"], "visible")

    def test_every_field_a_connector_declares_comes_back(self):
        """The class, not the cases: a declared field that is not a secret and is not returned is a field
        that is saved and never read back."""
        missing = []
        for typ, spec in I.CONNECTORS.items():
            inst = {"id": "i", "type": typ, "label": "x", "url": "http://192.168.0.9"}
            for f in spec["fields"]:
                inst[f["key"]] = "v"
            got = api._redact_integration(inst, admin=True)
            for f in spec["fields"]:
                if f["kind"] != I.PASSWORD and f["key"] not in got:
                    missing.append(f"{typ}.{f['key']}")
        self.assertEqual(missing, [])
        self.assertGreater(len(I.CONNECTORS), 40, "the population is the whole registry")


class TestTheTestButton(_Integ):

    def test_it_polls_the_lines_it_was_given_and_answers_with_the_values(self):
        page = I.Resp(200, NODE_EXPORTER)
        api._integration_client = lambda inst: FakeClient({"/metrics": page}, base=inst["url"])
        box = _call(api.handle_integration_test, dict(EXPORTER, prom_lines="mem = node_memory_active_bytes\x00"))
        self.assertEqual(box["status"], 200, box)
        self.assertTrue(box["body"]["ok"])
        self.assertEqual(box["body"]["metrics"], {"mem": 1840291840})

    def test_the_path_is_cleaned_like_a_saved_one(self):
        api._integration_client = lambda inst: FakeClient({"/metrics": I.Resp(200, NODE_EXPORTER)}, base=inst["url"])
        box = _call(api.handle_integration_test, dict(EXPORTER, prom_path="/m\x01etrics"))
        self.assertTrue(box["body"]["ok"], box)

    def test_a_bad_line_is_an_answer_not_a_crash(self):
        api._integration_client = lambda inst: FakeClient({}, base=inst["url"])
        box = _call(api.handle_integration_test, dict(EXPORTER, prom_lines="x = m{a=~'b'}"))
        self.assertEqual(box["status"], 200, box)
        self.assertFalse(box["body"]["ok"])
        self.assertIn("query form", box["body"]["detail"])


class TestFromThePollToTheHostCard(_Integ):
    """The whole way: an instance bound to a host is polled, the values are metrics, a threshold on one
    raises the alert every other connector's thresholds raise, and the host's own card shows the values
    and their trend."""

    def setUp(self):
        super().setUp()
        self.pages = {"/metrics": I.Resp(200, NODE_EXPORTER)}
        api._integration_client = lambda inst: FakeClient(self.pages, base=inst["url"])
        thresholds = [{"metric": "mem_active", "op": "gt", "value": 1900000000, "severity": "high"}]
        self.save(dict(EXPORTER, id="opn", device_id=DEV, metric_thresholds=thresholds))

    def poll(self):
        api._LOAD_CACHE.clear()
        inst = api._get_integrations()[0]
        res = api._poll_one_integration(inst)
        self.fired.clear()
        api._persist_integration_results([res])
        return res

    def page(self, memory):
        self.pages["/metrics"] = I.Resp(200, NODE_EXPORTER.replace("1.840291840e+09", memory))

    def test_the_poll_reads_the_values(self):
        res = self.poll()
        self.assertEqual(res["status"], I.OK, res)
        self.assertEqual(res["metrics"], {"mem_active": 1840291840, "node_load1": 0.42})

    def test_a_threshold_on_a_value_alerts_once_and_recovers(self):
        self.poll()
        self.assertEqual([e for e, _p in self.fired], [], "1.84e9 is under the line of 1.9e9")
        self.page("2.100000000e+09")
        self.poll()
        self.assertEqual([(e, p.get("metric")) for e, p in self.fired], [("integration_metric_alert", "mem_active")])
        self.assertEqual(self.fired[0][1].get("device_id"), DEV, "bound, so the alert routes through the host")
        self.poll()
        self.assertEqual(self.fired, [], "once, not on every poll")
        self.page("1.000000000e+09")
        self.poll()
        self.assertEqual([e for e, _p in self.fired], ["integration_metric_recovered"])

    def test_the_host_card_has_the_values_and_a_trend(self):
        for memory in ("1.000000000e+09", "1.200000000e+09", "1.500000000e+09"):
            self.page(memory)
            self.poll()
        box = _call(api.handle_device_integrations, None, DEV, verb="GET")
        self.assertEqual(box["status"], 200, box)
        row = box["body"]["integrations"][0]
        self.assertEqual(row["type"], "prometheus_exporter")
        self.assertEqual(row["type_label"], "Prometheus exporter (/metrics scrape)")
        self.assertEqual(row["metrics"]["mem_active"], 1500000000)
        self.assertEqual([p["val"] for p in row["series"]["mem_active"]], [1000000000, 1200000000, 1500000000])
        self.assertEqual({c["label"] for c in row["stats"]}, {"mem_active", "node_load1"})
        self.assertNotIn("192.168.0.1", json.dumps(row), "the address of an instance is not part of the card")

    def test_an_unbound_instance_keeps_no_trend(self):
        self.save(dict(EXPORTER, id="opn", device_id=""))
        for memory in ("1.000000000e+09", "1.200000000e+09"):
            self.page(memory)
            self.poll()
        state = api.load(api.INTEG_STATE_FILE)
        self.assertTrue(all("m" not in e for e in state["history"]["opn"]))


class TestTheUnreachableCases(_Integ):

    def test_an_unreachable_server_is_critical_with_the_reason_and_pages_like_any_other(self):
        def boom(inst):
            raise I.IntegrationError("the connection was refused")
        class Down(FakeClient):
            def request(self, *a, **k):
                raise I.IntegrationError("the connection was refused")
        self.save(dict(EXPORTER, id="opn"))
        api._integration_client = lambda inst: Down({}, base=inst["url"])
        res = api._poll_one_integration(api._get_integrations()[0])
        self.assertEqual(res["status"], I.CRIT)
        self.assertEqual(res["detail"], "the connection was refused")
        api._persist_integration_results([res])
        self.assertEqual([e for e, _p in self.fired], ["integration_down"])


if __name__ == "__main__":
    unittest.main()
