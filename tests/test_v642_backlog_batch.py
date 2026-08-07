"""Regression tests for the seven backlog fixes applied in the v6.4.2 sweep.

Each was reproduced before the fix and re-verified after. The fixes were made in
isolated worktrees by parallel agents; these tests are written centrally, on
purpose — an agent that writes both the fix and its test can satisfy itself.
"""

import ast
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
_JS = ROOT / "server" / "html" / "static" / "js"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v642-batch-"))


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _js_function(src, name):
    """Brace-balanced body of `function <name>(...)`."""
    m = re.search(r"\nfunction %s\s*\([^)]*\)\s*\{" % re.escape(name), src)
    if not m:
        raise AssertionError(f"js function not found: {name}")
    i = m.start() + 1
    k = src.index("{", i)
    depth = 0
    while True:
        if src[k] == "{":
            depth += 1
        elif src[k] == "}":
            depth -= 1
            if depth == 0:
                break
        k += 1
    return src[i:k + 1]


# Resolve node's real path via the full PATH. Runners (e.g. GitHub Actions) put
# node in a toolcache dir, NOT /usr/bin — so invoke it by absolute path and keep
# the minimal env only for TZ hygiene. Passing a bare "node" with PATH=/usr/bin:/bin
# made these tests pass locally (node in /usr/bin) but ERROR on CI (node elsewhere).
_NODE_BIN = shutil.which("node")


def _node(script, *argv, tz=None):
    env = {"PATH": "/usr/bin:/bin"}
    if tz:
        env["TZ"] = tz
    p = subprocess.run([_NODE_BIN or "node", "-e", script, *argv], capture_output=True,
                       text=True, env=env, timeout=60)
    if p.returncode:
        raise AssertionError(f"node failed: {p.stderr[-800:]}")
    return p.stdout.strip()


class TestIpv6IsRedactedByThePrivacyToggle(unittest.TestCase):
    """`(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}` can only match the fully
    EXPANDED eight-group form — a `::` run cannot satisfy `[0-9a-fA-F]{1,4}:`.
    So with "Send IP addresses = off" the toggle redacted IPv4 and shipped every
    real-world IPv6 address verbatim to the cloud provider, while reading as ON.
    Worse, a long address could match in two halves (`<IPv6>::<IPv6>`), which
    looks redacted in a spot-check while both halves are still there."""

    def setUp(self):
        self.san = _load("san_v642_batch", _CGI / "sanitize.py")
        self.ai = _load("aip_v642_batch", _CGI / "ai_provider.py")

    def test_compressed_forms_are_redacted(self):
        out = self.ai.redact("gw 2001:db8::1 peer fe80::1 lo ::1 v4 192.0.2.1", {})
        for leaked in ("2001:db8::1", "fe80::1", "::1", "192.0.2.1"):
            self.assertNotIn(leaked, out, f"{leaked} egressed verbatim: {out}")

    def test_mapped_and_bracketed_forms(self):
        for text, leaked in (("mapped ::ffff:192.0.2.1 here", "::ffff:192.0.2.1"),
                             ("peer [2001:db8::1]:443 up", "2001:db8::1")):
            self.assertNotIn(leaked, self.ai.redact(text, {}), text)

    def test_it_does_not_shred_ordinary_text(self):
        """A permissive candidate regex over free text is where collateral
        damage hides: an over-eager matcher mangles the very logs the operator
        is asking the model about."""
        for text in ("backup ran at 12:34:56 for 3s",
                     "ratio 1:2:3 and time 09:00",
                     "mac aa:bb:cc:dd:ee:ff",
                     "std::vector<int> and Foo::bar",
                     r"C:\Users\jak path",
                     "no colons at all here"):
            self.assertEqual(self.san._fold_ipv6(text, "<IPv6>"), text, text)

    def test_trailing_punctuation_survives(self):
        self.assertEqual(self.san._fold_ipv6("reached 2001:db8::1. Then stopped", "<X>"),
                         "reached <X>. Then stopped")

    def test_an_all_hex_identifier_is_redacted_and_that_is_deliberate(self):
        """`a::b` is character-for-character a legal IPv6 address AND a
        plausible C++/Rust path; nothing can tell them apart. Over-redacting
        costs readability, under-redacting ships operator addresses to a third
        party — so the tie breaks toward redaction, and the comment in
        sanitize.py must keep saying so rather than claiming immunity."""
        self.assertEqual(self.san._fold_ipv6("a::b", "<X>"), "<X>")
        note = (_CGI / "sanitize.py").read_text()
        self.assertIn("is character-for-character a legal IPv6 address", note)

    def test_both_copies_route_through_the_fold(self):
        """Assert the FOLD is wired in, not that the old pattern is gone. Both
        modules keep it on purpose and say why: in ai_provider it is a harmless
        belt-and-braces pass after the fold, and in logsig it also folds MAC /
        EUI-64 colon runs that `ipaddress` rejects and that have always folded
        to `<ip>` there. Deleting it would silently change log-signature
        grouping. (My first version of this test asserted removal — read the
        reasoning before overriding it.)"""
        for mod in ("ai_provider.py", "logsig.py"):
            src = (_CGI / mod).read_text()
            self.assertIn("_fold_ipv6", src,
                          f"{mod} does not route IPv6 through the compressed-form fold")


class TestFleetReportCsvToleratesMissingSections(unittest.TestCase):
    """`_fleet_report_csv_bytes` indexed `report['devices']` etc. directly, so
    any `?sections=` subset that dropped a block raised KeyError out of the
    handler — a 500 on the exact URL the Custom reports Download button builds.
    Its sibling `_render_report_email` has tolerated subsets since v3.14.0."""

    def setUp(self):
        self.api = _load("api_v642_batch_csv", _CGI / "api.py")

    def _report(self, sections):
        full = {
            'devices': {'total': 3, 'online': 2, 'offline': 1},
            'health': {'score': 88, 'grade': 'B'},
            'attention': {'critical': 1, 'warning': 2, 'info': 0},
            'sla': {'target': 99.9, 'actual': 99.95},
            'patches': {'devices_with_patches': 2, 'total_pending': 17},
            'cve': {'critical': 1, 'high': 2, 'medium': 3, 'low': 4,
                    'devices_affected': 2},
            'compliance': {'frameworks': {'cis': {'pass': 10, 'fail': 2}}},
        }
        return {k: v for k, v in full.items() if k in sections}

    def test_every_subset_renders(self):
        keys = ['devices', 'health', 'attention', 'sla', 'patches', 'cve', 'compliance']
        # each single section alone, each "all but one", and the full set
        subsets = [[k] for k in keys] + \
                  [[x for x in keys if x != k] for k in keys] + [keys, []]
        for sub in subsets:
            with self.subTest(sections=sub):
                out = self.api._fleet_report_csv_bytes(self._report(sub))
                self.assertIsInstance(out, (bytes, bytearray))
                self.assertIn(b'Section,Metric,Value', out)

    def test_the_selected_section_actually_appears(self):
        out = self.api._fleet_report_csv_bytes(self._report(['cve']))
        self.assertIn(b'CVE', out)
        self.assertNotIn(b'Devices,Total', out)


class TestIpAllowlistNeverBlocksAnAgent(unittest.TestCase):
    """The Settings hint promises the allowlist "never blocks an agent". It
    403'd the self-update signature fetch, the live-sample push and file-archive
    chunk upload — so an out-of-range agent could download an update binary and
    not verify it, and the UI text was a promise the code did not keep."""

    def setUp(self):
        self.api = _load("api_v642_batch_allow", _CGI / "api.py")

    def test_every_agent_path_is_exempt(self):
        """Exact-match list for fixed paths, suffix list for the two that live
        under /api/devices/<id>/ (so neither a prefix nor an exact match can
        cover them)."""
        src = (_CGI / "api.py").read_text()
        for path in ('/api/agent/signature', '/api/agent/win/signature',
                     '/api/agent/mac/signature', '/api/agent/download'):
            self.assertIn(f"'{path}'", src,
                          f"{path} is not exempt — the Settings hint lies")
        tree = ast.parse(src)
        suffixes = next(
            (ast.unparse(n.value) for n in ast.walk(tree)
             if isinstance(n, ast.Assign) and len(n.targets) == 1
             and getattr(n.targets[0], 'id', '') == '_IP_ALLOWLIST_EXEMPT_DEVICE_SUFFIXES'),
            None)
        self.assertIsNotNone(suffixes, 'the device-scoped exemption list is gone')
        for suffix in ('/live-sample', '/files/archive-chunk'):
            self.assertIn(suffix, suffixes)

    def test_the_hint_and_the_code_agree(self):
        """If the exemption is ever narrowed, the promise must be narrowed in
        the same commit — the 'UI text that lies' class."""
        html = (ROOT / "server" / "html" / "index.html").read_text()
        if 'never blocks an agent' not in html:
            self.skipTest('hint reworded — re-point this assertion')
        self.assertIn('_IP_ALLOWLIST_EXEMPT_DEVICE_SUFFIXES', (_CGI / "api.py").read_text())


class TestFailedTlsProbeIsNotAnExpiredCert(unittest.TestCase):
    """`days_until_expiry` returned 0 for "we have no expiry" — the same value
    that means "expires today". A transient DNS or connect failure therefore
    scored as an EXPIRED certificate and fired a CRITICAL tls_expiry webhook
    plus a "Certificate EXPIRED" Needs-Attention item."""

    def setUp(self):
        self.tls = _load("tlsmon_v642_batch", _CGI / "tls_monitor.py")

    def test_unknown_is_none_not_zero(self):
        self.assertIsNone(self.tls.days_until_expiry({}))
        self.assertIsNone(self.tls.days_until_expiry(
            {'tls_error': 'connection refused', 'expires_at': 0}))

    def test_real_expiries_still_compute(self):
        import time
        now = int(time.time())
        self.assertEqual(self.tls.days_until_expiry({'expires_at': now + 5 * 86400}), 5)
        self.assertEqual(self.tls.days_until_expiry({'expires_at': now - 2 * 86400}), -2)

    def test_zero_still_means_expires_today(self):
        """The fix must not make a genuinely-today expiry unreportable."""
        import time
        self.assertEqual(self.tls.days_until_expiry({'expires_at': int(time.time()) + 60}), 0)


class TestProxmoxSnapshotNamesMatchPve(unittest.TestCase):
    """`^[A-Za-z][A-Za-z0-9_]{0,39}$` forbids hyphens, but PVE's own rule is
    `pve-configid` (`^[a-z][a-z0-9_-]+$/i`). `list_snapshots` deliberately does
    NOT filter, so the UI drew Rollback and Delete on rows the handlers then
    refused — worst at the moment rollback matters most."""

    def setUp(self):
        self.px = _load("px_v642_batch", _CGI / "proxmox_client.py")

    def test_pve_legal_names_are_accepted(self):
        for name in ('pre-upgrade', 'before_upgrade', 'Snap1', 'has-dash', 'a-b-c'):
            self.assertTrue(self.px._valid_snapshot_name(name), name)

    def test_genuinely_invalid_names_still_rejected(self):
        for name in ('123bad', 'has space', '', 'x' * 41, '-lead', 'has/slash',
                     'has.dot', 'has:colon'):
            self.assertFalse(self.px._valid_snapshot_name(name), name)

    def test_the_length_rule_is_deliberately_unchanged(self):
        """The reported defect was the missing hyphen, so only the character
        class moved. PVE's pve-configid also wants >=2 chars, which this still
        accepts at 1 — a mismatch that surfaces as PVE's own error on a request
        the operator typed, not as a silent wrong result, so it is not worth
        widening the diff for."""
        self.assertTrue(self.px._valid_snapshot_name('a'))


class TestTimesheetDatesUseTheLocalCalendar(unittest.TestCase):
    """Time-entry dates defaulted to the UTC calendar day, so hours logged in
    the evening in the Americas — or after local midnight in Europe — landed on
    the wrong day, the wrong ISO week and the wrong invoice month. The CSV
    export then labelled the file with one week and requested another."""

    def setUp(self):
        self.src = (_JS / "app-billing.js").read_text()
        try:
            subprocess.run(["node", "--version"], capture_output=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            self.skipTest("node unavailable")

    def _helpers(self, *names):
        return "\n".join(_js_function(self.src, n) for n in names)

    def test_today_is_the_local_day_in_every_zone(self):
        probe = self._helpers("_localDayStr", "_isoWeekMonday", "_isoWeekString", "_todayStr") + r"""
        const Real = Date, F = Real.parse(process.argv[1]);
        class FakeDate extends Real { constructor(...a){ super(...(a.length?a:[F])); } static now(){ return F; } }
        const real = new Real(F); global.Date = FakeDate;
        console.log(JSON.stringify({local: real.toLocaleDateString('en-CA'), got: _todayStr()}));
        """
        for tz, when in (("Pacific/Auckland", "2026-07-31T01:15:00Z"),
                         ("America/New_York", "2026-08-01T02:30:00Z"),
                         ("Europe/Copenhagen", "2026-07-31T22:30:00Z"),
                         ("America/Los_Angeles", "2026-01-01T05:00:00Z")):
            with self.subTest(tz=tz):
                d = json.loads(_node(probe, when, tz=tz))
                self.assertEqual(d["got"], d["local"],
                                 "the default date is not the operator's calendar day")

    def test_csv_week_label_matches_its_own_bounds(self):
        """The filename said W32 while the from/to bounds fetched W31's rows —
        wrong data under a right-looking name, which is worse than an error."""
        probe = self._helpers("_localDayStr", "_isoWeekMonday", "_isoWeekString") + r"""
        const _tsCursor = new Date(Date.parse(process.argv[1]));
        const wk = _isoWeekString(_tsCursor);
        const base = new Date(_tsCursor);
        const day = base.getDay() || 7;
        const mon = new Date(base.getFullYear(), base.getMonth(), base.getDate() - (day - 1));
        const from = _localDayStr(mon);
        const to = _localDayStr(new Date(mon.getFullYear(), mon.getMonth(), mon.getDate() + 6));
        const [fy, fm, fd] = from.split('-').map(Number);
        console.log(JSON.stringify({wk, from, to,
          boundsWk: _isoWeekString(new Date(fy, fm - 1, fd)),
          endWk: _isoWeekString(new Date(...to.split('-').map((v,i)=> i===1? Number(v)-1 : Number(v))))}));
        """
        cases = [("Pacific/Auckland", "2026-08-03T00:30:00Z"),
                 ("America/New_York", "2026-08-03T02:30:00Z"),
                 ("Europe/Copenhagen", "2026-08-02T22:30:00Z"),
                 # both DST transition weeks — the old ±864e5 stepping broke here
                 ("America/Los_Angeles", "2026-11-02T04:30:00Z"),
                 ("Europe/Copenhagen", "2026-03-29T01:30:00Z")]
        for tz, when in cases:
            with self.subTest(tz=tz, when=when):
                d = json.loads(_node(probe, when, tz=tz))
                self.assertEqual(d["wk"], d["boundsWk"],
                                 f"file named {d['wk']} carries {d['boundsWk']} rows")
                self.assertEqual(d["wk"], d["endWk"],
                                 "the window straddles two ISO weeks")

    def test_the_export_does_not_step_by_milliseconds(self):
        body = _js_function(self.src, "tsExportCsv")
        # Strip // comments first: the explanatory comment says "rather than
        # ±864e5", and matching that made this fail against the FIXED code.
        # Fifth time prose has broken a check in this sweep.
        code = "\n".join(re.sub(r"//.*$", "", l) for l in body.splitlines())
        self.assertNotIn("864e5", code,
                         "stepping a week by fixed milliseconds breaks across a "
                         "DST boundary; step by date components")


class TestEscAttrProducesHtmlNotJsEscapes(unittest.TestCase):
    """`escAttr` emitted `\\x27`-style JS-string escapes into plain HTML
    attributes. A browser hands those back literally, so an apostrophe in a
    time-entry note made `JSON.parse` throw: Edit opened a blank form and Save
    overwrote the entry with empty values — silent data loss on a billing
    record. The 853 call sites are all quoted-attribute contexts; none is a JS
    string, which is what makes emitting HTML entities correct."""

    def setUp(self):
        self.app = (_JS / "app.js").read_text()
        try:
            subprocess.run(["node", "--version"], capture_output=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            self.skipTest("node unavailable")

    def test_it_no_longer_emits_backslash_x(self):
        body = _js_function(self.app, "escAttr")
        self.assertNotIn("\\\\x", body,
                         "escAttr still emits JS-string escapes into HTML attributes")

    def test_round_trip_through_a_parsed_attribute(self):
        from html.parser import HTMLParser

        probe = (_js_function(self.app, "escHtml") + "\n"
                 + _js_function(self.app, "escAttr") + "\n"
                 + "console.log(escAttr(process.argv[1]));")
        payload = json.dumps({"hours": 4, "note": "Rebuilt Bob's mail server",
                              "billable": True})
        attr = _node(probe, payload)

        class _P(HTMLParser):
            got = None
            extra = 0

            def handle_starttag(self, tag, attrs):
                d = dict(attrs)
                if "data-arg2" in d and self.got is None:
                    self.got = d["data-arg2"]
                else:
                    self.extra += 1

        p = _P(convert_charrefs=True)
        p.feed(f'<button data-arg2="{attr}"></button>')
        self.assertIsNotNone(p.got, "attribute did not survive parsing")
        self.assertEqual(json.loads(p.got), json.loads(payload),
                         "the value does not round-trip through the DOM")

    def test_it_still_prevents_attribute_breakout(self):
        """escAttr exists because of an XSS fix; changing its output must not
        weaken that."""
        from html.parser import HTMLParser

        probe = (_js_function(self.app, "escHtml") + "\n"
                 + _js_function(self.app, "escAttr") + "\n"
                 + "console.log(escAttr(process.argv[1]));")
        for hostile in ('" onclick="alert(1)', "' onclick='alert(1)",
                        '"><script>alert(1)</script>', "O'Brien", 'a\\"b',
                        '&quot; onclick=&quot;alert(1)'):
            with self.subTest(payload=hostile):
                attr = _node(probe, hostile)
                for quote in ('"', "'"):
                    class _P(HTMLParser):
                        tags = 0
                        attrs = None

                        def handle_starttag(self, tag, attrs):
                            self.tags += 1
                            if self.attrs is None:
                                self.attrs = dict(attrs)

                    p = _P(convert_charrefs=True)
                    p.feed(f"<button x={quote}{attr}{quote}></button>")
                    self.assertEqual(p.tags, 1, f"breakout with {quote}: {attr}")
                    self.assertEqual(list(p.attrs), ["x"],
                                     f"injected attribute with {quote}: {p.attrs}")
                    self.assertEqual(p.attrs["x"], hostile,
                                     "value did not round-trip exactly")


if __name__ == "__main__":
    unittest.main()


class TestWebhookSignatureBindsTheTimestamp(unittest.TestCase):
    """docs/webhooks.md told receiver authors to "bound the timestamp to reject
    replays" and shipped a verifier whose only defence was an age check on
    `X-RemotePower-Timestamp`. But the signature covered the BODY ALONE, so the
    timestamp header was attacker-mutable: anyone holding one captured delivery
    could replay that exact body forever by rewriting the timestamp to `now`,
    and the documented verifier returned True. Replayed alerts re-trigger
    downstream automation — paging, ticket reopen, remediation hooks.

    V2 binds the timestamp into the MAC (the Stripe/GitHub construction). It is
    sent ALONGSIDE the legacy header, never instead of it, because the legacy
    format is one deployed receivers already parse.
    """

    SECRET = 'shhh'

    def _sign(self, ts, body):
        import hashlib
        import hmac
        return 'v2=' + hmac.new(self.SECRET.encode(), ts.encode() + b'.' + body,
                                hashlib.sha256).hexdigest()

    def test_the_sender_emits_both_headers(self):
        src = (_CGI / "api.py").read_text()
        self.assertIn("X-RemotePower-Signature-V2", src)
        self.assertIn("X-RemotePower-Signature'] = 'sha256=' + _sig", src,
                      "the legacy header must keep being sent — dropping it "
                      "breaks every deployed receiver")

    def test_v2_covers_the_timestamp_and_v1_does_not(self):
        """The property that matters, stated as a difference: rewriting the
        timestamp must invalidate v2 while leaving v1 intact — which is exactly
        why an age check against v1 rejected nothing."""
        import hashlib
        import hmac
        body = b'{"event":"device_offline","device_id":"d1"}'
        ts = '1785500000'
        v1 = 'sha256=' + hmac.new(self.SECRET.encode(), body, hashlib.sha256).hexdigest()
        v2 = self._sign(ts, body)

        replay_ts = '1785599999'          # attacker rewrites the header to "now"
        self.assertEqual(
            v1, 'sha256=' + hmac.new(self.SECRET.encode(), body, hashlib.sha256).hexdigest(),
            "v1 is unchanged by the rewrite — that is the defect")
        self.assertNotEqual(self._sign(replay_ts, body), v2,
                            "v2 must not verify once the timestamp is rewritten")

    def test_the_documented_verifier_matches_the_sender(self):
        """The doc snippet is the thing operators paste; if it disagrees with
        the sender by one byte, every delivery fails verification."""
        doc = (ROOT / "docs" / "webhooks.md").read_text()
        self.assertIn("X-RemotePower-Signature-V2", doc)
        self.assertIn("ts.encode() + b'.' + raw_body", doc,
                      "the doc's construction must match the sender's")
        src = (_CGI / "api.py").read_text()
        self.assertIn("_ts.encode() + b'.' + body", src)

    def test_the_doc_no_longer_promises_replay_safety_from_v1(self):
        doc = (ROOT / "docs" / "webhooks.md").read_text()
        self.assertNotIn("bound the timestamp to\nreject replays", doc)
        self.assertIn("legacy", doc.lower(),
                      "the doc must mark the body-only signature as legacy")
