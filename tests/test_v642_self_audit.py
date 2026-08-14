"""Regressions an adversarial audit of this session's own changes turned up.

Every one of these was introduced by a fix earlier in the same sweep, and every
one was invisible to the full gate on both backends. They are grouped here
because they share a lesson worth keeping: a fix verified only against the case
it was written for can break a neighbouring case that nothing covered.

The two criticals live in their own files (`test_v642_config_secret_at_rest.py`
for the at-rest encryption strip, and the collector cases below for the log
replay); the rest are here.
"""

# A sibling from tests/ is imported inside a test method below.
# `unittest discover -s tests` puts this directory on sys.path for free;
# `python3 -m unittest tests.<this>` does not, and the method then fails
# with ModuleNotFoundError. See tests/test_modules_import_alone.py.
import sys as _rp_sys, pathlib as _rp_pl  # noqa: E402
_rp_sys.path.insert(0, str(_rp_pl.Path(__file__).resolve().parent))
import ast
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
_CLIENT = ROOT / "client"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v642-audit-"))

_spec = importlib.util.spec_from_file_location("api_v642_audit", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _load_agent(name, modname):
    spec = importlib.util.spec_from_file_location(modname, _CLIENT / name)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod
    spec.loader.exec_module(mod)
    return mod


class TestWildcardBindIsWorldOnEveryAgent(unittest.TestCase):
    """A dual-stack socket bound to every interface reports `::ffff:0.0.0.0`,
    and 0.0.0.0/8 is `is_private`, so the classifier called it 'lan' — silencing
    the world-exposed-port check for a service listening on all interfaces. The
    literal `0.0.0.0` / `::` forms were caught by an early return, so only the
    mapped spelling slipped through.

    Pre-existing on the Linux agent since v3.11.0; the v6.4.2 Windows/macOS
    rewrite inherited it while fixing the loopback half. Fixed on all three.
    """

    CASES = {
        '0.0.0.0': 'world', '::': 'world', '*': 'world',
        '::ffff:0.0.0.0': 'world', '::ffff:0:0': 'world',
        '127.0.0.1': 'local', '127.0.1.1': 'local', '::1': 'local',
        '::ffff:127.0.0.1': 'local',
        '192.168.1.5': 'lan', '10.0.0.3': 'lan', '::ffff:10.0.0.3': 'lan',
        'fe80::1': 'lan', '8.8.8.8': 'world', '2606:4700::1111': 'world',
    }
    # Only the Windows/macOS enumerators can hand back a NAME — netstat resolves
    # them. Linux reads /proc/net/tcp (or `ss -H -ltnp`), which is always
    # numeric, so 'localhost' there is an address it cannot parse and its
    # documented fail-loud default ('world' — an exposure we can't classify is
    # the riskier case) is correct. Don't widen an agent to satisfy a test.
    NAMED = {'localhost': 'local'}

    def _check(self, mod, fn, extra=None):
        for addr, want in dict(self.CASES, **(extra or {})).items():
            with self.subTest(agent=mod.__name__, addr=addr):
                self.assertEqual(fn(addr), want)

    def test_linux(self):
        m = _load_agent('remotepower-agent.py', 'ag_linux_v642')
        self._check(m, m._sock_scope)

    def test_windows(self):
        m = _load_agent('remotepower-agent-win.py', 'ag_win_v642')
        self._check(m, m._port_scope, self.NAMED)

    def test_macos(self):
        m = _load_agent('remotepower-agent-mac.py', 'ag_mac_v642')
        self._check(m, m._port_scope, self.NAMED)


class TestBruteForceKeepsHostnameSources(unittest.TestCase):
    """The IPv6-truncation fix replaced `src.split(':')[0]` with a strict
    `ipaddress` parse — which silently dropped every source that is not an
    address. sshd with `UseDNS yes` logs a RESOLVED HOSTNAME there, and the old
    extractor passed those through intact, so brute-force detection went
    completely silent on those hosts rather than merely mis-keying."""

    def test_a_hostname_source_is_kept_whole(self):
        self.assertEqual(api._brute_src_ip('scanner.badguy.example'),
                         'scanner.badguy.example')
        self.assertEqual(api._brute_src_ip('HOST.Example.COM.'), 'host.example.com')

    def test_addresses_still_normalise(self):
        self.assertEqual(api._brute_src_ip('2001:db8::1'), '2001:db8::1')
        self.assertEqual(api._brute_src_ip('[2001:db8::1]:22'), '2001:db8::1')
        self.assertEqual(api._brute_src_ip('192.0.2.1:1234'), '192.0.2.1')

    def test_ipv6_is_not_truncated_to_its_first_hextet(self):
        a = api._brute_src_ip('2001:db8::1')
        b = api._brute_src_ip('2001:470::9')
        self.assertNotEqual(a, b, 'unrelated sources must not share a counter')

    def test_junk_is_still_rejected(self):
        for junk in ('', '-', 'bad_host!', 'a' * 300, 'has space'):
            self.assertIsNone(api._brute_src_ip(junk), junk)


class TestWakeOnLanIgnoresIpv6(unittest.TestCase):
    """`_sanitize_ip` was widened to preserve IPv6, which it used to blank. WoL
    is an IPv4/L2 broadcast mechanism on an AF_INET socket, so a device whose
    stored `ip` is IPv6 went from "blanked → broadcast fallback, wakes fine" to
    a raised sendto and 'WoL send failed'."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="rp-v642-wol-"))
        self._cfg = api.CONFIG_FILE
        api.CONFIG_FILE = self.d / "config.json"
        api.save(api.CONFIG_FILE, {})

    def tearDown(self):
        api.CONFIG_FILE = self._cfg

    def test_ipv6_device_falls_back_to_broadcast(self):
        ok, info = api._send_wol({'mac': 'aa:bb:cc:dd:ee:ff', 'ip': '2001:db8::42'})
        self.assertTrue(ok, info)
        self.assertEqual(info['target'], '255.255.255.255')

    def test_ipv4_device_still_targeted_directly(self):
        ok, info = api._send_wol({'mac': 'aa:bb:cc:dd:ee:ff', 'ip': '192.168.1.50'})
        self.assertTrue(ok, info)
        self.assertEqual(info['target'], '192.168.1.50')

    def test_an_ipv6_configured_broadcast_is_ignored_too(self):
        api.save(api.CONFIG_FILE, {'wol_broadcast': 'ff02::1'})
        api._invalidate_load_cache(api.CONFIG_FILE)
        ok, info = api._send_wol({'mac': 'aa:bb:cc:dd:ee:ff', 'ip': ''})
        self.assertTrue(ok, info)
        self.assertEqual(info['target'], '255.255.255.255')


class TestCvss4SubsequentImpactCounts(unittest.TestCase):
    """The v4→v3.1 approximation mapped only the vulnerable-system impacts
    (VC/VI/VA). A vector whose impact lands entirely on the SUBSEQUENT system
    (`VC:N/VI:N/VA:N/SC:H/SI:H/SA:H`, an official 9.3 CRITICAL) therefore hit
    v3.1's zero-impact case and scored 0.0 — filed `low`, while presenting as a
    computed score with a named source."""

    @staticmethod
    def _band(x):
        return ('critical' if x >= 9 else 'high' if x >= 7 else
                'medium' if x >= 4 else 'low' if x > 0 else 'none')

    def test_bands_match_the_official_v4_scores(self):
        spec = importlib.util.spec_from_file_location(
            "cve_scanner_v642", _CGI / "cve_scanner.py")
        cs = importlib.util.module_from_spec(spec)
        sys.modules["cve_scanner_v642"] = cs
        spec.loader.exec_module(cs)
        cases = [
            # (vector, official v4 base score, official band)
            ('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:H', 9.3, 'critical'),
            ('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N', 9.3, 'critical'),
            ('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N', 6.9, 'medium'),
            ('CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N', 8.5, 'high'),
            ('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N', 5.1, 'medium'),
            ('CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N', 1.0, 'low'),
        ]
        for vector, official, band in cases:
            with self.subTest(vector=vector):
                got = cs._cvss_base_score(vector)
                self.assertIsNotNone(got, 'a v4 vector must never score unknown')
                self.assertEqual(self._band(got), band,
                                 f'official {official} is {band}, approximation '
                                 f'gave {got}')


class TestRagRetrievalIsGatedAtTheChokepoint(unittest.TestCase):
    """The scope gate went on `/api/ai/rag/search` only. The corpus is
    fleet-wide and untagged, and `POST /api/devices/{id}/runbook` retrieves from
    the same index with no check — it put out-of-scope hosts into the model
    prompt and the response body. `handle_ai_chat`'s own guard was also
    incomplete: it tests `_caller_scope()`, and a TENANT admin resolves to None
    there, so it never fired for them.

    The gate belongs in `_rag_retrieve` so every present and future consumer is
    covered; the search endpoint keeps its explicit 403 because a search that
    silently returns nothing reads as 'no results'."""

    def test_retrieval_itself_checks_scope_and_tenant(self):
        tree = ast.parse((_CGI / "api.py").read_text())
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == "_rag_retrieve")
        dumped = ast.dump(fn)
        self.assertIn("_caller_scope", dumped)
        self.assertIn("_tenant_gate", dumped)

    def test_no_consumer_retrieves_without_going_through_it(self):
        """If a caller ever reaches the index directly, the chokepoint is moot."""
        tree = ast.parse((_CGI / "api.py").read_text())
        offenders = []
        for fnode in ast.walk(tree):
            if not isinstance(fnode, ast.FunctionDef):
                continue
            if fnode.name in ("_rag_retrieve", "_rag_retrieve_pg", "_rag_get_index",
                              "_rag_reindex", "handle_ai_rag_search"):
                continue
            for n in ast.walk(fnode):
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) \
                        and n.func.attr == "search" \
                        and getattr(n.func.value, "id", "") == "idx":
                    offenders.append(f"{fnode.name}:{n.lineno}")
        self.assertEqual(offenders, [],
                         "these bypass _rag_retrieve's scope/tenant gate")


class TestMetricPipelineSeesOnlyFreshMeasurements(unittest.TestCase):
    """`sysinfo_partial` merges a partial beat over the stored record so the
    drawer/Checks/forecast stop emptying between cadence beats. But the metric
    consumers were handed the MERGED view, so a beat that measured nothing
    re-observed the last full reading: it appended a fresh-timestamped duplicate
    sample and advanced the flap-damping streak, firing metric_warning off a
    single real observation. Both now read the pre-merge view."""

    def test_both_consumers_take_the_pre_merge_view(self):
        tree = ast.parse((_CGI / "api.py").read_text())
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == "handle_heartbeat")
        src = ast.unparse(fn)
        self.assertIn("_fresh_si = safe_si", src,
                      "the pre-merge sysinfo must be captured before the merge")
        self.assertIn("process_metric_thresholds(dev_id, dev, _fresh_si", src,
                      "flap damping must not advance on a beat that measured nothing")
        self.assertIn("_record_metrics(dev_id, _fresh_si", src,
                      "a beat that measured nothing must not append a sample")


class TestLogCollectorsDoNotReplayOnUpgrade(unittest.TestCase):
    """The rotation fix reset the offset whenever the saved inode did not match
    — but it read the saved inode as `int(st.get('ino', 0) or 0)`, and every
    state file written before that key existed has no `ino`. So on the FIRST
    beat after an agent upgrade, 0 != the real inode, the offset was discarded,
    and the collector replayed the whole log as live traffic — firing log_watch
    rules fleet-wide on historical lines. `collect_file_log`, cited as the
    reference implementation, only resets on a KNOWN-different inode."""

    def setUp(self):
        import json as _json
        self.json = _json
        self.mod = _load_agent('remotepower-agent.py', 'ag_rot_v642')
        self.d = Path(tempfile.mkdtemp(prefix="rp-v642-rot-"))
        self.logdir = self.d / 'log'
        self.logdir.mkdir()
        self.log = self.logdir / 'access.log'
        self.log.write_text('\n'.join(f'10.0.0.1 - - "GET /old/{i}"'
                                      for i in range(300)) + '\n')
        self.mod.WEB_ACCESS_LOGS = [(str(self.log), 'nginx.access')]
        self.state = self.d / 'state'
        self.state.mkdir()
        self.sf = self.state / 'nginx_access_state.json'
        self.st0 = self.log.stat()

    def _beat(self, bump=None):
        if bump is not None:
            s = self.log.stat()
            os.utime(self.log, (s.st_atime, self.st0.st_mtime + bump))
        return self.mod.collect_web_access_logs(self.state).get('nginx.access') or []

    def test_a_pre_upgrade_state_file_does_not_replay(self):
        # v6.4.1 shape: {mtime, pos} and no `ino`. The agent was fully caught up.
        self.sf.write_text(self.json.dumps(
            {'mtime': self.st0.st_mtime - 10, 'pos': self.st0.st_size}))
        self.assertEqual(self._beat(), [],
                         'the whole log was replayed as live traffic')
        self.assertIn('ino', self.json.loads(self.sf.read_text()),
                      'the inode must be recorded so the NEXT rotation is caught')

    def test_new_lines_after_the_upgrade_still_arrive(self):
        self.sf.write_text(self.json.dumps(
            {'mtime': self.st0.st_mtime - 10, 'pos': self.st0.st_size}))
        self._beat()
        with self.log.open('a') as f:
            f.write('10.0.0.1 - - "GET /new"\n')
        self.assertEqual(self._beat(20), ['10.0.0.1 - - "GET /new"'])

    def test_a_real_rotation_still_resets(self):
        self.sf.write_text(self.json.dumps(
            {'mtime': self.st0.st_mtime - 10, 'pos': self.st0.st_size,
             'ino': self.st0.st_ino}))
        self.log.unlink()
        self.log.write_text('10.0.0.1 - - "GET /after-rotate"\n')
        self.assertEqual(self._beat(40), ['10.0.0.1 - - "GET /after-rotate"'])

    def test_copytruncate_still_resets(self):
        self.sf.write_text(self.json.dumps(
            {'mtime': self.st0.st_mtime - 10, 'pos': self.st0.st_size,
             'ino': self.st0.st_ino}))
        with self.log.open('w') as f:      # same inode, file shrinks
            f.write('10.0.0.1 - - "GET /post-truncate"\n')
        self.assertEqual(self._beat(20), ['10.0.0.1 - - "GET /post-truncate"'])


class TestContainerLogBaselineTakenBeforeQueuing(unittest.TestCase):
    """The fallback poll established its "ignore anything older" baseline on its
    first tick — ten seconds AFTER the 90s run-and-wait window closed. If the
    agent checked in during that gap (exactly the case the fallback exists for)
    the operator's own output was the newest match, so it became the baseline
    and was never shown: five minutes of "still waiting", then "the host is
    probably offline", with the logs sitting in the history the whole time."""

    def test_the_snapshot_predates_the_queued_command(self):
        import srcpin
        src = (ROOT / "server" / "html" / "static" / "js" / "app.js").read_text()
        fetch = srcpin.js_function(src, "_ctrLogsFetch")
        poll = srcpin.js_function(src, "_ctrLogsFallbackPoll")
        self.assertLess(fetch.index("/output`)"), fetch.index("containers/action`"),
                        "the history snapshot must be taken BEFORE the POST queues "
                        "the command")
        self.assertIn("priorOutputs", poll)
        self.assertNotIn("baselineTs === null", poll,
                         "the first-tick baseline is what dropped the output")


if __name__ == '__main__':
    unittest.main()
