"""AbuseIPDB / SniffCat: lookups, reports and timed auto-blocks.

The providers are faked at the one seam that talks to the network
(`_ip_intel_http`). Everything else runs for real: the brute-force detector
queues the source, the sweep looks it up, reports it and queues the block
through `_queue_command_batch` into the real command store, and the firewall
commands are executed by bash against stub firewall binaries.
"""
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlparse

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-ipintel-'))

_CGI = Path(__file__).resolve().parent.parent / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

import ip_intel  # noqa: E402

ATTACKER = '185.220.101.7'
ATTACKER6 = '2a0b:f4c0:16c:1::77'


def _fresh_api():
    import importlib.util
    os.environ['RP_DATA_DIR'] = tempfile.mkdtemp(prefix='rp-ipintel-api-')
    spec = importlib.util.spec_from_file_location('api_ipintel', _CGI / 'api.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── pure ───────────────────────────────────────────────────────────────────────

class TestProviders(unittest.TestCase):
    def test_abuseipdb_request_and_parse(self):
        req = ip_intel.abuseipdb_check_request(ATTACKER, 'k' * 80)
        u = urlparse(req['url'])
        self.assertEqual((u.scheme, u.netloc, u.path), ('https', 'api.abuseipdb.com', '/api/v2/check'))
        self.assertEqual(parse_qs(u.query)['ipAddress'], [ATTACKER])
        self.assertEqual(req['headers']['Key'], 'k' * 80)
        body = {'data': {'ipAddress': ATTACKER, 'abuseConfidenceScore': 100,
                         'totalReports': 4211, 'countryCode': 'DE', 'isp': 'Tor exit',
                         'usageType': 'Reserved', 'isWhitelisted': False}}
        r = ip_intel.abuseipdb_parse_check(200, body)
        self.assertEqual((r['score'], r['reports'], r['country']), (100, 4211, 'DE'))
        self.assertTrue(ip_intel.abuseipdb_parse_check(429, {})['rate_limited'])
        self.assertTrue(ip_intel.abuseipdb_parse_check(401, {'errors': [{'detail': 'bad key'}]})['auth'])
        self.assertFalse(ip_intel.abuseipdb_parse_check(200, {'nope': 1})['ok'])

    def test_abuseipdb_report_form(self):
        req = ip_intel.abuseipdb_report_request(ATTACKER, 'k' * 80, [18, 22], 'x' * 2000)
        form = parse_qs(req['body'].decode())
        self.assertEqual(form['categories'], ['18,22'])
        self.assertLessEqual(len(form['comment'][0]), 1024)

    def test_sniffcat_request_and_parse(self):
        req = ip_intel.sniffcat_check_request(ATTACKER, 's' * 40)
        u = urlparse(req['url'])
        self.assertEqual((u.netloc, u.path), ('api.sniffcat.com', '/api/v1/check'))
        self.assertEqual(req['headers']['X-Secret-Token'], 's' * 40)
        r = ip_intel.sniffcat_parse_check(200, {'success': True, 'status': 200, 'abuseConfidenceScore': 73})
        self.assertEqual(r['score'], 73)
        self.assertFalse(ip_intel.sniffcat_parse_check(200, {'success': False})['ok'])
        import json
        body = json.loads(ip_intel.sniffcat_report_request(ATTACKER, 's' * 40, [17, 18], 'comment here')['body'])
        self.assertEqual(body['categories'], [17, 18])

    def test_merge_takes_the_highest_score(self):
        v = ip_intel.merge({'abuseipdb': {'ok': True, 'score': 12, 'reports': 3, 'country': 'NL'},
                            'sniffcat': {'ok': True, 'score': 91, 'reports': 5},
                            'x': {'ok': False}})
        self.assertEqual((v['score'], v['reports'], v['country']), (91, 8, 'NL'))
        self.assertIsNone(ip_intel.merge({'abuseipdb': {'ok': False}})['score'])

    def test_comment_carries_no_host_details(self):
        c = ip_intel.report_comment('ssh', 42, 600)
        self.assertEqual(c, 'SSH brute force: 42 failed attempts within 10 minutes (reported by RemotePower)')
        self.assertGreaterEqual(len(c), 10)     # SniffCat's minimum

    def test_only_public_addresses(self):
        for ip in ('10.0.0.5', '192.168.1.1', '127.0.0.1', '169.254.1.1',
                   '203.0.113.9', '::1', 'fd00::1', '::ffff:10.0.0.1', '224.0.0.1'):
            self.assertFalse(ip_intel.is_public(ip), ip)
        for ip in (ATTACKER, ATTACKER6, '8.8.8.8'):
            self.assertTrue(ip_intel.is_public(ip), ip)

    def test_block_decision(self):
        pol = dict(ip_intel.DEFAULTS, block_enabled=True)
        self.assertTrue(ip_intel.block_decision(pol, {'score': 95}, 30)[0])
        self.assertFalse(ip_intel.block_decision(pol, {'score': 60}, 30)[0])
        self.assertFalse(ip_intel.block_decision(pol, {'score': 99, 'whitelisted': True}, 30)[0])
        self.assertFalse(ip_intel.block_decision(pol, {'score': None}, 30)[0])
        self.assertFalse(ip_intel.block_decision(dict(pol, block_enabled=False), {'score': 99}, 30)[0])


class TestFirewallCommands(unittest.TestCase):
    """Run the generated shell for real, against stub firewall binaries, and
    check which tool was called with what."""

    def _run(self, cmd, active):
        d = Path(tempfile.mkdtemp())
        log = d / 'calls.log'
        stubs = {
            'ufw': ('echo "Status: active"' if active == 'ufw' else 'echo "Status: inactive"'),
            'firewall-cmd': ('exit 0' if active == 'firewalld' else 'exit 252'),
            'iptables': 'exit 1',
            'ip6tables': 'exit 1',
        }
        for name, status_line in stubs.items():
            p = d / name
            p.write_text('#!/bin/sh\n'
                         f'echo "{name} $*" >> "{log}"\n'
                         f'case "$1 $2" in "status "*|"--state "*) {status_line};; esac\n'
                         'case "$1" in -C|-D) exit 1;; esac\n'
                         'exit 0\n')
            p.chmod(0o755)
        env = dict(os.environ, PATH=f'{d}:/usr/bin:/bin')
        subprocess.run(['bash', '-c', cmd], env=env, check=False, timeout=10)
        return log.read_text() if log.exists() else ''

    def test_ufw(self):
        calls = self._run(ip_intel.block_command(ATTACKER), 'ufw')
        self.assertIn(f'ufw insert 1 deny from {ATTACKER} comment rp-ipintel', calls)
        self.assertNotIn('iptables -I', calls)

    def test_firewalld(self):
        calls = self._run(ip_intel.block_command(ATTACKER6), 'firewalld')
        self.assertIn(f'--add-rich-rule=rule family=ipv6 source address={ATTACKER6} drop', calls)
        self.assertIn('firewall-cmd --reload', calls)

    def test_plain_iptables_fallback_and_unblock(self):
        calls = self._run(ip_intel.block_command(ATTACKER), 'none')
        self.assertIn(f'iptables -I INPUT -s {ATTACKER} -j DROP -m comment --comment rp-ipintel', calls)
        calls = self._run(ip_intel.unblock_command(ATTACKER6), 'none')
        self.assertIn(f'ip6tables -D INPUT -s {ATTACKER6} -j DROP', calls)

    def test_nothing_but_an_address_reaches_the_shell(self):
        for bad in ('1.2.3.4; rm -rf /', '$(id)', '1.2.3.4 ', 'example.com', ''):
            with self.assertRaises(ValueError, msg=bad):
                ip_intel.block_command(bad if bad != '1.2.3.4 ' else '1.2.3.4 x')


# ── API + sweep ────────────────────────────────────────────────────────────────

class _Case(unittest.TestCase):
    def setUp(self):
        self.api = api = _fresh_api()
        self.cap, self.audit, self.calls = {}, [], []

        def _respond(status, data=None):
            self.cap['status'], self.cap['data'] = status, data
            raise api.HTTPError(status, data)
        api.respond = _respond
        api.audit_log = lambda *a, **k: self.audit.append(a)
        api.fire_webhook = lambda *a, **k: None
        api.get_token_from_request = lambda: 'tok'
        self.scores = {'abuseipdb': 100, 'sniffcat': 80}

        def _http(req):
            self.calls.append(req)
            host = urlparse(req['url']).netloc
            prov = 'abuseipdb' if 'abuseipdb' in host else 'sniffcat'
            if req['method'] == 'POST':
                return 200, {'success': True, 'data': {}}
            if prov == 'abuseipdb':
                return 200, {'data': {'abuseConfidenceScore': self.scores[prov],
                                      'totalReports': 900, 'countryCode': 'DE',
                                      'isp': 'Example Hosting'}}
            return 200, {'success': True, 'status': 200,
                         'abuseConfidenceScore': self.scores[prov]}
        api._ip_intel_http = _http
        api.save(api.CONFIG_FILE, {
            'abuseipdb_api_key': 'a' * 80, 'sniffcat_api_key': 's' * 40,
            'ip_intel': {'lookup_enabled': True}})
        api.save(api.DEVICES_FILE, {
            'd1': {'name': 'web01', 'os': 'Ubuntu 24.04', 'token': 't', 'ip': '10.0.0.5'},
            'd2': {'name': 'win01', 'os': 'Windows 11', 'token': 't'},
            'd3': {'name': 'edge', 'os': 'Debian 12', 'token': 't', 'public_ip': '198.51.100.20'},
        })
        api._LOAD_CACHE.clear()

    def policy(self, **kw):
        cfg = self.api.load(self.api.CONFIG_FILE)
        cfg['ip_intel'] = dict(cfg.get('ip_intel') or {}, **kw)
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.api._LOAD_CACHE.clear()

    def attack(self, dev='d1', ip=ATTACKER, count=25, unit='sshd.service'):
        self.api.ip_intel_note_attack(dev, unit, ip, count, 600)
        self.api._LOAD_CACHE.clear()

    def sweep(self):
        st = self.api.load(self.api.IPINTEL_FILE) or {}
        st['last_sweep'] = 0
        self.api.save(self.api.IPINTEL_FILE, st)
        self.api._LOAD_CACHE.clear()
        self.api.run_ip_intel_if_due()
        self.api._LOAD_CACHE.clear()
        return self.api.load(self.api.IPINTEL_FILE)

    def queued(self, dev):
        return [c if isinstance(c, str) else c.get('command', '')
                for c in (self.api.load(self.api.CMDS_FILE) or {}).get(dev, [])]


class TestQueueing(_Case):
    def test_the_real_detector_queues_a_public_source(self):
        api = self.api
        api._brute_config = lambda: (True, 3, 600)
        lines = [f'Failed password for root from {ATTACKER} port 4{i} ssh2' for i in range(5)]
        api._detect_brute_force('d1', 'web01', 'sshd.service', lines)
        api._LOAD_CACHE.clear()
        q = (api.load(api.IPINTEL_FILE) or {}).get('queue') or []
        self.assertEqual([x['ip'] for x in q], [ATTACKER])

    def test_a_source_chosen_in_the_user_name_is_not_credited(self):
        """sshd logs the client-chosen user name BEFORE the real address, and
        keeps spaces in it. Logging in as `x from <victim>` used to credit the
        victim, which IP intel would then report under the operator's key."""
        api = self.api
        api._brute_config = lambda: (True, 3, 600)
        victim = '8.8.4.4'
        lines = []
        for i in range(5):
            lines += [
                f'Invalid user x from {victim} from {ATTACKER} port 4{i}',
                f'Failed password for invalid user x from {victim} port 22 from {ATTACKER} port 4{i} ssh2',
                f'Connection closed by invalid user x {victim} port 22 {ATTACKER} port 4{i} [preauth]',
                'pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh '
                f'ruser= rhost={ATTACKER}  user=rhost={victim}',
            ]
        api._detect_brute_force('d1', 'web01', 'sshd.service', lines)
        api._LOAD_CACHE.clear()
        q = (api.load(api.IPINTEL_FILE) or {}).get('queue') or []
        self.assertEqual({x['ip'] for x in q}, {ATTACKER})
        bf = api.load(api.BRUTE_FORCE_FILE) or {}
        self.assertEqual(set(bf['d1']['sshd.service']), {ATTACKER})

    def test_the_patterns_still_read_every_sshd_shape(self):
        """The anchoring must not cost a real line: with and without the port
        sshd stopped omitting, IPv6, and an empty pam rhost (no address)."""
        api = self.api
        pats = api._BRUTE_PATTERNS['ssh']

        def src(line):
            for pat in pats:
                m = pat.search(line)
                if m:
                    return m.group(1)
            return None
        self.assertEqual(src(f'Failed password for root from {ATTACKER} port 22 ssh2'), ATTACKER)
        self.assertEqual(src(f'Failed password for invalid user a b from {ATTACKER6} port 2 ssh2'), ATTACKER6)
        self.assertEqual(src(f'Invalid user admin from {ATTACKER}'), ATTACKER)
        self.assertEqual(src(f'Invalid user admin from {ATTACKER} port 22'), ATTACKER)
        self.assertEqual(src('pam_unix(sshd:auth): authentication failure; logname= uid=0 '
                             'euid=0 tty=ssh ruser= rhost=  user=root'), '')

    def test_private_sources_and_a_disabled_feature_queue_nothing(self):
        self.attack(ip='10.1.2.3')
        self.attack(ip='host.example.com')
        self.assertFalse((self.api.load(self.api.IPINTEL_FILE) or {}).get('queue'))
        self.policy(lookup_enabled=False)
        self.attack()
        self.assertFalse((self.api.load(self.api.IPINTEL_FILE) or {}).get('queue'))


class TestSweep(_Case):
    def test_lookup_is_cached_and_counted(self):
        self.attack()
        st = self.sweep()
        att = st['attackers'][ATTACKER]
        self.assertEqual(att['verdict']['score'], 100)
        self.assertEqual(att['verdict']['country'], 'DE')
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(st['budget']['abuseipdb'], 1)
        self.attack()
        self.sweep()
        self.assertEqual(len(self.calls), 2, 'second attack within the cache window looked up again')

    def test_budget_stops_lookups(self):
        self.policy(daily_lookup_budget=0)
        self.attack()
        self.sweep()
        self.assertEqual(self.calls, [])

    def test_reporting_is_opt_in_and_deduplicated(self):
        self.attack()
        self.sweep()
        self.assertFalse([c for c in self.calls if c['method'] == 'POST'])
        self.policy(report_enabled=True, report_min_count=10)
        self.attack(count=5)
        self.sweep()
        self.assertFalse([c for c in self.calls if c['method'] == 'POST'], 'reported below the minimum')
        self.attack(count=40)
        self.sweep()
        posts = [c for c in self.calls if c['method'] == 'POST']
        self.assertEqual(len(posts), 2)
        form = parse_qs([p for p in posts if 'abuseipdb' in p['url']][0]['body'].decode())
        self.assertEqual(form['categories'], ['18,22'])
        self.attack(count=40)
        self.sweep()
        self.assertEqual(len([c for c in self.calls if c['method'] == 'POST']), 2)

    def test_protected_addresses_are_never_reported(self):
        """A report is public and filed under the operator's account. The
        never-block rules used to apply only to blocking, so the office address
        in the UI allow-list was reported like any attacker."""
        cfg = self.api.load(self.api.CONFIG_FILE)
        cfg['ip_allowlist'] = ['185.220.101.0/24']
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.policy(report_enabled=True, report_min_count=1)
        self.attack(count=40)
        st = self.sweep()
        self.assertFalse([c for c in self.calls if c['method'] == 'POST'],
                         'an allow-listed address was reported')
        self.assertIn('never-block', str(st['attackers'][ATTACKER].get('errors')))
        # and the fleet's own public address
        self.attack(dev='d1', ip='198.51.100.20', count=40)
        self.sweep()
        self.assertFalse([c for c in self.calls if c['method'] == 'POST'])

    def test_block_queues_a_real_command_and_expires(self):
        self.policy(block_enabled=True)
        self.attack()
        st = self.sweep()
        self.assertIn(ATTACKER, st['blocks']['d1'])
        cmds = self.queued('d1')
        self.assertTrue(any(ATTACKER in c and 'deny from' in c for c in cmds), cmds)
        # expire it
        st['blocks']['d1'][ATTACKER]['until'] = int(time.time()) - 1
        self.api.save(self.api.IPINTEL_FILE, st)
        self.api._LOAD_CACHE.clear()
        st = self.sweep()
        self.assertNotIn('d1', st.get('blocks') or {})
        self.assertTrue(any('ufw --force delete deny from ' + ATTACKER in c for c in self.queued('d1')))

    def test_block_refusals(self):
        self.policy(block_enabled=True)
        self.scores = {'abuseipdb': 40, 'sniffcat': 30}
        self.attack()
        st = self.sweep()
        self.assertIn('below', st['attackers'][ATTACKER]['devices']['d1']['not_blocked'])
        self.scores = {'abuseipdb': 100, 'sniffcat': 100}
        self.attack(dev='d2', ip='185.220.101.8')
        st = self.sweep()
        self.assertIn('Linux', st['attackers']['185.220.101.8']['devices']['d2']['not_blocked'])
        # the fleet's own public address is never blocked
        self.attack(dev='d1', ip='198.51.100.20')
        st = self.sweep()
        self.assertEqual(st['attackers'], st['attackers'])  # recorded
        self.assertNotIn('198.51.100.20', (st.get('blocks') or {}).get('d1', {}))
        self.assertFalse([c for c in self.queued('d1') if '198.51.100.20' in c])

    def test_never_block_list_and_allowlist(self):
        cfg = self.api.load(self.api.CONFIG_FILE)
        cfg['ip_allowlist'] = ['185.220.101.0/24']
        self.api.save(self.api.CONFIG_FILE, cfg)
        self.policy(block_enabled=True)
        self.attack()
        st = self.sweep()
        self.assertIn('never-block', st['attackers'][ATTACKER]['devices']['d1']['not_blocked'])
        self.assertEqual(self.queued('d1'), [])

    def test_hourly_cap(self):
        self.policy(block_enabled=True, block_max_per_hour=2)
        for i in range(4):
            self.attack(ip=f'185.220.101.{20 + i}')
        st = self.sweep()
        self.assertEqual(len(st['blocks']['d1']), 2)

    def test_no_network_call_holds_the_store_lock(self):
        held = []
        api = self.api
        real = api._ip_intel_http

        def spy(req):
            held.append(getattr(api._LOCK_SCOPES, 'depth', 0))
            return real(req)
        api._ip_intel_http = spy
        self.policy(report_enabled=True, report_min_count=1, block_enabled=True)
        self.attack()
        self.sweep()
        self.assertTrue(held, 'no provider call was made')
        self.assertEqual(set(held), {0}, 'a provider call ran inside a store lock')
        # Structural check as well: phase 2 sits between the two lock blocks.
        import inspect
        src = inspect.getsource(api.run_ip_intel_if_due)
        p1 = src.index('# ── phase 2 ──')
        p3 = src.index('# ── phase 3 ──')
        self.assertNotIn('_LockedUpdate', src[p1:p3])
        self.assertIn('_ip_intel_http', src[p1:p3])


class TestEndpoints(_Case):
    def call(self, fn, method='GET', body=None, role='admin'):
        self.api.verify_token = lambda _t=None: ('alice', role)
        self.api.method = lambda: method
        self.api.get_json_obj = lambda: dict(body or {})
        self.cap.clear()
        try:
            fn()
        except self.api.HTTPError:
            pass
        self.api._LOAD_CACHE.clear()
        return self.cap.get('status'), self.cap.get('data') or {}

    def test_settings_keys_are_write_only(self):
        st, d = self.call(self.api.handle_ip_intel_settings, 'POST',
                          {'block_enabled': True, 'block_min_score': 500,
                           'sniffcat_api_key': 'n' * 40, 'never_block': '203.0.113.0/24'})
        self.assertEqual(st, 200)
        self.assertEqual(d['settings']['block_min_score'], 100)
        self.assertTrue(d['settings']['sniffcat_key_set'])
        self.assertNotIn('n' * 40, str(d))
        st, d = self.call(self.api.handle_ip_intel)
        self.assertNotIn('a' * 80, str(d))
        self.assertTrue(d['settings']['abuseipdb_key_set'])
        self.assertEqual(self.call(self.api.handle_ip_intel_settings, 'POST',
                                   {'never_block': 'not-a-net'})[0], 400)
        for role in ('viewer', 'auditor'):
            self.assertEqual(self.call(self.api.handle_ip_intel_settings, 'POST',
                                       {'block_enabled': False}, role=role)[0], 403)

    def test_config_get_does_not_echo_the_keys(self):
        self.api.verify_token = lambda _t=None: ('alice', 'admin')
        st, d = self.call(self.api.handle_config_get)
        self.assertNotIn('a' * 80, str(d))
        self.assertNotIn('s' * 40, str(d))

    def test_manual_block_and_unblock(self):
        st, _ = self.call(self.api.handle_ip_intel_block, 'POST',
                          {'device_id': 'd1', 'ip': ATTACKER}, role='viewer')
        self.assertEqual(st, 403)
        st, _ = self.call(self.api.handle_ip_intel_block, 'POST', {'device_id': 'd1', 'ip': ATTACKER})
        self.assertEqual(st, 200)
        self.assertIn(ATTACKER, (self.api.load(self.api.IPINTEL_FILE) or {})['blocks']['d1'])
        st, d = self.call(self.api.handle_ip_intel_block, 'POST',
                          {'device_id': 'd1', 'ip': '198.51.100.20'})
        self.assertEqual(st, 409)
        st, _ = self.call(self.api.handle_ip_intel_unblock, 'POST', {'device_id': 'd1', 'ip': ATTACKER})
        self.assertEqual(st, 200)
        self.assertNotIn('d1', (self.api.load(self.api.IPINTEL_FILE) or {}).get('blocks') or {})
        self.assertEqual(self.call(self.api.handle_ip_intel_block, 'POST',
                                   {'device_id': 'd2', 'ip': ATTACKER})[0], 409)

    def test_lookup_endpoint(self):
        st, d = self.call(self.api.handle_ip_intel_lookup, 'POST', {'ip': ATTACKER})
        self.assertEqual((st, d['verdict']['score']), (200, 100))
        self.assertEqual(self.call(self.api.handle_ip_intel_lookup, 'POST', {'ip': '10.0.0.1'})[0], 400)
        self.assertEqual(self.call(self.api.handle_ip_intel_lookup, 'POST', {'ip': ATTACKER},
                                   role='viewer')[0], 403)

    def test_block_endpoints_authenticate_before_touching_the_store(self):
        seen = []
        self.api._scope_block_device = lambda d: seen.append(d)
        self.api.verify_token = lambda _t=None: (None, None)
        self.api.method = lambda: 'POST'
        self.api.get_json_obj = lambda: {'device_id': 'd1', 'ip': ATTACKER}
        for fn in (self.api.handle_ip_intel_block, self.api.handle_ip_intel_unblock):
            self.cap.clear()
            try:
                fn()
            except self.api.HTTPError:
                pass
            self.assertEqual(self.cap.get('status'), 401)
        self.assertEqual(seen, [], 'the device store was consulted for an anonymous caller')

    def test_lookup_is_the_platform_operators_under_tenancy(self):
        self.api._tenancy_enforced = lambda: True
        self.api._caller_is_superadmin = lambda: False
        self.assertEqual(self.call(self.api.handle_ip_intel_lookup, 'POST', {'ip': ATTACKER})[0], 403)
        self.assertEqual(self.calls, [], 'a tenant admin spent the instance budget')

    def test_settings_are_admin_only_in_the_listing(self):
        st, d = self.call(self.api.handle_ip_intel, role='viewer')
        self.assertEqual((st, d['is_admin'], d['settings']), (200, False, {}))

    def test_listing_is_scoped_to_visible_devices(self):
        self.policy(block_enabled=True)
        self.attack()
        self.sweep()
        st, d = self.call(self.api.handle_ip_intel)
        self.assertEqual([a['ip'] for a in d['attackers']], [ATTACKER])
        self.assertEqual(len(d['blocks']), 1)
        self.api._scope_filter_devices = lambda devs, scope=None: {}
        st, d = self.call(self.api.handle_ip_intel)
        self.assertEqual((d['attackers'], d['blocks']), ([], []))


if __name__ == '__main__':
    unittest.main()
