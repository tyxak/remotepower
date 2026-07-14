"""GitHub issue monitor integration — connector + edge-triggered new-issue alerts.

Connector layer: the pure ``github`` connector against a fake HTTP client
(repo parsing/validation, PR filtering, per-repo high-water marks, auth
header, failure shapes). Wiring layer: ``_persist_integration_results``'s
edge-trigger (baseline-then-alert, newly-attached-repo baseline, carry-forward
across transient failures, anti-burst cap) and the event-registry defaults
(Alerts inbox ON, webhook/needs_attention OFF by default).
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))

import integrations as I  # noqa: E402


def _issue(number, title='t', pr=False):
    d = {'number': number, 'title': title,
         'html_url': f'https://github.com/o/r/issues/{number}'}
    if pr:
        d['pull_request'] = {'url': 'x'}
    return d


class FakeClient(I.HTTPClient):
    def __init__(self, routes=None):
        super().__init__('https://api.github.com')
        self.routes = routes or {}
        self.calls = []

    def request(self, method, path, headers=None, params=None, body=None):
        self.calls.append((method, path.split('?')[0], dict(headers or {})))
        v = self.routes.get(path.split('?')[0])
        if v is None:
            return I.Resp(404, json.dumps({'message': 'Not Found'}))
        return I.Resp(200, json.dumps(v))


class TestConnector(unittest.TestCase):
    def test_registered_with_stats(self):
        self.assertIn('github', I.CONNECTORS)
        self.assertTrue(I._STATS.get('github'))

    def test_counts_and_state_exclude_prs(self):
        c = FakeClient({'/repos/o/r/issues': [
            _issue(7), _issue(9, pr=True), _issue(5)]})
        res = I.poll_instance({'type': 'github', 'slug': 'o/r'}, c)
        self.assertEqual(res['status'], I.OK)
        self.assertEqual(res['metrics'], {'repos': 1, 'open_issues': 2})
        self.assertEqual(res['gh_state'], {'o/r': 7})
        self.assertEqual([i['number'] for i in res['gh_latest']], [7, 5])
        self.assertTrue(res['gh_latest'][0]['url'].startswith('https://github.com/'))

    def test_multiple_repos(self):
        c = FakeClient({'/repos/o/r/issues': [_issue(3)],
                        '/repos/o/r2/issues': [_issue(11)]})
        res = I.poll_instance({'type': 'github', 'slug': 'o/r, o/r2'}, c)
        self.assertEqual(res['gh_state'], {'o/r': 3, 'o/r2': 11})
        self.assertEqual(res['metrics']['repos'], 2)

    def test_invalid_repo_rejected_before_url_interpolation(self):
        # An absolute-URL / traversal "repo" must never reach the path builder.
        c = FakeClient({'/repos/o/r/issues': [_issue(1)]})
        res = I.poll_instance(
            {'type': 'github', 'slug': 'https://evil/x, o/r'}, c)
        self.assertEqual(res['status'], I.WARN)
        self.assertIn('invalid', res['detail'])
        for _m, path, _h in c.calls:
            self.assertTrue(path.startswith('/repos/o/r/'), path)

    def test_all_repos_invalid_is_critical(self):
        res = I.poll_instance({'type': 'github', 'slug': '///, nope'}, FakeClient())
        self.assertEqual(res['status'], I.CRIT)

    def test_unreachable_repo_is_warning(self):
        c = FakeClient({'/repos/o/r/issues': [_issue(1)]})
        res = I.poll_instance({'type': 'github', 'slug': 'o/r, o/gone'}, c)
        self.assertEqual(res['status'], I.WARN)
        self.assertIn('o/gone', res['detail'])

    def test_token_sent_as_bearer(self):
        c = FakeClient({'/repos/o/r/issues': []})
        I.poll_instance({'type': 'github', 'slug': 'o/r', 'secret': 'ghp_x'}, c)
        self.assertEqual(c.calls[0][2].get('Authorization'), 'Bearer ghp_x')

    def test_no_token_no_auth_header(self):
        c = FakeClient({'/repos/o/r/issues': []})
        I.poll_instance({'type': 'github', 'slug': 'o/r'}, c)
        self.assertNotIn('Authorization', c.calls[0][2])

    def test_website_url_autocorrected_to_api_root(self):
        # The predictable operator mistake: URL = the website (github.com), not the
        # API root. v6.1.3: the connector must rewrite the client BASE to
        # api.github.com and keep the path RELATIVE — building an absolute URL was
        # a bug, because the real SSRF-safe client rejects absolute paths.
        c = FakeClient({'/repos/o/r/issues': [_issue(2)]})
        c.base = 'https://github.com'   # what _integration_client would set from url
        res = I.poll_instance(
            {'type': 'github', 'slug': 'o/r', 'url': 'https://github.com/'}, c)
        self.assertEqual(res['status'], I.OK)
        self.assertEqual(res['gh_state'], {'o/r': 2})
        # The connector rewrote the base to the API root (relative paths from there).
        self.assertEqual(c.base, 'https://api.github.com')

    def test_absolute_path_is_rejected_by_the_real_client(self):
        # Guardrail: prove the old approach (absolute path) would actually fail on
        # the real SSRF-safe client, so this can't silently regress to false-green.
        with self.assertRaises(ValueError):
            I.HTTPClient('https://api.github.com')._full('https://api.github.com/x')

    def test_enterprise_api_root_untouched(self):
        c = FakeClient({'/repos/o/r/issues': [_issue(2)]})
        res = I.poll_instance(
            {'type': 'github', 'slug': 'o/r',
             'url': 'https://ghe.corp.example/api/v3'}, c)
        self.assertEqual(res['status'], I.OK)
        self.assertEqual(c.calls[0][1], '/repos/o/r/issues')


def _load_api():
    os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp())
    spec = importlib.util.spec_from_file_location('api_gh_integ', _CGI / 'api.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _result(gh_state, gh_latest, checked=1, status='ok'):
    return {'id': 'g1', 'label': 'GH', 'type': 'github', 'status': status,
            'detail': '', 'checked': checked, 'metrics': {},
            'gh_state': gh_state, 'gh_latest': gh_latest}


class TestNewIssueAlerts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = _load_api()

    def setUp(self):
        api = self.api
        api.save(api.INTEG_STATE_FILE, {})
        cfg = api.load(api.CONFIG_FILE)
        cfg['integrations'] = [{'id': 'g1', 'type': 'github', 'slug': 'o/r'}]
        cfg['integration_notified'] = {}
        api.save(api.CONFIG_FILE, cfg)
        self.fired = []
        self._orig = api.fire_webhook
        api.fire_webhook = lambda ev, p: self.fired.append((ev, p))

    def tearDown(self):
        self.api.fire_webhook = self._orig

    def _gh_events(self):
        return [(e, p) for e, p in self.fired if e == 'github_new_issue']

    def test_first_poll_baselines_silently(self):
        self.api._persist_integration_results(
            [_result({'o/r': 40}, [{'repo': 'o/r', 'number': 40, 'title': 'old', 'url': 'u'}])])
        self.assertEqual(self._gh_events(), [])

    def test_new_issue_fires_once_with_payload(self):
        api = self.api
        api._persist_integration_results(
            [_result({'o/r': 40}, [{'repo': 'o/r', 'number': 40, 'title': 'old', 'url': 'u'}])])
        api._persist_integration_results(
            [_result({'o/r': 41},
                     [{'repo': 'o/r', 'number': 41, 'title': 'fresh bug', 'url': 'u41'},
                      {'repo': 'o/r', 'number': 40, 'title': 'old', 'url': 'u'}], checked=2)])
        evs = self._gh_events()
        self.assertEqual(len(evs), 1)
        p = evs[0][1]
        self.assertEqual((p['repo'], p['number'], p['title'], p['url'], p['integration_id']),
                         ('o/r', 41, 'fresh bug', 'u41', 'g1'))
        # steady state — no re-fire
        self.fired.clear()
        api._persist_integration_results(
            [_result({'o/r': 41},
                     [{'repo': 'o/r', 'number': 41, 'title': 'fresh bug', 'url': 'u41'}], checked=3)])
        self.assertEqual(self._gh_events(), [])

    def test_newly_attached_repo_baselines(self):
        api = self.api
        api._persist_integration_results(
            [_result({'o/r': 40}, [{'repo': 'o/r', 'number': 40, 'title': 'x', 'url': 'u'}])])
        api._persist_integration_results(
            [_result({'o/r': 40, 'o/new': 90},
                     [{'repo': 'o/r', 'number': 40, 'title': 'x', 'url': 'u'},
                      {'repo': 'o/new', 'number': 90, 'title': 'y', 'url': 'u'}], checked=2)])
        self.assertEqual(self._gh_events(), [])

    def test_mark_carried_across_transient_failure(self):
        api = self.api
        api._persist_integration_results(
            [_result({'o/r': 40}, [{'repo': 'o/r', 'number': 40, 'title': 'x', 'url': 'u'}])])
        # repo fetch fails this poll → absent from gh_state; mark must survive
        api._persist_integration_results(
            [_result({'o/other': 1}, [{'repo': 'o/other', 'number': 1, 'title': 'z', 'url': 'u'}],
                     checked=2, status='warning')])
        # repo back, one new issue → alert (NOT a re-baseline)
        api._persist_integration_results(
            [_result({'o/r': 41, 'o/other': 1},
                     [{'repo': 'o/r', 'number': 41, 'title': 'while away', 'url': 'u'},
                      {'repo': 'o/other', 'number': 1, 'title': 'z', 'url': 'u'}], checked=3)])
        evs = self._gh_events()
        self.assertEqual([p['number'] for _, p in evs], [41])

    def test_burst_capped_with_summary(self):
        api = self.api
        api._persist_integration_results(
            [_result({'o/r': 10}, [{'repo': 'o/r', 'number': 10, 'title': 'x', 'url': 'u'}])])
        burst = [{'repo': 'o/r', 'number': n, 'title': f'i{n}', 'url': 'u'}
                 for n in range(11, 24)]     # 13 new issues
        api._persist_integration_results([_result({'o/r': 23}, burst, checked=2)])
        evs = self._gh_events()
        self.assertEqual(len(evs), 11)       # 10 individual + 1 summary
        self.assertIn('more new issue', evs[-1][1]['title'])


class TestEventWiring(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = TestNewIssueAlerts.api if hasattr(TestNewIssueAlerts, 'api') else _load_api()

    def test_event_registered(self):
        api = self.api
        self.assertIn('github_new_issue', api.WEBHOOK_EVENT_NAMES)
        self.assertEqual(api.EVENT_REGISTRY['github_new_issue']['kind'], 'github_issue')
        kinds = {k[0] for k in api.CHANNEL_KINDS}
        self.assertIn('github_issue', kinds)

    def test_alertable_low_severity(self):
        self.assertEqual(self.api._alert_severity('github_new_issue', {}), 'low')

    def test_default_routing_inbox_on_paging_off(self):
        slot = self.api._kind_default('github_issue')
        self.assertTrue(slot['alerts'])            # lands in the Alerts inbox
        self.assertTrue(slot['recent_activity'])
        self.assertFalse(slot['webhook'])          # doesn't page until opted in
        self.assertFalse(slot['needs_attention'])

    def test_alert_whitelist_carries_issue_identity(self):
        src = (_CGI / 'api.py').read_text()
        # _record_alert + _record_fleet_event summaries must keep repo/title/url
        # or the inbox/feed rows render empty (whitelists are silent when missed).
        # v5.8.0: the fleet-event whitelist was extended past 'label' with more
        # feed-detail fields, so it no longer closes on 'label'):.
        # v6.0.1: the _record_alert whitelist gained pool/paths/threshold after
        # repo/title/url, so it no longer closes on url'):.
        # v6.1.2: it then gained mac/old_ip/new_ip (network events), so the tuple
        # now closes on new_ip'): — assert the keys are present without pinning the
        # exact closing token (that brittleness is what keeps breaking here).
        self.assertIn("'repo', 'title', 'url',", src)
        self.assertIn("'pool', 'paths', 'threshold',", src)
        self.assertIn("'mac', 'old_ip', 'new_ip'):", src)
        self.assertIn("'repo', 'title', 'url', 'label',", src)


if __name__ == '__main__':
    unittest.main()
