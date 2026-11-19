#!/usr/bin/env python3
"""The audit trail never holds the secret address of a notification destination.

The address of a Slack, Discord, Teams, ntfy or Gotify destination is its credential: the secret is the path or the query. GET /api/config withholds it from
every caller but the instance's administrator, and the dead-letter list cuts it to the host. `POST /api/webhook/test` wrote the first 80 characters of the
address into the audit line of the test, and the audit trail is read by the `auditor` role (read-only), shipped by the audit forwarding to a SIEM and carried by the
redacted export.

* the line an administrator's Send test writes names the host and the destination's id, and an auditor reads no part of the secret in it, on every backend;
* the line is written with the destination's address in another shape too (a query secret, a user and password in the address);
* a ratchet over every `audit_log` call of the server: a message that formats a value named like an address passes it through one of the helpers that cut it, and the
  two calls that format one on purpose (they strip only the userinfo, and the path they keep is not a secret) are listed with the reason;
* the control of the ratchet: it finds the line as it was written before.
"""
import ast
import os
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-auditline-'))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import stores_support as S  # noqa: E402

setUpModule, tearDownModule = S.set_up_module, S.tear_down_module
api = S.api
ROOT = Path(__file__).resolve().parent.parent
CGI = ROOT / 'server' / 'cgi-bin'

SLACK_SECRET = 'sk7Hq29LmZx4Tn8Vb3Wc6Dy1'
SLACK_URL = 'https://hooks.example.invalid/services/T0AAAAA/B0BBBBB/' + SLACK_SECRET
NTFY_SECRET = 'topic-Zk41qWm90'
NTFY_URL = 'https://ntfy.example.invalid/alerts?auth=' + NTFY_SECRET
USERINFO_URL = 'https://bot:HunterTwo-77@hooks.example.invalid/in'


class TestSendTestWritesNoSecret(S.Case):
    def _dest(self, dest_id, url, fmt='generic'):
        dests = list((api.load(api.CONFIG_FILE) or {}).get('webhook_urls') or [])
        dests.append({'id': dest_id, 'name': dest_id, 'url': url, 'format': fmt, 'enabled': True})
        self.set_cfg(webhook_urls=dests)

    def _audit_rows(self, action):
        st, d = S.call('GET', '/api/audit-log', token=self.auditor)
        self.assertEqual(st, 200, d)
        rows = d if isinstance(d, list) else (d or {}).get('entries', [])
        return [e for e in rows if isinstance(e, dict) and e.get('action') == action]

    def setUp(self):
        super().setUp()
        self.add_user('auditor1', 'auditor', 'Audit-Passw0rd!x1')
        self.auditor = self.sign_in('auditor1', 'Audit-Passw0rd!x1')
        # nothing leaves the test: the delivery is refused before a socket is opened
        self._real = api._dispatch_one_webhook
        api._dispatch_one_webhook = lambda *a, **k: None
        self.addCleanup(setattr, api, '_dispatch_one_webhook', self._real)

    def test_the_control_the_auditor_cannot_read_the_address_in_the_settings(self):
        self._dest('wh_1', SLACK_URL, 'slack')
        st, d = S.call('GET', '/api/config', token=self.auditor)
        self.assertEqual(st, 200)
        self.assertNotIn(SLACK_SECRET, str(d))

    def test_send_test_names_the_host_and_not_the_path(self):
        self._dest('wh_1', SLACK_URL, 'slack')
        st, d = S.call('POST', '/api/webhook/test', {'id': 'wh_1'}, token=self.admin)
        self.assertEqual(st, 200, d)
        rows = self._audit_rows('webhook_test')
        self.assertEqual(len(rows), 1, 'the test must be audited: a line that is gone cannot leak, and is no answer')
        detail = rows[0]['detail']
        self.assertNotIn(SLACK_SECRET, detail)
        self.assertNotIn('/services/', detail)
        self.assertIn('wh_1', detail, 'the destination is named by its id')
        self.assertIn('https://hooks.example.invalid', detail, 'and the host stays, so a person can tell which service was tried')

    def test_a_query_secret_and_userinfo_are_cut_too(self):
        self._dest('wh_q', NTFY_URL, 'ntfy')
        self._dest('wh_u', USERINFO_URL)
        for dest_id in ('wh_q', 'wh_u'):
            st, d = S.call('POST', '/api/webhook/test', {'id': dest_id}, token=self.admin)
            self.assertEqual(st, 200, d)
        blob = ' '.join(e['detail'] for e in self._audit_rows('webhook_test'))
        for secret in (NTFY_SECRET, 'HunterTwo-77', 'auth='):
            self.assertNotIn(secret, blob)
        self.assertIn('ntfy.example.invalid', blob)
        self.assertIn('hooks.example.invalid', blob)

    def test_a_destination_without_a_readable_address_still_writes_a_line(self):
        self._dest('wh_x', 'not a url at all')
        st, d = S.call('POST', '/api/webhook/test', {'id': 'wh_x'}, token=self.admin)
        self.assertEqual(st, 200, d)
        rows = self._audit_rows('webhook_test')
        self.assertEqual(len(rows), 1)
        self.assertNotIn('not a url at all', rows[0]['detail'])


# ---- the ratchet over every audit_log call ------------------------------------------------------------------------------------------------------------------

ADDRESS_WORDS = ('url', 'endpoint', 'webhook')
CUTTER = '_redact_url_to_host'          # scheme://host and nothing after it
# (file, the formatted expression) -> why it may stay: these strip the userinfo and keep a path that is not a credential
ALLOWED = {
    ('api.py', '_audit_url'): 'the Pushgateway address with the userinfo stripped on the line above; its path names a job, not a credential',
    ('api.py', '_url_without_userinfo(url)'): 'the Git manifest address with the userinfo stripped: the path names the repository, which is what the line is for',
}


def audit_lines_that_format_an_address(src, fname):
    """(number of audit_log calls, [(lineno, expression)] for each one that formats a value named like an address without cutting it to the host)."""
    out, calls = [], 0
    for node in ast.walk(ast.parse(src)):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        name = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ''
        if name != 'audit_log':
            continue
        calls += 1
        for a in list(node.args[1:]) + [k.value for k in node.keywords if k.arg == 'detail']:
            for n in ast.walk(a):
                if not isinstance(n, ast.FormattedValue):
                    continue
                seg = ast.unparse(n.value)
                if any(w in seg.lower() for w in ADDRESS_WORDS) and CUTTER not in seg:
                    out.append((node.lineno, seg))
    return calls, out


class TestNoAuditLineFormatsAnAddress(unittest.TestCase):
    def test_every_audit_call_cuts_an_address_or_is_listed(self):
        total, flagged = 0, []
        for p in sorted(CGI.glob('*.py')):
            n, hits = audit_lines_that_format_an_address(p.read_text(), p.name)
            total += n
            flagged += [(p.name, ln, seg) for ln, seg in hits]
        self.assertGreater(total, 400, 'the scan must be looking at the audit calls of the server (it counted %d)' % total)
        unlisted = [(f, ln, seg) for f, ln, seg in flagged if (f, seg) not in ALLOWED]
        self.assertEqual(unlisted, [], 'an audit line formats an address that may carry its own secret; cut it with _redact_url_to_host')
        # an entry nobody needs any more is removed, so the list only shrinks
        seen = {(f, seg) for f, ln, seg in flagged}
        self.assertEqual(sorted(set(ALLOWED) - seen), [], 'a listed exception no longer occurs: delete it')

    def test_control_the_scan_finds_the_line_as_it_was_written(self):
        old = ("def handle_webhook_test():\n"
               "    audit_log(actor, 'webhook_test',\n"
               "              f'targeted={target_id} url={match.get(\"url\",\"?\")[:80]}')\n")
        total, hits = audit_lines_that_format_an_address(old, 'x.py')
        self.assertEqual(total, 1)
        self.assertEqual(len(hits), 1, 'the scan must flag the old line, or it measures nothing')

    def test_control_the_scan_passes_the_line_as_it_is_written_now(self):
        new = ("def handle_webhook_test():\n"
               "    audit_log(actor, 'webhook_test',\n"
               "              f'targeted={target_id} url={_redact_url_to_host(match.get(\"url\")) or \"?\"}')\n")
        total, hits = audit_lines_that_format_an_address(new, 'x.py')
        self.assertEqual((total, hits), (1, []))


if __name__ == '__main__':
    unittest.main()
