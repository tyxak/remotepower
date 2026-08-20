#!/usr/bin/env python3
"""Every one-click alert link RemotePower has ever emailed was permanent.

`/api/alerts/act` is public by design — the HMAC signature IS the capability, so
an operator can acknowledge from their phone without logging in. But the tag was
over `(alert_id, op)` alone, with no deadline anywhere, so the link never
stopped working.

That leaves a standing capability over the alert inbox in every mailbox that has
ever received an alert mail: an archive, a shared ops inbox, a forwarded thread,
a departed employee's mail. Whoever reads it later can resolve that alert, which
is how an ongoing incident gets hidden rather than noticed.

The failure page already said a link might be "not valid or has expired" — the
UI-text-that-lies class, since no link the product ever sent could expire.

The deadline is signed rather than stored, so the endpoint stays stateless and a
tampered `e` simply fails to verify.
"""
import importlib.util
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(_ROOT / 'tests'))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-aal-'))
_spec = importlib.util.spec_from_file_location('api_alert_link', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

import srcpin                                                    # noqa: E402


class TestTheDeadlineIsSigned(unittest.TestCase):

    def test_the_signature_covers_the_expiry(self):
        """If `exp` were outside the signed message, an attacker would just
        edit `e` in the URL."""
        a = api._alert_act_sig('al1', 'ack', 1000)
        b = api._alert_act_sig('al1', 'ack', 2000)
        self.assertNotEqual(a, b)

    def test_it_still_covers_the_alert_and_the_op(self):
        """The properties that were already there. A rewrite that signed only
        the deadline would pass the test above."""
        base = api._alert_act_sig('al1', 'ack', 1000)
        self.assertNotEqual(base, api._alert_act_sig('al2', 'ack', 1000))
        self.assertNotEqual(base, api._alert_act_sig('al1', 'resolve', 1000))

    def test_it_is_namespaced(self):
        """So a tag cannot be replayed as another signed artefact."""
        body = srcpin.py_function((_CGI / 'api.py').read_text(), '_alert_act_sig')
        self.assertIn("alertact:", body)

    def test_the_tag_is_wide_enough(self):
        self.assertGreaterEqual(len(api._alert_act_sig('al1', 'ack', 1)), 32)

    def test_the_ttl_is_a_week_not_forever(self):
        self.assertGreater(api.ALERT_ACT_LINK_TTL, 0)
        self.assertLessEqual(api.ALERT_ACT_LINK_TTL, 30 * 86400,
                             'a link this long-lived is barely an expiry')


class TestTheEndpointEnforcesIt(unittest.TestCase):

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix='rp-aal-run-'))
        self._saved = {n: getattr(api, n) for n in ('DATA_DIR', 'ALERTS_FILE')}
        api.DATA_DIR = self.dir
        api.ALERTS_FILE = self.dir / 'alerts.json'
        api.save(api.ALERTS_FILE, {'alerts': [
            {'id': 'al1', 'event': 'device_offline', 'device_id': 'd1',
             'status': 'open'}]})
        self.cap = {}
        self._page = api._public_action_page

        def _p(title, msg):
            self.cap['title'] = title
            raise SystemExit
        api._public_action_page = _p

    def tearDown(self):
        for n, v in self._saved.items():
            setattr(api, n, v)
        api._public_action_page = self._page

    def _act(self, aid='al1', op='ack', exp=None, sig=None):
        now = int(time.time())
        exp = now + 3600 if exp is None else exp
        sig = api._alert_act_sig(aid, op, exp) if sig is None else sig
        self.cap.clear()
        api._RCTX.environ = {
            'REQUEST_METHOD': 'GET', 'PATH_INFO': '/api/alerts/act',
            'QUERY_STRING': f'a={aid}&op={op}&e={exp}&s={sig}'}
        try:
            api.handle_alert_act()
        except (SystemExit, api.HTTPError):
            pass
        # _public_action_page renders the SUCCESS page too (title
        # 'Done'), so a sentinel default would never be seen. Take
        # the title it actually rendered.
        return self.cap.get('title', '(no page)')

    def _acked(self):
        api._invalidate_load_cache(api.ALERTS_FILE)
        a = (api.load(api.ALERTS_FILE) or {})['alerts'][0]
        return bool(a.get('acknowledged_at'))

    def test_a_fresh_link_still_works(self):
        """The control. Everything below asserts a refusal, and an endpoint that
        refused everything would satisfy all of it while breaking the feature."""
        self.assertEqual('Done', self._act())
        self.assertTrue(self._acked())

    def test_an_expired_link_is_refused(self):
        self.assertEqual('Link expired', self._act(exp=int(time.time()) - 10))
        self.assertFalse(self._acked(), 'the expired link acted anyway')

    def test_editing_the_deadline_does_not_extend_it(self):
        """The whole point of signing it."""
        now = int(time.time())
        stale = now - 10
        sig = api._alert_act_sig('al1', 'ack', stale)
        self.assertEqual('Invalid link', self._act(exp=now + 99999, sig=sig))
        self.assertFalse(self._acked())

    def test_a_missing_deadline_is_refused(self):
        """An old link, from before this release, has no `e` at all. It must
        stop working — tolerating it would leave every already-sent permanent
        link permanent, which is the whole finding."""
        self.cap.clear()
        api._RCTX.environ = {
            'REQUEST_METHOD': 'GET', 'PATH_INFO': '/api/alerts/act',
            'QUERY_STRING': f'a=al1&op=ack&s={api._alert_act_sig("al1", "ack", 0)}'}
        try:
            api.handle_alert_act()
        except (SystemExit, api.HTTPError):
            pass
        self.assertIn(self.cap.get('title'), ('Invalid link', 'Link expired'))
        self.assertFalse(self._acked())

    def test_a_forged_signature_is_refused(self):
        self.assertEqual('Invalid link', self._act(sig='0' * 32))
        self.assertFalse(self._acked())

    def test_a_tag_for_one_op_does_not_authorise_the_other(self):
        now = int(time.time()) + 3600
        ack_sig = api._alert_act_sig('al1', 'ack', now)
        self.assertEqual('Invalid link',
                         self._act(op='resolve', exp=now, sig=ack_sig))

    def test_a_tag_for_one_alert_does_not_authorise_another(self):
        api.save(api.ALERTS_FILE, {'alerts': [
            {'id': 'al1', 'status': 'open'}, {'id': 'al2', 'status': 'open'}]})
        now = int(time.time()) + 3600
        self.assertEqual('Invalid link',
                         self._act(aid='al2', exp=now,
                                   sig=api._alert_act_sig('al1', 'ack', now)))

    def test_the_signature_is_checked_before_the_clock(self):
        """Answering differently for a well-formed expired link and a forged one
        tells an attacker when they have the key right."""
        body = srcpin.py_function((_CGI / 'api.py').read_text(), 'handle_alert_act')
        self.assertLess(body.index('compare_digest'), body.index('Link expired'))


class TestTheMintedLinkCarriesIt(unittest.TestCase):

    def test_both_links_include_a_deadline(self):
        body = srcpin.py_function((_CGI / 'api.py').read_text(),
                                  '_alert_email_ack_block')
        self.assertEqual(2, body.count('&e={_exp}'),
                         'a minted link is missing its deadline')
        self.assertIn('ALERT_ACT_LINK_TTL', body)


if __name__ == '__main__':
    unittest.main()
