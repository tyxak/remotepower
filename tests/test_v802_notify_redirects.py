"""A destination whose receiver answers every delivery with a redirect is a failing destination (8.0.2).

The opener the product delivers with refuses redirects (a 3xx must never carry the alert, and the token in the request, to another address), so a 301, a
302 or a 307 reaches `_dispatch_one_webhook` as an HTTPError. It filed the delivery in the dead-letter list as a permanent failure and logged
`HTTP 302`. The reader of that log line that decides whether the destination is failing (`_delivery_outcome`) took any status under 400 for
"delivered", so two readers of one line disagreed: five deliveries went to the dead-letter list and the destination was never marked, and no alert
was raised. That is what an `http://` address in front of an https-only service does (it answers 301), and what a receiver behind a sign-in proxy
does (302). Nobody needs to be hostile for the alerts of that destination to stop in silence.

Driven through the real fan-out to a real receiver on a local port, with the product's own opener (`_ssrf_safe_opener`, which refuses the redirect), so the
3xx comes out of urllib as an HTTPError and not out of a made-up error:

* 301, 302, 303, 307 and 308 each count as a failed delivery: the third raises the alert, the dead-letter list files them, and the Settings card marks the
  destination;
* a 2xx is delivered (200, 201, 202, 204) and 4xx and 5xx are failures, as before (the controls);
* the two readers of a delivery agree on every status the receiver can answer: the dead-letter list files exactly the deliveries the outcome calls failed.
"""
import http.server
import importlib.util
import os
import sys
import tempfile
import threading
import unittest
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / 'server' / 'cgi-bin'
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(Path(__file__).resolve().parent))
os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-v802-notify-redirect-'))
_spec = importlib.util.spec_from_file_location('api_v802_notify_redirect', _CGI / 'api.py')
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)

EVENT = 'server_disk_low'
KEY = 'wh:wh_r'
REDIRECTS = (301, 302, 303, 307, 308)

_WARNINGS = None


def setUpModule():
    # urllib's HTTPError of a refused delivery wraps a real response, and the delivery code lets it be collected without closing it: the ResourceWarning
    # that says so is about that code and not about what is measured here, and a status per delivery would print a page of them.
    global _WARNINGS
    _WARNINGS = warnings.catch_warnings()
    _WARNINGS.__enter__()
    warnings.simplefilter('ignore', ResourceWarning)


def tearDownModule():
    _WARNINGS.__exit__(None, None, None)


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_a):
        pass

    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length') or 0))
        self.send_response(self.server.answer)
        if 300 <= self.server.answer < 400:
            self.send_header('Location', 'http://127.0.0.1:1/login')
        self.send_header('Content-Length', '0')
        self.end_headers()


class World:
    """A receiver answering `status` to every POST, the real fan-out in front of it, and a clean store."""

    def __init__(self, status):
        self.status = status

    def __enter__(self):
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), _Handler)
        self.server.answer = self.status
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        dest = {'id': 'wh_r', 'name': 'Chat ops', 'url': f'http://127.0.0.1:{self.server.server_address[1]}/hook', 'format': 'generic', 'enabled': True}
        api.save(api.CONFIG_FILE, {'webhook_urls': [dest], 'webhook_allow_loopback': True})
        for f, empty in ((api.ALERTS_FILE, {'alerts': []}), (api.NOTIFY_HEALTH_FILE, {}), (api.WEBHOOK_LOG_FILE, {'entries': []}),
                         (api.WEBHOOK_DLQ_FILE, {'entries': []}), (api.WEBHOOK_RATELIMIT_FILE, {}), (api.MAINT_FILE, {'windows': []})):
            api.save(f, empty)
        api._LOAD_CACHE.clear()
        return self

    def __exit__(self, *_exc):
        self.server.shutdown()
        self.server.server_close()
        for f, empty in ((api.CONFIG_FILE, {}), (api.ALERTS_FILE, {'alerts': []}), (api.NOTIFY_HEALTH_FILE, {})):
            api.save(f, empty)
        api._LOAD_CACHE.clear()
        return False

    def events(self, n):
        for _ in range(n):
            api._LOAD_CACHE.clear()
            api.fire_webhook(EVENT, {'name': 'server', 'percent': 97})
        api._LOAD_CACHE.clear()

    def streak(self):
        api._LOAD_CACHE.clear()
        return ((api.load(api.NOTIFY_HEALTH_FILE) or {}).get(KEY) or {}).get('fails', 0)

    def dead_letters(self):
        api._LOAD_CACHE.clear()
        return (api.load(api.WEBHOOK_DLQ_FILE) or {}).get('entries', [])

    def alerts(self):
        api._LOAD_CACHE.clear()
        return [a for a in (api.load(api.ALERTS_FILE) or {}).get('alerts', [])
                if a.get('event') == 'notify_dest_failing' and not a.get('resolved_at')]


class TestEachRedirectIsAFailure(unittest.TestCase):
    def test_every_redirect_status_raises_the_alert_on_the_third_delivery(self):
        for status in REDIRECTS:
            with self.subTest(status=status), World(status) as w:
                w.events(2)
                self.assertEqual((w.streak(), len(w.alerts())), (2, 0), 'two are not yet news')
                w.events(1)
                (alert,) = w.alerts()
                self.assertIn(f'HTTP {status}', alert['payload']['detail'])
                self.assertEqual(api._notify_failing_destinations().get(KEY, (0,))[0], w.streak(), 'the Settings card marks it')
                self.assertGreaterEqual(w.streak(), 3)

    def test_the_dead_letter_list_holds_the_same_deliveries_the_destination_failed(self):
        """Three events, and the alert about them, which goes to this destination too and is refused the same way: the four are in the list
        and the four are the streak."""
        with World(302) as w:
            w.events(3)
            self.assertEqual([e['event'] for e in w.dead_letters()], [EVENT, EVENT, EVENT, 'notify_dest_failing'])
            self.assertEqual(w.streak(), 4)

    def test_the_redirect_is_what_the_real_library_raised(self):
        """The control for the setup: the dead-letter entry names the status and its reason, as urllib's HTTPError does."""
        with World(302) as w:
            w.events(1)
            (entry,) = w.dead_letters()
            self.assertEqual(entry['error'], 'HTTP 302: Found')


class TestTheControls(unittest.TestCase):
    def after_three(self, status):
        with World(status) as w:
            w.events(3)
            return w.streak(), len(w.dead_letters()), len(w.alerts())

    def test_a_2xx_is_delivered_and_writes_nothing(self):
        for status in (200, 201, 202, 204):
            self.assertEqual(self.after_three(status), (0, 0, 0), status)

    def test_a_4xx_and_a_5xx_fail_as_before(self):
        """Three events and the alert about them, which the same receiver refuses too: four failed deliveries, one alert."""
        for status in (400, 401, 404, 429, 500, 502, 503):
            self.assertEqual(self.after_three(status), (4, 4, 1), status)


class TestTheTwoReadersOfOneDeliveryAgree(unittest.TestCase):
    STATUSES = (200, 201, 202, 203, 204, 205, 206, 300, 301, 302, 303, 304, 305, 307, 308, 400, 401, 403, 404, 410, 418, 429, 500, 501, 502, 503, 504)

    def test_on_every_status_the_dead_letter_list_files_what_the_outcome_calls_failed(self):
        """One delivery per status, to a real receiver. urllib raises an HTTPError for everything that is not a 2xx (the redirects among them, since the
        opener refuses to follow them), and `_dispatch_one_webhook` files each of those in the dead-letter list. `_delivery_outcome` reads the same
        delivery from the log. Over the statuses a receiver can answer they call the same ones failed."""
        seen = {}
        for status in self.STATUSES:
            with World(status) as w:
                w.events(1)
                seen[status] = (len(w.dead_letters()), w.streak())
        self.assertGreaterEqual(len(seen), 25, 'the derivation measured nothing')
        for status, (filed, failed) in seen.items():
            self.assertEqual(filed, failed, f'{status}: the dead-letter list and the failure streak disagree about one delivery')
            self.assertEqual(failed, 0 if 200 <= status < 300 else 1, f'{status}: delivered is a 2xx and nothing else')

    def test_the_reading_of_one_delivery_with_a_redirect_in_it(self):
        read = api._delivery_outcome
        self.assertEqual(read([(302, 'HTTP 302 [generic]: Found')]), (False, 'HTTP 302 [generic]: Found'))
        self.assertEqual(read([('302', 'HTTP 302 [generic]: Found')]), (False, 'HTTP 302 [generic]: Found'))
        self.assertEqual(read([(200, 'OK (200) [generic]')]), (True, ''))
        self.assertEqual(read([(204, 'OK (204) [generic]')]), (True, ''))

    def test_the_edges_of_the_ranges(self):
        read = api._delivery_outcome
        for status, delivered in ((199, False), (200, True), (299, True), (300, False), (399, False), (400, False), (599, False)):
            self.assertEqual(read([(status, 'x')])[0], delivered, status)

    def test_what_was_not_tried_is_still_neither(self):
        """The statuses of a delivery that was not attempted are words, not numbers, and stay out of the reading."""
        read = api._delivery_outcome
        for word in ('filtered', 'digest', 'dry-run', 'suppressed', 'disabled'):
            self.assertIsNone(read([(word, 'x')]), word)


if __name__ == '__main__':
    unittest.main()
