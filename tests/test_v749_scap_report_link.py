#!/usr/bin/env python3
"""The SCAP report opens from a one-minute link that keeps its own sandbox (7.4.9, web client audit W1).

The report is HTML supplied by the host's agent. The server answers with a Content-Security-Policy that includes `sandbox`, so a
compromised host cannot run script or reach the dashboard from it. The page fetched the report with the X-Token header and opened
it as a `blob:` URL, which takes the dashboard's origin and policy and drops that sandbox: with an absolute same-origin script
reference in the report the dashboard's own code loaded in that tab, and a click on an agent-supplied `data-action` link called the
application with the operator's session.

The page now asks `POST /api/scap/<id>/report-ticket` (signed in, host scope checked) for a link, and opens that link, so the
response's own headers apply. The link is signed with a key derived from the install's audit key, names the host, and is good for
one minute.
"""
import gzip
import importlib.util
import io
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v749-scap-"))
_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import srcpin  # noqa: E402

_spec = importlib.util.spec_from_file_location("api_v749_scap", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)                      # type: ignore[arg-type]
_spec.loader.exec_module(api)                                     # type: ignore[union-attr]

SC = api.scap_handlers_mod       # the module that holds the link helpers; api re-binds only the handlers
DEV = "h1"
HTML = b'<html><style>td{color:red}</style><script src="/static/js/app.js"></script><a data-action="x">hi</a></html>'


class _Captured(SystemExit):
    def __init__(self, status, body):
        super().__init__(0)
        self.status, self.body = status, body


class TestTheLink(unittest.TestCase):

    def test_a_fresh_link_for_the_host_is_accepted(self):
        now = int(time.time())
        t = SC.scap_ticket_make(DEV, now)
        self.assertTrue(SC.scap_ticket_ok(DEV, t, now))
        self.assertTrue(SC.scap_ticket_ok(DEV, t, now + 59))

    def test_an_expired_link_is_refused(self):
        now = int(time.time())
        t = SC.scap_ticket_make(DEV, now)
        self.assertFalse(SC.scap_ticket_ok(DEV, t, now + SC.SCAP_TICKET_TTL + 1))

    def test_a_link_is_for_one_host(self):
        now = int(time.time())
        self.assertFalse(SC.scap_ticket_ok("h2", SC.scap_ticket_make(DEV, now), now))

    def test_a_tampered_or_forged_link_is_refused(self):
        now = int(time.time())
        exp, sig = SC.scap_ticket_make(DEV, now).split(".")
        for bad in (f"{int(exp) + 30}.{sig}", f"{exp}.{sig[:-1]}0", f"{exp}.", f".{sig}", f"{exp}.{'0' * 64}"):
            with self.subTest(bad=bad[:30]):
                self.assertFalse(SC.scap_ticket_ok(DEV, bad, now))

    def test_a_link_with_an_expiry_far_in_the_future_is_refused(self):
        now = int(time.time())
        exp = now + 10 ** 6
        import hashlib
        import hmac
        sig = hmac.new(SC._ticket_key(), f"{DEV}:{exp}".encode(), hashlib.sha256).hexdigest()
        self.assertFalse(SC.scap_ticket_ok(DEV, f"{exp}.{sig}", now), "a validly signed link cannot outlive the window")

    def test_hostile_values_do_not_raise(self):
        for bad in (None, "", "abc", "é.é", "1e400.x", "9" * 400 + ".x", "-1.x", "\ud83d.x", 5, b"x", "." * 5000):
            with self.subTest(bad=repr(bad)[:20]):
                self.assertFalse(SC.scap_ticket_ok(DEV, bad))


class _Handlers(unittest.TestCase):

    def setUp(self):
        self._saved = {k: getattr(api, k) for k in ("respond", "verify_token")}
        self._env = dict(os.environ)
        self._stdout = sys.stdout
        now = int(time.time())
        api.save(api.DEVICES_FILE, {DEV: {"id": DEV, "name": "h1", "hostname": "h1", "token": "t", "last_seen": now,
                                          "enrolled": now, "tags": [], "group": "", "sysinfo": {}}})
        api.save(api.USERS_FILE, {"viewer1": {"role": "viewer", "password_hash": "x"}})
        api.save(api.TOKENS_FILE, {api._token_hash("tok-v"): {"user": "viewer1", "created": now, "ttl": 86400, "last_seen": now}})
        api.SCAP_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        (api.SCAP_REPORTS_DIR / f"{DEV}.html.gz").write_bytes(gzip.compress(HTML))
        api._LOAD_CACHE.clear()

        def fake(status, data, *a, **k):
            raise _Captured(status, data)
        setattr(api, "respond", fake)

    def tearDown(self):
        sys.stdout = self._stdout
        for k, v in self._saved.items():
            setattr(api, k, v)
        os.environ.clear()
        os.environ.update(self._env)
        api._LOAD_CACHE.clear()
        try:
            (api.SCAP_REPORTS_DIR / f"{DEV}.html.gz").unlink()
        except OSError:
            pass

    def request(self, verb, query="", token=None):
        os.environ.update({"REQUEST_METHOD": verb, "PATH_INFO": f"/api/scap/{DEV}/report", "QUERY_STRING": query,
                           "CONTENT_LENGTH": "0"})
        os.environ.pop("HTTP_X_TOKEN", None)
        if token:
            os.environ["HTTP_X_TOKEN"] = token
        api._LOAD_CACHE.clear()

    def download(self, query="", token=None, dev=DEV):
        """(status, headers text, body bytes) of the report handler; it writes a CGI response itself on success."""
        self.request("GET", query, token)
        raw = io.BytesIO()
        wrapper = io.TextIOWrapper(raw, encoding="utf-8", write_through=True)
        sys.stdout = wrapper
        status = 200
        try:
            api.handle_scap_report_download(dev)
        except _Captured as c:
            status = c.status
        except SystemExit:
            pass
        finally:
            wrapper.flush()
            sys.stdout = self._stdout
        data = raw.getvalue()
        wrapper.detach()
        if status != 200:
            return status, "", b""
        head, _, body = data.partition(b"\n\n")
        return 200, head.decode(), body

    def ticket(self, token="tok-v"):
        self.request("POST", "", token)
        try:
            api.handle_scap_report_ticket(DEV)
        except _Captured as c:
            return c.status, c.body
        self.fail("no response")


class TestTheDownload(_Handlers):

    def test_a_valid_link_serves_the_report_with_its_own_sandbox_and_no_session(self):
        status, head, body = self.download("ticket=" + SC.scap_ticket_make(DEV))
        self.assertEqual(status, 200)
        self.assertEqual(body, HTML)
        csp = [ln for ln in head.splitlines() if ln.lower().startswith("content-security-policy")]
        self.assertEqual(len(csp), 1, head)
        self.assertIn("sandbox", csp[0])
        self.assertIn("default-src 'none'", csp[0])
        self.assertIn("X-Frame-Options: DENY", head)

    def test_a_bad_link_is_a_403_and_serves_nothing(self):
        now = int(time.time())
        for q in ("ticket=garbage", "ticket=" + SC.scap_ticket_make("h2", now), "ticket=" + SC.scap_ticket_make(DEV, now - 3600)):
            with self.subTest(q=q[:30]):
                status, _, body = self.download(q)
                self.assertEqual(status, 403)
                self.assertEqual(body, b"")

    def test_without_a_link_the_session_is_still_required(self):
        self.assertEqual(self.download()[0], 401)
        status, head, body = self.download(token="tok-v")
        self.assertEqual((status, body), (200, HTML))


class TestTheTicketRoute(_Handlers):

    def test_it_needs_a_signed_in_caller(self):
        self.assertEqual(self.ticket(token=None)[0], 401)
        self.assertEqual(self.ticket(token="not-a-session")[0], 401)

    def test_a_signed_in_caller_gets_a_link_that_opens_the_report(self):
        status, body = self.ticket()
        self.assertEqual(status, 200)
        self.assertEqual(body["expires_in"], SC.SCAP_TICKET_TTL)
        self.assertTrue(body["url"].startswith(f"/api/scap/{DEV}/report?ticket="))
        s2, _, html = self.download(body["url"].split("?", 1)[1])
        self.assertEqual((s2, html), (200, HTML))

    def test_a_host_with_no_report_is_a_404(self):
        (api.SCAP_REPORTS_DIR / f"{DEV}.html.gz").unlink()
        self.assertEqual(self.ticket()[0], 404)

    def test_both_routes_are_registered(self):
        rows = {(r[1], r[4]) for r in api._PATTERN_ROUTE_DEFS if r[2] == "/api/scap/"}
        self.assertIn((("GET",), "handle_scap_report_download"), rows)
        self.assertIn((("POST",), "handle_scap_report_ticket"), rows)


class TestThePageOpensTheLink(unittest.TestCase):

    def test_the_report_is_not_opened_as_a_blob(self):
        js = (_ROOT / "server" / "html" / "static" / "js" / "app-compliance.js").read_text(encoding="utf-8")
        body = srcpin.js_function(js, "downloadScapReport")
        self.assertNotIn("createObjectURL", body)
        self.assertNotIn("blob", body.lower().replace("// ", ""))
        self.assertIn("/report-ticket", body)
        self.assertIn("location.replace(r.url)", body)
        self.assertIn("w.opener = null", body)


if __name__ == "__main__":
    unittest.main()
