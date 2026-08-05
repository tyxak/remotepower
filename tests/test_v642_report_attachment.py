"""v6.4.2: a scheduled report emailed a preview of itself, not the report.

A definition saved with `format: csv` sent only the plain-text summary —
`attachments` was None on every send, because the sweep never read `format` at
all. The mailer had working multipart support the whole time.

Driven through the REAL sweep with the mailer stubbed at the boundary, because
the bug was invisible to any source assertion: every line in the sweep was
correct, one was simply absent.

Run: python3 -m pytest tests/test_v642_report_attachment.py -q
"""
import os
import sys
import tempfile
import unittest
import importlib.util
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
_ROOT = Path(__file__).resolve().parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
_spec = importlib.util.spec_from_file_location("api_v642_att", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestScheduledReportAttachment(unittest.TestCase):
    def setUp(self):
        self.sent = []
        self._orig = {n: getattr(api.smtp_notifier, n) for n in ("send_email",)}
        self._log = api._log_email

        def _send(cfg, recipients, subject, body, extra_headers=None,
                  html_body=None, attachments=None, force=False):
            self.sent.append({"subject": subject, "body": body,
                              "attachments": list(attachments or [])})
            return {"ok": True}
        api.smtp_notifier.send_email = _send
        api._log_email = lambda *a, **k: None
        api.save(api.DEVICES_FILE, {"d1": {"name": "web01", "token": "t", "monitored": True}})

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api.smtp_notifier, n, v)
        api._log_email = self._log

    def _run(self, fmt, name="Monthly board report"):
        self.sent.clear()
        cfg = api.load(api.CONFIG_FILE) or {}
        cfg["report_definitions"] = [{
            "id": "r1", "name": name, "cron": "* * * * *", "enabled": True,
            "recipients": ["finance@example.com"],
            "sections": ["devices", "health"], "format": fmt,
        }]
        api.save(api.CONFIG_FILE, cfg)
        # Clear the once-per-minute claim so the sweep is due.
        api.save(api.DATA_DIR / "report_schedule_state.json", {})
        api._LOAD_CACHE.clear()
        api._maybe_send_report_definitions()
        return self.sent

    def test_csv_definition_attaches_a_csv(self):
        sent = self._run("csv")
        self.assertTrue(sent, "the sweep did not fire")
        atts = sent[0]["attachments"]
        self.assertEqual(len(atts), 1, "expected exactly one attachment")
        fname, ctype, raw = atts[0]
        self.assertTrue(fname.endswith(".csv"), fname)
        self.assertEqual(ctype, "text/csv")
        self.assertTrue(raw, "the attachment is empty")

    def test_json_definition_attaches_json(self):
        atts = self._run("json")[0]["attachments"]
        self.assertEqual(len(atts), 1)
        self.assertTrue(atts[0][0].endswith(".json"))
        self.assertEqual(atts[0][1], "application/json")

    def test_the_readable_summary_is_still_sent(self):
        """The attachment is the artifact; the body is the preview. Replacing
        one with the other would be a regression, not a fix."""
        sent = self._run("csv")
        self.assertTrue(sent[0]["body"].strip(),
                        "the plain-text summary was dropped")

    def test_the_filename_is_derived_from_the_definition_name(self):
        """Otherwise every scheduled report lands in an inbox as the same
        filename and the operator cannot tell them apart."""
        atts = self._run("csv", name="Q3 Board / Exec Review")[0]["attachments"]
        self.assertTrue(atts[0][0].startswith("q3-board-exec-review-"), atts[0][0])

    def test_a_broken_attachment_does_not_cost_the_email(self):
        """The report itself is more valuable than the file — a build failure
        must degrade to today's behaviour, not drop the send."""
        # Patch the MODULE's own global, not api's re-imported alias: the sweep
        # calls its file-local `_fleet_report_csv_bytes`, so stubbing
        # `api._fleet_report_csv_bytes` intercepts nothing. Worth pinning — it
        # is the same shape as stubbing a name the code under test never reads.
        mod = api.reports_handlers_mod
        real = mod._fleet_report_csv_bytes

        def _boom(*a, **k):
            raise RuntimeError("synthetic")
        mod._fleet_report_csv_bytes = _boom
        try:
            sent = self._run("csv")
        finally:
            mod._fleet_report_csv_bytes = real
        self.assertTrue(sent, "a failed attachment build swallowed the whole email")
        self.assertEqual(sent[0]["attachments"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
