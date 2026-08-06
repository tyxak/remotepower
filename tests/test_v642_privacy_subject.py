"""v6.4.2 — data-subject rights get a front door (GDPR Art. 15 / 17).

`handle_user_delete` was `del users[username]; save(USERS_FILE, users)`. It did
not unlink `AVATARS_DIR/<user>.img`, prune the user's token rows, or touch
anything else naming them. And the instance holds personal data well outside
users.json: the Contacts directory (name / role / company / email / phone /
notes), ticket `created_by`/`assignee` and comment authors, time-billing
entries, and audit `actor` fields.

So an EU MSP receiving an Article 17 erasure request from a departed contractor
could delete the account and still be left with their avatar JPEG on disk,
their name on forty ticket comments and every timesheet line, their phone
number in Contacts — and no report that even enumerates where it all is. The
answer had to be assembled by grepping the data directory.

`docs/compliance.md` covers SOC 2 and ISO 27001 and was silent on data-subject
rights, while the product ships an explicitly GDPR-framed PII *scanner* — which
finds regulated data on managed HOSTS, not the data RemotePower itself holds
about people. That gap is precisely why a buyer assumes this side is covered.
"""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-priv-"))

_spec = importlib.util.spec_from_file_location("api_priv", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _Base(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for attr in ("USERS_FILE", "TOKENS_FILE", "CONTACTS_FILE", "TICKETS_FILE",
                     "TIME_ENTRIES_FILE", "AUDIT_LOG_FILE", "AVATARS_DIR"):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
            if attr != "AVATARS_DIR":
                api._invalidate_load_cache(getattr(api, attr))
        api.AVATARS_DIR.mkdir(parents=True, exist_ok=True)
        api.save(api.USERS_FILE, {"admin": {"role": "admin"},
                                  "boss": {"role": "admin"},
                                  "dana": {"role": "viewer",
                                           "email": "dana@acme.io"}})
        api.save(api.TOKENS_FILE, {"t1": {"user": "dana"}, "t2": {"user": "admin"}})
        api.save(api.CONTACTS_FILE, {"c1": {"name": "dana",
                                            "email": "dana@acme.io",
                                            "phone": "+45 12 34 56 78"}})
        api.save(api.TICKETS_FILE, {"tickets": [
            {"id": 1, "created_by": "dana",
             "comments": [{"by": "dana"}, {"by": "admin"}]},
            {"id": 2, "assignee": "dana", "comments": []}]})
        api.save(api.TIME_ENTRIES_FILE, {"entries": [{"user": "dana", "hours": 3}]})
        api.save(api.AUDIT_LOG_FILE, {"entries": [{"actor": "dana"},
                                                  {"actor": "admin"}]})
        (api.AVATARS_DIR / "dana.img").write_bytes(b"x")
        for a in ("USERS_FILE", "TOKENS_FILE", "CONTACTS_FILE", "TICKETS_FILE",
                  "TIME_ENTRIES_FILE", "AUDIT_LOG_FILE"):
            api._invalidate_load_cache(getattr(api, a))
        self.cap = {}
        self.audits = []
        self._orig = {n: getattr(api, n) for n in
                      ("respond", "method", "get_json_body", "audit_log", "_env",
                       "require_admin_auth", "require_admin_or_auditor_auth")}
        api.require_admin_auth = lambda: "admin"
        api.require_admin_or_auditor_auth = lambda: "admin"
        api.audit_log = lambda a, act, detail="", **k: self.audits.append((act, detail))
        self._qs = ""
        _real_env = self._orig["_env"]
        api._env = lambda k, d="": (self._qs if k == "QUERY_STRING"
                                    else _real_env(k, d))

        def _resp(s, b=None):
            self.cap["s"], self.cap["b"] = s, b
            raise api.HTTPError(s, b)
        api.respond = _resp
        api.method = lambda: "GET"

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for a, v in self._files.items():
            setattr(api, a, v)

    def call(self, fn, *a):
        try:
            fn(*a)
        except api.HTTPError:
            pass
        return self.cap.get("b")

    def kinds(self, records):
        return {r["kind"] for r in records}


class TestTheEnumerator(_Base):
    def test_it_finds_every_place_the_person_is_named(self):
        """The Article 15 question — "produce everything you hold on this
        person" — which previously had to be answered by grepping the data
        directory."""
        r = api._subject_scan("dana", "dana@acme.io")
        self.assertEqual(
            self.kinds(r),
            {"account", "avatar", "session", "contact", "ticket", "comment",
             "time entry", "audit entry"})

    def test_it_says_what_can_go_and_what_cannot(self):
        r = api._subject_scan("dana")
        erasable = {x["kind"] for x in r if x["erasable"]}
        retained = {x["kind"] for x in r if not x["erasable"]}
        self.assertEqual(erasable, {"account", "avatar", "session", "contact"})
        self.assertEqual(retained, {"ticket", "comment", "time entry",
                                    "audit entry"})

    def test_it_finds_a_contact_by_email_alone(self):
        """A departed contractor may never have had an account."""
        r = api._subject_scan("", "dana@acme.io")
        self.assertIn("contact", self.kinds(r))

    def test_it_does_not_match_a_different_person(self):
        self.assertEqual(api._subject_scan("someone-else"), [])

    def test_it_counts_rather_than_dumping_records(self):
        """The report enumerates WHERE the data is. Returning forty ticket
        comments verbatim would make the report itself a copy of the personal
        data it is describing."""
        r = [x for x in api._subject_scan("dana") if x["kind"] == "comment"]
        self.assertEqual(r[0]["ref"], "1 comment(s)")

    def test_an_empty_instance_does_not_raise(self):
        for a in ("USERS_FILE", "TOKENS_FILE", "CONTACTS_FILE", "TICKETS_FILE",
                  "TIME_ENTRIES_FILE", "AUDIT_LOG_FILE"):
            api.save(getattr(api, a), {})
            api._invalidate_load_cache(getattr(api, a))
        # …including the avatar, which lives on disk rather than in a store —
        # the first draft of this test left it and then "proved" an empty scan
        # was broken when it was correctly reporting a real file.
        (api.AVATARS_DIR / "dana.img").unlink()
        self.assertEqual(api._subject_scan("dana"), [])

    def test_the_endpoint_needs_a_subject(self):
        self.call(api.handle_privacy_subject)
        self.assertEqual(self.cap["s"], 400)

    def test_the_endpoint_reports_counts_and_caveats(self):
        self._qs = "who=dana"
        r = self.call(api.handle_privacy_subject)
        self.assertEqual(r["erasable"], 4)
        self.assertEqual(r["retained"], 4)
        self.assertTrue(any("hash-chained" in n for n in r["notes"]))
        self.assertTrue(any("Backups" in n for n in r["notes"]))

    def test_reading_the_report_is_itself_audited(self):
        """A subject-access report is a privileged read of personal data."""
        self._qs = "who=dana"
        self.call(api.handle_privacy_subject)
        self.assertIn("privacy_subject_report", [a for a, _ in self.audits])

    def test_an_auditor_may_read_it(self):
        """The auditor role exists for exactly this kind of question."""
        seen = []
        api.require_admin_or_auditor_auth = lambda: (seen.append(1), "a")[1]
        self._qs = "who=dana"
        self.call(api.handle_privacy_subject)
        self.assertEqual(len(seen), 1)


class TestErasure(_Base):
    def erase(self, **kw):
        api.method = lambda: "POST"
        body = {"who": "dana", "confirm": "dana"}
        body.update(kw)
        api.get_json_body = lambda: body
        return self.call(api.handle_privacy_erase)

    def test_it_removes_what_can_be_removed(self):
        r = self.erase(email="dana@acme.io")
        self.assertTrue(r["ok"])
        api._invalidate_load_cache(api.USERS_FILE)
        self.assertNotIn("dana", api.load(api.USERS_FILE))
        self.assertFalse((api.AVATARS_DIR / "dana.img").exists())
        api._invalidate_load_cache(api.TOKENS_FILE)
        self.assertEqual(list(api.load(api.TOKENS_FILE)), ["t2"])
        api._invalidate_load_cache(api.CONTACTS_FILE)
        self.assertEqual(api.load(api.CONTACTS_FILE), {})

    def test_it_does_not_touch_the_audit_log(self):
        """It is hash-chained. Rewriting an entry destroys the tamper-evidence
        that makes the log evidence at all — and retaining it is the lawful
        answer, not a limitation to work around."""
        self.erase()
        api._invalidate_load_cache(api.AUDIT_LOG_FILE)
        self.assertEqual(len((api.load(api.AUDIT_LOG_FILE) or {})["entries"]), 2)

    def test_it_does_not_touch_ticket_or_time_records(self):
        self.erase()
        api._invalidate_load_cache(api.TICKETS_FILE)
        self.assertEqual(len((api.load(api.TICKETS_FILE) or {})["tickets"]), 2)
        api._invalidate_load_cache(api.TIME_ENTRIES_FILE)
        self.assertEqual(len((api.load(api.TIME_ENTRIES_FILE) or {})["entries"]), 1)

    def test_it_reports_exactly_what_it_did_not_do(self):
        """Reporting a clean sweep it did not perform is the failure mode this
        whole feature exists to avoid."""
        r = self.erase()
        self.assertEqual({x["kind"] for x in r["retained"]},
                         {"ticket", "comment", "time entry", "audit entry"})

    def test_it_warns_that_backups_still_hold_the_data(self):
        self.assertTrue(any("Backups" in n for n in self.erase()["notes"]))

    def test_it_says_the_erasure_itself_is_logged(self):
        """The audit entry names the subject — it is the evidence the request
        was honoured, and a DPO will ask for it. Better said up front than
        discovered later."""
        self.assertTrue(any("recorded in the audit log" in n
                            for n in self.erase()["notes"]))
        self.assertIn("privacy_erase", [a for a, _ in self.audits])

    def test_confirmation_must_repeat_the_subject(self):
        self.erase(confirm="yes")
        self.assertEqual(self.cap["s"], 400)
        api._invalidate_load_cache(api.USERS_FILE)
        self.assertIn("dana", api.load(api.USERS_FILE))

    def test_it_refuses_to_erase_the_caller(self):
        self.erase(who="admin", confirm="admin")
        self.assertEqual(self.cap["s"], 400)

    def test_it_refuses_to_erase_the_last_admin(self):
        """An erasure request is not a reason to lock everyone out."""
        api.save(api.USERS_FILE, {"solo": {"role": "admin"},
                                  "viewer": {"role": "viewer"}})
        api._invalidate_load_cache(api.USERS_FILE)
        api.require_admin_auth = lambda: "someone-else"
        self.erase(who="solo", confirm="solo")
        self.assertEqual(self.cap["s"], 400)

    def test_erasing_someone_with_nothing_stored_is_not_an_error(self):
        r = self.erase(who="ghost", confirm="ghost")
        self.assertTrue(r["ok"])
        self.assertEqual(r["erased"], [])

    def test_it_is_admin_only(self):
        seen = []
        api.require_admin_auth = lambda: (seen.append(1), "admin")[1]
        self.erase()
        self.assertEqual(len(seen), 1)

    def test_it_rejects_a_GET(self):
        api.method = lambda: "GET"
        api.get_json_body = lambda: {}
        self.call(api.handle_privacy_erase)
        self.assertEqual(self.cap["s"], 405)


class TestDeletingAUserCleansUpAfterItself(_Base):
    def test_it_unlinks_the_avatar_and_the_sessions(self):
        """`del users[username]; save(...)` left both behind. The tokens were
        inert — verify_token returns None once the user record is gone — but
        both are still storage naming a person who asked to be removed."""
        api.method = lambda: "DELETE"
        r = self.call(api.handle_user_delete, "dana")
        self.assertTrue(r["ok"])
        self.assertFalse((api.AVATARS_DIR / "dana.img").exists())
        api._invalidate_load_cache(api.TOKENS_FILE)
        self.assertEqual(list(api.load(api.TOKENS_FILE)), ["t2"])
        self.assertIn("avatar", r["also_removed"])

    def test_it_points_at_what_survives(self):
        """An operator who deletes an account and is told nothing reasonably
        assumes nothing is left."""
        api.method = lambda: "DELETE"
        r = self.call(api.handle_user_delete, "dana")
        self.assertIn("/api/privacy/subject", r["note"])
        self.assertIn("retained", r["note"])

    def test_the_existing_guards_still_hold(self):
        api.method = lambda: "DELETE"
        api.require_admin_auth = lambda: "dana"
        self.call(api.handle_user_delete, "dana")
        self.assertEqual(self.cap["s"], 400)     # cannot delete yourself


class TestWiring(unittest.TestCase):
    def test_the_routes_resolve(self):
        exact = api._build_exact_routes()
        self.assertIn(("GET", "/api/privacy/subject"), exact)
        self.assertIn(("POST", "/api/privacy/erase"), exact)

    def test_the_handlers_live_in_the_bound_module(self):
        """api.py is at the inline-handler ratchet ceiling."""
        self.assertEqual(api.handle_privacy_subject.__module__,
                         "attention_handlers")

    def test_the_compliance_doc_covers_subject_rights(self):
        """It covered SOC 2 and ISO 27001 and was silent here, while the
        product ships a GDPR-framed PII scanner — which is exactly why a buyer
        assumes this side exists."""
        p = ROOT / "docs" / "compliance.md"
        if not p.exists():
            self.skipTest("excluded from this tree")
        txt = p.read_text()
        for word in ("data-subject rights", "erasure", "/api/privacy/subject",
                     "17(3)(b)"):
            with self.subTest(word=word):
                self.assertIn(word, txt.lower() if word.islower() else txt)


if __name__ == "__main__":
    unittest.main()
