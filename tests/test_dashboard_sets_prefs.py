#!/usr/bin/env python3
"""8.0.0: named dashboard layouts ("sets") in the account's ui_prefs, as the server keeps them.

A set is {id, name, w}: `w` lists only the widgets the set shows, in order, as 'key' or 'key:size' (the size only when it is not the
widget's own default, which the client knows). That is what keeps eight sets to a few hundred bytes each, because the whole prefs
document is dropped when it passes MAX_UI_PREFS_BYTES (16 KB), and a user's views, layout and signature live in the same document.
`dashboard_set` names the set in use.

The client posts the whole document on every save, so everything it sends has to be checked here: unknown widgets, repeats, sizes
that are not one of the three, ids and names of the wrong kind, too many sets, too many bytes. And a bad set must cost the rest of
the document nothing.
"""
import json
import os
import random
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_v622_alert_params import ROOT, api  # noqa: E402

KEYS = list(api.DASHBOARD_WIDGETS)
S = api._sanitise_ui_prefs


def _set(sid="a1", name="Security", w=None):
    return {"id": sid, "name": name, "w": ["attseverity", "cves:lg"] if w is None else w}


class TestShape(unittest.TestCase):
    def test_a_set_keeps_its_widgets_in_order_with_the_sizes_that_were_chosen(self):
        out = S({"dashboard_sets": [_set(w=["cves:lg", "tickets", "offline:sm", "updates:md"])]})
        self.assertEqual(out["dashboard_sets"], [{"id": "a1", "name": "Security", "w": ["cves:lg", "tickets", "offline:sm", "updates:md"]}])

    def test_unknown_widgets_repeats_and_odd_sizes_are_dropped(self):
        out = S({"dashboard_sets": [_set(w=["cves", "cves:lg", "nope", "tickets:huge", 5, None, ["x"], {"k": 1}, "offline:", ":sm", "",
                                           "updates:SM", "drift:lg:md"])]})
        # 'cves' once (the first); 'tickets', 'updates' (the size is case-sensitive) and 'drift' (a size of "lg:md") keep the widget and
        # lose the size they sent; 'offline:' has no size; the unknown, the non-strings and the empty ones are gone
        self.assertEqual(out["dashboard_sets"][0]["w"], ["cves", "tickets", "offline", "updates", "drift"])

    def test_every_widget_the_page_has_is_accepted(self):
        out = S({"dashboard_sets": [_set(w=KEYS)]})
        self.assertEqual(out["dashboard_sets"][0]["w"], KEYS)
        self.assertEqual(len(KEYS), 71, 'the catalog this was written against; a new widget changes the byte budget below')

    def test_ids_must_be_short_lower_case_and_unique(self):
        # "123", "1e5" and "0x1f" start with a digit: the click dispatcher passes data-arg through Number() when it can, so an id
        # like that would reach the handler as a number and never match the layout
        bad = ["", "A1", "a b", "a-b", "a_b", "x" * 13, "é", "a1\n", None, 5, ["a1"], {"id": "a1"}, "1a", "123", "0", "1e5", "0x1f", "9" * 12]
        for sid in bad:
            with self.subTest(id=sid):
                self.assertNotIn("dashboard_sets", S({"dashboard_sets": [_set(sid=sid)]}))
        out = S({"dashboard_sets": [_set("a1", "One"), _set("a1", "Two"), _set("b2", "Three")]})
        self.assertEqual([s["id"] for s in out["dashboard_sets"]], ["a1", "b2"], 'the second set with the same id is dropped')

    def test_an_id_the_page_makes_is_one_the_server_keeps(self):
        # app-dashsets.js: 's' + the first six characters of a random base-36 string
        rnd = random.Random(1)
        for _ in range(500):
            sid = "s" + "".join(rnd.choice("0123456789abcdefghijklmnopqrstuvwxyz") for _ in range(rnd.randint(0, 6)))
            self.assertEqual(S({"dashboard_sets": [_set(sid=sid)]})["dashboard_sets"][0]["id"], sid)

    def test_names_are_trimmed_cut_and_required(self):
        out = S({"dashboard_sets": [_set("a1", "  Night shift  "), _set("b2", "x" * 100), _set("c3", "   "), _set("d4", ""), _set("e5", None)]})
        names = {s["id"]: s["name"] for s in out["dashboard_sets"]}
        self.assertEqual(names["a1"], "Night shift")
        self.assertEqual(len(names["b2"]), api.MAX_UI_PREFS_DASH_SET_NAME)
        self.assertNotIn("c3", names)
        self.assertNotIn("d4", names)
        # a name is text: it is stored as typed and escaped where it is drawn
        self.assertEqual(S({"dashboard_sets": [_set("a1", "<b>x</b>")]})["dashboard_sets"][0]["name"], "<b>x</b>")

    def test_a_set_with_no_widgets_is_allowed_and_a_w_of_the_wrong_kind_is_empty(self):
        for w in ([], None, "cves", {"cves": 1}, 5):
            with self.subTest(w=w):
                out = S({"dashboard_sets": [{"id": "a1", "name": "Empty", "w": w}]})
                self.assertEqual(out["dashboard_sets"][0]["w"], [])

    def test_the_set_in_use_must_be_one_that_survived(self):
        doc = {"dashboard_sets": [_set("a1"), _set("b2", "Patching")]}
        self.assertEqual(S({**doc, "dashboard_set": "b2"})["dashboard_set"], "b2")
        for active in ("zz", "", None, 7, ["a1"], {"a1": 1}, "A1"):
            with self.subTest(active=active):
                self.assertNotIn("dashboard_set", S({**doc, "dashboard_set": active}))
        self.assertNotIn("dashboard_set", S({"dashboard_set": "a1"}), 'with no sets there is nothing to be in use')
        self.assertNotIn("dashboard_set", S({"dashboard_sets": [_set("a1", "")], "dashboard_set": "a1"}), 'a set that was dropped cannot be active')

    def test_the_kinds_the_client_could_send_instead_of_a_list_are_ignored(self):
        for bad in (None, 1, "x", {}, {"id": "a1"}, True):
            with self.subTest(sets=bad):
                self.assertEqual(S({"dashboard_sets": bad, "temp_unit": "f"}), {"temp_unit": "f"})
        self.assertEqual(S({"dashboard_sets": [None, 1, "x", [], _set()]})["dashboard_sets"], [_set()])

    def test_neither_key_is_taken_for_a_table(self):
        out = S({"dashboard_set": {"density": "compact"}, "dashboard_sets": {"density": "compact"}})
        self.assertEqual(out, {}, 'a dict under these names must not become a per-table entry')

    def test_the_saved_layout_and_the_sets_are_independent(self):
        out = S({"dashboard": [{"key": "cves", "on": True, "size": "lg"}], "dashboard_sets": [_set()], "dashboard_set": "a1"})
        self.assertEqual(out["dashboard"], [{"key": "cves", "on": True, "size": "lg"}])
        self.assertEqual(out["dashboard_set"], "a1")
        self.assertEqual(S({"dashboard_sets": [_set()]}).get("dashboard"), None, 'no sets-to-layout copying on the server')


class TestBudget(unittest.TestCase):
    def test_no_more_than_eight_sets(self):
        out = S({"dashboard_sets": [_set("s%d" % i, "S%d" % i, ["cves"]) for i in range(20)]})
        self.assertEqual(len(out["dashboard_sets"]), api.MAX_UI_PREFS_DASH_SETS)
        self.assertEqual([s["id"] for s in out["dashboard_sets"]], ["s%d" % i for i in range(8)], 'the first eight, in order')

    def test_the_sets_together_stay_inside_their_bytes_and_the_first_ones_win(self):
        full = [_set("s%d" % i, "N" * 40, KEYS[:] ) for i in range(8)]
        out = S({"dashboard_sets": full})["dashboard_sets"]
        self.assertLess(len(out), 8, 'eight full sets do not fit; the rest are dropped, not squeezed')
        self.assertGreaterEqual(len(out), 2)
        self.assertEqual([s["id"] for s in out], ["s%d" % i for i in range(len(out))])
        self.assertLessEqual(len(json.dumps(out, ensure_ascii=False, separators=(',', ':'))), api.MAX_UI_PREFS_DASH_SET_CHARS)

    def test_a_list_that_fits_by_the_pages_count_is_kept_whole(self):
        # The page counts compact JSON (JSON.stringify) and refuses what does not fit, so the server must count the same way: a list that
        # the page accepted and the server dropped would be lost at the next save. Build one that fits with a few characters to spare.
        def compact(s):
            return len(json.dumps({"id": s["id"], "name": s["name"], "w": s["w"]}, ensure_ascii=False, separators=(",", ":")))
        sets = [_set("s%d" % i, "N" * 40, KEYS[:]) for i in range(3)]
        used = sum(compact(s) for s in sets)
        filler = _set("s3", "Filler", [])
        k = 0
        while used + compact(_set("s3", "Filler", KEYS[:k + 1])) <= api.MAX_UI_PREFS_DASH_SET_CHARS and k < len(KEYS):
            k += 1
        filler["w"] = KEYS[:k]
        sets.append(filler)
        total = sum(compact(s) for s in sets)
        self.assertLessEqual(total, api.MAX_UI_PREFS_DASH_SET_CHARS)
        self.assertGreater(total, api.MAX_UI_PREFS_DASH_SET_CHARS - 20, 'control: the list sits right at the limit')
        spaced = sum(len(json.dumps(s, ensure_ascii=False)) for s in sets)
        self.assertGreater(spaced, api.MAX_UI_PREFS_DASH_SET_CHARS, 'control: counted with the spaces json.dumps adds, the same list would not fit')
        out = S({"dashboard_sets": sets})["dashboard_sets"]
        self.assertEqual([s["id"] for s in out], ["s0", "s1", "s2", "s3"], 'every layout the page accepted is kept')
        self.assertEqual(out[3]["w"], filler["w"])

    def test_eight_sets_of_a_realistic_size_all_fit(self):
        realistic = [_set("s%d" % i, "Layout number %d" % i, KEYS[i:i + 18]) for i in range(8)]
        out = S({"dashboard_sets": realistic})["dashboard_sets"]
        self.assertEqual(len(out), 8, 'a layout of eighteen widgets is typical: all eight must fit')

    def test_the_sets_cannot_tip_a_document_that_the_other_fields_leave_room_for(self):
        # the largest values the other fields take apart from the views: the signature and the post-it
        doc = {"signature": "s" * 8000, "postit": "p" * 2000, "default_ssh_username": "operator",
               "dashboard_sets": [_set("s%d" % i, "N" * 40, KEYS[:]) for i in range(8)], "dashboard_set": "s0"}
        out = S(doc)
        self.assertNotEqual(out, {}, 'the document was dropped whole: the sets pushed it over MAX_UI_PREFS_BYTES')
        self.assertEqual(len(out["signature"]), 8000)
        self.assertEqual(len(out["postit"]), 2000)
        self.assertLess(len(json.dumps(out)), api.MAX_UI_PREFS_BYTES)

    def test_names_in_chinese_cost_six_bytes_a_character_in_the_document_and_it_still_fits(self):
        name = "界" * 40
        doc = {"signature": "s" * 8000, "postit": "p" * 2000,
               "dashboard_sets": [_set("s%d" % i, name, KEYS[:i * 4]) for i in range(8)], "dashboard_set": "s0"}
        out = S(doc)
        self.assertNotEqual(out, {}, 'the document was dropped whole')
        self.assertEqual(len(out["dashboard_sets"]), 8)
        self.assertLess(len(json.dumps(out)), api.MAX_UI_PREFS_BYTES, 'measured the way the server measures the document')

    def test_the_budget_figures_hold_together(self):
        self.assertLessEqual(api.MAX_UI_PREFS_DASH_SET_CHARS * 2, api.MAX_UI_PREFS_BYTES, 'a fifth of the document at most, before escapes')
        self.assertEqual(api.MAX_UI_PREFS_DASH_SETS, 8)


class TestHostileDocuments(unittest.TestCase):
    """A property check: whatever shape arrives, the answer is built only of known widgets and valid ids, and nothing raises."""

    def _random_value(self, rnd, depth=0):
        pool = [None, True, False, 0, 1, -1, 2.5, "", " ", "x", "cves", "cves:lg", "a1", "A", "é", "x" * 80, "a:b:c", ":", "tickets:sm"]
        if depth < 2:
            pool += [[], {}, [self._random_value(rnd, depth + 1) for _ in range(rnd.randint(0, 4))],
                     {rnd.choice(["id", "name", "w", "k"]): self._random_value(rnd, depth + 1) for _ in range(rnd.randint(0, 4))}]
        return rnd.choice(pool)

    def test_random_documents_never_raise_and_never_carry_an_unknown_widget(self):
        rnd = random.Random(8000)
        seen_sets = 0
        for _ in range(3000):
            sets = [{"id": rnd.choice(["a1", "b2", "c3", self._random_value(rnd)]),
                     "name": rnd.choice(["Night", "", self._random_value(rnd)]),
                     "w": rnd.choice([["cves", "tickets:lg"], self._random_value(rnd), [self._random_value(rnd) for _ in range(5)]])}
                    if rnd.random() < 0.8 else self._random_value(rnd) for _ in range(rnd.randint(0, 5))]
            doc = {"dashboard_sets": sets if rnd.random() < 0.9 else self._random_value(rnd), "dashboard_set": rnd.choice(["a1", "b2", self._random_value(rnd)])}
            out = S(doc)
            for s in out.get("dashboard_sets", []):
                seen_sets += 1
                self.assertRegex(s["id"], r"^[a-z][a-z0-9]{0,11}$")
                self.assertTrue(s["name"] and len(s["name"]) <= api.MAX_UI_PREFS_DASH_SET_NAME)
                keys = [item.partition(":")[0] for item in s["w"]]
                self.assertEqual(len(keys), len(set(keys)), 'no widget twice')
                for item in s["w"]:
                    key, _, size = item.partition(":")
                    self.assertIn(key, KEYS)
                    self.assertIn(size, ("", "sm", "md", "lg"))
            if "dashboard_set" in out:
                self.assertIn(out["dashboard_set"], [s["id"] for s in out["dashboard_sets"]])
        self.assertGreater(seen_sets, 500, 'control: the generator reached the code that keeps a set')


class TestEndpoints(unittest.TestCase):
    """Through the real handlers: the document is replaced as a whole, so a save without the sets removes them."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._old_users = api.USERS_FILE
        api.USERS_FILE = self.d / Path(self._old_users).name
        self._stubs = {n: getattr(api, n) for n in ("require_auth", "method", "get_json_body", "respond")}
        self.cap, self.body = {}, {}
        api.require_auth = lambda require_admin=False: "jakob"
        api.method = lambda: "POST"
        api.get_json_body = lambda: self.body
        api._begin_request()

        def _resp(status, body=None):
            self.cap["s"], self.cap["b"] = status, body
            raise api.HTTPError(status, body)

        api.respond = _resp
        api.save(api.USERS_FILE, {"jakob": {"role": "admin", "created": 1}})

    def tearDown(self):
        for n, v in self._stubs.items():
            setattr(api, n, v)
        api.USERS_FILE = self._old_users

    def _call(self, fn):
        self.cap = {}
        try:
            fn()
        except api.HTTPError:
            pass
        return self.cap["s"], self.cap["b"]

    def test_a_save_and_a_read_give_the_sets_back_and_a_save_without_them_removes_them(self):
        self.body = {"dashboard_sets": [_set("a1", "Security", ["attseverity", "cves:lg"]), _set("b2", "Capacity", ["capacity"])],
                     "dashboard_set": "b2", "temp_unit": "f"}
        status, answer = self._call(api.handle_ui_prefs_set)
        self.assertEqual(status, 200)
        self.assertEqual(answer["prefs"]["dashboard_set"], "b2")
        status, stored = self._call(api.handle_ui_prefs_get)
        self.assertEqual(status, 200)
        self.assertEqual([s["name"] for s in stored["dashboard_sets"]], ["Security", "Capacity"])
        self.assertEqual(stored["dashboard_set"], "b2")
        self.body = {"temp_unit": "f"}
        self._call(api.handle_ui_prefs_set)
        status, stored = self._call(api.handle_ui_prefs_get)
        self.assertEqual(stored, {"temp_unit": "f"}, 'the document is replaced as a whole')

    def test_a_bad_set_costs_the_rest_of_the_document_nothing(self):
        self.body = {"temp_unit": "f", "postit": "remember", "dashboard": [{"key": "cves", "on": True, "size": "md"}],
                     "dashboard_sets": [_set("BAD ID", "x"), {"id": "a1", "name": "Ok", "w": ["nope"]}], "dashboard_set": "BAD ID"}
        self._call(api.handle_ui_prefs_set)
        _status, stored = self._call(api.handle_ui_prefs_get)
        self.assertEqual(stored["temp_unit"], "f")
        self.assertEqual(stored["postit"], "remember")
        self.assertEqual(stored["dashboard"], [{"key": "cves", "on": True, "size": "md"}])
        self.assertEqual(stored["dashboard_sets"], [{"id": "a1", "name": "Ok", "w": []}])
        self.assertNotIn("dashboard_set", stored)


class TestTheClientAndTheServerAgreeOnTheCatalog(unittest.TestCase):
    def test_the_server_widget_list_is_the_clients(self):
        import re
        js = (ROOT / "server" / "html" / "static" / "js" / "app.js").read_text(encoding="utf-8")
        start = js.index("const DASH_WIDGETS = [")
        block = js[start:js.index("\n];", start)]
        client = re.findall(r"key:\s*'([a-z]+)'", block)
        self.assertEqual(client, KEYS, 'a set is checked against the server list: the two lists must be the same')


if __name__ == "__main__":
    unittest.main()
