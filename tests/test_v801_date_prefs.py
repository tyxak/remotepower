#!/usr/bin/env python3
"""The order a date is written in, and the 12 or 24 hour clock, apart from the interface language.

`_localeTag()` maps English to 'en', so an English interface wrote `11/7/2026, 2:05:03 PM` for a person in Europe, and the only way
to change it was to change the language. Two preferences of the account now do it: `ui_prefs.date_order` (dmy, mdy or ymd) and
`ui_prefs.clock` (h24 or h12). A key that is not stored is Automatic, the language's own style, so nobody sees a change until they
choose. Both are saved to the account (`ui_prefs`) the way the language is, so they follow a person to another browser.

What this module holds:

* the server keeps the two words and drops anything else, without costing the other prefs (`_sanitise_ui_prefs`);
* the page: both selects sit next to the language picker, offer exactly the words the server knows, and are wired;
* the formatter, `_fmtDateText` in app.js, which every date helper ends in. It runs here in V8 with real ICU (node), over
  seven languages, four orders, three clocks, eleven shapes and instants either side of local midnight in five time zones, and it is
  checked against what the engine itself writes, never against a copy of the rule: Automatic is exactly today's output, the clock
  alone is the engine's own `hourCycle`, an order the language already has is its own text, and in every case the numbers and the
  words are the ones the engine wrote, in the digits it wrote them in (Arabic, Persian and Devanagari digits included);
* an invalid date never throws and reads as it always did, and an engine without Intl (the V8 of the repo's load harness) keeps
  the language's own form;
* a ratchet: a direct `toLocale*String` call anywhere in the client, outside `_fmtDateText`, fails. The sites that format a
  number are listed one by one and can only shrink.
"""
import collections
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unicodedata
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _jsload_harness  # noqa: E402
import browser_required  # noqa: E402
import srcpin  # noqa: E402
from display_writes import strip_js_comments  # noqa: E402
from i18n_engine import dict_rows  # noqa: E402
from test_v749_look_server import BAD_KINDS, BAD_WORDS, _Base, api  # noqa: E402

try:
    from py_mini_racer import MiniRacer
    _HAVE_V8 = True
except Exception:                          # pragma: no cover - env dependent
    _HAVE_V8 = False

_ROOT = Path(__file__).resolve().parent.parent
_JS = _ROOT / "server" / "html" / "static" / "js"
_HTML = _ROOT / "server" / "html" / "index.html"
_NODE = shutil.which("node")
_GATE_NODE = bool(_NODE) or browser_required.required()

_TMP = []


def tearDownModule():
    for d in _TMP:
        shutil.rmtree(d, ignore_errors=True)


# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# the server
# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

# what a client could send for the two words, other than the words the product knows
DATE_BAD_WORDS = ["DMY", "Dmy", "dmy ", " dmy", "dmy\n", "d-m-y", "day", "auto", "automatic", "iso", "ISO", "y-m-d", "dd/mm/yyyy",
                  "ymd;color:red", "'><script>1</script>", "url(x)"]
CLOCK_BAD_WORDS = ["H24", "24", "12", "24h", "12h", "h23", "h11", "h12 ", " h24", "h24\n", "auto", "automatic", "am", "pm", "true",
                   "hour12", "h24;color:red", "'><script>1</script>"]


class TestUiPrefsKeepTheDateOrderAndTheClock(_Base):

    def test_the_words_the_product_knows_are_kept(self):
        for order in api.UI_DATE_ORDERS:
            self.assertEqual(api._sanitise_ui_prefs({"date_order": order}), {"date_order": order})
        for clock in api.UI_CLOCKS:
            self.assertEqual(api._sanitise_ui_prefs({"clock": clock}), {"clock": clock})

    def test_the_lists_hold_what_the_ui_offers(self):
        # Automatic is not a word: it is the key being absent, so a new browser and an old account agree
        self.assertEqual(api.UI_DATE_ORDERS, ("dmy", "mdy", "ymd"))
        self.assertEqual(api.UI_CLOCKS, ("h24", "h12"))

    def test_anything_else_is_dropped(self):
        for bad in BAD_WORDS + BAD_KINDS + DATE_BAD_WORDS:
            with self.subTest(order=repr(bad)[:40]):
                self.assertEqual(api._sanitise_ui_prefs({"date_order": bad}), {})
        for bad in BAD_WORDS + BAD_KINDS + CLOCK_BAD_WORDS:
            with self.subTest(clock=repr(bad)[:40]):
                self.assertEqual(api._sanitise_ui_prefs({"clock": bad}), {})

    def test_a_bad_word_does_not_cost_the_other_prefs(self):
        clean = api._sanitise_ui_prefs({"date_order": "iso", "clock": "h12", "look": "pilot", "temp_unit": "f", "team": "NOC"})
        self.assertEqual(clean, {"clock": "h12", "look": "pilot", "temp_unit": "f", "team": "NOC"})
        clean = api._sanitise_ui_prefs({"date_order": "ymd", "clock": "24h", "typeface": "b612"})
        self.assertEqual(clean, {"date_order": "ymd", "typeface": "b612"})

    def test_they_travel_with_the_rest_of_the_document(self):
        doc = {"look": "pilot", "typeface": "b612", "time_display": "absolute", "date_order": "dmy", "clock": "h24"}
        self.assertEqual(api._sanitise_ui_prefs(doc), doc)

    def test_the_two_words_do_not_stand_in_for_each_other(self):
        self.assertNotIn("date_order", api._sanitise_ui_prefs({"date_order": "h24"}))
        self.assertNotIn("clock", api._sanitise_ui_prefs({"clock": "dmy"}))

    def test_a_non_object_is_an_empty_document(self):
        for raw in (None, [], "dmy", 5, ["date_order"]):
            self.assertEqual(api._sanitise_ui_prefs(raw), {})

    def test_the_account_keeps_them_through_the_real_handler(self):
        status, body = self.call(api.handle_ui_prefs_set, body={"date_order": "dmy", "clock": "h24", "temp_unit": "c"})
        self.assertEqual(status, 200, body)
        self.assertEqual(self.prefs(), {"date_order": "dmy", "clock": "h24", "temp_unit": "c"})
        status, body = self.call(api.handle_ui_prefs_get, method="GET")
        self.assertEqual((status, body["date_order"], body["clock"]), (200, "dmy", "h24"))

    def test_a_bad_value_never_reaches_the_store(self):
        status, _body = self.call(api.handle_ui_prefs_set, body={"date_order": "ymd;color:red", "clock": "25", "temp_unit": "f"})
        self.assertEqual(status, 200)
        self.assertEqual(self.prefs(), {"temp_unit": "f"})

    def test_a_save_without_them_is_automatic_again(self):
        # whole-document replacement is the contract: the page deletes the key to go back to Automatic, so a missing key means unset
        self.call(api.handle_ui_prefs_set, body={"date_order": "ymd", "clock": "h12"})
        self.call(api.handle_ui_prefs_set, body={"clock": "h12"})
        self.assertEqual(self.prefs(), {"clock": "h12"})
        self.call(api.handle_ui_prefs_set, body={})
        self.assertEqual(self.prefs(), {})

    def test_each_account_has_its_own(self):
        self.call(api.handle_ui_prefs_set, body={"date_order": "dmy"})
        self.user = "bob"
        self.call(api.handle_ui_prefs_set, body={"date_order": "mdy", "clock": "h12"})
        users = api.load(api.USERS_FILE)
        self.assertEqual(users["jakob"]["ui_prefs"], {"date_order": "dmy"})
        self.assertEqual(users["bob"]["ui_prefs"], {"date_order": "mdy", "clock": "h12"})

    def test_a_viewer_can_set_their_own(self):
        self.user, self.role = "bob", "viewer"
        status, _body = self.call(api.handle_ui_prefs_set, body={"clock": "h24"})
        self.assertEqual(status, 200)
        self.assertEqual(api.load(api.USERS_FILE)["bob"]["ui_prefs"], {"clock": "h24"})


class TestTheLanguageIsNotTouched(_Base):
    """The language has its own endpoint and its own place on the account; the two words must not have moved it."""

    def test_the_language_still_validates_on_its_own(self):
        status, body = self.call(api.handle_me_lang, body={"lang": "de"})
        self.assertEqual((status, body["lang"]), (200, "de"))
        status, _body = self.call(api.handle_me_lang, body={"lang": "dmy"})
        self.assertEqual(status, 400)

    def test_me_still_carries_the_language_and_no_date_words(self):
        self.call(api.handle_ui_prefs_set, body={"date_order": "dmy"})
        status, body = self.call(api.handle_me, method="GET")
        self.assertEqual(status, 200, body)
        self.assertIn("lang", body)
        self.assertNotIn("date_order", body)


# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# the page
# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

def _options(select_id, html):
    m = re.search(r'<select id="%s"[^>]*>(.*?)</select>' % re.escape(select_id), html, re.S)
    assert m, select_id
    return re.findall(r'<option value="([^"]*)">([^<]*)</option>', m.group(1))


class TestTheSelectsNextToTheLanguage(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.html = _HTML.read_text(encoding="utf-8")
        cls.app = (_JS / "app.js").read_text(encoding="utf-8")

    def test_both_sit_in_the_language_card_after_the_language_picker(self):
        card = re.search(r'<div class="settings-section"[^>]*>\s*<div class="section-title"[^>]*>Language</div>(.*?)\n        </div>\n',
                         self.html, re.S)
        self.assertIsNotNone(card, "the Language card was not found")
        body = card.group(1)
        lang, order, clock = (body.find('id="%s"' % i) for i in ("acct-lang", "acct-date-order", "acct-clock"))
        self.assertTrue(0 <= lang < order < clock, (lang, order, clock))

    def test_they_offer_automatic_and_exactly_the_words_the_server_knows(self):
        self.assertEqual([v for v, _t in _options("acct-date-order", self.html)], ["auto"] + list(api.UI_DATE_ORDERS))
        self.assertEqual([v for v, _t in _options("acct-clock", self.html)], ["auto"] + list(api.UI_CLOCKS))

    def test_each_has_a_label_that_points_at_it(self):
        for sel, label in (("acct-date-order", "Date order"), ("acct-clock", "Clock")):
            self.assertRegex(self.html, r'<label for="%s" class="form-label">%s</label>' % (sel, label))

    def test_the_page_reads_the_same_words_the_server_keeps(self):
        for fn, key, words in (("_dateOrder", "date_order", api.UI_DATE_ORDERS), ("_clockPref", "clock", api.UI_CLOCKS)):
            body = srcpin.js_function(self.app, fn)
            self.assertIn("_uiPrefs.%s" % key, body)
            self.assertEqual(set(re.findall(r"=== '(\w+)'", body)), set(words), fn)
            self.assertIn("'auto'", body, fn)

    def test_the_account_page_saves_them_the_way_the_other_prefs_are_saved(self):
        body = srcpin.js_function(self.app, "loadAccount")
        self.assertIn("['acct-date-order', 'date_order']", body)
        self.assertIn("['acct-clock', 'clock']", body)
        self.assertIn("delete _uiPrefs[key]", body, "Automatic is the key absent, not the word 'auto'")
        self.assertIn("flushUiPrefs()", body)


class TestTheNewStringsAreInSixLanguages(unittest.TestCase):

    STRINGS = [
        "Date order", "Automatic", "Day first (31/12/2026)", "Month first (12/31/2026)", "Year first (2026-12-31)",
        "24-hour (14:30)", "12-hour (2:30 PM)", "Clock", "Date and time format saved",
        "Automatic follows the interface language. Date order sets whether a date reads day first, month first or year first, and "
        "Clock sets 24-hour or 12-hour time. Saved to your account, so it follows you to other browsers.",
    ]

    def test_each_string_is_a_key_with_zh_hi_es_ar_de_fr(self):
        rows = dict_rows((_JS / "i18n.js").read_text(encoding="utf-8"))
        self.assertGreater(len(rows), 5000, "control: the dictionary was read")
        for s in self.STRINGS:
            with self.subTest(s=s[:40]):
                self.assertIn(s, rows)
                self.assertEqual(set(rows[s]), {"zh", "hi", "es", "ar", "de", "fr"})

    def test_each_string_is_written_exactly_so_in_the_interface(self):
        source = _HTML.read_text(encoding="utf-8") + "\n".join(p.read_text(encoding="utf-8") for p in _JS.glob("app*.js"))
        for s in self.STRINGS:
            with self.subTest(s=s[:40]):
                self.assertIn(s, source)

    def test_the_docs_say_where_they_are(self):
        doc = (_ROOT / "docs" / "my-account.md").read_text(encoding="utf-8")
        row = next(line for line in doc.splitlines() if line.startswith("| **Language**"))
        for word in ("Date order", "Clock", "Automatic"):
            self.assertIn(word, row)


# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# the formatter, in V8 with real ICU
# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

# the one JS file that runs the jobs: it loads the client the way the repo's load harness does (every script in index.html order,
# under the permissive DOM stub), then evaluates each job in that context and returns what the real helper wrote beside what the
# engine's own toLocale*String writes for the same instant, language and options.
_RUNNER = r"""
const vm = require('vm'), fs = require('fs');
const [clientPath, jobsPath] = process.argv.slice(2);
const ctx = vm.createContext({ console });
vm.runInContext(fs.readFileSync(clientPath, 'utf8'), ctx, { filename: 'client.js' });
const run = code => vm.runInContext(code, ctx);
run("window = { RPi18n: { current: 'en' } };");
const jobs = JSON.parse(fs.readFileSync(jobsPath, 'utf8'));
const one = run(`(function (j, ts) {
  const d = new Date(ts * 1000);
  const tag = j.tag || _localeTag();
  const nat = extra => {
    const o = Object.assign({}, j.opts || {}, extra || {});
    return j.kind === 'date' ? d.toLocaleDateString(tag, o) : j.kind === 'time' ? d.toLocaleTimeString(tag, o) : d.toLocaleString(tag, o);
  };
  const cx = j.clock === 'h24' ? { hourCycle: 'h23' } : j.clock === 'h12' ? { hourCycle: 'h12' } : {};
  const res = {
    actual: eval(j.expr.split('TS').join(String(ts))),
    native: nat(),
    native_clock: nat(cx),
    local: { y: d.getFullYear(), mo: d.getMonth() + 1, d: d.getDate(), H: d.getHours(), M: d.getMinutes(), S: d.getSeconds() },
    tag: tag,
  };
  if (j.parts) res.parts = new Intl.DateTimeFormat(tag, Object.assign({}, j.opts, cx)).formatToParts(d).map(p => [p.type, p.value]);
  return res;
})`);
const out = [];
for (const j of jobs) {
  let ts;
  if (j.instant.local) { const a = j.instant.local; ts = new Date(a[0], a[1] - 1, a[2], a[3], a[4], a[5]).getTime() / 1000; }
  else if (j.instant.utc) { const a = j.instant.utc; ts = Date.UTC(a[0], a[1] - 1, a[2], a[3], a[4], a[5]) / 1000; }
  else { ts = j.instant.raw; }
  const prefs = {};
  if (j.order && j.order !== 'auto') prefs.date_order = j.order;
  if (j.clock && j.clock !== 'auto') prefs.clock = j.clock;
  try {
    run('window.RPi18n.current = ' + JSON.stringify(j.lang || 'en') + '; _uiPrefs = ' + JSON.stringify(prefs) + ';');
    out.push(one(j, ts));
  } catch (e) { out.push({ error: String(e && e.message || e) }); }
}
process.stdout.write(JSON.stringify(out));
"""

LANGS = ("en", "zh", "hi", "es", "ar", "de", "fr")
ORDERS = ("auto", "dmy", "mdy", "ymd")
CLOCKS = ("auto", "h24", "h12")

# (name, kind, opts the engine is also given, the expression the helper is called with, TS is the instant in UNIX seconds)
SHAPES = (
    ("ts", "ts", None, "_fmtAbsTs(TS)"),
    ("date", "date", None, "_fmtAbsDate(TS)"),
    ("time", "time", None, "_fmtAbsTime(TS)"),
    ("md", "date", {"month": "short", "day": "numeric"}, "_fmtAbsDate(TS, { month: 'short', day: 'numeric' })"),
    ("wd_md", "date", {"weekday": "short", "month": "short", "day": "numeric"},
     "_fmtAbsDate(TS, { weekday: 'short', month: 'short', day: 'numeric' })"),
    ("md_time", "ts", {"month": "short", "day": "numeric", "hour": "2-digit", "minute": "2-digit"},
     "_fmtAbsTs(TS, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })"),
    ("long", "date", {"year": "numeric", "month": "long", "day": "numeric"},
     "_fmtAbsDate(TS, { year: 'numeric', month: 'long', day: 'numeric' })"),
    ("month_year", "ts", {"month": "long", "year": "numeric"},
     "_fmtDateText(new Date(TS * 1000), 'ts', { month: 'long', year: 'numeric' }, _localeTag())"),
    ("axis_days", "date", {"month": "short", "day": "2-digit"}, "_fmtTs(TS, 345600)"),
    ("axis_two_days", "ts", {"month": "short", "day": "2-digit", "hour": "2-digit", "minute": "2-digit"}, "_fmtTs(TS, 172800)"),
    ("axis_hours", "time", {"hour": "2-digit", "minute": "2-digit"}, "_fmtTs(TS, 3600)"),
)
# the shapes whose date is all digits (the others name the month)
NUMERIC_SHAPES = ("ts", "date")
PARTS_SHAPES = {s[0] for s in SHAPES if s[2] and ("month" in s[2] or "year" in s[2] or "day" in s[2])}

# instants either side of local midnight and of the year, and ones that are one day in UTC and another in the zone
INSTANTS = (
    {"local": [2026, 11, 7, 14, 5, 3]},
    {"local": [2026, 2, 1, 0, 5, 0]},
    {"local": [2026, 12, 31, 23, 59, 30]},
    {"local": [2026, 3, 8, 0, 30, 15]},
    {"utc": [2026, 12, 31, 23, 59, 30]},
    {"utc": [2026, 6, 15, 0, 0, 5]},
)
ZONES = ("UTC", "Pacific/Kiritimati", "Pacific/Pago_Pago", "America/St_Johns", "Asia/Kolkata")

# other tags the helper can be given directly (the interface offers seven languages, one of them right to left, but the formatter
# takes any tag): right to left languages, and digits that are not the Latin ones
EXTRA_TAGS = ("ar-EG", "he-IL", "fa-IR", "ur-PK", "hi-IN-u-nu-deva", "ar-SA-u-nu-latn", "th-TH-u-nu-thai")


def digits_family(s):
    """The zero of the digit set of each digit in s: the Latin digits share one, Arabic-Indic another."""
    return {ord(c) - unicodedata.digit(c) for c in s if c.isdecimal()}


def numbers(s):
    return [int("".join(str(unicodedata.digit(c)) for c in g)) for g in re.findall(r"\d+", s)]


def words(s):
    return sorted(c for c in s if unicodedata.category(c)[0] in "LM")


def words_kept(actual, native_clock, result):
    """The letters of the output are those of the engine's text (a unit like 年 stays), or those of its fields alone (the words that
    only glued the fields together in the old order are gone). Which is which comes from the engine's own parts."""
    whole = words(native_clock)
    if words(actual) == whole:
        return True
    if result.get("parts"):
        fields = words("".join(v for t, v in result["parts"] if t != "literal"))
        return words(actual) == fields
    return False


def run_node(zone, jobs):
    d = Path(tempfile.mkdtemp(prefix="rp-datepref-"))
    _TMP.append(d)
    (d / "runner.js").write_text(_RUNNER, encoding="utf-8")
    (d / "client.js").write_text(_jsload_harness.concat(), encoding="utf-8")
    (d / "jobs.json").write_text(json.dumps(jobs), encoding="utf-8")
    env = dict(os.environ, TZ=zone)
    proc = subprocess.run([_NODE, str(d / "runner.js"), str(d / "client.js"), str(d / "jobs.json")], capture_output=True, env=env,
                          timeout=600)
    if proc.returncode != 0:
        raise AssertionError("node failed in %s:\n%s" % (zone, proc.stderr.decode(errors="replace")[-1500:]))
    out = json.loads(proc.stdout.decode("utf-8"))
    assert len(out) == len(jobs)
    return out


def matrix_jobs():
    jobs = []
    for lang in LANGS:
        for order in ORDERS:
            for clock in CLOCKS:
                for name, kind, opts, expr in SHAPES:
                    for inst in INSTANTS:
                        jobs.append({"lang": lang, "order": order, "clock": clock, "shape": name, "kind": kind, "opts": opts,
                                     "expr": expr, "instant": inst, "parts": name in PARTS_SHAPES})
    return jobs


def expected_order(order, present):
    seq = {"dmy": ("day", "month", "year"), "mdy": ("month", "day", "year"), "ymd": ("year", "month", "day")}[order]
    return [t for t in seq if t in present]


def default_orders(jobs, results):
    """The order each language writes a numeric date in, read from the engine's own output for a day that is not a month."""
    out = {}
    for j, r in zip(jobs, results):
        if j["shape"] == "date" and j["instant"] == {"local": [2026, 11, 7, 14, 5, 3]} and j["order"] == "auto" and j["clock"] == "auto":
            n = numbers(r["native"])[:3]
            out[j["lang"]] = {(7, 11, 2026): "dmy", (11, 7, 2026): "mdy", (2026, 11, 7): "ymd"}[tuple(n)]
    return out


def verdicts(jobs, results, zone, stats=None):
    """Every violated invariant as a line of text; an empty list is a pass. `stats` counts each check that actually ran, so a check
    that skips every case (an ambiguous instant, a shape without parts) shows up as a count of zero instead of as a pass."""
    bad = []
    stats = collections.Counter() if stats is None else stats
    defaults = default_orders(jobs, results)
    assert set(defaults) == set(LANGS), defaults

    def fail(j, why, r):
        bad.append("%s %s %s/%s %s %s: %s -> %r (engine %r, with the clock %r)" % (
            zone, j["lang"], j["order"], j["clock"], j["shape"], j["instant"], why, r["actual"], r["native"], r["native_clock"]))

    for j, r in zip(jobs, results):
        if "error" in r:
            bad.append("%s %s %s/%s %s: threw %s" % (zone, j["lang"], j["order"], j["clock"], j["shape"], r["error"]))
            continue
        a, nc, loc = r["actual"], r["native_clock"], r["local"]
        order, clock, shape = j["order"], j["clock"], j["shape"]
        for junk in ("undefined", "NaN", "Invalid", "[object"):
            if junk in a:
                fail(j, "junk in the text", r)
        # V8 writes a plain space before AM and PM where formatToParts() keeps ICU's narrow no-break space; text pieced together
        # from parts must not carry the one the engine's own text does not
        if "\u202f" in a and "\u202f" not in nc:
            fail(j, "a narrow no-break space the engine's own text does not have", r)
        if order == "auto":
            # Automatic and the clock alone are what the engine writes, nothing more
            stats["engine's own text"] += 1
            if a != nc:
                fail(j, "not the engine's own text", r)
            continue
        stats["numbers and words kept"] += 1
        # the numbers and the words are the engine's, wherever they were moved to. A word that only joined the fields in the old
        # order ("de" in Spanish) may go; the names of months and days, the day period and a unit (年 月 日) may not.
        if sorted(numbers(a)) != sorted(numbers(nc)) or not words_kept(a, nc, r):
            fail(j, "numbers or words changed", r)
        if not digits_family(a) <= digits_family(nc):
            fail(j, "digits of another script", r)
        if "\u200f" in nc and shape in NUMERIC_SHAPES and "\u200f" not in a:
            fail(j, "the right to left marks were lost", r)
        # an order the language already has is its own text (year first numbers are rewritten as ISO on purpose)
        if order == defaults[j["lang"]] and shape in NUMERIC_SHAPES + ("long",) and not (order == "ymd" and shape in NUMERIC_SHAPES):
            stats["the language's own order"] += 1
            if a != nc:
                fail(j, "the language's own order was rewritten", r)
        time_ints = {loc["H"], loc["M"], loc["S"], loc["H"] % 12 or 12}
        if shape in NUMERIC_SHAPES and loc["d"] != loc["mo"]:
            stats["numeric order"] += 1
            want = {"dmy": [loc["d"], loc["mo"], loc["y"]], "mdy": [loc["mo"], loc["d"], loc["y"]],
                    "ymd": [loc["y"], loc["mo"], loc["d"]]}[order]
            if numbers(a)[:3] != want:
                fail(j, "the date is not in order %s" % order, r)
        if order == "ymd" and shape == "date" and loc["d"] != loc["mo"]:
            stats["year first is ISO"] += 1
            iso = re.sub(r"[^\d-]", "", "".join(str(unicodedata.digit(c)) if c.isdecimal() else c for c in a))
            if iso != "%04d-%02d-%02d" % (loc["y"], loc["mo"], loc["d"]):
                fail(j, "year first is not 2026-11-07", r)
        if "parts" in r and r["parts"]:
            present = [t for t, _v in r["parts"] if t in ("day", "month", "year")]
            texts = {t: v for t, v in r["parts"] if t in present}
            offs = {}
            for t in present:
                if t == "month" and not re.fullmatch(r"\d+", texts[t]):
                    pos = a.find(texts[t])
                elif t == "month":
                    pos = next((m.start() for m in re.finditer(r"\d+", a) if numbers(m.group())[0] == loc["mo"]), -1)
                else:
                    want_int = loc["d"] if t == "day" else loc["y"]
                    pos = next((m.start() for m in re.finditer(r"\d+", a) if numbers(m.group())[0] == want_int), -1)
                offs[t] = pos
            with_time = shape in ("md_time", "axis_two_days")
            ambiguous = (with_time and (loc["d"] in time_ints or loc["mo"] in time_ints)) or loc["d"] == loc["mo"] \
                or any(p < 0 for p in offs.values()) or len(set(offs.values())) != len(offs)
            if len(present) >= 2 and not ambiguous:
                stats["named fields in order"] += 1
                got = sorted(present, key=lambda t: offs[t])
                if got != expected_order(order, present):
                    fail(j, "fields %s are not in order %s" % (got, order), r)
        if clock != "auto" and shape in ("time", "axis_hours"):
            stats["the hour"] += 1
            h = loc["H"] if clock == "h24" else (loc["H"] % 12 or 12)
            if numbers(a)[0] != h:
                fail(j, "the hour should read %d" % h, r)
    return bad


@unittest.skipUnless(_GATE_NODE, "node is not installed")
class TestTheFormatterInRealV8(unittest.TestCase):
    """The matrix. One node process per time zone, each running every job against the real client code."""

    @classmethod
    def setUpClass(cls):
        if not _NODE:
            browser_required.skip_or_fail("node is not installed")
        cls.jobs = matrix_jobs()
        cls.by_zone = {z: run_node(z, cls.jobs) for z in ZONES}

    def test_the_matrix_is_as_large_as_it_says(self):
        self.assertEqual(len(self.jobs), len(LANGS) * len(ORDERS) * len(CLOCKS) * len(SHAPES) * len(INSTANTS))
        self.assertGreater(len(self.jobs), 4000)
        for zone, results in self.by_zone.items():
            self.assertEqual(len(results), len(self.jobs), zone)
            self.assertFalse([r for r in results if "error" in r][:3], zone)

    def test_every_invariant_holds_in_every_zone(self):
        bad, stats = [], collections.Counter()
        for zone, results in self.by_zone.items():
            bad += verdicts(self.jobs, results, zone, stats)
        self.assertEqual(bad[:12], [], "%d cases broke an invariant; the first ones are above" % len(bad))
        self.assertGreater(sum(stats.values()), 40000, "control: the checks ran")

    def test_every_check_really_ran(self):
        """A check that skips every case passes. Each one below ran on at least this many cases (a count measured on the demo
        tree, set well under it): an ambiguous instant, a shape the engine gives no parts for, or a filter that drifted would drop one
        of these to zero."""
        stats = collections.Counter()
        for zone, results in self.by_zone.items():
            verdicts(self.jobs, results, zone, stats)
        floor = {"engine's own text": 5000, "numbers and words kept": 15000, "the language's own order": 1200, "numeric order": 2500,
                 "year first is ISO": 400, "named fields in order": 8000, "the hour": 1800}
        self.assertEqual({k: v for k, v in stats.items() if v < floor[k]}, {}, dict(stats))
        self.assertEqual(set(stats), set(floor), "a check was added or lost: list its floor")

    def test_the_instants_really_are_another_day_in_the_far_zones(self):
        """Control for the zone part: the same instant in UTC is a different local day in Kiritimati and in Pago Pago, so a formatter
        that took the day from UTC would pass in one zone and fail in the other."""
        days = {}
        for zone, results in self.by_zone.items():
            for j, r in zip(self.jobs, results):
                if j["instant"] == {"utc": [2026, 12, 31, 23, 59, 30]} and j["shape"] == "date" and j["lang"] == "en" \
                        and j["order"] == "auto" and j["clock"] == "auto":
                    days[zone] = (r["local"]["y"], r["local"]["mo"], r["local"]["d"])
        self.assertEqual(days["UTC"], (2026, 12, 31))
        self.assertEqual(days["Pacific/Kiritimati"], (2027, 1, 1))
        self.assertEqual(days["Pacific/Pago_Pago"], (2026, 12, 31))
        self.assertEqual(days["Asia/Kolkata"], (2027, 1, 1))

    def test_midnight_reads_00_on_a_24_hour_clock_and_12_on_a_12_hour_one(self):
        seen = 0
        for zone, results in self.by_zone.items():
            for j, r in zip(self.jobs, results):
                if j["shape"] == "time" and j["instant"] == {"local": [2026, 2, 1, 0, 5, 0]} and j["order"] == "auto":
                    if j["clock"] == "h24":
                        self.assertEqual(numbers(r["actual"])[:3], [0, 5, 0], (zone, j["lang"], r["actual"]))
                        seen += 1
                    elif j["clock"] == "h12":
                        self.assertEqual(numbers(r["actual"])[:3], [12, 5, 0], (zone, j["lang"], r["actual"]))
                        seen += 1
        self.assertEqual(seen, len(ZONES) * len(LANGS) * 2)

    def test_english_reads_the_way_a_person_expects(self):
        """Written out, because every other check is against the engine and this is against the person."""
        got = {}
        for j, r in zip(self.jobs, self.by_zone["UTC"]):
            if j["lang"] == "en" and j["instant"] == {"local": [2026, 11, 7, 14, 5, 3]}:
                got[(j["shape"], j["order"], j["clock"])] = r["actual"]
        self.assertEqual(got[("date", "auto", "auto")], "11/7/2026")
        self.assertEqual(got[("date", "dmy", "auto")], "7/11/2026")
        self.assertEqual(got[("date", "mdy", "auto")], "11/7/2026")
        self.assertEqual(got[("date", "ymd", "auto")], "2026-11-07")
        self.assertEqual(got[("md", "dmy", "auto")], "7 Nov")
        self.assertEqual(got[("md", "mdy", "auto")], "Nov 7")
        self.assertEqual(got[("wd_md", "dmy", "auto")], "Sat, 7 Nov")
        self.assertEqual(got[("long", "dmy", "auto")], "7 November 2026")
        self.assertEqual(got[("long", "ymd", "auto")], "2026 November 7")
        self.assertEqual(got[("month_year", "ymd", "auto")], "2026 November")
        self.assertTrue(got[("ts", "dmy", "h24")].startswith("7/11/2026, 14:05:03"), got[("ts", "dmy", "h24")])
        self.assertTrue(got[("ts", "ymd", "h24")].startswith("2026-11-07, 14:05:03"), got[("ts", "ymd", "h24")])
        self.assertEqual(got[("time", "auto", "h24")], "14:05:03")
        self.assertRegex(got[("time", "auto", "h12")], r"^2:05:03\s?PM$")
        self.assertEqual(got[("axis_hours", "dmy", "h24")], "14:05")


@unittest.skipUnless(_GATE_NODE, "node is not installed")
class TestOtherTagsAndDigits(unittest.TestCase):
    """The formatter takes any tag. Right to left languages and digit sets other than the Latin ones must come out with the digits
    and the marks the engine wrote, the same numbers and the same words, whatever the order."""

    @classmethod
    def setUpClass(cls):
        if not _NODE:
            browser_required.skip_or_fail("node is not installed")
        cls.jobs = []
        for tag in EXTRA_TAGS:
            for order in ORDERS:
                for clock in CLOCKS:
                    for name, kind, opts, _expr in SHAPES:
                        if name not in ("ts", "date", "time", "md", "long"):
                            continue
                        expr = "_fmtDateText(new Date(TS * 1000), %s, %s, %s)" % (
                            json.dumps(kind), json.dumps(opts) if opts else "undefined", json.dumps(tag))
                        cls.jobs.append({"lang": "en", "tag": tag, "order": order, "clock": clock, "shape": name, "kind": kind,
                                         "opts": opts, "expr": expr, "instant": {"local": [2026, 11, 7, 14, 5, 3]},
                                         "parts": name in PARTS_SHAPES})
        cls.results = run_node("UTC", cls.jobs)

    def test_nothing_throws_and_the_numbers_and_words_are_the_engines(self):
        bad = []
        for j, r in zip(self.jobs, self.results):
            if "error" in r:
                bad.append("%s: threw %s" % (j["tag"], r["error"]))
                continue
            if j["order"] == "auto":
                if r["actual"] != r["native_clock"]:
                    bad.append("%s %s/%s %s: %r != %r" % (j["tag"], j["order"], j["clock"], j["shape"], r["actual"], r["native_clock"]))
                continue
            if sorted(numbers(r["actual"])) != sorted(numbers(r["native_clock"])) \
                    or not words_kept(r["actual"], r["native_clock"], r):
                bad.append("%s %s/%s %s: %r vs %r" % (j["tag"], j["order"], j["clock"], j["shape"], r["actual"], r["native_clock"]))
            if not digits_family(r["actual"]) <= digits_family(r["native_clock"]):
                bad.append("%s %s/%s %s: digits changed script %r vs %r" % (j["tag"], j["order"], j["clock"], j["shape"], r["actual"],
                                                                         r["native_clock"]))
            if "\u200f" in r["native_clock"] and j["shape"] in ("ts", "date") and "\u200f" not in r["actual"]:
                bad.append("%s %s/%s %s: marks lost %r" % (j["tag"], j["order"], j["clock"], j["shape"], r["actual"]))
        self.assertEqual(bad[:10], [])

    def test_the_control_the_tags_really_use_other_digits_and_marks(self):
        """If the engine wrote Latin digits for all of them, the digit checks above would measure nothing."""
        fams = set()
        marks = 0
        for j, r in zip(self.jobs, self.results):
            if j["order"] == "auto" and j["clock"] == "auto" and j["shape"] == "ts":
                fams |= digits_family(r["native"])
                marks += "\u200f" in r["native"]
        self.assertGreaterEqual(len(fams), 3, fams)
        self.assertGreater(marks, 0)


@unittest.skipUnless(_GATE_NODE, "node is not installed")
class TestAnInvalidDate(unittest.TestCase):
    """An invalid date reads as it always did, for every preference, and never throws."""

    EXPRS = (
        ("_fmtAbsTs('abc')", "Invalid Date"), ("_fmtAbsTs(1e20)", "Invalid Date"), ("_fmtAbsDate('abc')", "Invalid Date"),
        ("_fmtAbsTime('abc')", "Invalid Date"), ("_fmtTs('abc', 3600)", "Invalid Date"), ("_fmtTs('abc', 345600)", "Invalid Date"),
        ("fmtDate('abc')", "Invalid Date"),
        ("_fmtDateText(new Date(NaN), 'ts', undefined, _localeTag())", "Invalid Date"),
        ("_fmtDateText(new Date(NaN), 'date', { month: 'short', day: 'numeric' }, _localeTag())", "Invalid Date"),
        ("_fmtIsoDay('abc')", ""),
    )

    @classmethod
    def setUpClass(cls):
        if not _NODE:
            browser_required.skip_or_fail("node is not installed")
        cls.jobs = []
        for lang in LANGS:
            for order in ORDERS:
                for clock in CLOCKS:
                    for expr, _want in cls.EXPRS:
                        # the instant is out of range, so the engine's own answer to it is "Invalid Date" (the control below)
                        cls.jobs.append({"lang": lang, "order": order, "clock": clock, "shape": expr, "kind": "ts", "opts": None,
                                         "expr": expr, "instant": {"raw": 1e20}, "parts": False})
        cls.results = run_node("UTC", cls.jobs)

    def test_it_reads_as_it_always_did(self):
        want = dict(self.EXPRS)
        bad = []
        for j, r in zip(self.jobs, self.results):
            if "error" in r:
                bad.append("%s %s/%s %s: threw %s" % (j["lang"], j["order"], j["clock"], j["shape"], r["error"]))
            elif r["actual"] != want[j["shape"]]:
                bad.append("%s %s/%s %s: %r" % (j["lang"], j["order"], j["clock"], j["shape"], r["actual"]))
        self.assertEqual(bad[:10], [])

    def test_the_text_of_an_invalid_date_is_the_engines_not_a_default_of_ours(self):
        """Control: the engine itself answers 'Invalid Date' for toLocaleString, so the expectation above is not an invention."""
        self.assertEqual({r["native"] for r in self.results if "error" not in r}, {"Invalid Date"})


@unittest.skipUnless(_GATE_NODE, "node is not installed")
class TestTheFormatterKeepsItsManners(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if not _NODE:
            browser_required.skip_or_fail("node is not installed")
        def job(shape, expr, order="dmy", clock="auto"):
            return {"lang": "en", "order": order, "clock": clock, "shape": shape, "kind": "ts", "opts": None, "expr": expr,
                    "instant": {"raw": 1790000000}, "parts": False}

        cls.jobs = [
            # one formatter per language and options, not one per call
            job("cache", "(function () { const a = _dtf('en', { month: 'numeric' }); const b = _dtf('en', { month: 'numeric' });"
                         " return [a === b, _dtf('de', { month: 'numeric' }) === a]; })()"),
            # the cache stays bounded: 96 different formatters are asked for, one after another
            job("bounded", "(function () { const zones = ['UTC', 'Asia/Tokyo', 'Europe/Paris', 'America/Chicago', 'Asia/Kolkata', 'Africa/Cairo',"
                           " 'Australia/Sydney', 'Pacific/Auckland', 'America/Sao_Paulo', 'Europe/Moscow', 'Asia/Dubai', 'America/Denver'];"
                           " for (let i = 0; i < 96; i++) { _dtf('en', { month: ['numeric', '2-digit', 'short', 'long'][i % 4],"
                           " day: i % 8 < 4 ? 'numeric' : '2-digit', timeZone: zones[Math.floor(i / 8)] }); } return _dtf.cache.size; })()"),
            # the caller's options object is never written to (a frozen one would throw in strict code)
            job("frozen", "_fmtAbsTs(TS, Object.freeze({ month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }))",
                order="ymd", clock="h24"),
            # the account's clock beats an hour12 a call site passed
            job("hour12", "_fmtAbsTime(TS, { hour: 'numeric', minute: '2-digit', hour12: true })", order="ymd", clock="h24"),
        ]
        cls.results = run_node("UTC", cls.jobs)

    def test_a_formatter_is_reused(self):
        self.assertEqual(self.results[0]["actual"], [True, False])

    def test_the_cache_is_bounded(self):
        size = self.results[1]["actual"]
        self.assertGreater(size, 0)
        self.assertLessEqual(size, 60)

    def test_the_options_of_the_caller_are_not_written_to(self):
        self.assertNotIn("error", self.results[2])
        self.assertEqual(self.results[2]["actual"], "Sep 21, 14:13")      # 2026-09-21 14:13:20 UTC, in the order a person asked for

    def test_the_clock_choice_beats_an_hour12_the_caller_passed(self):
        # 2026-09-21 14:13:20 UTC: a 24 hour clock reads 14, whatever hour12 the call site asked for
        self.assertTrue(self.results[3]["actual"].startswith("14:13"), self.results[3]["actual"])


# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# an engine without Intl: the V8 of the repo's load harness
# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

@unittest.skipUnless(_HAVE_V8, "py_mini_racer not installed")
class TestInTheLoadHarnessV8(unittest.TestCase):
    """The harness evaluates every script of the client under the DOM stub in py_mini_racer, a V8 built without Intl. The helpers must
    load there, and with a preference chosen they must keep the language's own form instead of throwing."""

    @classmethod
    def setUpClass(cls):
        cls.ctx = MiniRacer()
        cls.ctx.eval(_jsload_harness.concat())
        cls.ctx.eval("window = { RPi18n: { current: 'de' } };")

    def prefs(self, order=None, clock=None):
        body = ", ".join(x for x in ("date_order: '%s'" % order if order else "", "clock: '%s'" % clock if clock else "") if x)
        self.ctx.eval("_uiPrefs = { %s };" % body)

    def test_the_harness_v8_really_has_no_intl(self):
        if self.ctx.eval("typeof Intl") != "undefined":
            self.skipTest("this V8 has Intl; the node matrix covers it")
        self.assertEqual(self.ctx.eval("typeof Intl"), "undefined")

    def test_the_helpers_load_and_a_chosen_preference_changes_nothing_without_intl(self):
        if self.ctx.eval("typeof Intl") != "undefined":
            self.skipTest("this V8 has Intl; the node matrix covers it")
        self.prefs()
        native = self.ctx.eval("new Date(1790000000 * 1000).toLocaleString(_localeTag())")
        self.assertEqual(self.ctx.eval("_fmtAbsTs(1790000000)"), native)
        for order, clock in (("dmy", None), ("mdy", None), ("ymd", None), (None, "h24"), (None, "h12"), ("ymd", "h24")):
            with self.subTest(order=order, clock=clock):
                self.prefs(order, clock)
                self.assertEqual(self.ctx.eval("_fmtAbsTs(1790000000)"), native)
                self.assertEqual(self.ctx.eval("_fmtAbsDate(1790000000)"), self.ctx.eval("new Date(1790000000 * 1000).toLocaleDateString(_localeTag())"))
                self.assertEqual(self.ctx.eval("_fmtAbsTime(1790000000)"), self.ctx.eval("new Date(1790000000 * 1000).toLocaleTimeString(_localeTag())"))
        self.prefs()

    def test_a_prefs_object_that_is_not_there_or_is_wrong_is_automatic(self):
        for value in ("undefined", "null", "{}", "{ date_order: 'iso', clock: 25 }", "{ date_order: ['dmy'], clock: {} }", "'dmy'"):
            with self.subTest(value=value):
                self.ctx.eval("_uiPrefs = %s;" % value)
                self.assertEqual((self.ctx.eval("_dateOrder()"), self.ctx.eval("_clockPref()")), ("auto", "auto"))
        self.prefs()

    def test_each_word_is_read_as_that_word(self):
        for order in api.UI_DATE_ORDERS:
            self.prefs(order=order)
            self.assertEqual(self.ctx.eval("_dateOrder()"), order)
        for clock in api.UI_CLOCKS:
            self.prefs(clock=clock)
            self.assertEqual(self.ctx.eval("_clockPref()"), clock)
        self.prefs()


# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# the ratchet
# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

# A call that turns a Date (or a number) into text for a person with the engine's own locale methods. The formatter is the one place
# that may hold them for a date; a number is formatted with them where it is, and those sites are listed one by one below.
_NATIVE = re.compile(r"\.toLocale(?:Date|Time)?String\(|\bIntl\.DateTimeFormat\b")

# What may hold a native call, by function. _fmtDateText holds the three methods (and tests that Intl exists); _dtf builds the
# formatters it reuses.
ALLOWED_HOLDERS = {"app.js": ("_fmtDateText", "_dtf")}

# Pages that load no app.js: the public status page, the printable report, the customer portal and the fleet query page. The helper
# does not exist there and they have no language picker or account, so the browser's own locale is the right answer. File -> how many.
STANDALONE = {"fleet-query.js": 1, "portal.js": 1, "report.js": 1, "status.js": 2}

# The client's own sites that format a NUMBER with toLocaleString. The scan cannot tell a number from a Date by syntax, so each one
# is listed by its receiver, and a new receiver or a second one of the same text fails the test. The list can only shrink: a site that
# goes (converted, or moved) has to come off it, so no slack is left for a date to take its place.
NUMBER_SITES = {
    ("app-billing.js", "Number(n || 0)"): "an amount, the fallback when fmtMoney is missing (in the browser's own locale)",
    ("app-cve.js", "f.kev_count"): "how many known-exploited CVEs the feed holds",
    ("app.js", "n"): "fmtMoney: the plain decimal when the currency is not a code",
    ("app.js", "(Number(r.count) || 0)"): "a count cell in a table with bars",
    ("app.js", "v"): "a metric of a host's integration chips",
    ("app.js", "Math.round(b / 1048576)"): "megabytes of cache and of used memory in the host drawer",
    ("app.js", "grand"): "the personal data scan total",
    ("app.js", "Number(n)"): "the count of one kind of personal data on a host",
    ("app.js", "Number(f.count || 0)"): "the count of one finding of the personal data scan",
    ("app.js", "Number(h.files || 0)"): "the files with matches on one host in the personal data scan",
}


def receiver(text, dot):
    """The expression a method is called on: back from the dot over names, dots and balanced brackets."""
    i = dot
    while i > 0:
        c = text[i - 1]
        if c in ")]":
            depth, j = 0, i - 1
            while j >= 0:
                if text[j] in ")]":
                    depth += 1
                elif text[j] in "([":
                    depth -= 1
                if depth == 0:
                    break
                j -= 1
            i = j
        elif c.isalnum() or c in "_$.":
            i -= 1
        else:
            break
    return text[i:dot].strip()


def native_calls(name, source):
    """[(method, receiver, holder)] of every native call in one script, outside comments."""
    src = strip_js_comments(source)
    spans = []
    for fn in ALLOWED_HOLDERS.get(name, ()):
        body = srcpin.js_function(src, fn)
        a = src.find(body)
        spans.append((fn, a, a + len(body)))
    out = []
    for m in _NATIVE.finditer(src):
        holder = next((fn for fn, a, b in spans if a <= m.start() < b), "")
        recv = receiver(src, m.start()) if m.group(0).startswith(".") else ""
        out.append((m.group(0), recv, holder))
    return out


def census():
    """Counts over the client: files read, native calls outside the holders, and the ones in them."""
    files = [p for p in sorted(_JS.glob("*.js")) if p.name != "i18n.js"]
    outside, inside = [], []
    for p in files:
        for method, recv, holder in native_calls(p.name, p.read_text(encoding="utf-8")):
            (inside if holder else outside).append((p.name, method, recv))
    return files, outside, inside


class TestNoDateGoesAroundTheFormatter(unittest.TestCase):

    def test_the_scan_sees_a_call_and_spares_a_comment(self):
        self.assertEqual(native_calls("x.js", "a = d.toLocaleString(loc);"), [(".toLocaleString(", "d", "")])
        self.assertEqual(native_calls("x.js", "a = new Date(t * 1000).toLocaleDateString('en');"),
                         [(".toLocaleDateString(", "Date(t * 1000)", "")])
        self.assertEqual(native_calls("x.js", "a = d.toLocaleTimeString();"), [(".toLocaleTimeString(", "d", "")])
        self.assertEqual(native_calls("x.js", "a = new Intl.DateTimeFormat('en').format(d);"), [("Intl.DateTimeFormat", "", "")])
        self.assertEqual(native_calls("x.js", "a = (Number(r.count) || 0).toLocaleString(loc);"),
                         [(".toLocaleString(", "(Number(r.count) || 0)", "")])
        self.assertEqual(native_calls("x.js", "// d.toLocaleString(loc)\n/* d.toLocaleDateString(loc) */ a = 1;"), [])
        self.assertEqual(native_calls("x.js", "a = `${grand.toLocaleString(loc)} hosts`;"), [(".toLocaleString(", "grand", "")])

    def test_the_holders_are_the_only_place_and_the_scan_knows_where_they_end(self):
        src = "function _fmtDateText(d, k) {\n  return d.toLocaleString(tag);\n}\nfunction _dtf(t, o) { return new Intl.DateTimeFormat(t, o); }\n" \
              "function other(d) { return d.toLocaleString(tag); }\n"
        got = native_calls("app.js", src)
        self.assertEqual([h for _m, _r, h in got], ["_fmtDateText", "_dtf", ""])

    def test_the_population_is_the_whole_client(self):
        files, outside, inside = census()
        self.assertGreater(len(files), 60, "control: the scripts were found")
        self.assertGreater(len(outside) + len(inside), 18, "control: the calls were found")
        self.assertEqual(len(inside), 5, "the formatter holds three methods, one feature test and one constructor")

    def test_a_date_does_not_go_around_the_formatter(self):
        _files, outside, _inside = census()
        found = {}
        for name, _method, recv in outside:
            if name in STANDALONE:
                continue
            found[(name, recv)] = found.get((name, recv), 0) + 1
        new = {k: n for k, n in found.items() if n > (1 if k in NUMBER_SITES else 0)}
        gone = [k for k in NUMBER_SITES if k not in found]
        self.assertEqual(new, {}, "a Date is written with a native toLocale*String call, which ignores the date order and the clock "
                                  "the account chose: use _fmtAbsTs, _fmtAbsDate or _fmtAbsTime with seconds, or _fmtDateText with a "
                                  "Date. (A number goes on NUMBER_SITES only if it cannot be anything else; the list does not grow.)")
        self.assertEqual(gone, [], "a number site is gone (converted, or moved): take it off NUMBER_SITES, so the list only shrinks")
        self.assertEqual(sum(found.values()), len(NUMBER_SITES))

    def test_the_standalone_pages_are_held_at_their_count(self):
        _files, outside, _inside = census()
        counts = {}
        for name, _method, _recv in outside:
            if name in STANDALONE:
                counts[name] = counts.get(name, 0) + 1
        self.assertEqual(counts, STANDALONE, "a standalone page gained or lost a native call: the ceiling is the count")

    def test_the_standalone_pages_load_no_app_js(self):
        """The carve-out has to stay true. A page that starts loading app.js should join the ratchet instead of keeping its count."""
        html = _ROOT / "server" / "html"
        for js in STANDALONE:
            page = html / js.replace(".js", ".html")
            self.assertTrue(page.exists(), page)
            self.assertNotIn("js/app.js", page.read_text(encoding="utf-8"), "%s loads app.js now" % page.name)

    def test_the_helpers_end_in_the_formatter(self):
        app = (_JS / "app.js").read_text(encoding="utf-8")
        for fn in ("_fmtAbsTs", "_fmtAbsDate", "_fmtAbsTime", "fmtDate", "_fmtTs", "_fmtIsoDay"):
            self.assertIn("_fmtDateText(", srcpin.js_function(app, fn), fn)
            self.assertIn("_localeTag()", srcpin.js_function(app, fn), fn)

    def test_the_census_reads_what_the_report_quotes(self):
        """The ratio the report quotes is derived here, so a number in a report can be re-run: the sites that format a date or a
        time for a person go through the formatter."""
        helpers = ("_fmtAbsTs", "_fmtAbsDate", "_fmtAbsTime", "_fmtTs", "_absTs", "_fmtDateText", "_fmtIsoDay")
        via = 0
        for p in sorted(_JS.glob("app*.js")):
            src = strip_js_comments(p.read_text(encoding="utf-8"))
            for fn in helpers:
                via += len(re.findall(r"(?<![\w.$])%s\(" % fn, src)) - len(re.findall(r"function\s+%s\(" % fn, src))
        self.assertGreater(via, 100, "control: the call sites of the helpers were counted")


if __name__ == "__main__":
    unittest.main()
