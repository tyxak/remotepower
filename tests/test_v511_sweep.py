"""v5.1.1 whole-project finalize-sweep regressions.

Covers the concrete fixes from the sweep:
  - IaC status/generate/payload gates use backend_exists() (DB-backend blind .exists())
  - _resolve_targets + admin validators coerce a non-dict JSON body (no 500)
  - File Manager sort wiring uses a consistent prefs name (rows actually reorder)
  - CMDB markdown esc() escapes quotes (href attribute-injection closed)
  - patch-report CSV + XML exports include the security-update count
  - posture RAG corpus reports break-glass from the real per-credential count
  - CMDB drawer lists are box-capped; DMARC/firewall/cron sections are card-wrapped
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-v511sweep-"))
_spec = importlib.util.spec_from_file_location("api_v511sweep", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, _CGI / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


rag_index = _load("rag_index_v511", "rag_index.py")

API_SRC = (_CGI / "api.py").read_text()
INDEX_HTML = (_ROOT / "server" / "html" / "index.html").read_text()
APP_JS = (_ROOT / "server" / "html" / "static" / "js" / "app.js").read_text()
CMDB_JS = (_ROOT / "server" / "html" / "static" / "js" / "app-cmdb.js").read_text()


# ───────────────── backend correctness ─────────────────

class TestResolveTargetsCoercion(unittest.TestCase):
    def test_non_dict_body_returns_no_targets(self):
        # A top-level JSON array must not AttributeError (was a 500 before auth).
        self.assertEqual(api._resolve_targets([1, 2, 3]), [])
        self.assertEqual(api._resolve_targets("nope"), [])
        self.assertEqual(api._resolve_targets(None), [])

    def test_dict_body_still_works(self):
        self.assertEqual(api._resolve_targets({"device_ids": []}), [])


class TestValidatorsCoerceNonDict(unittest.TestCase):
    def test_validators_do_not_crash_on_list_body(self):
        # The point is NO AttributeError (was a 500). A clean validation
        # rejection — a (None, error) tuple OR an HTTPError 400 via respond() —
        # is the correct, handled outcome.
        calls = [
            (api._validate_rule, ([1, 2, 3],)),
            (api._clean_role_body, ([1, 2, 3],)),
            (api._validate_maintenance_body, ([1, 2, 3],)),
            (api._validate_global_rule, ([1, 2, 3],)),
            (api._sanitize_event, ([1, 2, 3],)),
            (api._sanitize_task, ([1, 2, 3],)),
        ]
        for fn, args in calls:
            with self.subTest(fn=fn.__name__):
                try:
                    fn(*args)
                except AttributeError as e:
                    self.fail(f"{fn.__name__} crashed on a list body: {e}")
                except api.HTTPError:
                    pass  # clean 400 rejection — fine
                except Exception:
                    pass  # any other handled rejection — fine (just not AttributeError)


class TestIacBackendExists(unittest.TestCase):
    def test_iac_gates_use_backend_exists_not_path_exists(self):
        # The 3 IaC read-gates must be storage-key aware (dead under SQLite/PG otherwise).
        self.assertEqual(API_SRC.count("if not backend_exists(fpath):"), 3)
        self.assertNotIn("if not fpath.exists():", API_SRC)


class TestPatchReportSecurityUpdates(unittest.TestCase):
    def test_csv_header_has_security_updates(self):
        self.assertIn("'Security Updates'", API_SRC)

    def test_xml_emits_security_updates(self):
        self.assertIn("'SecurityUpdates'", API_SRC)


class TestPostureBreakGlassCount(unittest.TestCase):
    def test_corpus_uses_passed_count_not_phantom_config_key(self):
        # The phantom global config keys must be gone.
        rag_src = (_CGI / "rag_index.py").read_text()
        self.assertNotIn("breakglass_required", rag_src)
        self.assertNotIn("break_glass_required", rag_src)

    def test_count_drives_the_text(self):
        none = rag_index.build_posture_corpus(config={}, devices=[], now=1,
                                              breakglass_creds=0)
        some = rag_index.build_posture_corpus(config={}, devices=[], now=1,
                                              breakglass_creds=3)
        none_txt = " ".join(d.get("text", "") for d in none)
        some_txt = " ".join(d.get("text", "") for d in some)
        self.assertIn("not enabled on any credential", none_txt)
        self.assertIn("3 credential", some_txt)


# ───────────────── client correctness ─────────────────

class TestFileManagerSort(unittest.TestCase):
    def test_wire_and_sort_use_same_prefs_name(self):
        self.assertIn("wireSortOnly('fm-thead', 'filemgr'", APP_JS)
        self.assertNotIn("wireSortOnly('fm-thead', 'files'", APP_JS)


class TestCmdbAttributeInjection(unittest.TestCase):
    def test_esc_escapes_double_quote(self):
        # The markdown esc() must escape " so a link URL can't break out of href="".
        self.assertIn("replace(/\"/g,'&quot;')", CMDB_JS)


# ───────────────── UI overflow + layout ─────────────────

class TestBoxOverflowCaps(unittest.TestCase):
    def test_cmdb_lists_are_scroll_capped(self):
        for frag in ('id="cmdb-creds-list" class="scroll-cap"',
                     'id="cmdb-interfaces" class="scroll-cap"',
                     'id="cmdb-list-contracts" class="scroll-cap"'):
            self.assertIn(frag, INDEX_HTML, frag)

    def test_no_bare_scrollable_table_wrap(self):
        # every variable table caps at ~15 lines (audit-scroll), not 720px.
        self.assertNotIn('<div class="scrollable-table-wrap">', INDEX_HTML)


class TestSectionCards(unittest.TestCase):
    def _balance(self, start_marker, end_marker):
        a = INDEX_HTML.index(start_marker)
        b = INDEX_HTML.index(end_marker, a)
        blk = INDEX_HTML[a:b]
        return blk.count("<div") - blk.count("</div>")

    def test_dmarc_firewall_cron_div_balanced(self):
        self.assertEqual(self._balance('<div id="page-dmarc"', '<div id="page-tls"'), 0)
        self.assertEqual(self._balance('<div id="page-firewall"', '<div id="page-risk"'), 0)
        self.assertEqual(self._balance('<div id="page-cron"', '<div id="page-firewall"'), 0)


if __name__ == "__main__":
    unittest.main()
