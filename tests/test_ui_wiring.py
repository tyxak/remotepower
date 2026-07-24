"""UI wiring parity — every name on one side must resolve on the other.

JS fails silently: a data-action naming a function that doesn't exist, a
getElementById on an id nobody renders, or an api() call to a route the server
doesn't serve all die at runtime in a branch nobody exercised, with no build
error anywhere. This file makes those cross-references a build failure.

Layers pinned (each caught a real shipped bug or near-miss):
  1. data-action / data-change / data-input / data-action-btn / dataset.*
     names (index.html + every JS-generated string) -> a global function.
  2. data-drawer-act values -> _drawerActMap keys.
  3. getElementById targets -> an id in static HTML or created dynamically.
  4. _MON_PANELS / _CONTAINER_PANELS / _TLS_PANELS <-> actual panel ids
     (both directions).
  5. tableCtl.register / wireSortOnly element ids exist.
  6. every JS api('METHOD', path) shape -> a server route (exact +
     dispatcher-derived; a source-level fallback covers the any-method
     dispatcher branches _dispatcher_routes deliberately skips).

False-positive rules learned building this: strip comments before extracting
(a documented example is not a reference), and extract function definitions
with \\bfunction (a `}function x()` one-liner is still a definition).
"""

import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_CGI = ROOT / "server" / "cgi-bin"
_JS = ROOT / "server" / "html" / "static" / "js"
_HTML = ROOT / "server" / "html"
sys.path.insert(0, str(_CGI))
os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp(prefix="rp-uiwiring-"))


def _strip_comments(t):
    t = re.sub(r"^\s*//.*$", "", t, flags=re.M)
    t = re.sub(r"/\*.*?\*/", "", t, flags=re.S)
    return t


def _all_js():
    return {p.name: p.read_text() for p in _JS.glob("*.js")}


def _index_html():
    return (_HTML / "index.html").read_text()


def _global_defs(js_files):
    defs = set()
    for t in js_files.values():
        s = _strip_comments(t)
        defs |= set(re.findall(r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\(", s))
        defs |= set(re.findall(r"window\.([A-Za-z_$][\w$]*)\s*=", s))
        defs |= set(re.findall(
            r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(", s))
    return defs


def _known_ids(js_files, html_files):
    """(exact_ids, dynamic_prefixes) — a template id like
    id="audit-body-${s.key}" makes 'audit-body-' a dynamic prefix; any
    getElementById('audit-body-<x>') then counts as resolvable."""
    ids = set()
    prefixes = set()
    for t in html_files:
        ids |= set(re.findall(r'id="([^"$]+)"', t))
    for t in js_files.values():
        ids |= set(re.findall(r"""\.id\s*=\s*['"`]([^'"`$]+)['"`]""", t))
        ids |= set(re.findall(r'id="([^"$]+)"', t))
        ids |= set(re.findall(r"id='([^'$]+)'", t))
        ids |= set(re.findall(r"setAttribute\('id',\s*'([^']+)'", t))
        prefixes |= set(re.findall(r'id="([^"$]+)\$\{', t))
        prefixes |= set(re.findall(r"""\.id\s*=\s*['"`]([^'"`$]+)['"`]\s*\+""", t))
        prefixes |= set(re.findall(r"\.id\s*=\s*`([^`$]+)\$\{", t))
    prefixes = {p for p in prefixes if p}
    return ids, prefixes


def _id_known(target, ids, prefixes):
    return target in ids or any(target.startswith(p) for p in prefixes)


class TestDispatchNamesResolve(unittest.TestCase):
    def test_every_dispatch_ref_has_a_global_handler(self):
        js = _all_js()
        defs = _global_defs(js)
        refs = {}
        sources = [("index.html", _index_html())] + list(js.items())
        for src, text in sources:
            s = _strip_comments(text) if src.endswith(".js") else text
            for attr in ("data-action", "data-change", "data-input",
                         "data-action-btn"):
                for name in re.findall(attr + r'="([A-Za-z_$][\w$]*)"', s):
                    refs.setdefault((attr, name), set()).add(src)
            if src.endswith(".js"):
                for name in re.findall(
                        r"dataset\.(?:action|actionBtn|change|input)\s*=\s*"
                        r"'([A-Za-z_$][\w$]*)'", s):
                    refs.setdefault(("dataset", name), set()).add(src)
        missing = sorted(f'{a}="{n}" (in {", ".join(sorted(srcs))})'
                         for (a, n), srcs in refs.items() if n not in defs)
        self.assertEqual(missing, [],
                         "dispatch references naming no global function — the "
                         "control is silently inert:\n  " + "\n  ".join(missing))

    def test_every_drawer_act_is_in_the_map(self):
        js = _all_js()
        appjs = _strip_comments(js["app.js"])
        map_keys = set(re.findall(r"_drawerActMap\.set\('([^']+)'", appjs))
        refs = set()
        for t in [appjs, _index_html()]:
            refs |= set(re.findall(r'data-drawer-act="([^"$]+)"', t))
        self.assertEqual(sorted(refs - map_keys), [],
                         "data-drawer-act values missing from _drawerActMap")


class TestElementIdsExist(unittest.TestCase):
    def test_every_getelementbyid_target_exists_somewhere(self):
        js = _all_js()
        htmls = [p.read_text() for p in _HTML.glob("*.html")]
        known, prefixes = _known_ids(js, htmls)
        suspects = {}
        for name, t in js.items():
            s = _strip_comments(t)
            for m in re.findall(r"getElementById\(\s*'([^'$]+)'\s*\)", s):
                if not _id_known(m, known, prefixes):
                    suspects.setdefault(m, set()).add(name)
        listing = sorted(f'{i} ({", ".join(sorted(srcs))})'
                         for i, srcs in suspects.items())
        self.assertEqual(listing, [],
                         "getElementById targets that exist nowhere (static "
                         "html or dynamically created):\n  "
                         + "\n  ".join(listing))


class TestPanelConstants(unittest.TestCase):
    """The show-one/show-all panel lists and the page's actual panels must
    stay in lockstep BOTH ways: a panel missing from the constant is skipped
    by showMonitorSection-style toggles and gets stuck hidden/visible."""

    _CONSTS = {
        "_MON_PANELS": "mon-panel-",
        "_CONTAINER_PANELS": "containers-panel-",
        "_TLS_PANELS": "tls-panel-",
    }

    def test_lockstep_both_directions(self):
        js = _all_js()["app.js"]
        html = _index_html()
        html_ids = set(re.findall(r'id="([^"$]+)"', html))
        for const, prefix in self._CONSTS.items():
            m = re.search(const + r"\s*=\s*\[([^\]]+)\]", js)
            self.assertIsNotNone(m, const)
            listed = set(re.findall(r"'([^']+)'", m.group(1)))
            absent = sorted(i for i in listed if i not in html_ids)
            self.assertEqual(absent, [], f"{const} lists ids not in index.html")
            in_html = {i for i in html_ids if i.startswith(prefix)}
            unlisted = sorted(in_html - listed)
            self.assertEqual(unlisted, [],
                             f"panels in index.html missing from {const}")


class TestTableRegistrations(unittest.TestCase):
    def test_register_and_wiresort_ids_exist(self):
        js = _all_js()
        htmls = [p.read_text() for p in _HTML.glob("*.html")]
        known, prefixes = _known_ids(js, htmls)
        bad = []
        for name, t in js.items():
            s = _strip_comments(t)
            for m in re.finditer(r"tableCtl\.register\(\{(.*?)\brow:", s, re.S):
                blk = m.group(1)
                nm = re.search(r"name:\s*'([^']+)'", blk)
                tname = nm.group(1) if nm else "?"
                for fld in ("tbody", "filterInput", "sortHeaders"):
                    fm = re.search(fld + r":\s*'([^']+)'", blk)
                    if fm and not _id_known(fm.group(1), known, prefixes):
                        bad.append(f"{name}: register({tname}).{fld} -> "
                                   f"{fm.group(1)}")
            for m in re.finditer(r"wireSortOnly\('([^']+)'", s):
                if not _id_known(m.group(1), known, prefixes):
                    bad.append(f"{name}: wireSortOnly -> {m.group(1)}")
        self.assertEqual(bad, [], "table wiring ids that exist nowhere:\n  "
                         + "\n  ".join(bad))


class TestCacheBustLockstep(unittest.TestCase):
    """sw.js CACHE_NAME and every ?v= in index.html must carry the SAME
    version string — they were kept in lockstep by hand on every client-asset
    change, and a forgotten bump means browsers serve a stale shell against a
    new API. Made structural in the v6.4.0 micropolish pass."""

    def test_cache_name_matches_every_asset_version(self):
        sw = (_HTML / "sw.js").read_text()
        m = re.search(r"CACHE_NAME\s*=\s*'remotepower-shell-v([\w.\-]+)'", sw)
        self.assertIsNotNone(m, "CACHE_NAME not found in sw.js")
        ver = m.group(1)
        html = _index_html()
        versions = set(re.findall(r"\?v=([\w.\-]+)", html))
        self.assertEqual(versions, {ver},
                         f"index.html ?v= values {sorted(versions)} out of "
                         f"lockstep with sw.js CACHE_NAME v{ver} — bump both "
                         "together on every client-asset change")


class TestEveryDataAttributeIsConsumed(unittest.TestCase):
    """Full-index audit: every data-* attribute NAME used anywhere in
    index.html (or JS-generated markup) must have a CONSUMER — a dataset.X
    read, a [data-x] selector, or a getAttribute('data-x') — somewhere in the
    client JS or a CSS attribute selector. A typo'd or abandoned attribute
    name silently does nothing (first run found: data-submit carried the
    OIDC/SAML Enter-submit handler names with NO dispatcher — Enter reloaded
    the page and discarded the form — plus three orphan attribute families
    left from abandoned designs, now removed)."""

    def test_every_attribute_name_has_a_consumer(self):
        # Scope: attributes AUTHORED in index.html — the static surface, where
        # an unconsumed attribute means broken wiring. JS-generated markup also
        # stamps data-* values that are deliberate one-way state carriers
        # (data-ok/down on board bars etc.); those are excluded as low-signal.
        js_all = _all_js()
        html = _index_html()
        css = (_HTML / "static" / "css" / "styles.css").read_text()
        used = set(re.findall(r"data-([a-z][a-z0-9-]*)=", html))
        consumed = set()
        corpus = "".join(js_all.values())
        for name in used:
            camel = re.sub(r"-(.)", lambda m: m.group(1).upper(), name)
            if (f"dataset.{camel}" in corpus
                    or f"[data-{name}" in corpus
                    or f"getAttribute('data-{name}')" in corpus
                    or f'getAttribute("data-{name}")' in corpus
                    or f"[data-{name}" in css):
                consumed.add(name)
        orphans = sorted(used - consumed)
        self.assertEqual(orphans, [],
                         "data-* attribute names with NO consumer anywhere — "
                         "a typo, or wiring that was never built:\n  "
                         + "\n  ".join(orphans))


class TestApiCallsAreServed(unittest.TestCase):
    """Every api('METHOD', path) shape in the client must match a server
    route. Template holes (${...}) and string-concat tails count as one
    variable path segment. _dispatcher_routes() skips any-method dispatcher
    branches by design, so a static-prefix presence check against the server
    source is the fallback before calling something unserved."""

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "api_uiwiring", _CGI / "api.py")
        api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(api)
        cls.api = api
        cls.routes = []
        for (m, p) in (list(api._build_exact_routes().keys())
                       + list(api._dispatcher_routes())):
            rx = re.sub(r"\{[^}]+\}", "[^/]+",
                        re.escape(p).replace(r"\{", "{").replace(r"\}", "}"))
            cls.routes.append((m, re.compile("^" + rx + "$")))
        cls.server_src = "".join(p.read_text() for p in _CGI.glob("*.py"))

    def _served(self, method, path):
        return any(m == method and rx.match(path) for m, rx in self.routes)

    def test_every_client_call_shape_matches_a_route(self):
        calls = {}
        for name, t in _all_js().items():
            s = _strip_comments(t)
            for m in re.finditer(
                    r"""api\(\s*'(GET|POST|PUT|DELETE|PATCH)'\s*,\s*"""
                    r"""(`[^`]*`|'[^']*')\s*([+)])""", s):
                meth, raw, nxt = m.group(1), m.group(2)[1:-1], m.group(3)
                path = re.sub(r"\$\{[^}]+\}", "~VAR~", raw.split("?")[0])
                if nxt == "+":
                    path += "~VAR~"
                calls.setdefault((meth, path), set()).add(name)
        unserved = []
        for (meth, path), srcs in sorted(calls.items()):
            full = "/api" + path
            if self._served(meth, full.replace("~VAR~", "xvarx")):
                continue
            static_prefix = full.split("~VAR~")[0]
            tail = full.split("~VAR~")[-1] if "~VAR~" in full else ""
            pref_ok = static_prefix.rstrip("/") and (
                static_prefix.rstrip("/") in self.server_src
                or static_prefix in self.server_src)
            tail_ok = (not tail) or (tail in self.server_src) \
                or (f"endswith('{tail}')" in self.server_src)
            if pref_ok and tail_ok:
                continue
            unserved.append(f"{meth} {full} ({', '.join(sorted(srcs))})")
        self.assertEqual(unserved, [],
                         "client api() calls with no matching server route:\n  "
                         + "\n  ".join(unserved))


if __name__ == "__main__":
    unittest.main()
