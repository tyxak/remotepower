#!/usr/bin/env python3
"""v6.4.2 documentation guardrails.

Three things are pinned here, and only one of them is a text check:

  * `docs/features.md` stays TABLES-ONLY (the house rule that keeps it a flat
    feature reference rather than a second changelog);
  * `docs/accessibility.md` — the WCAG 2.1 AA conformance statement — never
    claims a conformance level the code does not support, and its stated
    limitations stay TRUE of the tree (the checks re-derive each fact from
    `server/html`, so the doc rots loudly instead of quietly);
  * the contracts `docs/alerts.md` describes are DRIVEN — `handle_alerts_list`
    is called for real with seeded alerts to prove `offset`/`q`/`severity`/
    `device_id` behave as documented, `_alert_first_seen` is exercised for its
    documented fallbacks, and the documented `control_plane_security_change`
    table is compared against the registry it claims to describe.

The overclaim checks are deliberately ONE-DIRECTIONAL: they fire when a doc
promises more than the code delivers, and stay quiet when the code has grown
past a documented limitation. Understating is a stale doc; overstating a
conformance level is the thing that must never ship.
"""
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("RP_DATA_DIR", tempfile.mkdtemp())

import importlib.util  # noqa: E402

_ROOT = Path(__file__).resolve().parents[1]
_DOCS = _ROOT / "docs"
_HTML = _ROOT / "server" / "html"
_CGI = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI))
sys.path.insert(0, str(Path(__file__).parent))

from srcpin import js_function  # noqa: E402

_spec = importlib.util.spec_from_file_location("api_v642_docs", _CGI / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


def _read(p):
    return p.read_text(encoding="utf-8")


# ── docs/features.md — TABLES ONLY ──────────────────────────────────────────

class TestFeaturesMdIsTablesOnly(unittest.TestCase):
    """The documented hygiene grep must print 0:

        grep -cE '^### |^## (v[0-9]|What.s new|Added in)|```' docs/features.md
    """

    def setUp(self):
        self.src = _read(_DOCS / "features.md")

    def test_hygiene_grep_is_zero(self):
        pat = re.compile(r"^### |^## (v[0-9]|What.s new|Added in)|```", re.M)
        hits = pat.findall(self.src)
        self.assertEqual(
            hits, [],
            "docs/features.md is TABLES-ONLY: no ### subsections, no dated "
            "changelog headers, no code fences. Offending matches: %r" % (hits,))

    def test_no_shell_or_token_examples(self):
        for bad in ("curl ", "X-Token: YOUR"):
            self.assertNotIn(
                bad, self.src,
                f"{bad!r} belongs in a per-topic docs/<topic>.md guide, not in "
                "the flat feature reference")

    def test_every_body_line_is_a_table_row_heading_or_blank(self):
        """Catches narrative paragraphs, which the grep above does not.

        The one permitted non-table line is the file's opening legend, which
        points history at CHANGELOG.md."""
        prose = []
        for i, line in enumerate(self.src.splitlines(), 1):
            s = line.strip()
            if not s or s.startswith(("|", "#", "---", ">", "←")):
                continue
            if s.startswith("Version tags"):   # the legend line
                continue
            prose.append((i, s[:80]))
        self.assertEqual(prose, [],
                         f"non-table prose in features.md: {prose}")


# ── docs/accessibility.md — exists, honest, and machine-checked ─────────────

class TestAccessibilityStatementExists(unittest.TestCase):
    PATH = _DOCS / "accessibility.md"

    def setUp(self):
        self.assertTrue(self.PATH.exists(),
                        "docs/accessibility.md (the conformance statement) is missing")
        self.src = _read(self.PATH)

    def test_names_the_standard_and_the_scope(self):
        self.assertIn("WCAG 2.1", self.src)
        self.assertRegex(self.src, r"(?i)\blevel\s+AA\b")
        self.assertRegex(self.src, r"(?i)\bscope\b")

    def test_states_a_self_assessed_level_not_a_certification(self):
        self.assertRegex(
            self.src, r"(?i)partially supports WCAG 2\.1 AA",
            "the statement must name the level it actually claims")
        flat = re.sub(r"\s+", " ", self.src)
        self.assertRegex(
            flat, r"(?i)\bis not:?\*{0,2} a certification\b",
            "the statement must disclaim certification, like compliance.md does")

    def test_has_a_per_criterion_table(self):
        # A VPAT is built from criterion rows; a prose-only page cannot back one.
        for sc in ("1.4.3", "2.1.1", "2.4.7", "3.3.1", "4.1.2"):
            self.assertIn(sc, self.src, f"success criterion {sc} is not assessed")
        self.assertIn("Not evaluated", self.src,
                      "untested criteria must be marked as untested, not omitted")

    def test_is_reachable_from_the_docs_set(self):
        linkers = [p.name for p in sorted(_DOCS.glob("*.md"))
                   if p.name != "accessibility.md"
                   and "accessibility.md" in _read(p)]
        self.assertTrue(
            linkers,
            "docs/accessibility.md is orphaned — nothing in docs/ links to it")


class TestAccessibilityClaimsMatchTheCode(unittest.TestCase):
    """Every factual claim in the statement is re-derived here from
    `server/html`. These are the checks that keep a conformance statement from
    silently going stale — which is the failure mode that makes one dangerous."""

    def setUp(self):
        self.doc = _read(_DOCS / "accessibility.md")
        self.index = _read(_HTML / "index.html")
        self.css = _read(_HTML / "static" / "css" / "styles.css")
        self.js = {p.name: _read(p)
                   for p in sorted((_HTML / "static" / "js").glob("app*.js"))}

    # -- claims of things that ARE implemented -----------------------------

    def test_every_form_control_really_has_an_accessible_name(self):
        """The doc says the unnamed-control ratchet stands at 0. Re-run the
        real analyzer rather than trusting the number."""
        from test_a11y_labels import unnamed_controls
        self.assertEqual(
            unnamed_controls(self.index), [],
            "accessibility.md claims every form control has an accessible "
            "name; the analyzer disagrees")

    def test_axe_gate_really_has_no_exemptions(self):
        import test_a11y_axe
        self.assertEqual(
            test_a11y_axe._AXE_OPTIONS, {},
            "accessibility.md claims the axe gate runs with every default rule "
            "enabled and zero exemptions")

    def test_skip_link_focus_ring_and_reduced_motion_are_present(self):
        self.assertIn('class="skip-link"', self.index)
        self.assertRegex(self.css, r":focus-visible\s*\{[^}]*outline:")
        self.assertIn("prefers-reduced-motion", self.css)

    def test_active_nav_is_exposed_with_aria_current(self):
        self.assertIn("aria-current", self.js["app.js"])

    def test_language_count_matches_the_i18n_language_list(self):
        i18n = _read(_HTML / "static" / "js" / "i18n.js")
        m = re.search(r"var LANGS = \[([^\]]+)\]", i18n)
        self.assertIsNotNone(m, "could not read the LANGS list from i18n.js")
        langs = re.findall(r"'([a-z]{2})'", m.group(1))
        self.assertIn(f"**{len(langs)} languages**", self.doc,
                      f"the statement's language count is stale (i18n.js ships "
                      f"{len(langs)}: {langs})")
        self.assertIn("ar", langs, "the RTL claim rests on Arabic shipping")

    # -- claims of things that are NOT implemented (one-directional) -------

    def test_form_error_identification_gap_is_stated_while_it_exists(self):
        """SC 3.3.1: no aria-invalid / aria-describedby anywhere. If that is
        ever fixed, this stops asserting — an understated doc is stale, not
        dangerous — but while the gap exists the statement must own it."""
        present = sum(src.count("aria-invalid") + src.count("aria-describedby")
                      for src in [self.index] + list(self.js.values()))
        if present:
            return
        self.assertRegex(
            self.doc, r"3\.3\.1[^|]*\|[^|]*\|[^|]*Does not support",
            "aria-invalid/aria-describedby appear nowhere in the interface, so "
            "SC 3.3.1 must be marked 'Does not support'")
        self.assertIn("aria-invalid", self.doc,
                      "the statement must name the missing mechanism")

    def test_modal_bypass_limitation_is_stated_while_it_exists(self):
        bypass = {name: src.count("classList.add('active')")
                  for name, src in self.js.items()
                  if name in ("app-drift.js", "app-ai.js")}
        if not any(bypass.values()):
            return
        self.assertRegex(
            self.doc, r"(?i)app-drift\.js",
            "dialogs still activate themselves with classList.add('active') "
            f"instead of openModal() ({bypass}); the statement must say so")

    def test_command_palette_dialog_limitation_is_stated_while_it_exists(self):
        app = self.js["app.js"]
        body = js_function(app, "openCommandPalette")
        if "role', 'dialog'" in body or 'role="dialog"' in body:
            return
        self.assertRegex(self.doc, r"(?i)command palette is not exposed as a dialog")


class TestNoDocOverclaimsConformance(unittest.TestCase):
    """No document may assert a conformance level the product has not been
    assessed against. Scans every doc and the shipped UI text."""

    _BAD = [
        (re.compile(r"(?i)\bfull(y)?\s+(conforms?|conformant|compliant)\s+"
                    r"(with|to)?\s*(wcag|section\s*508|en\s*301)"),
         "claims full conformance"),
        (re.compile(r"(?i)wcag[^.\n]{0,40}\b(compliant|certified|certification)\b"),
         "claims WCAG compliance/certification"),
        (re.compile(r"(?i)(section\s*508|en\s*301\s*549)[^.\n]{0,40}"
                    r"\b(compliant|certified)\b"),
         "claims Section 508 / EN 301 549 compliance"),
        (re.compile(r"(?i)\bwcag\s*(2\.\d\s*)?AAA\b"),
         "claims WCAG AAA"),
        (re.compile(r"(?i)\bfully accessible\b"), "claims 'fully accessible'"),
    ]

    def test_no_overclaim_in_docs_or_ui(self):
        targets = sorted(_DOCS.glob("*.md")) + [_HTML / "index.html",
                                                _ROOT / "README.md"]
        offences = []
        for p in targets:
            if not p.exists():
                continue
            src = _read(p)
            for pat, why in self._BAD:
                for m in pat.finditer(src):
                    line = src[:m.start()].count("\n") + 1
                    offences.append(f"{p.name}:{line} {why}: {m.group(0)!r}")
        self.assertEqual(offences, [],
                         "documents assert an unassessed conformance level:\n"
                         + "\n".join(offences))


# ── docs/alerts.md — drive the contracts it describes ───────────────────────

class _HandlerBase(unittest.TestCase):
    """Drive handlers directly with stubbed auth/request/respond.

    Same shape as tests/test_v3120.py: a real store in a scratch dir, respond()
    captured through the HTTPError it genuinely raises (not a monkeypatched
    stub that would let an ungated handler pass), everything restored in
    tearDown so nothing leaks into a later module.
    """

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._files = {}
        for attr in ('USERS_FILE', 'ALERTS_FILE', 'CONFIG_FILE',
                     'ROLES_FILE', 'DEVICES_FILE'):
            self._files[attr] = getattr(api, attr)
            setattr(api, attr, self.d / Path(getattr(api, attr)).name)
        self.cap = {}
        self._orig = {n: getattr(api, n) for n in
                      ('require_auth', 'verify_token', 'get_token_from_request',
                       'audit_log', 'respond', 'method', '_caller_scope')}
        self._qs = os.environ.get('QUERY_STRING')
        api.require_auth = lambda require_admin=False: 'jakob'
        api.verify_token = lambda t: ('jakob', 'admin')
        api.get_token_from_request = lambda: 't'
        api.audit_log = lambda *a, **k: None
        api._caller_scope = lambda: None
        api.method = lambda: 'GET'

        def _resp(s, b=None):
            self.cap['s'] = s
            self.cap['b'] = b
            raise api.HTTPError(s, b)
        api.respond = _resp

    def tearDown(self):
        for n, v in self._orig.items():
            setattr(api, n, v)
        for attr, v in self._files.items():
            setattr(api, attr, v)
        if self._qs is None:
            os.environ.pop('QUERY_STRING', None)
        else:
            os.environ['QUERY_STRING'] = self._qs

    def call(self, fn, *a):
        try:
            fn(*a)
        except api.HTTPError:
            pass
        return self.cap.get('b')


class TestAlertsListContractIsAsDocumented(_HandlerBase):
    """Every query parameter docs/alerts.md advertises is driven for real."""

    DOC = _read(_DOCS / "alerts.md")

    def _seed(self):
        rows = []
        for i in range(1, 26):
            rows.append({
                'id': f'a{i:02d}', 'ts': 1000 + i, 'first_seen': 1000 + i,
                'event': 'disk_full' if i % 2 else 'device_offline',
                'title': f'row {i}',
                'severity': 'critical' if i % 5 == 0 else 'medium',
                'device_id': 'd1' if i <= 20 else 'd2',
                'device_name': 'web01' if i <= 20 else 'db01',
                'acknowledged_at': None, 'resolved_at': None, 'payload': {},
            })
        api.save(api.ALERTS_FILE, {'alerts': rows})

    def _list(self, qs):
        os.environ['QUERY_STRING'] = qs
        return self.call(api.handle_alerts_list)

    def test_envelope_reports_total_offset_and_limit(self):
        self._seed()
        r = self._list('status=open&limit=10')
        for k in ('alerts', 'total', 'offset', 'limit'):
            self.assertIn(k, r, f"the documented envelope key {k!r} is missing")
        self.assertEqual(r['total'], 25)
        self.assertEqual(r['limit'], 10)
        self.assertEqual(len(r['alerts']), 10)

    def test_offset_reaches_rows_past_the_first_page(self):
        """The bug the parameter exists to fix: row 201 was unreachable."""
        self._seed()
        first = [a['id'] for a in self._list('status=open&limit=10')['alerts']]
        second = self._list('status=open&limit=10&offset=10')
        ids = [a['id'] for a in second['alerts']]
        self.assertEqual(second['offset'], 10)
        self.assertEqual(len(ids), 10)
        self.assertFalse(set(ids) & set(first), 'pages overlap')
        # Newest first, and paging walks strictly backwards through the list.
        self.assertEqual(first[0], 'a25')
        self.assertEqual(ids[0], 'a15')

    def test_offset_past_the_end_is_an_empty_page_not_an_error(self):
        self._seed()
        r = self._list('status=open&limit=10&offset=999')
        self.assertEqual(r['alerts'], [])
        self.assertEqual(r['total'], 25)

    def test_negative_offset_is_clamped(self):
        self._seed()
        r = self._list('status=open&offset=-5')
        self.assertEqual(r['offset'], 0)

    def test_device_id_filter_is_exact_and_total_is_post_filter(self):
        self._seed()
        r = self._list('status=open&device_id=d2')
        self.assertEqual(r['total'], 5)
        self.assertTrue(all(a['device_id'] == 'd2' for a in r['alerts']))

    def test_severity_filter_accepts_repeat_and_comma_forms(self):
        self._seed()
        crit = self._list('status=open&severity=critical')
        self.assertEqual(crit['total'], 5)
        self.assertTrue(all(a['severity'] == 'critical' for a in crit['alerts']))
        both_comma = self._list('status=open&severity=critical,medium')
        both_repeat = self._list('status=open&severity=critical&severity=medium')
        self.assertEqual(both_comma['total'], 25)
        self.assertEqual(both_repeat['total'], 25)

    def test_q_matches_device_name_event_and_title_case_insensitively(self):
        self._seed()
        self.assertEqual(self._list('status=open&q=DB01')['total'], 5)
        self.assertEqual(self._list('status=open&q=device_offline')['total'], 12)
        self.assertEqual(self._list('status=open&q=row 7')['total'], 1)
        self.assertEqual(self._list('status=open&q=nothing-matches')['total'], 0)

    def test_filters_compose(self):
        self._seed()
        r = self._list('status=open&device_id=d1&severity=critical')
        self.assertEqual(r['total'], 4)   # rows 5,10,15,20 are on d1

    def test_doc_documents_each_parameter_the_handler_reads(self):
        for p in ('status', 'limit', 'offset', 'q', 'severity', 'device_id'):
            self.assertIn(f"`{p}`", self.DOC,
                          f"alerts.md does not document the {p!r} parameter")


class TestAlertFirstSeenContract(_HandlerBase):
    """`first_seen` is what the inbox ages an alert from — docs/alerts.md
    promises it survives a repeat firing and that old rows adopt their `ts`."""

    DOC = _read(_DOCS / "alerts.md")

    def test_first_seen_falls_back_to_ts_then_zero(self):
        self.assertEqual(api._alert_first_seen({'first_seen': 500, 'ts': 900}), 500)
        self.assertEqual(api._alert_first_seen({'ts': 900}), 900,
                         'a pre-upgrade row must adopt its ts as first observation')
        self.assertEqual(api._alert_first_seen({}), 0)
        self.assertEqual(api._alert_first_seen(None), 0)
        self.assertEqual(api._alert_first_seen({'first_seen': 'bogus', 'ts': 'x'}), 0)

    def test_documented(self):
        self.assertIn('first_seen', self.DOC)
        self.assertIn('resolve_note', self.DOC)


class TestControlPlaneEventDocMatchesRegistry(unittest.TestCase):
    """The alerts.md table of `change` values must equal the code's dict —
    a documented value that cannot fire, or a firing value nobody documented,
    are both real defects."""

    DOC = _read(_DOCS / "alerts.md")
    EVENT = 'control_plane_security_change'

    def test_event_is_registered_with_the_documented_shape(self):
        spec = api.EVENT_REGISTRY.get(self.EVENT)
        self.assertIsNotNone(spec, f'{self.EVENT} is not in EVENT_REGISTRY')
        self.assertEqual(spec.get('severity'), 'high')
        self.assertEqual(spec.get('kind'), 'accounts')
        self.assertEqual(spec.get('lifecycle'), 'point',
                         'the doc says it does not auto-resolve')
        self.assertNotIn('resolves', spec)

    def _section(self):
        """The control-plane section only — alerts.md has other backticked
        tables (the query-parameter list) whose keys must not be mixed in."""
        m = re.search(r"\n## Watching RemotePower itself.*?(?=\n## )",
                      self.DOC, re.S)
        self.assertIsNotNone(
            m, "alerts.md has no control-plane security section")
        return m.group(0)

    def test_every_change_value_is_documented_and_vice_versa(self):
        coded = set(api._CONTROL_PLANE_CHANGES)
        documented = set(re.findall(r"^\| `([a-z_]+)` \|", self._section(), re.M))
        self.assertTrue(coded, 'no control-plane changes defined')
        self.assertEqual(
            coded - documented, set(),
            'these control-plane changes can fire but are undocumented')
        self.assertEqual(
            documented - coded, set(),
            'alerts.md documents control-plane changes that cannot fire')

    def test_kind_is_a_real_channel_kind(self):
        kinds = {k for k, _label, _group in api.CHANNEL_KIND_DEFS}
        self.assertIn('accounts', kinds,
                      "the doc says it routes per channel under the 'accounts' "
                      "kind; that kind must exist or routing drops it")


# ── docs/scaling.md + docs/sso.md — the tenancy hole ────────────────────────

class TestTenancyIsDocumentedWhereTheUiPoints(unittest.TestCase):
    SCALING = _read(_DOCS / "scaling.md")
    SSO = _read(_DOCS / "sso.md")

    def test_scaling_doc_has_real_tenancy_content(self):
        """It used to contain 8 matches for 'tenan' — every one of them the
        word 'maintenance' — while Settings pointed operators at it."""
        stripped = re.sub(r"(?i)maintenance", "", self.SCALING)
        self.assertGreaterEqual(
            len(re.findall(r"(?i)tenan", stripped)), 20,
            "Settings → Security → Multi-tenancy points at scaling.md; it must "
            "actually document tenancy")

    def test_settings_hint_still_points_at_the_documented_file(self):
        index = _read(_HTML / "index.html")
        # Scope to the Multi-tenancy hint paragraph itself, so an unrelated
        # doc link added nearby can't satisfy (or break) this.
        para = re.search(r">Multi-tenancy<.*?</p>", index, re.S)
        self.assertIsNotNone(para, "the Multi-tenancy Settings section vanished")
        m = re.search(r"docs/([a-z-]+\.md)", para.group(0))
        self.assertIsNotNone(m, "the Multi-tenancy Settings hint lost its doc link")
        self.assertEqual(
            m.group(1), "scaling.md",
            "the Multi-tenancy hint points at a file that does not document tenancy")

    def test_every_documented_tenant_endpoint_really_exists(self):
        exact = {p for _m, p in api._build_exact_routes().keys()}
        pattern_paths = {d[2] for d in api._PATTERN_ROUTE_DEFS}
        self.assertIn('/api/tenants', exact)
        self.assertIn('/api/tenancy/readiness', exact)
        self.assertIn('/api/tenants/', pattern_paths)
        for path in ('/api/tenants', '/api/tenancy/readiness',
                     '/api/tenants/{id}/users', '/api/tenants/{id}/branding'):
            self.assertIn(path, self.SCALING,
                          f'{path} is missing from the endpoint table')

    def test_superadmin_trap_is_documented_while_it_exists(self):
        """`handle_user_create` stamps no tenant_id, so a new admin resolves to
        the default tenant — i.e. a platform superadmin. Documented in both the
        tenancy workflow and the identity doc until the code changes."""
        import inspect
        src = inspect.getsource(api.handle_user_create)
        if 'tenant_id' in src:
            return
        for doc, name in ((self.SCALING, 'scaling.md'), (self.SSO, 'sso.md')):
            self.assertRegex(
                doc, r"(?i)superadmin",
                f'{name} must warn that creating an admin without a tenant '
                'assignment produces a platform superadmin')
        self.assertIn('/api/tenants/', self.SCALING,
                      'the corrective call must be shown, not just described')

    def test_readiness_doc_matches_the_stores_the_endpoint_reports(self):
        """The isolation table is the honest half — it must not drift from the
        endpoint that renders the same information in Settings."""
        import inspect
        src = inspect.getsource(api.handle_tenancy_readiness)
        for key in re.findall(r"'key': '([a-z_]+)'", src):
            label = {'device_derived': 'device id', 'roles': 'roles',
                     'audit': 'Audit log'}.get(key, key)
            self.assertRegex(
                self.SCALING, r"(?i)" + re.escape(label),
                f"the readiness endpoint reports the {key!r} store; the "
                "isolation table in scaling.md does not mention it")


if __name__ == '__main__':
    unittest.main()
