#!/usr/bin/env python3
"""7.4.1, issue #41: a script must not "show" with `style.display = ''` what a class hides.

The maintenance window form kept its cron and duration fields in a row with the `d-none` class and
showed it by writing `style.display = ''`. That only clears the inline property, so the class kept
the row hidden: picking "Recurring (cron)" showed nothing to fill in. The same write hid steps 2 and
3 of the ACME wizard, the Timeline and Logs tabs of the certificate dialog, the conversation tab of
the IaC page, the file-path field and two hints of the log rule dialog, and the "saved" badges beside
the SMTP and LDAP passwords: 11 elements, each measured broken in a real browser on the old code. The
scan flags 14 writes there; the other three (the Back and Issue buttons of the wizard, the IaC status
line) worked by accident, because a later rule out-ranked the class or the class list was rebuilt.

The check that was meant to stop it (test_v232) matched only a literal `= ''`. 4 of the 31 writes that
can be blank have that shape, and none of the broken ones did: all were written `cond ? '' : 'none'`.
The scan is tests/display_writes.py. This file holds the rule, the controls that show the scan can
fail, and the stylesheet half (a control that carries `d-none` stays hidden).
"""
import re
import sys
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import display_writes as dw  # noqa: E402


class TestTheShippedSource(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.js, cls.html, cls.css = dw.shipped_sources()
        cls.r = dw.scan(cls.js, cls.html, cls.css)

    def ratio(self):
        r = self.r
        return ('%d display writes, %d can be blank, %d of those resolve to markup, %d do not, '
                '%d reach an element a class hides'
                % (len(r['writes']), len(r['blank']), len(r['resolved']), len(r['unresolved']),
                   len(r['violations'])))

    def test_the_population_is_not_empty(self):
        """Every extraction here is a regex over source; a change that broke one would empty the
        population while the assertions below still passed."""
        r = self.r
        self.assertGreater(len(r['writes']), 150, self.ratio())
        self.assertGreater(len(r['blank']), 8, self.ratio())
        self.assertGreater(len(r['resolved']), 5, self.ratio())
        hiders = dw.hiding_classes(self.css)
        self.assertIn('d-none', hiders)
        self.assertGreater(len([c for c in hiders if c.startswith('isl-')]), 20,
                           'the isl-* classes that hide are the lifted inline display:none; '
                           'the stylesheet reader found %d hiding classes' % len(hiders))

    def test_no_blank_write_reaches_an_element_a_class_hides(self):
        left = [v for v in self.r['violations'] if (v[0], v[2]) not in dw.ALLOW]
        self.assertEqual(
            left, [],
            'style.display = \'\' only clears the inline property; these elements carry a class that '
            'hides them, so the write never shows them. Toggle the d-none class instead, or write an '
            'explicit display value.\n  (%s)\n  ' % self.ratio()
            + '\n  '.join('%s:%d  %s  hidden by %s' % v for v in left))

    def test_every_allowed_write_is_still_there(self):
        seen = {(v[0], v[2]) for v in self.r['violations']}
        gone = sorted(k for k in dw.ALLOW if k not in seen)
        self.assertEqual(gone, [], 'ALLOW entries that no longer match anything; delete them: %s' % gone)

    def test_the_writes_the_scan_cannot_resolve_are_the_listed_ones(self):
        seen = {(w['file'], w['rhs']) for w in self.r['unresolved']}
        new = sorted(k for k in seen if k not in dw.UNRESOLVED_OK)
        gone = sorted(k for k in dw.UNRESOLVED_OK if k not in seen)
        self.assertEqual(new, [], 'a write that can be blank and points at something the scan cannot '
                                  'find in markup. Make it resolvable (a literal id or a class selector) '
                                  'or list it with the reason: %s' % new)
        self.assertEqual(gone, [], 'UNRESOLVED_OK entries that no longer match; delete them: %s' % gone)

    def test_no_old_shape_survives_at_the_eleven_elements(self):
        """Belt and braces on the named elements: the elements of the report must not be the target
        of any write that can be blank, whatever the scan makes of the rest."""
        named = ('maint-cron-row', 'acme-issue-back', 'acme-issue-go', 'iac-convo-output',
                 'iac-status', 'log-rule-path-row', 'log-rule-global-hint', 'log-rule-unit-hint',
                 'cfg-smtp-pw-set-badge', 'cfg-ldap-pw-set-badge')
        hits = [(w['file'], w['line'], w['target']) for w in self.r['blank']
                if w['target'] and w['target'][1].lstrip('#') in named]
        self.assertEqual(hits, [])
        hits = [w for w in self.r['blank'] if w['target'] and w['target'] in
                (('sel', '.acme-step'), ('sel', '.acme-detail-pane'))]
        self.assertEqual(hits, [])


class TestTheScanSeesEachShape(unittest.TestCase):
    """The scan is shown pages made wrong on purpose, one per way the old code wrote it."""

    HTML = ('<div id="row" class="d-none"></div>'
            '<span id="tag" class="isl-9"></span>'
            '<div id="free"></div>'
            '<div class="step" data-step="1"></div><div class="step d-none" data-step="2"></div>')
    CSS = '.isl-9 { display:none; color:red }\n.d-none { display:none }\n'

    def scan(self, js, css=None, html=None):
        return dw.scan({'t.js': js}, html or self.HTML, css or self.CSS, js_templates={})

    def flagged(self, js, **kw):
        return [v[2] for v in self.scan(js, **kw)['violations']]

    def test_a_conditional_write_to_a_literal_id(self):
        self.assertEqual(self.flagged("document.getElementById('row').style.display = (t === 'x') ? '' : 'none';"),
                         ['#row'])

    def test_the_reversed_conditional(self):
        self.assertEqual(self.flagged("document.getElementById('row').style.display = on ? 'none' : '';"),
                         ['#row'])

    def test_an_unconditional_blank(self):
        self.assertEqual(self.flagged("document.getElementById('row').style.display = '';"), ['#row'])

    def test_a_variable_bound_to_the_id(self):
        js = "const el = document.getElementById('row');\nif (x) {\n  el.style.display = x ? '' : 'none';\n}\n"
        self.assertEqual(self.flagged(js), ['#row'])

    def test_a_loop_over_a_class_selector(self):
        js = ("document.querySelectorAll('.step').forEach(el => {\n"
              "  el.style.display = n(el) === cur ? '' : 'none';\n});\n")
        self.assertEqual(self.flagged(js), ['.step'])

    def test_a_for_of_loop_over_a_class_selector(self):
        js = ("for (const el of document.querySelectorAll('.step')) {\n"
              "  el.style.display = n(el) === cur ? '' : 'none';\n}\n")
        self.assertEqual(self.flagged(js), ['.step'])

    def test_a_class_lifted_out_of_an_inline_style(self):
        self.assertEqual(self.flagged("document.getElementById('tag').style.display = on ? '' : 'none';"),
                         ['#tag'])

    def test_a_selector_with_a_placeholder_still_resolves_by_its_class(self):
        js = ("document.querySelectorAll(`#box-${id} .step`).forEach(r => {\n"
              "  r.style.display = ok ? '' : 'none';\n});\n")
        self.assertEqual(self.flagged(js), ['#box-${id} .step'])

    def test_an_explicit_value_is_the_right_way_and_is_not_flagged(self):
        self.assertEqual(self.flagged("document.getElementById('row').style.display = on ? 'block' : 'none';"), [])

    def test_a_blank_write_at_an_element_nothing_hides_is_not_flagged(self):
        self.assertEqual(self.flagged("document.getElementById('free').style.display = on ? '' : 'none';"), [])

    def test_a_comment_is_not_a_write(self):
        js = ("// document.getElementById('row').style.display = '';\n"
              "/* document.getElementById('row').style.display = ''; */\n"
              "const s = 1; // el.style.display = ''\n")
        r = self.scan(js)
        self.assertEqual((r['writes'], r['violations']), ([], []))

    def test_a_comment_marker_inside_a_string_does_not_swallow_the_line(self):
        js = "const u = 'http://x'; document.getElementById('row').style.display = '';\n"
        self.assertEqual(self.flagged(js), ['#row'])

    def test_a_template_literal_with_a_slash_pair_does_not_hide_the_next_write(self):
        js = ("const h = `<a href=\"//x\">${a}</a>`;\n"
              "document.getElementById('row').style.display = '';\n")
        self.assertEqual(self.flagged(js), ['#row'])

    def test_a_write_split_over_two_lines(self):
        js = "document.getElementById('row').style.display =\n  on ? '' : 'none';\n"
        self.assertEqual(self.flagged(js), ['#row'])

    def test_a_hiding_rule_inside_an_at_rule_does_not_count(self):
        css = '@media print { .printonly { display:none } }\n.d-none { display:none }\n'
        self.assertNotIn('printonly', dw.hiding_classes(css))

    def test_the_members_of_an_is_list_do_not_become_hiders(self):
        """The stylesheet now has `:is(.btn, .btn-primary).d-none.d-none { display: none }`. A reader
        that split the selector list at every comma made .btn-primary a hiding class, and the scan
        flagged every write at a primary button."""
        css = ':is(.btn, .btn-primary).d-none.d-none { display: none; }\n.d-none { display:none }\n'
        hiders = dw.hiding_classes(css)
        self.assertNotIn('btn-primary', hiders)
        self.assertNotIn('btn', hiders)
        self.assertEqual(dw.split_selector_list(':is(.a, .b).c, .d'), [':is(.a, .b).c', ' .d'])

    def test_a_comment_in_the_stylesheet_does_not_define_a_hider(self):
        css = '/* .ghost { display:none } */\n.d-none { display:none }\n'
        self.assertNotIn('ghost', dw.hiding_classes(css))


class TestTheScanSeesTheRealMarkup(unittest.TestCase):
    """The old write, put back, is flagged against the real index.html and styles.css.

    Each snippet is what the old code did at the element the report is about. If the markup lost
    its hiding class the write would become harmless and this would say so; if the scan lost a shape
    it would stop seeing the write.
    """

    OLD = {
        'maint-cron-row': "document.getElementById('maint-cron-row').style.display = (t === 'cron') ? '' : 'none';",
        'acme-issue-back': "document.getElementById('acme-issue-back').style.display = n > 1 ? '' : 'none';",
        'acme-issue-go': "document.getElementById('acme-issue-go').style.display = n === 3 ? '' : 'none';",
        'iac-convo-output': "document.getElementById('iac-convo-output').style.display = tab === 'convo' ? '' : 'none';",
        'iac-status': "document.getElementById('iac-status').style.display = msg ? '' : 'none';",
        'log-rule-path-row': "document.getElementById('log-rule-path-row').style.display = s === 'path' ? '' : 'none';",
        'log-rule-global-hint': "document.getElementById('log-rule-global-hint').style.display = g ? '' : 'none';",
        'log-rule-unit-hint': "document.getElementById('log-rule-unit-hint').style.display = g ? '' : 'none';",
        'cfg-smtp-pw-set-badge': "document.getElementById('cfg-smtp-pw-set-badge').style.display = d.x ? '' : 'none';",
        'cfg-ldap-pw-set-badge': "document.getElementById('cfg-ldap-pw-set-badge').style.display = d.y ? '' : 'none';",
        '.acme-step': ("document.querySelectorAll('.acme-step').forEach(el => {\n"
                       "  el.style.display = k(el) === cur ? '' : 'none';\n});"),
        '.acme-detail-pane': ("document.querySelectorAll('.acme-detail-pane').forEach(p =>\n"
                              "  p.style.display = p.id === `acme-detail-${tab}` ? '' : 'none');"),
    }

    @classmethod
    def setUpClass(cls):
        cls.js, cls.html, cls.css = dw.shipped_sources()

    def test_each_old_write_is_flagged(self):
        self.assertGreaterEqual(len(self.OLD), 12)
        for name, snippet in self.OLD.items():
            with self.subTest(element=name):
                r = dw.scan({'old.js': snippet}, self.html, self.css, js_templates=self.js)
                names = [v[2].lstrip('#') for v in r['violations']]
                self.assertEqual(names, [name], 'the old write at %s was not flagged' % name)

    def test_the_real_source_with_one_fix_undone_fails(self):
        """The same thing through the real file: put back the line the fix replaced, scan the whole
        source, and the gate's own filter reports it."""
        undo = [
            ('app.js',
             "document.getElementById('maint-cron-row').classList.toggle('d-none', t !== 'cron');",
             "document.getElementById('maint-cron-row').style.display = (t === 'cron') ? '' : 'none';",
             '#maint-cron-row'),
            ('app.js',
             "document.getElementById('cfg-smtp-pw-set-badge').classList.toggle('d-none', !data.smtp_password_set);",
             "document.getElementById('cfg-smtp-pw-set-badge').style.display = data.smtp_password_set ? '' : 'none';",
             '#cfg-smtp-pw-set-badge'),
            ('app-dns.js',
             "p.classList.toggle('d-none', p.id !== `acme-detail-${tab}`));",
             "p.style.display = p.id === `acme-detail-${tab}` ? '' : 'none');",
             '.acme-detail-pane'),
            ('app-logs.js',
             "document.getElementById('log-rule-path-row').classList.toggle('d-none', sourceType !== 'path');",
             "document.getElementById('log-rule-path-row').style.display = sourceType === 'path' ? '' : 'none';",
             '#log-rule-path-row'),
        ]
        for fname, fixed, old, who in undo:
            with self.subTest(element=who):
                self.assertIn(fixed, self.js[fname], 'the fixed line is not where this test expects it')
                mutated = dict(self.js)
                mutated[fname] = self.js[fname].replace(fixed, old, 1)
                self.assertNotEqual(mutated[fname], self.js[fname])
                r = dw.scan(mutated, self.html, self.css)
                left = [v[2] for v in r['violations'] if (v[0], v[2]) not in dw.ALLOW]
                self.assertEqual(left, [who])


class TestAHiddenControlStaysHidden(unittest.TestCase):
    """The stylesheet half. A browser measured the sign-in page of the released 7.3.0: the SSO, SAML
    and passkey buttons carry `d-none` and were drawn anyway, because `.login-btn-oidc` sets
    `display: block` later in the sheet. The Back and Issue buttons of the ACME wizard lost to the row
    rule that gives a button in a modal footer `display: inline-flex`. The rendered check is
    test_v741_hidden_means_hidden_e2e; this one holds the rule itself."""

    @classmethod
    def setUpClass(cls):
        cls.css = dw.strip_css_comments(dw.CSS.read_text())

    def rule(self):
        m = re.search(r':is\(([^)]*)\)\.d-none\.d-none\s*\{([^}]*)\}', self.css)
        self.assertTrue(m, 'the rule that keeps a hidden control hidden is missing from styles.css')
        return [c.strip() for c in m.group(1).split(',')], m.group(2)

    def test_it_covers_the_buttons_that_were_drawn_anyway(self):
        classes, _ = self.rule()
        for c in ('.btn-primary', '.btn-secondary', '.btn-icon', '.btn', '.login-btn'):
            self.assertIn(c, classes)

    def test_it_is_not_important_so_an_inline_display_still_shows_the_control(self):
        """#cs-modal-delete-btn and #cmdb-vault-action carry d-none and are shown by an inline
        display; an !important rule would hide them for good (and a whole-app one blanked the app)."""
        _, body = self.rule()
        self.assertRegex(body, r'display\s*:\s*none\s*;?\s*$')
        self.assertNotIn('important', body)

    def test_it_outranks_the_two_rules_that_beat_the_plain_class(self):
        """The doubled class gives specificity (0,3,0); the row rule is (0,2,0) and .login-btn-oidc
        (0,1,0), so the order of the sheet no longer decides."""
        self.assertRegex(self.css, r'\.login-btn-oidc\s*\{[^}]*display\s*:\s*block')
        self.assertRegex(self.css, r':is\(\.btn, \.btn-secondary, \.btn-primary\)\s*\{\s*display:\s*inline-flex')


if __name__ == '__main__':
    unittest.main()
