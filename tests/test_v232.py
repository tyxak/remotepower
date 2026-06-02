#!/usr/bin/env python3
"""
Tests for v2.3.2 — security hardening.

  - Password hashing: the bcrypt-less fallback is now salted PBKDF2,
    not bare unsalted SHA-256. Legacy SHA-256 hashes still verify
    (backward compatibility). PBKDF2 hashes are self-describing and
    salted (two hashes of the same password differ).
  - The seeded default admin carries `must_change_password`, surfaced
    in the login response and cleared when the password is changed.
"""

import sys as _cj_sys
from pathlib import Path as _cj_Path
_cj_sys.path.insert(0, str(_cj_Path(__file__).resolve().parent))
from clientjs import client_js
import hashlib
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT    = Path(__file__).parent.parent
_CGI_BIN = _ROOT / "server" / "cgi-bin"
sys.path.insert(0, str(_CGI_BIN))

os.environ.setdefault('REQUEST_METHOD', 'GET')
os.environ.setdefault('PATH_INFO', '/')
os.environ.setdefault('CONTENT_LENGTH', '0')
_spec = importlib.util.spec_from_file_location("api_v232", _CGI_BIN / "api.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class TestPasswordHashing(unittest.TestCase):

    def test_pbkdf2_round_trip(self):
        h = api._pbkdf2_hash('correct horse')
        self.assertTrue(h.startswith('pbkdf2$'))
        self.assertTrue(api.verify_password('correct horse', h))
        self.assertFalse(api.verify_password('wrong horse', h))

    def test_pbkdf2_is_salted(self):
        # Two hashes of the same password must differ — proves a
        # per-hash random salt (the whole point vs. bare sha256).
        h1 = api._pbkdf2_hash('samepw')
        h2 = api._pbkdf2_hash('samepw')
        self.assertNotEqual(h1, h2)
        # ...yet both verify
        self.assertTrue(api.verify_password('samepw', h1))
        self.assertTrue(api.verify_password('samepw', h2))

    def test_pbkdf2_iteration_count(self):
        # OWASP floor — don't let this silently regress
        self.assertGreaterEqual(api._PBKDF2_ITERATIONS, 600_000)
        h = api._pbkdf2_hash('x')
        self.assertEqual(h.split('$')[1], str(api._PBKDF2_ITERATIONS))

    def test_legacy_sha256_no_longer_verifies(self):
        # The weak unsalted-SHA-256 verify path was removed (CodeQL: weak
        # hashing of sensitive data). Pre-2.3.2 hashes no longer authenticate —
        # such an account is reset via remotepower-passwd. Only bcrypt/PBKDF2
        # hashes verify now.
        legacy = hashlib.sha256(b'oldpassword').hexdigest()
        self.assertFalse(api.verify_password('oldpassword', legacy))
        self.assertFalse(api.verify_password('nope', legacy))

    def test_hash_password_no_bare_sha256(self):
        # hash_password must never emit a bare 64-hex sha256 — that was
        # the weak pre-2.3.2 fallback. Output is bcrypt ($2) or pbkdf2$.
        h = api.hash_password('whatever')
        self.assertTrue(h.startswith('$2') or h.startswith('pbkdf2$'),
                        f'unexpected hash format: {h[:12]}')
        # specifically: not a bare hex digest
        self.assertFalse(len(h) == 64 and all(c in '0123456789abcdef' for c in h))

    def test_verify_rejects_garbage(self):
        for junk in ('', 'x', 'pbkdf2$bad', 'pbkdf2$1$2', '$2bad'):
            self.assertFalse(api.verify_password('pw', junk))

    def test_corrupt_pbkdf2_does_not_crash(self):
        # A malformed pbkdf2 string must return False, not raise
        self.assertFalse(api.verify_password('pw', 'pbkdf2$notanint$ab$cd'))


class TestDefaultUserHardening(unittest.TestCase):

    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        api.USERS_FILE = self._tmp / 'users.json'

    def test_default_user_not_bare_sha256(self):
        # Re-seed a fresh users.json and check the hash format.
        api.ensure_default_user()
        users = api.load(api.USERS_FILE)
        h = users['admin']['password_hash']
        # Must be bcrypt or pbkdf2 — never the old bare sha256 of
        # b'remotepower'
        self.assertTrue(h.startswith('$2') or h.startswith('pbkdf2$'))
        self.assertNotEqual(h, hashlib.sha256(b'remotepower').hexdigest())
        # The documented default password still works
        self.assertTrue(api.verify_password('remotepower', h))

    def test_default_user_flagged_must_change(self):
        api.ensure_default_user()
        users = api.load(api.USERS_FILE)
        self.assertTrue(users['admin'].get('must_change_password'))


class TestSecurityAssets(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.js = client_js()
        cls.docker_nginx = (_ROOT / 'docker/nginx-docker.conf').read_text()
        cls.bare_nginx = (_ROOT / 'server/conf/remotepower.conf').read_text()

    def test_default_pw_banner_in_js(self):
        self.assertIn('_mustChangePassword', self.js)
        self.assertIn('default-pw-banner', self.js)

    def test_nginx_configs_have_security_headers(self):
        # Both nginx configs ship the hardening headers — regression
        # guard so a future edit doesn't silently drop them.
        for name, conf in (('docker', self.docker_nginx),
                           ('bare-metal', self.bare_nginx)):
            self.assertIn('X-Frame-Options', conf, f'{name} missing X-Frame-Options')
            self.assertIn('Content-Security-Policy', conf, f'{name} missing CSP')
            self.assertIn('X-Content-Type-Options', conf, f'{name} missing nosniff')

    def test_nginx_blocks_cgi_bin_source(self):
        # Defense in depth: cgi-bin/ lives inside the web root but is only meant
        # to be executed via /api/ through fcgiwrap, so both nginx configs must
        # deny the /cgi-bin/ URL (it should never resolve to a static file).
        import re
        for name, conf in (('docker', self.docker_nginx),
                           ('bare-metal', self.bare_nginx)):
            m = re.search(r'location\s+\^~\s+/cgi-bin/\s*\{([^}]*)\}', conf)
            self.assertIsNotNone(
                m, f"{name} nginx config has no `location ^~ /cgi-bin/` block — "
                   f"the CGI source is publicly downloadable")
            body = m.group(1)
            self.assertTrue(
                'deny all' in body or 'return 404' in body or 'return 403' in body,
                f"{name} /cgi-bin/ block must deny access (deny all / return 404)")

    def test_csp_no_unsafe_inline(self):
        # L1 security fix: 'unsafe-inline' must not appear in the CSP directive.
        import re
        for name, conf in (('docker', self.docker_nginx),
                           ('bare-metal', self.bare_nginx)):
            csp_line = next(
                (l for l in conf.splitlines() if 'add_header Content-Security-Policy' in l),
                ''
            )
            self.assertTrue(csp_line,
                            f"{name} has no add_header Content-Security-Policy line")
            self.assertNotIn("'unsafe-inline'", csp_line,
                             f"{name} CSP directive still contains 'unsafe-inline' (L1 finding)")

    # All HTML files that get served to a browser. Anything added here is
    # subject to the strict CSP and must contain no inline code or external
    # auto-loaded resources.
    _SHIPPED_HTML = [
        ('server/html/index.html',   'index.html'),
        ('server/html/swagger.html', 'swagger.html'),
        ('docs/Manual.html',         'Manual.html'),
    ]

    def test_no_inline_scripts_in_html(self):
        import re
        for relpath, name in self._SHIPPED_HTML:
            html = (_ROOT / relpath).read_text()
            inline_scripts = re.findall(r'<script(?![^>]*src=)[^>]*>', html, re.IGNORECASE)
            self.assertEqual(inline_scripts, [],
                             f'Inline <script> blocks found in {name}: {inline_scripts}')
            inline_styles = re.findall(r'<style[^>]*>', html, re.IGNORECASE)
            self.assertEqual(inline_styles, [],
                             f'Inline <style> blocks found in {name}: {inline_styles}')
            # Only flag tags that the browser auto-loads (script/link/img/iframe),
            # not user-clickable <a href> documentation links.
            ext = re.findall(
                r'<(?:script|link|img|iframe)[^>]*\s(?:src|href)="(https?://[^"]+)"',
                html, re.IGNORECASE)
            self.assertEqual(ext, [],
                             f'{name} auto-loads external resources: {ext}')

    def test_no_inline_event_handlers_in_html(self):
        import re
        for relpath, name in self._SHIPPED_HTML:
            html = (_ROOT / relpath).read_text()
            handlers = re.findall(r'\s(on(?:click|change|input|keydown|drop|dragover|dragleave|load|error)=)', html)
            self.assertEqual(handlers, [],
                             f'Inline event handlers found in {name}: {handlers}')
            attr_styles = re.findall(r'<[a-zA-Z][^>]*\sstyle="', html)
            self.assertEqual(attr_styles, [],
                             f'Inline style= attrs found in {name}: {len(attr_styles)}')

    def test_no_javascript_uri_in_html(self):
        # CSP `script-src 'self'` blocks javascript: URIs (e.g. <a href="javascript:foo()">).
        # Use data-action="…" data-prevent-default instead.
        import re
        for relpath, name in self._SHIPPED_HTML:
            html = (_ROOT / relpath).read_text()
            uris = re.findall(r'(?:href|src)\s*=\s*[\'"]javascript:[^\'"]*[\'"]', html, re.IGNORECASE)
            self.assertEqual(uris, [],
                             f'{name} contains javascript: URIs: {uris}')

    def test_vendor_libs_are_self_hosted(self):
        # CSP 'self' only allows /static/* origins, so the vendor libs the
        # app loads at runtime must live on disk under static/vendor/.
        vendor_dir = _ROOT / 'server' / 'html' / 'static' / 'vendor'
        self.assertTrue(vendor_dir.is_dir(), 'static/vendor/ is missing')
        expected = [
            'xterm/xterm.min.js',
            'xterm/xterm.min.css',
            'xterm-addon-fit/addon-fit.min.js',
            'qrcode-generator/qrcode.min.js',
            'fonts/inter-jetbrains.css',
            'swagger-ui/swagger-ui-bundle.min.js',
            'swagger-ui/swagger-ui.min.css',
        ]
        for rel in expected:
            self.assertTrue((vendor_dir / rel).is_file(),
                            f'vendor file missing: {rel}')

    def test_no_external_cdn_in_shipped_assets(self):
        # No code path should auto-load https:// resources — would be blocked
        # by `script-src 'self'` / `style-src 'self'`.
        import re
        css = (_ROOT / 'server' / 'html' / 'static' / 'css' / 'styles.css').read_text()
        # @import / url() in CSS to external origins
        ext = re.findall(r'(?:@import\s+url\(|url\(|src=)\s*[\'"]?(https?://[^\'")\s]+)', css)
        self.assertEqual(ext, [], f'styles.css loads external resources: {ext}')

        js = client_js()
        # script.src = 'https://...' or link.href = 'https://...' assignments
        ext = re.findall(r'\.(?:src|href)\s*=\s*[\'"`](https?://[^\'"`]+)', js)
        self.assertEqual(ext, [],
                         f'app.js auto-loads external scripts/stylesheets: {ext}')

    def test_no_inline_event_handlers_in_appjs(self):
        appjs_path = _ROOT / 'server' / 'html' / 'static' / 'js' / 'app.js'
        appjs = client_js()
        import re
        # Only flag occurrences not on comment lines
        code_lines = [l for l in appjs.splitlines() if not l.strip().startswith('//')]
        code = '\n'.join(code_lines)
        for attr in ('onclick=', 'onchange=', 'oninput='):
            self.assertNotIn(attr, code,
                             f"Inline {attr} found in app.js template strings")


class TestCSPMigrationFidelity(unittest.TestCase):
    """Each test below codifies a pattern that broke during the v3.0.4 →
    v3.0.5 CSP migration and was patched in production. Together they
    make sure no future commit reintroduces any of them. New patterns
    discovered in operations should land here with a one-paragraph
    comment that names the failure mode the operator saw."""

    JS_FILES = [
        'server/html/static/js/app.js',
        'server/html/static/js/sw-register.js',
        'server/html/static/js/swagger-init.js',
        'server/html/sw.js',
    ]
    HTML_FILES = [
        'server/html/index.html',
        'server/html/swagger.html',
        'docs/Manual.html',
    ]
    CSS_FILES = [
        'server/html/static/css/styles.css',
        'server/html/static/css/swagger.css',
        'server/html/static/css/manual.css',
    ]

    # Every DOM event that the browser will dispatch from an inline `on…=`
    # attribute. Kept narrow so we don't flag arbitrary identifiers that
    # happen to start with "on".
    DOM_EVENTS = frozenset({
        'onclick', 'onchange', 'oninput', 'onkeydown', 'onkeyup', 'onkeypress',
        'onfocus', 'onblur', 'onsubmit', 'onreset', 'onload', 'onerror',
        'onresize', 'onscroll', 'onmouseover', 'onmouseout', 'onmousedown',
        'onmouseup', 'onmousemove', 'onmouseenter', 'onmouseleave',
        'oncontextmenu', 'ondrag', 'ondragstart', 'ondragend', 'ondragover',
        'ondragleave', 'ondrop', 'onwheel', 'onanimationend',
        'ontransitionend', 'ontoggle', 'onbeforeinput', 'onpointerdown',
        'onpointerup', 'onpointermove', 'onpointercancel', 'oncopy', 'oncut',
        'onpaste', 'onauxclick', 'ondblclick', 'ontouchstart', 'ontouchend',
        'ontouchmove',
    })

    def _strip_js_comments(self, text):
        """Drop JS line-comments and bare lines starting with `*` (block-
        comment continuation). Not a real parser — good enough to avoid
        flagging things we wrote about in comments."""
        out = []
        for line in text.splitlines():
            s = line.lstrip()
            if s.startswith('//'):
                continue
            if s.startswith('*'):
                continue
            out.append(line)
        return '\n'.join(out)

    # ── 1. inline on*= handlers anywhere in shipped JS or HTML ─────────────
    def test_no_inline_on_handlers_in_js_templates(self):
        """`<button onclick="…">` inside an innerHTML template string is
        blocked at runtime by `script-src 'self'` (no `'unsafe-inline'`).
        Failure mode the operator sees: clicking the button does nothing
        and the console shows a `Refused to execute inline event handler`
        message. Use data-action / data-action-btn delegation instead."""
        import re
        for f in self.JS_FILES:
            body = (_ROOT / f).read_text()
            code = self._strip_js_comments(body)
            handlers = [m.group(1) for m in re.finditer(
                r'\s(on[a-zA-Z]+)\s*=\s*[\'"]', code) if m.group(1).lower() in self.DOM_EVENTS]
            self.assertFalse(handlers,
                f"{f} contains inline on*= handlers: {sorted(set(handlers))}")

    def test_no_inline_on_handlers_in_html_files(self):
        """Same as above but for the static HTML files served to the browser."""
        import re
        for f in self.HTML_FILES:
            body = (_ROOT / f).read_text()
            handlers = [m.group(1) for m in re.finditer(
                r'\s(on[a-zA-Z]+)\s*=\s*[\'"]', body) if m.group(1).lower() in self.DOM_EVENTS]
            self.assertFalse(handlers,
                f"{f} contains inline on*= handlers: {sorted(set(handlers))}")

    # ── 2 & 3. inline style="…" attributes ─────────────────────────────────
    def test_no_inline_style_attributes_in_html(self):
        """`<div style="color:red">` is blocked by `style-src 'self'` (no
        unsafe-inline). Use a utility class or the isl-N auto-generated
        class. Failure mode: the inline style doesn't render."""
        import re
        for f in self.HTML_FILES:
            body = (_ROOT / f).read_text()
            hits = re.findall(r'<[a-zA-Z][^>]*\sstyle="', body)
            self.assertEqual(hits, [],
                f'{f} contains {len(hits)} inline style="" attribute(s)')

    def test_no_inline_style_in_js_innerhtml(self):
        """`<div style="…">` typed into an innerHTML template string —
        same block as test 2 but caught for the JS-template case."""
        import re
        for f in self.JS_FILES:
            body = (_ROOT / f).read_text()
            code = self._strip_js_comments(body)
            hits = re.findall(r'<[a-zA-Z][^<>]*\sstyle="[^"]', code)
            self.assertEqual(hits, [],
                f'{f} contains {len(hits)} style="…" in template strings')

    # ── 4. setAttribute('on*'|'style', …) ──────────────────────────────────
    def test_no_setattribute_on_or_style(self):
        """`element.setAttribute('onclick', …)` writes the inline attribute
        via DOM, which CSP still blocks. Same for `setAttribute('style', …)`.
        Use element.addEventListener and element.style.<prop> = … instead."""
        import re
        for f in self.JS_FILES:
            body = (_ROOT / f).read_text()
            code = self._strip_js_comments(body)
            hits = re.findall(
                r"setAttribute\(\s*['\"](on[a-zA-Z]+|style)['\"]", code)
            self.assertEqual(hits, [],
                f'{f} contains setAttribute({hits}) — CSP-blocked at runtime')

    # ── 5. element.on* = '…string…' (string-form handler assignment) ───────
    def test_no_string_form_event_handler_assignments(self):
        """`el.onclick = 'doSomething()'` is parsed-and-evaluated by the
        browser and is rejected by `script-src 'self'` for the same reason
        as inline on*= attributes. Function-form assignments
        (`el.onclick = fn` or `el.onclick = () => …`) are fine."""
        import re
        for f in self.JS_FILES:
            body = (_ROOT / f).read_text()
            code = self._strip_js_comments(body)
            hits = re.findall(
                r"\.on(?:click|change|input|error|load|keydown|drop|"
                r"mouseover|mouseout|toggle|submit|focus|blur)\s*=\s*"
                r"['\"][^'\"]+['\"]", code)
            self.assertEqual(hits, [],
                f'{f} contains string-form event handler assignments: {len(hits)}')

    # ── 6. dynamic <style> element injection ───────────────────────────────
    def test_no_dynamic_style_element_creation(self):
        """`document.createElement('style')` followed by `appendChild` is
        blocked by `style-src 'self'` because the resulting `<style>` node
        is "inline". Move the rule to styles.css (or one of the page-
        specific stylesheets)."""
        import re
        for f in self.JS_FILES:
            body = (_ROOT / f).read_text()
            code = self._strip_js_comments(body)
            hits = re.findall(r"createElement\(\s*['\"]style['\"]", code)
            self.assertEqual(hits, [],
                f'{f} creates {len(hits)} <style> element(s) at runtime')

    # ── 7. document.write / writeln ────────────────────────────────────────
    def test_no_document_write(self):
        """document.write / writeln after page load would re-parse the
        document and inject inline scripts that defy CSP. Never used in
        this codebase, but worth a guardrail."""
        import re
        for f in self.JS_FILES:
            body = (_ROOT / f).read_text()
            code = self._strip_js_comments(body)
            hits = re.findall(r"document\.write(?:ln)?\s*\(", code)
            self.assertEqual(hits, [],
                f'{f} uses document.write/writeln')

    # ── 8 & 9. eval / new Function / string-form setTimeout/Interval ───────
    def test_no_eval_or_function_constructor(self):
        """Both require `'unsafe-eval'` in script-src, which the project's
        CSP deliberately omits. Use a closure or a pre-defined function."""
        import re
        for f in self.JS_FILES:
            body = (_ROOT / f).read_text()
            code = self._strip_js_comments(body)
            hits = re.findall(r"\beval\s*\(|new\s+Function\s*\(", code)
            self.assertEqual(hits, [],
                f'{f} uses eval/new Function — needs unsafe-eval')

    def test_no_string_timer_callbacks(self):
        """`setTimeout('foo()', 100)` is the function-equivalent of eval and
        is similarly blocked. Pass a function reference instead."""
        import re
        for f in self.JS_FILES:
            body = (_ROOT / f).read_text()
            code = self._strip_js_comments(body)
            hits = re.findall(r"set(?:Timeout|Interval)\s*\(\s*['\"]", code)
            self.assertEqual(hits, [],
                f'{f} uses string-form setTimeout/setInterval')

    # ── 10. javascript: URIs ───────────────────────────────────────────────
    def test_no_javascript_uri_anywhere(self):
        """`<a href="javascript:…">` and the script-tag-src equivalent are
        blocked by `script-src 'self'`. Use a data-action / preventDefault
        click handler."""
        import re
        for f in self.JS_FILES + self.HTML_FILES:
            body = (_ROOT / f).read_text()
            code = self._strip_js_comments(body) if str(f).endswith('.js') else body
            hits = re.findall(r"['\"]\s*javascript:", code)
            self.assertEqual(hits, [],
                f'{f} contains {len(hits)} javascript: URI(s)')

    # ── 11. external @import / url() in CSS ────────────────────────────────
    def test_no_external_imports_in_css(self):
        """`@import url('https://…')` and `url('https://…')` in CSS are
        blocked by `style-src 'self'` (and the corresponding font-src /
        img-src). All vendor assets must live under /static/vendor/."""
        import re
        for f in self.CSS_FILES:
            body = (_ROOT / f).read_text()
            hits = re.findall(
                r"(?:@import\s+url\(|url\()\s*['\"]?(https?://[^'\")]+)",
                body)
            self.assertEqual(hits, [],
                f'{f} references external URLs: {hits}')

    # ── 12. CSS rules with un-substituted JS template `${…}` ───────────────
    def test_no_unresolved_template_in_css(self):
        """The auto-class generator that ran during the CSP migration
        occasionally left a JS template `${expr}` baked into a CSS rule.
        Browsers silently drop the declaration containing the unresolved
        token, so the visual effect that depended on it (severity colour,
        active-row highlight, etc.) silently disappears. Forty real
        instances were patched across v3.0.5; this guard catches any
        future reintroduction."""
        import re
        for f in self.CSS_FILES:
            body = (_ROOT / f).read_text()
            hits = re.findall(r'\.\w+[\w.:>+~,\s-]*\{[^}]*\$\{', body)
            self.assertEqual(hits, [],
                f'{f} contains {len(hits)} rule(s) with un-substituted ${{}}')

    # ── 13. .style.display = '' against an element with a display:none class ─
    def test_no_empty_display_reveal_against_class(self):
        """`element.style.display = ''` clears only the inline `style`
        attribute; if a CSS class on the element sets display:none, the
        element stays hidden. This was the headline bug across v3.0.5 —
        AI page, Audit tab, Host Config tabs, Logs Fleet-wide tab, the
        Mitigation modal, etc. all rendered blank when their reveal path
        was `style.display = ''`. Operators see: panel content never
        appears after clicking the tab/button.

        This test catches the `document.getElementById('X').style.display = ''`
        form where X is in HTML with a class that has display:none. The
        variable form (`section.style.display = ''`) can't be statically
        resolved, but `style.display = 'block'` (or 'flex'/'inline-block')
        is the universal correct reveal — make sure ANY .style.display
        empty-string reveal is on an element with no display:none class."""
        import re
        html = (_ROOT / 'server' / 'html' / 'index.html').read_text()
        css  = (_ROOT / 'server' / 'html' / 'static' / 'css' / 'styles.css').read_text()
        js   = client_js()

        hidden_classes = set(re.findall(
            r'\.([a-z][a-z0-9_-]*)\s*\{[^}]*display\s*:\s*none[^}]*\}', css))
        id_classes = {}
        for m in re.finditer(r'<[a-z][^>]*\bid="([^"]+)"[^>]*>', html):
            cm = re.search(r'\bclass="([^"]+)"', m.group(0))
            if cm:
                id_classes[m.group(1)] = cm.group(1).split()

        bugs = []
        for m in re.finditer(
                r"document\.getElementById\(['\"]([^'\"]+)['\"]\)"
                r"\.style\.display\s*=\s*['\"][\"\']", js):
            elid = m.group(1)
            hidden = [c for c in id_classes.get(elid, []) if c in hidden_classes]
            if hidden:
                line = js[:m.start()].count('\n') + 1
                bugs.append(f'app.js:{line}  #{elid} hidden by class {hidden}')
        self.assertEqual(bugs, [],
            'Empty-string display reveal against display:none class — use explicit '
            '"block" / "flex" / "inline-block" instead:\n  ' + '\n  '.join(bugs))

    # ── 14. <a href="#"> with data-action but no data-prevent-default ──────
    def test_data_action_anchors_have_prevent_default(self):
        """`<a href="#" data-action="…">` without `data-prevent-default`
        appends `#` to the URL and scrolls to the top before the action
        runs. Spotted on the Home page's Fleet-activity device-card link
        in v3.0.5."""
        import re
        for f in self.JS_FILES + self.HTML_FILES:
            body = (_ROOT / f).read_text()
            code = self._strip_js_comments(body) if str(f).endswith('.js') else body
            hits = []
            for m in re.finditer(
                    r'<a\s+[^>]*href\s*=\s*["\']#["\'][^>]*>', code):
                s = m.group(0)
                if 'data-action' in s and 'data-prevent-default' not in s:
                    hits.append(s[:120])
            self.assertEqual(hits, [],
                f'{f} contains data-action anchors without data-prevent-default')

    # ── 15. duplicate IDs in HTML ──────────────────────────────────────────
    def test_no_duplicate_ids_in_html(self):
        """Two elements with the same id collapse via getElementById —
        only the first match is returned, the second is orphaned DOM. In
        v3.0.5 the device-drawer was duplicated, the new dynamic version
        and an old hardcoded version both carrying id='device-drawer';
        the Audit tab was the first element's empty container and the
        old hardcoded sections were unreachable.

        Skips matches that appear inside `<code>` and `<pre>` tags —
        those are documentation showing literal text, not real attrs."""
        import re
        from collections import Counter
        for f in self.HTML_FILES:
            body = (_ROOT / f).read_text()
            # Drop the contents of <code>…</code> and <pre>…</pre> first
            stripped = re.sub(r'<code>.*?</code>', '', body, flags=re.DOTALL)
            stripped = re.sub(r'<pre[^>]*>.*?</pre>', '', stripped, flags=re.DOTALL)
            ids = re.findall(r'\bid="([^"]+)"', stripped)
            dups = sorted(x for x, c in Counter(ids).items() if c > 1)
            self.assertEqual(dups, [],
                f'{f} contains duplicate IDs: {dups}')


if __name__ == '__main__':
    unittest.main(verbosity=2)
