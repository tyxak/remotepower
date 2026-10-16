"""The translation dictionary is fetched from a URL that changes with every release.

/static/ is served `Cache-Control: public, max-age=31536000, immutable`, so a
static URL must change whenever its file does. app.js built the dictionary's URL
as 'static/js/i18n.js?v=' + (window.RP_VERSION || '6.1.2'), and nothing ever set
RP_VERSION: from 6.1.2 on, every install asked for i18n.js?v=6.1.2, and a browser
that had it kept that copy for a year. deploy-server.sh's content-hash rewrite
only touches <script src> and <link href> in index.html, so it never reached the
URL either. A non-English user could miss every translation shipped since.

Now index.html carries the URL in <meta name="rp-i18n">, where the cache-bust
lockstep test, both bump tools and the deploy rewrite all see it, and the loader
reads it. These tests run the loader under node and the deploy rewrite in a
temporary web root.
"""
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

import srcpin  # noqa: E402

_HTML = _ROOT / 'server' / 'html'
_NODE = shutil.which('node')
_META = re.compile(r'<meta name="rp-i18n" content="([^"]+)">')


def _marker():
    sw = (_HTML / 'sw.js').read_text()
    return re.search(r"CACHE_NAME\s*=\s*'remotepower-shell-v([\w.\-]+)'", sw).group(1)


class TestTheUrlIsInThePage(unittest.TestCase):

    def test_index_html_names_the_dictionary_with_the_cache_marker(self):
        found = _META.findall((_HTML / 'index.html').read_text())
        self.assertEqual(found, ['static/js/i18n.js?v=%s' % _marker()])

    def test_the_loader_has_no_version_of_its_own(self):
        body = srcpin.js_function((_HTML / 'static/js/app.js').read_text(), '_ensureI18n')
        self.assertIn('meta[name="rp-i18n"]', body)
        self.assertNotIn('RP_VERSION', body)
        self.assertIsNone(re.search(r"'\d+\.\d+\.\d+", body), 'a version literal in the loader')


@unittest.skipUnless(_NODE, 'node not installed')
class TestTheLoaderUsesIt(unittest.TestCase):
    """The real _ensureI18n, run under node with just enough of a document."""

    def run_loader(self, meta_content):
        fn = srcpin.js_function((_HTML / 'static/js/app.js').read_text(), '_ensureI18n')
        script = (
            'const window = {}; let appended = null;\n'
            'const document = {\n'
            '  querySelector: (s) => (s === \'meta[name="rp-i18n"]\' && %s !== null) ? {content: %s} : null,\n'
            '  createElement: () => ({}),\n'
            '  head: { appendChild: (el) => { appended = el; } },\n'
            '};\n'
            'let _i18nPromise = null;\n%s\n'
            '_ensureI18n();\n'
            'process.stdout.write(JSON.stringify(appended && appended.src));\n'
        ) % (json.dumps(meta_content), json.dumps(meta_content), fn)
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / 'run.js').write_text(script)
            p = subprocess.run([_NODE, 'run.js'], cwd=td, capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr[-1500:])
        return json.loads(p.stdout)

    def test_it_fetches_the_url_the_page_names(self):
        self.assertEqual(self.run_loader('static/js/i18n.js?v=abc123def456'),
                         'static/js/i18n.js?v=abc123def456')

    def test_without_the_meta_it_still_loads_the_dictionary(self):
        self.assertTrue(self.run_loader(None).startswith('static/js/i18n.js'))


class TestTheDeployRewriteHashesIt(unittest.TestCase):
    """deploy-server.sh's own Python, run against a temporary web root."""

    def rewrite_code(self):
        sh = _ROOT / 'deploy-server.sh'
        if not sh.exists():
            self.skipTest('excluded from dist tree')
        blocks = re.findall(r"python3 - << 'PYEOF'\n(.*?)\nPYEOF", sh.read_text(), re.S)
        found = [b for b in blocks if 'WEB_ROOT' in b and '_replace' in b]
        self.assertEqual(len(found), 1, 'control: the content-hash rewrite was found in deploy-server.sh')
        self.assertIn("WEB_ROOT = Path('/var/www/remotepower')", found[0])
        return found[0]

    def run_rewrite(self, web_root):
        run = self.rewrite_code().replace("WEB_ROOT = Path('/var/www/remotepower')", 'WEB_ROOT = Path(%r)' % str(web_root))
        p = subprocess.run([sys.executable, '-c', run], capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr)
        return (Path(web_root) / 'index.html').read_text()

    def test_the_real_page_hashes_styles_and_the_dictionary_and_keeps_scripts_on_the_marker(self):
        """The real index.html and the real files. Stylesheets and the dictionary
        get content hashes. Scripts keep the release marker: lazy modules take
        their ?v= from app.js's tag and the sidebar's version pill reads the
        version out of it (TestScriptsCarryTheMarker says why)."""
        marker = _marker()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / 'www'
            shutil.copytree(_HTML, root, ignore=shutil.ignore_patterns('vendor', '*.png', '*.ico', '*.woff2'))
            html = self.run_rewrite(root)
        links = re.findall(r'<link [^>]*href="static/[^"?]+\?v=([^"]+)"', html)
        scripts = re.findall(r'<script\b[^>]*\bsrc="static/[^"?]+\?v=([^"]+)"', html)
        meta = _META.findall(html)
        self.assertGreaterEqual(len(links), 1, 'control: the page links its stylesheet')
        self.assertGreaterEqual(len(scripts), 20, 'control: the page loads its scripts')
        self.assertEqual([v for v in links if not re.fullmatch(r'[0-9a-f]{12}', v)], [])
        self.assertEqual(len(meta), 1)
        self.assertRegex(meta[0], r'^static/js/i18n\.js\?v=[0-9a-f]{12}$')
        self.assertEqual(set(scripts), {marker})

    def test_the_meta_gets_the_dictionarys_content_hash(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'static' / 'js').mkdir(parents=True)
            (root / 'static' / 'js' / 'i18n.js').write_text('var DICT = {};\n')
            (root / 'static' / 'js' / 'app.js').write_text('// app\n')
            (root / 'index.html').write_text(
                '<meta name="rp-i18n" content="static/js/i18n.js?v=7.4.0-1">\n'
                '<script defer src="static/js/app.js?v=7.4.0-1"></script>\n')
            html = self.run_rewrite(root)
        want = hashlib.sha256(b'var DICT = {};\n').hexdigest()[:12]
        self.assertIn('content="static/js/i18n.js?v=%s"' % want, html)
        self.assertIn('static/js/app.js?v=7.4.0-1"', html, 'a script keeps the marker')


class TestScriptsCarryTheMarker(unittest.TestCase):
    """Why the deploy rewrite leaves scripts alone: two readers of app.js's ?v=."""

    def test_lazy_modules_take_their_version_from_app_js(self):
        body = srcpin.js_function((_HTML / 'static/js/app.js').read_text(), '_jsBundleVersion')
        self.assertIn('static/js/app.js', body)

    def test_the_version_pill_reads_a_dotted_version_out_of_it(self):
        src = (_HTML / 'static/js/app.js').read_text()
        self.assertIn("script[src*=\"app.js?v=\"]", src)
        self.assertIn('[?&]v=(\\d+\\.\\d+\\.\\d+)', src)
        self.assertRegex('static/js/app.js?v=%s' % _marker(), r'[?&]v=(\d+\.\d+\.\d+)',
                         'the marker carries the version the pill shows')

if __name__ == '__main__':
    unittest.main()
