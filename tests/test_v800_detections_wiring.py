#!/usr/bin/env python3
"""8.0.0: Detections -- every place a module, an event and a tab has to be named, read from the sources.

A module that is named in one registry and not in the next fails quietly: the Settings box that does not save, the tab that never loads its file, the event that never shows in the
feed, the route the API reference does not list. Each of those has its check here, and each is a population read from the code, not a list kept by hand. The behaviour behind them
is tested in test_v800_detections_rules.py (the rules), test_v800_detections_sweep.py (the sweep and the routes) and test_v800_detections_e2e.py (the page).
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('RP_DATA_DIR', tempfile.mkdtemp(prefix='rp-detections-wiring-'))
_TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(_TESTS))
sys.path.insert(0, str(_TESTS.parent / 'server' / 'cgi-bin'))

import srcpin  # noqa: E402
from test_ip_intel import _fresh_api  # noqa: E402

ROOT = _TESTS.parent
JS = ROOT / 'server' / 'html' / 'static' / 'js'
APP = (JS / 'app.js').read_text()
DET = (JS / 'app-detections.js').read_text()
HTML = (ROOT / 'server' / 'html' / 'index.html').read_text()
NODE = shutil.which('node')


class TestTheModuleIsNamedWhereAModuleMustBe(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.api = _fresh_api()

    def test_the_server_registry_says_off_by_default_and_names_the_prefix(self):
        self.assertEqual(self.api._MODULES['detections'], ('detections_module_enabled', False, ('/api/detections',)))
        self.assertFalse(self.api._module_on('detections'), 'an installation that never opted in has no sweep and no routes')

    def test_the_client_mirrors_have_the_same_key_and_default(self):
        self.assertRegex(APP, r"MODULE_PAGES = \{[^}]*\bdetections:\s+null,")
        self.assertIn("['cfg-mod-detections', 'detections_module_enabled', false]", APP)
        self.assertEqual(len(re.findall(r'id="cfg-mod-detections"', HTML)), 1, 'the Settings box that the module row of the client loads and saves')

    def test_the_client_registry_has_the_same_modules_as_the_server_one(self):
        server = set(self.api._MODULES)
        pages = set(re.findall(r'^\s{2}([a-z_]+):\s+(?:null|\'[a-z-]+\'),', APP[APP.index('const MODULE_PAGES = {'):APP.index('const MODULE_SETTINGS')], re.M))
        settings = {re.match(r"cfg-mod-(\w+)", i).group(1) for i in re.findall(r"\['(cfg-mod-\w+)',", APP)}
        self.assertEqual((server - pages, pages - server), (set(), set()))
        self.assertEqual((server - settings, settings - server), (set(), set()))

    def test_the_tab_is_hidden_by_its_module_and_its_file_is_fetched_only_then(self):
        self.assertIn('data-pg-tab-btn="detections" data-module="detections"', HTML)
        self.assertIn("['ipintel', 'detections', 'detections', 'app-detections.js', 'detectionsEnter']", APP)
        lazy = re.search(r"const _LAZY_NON_PAGE_MODULES = \[([^\]]*)\]", APP).group(1)
        self.assertIn("'app-detections.js'", lazy)
        self.assertNotRegex(HTML, r'<script[^>]+app-detections\.js', 'a script tag would load it for everybody, module on or not')
        self.assertTrue((JS / 'app-detections.js').is_file())

    def test_the_card_carries_its_tab_and_starts_hidden(self):
        m = re.search(r'<div id="detections-wrap" data-pg-tab="detections" hidden>', HTML)
        self.assertTrue(m, 'the wrapper that detectionsEnter shows when the module is on')


class TestAGatedFieldOfALazyPageIsGated(unittest.TestCase):
    """Fleet Query is a lazy page: its markup is a <template> that showPage clones on the first visit, after the module gates ran. The Talks to field kept its d-none for ever."""

    def test_showpage_applies_the_gates_to_the_clone(self):
        body = srcpin.js_function(APP, 'showPage')
        i = body.index('cloneNode(true)')
        self.assertIn('_applyModuleElementGates(window._modules)', body[i:i + 700], 'the gates must run after the clone, or a gated field of a lazy page is never shown')

    def test_every_element_a_module_gates_that_is_inside_a_lazy_page_is_covered_by_that(self):
        lazy = re.findall(r'<template data-page-tpl="([a-z-]+)">(.*?)</template>', HTML, re.S)
        self.assertTrue(lazy, 'the scan found no lazy page')
        gated = {name: re.findall(r'data-module="(\w+)"', body) for name, body in lazy if 'data-module="' in body}
        self.assertEqual(sorted(gated), ['query'], 'if another lazy page names a module, it depends on the same call: %s' % gated)
        self.assertEqual(sorted(set(gated['query'])), ['detections', 'traffic'])


class TestTheEventIsNamedWhereAnEventMustBe(unittest.TestCase):

    @unittest.skipUnless(NODE, 'node not installed')
    def test_a_detection_in_the_feed_opens_the_tab_and_no_other_event_does(self):
        body = srcpin.js_function(APP, '_homeActivityAttrs')
        script = ('function escAttr(s){return String(s);}\n' + body + '\n'
                  'const out = {};\n'
                  'for (const ev of ["detection_found", "traffic_watch", "brute_force_detected", "cve_found"]) out[ev] = _homeActivityAttrs(ev, {device_id: "d1", device_name: "web01"});\n'
                  'console.log(JSON.stringify(out));\n')
        d = Path(tempfile.mkdtemp(prefix='rp-detroute-'))
        try:
            f = d / 'route.js'
            f.write_text(script)
            r = subprocess.run([NODE, str(f)], capture_output=True, text=True, timeout=60)
        finally:
            shutil.rmtree(d, ignore_errors=True)
        self.assertEqual(r.returncode, 0, r.stderr[-400:])
        out = json.loads(r.stdout)
        self.assertIn('data-home-act="detections"', out['detection_found'])
        for other in ('traffic_watch', 'brute_force_detected', 'cve_found'):
            self.assertNotIn('data-home-act="detections"', out[other], 'a case group lost its return to the new one: %s' % other)

    def test_the_nav_action_the_feed_names_goes_to_the_tab_of_the_page(self):
        body = srcpin.js_function(APP, '_homeNavAction')
        case = re.search(r"case 'detections':(.*?)break;", body, re.S)
        self.assertTrue(case, 'the feed names an act the click handler does not know')
        self.assertIn("showPage('ipintel'", case.group(1))
        self.assertIn("pgTab('ipintel:detections')", case.group(1))

    def test_the_feed_and_the_inbox_know_the_event(self):
        self.assertRegex(APP, r"'detection_found': 'critical'")
        feed = APP[APP.index('function _renderHomeActivity'):]
        self.assertIn("'detection_found',", feed[:feed.index('const _seenActivity')], 'the allow list of the activity feed (test_v223 holds that it equals the server set)')
        self.assertIn("e.event === 'detection_found' ? p.detail", feed, 'two findings on one host are two rows')

    def test_the_server_names_the_event_in_every_registry_it_has(self):
        api = _fresh_api()
        ev = api.EVENT_REGISTRY['detection_found']
        self.assertEqual((ev['kind'], ev['severity'], ev.get('lifecycle')), ('detections', None, 'point'))
        self.assertIn('detection_found', api.WEBHOOK_EVENT_NAMES)
        self.assertIn('detection_found', api._ALERT_RULES)
        self.assertIn('detections', {k for k, _l, _g in api.CHANNEL_KIND_DEFS})
        self.assertIn('"detection_found": 0x', (ROOT / 'server' / 'cgi-bin' / 'notify.py').read_text(), 'a colour for the chat message')
        self.assertIn('elif event == "detection_found":', (ROOT / 'server' / 'cgi-bin' / 'notify.py').read_text(), 'a sentence for the message')


class TestThePageReadsWhatTheMarkupHas(unittest.TestCase):

    def test_every_id_the_script_reads_is_in_the_page(self):
        ids = set(re.findall(r"getElementById\('(detections-[a-z-]+)'\)", DET)) | set(re.findall(r"'(detections-[a-z-]+)'", DET))
        ids = {i for i in ids if i not in ('detections-findings',)}                    # the name of the table, not an element
        missing = sorted(i for i in ids if 'id="%s"' % i not in HTML)
        self.assertTrue(ids, 'the scan found nothing to check')
        self.assertEqual(missing, [])

    def test_every_action_the_markup_and_the_script_dispatch_is_a_function_of_the_script(self):
        actions = set(re.findall(r'data-action="(detections\w*|loadDetections)"', HTML)) | set(re.findall(r'data-action="(detections\w*|loadDetections)"', DET))
        self.assertEqual(actions, {'loadDetections', 'detectionsSave', 'detectionsOpenHost'})
        for a in actions:
            self.assertRegex(DET, r'(?:async )?function %s\(' % a)

    def test_the_table_has_a_sortable_head_for_every_column_the_script_registers(self):
        cols = re.search(r"columns: \[([^\]]*)\]", DET).group(1)
        names = re.findall(r"'(\w+)'", cols)
        head = re.search(r'<thead id="detections-findings-thead">(.*?)</thead>', HTML, re.S).group(1)
        self.assertEqual(re.findall(r'data-col="(\w+)"', head), names)

    def test_nothing_in_the_script_breaks_the_content_security_policy(self):
        self.assertNotRegex(DET, r'\sstyle="', 'an inline style is refused by the policy')
        self.assertNotRegex(DET, r'\son(click|change|input|load|error)=', 'an inline handler is refused by the policy')
        pane = HTML[HTML.index('id="detections-wrap"'):HTML.index('id="ipintel-lookup-card"')]
        self.assertNotRegex(pane, r'\sstyle="')
        self.assertNotRegex(pane, r'\son(click|change|input|load|error)=')

    def test_text_from_a_host_is_escaped_where_the_script_builds_markup(self):
        for field in ('f.name || f.id', "f.detail || ''", '_dtRuleTitle(f.rule)', '_dtAddress(f)', 'p.label', 'r.title', 'r.why'):
            self.assertIn('escHtml(%s)' % field, DET, field)
        self.assertNotRegex(DET, r'\$\{(?:f|r|p)\.(?:detail|name|ip|process|title|why|label)\}', 'a value from a host or a rule goes through escHtml, never straight into a template')

    def test_a_number_that_travels_through_data_arg_is_an_index_and_never_an_id(self):
        self.assertIn('data-arg="${f._i}"', DET)
        self.assertNotRegex(DET, r'data-arg="\$\{(?:f|r)\.id\}"')


class TestTheRoutesAreInTheReference(unittest.TestCase):

    def test_both_routes_are_in_the_dispatcher_and_so_in_the_api_reference(self):
        api = _fresh_api()
        routes = set(api._dispatcher_routes())
        self.assertIn(('GET', '/api/detections'), routes)
        self.assertIn(('POST', '/api/detections/rules'), routes)

    def test_the_prefix_gate_covers_the_whole_surface(self):
        src = (ROOT / 'server' / 'cgi-bin' / 'api.py').read_text()
        paths = set(re.findall(r"'(/api/detections[a-z/]*)'", src))
        self.assertTrue(paths <= {'/api/detections', '/api/detections/rules'}, paths)
        self.assertTrue(all(p.startswith('/api/detections') for p in paths))


if __name__ == '__main__':
    unittest.main()
