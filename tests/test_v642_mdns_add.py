"""v6.4.2 — the mDNS service list must offer "Add as device".

The finding this closes: discovered mDNS/Bonjour services were listed read-only.
An operator saw a printer, a NAS, a Home Assistant instance advertising itself
on the LAN and had no way to act on it, while every other discovery surface in
the product (the netscan list, the ARP table) offers "Add as device". A dead end.

Both halves are pinned here, because either one alone IS the dead end this
release is about:

  * the BUTTON must appear in the rendered markup (and carry a real icon, a
    dispatchable data-action and a numeric index) — proven by executing the
    shipped `loadMdns` source against a stub DOM, not by grepping for it;
  * the FUNCTION it dispatches to must exist, and must call a helper that
    itself exists with the parameter shape it actually consumes — proven by
    executing `mdnsAddDevice` and capturing what reaches `agentlessAddOpen`.

A source-text assertion alone would pass on a misspelled global (`_icon('ban')`,
`agentlessAddDevice(...)`) and ship an inert button, which is exactly the class
of bug the whole sweep exists to kill.
"""

import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import srcpin  # noqa: E402

_ROOT = Path(__file__).resolve().parent.parent
_JS = _ROOT / 'server' / 'html' / 'static' / 'js'
_CGI = _ROOT / 'server' / 'cgi-bin'
_NETJS = _JS / 'app-network.js'


def _net_src():
    return _NETJS.read_text()


def _app_src():
    return (_JS / 'app.js').read_text()


def _have_node():
    try:
        subprocess.run(['node', '--version'], capture_output=True, timeout=10)
        return True
    except Exception:
        return False


# A DOM stub narrow enough to be obviously correct, wide enough to run the real
# renderer: element identity, children, dataset, className/title, textContent
# and an innerHTML that clears children (which is how loadMdns resets the box).
_DOM = r"""
class El {
  constructor(tag) {
    this.tag = tag; this.children = []; this.dataset = {};
    this.className = ''; this.title = ''; this._text = ''; this._html = '';
  }
  appendChild(c) { this.children.push(c); return c; }
  set innerHTML(v) { this._html = String(v); this.children = []; }
  get innerHTML() { return this._html; }
  set textContent(v) { this._text = String(v); this.children = []; }
  get textContent() { return this._text; }
  get outerHTML() {
    const attrs = [];
    if (this.className) attrs.push(`class="${this.className}"`);
    if (this.title) attrs.push(`title="${this.title}"`);
    for (const k of Object.keys(this.dataset)) {
      const a = k.replace(/[A-Z]/g, m => '-' + m.toLowerCase());
      attrs.push(`data-${a}="${this.dataset[k]}"`);
    }
    const open = `<${this.tag}${attrs.length ? ' ' + attrs.join(' ') : ''}>`;
    const inner = this._html + this._text
      + this.children.map(c => c.outerHTML).join('');
    return `${open}${inner}</${this.tag}>`;
  }
}
class TextNode {
  constructor(t) { this._t = String(t); }
  get outerHTML() { return this._t; }
  get textContent() { return this._t; }
}
const _byId = {};
const document = {
  createElement: t => new El(t),
  createTextNode: t => new TextNode(t),
  getElementById: id => _byId[id] || (_byId[id] = new El('div')),
};
function walk(node, out) {
  out = out || [];
  for (const c of (node.children || [])) { out.push(c); walk(c, out); }
  return out;
}
"""


def _run_node(script):
    p = subprocess.run(['node', '-e', script], capture_output=True,
                       text=True, timeout=60)
    if p.returncode != 0:
        raise AssertionError('node failed:\n' + (p.stderr or '')[-2000:])
    return json.loads(p.stdout)


@unittest.skipUnless(_have_node(), 'node unavailable')
class TestMdnsRowRendersAnAddButton(unittest.TestCase):
    """Half 1 — the control exists, in the real renderer's output."""

    SERVICES = [
        {'name': 'Brother HL-2270DW', 'type': '_ipp._tcp',
         'host': 'printer.local', 'address': '192.168.1.9', 'port': 631,
         'seen_by': ['nuc01']},
        {'name': '', 'type': '_hap._tcp', 'host': 'hass.local',
         'address': '192.168.1.20', 'port': 8123, 'seen_by': ['nuc01']},
    ]

    @classmethod
    def setUpClass(cls):
        src = _net_src()
        app = _app_src()
        # The REAL _icon + _ICONS, so an icon name that does not exist in the
        # map renders an empty string and the <svg> assertion below fails.
        icons = srcpin.balanced_block(app, 'const _ICONS = {')
        icon_fn = srcpin.js_function(app, '_icon')
        load = srcpin.js_function(src, 'loadMdns')
        # js_function anchors on 'function <name>(' first, so it drops a
        # leading `async` — put it back rather than executing a broken body.
        if 'async function loadMdns(' in src and not load.startswith('async'):
            load = 'async ' + load
        payload = json.dumps({'ok': True, 'enabled': True,
                              'services': cls.SERVICES})
        script = _DOM + icons + ';\n' + icon_fn + '\n' + load + '\n' + r"""
let _mdnsServices = [];
const api = async () => (__PAYLOAD__);
(async () => {
  await loadMdns();
  const box = document.getElementById('mdns-list');
  const nodes = walk(box);
  const buttons = nodes.filter(n => n.tag === 'button');
  console.log(JSON.stringify({
    html: box.outerHTML,
    ths: (nodes.find(n => n.tag === 'thead') || {}).innerHTML || '',
    rows: nodes.filter(n => n.tag === 'tr').length,
    cellsPerRow: nodes.filter(n => n.tag === 'tr')
                      .map(r => r.children.length),
    buttons: buttons.map(b => ({
      cls: b.className, action: b.dataset.action, arg: b.dataset.arg,
      title: b.title, html: b.outerHTML,
    })),
  }));
})();
""".replace('__PAYLOAD__', payload)
        cls.out = _run_node(script)

    def test_one_button_per_service_row(self):
        self.assertEqual(self.out['rows'], len(self.SERVICES),
                         'one <tr> per advertised service')
        self.assertEqual(len(self.out['buttons']), len(self.SERVICES),
                         'every discovered service row must offer the action — '
                         'the finding is that the list was a dead end')

    def test_button_dispatches_to_mdns_add_device_by_index(self):
        args = [b['arg'] for b in self.out['buttons']]
        self.assertEqual(args, ['0', '1'],
                         'data-arg must be the row index (the dispatcher '
                         'Number()s it, so an index is the safe shape)')
        for b in self.out['buttons']:
            self.assertEqual(b['action'], 'mdnsAddDevice')

    def test_button_carries_a_real_icon_not_an_invented_one(self):
        # _icon() returns '' for a name absent from _ICONS, so a bogus icon
        # name renders a button with no <svg> at all.
        for b in self.out['buttons']:
            self.assertIn('<svg', b['html'],
                          "the icon name must exist in app.js's _ICONS map")
            self.assertIn('Add as device', b['html'])

    def test_no_inline_handler_or_style_attribute(self):
        # CSP: script-src 'self'; style-src 'self' — an inline on*= or style=
        # in the built markup is silently dead in production.
        html = self.out['html']
        self.assertNotRegex(html, r'\son[a-z]+\s*=',
                            'inline event handler — blocked by CSP')
        self.assertNotIn('style="', html, 'inline style — blocked by CSP')

    def test_header_and_body_column_counts_match(self):
        ths = self.out['ths'].count('<th')
        self.assertEqual(ths, 7, 'the action column needs its own <th>')
        for n in self.out['cellsPerRow']:
            self.assertEqual(n, ths,
                             'a body row with fewer cells than the header '
                             'misaligns the whole table')


@unittest.skipUnless(_have_node(), 'node unavailable')
class TestMdnsAddDeviceReachesEnrollment(unittest.TestCase):
    """Half 2 — the handler exists and hands the right shape to the opener."""

    @classmethod
    def setUpClass(cls):
        src = _net_src()
        fn = srcpin.js_function(src, 'mdnsAddDevice')
        script = fn + '\n' + r"""
const calls = [];
function agentlessAddOpen(p) { calls.push(p); }
let _mdnsServices = [
  {name: 'Synology DS920', type: '_smb._tcp', host: 'nas.local',
   address: '192.168.1.4', port: 445},
  {name: '', type: '_hap._tcp', host: 'hass.local',
   address: '192.168.1.20', port: 8123},
  {name: '', type: '_raop._tcp', host: '', address: '192.168.1.31', port: 7000},
];
mdnsAddDevice(0); mdnsAddDevice(1); mdnsAddDevice(2);
mdnsAddDevice(99);            // out of range must be a no-op, not a throw
console.log(JSON.stringify(calls));
"""
        cls.calls = _run_node(script)

    def test_it_calls_the_enrollment_opener_once_per_valid_index(self):
        self.assertEqual(len(self.calls), 3,
                         'an out-of-range index must be ignored silently')

    def test_prefill_carries_hostname_and_address(self):
        self.assertEqual(self.calls[0], {
            'name': 'Synology DS920', 'hostname': 'nas.local',
            'ip': '192.168.1.4', 'mac': '',
        })

    def test_name_falls_back_to_host_then_address(self):
        # mDNS instance names are frequently blank; the modal requires a name,
        # so a blank one that reached the field would just be a second dead end.
        self.assertEqual(self.calls[1]['name'], 'hass.local')
        self.assertEqual(self.calls[2]['name'], '192.168.1.31')
        for c in self.calls:
            self.assertTrue(c['name'], 'the prefilled name is never blank')


class TestBothHalvesAreWiredForReal(unittest.TestCase):
    """The dead-end guards that need no browser."""

    def test_the_handler_is_a_global_the_dispatcher_can_find(self):
        # The delegated dispatcher resolves window[dataset.action]; a function
        # nested inside another one would be invisible to it.
        src = _net_src()
        self.assertRegex(src, r'(?m)^function mdnsAddDevice\(',
                         'mdnsAddDevice must be a top-level declaration')
        self.assertRegex(src, r"(?m)^let _mdnsServices = \[\];",
                         'the row array must be module-scope for index lookup')

    def test_the_helper_it_calls_actually_exists(self):
        # The invented-helper-name class: JS fails silently, so a call to a
        # function that does not exist dies only when a user clicks.
        joined = '\n'.join(p.read_text() for p in sorted(_JS.glob('*.js')))
        self.assertRegex(joined, r'(?m)^(async )?function agentlessAddOpen\(')

    def test_the_renderer_stores_the_rows_it_renders(self):
        body = srcpin.js_function(_net_src(), 'loadMdns')
        self.assertIn('_mdnsServices = svcs', body,
                      'without this the index in data-arg resolves against a '
                      'stale (or empty) array')

    def test_the_list_endpoint_exists_in_the_route_table(self):
        api_src = (_CGI / 'api.py').read_text()
        self.assertIn("('GET', '/api/mdns'): handle_mdns_services", api_src)
        self.assertRegex(api_src, r'(?m)^def handle_mdns_services\(')
        # The client asks for '/mdns' (api() prefixes /api).
        self.assertIn("api('GET', '/mdns')", _net_src())

    def test_the_fields_the_prefill_reads_are_the_fields_the_server_sends(self):
        # The dead-signal class: a consumer reading a key no producer writes.
        api_src = (_CGI / 'api.py').read_text()
        ingest = srcpin.py_function(api_src, '_ingest_mdns')
        for key in ('name', 'type', 'host', 'address', 'port'):
            self.assertIn(f"'{key}':", ingest,
                          f'_ingest_mdns must persist {key!r} — the UI reads it')
        handler = srcpin.py_function(api_src, 'handle_mdns_services')
        self.assertIn("'seen_by'", handler)

    def test_the_action_column_is_not_sortable_by_accident(self):
        # The mDNS table is not wired to tableCtl, so no data-col is expected;
        # if someone wires it later, the action <th> must not become a sort key.
        body = srcpin.js_function(_net_src(), 'loadMdns')
        self.assertNotIn('wireSortOnly', body)
        self.assertNotIn('data-col', body)

    def test_classes_used_exist_in_the_stylesheet(self):
        css = (_ROOT / 'server' / 'html' / 'static' / 'css'
               / 'styles.css').read_text()
        body = srcpin.js_function(_net_src(), 'loadMdns')
        used = re.search(r"btn\.className = '([^']+)'", body)
        self.assertIsNotNone(used, 'the button must set a className')
        for cls in used.group(1).split():
            self.assertRegex(css, r'\.' + re.escape(cls) + r'\b',
                             f'.{cls} is not defined in styles.css')


if __name__ == '__main__':
    unittest.main()
