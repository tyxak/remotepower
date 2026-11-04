#!/usr/bin/env python3
"""7.4.9: the Home hero of the Pilot look, drawn by the real code of app-pilot.js run under node.

The hero is a dot-matrix readout of the hosts online and the fleet as a field of dots, one per host, grouped by host group. What it
shows has to be what the rest of Home shows, so the rules are the ones the Fleet health card already has: a host is critical when it
is offline or has a critical finding, a warning when it has a warning, fine otherwise, and not monitored hosts are hollow dots and
are left out of the online count (the tile they replace left them out too).

The functions run against a small stand-in for the DOM, so the tree they build can be read: how many dots, in which state, in which
cluster, in which order, and what the click on a dot does. The module is also held to what the header of the file promises: it
requests nothing and it never puts a host name through innerHTML (host names are other people's text).
"""
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_JS = _ROOT / "server" / "html" / "static" / "js"
sys.path.insert(0, str(pathlib.Path(__file__).parent))
import srcpin  # noqa: E402

_NODE = shutil.which("node")
_PILOT = (_JS / "app-pilot.js").read_text()
_APP = (_JS / "app.js").read_text()
_HTML = (_ROOT / "server" / "html" / "index.html").read_text()
_CSS = (_ROOT / "server" / "html" / "static" / "css" / "styles.css").read_text()

DOM = r"""
class El {
  constructor(tag, ns) { this.tag = tag; this.ns = ns || null; this.attrs = {}; this.children = []; this.dataset = {}; this._cls = '';
    this.hidden = false; this.title = ''; this.textContent = ''; this.listeners = {}; const self = this;
    this.classList = { add(c) { if (!self._cls.split(' ').includes(c)) self._cls = (self._cls + ' ' + c).trim(); },
      remove(c) { self._cls = self._cls.split(' ').filter(x => x && x !== c).join(' '); },
      contains(c) { return self._cls.split(' ').includes(c); } }; }
  set className(v) { this._cls = String(v); }
  get className() { return this._cls; }
  setAttribute(k, v) { if (k === 'class') this._cls = String(v); else this.attrs[k] = String(v); }
  appendChild(c) { this.children.push(c); return c; }
  replaceChildren(...cs) { this.children = cs; }
  addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
  contains(x) { return x === this || this.children.some(c => c.contains(x)); }
}
const document = { createElement: t => new El(t), createElementNS: (ns, t) => new El(t, ns) };
function dump(e) { return { tag: e.tag, cls: e._cls, text: e.textContent, attrs: e.attrs, data: e.dataset, title: e.title,
  hidden: e.hidden, n: e.children.length, children: e.children.map(dump) }; }
const opened = [];
function openDeviceDrawer(id, name) { opened.push([id, name]); }
"""

CONSTS = ("_PILOT_GLYPHS", "_PILOT_SVG_NS", "_PILOT_STATE_CLASS", "_PILOT_MAX_DOTS")
FUNCS = ("_pilotDotMatrix", "_pilotHostState", "_pilotEl", "_pilotHeroRender")


def _const(name):
    m = re.search(r"^const %s = .+?;\s*$" % name, _PILOT, re.M | re.S) if name == "_PILOT_GLYPHS" else \
        re.search(r"^const %s = .+;\s*$" % name, _PILOT, re.M)
    assert m, name
    text = m.group(0)
    if name == "_PILOT_GLYPHS":
        text = text[: text.index("\n};") + 3]
    return text


def code(src):
    """The source without its comments (a promise about the code is not broken by a comment that names it)."""
    return re.sub(r"/\*.*?\*/|(?<![:\w])//[^\n]*", "", src, flags=re.S)


def run(body):
    parts = [DOM] + [_const(c) for c in CONSTS] + [srcpin.js_function(_PILOT, f) for f in FUNCS]
    script = "\n".join(parts) + "\n" + body
    with tempfile.TemporaryDirectory() as d:
        path = pathlib.Path(d) / "hero.js"
        path.write_text(script)
        proc = subprocess.run([str(_NODE), str(path)], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def host(i, group="g", online=True, monitored=True, name=None):
    return {"id": "h%d" % i, "name": name or "host%02d" % i, "group": group, "online": online, "monitored": monitored}


def draw(devs, health=None):
    """The hero drawn for these hosts: the dump of the #home-hero element."""
    # the element starts hidden, as it is in the page: drawing a hero has to show it
    return run("const h = new El('div'); h.hidden = true; _pilotHeroRender(h, %s, %s); console.log(JSON.stringify(dump(h)));"
               % (json.dumps(devs), json.dumps(health)))


def find(node, cls):
    """Every descendant whose class list has this class."""
    out = []
    for c in node["children"]:
        if cls in c["cls"].split():
            out.append(c)
        out += find(c, cls)
    return out


@unittest.skipUnless(_NODE, "node not installed")
class TestTheDigits(unittest.TestCase):

    def test_the_glyphs_are_ten_distinct_five_by_seven_grids(self):
        g = run("console.log(JSON.stringify(_PILOT_GLYPHS));")
        self.assertEqual(sorted(g), list("0123456789"))
        for digit, rows in g.items():
            self.assertEqual(len(rows), 7, digit)
            for row in rows:
                self.assertRegex(row, r"^[01]{5}$", digit)
        self.assertEqual(len({tuple(r) for r in g.values()}), 10, "two digits draw the same")

    def test_the_digits_look_like_digits(self):
        """The table is data whose correctness is its shape, so it is pinned as the shapes themselves."""
        art = {
            "0": [".###.", "#...#", "#..##", "#.#.#", "##..#", "#...#", ".###."],
            "1": ["..#..", ".##..", "..#..", "..#..", "..#..", "..#..", ".###."],
            "2": [".###.", "#...#", "....#", "...#.", "..#..", ".#...", "#####"],
            "3": ["####.", "....#", "....#", ".###.", "....#", "....#", "####."],
            "4": ["...#.", "..##.", ".#.#.", "#..#.", "#####", "...#.", "...#."],
            "5": ["#####", "#....", "####.", "....#", "....#", "#...#", ".###."],
            "6": ["..##.", ".#...", "#....", "####.", "#...#", "#...#", ".###."],
            "7": ["#####", "....#", "...#.", "..#..", ".#...", ".#...", ".#..."],
            "8": [".###.", "#...#", "#...#", ".###.", "#...#", "#...#", ".###."],
            "9": [".###.", "#...#", "#...#", ".####", "....#", "...#.", ".##.."],
        }
        g = run("console.log(JSON.stringify(_PILOT_GLYPHS));")
        for digit, rows in art.items():
            self.assertEqual(g[digit], [r.replace("#", "1").replace(".", "0") for r in rows], digit)

    def test_a_number_is_a_grid_of_circles_with_the_lit_ones_marked(self):
        for text in ("7", "17", "1234", "0"):
            with self.subTest(text=text):
                svg = run("const s = _pilotDotMatrix(%s); console.log(JSON.stringify(dump(s)));" % json.dumps(text))
                g = run("console.log(JSON.stringify(_PILOT_GLYPHS));")
                self.assertEqual(svg["n"], 35 * len(text))
                lit = sum(row.count("1") for ch in text for row in g[ch])
                self.assertEqual(sum(1 for c in svg["children"] if c["cls"] == "on"), lit)
                self.assertEqual(sum(1 for c in svg["children"] if c["cls"] == "off"), 35 * len(text) - lit)
                self.assertEqual(svg["attrs"]["viewBox"], "0 0 %d 56" % ((6 * len(text) - 1) * 8))
                self.assertEqual(svg["attrs"]["aria-hidden"], "true")

    def test_each_digit_sits_in_its_own_column_block(self):
        svg = run("console.log(JSON.stringify(dump(_pilotDotMatrix('17'))));")
        xs = sorted({float(c["attrs"]["cx"]) for c in svg["children"]})
        self.assertEqual(xs[0], 4.0)                       # the first cell of the first digit, half a pitch in
        self.assertEqual(xs[5], (6 + 0 + 0.5) * 8)         # the first cell of the second digit starts after one empty column
        self.assertEqual(len(xs), 10)
        self.assertEqual({float(c["attrs"]["cy"]) for c in svg["children"]}, {(y + 0.5) * 8 for y in range(7)})

    def test_what_is_not_a_digit_is_left_out(self):
        a = run("console.log(JSON.stringify(dump(_pilotDotMatrix('1a7%'))));")
        b = run("console.log(JSON.stringify(dump(_pilotDotMatrix('17'))));")
        self.assertEqual(a, b)
        empty = run("console.log(JSON.stringify(dump(_pilotDotMatrix(''))));")
        self.assertEqual((empty["n"], empty["attrs"]["viewBox"]), (0, "0 0 8 56"))


@unittest.skipUnless(_NODE, "node not installed")
class TestOneHostsState(unittest.TestCase):

    def state(self, d, rec=None):
        return run("console.log(JSON.stringify(_pilotHostState(%s, %s)));" % (json.dumps(d), json.dumps(rec)))

    def test_the_rules(self):
        on = {"online": True, "monitored": True}
        cases = [
            ({"online": True}, None, "ok"),
            (on, {"critical": 0, "warning": 0}, "ok"),
            (on, {"critical": 0, "warning": 2}, "warn"),
            (on, {"critical": 1, "warning": 0}, "crit"),
            (on, {"critical": 3, "warning": 5}, "crit"),             # a critical finding wins over a warning
            ({"online": False, "monitored": True}, None, "crit"),    # offline is critical with nothing else said
            ({"online": False}, {"critical": 0, "warning": 0}, "crit"),
            ({"online": False, "monitored": False}, {"critical": 9}, "none"),   # not monitored: never alerts, however it looks
            ({"online": True, "monitored": False}, None, "none"),
        ]
        for d, rec, want in cases:
            with self.subTest(d=d, rec=rec):
                self.assertEqual(self.state(d, rec), want)


@unittest.skipUnless(_NODE, "node not installed")
class TestTheHero(unittest.TestCase):

    def test_no_hosts_no_hero(self):
        for devs in ([], None, "x", {}, 5):
            with self.subTest(devs=repr(devs)):
                h = draw(devs)
                self.assertEqual((h["hidden"], h["n"]), (True, 0))
                self.assertNotIn("is-ready", h["cls"].split())

    def test_a_drawn_hero_is_ready_and_shown(self):
        h = draw([host(1)])
        self.assertIs(h["hidden"], False)
        self.assertIn("is-ready", h["cls"].split())
        self.assertEqual(h["n"], 1)

    def test_a_redraw_replaces_it_and_a_fleet_that_empties_clears_it(self):
        out = run("const h = new El('div'); h.hidden = true; _pilotHeroRender(h, %s, null); _pilotHeroRender(h, %s, null);"
                  "const mid = dump(h); _pilotHeroRender(h, [], null); console.log(JSON.stringify([mid, dump(h)]));"
                  % (json.dumps([host(1), host(2)]), json.dumps([host(3)])))
        self.assertEqual(out[0]["n"], 1)
        self.assertEqual(len(find(out[0], "pilot-dot")) - len(find(out[0], "pilot-key")), 1)   # one host, not two plus one
        self.assertEqual((out[1]["n"], out[1]["hidden"]), (0, True))
        self.assertNotIn("is-ready", out[1]["cls"].split())

    def test_the_readout_counts_monitored_hosts_online(self):
        devs = [host(1), host(2), host(3, online=False), host(4, monitored=False, online=False)]
        h = draw(devs)
        num = find(h, "pilot-num")[0]
        self.assertEqual([c["text"] for c in num["children"] if c["tag"] == "span"], ["2"])    # the number a screen reader hears
        self.assertEqual(len([c for c in num["children"][0]["children"] if c["cls"] == "on"]),
                         sum(row.count("1") for row in run("console.log(JSON.stringify(_PILOT_GLYPHS));")["2"]))
        self.assertEqual(find(h, "pilot-cap")[0]["text"], "1 host offline")

    def test_the_caption_and_the_colour_follow_how_many_are_offline(self):
        cases = [(5, 0, "All hosts reporting in", "is-ok"), (5, 1, "1 host offline", "is-warn"),
                 (4, 1, "1 host offline", "is-warn"), (4, 2, "2 hosts offline", "is-crit"), (5, 3, "3 hosts offline", "is-crit")]
        for total, off, caption, colour in cases:
            with self.subTest(total=total, off=off):
                devs = [host(i, online=i >= off) for i in range(total)]
                h = draw(devs)
                self.assertEqual(find(h, "pilot-cap")[0]["text"], caption)
                self.assertIn(colour, find(h, "pilot-num")[0]["cls"].split())

    def test_the_readout_is_a_button_to_the_host_list(self):
        r = find(draw([host(1)]), "pilot-readout")[0]
        self.assertEqual((r["data"]["action"], r["data"]["arg"], r["attrs"]["role"], r["attrs"]["tabindex"]),
                         ("statNav", "devices", "button", "0"))

    def test_every_host_is_one_dot_in_its_state(self):
        devs = [host(1), host(2), host(3, online=False), host(4, monitored=False), host(5), host(6)]
        health = {"devices": [{"device_id": "h2", "critical": 0, "warning": 3}, {"device_id": "h5", "critical": 2, "warning": 0}]}
        h = draw(devs, health)
        dots = [d for d in find(h, "pilot-matrix")[0]["children"] for d in d["children"][0]["children"]]
        by_name = {d["data"]["name"]: [c for c in d["cls"].split() if c.startswith("is-")][0] for d in dots}
        self.assertEqual(by_name, {"host01": "is-ok", "host02": "is-warn", "host03": "is-crit", "host04": "is-none",
                                   "host05": "is-crit", "host06": "is-ok"})
        self.assertEqual({d["data"]["dev"] for d in dots}, {"h%d" % i for i in range(1, 7)})

    def test_the_legend_counts_add_up_to_the_hosts_drawn(self):
        devs = [host(i) for i in range(1, 8)] + [host(8, online=False), host(9, monitored=False)]
        h = draw(devs, {"devices": [{"device_id": "h1", "critical": 0, "warning": 1}]})
        legend = find(h, "pilot-legend")[0]
        keys = {k["children"][1]["text"]: int(k["children"][2]["text"]) for k in legend["children"] if "pilot-key" in k["cls"]}
        self.assertEqual(keys, {"Healthy": 6, "Warning": 1, "Critical": 1, "Unmonitored": 1})
        self.assertEqual(sum(keys.values()), len(devs))

    def test_a_state_nobody_is_in_has_no_key(self):
        legend = find(draw([host(1), host(2)]), "pilot-legend")[0]
        self.assertEqual([k["children"][1]["text"] for k in legend["children"]], ["Healthy"])

    def test_the_hosts_are_clustered_by_group_and_the_unnamed_come_last(self):
        devs = [host(1, "web"), host(2, ""), host(3, "db"), host(4, "web", name="alpha"), host(5, "db", name="zulu"), host(6, "db", name="beta")]
        h = draw(devs)
        clusters = find(h, "pilot-matrix")[0]["children"]
        names = [[d["data"]["name"] for d in c["children"][0]["children"]] for c in clusters]
        labels = [c["children"][1]["text"] if len(c["children"]) > 1 else None for c in clusters]
        self.assertEqual(labels, ["db", "web", None])
        self.assertEqual(names, [["beta", "host03", "zulu"], ["alpha", "host01"], ["host02"]])

    def test_a_dot_says_who_it_is_and_what_is_wrong(self):
        h = draw([host(1, name="gitea.lab", online=False), host(2, name="nas")],
                 {"devices": [{"device_id": "h2", "critical": 2, "warning": 1}]})
        titles = sorted(d["title"] for d in find(h, "pilot-dot") if d["data"].get("dev"))
        self.assertEqual(titles, ["gitea.lab · offline", "nas · 2 critical · 1 warning"])

    def test_the_field_grows_smaller_dots_for_a_bigger_fleet_and_drops_the_labels(self):
        for n, size in ((1, None), (48, None), (49, "is-md"), (160, "is-md"), (161, "is-sm"), (400, "is-sm")):
            with self.subTest(n=n):
                h = draw([host(i, "g%d" % (i % 3)) for i in range(n)])
                matrix = find(h, "pilot-matrix")[0]
                classes = matrix["cls"].split()
                self.assertEqual([c for c in classes if c in ("is-md", "is-sm")], [size] if size else [])
                labelled = bool(find(matrix, "pilot-glabel"))
                self.assertEqual(labelled, size is None)

    def test_a_fleet_past_the_cap_is_cut_and_says_how_many_more(self):
        n = 1500 + 37
        h = draw([host(i, "g%d" % (i % 5), name="h%04d" % i) for i in range(n)])
        matrix = find(h, "pilot-matrix")[0]
        dots = [d for c in matrix["children"] for d in c["children"][0]["children"]]
        self.assertEqual(len(dots), 1500)
        legend = find(h, "pilot-legend")[0]
        self.assertEqual([c["text"] for c in legend["children"] if "pilot-cap" in c["cls"]], ["+37"])
        # exactly at the cap nothing is cut
        h = draw([host(i, "g") for i in range(1500)])
        self.assertEqual([c for c in find(h, "pilot-legend")[0]["children"] if "pilot-cap" in c["cls"]], [])

    def test_the_field_is_for_the_eye_the_readout_for_the_ear(self):
        h = draw([host(1)])
        self.assertEqual(find(h, "pilot-matrix")[0]["attrs"]["aria-hidden"], "true")

    def test_a_hostile_name_stays_text(self):
        evil = '<img src=x onerror=alert(1)>"\''
        h = draw([host(1, name=evil, group=evil)])
        dot = find(h, "pilot-dot")[0]
        self.assertEqual((dot["data"]["name"], dot["title"]), (evil, evil))
        self.assertEqual(find(h, "pilot-glabel")[0]["text"], evil)


@unittest.skipUnless(_NODE, "node not installed")
class TestTheClick(unittest.TestCase):

    def click(self, setup):
        return run("const h = new El('div'); _pilotHeroRender(h, %s, null); _pilotHeroRender(h, %s, null);"
                   "const L = h.listeners.click || []; %s console.log(JSON.stringify({listeners: L.length, opened}));"
                   % (json.dumps([host(1), host(2)]), json.dumps([host(1), host(2)]), setup))

    def test_it_is_bound_once_however_often_the_hero_is_drawn(self):
        self.assertEqual(self.click("")["listeners"], 1)

    def test_a_click_on_a_dot_opens_that_host(self):
        # hero -> field -> matrix -> cluster -> row -> the first dot
        out = self.click("const dot = h.children[0].children[1].children[1].children[0].children[0].children[0];"
                         "L[0]({target: {closest: s => dot}});")
        self.assertEqual(out["opened"], [["h1", "host01"]])

    def test_a_click_elsewhere_opens_nothing(self):
        self.assertEqual(self.click("L[0]({target: {closest: s => null}}); L[0]({target: {}});")["opened"], [])

    def test_a_dot_that_is_not_in_the_hero_opens_nothing(self):
        out = self.click("const stray = new El('span'); stray.dataset.dev = 'x'; stray.dataset.name = 'x'; L[0]({target: {closest: s => stray}});")
        self.assertEqual(out["opened"], [])


class TestThePromises(unittest.TestCase):

    def test_it_requests_nothing(self):
        for token in ("api(", "fetch(", "XMLHttpRequest", "sendBeacon"):
            self.assertNotIn(token, code(_PILOT))

    def test_a_host_name_never_goes_through_html(self):
        for token in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
            self.assertNotIn(token, code(_PILOT))

    def test_the_scan_sees_what_it_is_for(self):
        # a module that did use one of the tokens would contain it in its code; one that only names it in a comment would not
        self.assertIn("innerHTML", code("x.innerHTML = name;"))
        self.assertIn("api(", code("const d = await api('GET', '/devices');"))
        self.assertNotIn("innerHTML", code("/* never reaches innerHTML */ const x = 1; // not innerHTML either"))
        self.assertIn("innerHTML", code("const u = 'http://x.y'; el.innerHTML = u;"))
        # and the module does name it in its header, which is why the comments have to be left out
        self.assertIn("innerHTML", _PILOT)

    def test_every_class_the_module_writes_has_a_rule_in_the_pilot_block(self):
        written = set(re.findall(r"'(?:pilot-[\w-]+|is-[\w-]+)'", _PILOT)) | set(re.findall(r"'pilot-[\w-]+ ", _PILOT))
        written = {w.strip("' ") for w in written}
        written |= set(re.findall(r"is-(?:ok|warn|crit|none|md|sm|ready)", _PILOT))
        block = _CSS[_CSS.index("═══ PILOT LOOK (7.4.9) ═══ BEGIN"):_CSS.index("═══ PILOT LOOK (7.4.9) ═══ END")]
        self.assertGreater(len(written), 14, written)
        for cls in sorted(written):
            self.assertIn("." + cls, block, cls)

    def test_the_hero_module_is_lazy_and_loaded_by_one_eager_function(self):
        self.assertRegex(_APP, r"const _LAZY_NON_PAGE_MODULES = \[[^\]]*'app-pilot\.js'")
        shim = srcpin.js_function(_APP, "_renderHomeHero")
        self.assertIn("await _loadJsModule('app-pilot.js')", shim)
        self.assertIn("_pilotHeroRender(host, devs, health)", shim)

    def test_classic_draws_no_hero_and_takes_a_leftover_one_away(self):
        shim = srcpin.js_function(_APP, "_renderHomeHero")
        self.assertIn("document.body.dataset.look !== 'pilot'", shim)
        first = shim[: shim.index("await _loadJsModule")]
        self.assertIn("host.replaceChildren();", first)
        self.assertIn("host.hidden = true;", first)
        self.assertIn("host.classList.remove('is-ready');", first)

    def test_a_look_that_changes_while_the_module_loads_is_respected(self):
        shim = srcpin.js_function(_APP, "_renderHomeHero")
        after = shim[shim.index("await _loadJsModule"):]
        self.assertIn("if (document.body.dataset.look !== 'pilot') return;", after)
        self.assertLess(after.index("if (document.body.dataset.look !== 'pilot') return;"), after.index("_pilotHeroRender("))

    def test_home_draws_it_right_after_the_tiles(self):
        load = srcpin.js_function(_APP, "loadHome")
        self.assertIn("_renderHomeTiles(devs, drift, cves, mailwatch);\n  _renderHomeHero(devs, home.health);", load)

    def test_the_page_has_the_element_hidden_and_before_the_tiles(self):
        self.assertIn('<div id="home-hero" hidden></div>', _HTML)
        self.assertLess(_HTML.index('id="home-hero"'), _HTML.index('id="home-tiles"'))

    def test_the_tile_steps_aside_only_once_the_hero_is_there(self):
        # a hero that failed to load must not leave Home without the number of hosts online
        self.assertIn('body[data-look="pilot"] #home-hero.is-ready ~ #home-tiles .tile[data-arg="devices"] { display: none; }', _CSS)
        tile = srcpin.js_function(_APP, "_renderHomeTiles")
        self.assertIn("nav: 'devices'", tile)


if __name__ == "__main__":
    unittest.main()
