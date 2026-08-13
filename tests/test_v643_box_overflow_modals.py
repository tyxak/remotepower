#!/usr/bin/env python3
"""The ~15-line cap applies inside dialogs too — and nothing was measuring them.

`test_v643_box_overflow_rendered.py` walks every sidebar page and measures each
box against the cap. It looks exhaustive, and for pages it is. But its selector
is `#app .page.active *`, and a `.modal-overlay` is `display:none` until
something calls `openModal()` — so all 138 dialogs were outside the only
measurement that has ever been able to see this defect class.

That is not a small blind spot. Dialogs are where the forms are, and a form is
exactly the shape that grows without bound: a device picker listing the fleet, a
role editor listing every permission, a restore dialog listing every archive. A
page-level table with 200 rows was caught. The same 200 rows in a dialog were
not looked at.

The accessibility suite already opens all 138 (`test_a11y_axe_modals.py`), which
is where the discovery-and-open technique here comes from — including its most
important property: if the dialogs do not actually open, that is a FAILURE, not
a quiet pass. A walk that opens nothing measures nothing while reporting a clean
sweep, and this whole release exists because of gates that did that.

WHAT THIS MEASURES, AND WHAT IT DOES NOT — stated because the distinction is
easy to miss and the file would otherwise read as stronger than it is.

`openModal(id)` adds `.active` and moves focus. It does NOT call the loader that
fills a dialog with rows; each dialog's opener function does that, and this walk
does not call them. So what is measured is every dialog AS OPENED: its markup,
its static content, and any box that is already tall without data. A picker that
grows only once the fleet is fetched into it is NOT covered.

`opened` is not `populated`, and the `opened > half` guard below only proves the
former — so a second class in this file closes that gap rather than leaving it
as a caveat. `TestDialogsOpenedByRealClicksAreCapped` does what an operator
does: it CLICKS each visible control on a seeded instance and measures whatever
dialog the click opened, so the handler behind the button has real rows to
render. That measures fewer dialogs (only those a visible control opens) and
measures them properly; this walk has the breadth, that one has the data, and
both are needed.

The seeder still runs because the login this walk needs (`alice/demo`) is an
account the seeder creates; there is no `admin` on a seeded instance.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import browser_required

try:
    from playwright.sync_api import sync_playwright
except ImportError:                                     # pragma: no cover
    sync_playwright = None

# A dialog is inherently shorter than a page: it floats over one, and the design
# caps the panel itself. A box inside it that renders past ~15 rows without
# scrolling is the defect. Thresholds match the page walk so the two agree.
_TALL_PX = 620
_MANY_CHILDREN = 12

# Dialogs whose body is legitimately one long scrolling document rather than a
# list of rows. An undeclared exemption is indistinguishable from a box nobody
# looked at, so each states its reason.
EXEMPT_MODALS = {}

# Measures INSIDE the open dialog only. Same ancestor walk as the page version:
# a <tbody> never scrolls, its wrapper does, and a version of this without the
# walk reported every correctly-wrapped table as broken.
_MEASURE_MODAL = """(mid) => {
  const root = document.getElementById(mid);
  if (!root) return [];
  const out = [], seen = new Set();
  root.querySelectorAll('*').forEach(el => {
    const st = getComputedStyle(el);
    if (st.display === 'none' || st.visibility === 'hidden') return;
    const sh = el.scrollHeight;
    if (sh < %d) return;
    if (el.children.length < %d) return;
    // The overlay and its panel are the dialog chrome, not a list.
    if (el === root) return;
    if (el.classList && (el.classList.contains('modal') ||
        el.classList.contains('modal-overlay'))) return;
    for (let a = el; a && a !== root.parentElement; a = a.parentElement) {
      const as = getComputedStyle(a);
      if (['auto','scroll'].includes(as.overflowY) && a.clientHeight > 0
          && a.clientHeight < sh) return;
      const c = a.classList;
      if (c && (c.contains('scrollable-table-wrap') || c.contains('scroll-cap')
          || c.contains('scroll-cap-sm') || c.contains('audit-scroll')
          || c.contains('table-card'))) return;
    }
    const key = (el.id || '') + '|' + el.className;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({id: el.id || '', cls: String(el.className).slice(0, 60),
              tag: el.tagName, h: sh, kids: el.children.length});
  });
  return out;
}""" % (_TALL_PX, _MANY_CHILDREN)


def _nav_pages():
    """Sidebar pages, using the same tolerant regex the other gates now use —
    the strict form matched 74 of 81 because six buttons carry an id between
    the class and data-page."""
    html = (_ROOT / 'server' / 'html' / 'index.html').read_text()
    seen, out = set(), []
    for m in re.finditer(r'class="nav-btn[^"]*"[^>]*\sdata-page="([a-z-]+)"', html):
        if m.group(1) not in seen:
            seen.add(m.group(1)); out.append(m.group(1))
    return out


def _modal_ids():
    """Every `.modal-overlay` that has an id — the id is what openModal() takes.

    Two patterns because the attribute order is not consistent in the markup,
    and matching only one silently halves the walk.
    """
    html = (_ROOT / 'server' / 'html' / 'index.html').read_text()
    ids = []
    for pat in (r'<div[^>]*\bid="([a-z0-9-]+)"[^>]*class="[^"]*\bmodal-overlay\b',
                r'<div[^>]*class="[^"]*\bmodal-overlay\b[^"]*"[^>]*\bid="([a-z0-9-]+)"'):
        for m in re.finditer(pat, html):
            if m.group(1) not in ids:
                ids.append(m.group(1))
    return ids


class _ModalBase(unittest.TestCase):
    """Shared stack: seeded data dir, real gunicorn, one browser.

    Both measurement classes need the same expensive setup — a seeded instance
    and a logged-in browser — so it lives here rather than being paid twice.
    """
    @classmethod
    def setUpClass(cls):
        if sync_playwright is None:
            browser_required.skip_or_fail('playwright not installed')
        if os.environ.get('RP_STORAGE_BACKEND') == 'sqlite':
            raise unittest.SkipTest('layout is backend-agnostic — measured once')
        seeder = _ROOT / 'packaging' / 'seed-demo-data.py'
        if not seeder.is_file():
            raise unittest.SkipTest('demo seeder not in this tree')
        cls.data_dir = tempfile.mkdtemp(prefix='rp-modalboxes-')
        proc = subprocess.run(
            [sys.executable, str(seeder), '--data-dir', cls.data_dir, '--apply'],
            capture_output=True, cwd=str(_ROOT), timeout=900)
        if proc.returncode != 0:
            raise unittest.SkipTest(
                'demo seeder failed: ' + proc.stderr.decode(errors='replace')[-300:])
        from e2e_harness import start_stack
        cls._pw = sync_playwright().start()
        try:
            cls.browser = cls._pw.chromium.launch()
        except Exception as exc:
            cls._pw.stop()
            browser_required.skip_or_fail(f'chromium not available: {exc}')
        try:
            cls.base, cls._shutdown = start_stack(data_dir=cls.data_dir)
        except Exception as exc:
            cls.browser.close(); cls._pw.stop()
            raise unittest.SkipTest(f'app stack not available: {exc}')

    @classmethod
    def tearDownClass(cls):
        try:
            cls.browser.close(); cls._pw.stop()
        finally:
            cls._shutdown()

    def _login(self, page):
        page.goto(self.base + '/index.html')
        # The seeder builds its own operator accounts; there is no 'admin'.
        page.fill('#login-user', 'alice')
        page.fill('#login-pass', 'demo')
        page.click('#login-form button[type="submit"]')
        page.wait_for_selector('#app', state='visible', timeout=90000)
        page.wait_for_timeout(6000)


class TestNoDialogBoxGrowsUnbounded(_ModalBase):

    def test_every_dialog_caps_its_variable_row_boxes(self):
        ids = _modal_ids()
        self.assertGreater(len(ids), 100,
                           f'found only {len(ids)} dialogs — the id/class regex '
                           'missed most of the 138 that exist')
        ctx = self.browser.new_context(viewport={'width': 1440, 'height': 900})
        page = ctx.new_page()
        findings, opened = {}, 0
        try:
            self._login(page)
            for mid in ids:
                # Close whatever the previous target left open, so a stacked
                # overlay cannot be measured as part of the next dialog.
                page.evaluate(
                    "(() => { document.querySelectorAll('.modal-overlay.active')"
                    ".forEach(e => e.classList.remove('active')); })()")
                page.evaluate(
                    f"typeof openModal === 'function' && openModal({mid!r})")
                page.wait_for_timeout(220)
                is_open = page.evaluate(
                    "m => { const e = document.getElementById(m);"
                    " return !!e && e.classList.contains('active'); }", mid)
                if not is_open:
                    continue
                opened += 1
                if mid in EXEMPT_MODALS:
                    continue
                bad = page.evaluate(_MEASURE_MODAL, mid)
                if bad:
                    findings[mid] = bad
        finally:
            page.close(); ctx.close()

        # A walk where nothing opened is a walk that measured nothing while
        # reporting a clean sweep — the exact failure this release is about.
        self.assertGreater(opened, len(ids) // 2,
                           f'only {opened} of {len(ids)} dialogs actually '
                           'opened — this measured almost nothing')
        self.assertEqual(findings, {},
                         'These boxes inside dialogs render past the ~15-line '
                         'cap and neither they nor any ancestor scroll:\n' +
                         json.dumps(findings, indent=2))

    def test_the_measurement_can_actually_see_a_violation(self):
        """Positive control. The assertion above is 'nothing was found', which is
        the shape that passes when the instrument is broken. Force a tall
        uncapped box into a real open dialog and require it to be reported."""
        ids = _modal_ids()
        ctx = self.browser.new_context(viewport={'width': 1440, 'height': 900})
        page = ctx.new_page()
        try:
            self._login(page)
            target = None
            for mid in ids:
                page.evaluate(
                    f"typeof openModal === 'function' && openModal({mid!r})")
                page.wait_for_timeout(200)
                if page.evaluate("m => { const e = document.getElementById(m);"
                                 " return !!e && e.classList.contains('active'); }",
                                 mid):
                    target = mid
                    break
            self.assertIsNotNone(target, 'no dialog opened at all')
            page.evaluate("""(m) => {
              const root = document.getElementById(m);
              const d = document.createElement('div');
              d.id = 'rp-probe-tall-modal-box';
              for (let i = 0; i < 40; i++) {
                const r = document.createElement('div');
                r.style.height = '40px'; r.textContent = 'row ' + i;
                d.appendChild(r);
              }
              root.appendChild(d);
            }""", target)
            found = [b['id'] for b in page.evaluate(_MEASURE_MODAL, target)]
            self.assertIn('rp-probe-tall-modal-box', found,
                          'the measurement cannot see a 1600px 40-child box '
                          'inside an open dialog — it would report a clean '
                          'sweep no matter what shipped')
        finally:
            page.close(); ctx.close()


class TestDialogsOpenedByRealClicksAreCapped(_ModalBase):
    """The populated half — dialogs measured as an OPERATOR gets them.

    The walk above calls openModal() directly, which adds `.active` and moves
    focus and does NOT run the loader that fills the dialog with rows. So it
    measures markup, and a picker that only grows once the fleet is fetched into
    it is invisible to it. That limitation is stated at the top of this file;
    this class is what closes it.

    Instead of mapping 138 dialogs to 138 opener functions, it does what an
    operator does: crawls the pages and CLICKS each visible `data-action`
    control, then measures whatever dialog that click opened. The stack is
    seeded, so the handler behind the button has real rows to render — which is
    the whole difference. The technique is lifted from
    test_v640_e2e_click_sweep.py, including its denylist of session-ending and
    navigate-away actions.

    It measures fewer dialogs than the walk above (only those a visible control
    opens) and measures them PROPERLY. The two are complements, not rivals, and
    both are needed: one has breadth, the other has data.
    """

    # Session-ending / stack-ending / navigate-away actions, same set the click
    # sweep denies — clicking these ends the run rather than opening a dialog.
    DENY = re.compile(
        r"logout|doLogout|downloadDiagnostics|exportEverything|restartServer|"
        r"shutdownServer|factoryReset|serverSelfUpdate|openSwagger|openApiDocs",
        re.I)

    def test_dialogs_opened_by_clicking_are_capped(self):
        pages = _nav_pages()
        self.assertGreater(len(pages), 50, 'page enumeration found almost nothing')
        ctx = self.browser.new_context(viewport={'width': 1440, 'height': 900})
        page = ctx.new_page()
        findings, opened, clicked = {}, 0, 0
        try:
            self._login(page)
            for pg_name in pages:
                page.evaluate("n => { try { showPage(n) } catch (e) {} }", pg_name)
                page.wait_for_timeout(500)
                names = page.evaluate("""() => {
                  const out = new Set();
                  for (const el of document.querySelectorAll(
                           '[data-action],[data-action-btn]')) {
                    const r = el.getBoundingClientRect();
                    if (r.width > 0 && r.height > 0) {
                      out.add(el.dataset.action || el.dataset.actionBtn);
                    }
                  }
                  return [...out];
                }""")
                for name in names:
                    if not name or self.DENY.search(name):
                        continue
                    page.evaluate("""(name) => {
                      const els = document.querySelectorAll(
                        `[data-action='${name}'],[data-action-btn='${name}']`);
                      for (const el of els) {
                        const r = el.getBoundingClientRect();
                        if (r.width > 0 && r.height > 0) { el.click(); return; }
                      }
                    }""", name)
                    clicked += 1
                    # Let the handler fetch and render. This is the point of the
                    # class, so it gets real time rather than the 60ms the click
                    # sweep uses (it only needs the error, not the content).
                    page.wait_for_timeout(450)
                    live = page.evaluate(
                        "() => [...document.querySelectorAll('.modal-overlay.active')]"
                        ".map(m => m.id).filter(Boolean)")
                    for mid in live:
                        if mid in EXEMPT_MODALS:
                            continue
                        opened += 1
                        bad = page.evaluate(_MEASURE_MODAL, mid)
                        if bad:
                            findings.setdefault(mid, []).extend(bad)
                    page.evaluate(
                        "document.querySelectorAll('.modal-overlay.active')"
                        ".forEach(m => m.classList.remove('active'));"
                        "document.querySelectorAll('.drawer.open')"
                        ".forEach(d => d.classList.remove('open'));")
        finally:
            page.close(); ctx.close()

        # Instrument controls. A sweep that clicked nothing, or opened nothing,
        # reports a clean result while proving nothing — the exact failure this
        # release exists to close.
        self.assertGreater(clicked, 100,
                           f'only {clicked} controls clicked — the crawl is not '
                           'reaching the pages')
        self.assertGreater(opened, 5,
                           f'only {opened} dialogs opened from {clicked} clicks — '
                           'no dialog was measured with real data in it, so this '
                           'proved nothing')
        self.assertEqual(findings, {},
                         'These boxes inside dialogs render past the ~15-line cap '
                         'once REAL data is loaded into them:\n'
                         + json.dumps(findings, indent=2))


class TestTheExemptionsAreHonest(unittest.TestCase):
    """No browser needed — keeps the exemption list from rotting into a place
    to hide a real box."""

    def test_every_exemption_states_a_reason(self):
        for mid, why in EXEMPT_MODALS.items():
            self.assertGreater(len(why), 30,
                               f'{mid} is exempt without a real reason')

    def test_exemptions_name_dialogs_that_exist(self):
        ids = set(_modal_ids())
        for mid in EXEMPT_MODALS:
            self.assertIn(mid, ids,
                          f'{mid} is exempt but is not a dialog in index.html — '
                          'a stale exemption hides whatever takes its id next')


if __name__ == '__main__':
    unittest.main()
