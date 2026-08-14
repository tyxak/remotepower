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


def _dialog_actions():
    """`data-action` names whose handler calls `openModal()`.

    DERIVED from the sources rather than hand-listed, so it cannot go stale the
    way a maintained list would — a new dialog opener is picked up the moment it
    exists, and one that is deleted stops being clicked.

    This is what makes the class affordable. Clicking every data-action reaches
    the same dialogs and takes over eleven minutes, in a file that runs in the
    serial gate; clicking only the openers is ~70 targets. Clicking the ELEMENT
    rather than calling the function matters too — the element carries the
    `data-arg` the handler needs, so the dialog opens against a real record
    instead of an empty one.
    """
    html = (_ROOT / 'server' / 'html' / 'index.html').read_text()
    js_dir = _ROOT / 'server' / 'html' / 'static' / 'js'
    js = ''.join(p.read_text() for p in sorted(js_dir.glob('app*.js')))
    out = set()
    for name in set(re.findall(r'data-action="([A-Za-z_][\w]*)"', html)):
        m = re.search(rf'(?:async\s+)?function {re.escape(name)}\s*\(', js)
        if not m:
            continue
        body = js[m.start():]
        nxt = re.search(r'\n(?:async )?function ', body[10:])
        body = body[:nxt.start() + 10] if nxt else body[:4000]
        if 'openModal(' in body:
            out.add(name)
    return out


_DIALOG_ACTIONS = _dialog_actions()


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

    # Two instruments, both injected before any page script runs (Playwright
    # adds them through the debugger, so `script-src 'self'` is untouched).
    #
    # __rpInflight counts outstanding fetches, so the wait can tell "nothing is
    # coming" from "the handler is still working" instead of sleeping a fixed
    # interval and hoping.
    #
    # __rpOpened is the one that matters. Polling asks "is a dialog open at the
    # moment I look", which misses any dialog that opens and closes between two
    # looks — and a fixed sleep and a poll loop BOTH returned the same 2 dialogs
    # from ~1000 clicks under load, which is what finally ruled timing out as
    # the cause. A MutationObserver records every overlay that became active at
    # any instant, so detection stops depending on when the measurement runs.
    _INSTRUMENT = """
      window.__rpInflight = 0;
      const _f = window.fetch;
      window.fetch = function (...a) {
        window.__rpInflight++;
        return _f.apply(this, a).finally(() => { window.__rpInflight--; });
      };
      window.__rpOpened = [];
      // An init script runs at document-start, where documentElement is not
      // reliably there yet — observe() then throws, the REST OF THIS SCRIPT
      // never runs, and __rpOpened stays undefined. That reads downstream as
      // "no dialog ever opened", which is how this instrument reported 0
      // dialogs from 1012 clicks and looked like an application bug.
      // _assert_instrument_works() below is the guard against believing it.
      const _install = () => {
        new MutationObserver(ms => {
          for (const m of ms) {
            const el = m.target;
            if (el.classList && el.classList.contains('modal-overlay')
                && el.classList.contains('active') && el.id
                && !window.__rpOpened.includes(el.id)) {
              window.__rpOpened.push(el.id);
            }
          }
        }).observe(document.body || document.documentElement,
                   {subtree: true, attributes: true, attributeFilter: ['class']});
        window.__rpObserving = true;
      };
      if (document.body) { _install(); }
      else { document.addEventListener('DOMContentLoaded', _install); }
    """

    @staticmethod
    def _dialogs_after_click(page, budget_ms=2400, step_ms=60):
        """Every dialog the click opened, whether or not it is still open.

        Waits only while the page is still working: no dialog recorded and no
        request in flight means nothing is coming, and the loop stops after two
        quiet samples (~120ms) rather than burning the whole budget on the ~9
        in 10 clicks that open nothing. A click whose handler is mid-request
        keeps the full budget however loaded the machine is.
        """
        waited, quiet = 0, 0
        while waited < budget_ms:
            seen = page.evaluate("() => window.__rpOpened || []")
            inflight = page.evaluate("() => window.__rpInflight || 0")
            if seen and not inflight:
                page.wait_for_timeout(120)      # a frame for the last render
                return page.evaluate("() => window.__rpOpened || []")
            if not seen and not inflight:
                quiet += 1
                if quiet >= 2:
                    return []
            else:
                quiet = 0
            page.wait_for_timeout(step_ms)
            waited += step_ms
        return page.evaluate("() => window.__rpOpened || []")

    @staticmethod
    def _assert_instrument_works(page, case):
        """Prove the observer records a dialog we KNOW opened.

        Every measurement in this class is of the form "these are the dialogs
        that opened", and the failure mode of a broken instrument is an empty
        list — indistinguishable from a page where nothing opened, and it reads
        as an application bug rather than a test bug. So open one deliberately
        and require it to be recorded. If this fails, nothing below means
        anything.
        """
        page.evaluate("() => { window.__rpOpened = []; }")
        ok = page.evaluate("() => !!window.__rpObserving")
        case.assertTrue(ok, 'the MutationObserver never installed — every '
                            '"no dialogs opened" result below would be a lie')
        target = page.evaluate("""() => {
          const el = document.querySelector('.modal-overlay[id]');
          if (!el) return null;
          el.classList.add('active');
          return el.id;
        }""")
        case.assertIsNotNone(target, 'no .modal-overlay[id] in the DOM at all')
        page.wait_for_timeout(120)
        seen = page.evaluate("() => window.__rpOpened || []")
        case.assertIn(target, seen,
                      f'the observer did not record {target} becoming active, '
                      'so it cannot record any other dialog either')
        page.evaluate("""id => { const el = document.getElementById(id);
                                 if (el) el.classList.remove('active'); }""", target)
        page.evaluate("() => { window.__rpOpened = []; }")

    @classmethod
    def _denied(cls):
        """Derived openers the DENY list suppresses — they are never clicked, so
        the early exit must not wait for them."""
        return {a for a in _DIALOG_ACTIONS if cls.DENY.search(a)}

    def test_dialogs_opened_by_clicking_are_capped(self):
        pages = _nav_pages()
        # 78, not 50. A floor far below the true count only catches TOTAL
        # collapse: this sweep sat at 75 of 81 for releases — six buttons
        # carry an id before data-page and were never enumerated — and the
        # old `> 50` passed the whole time. A threshold has to be near the
        # real number to catch shrinkage.
        self.assertGreater(len(pages), 78, 'page enumeration found almost nothing')
        # If the derivation breaks, the sweep clicks nothing and reports a
        # clean result — the exact shape this release exists to close.
        self.assertGreater(
            len(_DIALOG_ACTIONS), 40,
            f'only {len(_DIALOG_ACTIONS)} dialog-opening actions derived from '
            'the sources — the derivation is broken, so this sweep would click '
            'almost nothing and pass while measuring almost nothing')
        ctx = self.browser.new_context(viewport={'width': 1440, 'height': 900})
        page = ctx.new_page()
        page.add_init_script(self._INSTRUMENT)
        findings, opened, clicked = {}, 0, 0
        # Clicked ONCE each, globally. These are static index.html controls, so
        # they sit in the shared DOM on every page — filtering per page by
        # presence would click all ~70 on all ~80 pages, which is worse than the
        # unfiltered sweep it replaced. The page walk still earns its keep: it
        # loads each page's data, so a dialog opened later renders against a
        # populated store rather than an empty one.
        done_actions = set()
        try:
            self._login(page)
            self._assert_instrument_works(page, self)
            for pg_name in pages:
                # Every opener already clicked — the rest of the walk can only
                # repeat itself, and each page still costs a settle.
                if done_actions >= _DIALOG_ACTIONS - self._denied():
                    break
                page.evaluate("n => { try { showPage(n) } catch (e) {} }", pg_name)
                # Wait for the page's OWN data to arrive before enumerating.
                # A flat 500ms enumerated static chrome only: the row-level
                # buttons — the edit/inspect/assign controls that open the
                # dialogs this class exists to measure — do not exist until the
                # fetch lands. With the sleep, 1014 clicks opened ONE dialog,
                # which reads as "the app barely uses dialogs" and is really
                # "the buttons were not there yet".
                for _ in range(40):                     # up to ~4s
                    if not page.evaluate("() => window.__rpInflight || 0"):
                        break
                    page.wait_for_timeout(100)
                page.wait_for_timeout(400)
                # Only the controls that can actually open a dialog, and only
                # those PRESENT on this page. Two earlier shapes were both
                # wrong, in opposite directions:
                #
                #   * filtered on a non-zero bounding box — the dialog-opening
                #     controls are overwhelmingly in Settings panes that are
                #     not the active one, so they have zero size until an
                #     operator switches to them. Measured directly: of five
                #     actions known to call openModal(), all five had a zero
                #     box and three opened their dialog the moment they were
                #     clicked. The filter removed the entire population.
                #   * no filter at all — ~2000 clicks, each with a wait budget,
                #     and this file runs in the SERIAL GATE (it is not matched
                #     by the `tests/*e2e*.py` exclusion). Killed at 11 minutes
                #     with no end in sight. Correct answer, unusable cost.
                #
                # `_DIALOG_ACTIONS` is derived from the sources, so it cannot
                # drift the way a hand-kept list would.
                names = page.evaluate("""(want) => want.filter(n =>
                  document.querySelector(
                    `[data-action='${n}'],[data-action-btn='${n}']`))""",
                  sorted(_DIALOG_ACTIONS))
                for name in names:
                    if not name or self.DENY.search(name):
                        continue
                    if name in done_actions:
                        continue
                    done_actions.add(name)
                    # Reset the observer BEFORE the click, not after. The
                    # earlier order wiped any dialog the click opened
                    # synchronously — which is most of them — and left the
                    # sweep reporting zero while the instrument was working
                    # perfectly. A self-check proves the observer records; it
                    # cannot prove the caller reads it at the right moment.
                    page.evaluate("() => { window.__rpOpened = []; }")
                    page.evaluate("""(name) => {
                      const el = document.querySelector(
                        `[data-action='${name}'],[data-action-btn='${name}']`);
                      if (el) el.click();
                    }""", name)
                    clicked += 1
                    live = self._dialogs_after_click(page)
                    for mid in live:
                        if mid in EXEMPT_MODALS:
                            continue
                        opened += 1
                        page.evaluate(
                            "id => { const el = document.getElementById(id);"
                            "        if (el) el.classList.add('active'); }", mid)
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
        # `clicked` is now bounded by the DERIVED set, not by how many controls
        # happen to be on screen, so the old `> 100` was a leftover from the
        # click-everything design and failed at 71 — a correct sweep tripping a
        # stale guard. What matters is that the sweep reached MOST of the set:
        # a crawl that never left the first page would click far fewer.
        self.assertGreaterEqual(
            clicked, int(len(_DIALOG_ACTIONS) * 0.8),
            f'only {clicked} of {len(_DIALOG_ACTIONS)} dialog-opening controls '
            'were reached — the crawl is not getting to the pages that hold them')
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
