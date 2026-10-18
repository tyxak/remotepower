"""In-page measurements for the keyboard gate (tests/test_v740_keyboard_e2e.py).

Everything here runs in the browser against the real page. The functions return plain data; the test
decides what is a failure. They are kept apart from the test so that the positive controls can run the
very same code on a page that has been made wrong on purpose.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

FOCUSABLE = ("a[href],button:not([disabled]),input:not([disabled]):not([type=hidden]),select:not([disabled]),"
             "textarea:not([disabled]),[tabindex]:not([tabindex='-1'])")


def dialog_ids():
    """Every `.modal-overlay` in index.html that has an id, which is what openModal() takes.

    Two patterns because the attribute order is not the same everywhere in the markup, and matching one
    silently halves the walk.
    """
    html = (ROOT / 'server' / 'html' / 'index.html').read_text(encoding='utf-8')
    ids = []
    for pat in (r'<div[^>]*\bid="([a-z0-9-]+)"[^>]*class="[^"]*\bmodal-overlay\b',
                r'<div[^>]*class="[^"]*\bmodal-overlay\b[^"]*"[^>]*\bid="([a-z0-9-]+)"'):
        for m in re.finditer(pat, html):
            if m.group(1) not in ids:
                ids.append(m.group(1))
    return ids


def nav_pages():
    html = (ROOT / 'server' / 'html' / 'index.html').read_text(encoding='utf-8')
    seen, out = set(), []
    for m in re.finditer(r'class="nav-btn[^"]*"[^>]*\sdata-page="([a-z-]+)"', html):
        if m.group(1) not in seen:
            seen.add(m.group(1))
            out.append(m.group(1))
    return out


# What the dialog looks like from the keyboard, right after it opens.
DIALOG_STATE = """([id, FOC]) => {
  const el = document.getElementById(id);
  const a = document.activeElement;
  const foc = [...el.querySelectorAll(FOC)].filter(n => n.offsetParent !== null);
  const isClose = n => n.classList.contains('modal-close') || /^close\\b/i.test(n.getAttribute('aria-label') || '');
  const d = n => n ? n.tagName.toLowerCase() + (n.id ? '#' + n.id : '') + (n.className ? '.' + String(n.className).split(' ')[0] : '') : null;
  return {active: el.classList.contains('active'), inside: el.contains(a), landed: d(a), landedOnClose: !!(a && isClose(a)),
          controls: foc.length, otherControls: foc.filter(n => !isClose(n)).length};
}"""

INSIDE = "id => document.getElementById(id).contains(document.activeElement)"
CLOSED = "id => !document.getElementById(id) || !document.getElementById(id).classList.contains('active')"


def walk_dialog(page, mid, opener_selector='#toast-history-btn', tab_presses=None, open_js=None):
    """Open one dialog the way the app does and exercise it with the keyboard. Returns a dict of facts."""
    rec = {'id': mid}
    page.evaluate("() => document.querySelectorAll('.modal-overlay.active').forEach(m => closeModal(m.id))")
    page.evaluate("s => { const o = document.querySelector(s); o.focus(); window.__opener = o; }", opener_selector)
    page.evaluate(open_js or "id => openModal(id)", mid)
    page.wait_for_timeout(90)
    rec.update(page.evaluate(DIALOG_STATE, [mid, FOCUSABLE]))
    if not rec['active']:
        return rec
    n = rec['controls']
    escaped = False
    for _ in range(tab_presses if tab_presses is not None else min(n, 20) + 2):
        page.keyboard.press('Tab')
        if not page.evaluate(INSIDE, mid):
            escaped = True
            break
    rec['tab_escaped'] = escaped
    page.evaluate("""([id, FOC]) => { const el = document.getElementById(id);
        const f = [...el.querySelectorAll(FOC)].filter(n => n.offsetParent !== null); if (f[0]) f[0].focus(); }""", [mid, FOCUSABLE])
    page.keyboard.press('Shift+Tab')
    rec['shift_tab_escaped'] = not page.evaluate(INSIDE, mid)
    page.keyboard.press('Escape')
    page.wait_for_timeout(50)
    rec['escape_closes'] = page.evaluate(CLOSED, mid)
    rec['focus_returned'] = page.evaluate("() => document.activeElement === window.__opener")
    page.evaluate("() => document.querySelectorAll('.modal-overlay.active').forEach(m => closeModal(m.id))")
    return rec


# One page: controls a mouse can use and a keyboard cannot, and controls that show no change when focused.
MEASURE_PAGE = r"""(name) => {
  const root = document.getElementById('page-' + name) || document.body;
  const vis = el => { const r = el.getClientRects(); if (!r.length) return false; const s = getComputedStyle(el);
                      return s.visibility !== 'hidden' && s.display !== 'none' && r[0].width > 0 && r[0].height > 0; };
  const NATIVE = new Set(['BUTTON', 'INPUT', 'SELECT', 'TEXTAREA', 'SUMMARY']);
  const nativeFocusable = el => NATIVE.has(el.tagName) || (el.tagName === 'A' && el.hasAttribute('href')) || el.isContentEditable;
  const INNER = "a[href],button,input,select,textarea,[tabindex]:not([tabindex='-1'])";
  const desc = el => el.tagName.toLowerCase() + (el.id ? '#' + el.id : '') + (el.classList.length ? '.' + [...el.classList].slice(0, 2).join('.') : '');
  const label = el => (el.textContent || '').trim().replace(/\s+/g, ' ').slice(0, 30);
  const focusableAncestor = el => { for (let a = el.parentElement; a && a !== root; a = a.parentElement) { if (nativeFocusable(a) || a.tabIndex >= 0) return true; } return false; };

  // (1) a click handler on something the keyboard cannot reach
  const mouseOnly = [];
  root.querySelectorAll('[data-action],[data-action-btn],[data-home-act]').forEach(el => {
    if (!vis(el) || (nativeFocusable(el) && !el.disabled) || el.tabIndex >= 0 || focusableAncestor(el)) return;
    if (el.tagName === 'LABEL' || el.tagName === 'OPTION') return;           // a label forwards to its control
    if (el.tagName === 'TR' && el.querySelector(INNER)) return;              // a clickable row whose cells hold their own buttons
    mouseOnly.push({el: desc(el), action: el.getAttribute('data-action') || el.getAttribute('data-action-btn') || el.getAttribute('data-home-act'), text: label(el)});
  });

  // (2) looks clickable (cursor: pointer) and has no keyboard path
  const pointerOnly = [];
  root.querySelectorAll('*').forEach(el => {
    if (!vis(el) || getComputedStyle(el).cursor !== 'pointer') return;
    if (['OPTION', 'LABEL', 'SELECT'].includes(el.tagName) || el.closest('label')) return;
    if (nativeFocusable(el) || el.tabIndex >= 0 || focusableAncestor(el)) return;
    if (el.querySelector(INNER)) return;
    const par = el.parentElement;
    if (par && par !== root && getComputedStyle(par).cursor === 'pointer') return;   // report the outermost box once
    pointerOnly.push({el: desc(el), text: label(el)});
  });

  // (3) focusable controls: the style at rest against the style while focused from the keyboard
  const FOC = "a[href],button:not([disabled]),input:not([disabled]):not([type=hidden]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex='-1'])";
  const els = [...root.querySelectorAll(FOC)].filter(vis).slice(0, 90);
  const sty = el => { const s = getComputedStyle(el);
    return {ol: s.outlineStyle + ' ' + s.outlineWidth + ' ' + s.outlineColor, bs: s.boxShadow, bc: s.borderTopColor + s.borderBottomColor,
            bg: s.backgroundColor, c: s.color, td: s.textDecorationLine, op: s.opacity}; };
  if (document.activeElement && document.activeElement.blur) document.activeElement.blur();
  const rest = els.map(sty);
  const noChange = [];
  let focused = 0;
  els.forEach((el, i) => {
    el.focus({preventScroll: true});
    if (document.activeElement !== el) { return; }          // inert or clipped right now: the browser's own Tab skips it too
    focused += 1;
    const s1 = sty(el);
    if (!Object.keys(s1).some(k => s1[k] !== rest[i][k])) noChange.push(desc(el));
    el.blur();
  });
  return {mouseOnly, pointerOnly, noChange, listed: els.length, focused,
          positiveTabindex: [...root.querySelectorAll('[tabindex]')].filter(e => e.tabIndex > 0).length};
}"""
