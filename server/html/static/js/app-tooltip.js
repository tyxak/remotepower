// app-tooltip.js — the tooltip that stands in for the browser's own (7.4.0).
//
// The markup keeps title="…", so without this script nothing changes: the browser
// shows its own tooltip after about a second, never on a touch screen, in its own
// colours. With it, the script takes the title over while an element is hovered,
// focused with the keyboard or held with a finger, and shows the same words in the
// app's own tooltip: after 350 ms, in the theme's colours, and on touch after a
// long press. Eager and classic, like the other shared scripts; it only listens.
//
// What it keeps:
//   * The accessible name. An icon-only control is named by its title, so while its
//     title is off it carries the same words as aria-label, and loses them again
//     when the title goes back (a label left behind would go stale the day the app
//     changes that title). A control with text of its own gets the tooltip as its
//     description (aria-describedby) while the tooltip is shown.
//   * The title itself. It goes back as soon as the pointer or focus leaves, and
//     before a key press or a click acts, so whatever reads the attribute
//     (assistive technology, an extension, the language switcher, a handler that
//     wants the control's title) finds it there. A title the app changed in the
//     meantime is left as the app set it.
//   * WCAG 1.4.13: Escape dismisses the tooltip, and it stays open while the
//     pointer is over it.
//
// Form fields keep the browser's tooltip: the title on an input is its validation
// hint and sometimes its only name. data-no-tip opts any element out. Code that
// has no native fallback to keep can use data-tip="…" instead of title.
(function () {
  'use strict';

  var SHOW_MS = 350;        // pointer rests on an element
  var FOCUS_MS = 120;       // keyboard focus
  var GRACE_MS = 140;       // time to cross the gap into the tooltip
  var HOLD_MS = 500;        // finger held on an element
  var TOUCH_SHOW_MS = 2600; // how long a held tooltip stays
  var GAP = 8;              // between element and tooltip
  var EDGE = 8;             // between tooltip and the window edge

  var tip = null;           // the one tooltip element, a direct child of <body>
  var anchor = null;        // the element the tooltip belongs to
  var shown = false;
  var taken = new WeakMap();      // element -> the title we took off it
  var named = new WeakMap();      // element -> the aria-label we gave it while its title is off
  var describedBy = new WeakMap(); // element -> its aria-describedby before ours
  var warmUntil = 0;              // moving along a toolbar: the next tooltip skips the wait
  var showTimer = null, hideTimer = null, holdTimer = null, touchTimer = null, watchTimer = null;
  var suppressClickUntil = 0;

  // Where the tooltip goes: below the element, or above when there is no room, or
  // beside it for the sidebar. Pure, so it can be tested without a layout engine.
  // a = the element's rect, t = the tooltip's size, v = the window's size.
  function place(a, t, v, side) {
    function clamp(x, lo, hi) { return Math.max(lo, Math.min(x, hi)); }
    var left, top;
    if (side === 'right' || side === 'left') {
      var rightX = a.right + GAP, leftX = a.left - GAP - t.w;
      var fitsRight = rightX + t.w <= v.w - EDGE, fitsLeft = leftX >= EDGE;
      // the side asked for, unless only the other one has room
      var useRight = side === 'right' ? (fitsRight || !fitsLeft) : (!fitsLeft && fitsRight);
      left = useRight ? rightX : leftX;
      top = clamp(a.top + (a.height - t.h) / 2, EDGE, Math.max(EDGE, v.h - t.h - EDGE));
      return { left: Math.round(left), top: Math.round(top), side: useRight ? 'right' : 'left' };
    }
    var below = a.bottom + GAP, above = a.top - GAP - t.h;
    var useBelow = below + t.h <= v.h - EDGE || above < EDGE;
    top = useBelow ? below : above;
    left = clamp(a.left + (a.width - t.w) / 2, EDGE, Math.max(EDGE, v.w - t.w - EDGE));
    return { left: Math.round(left), top: Math.round(top), side: useBelow ? 'below' : 'above' };
  }

  function tipEl() {
    if (!tip) {
      tip = document.createElement('div');
      tip.id = 'rp-tooltip';
      tip.setAttribute('role', 'tooltip');
      tip.hidden = true;
      // Stay open while the pointer is on it (WCAG 1.4.13: hoverable).
      tip.addEventListener('pointerenter', function () { clearTimeout(hideTimer); });
      tip.addEventListener('pointerleave', function () { release(); });
      document.body.appendChild(tip);   // never inside .container: its z-index would seal the tooltip under the sidebar
    }
    return tip;
  }

  // The element a pointer or focus event is about, or null when it has no tooltip.
  function pick(node) {
    if (!node || !node.closest) return null;
    var el = node.closest('[title],[data-tip]');
    if (!el || el.closest('#rp-tooltip') || el.hasAttribute('data-no-tip')) return null;
    if (/^(INPUT|SELECT|TEXTAREA|IFRAME)$/.test(el.tagName)) return null;
    return el;
  }

  function interactive(el) {
    return /^(BUTTON|A|SUMMARY)$/.test(el.tagName) || el.hasAttribute('role') || el.hasAttribute('tabindex');
  }

  // Take the title off the element so the browser's own tooltip never starts, and
  // make sure the element still has a name. Returns the words, or ''.
  function take(el) {
    var words = el.getAttribute('title');
    if (words === null) return (el.getAttribute('data-tip') || '').trim();
    words = words.trim();
    if (!words) return '';
    taken.set(el, el.getAttribute('title'));
    el.removeAttribute('title');
    var bare = !el.hasAttribute('aria-label') && !el.hasAttribute('aria-labelledby')
      && !(el.textContent || '').trim() && !el.querySelector('img[alt]:not([alt=""])');
    if (bare && interactive(el)) { el.setAttribute('aria-label', words); named.set(el, words); }
    return words;
  }

  function giveBack(el) {
    if (named.has(el)) {
      if (el.getAttribute('aria-label') === named.get(el)) el.removeAttribute('aria-label');
      named.delete(el);
    }
    if (!taken.has(el)) return;
    // an app that set a new title while this one was held keeps its own
    if (!el.hasAttribute('title')) el.setAttribute('title', taken.get(el));
    taken.delete(el);
  }

  function describe(el, on) {
    if (on) {
      describedBy.set(el, el.getAttribute('aria-describedby'));
      var ids = (el.getAttribute('aria-describedby') || '').split(/\s+/).filter(Boolean);
      if (ids.indexOf('rp-tooltip') < 0) ids.push('rp-tooltip');
      el.setAttribute('aria-describedby', ids.join(' '));
    } else if (describedBy.has(el)) {
      var was = describedBy.get(el);
      if (was === null) el.removeAttribute('aria-describedby'); else el.setAttribute('aria-describedby', was);
      describedBy.delete(el);
    }
  }

  function reveal(words) {
    if (!anchor || !anchor.isConnected) { release(); return; }
    var t = tipEl();
    t.textContent = words;
    t.hidden = false;
    t.style.left = '0px';
    t.style.top = '0px';
    var r = anchor.getBoundingClientRect();
    var size = t.getBoundingClientRect();
    var at = place(r, { w: size.width, h: size.height },
      { w: document.documentElement.clientWidth, h: document.documentElement.clientHeight },
      anchor.closest('.sidebar') ? (document.documentElement.dir === 'rtl' ? 'left' : 'right') : 'below');
    t.style.left = at.left + 'px';
    t.style.top = at.top + 'px';
    t.setAttribute('data-side', at.side);
    describe(anchor, true);
    shown = true;
    clearInterval(watchTimer);
    // The element can be replaced under a still pointer (a table that refreshes);
    // nothing fires an event for that, so look.
    watchTimer = setInterval(function () { if (!anchor || !anchor.isConnected) release(); }, 400);
  }

  function arm(el, delay) {
    if (el === anchor) { clearTimeout(hideTimer); return; }
    release();
    var words = take(el);
    if (!words) { giveBack(el); return; }
    anchor = el;
    clearTimeout(showTimer);
    if (delay === SHOW_MS && Date.now() < warmUntil) delay = 60;
    showTimer = setTimeout(function () { reveal(words); }, delay);
  }

  function release() {
    clearTimeout(showTimer); clearTimeout(hideTimer); clearTimeout(touchTimer); clearInterval(watchTimer);
    if (anchor) {
      describe(anchor, false);
      giveBack(anchor);
    }
    if (shown) warmUntil = Date.now() + 400;
    anchor = null;
    shown = false;
    if (tip) tip.hidden = true;
  }

  function releaseSoon() {
    clearTimeout(hideTimer);
    hideTimer = setTimeout(release, GRACE_MS);
  }

  // ── the pointer (a mouse or a pen; touch has its own path below) ─────────────
  document.addEventListener('pointerover', function (e) {
    if (e.pointerType === 'touch') return;
    var el = pick(e.target);
    if (el) arm(el, SHOW_MS);
    else if (anchor && !(tip && tip.contains(e.target))) releaseSoon();
  });
  document.addEventListener('pointerout', function (e) {
    if (e.pointerType === 'touch' || !anchor) return;
    var to = e.relatedTarget;
    if (anchor.contains(to) || (tip && tip.contains(to))) return;
    if (anchor.contains(e.target)) releaseSoon();
  });

  // ── the keyboard ─────────────────────────────────────────────────────────────
  document.addEventListener('focusin', function (e) {
    var el = pick(e.target);
    if (el && el.matches && el.matches(':focus-visible')) arm(el, FOCUS_MS);
  });
  document.addEventListener('focusout', function (e) {
    if (anchor && anchor.contains(e.target)) release();
  });
  // Escape dismisses it; Enter, Space or any other key that may act on the control
  // gives its title back first, because the handler can read it.
  document.addEventListener('keydown', function (e) {
    if (anchor && !/^(Tab|Shift|Control|Alt|Meta)$/.test(e.key)) release();
  }, true);

  // ── a finger: hold to read, and the hold is not a tap ────────────────────────
  document.addEventListener('touchstart', function (e) {
    var el = pick(e.target);
    clearTimeout(holdTimer);
    if (!el) return;
    holdTimer = setTimeout(function () {
      arm(el, 0);
      suppressClickUntil = Date.now() + 1200;
      clearTimeout(touchTimer);
      touchTimer = setTimeout(release, TOUCH_SHOW_MS);
    }, HOLD_MS);
  }, { passive: true });
  ['touchend', 'touchmove', 'touchcancel'].forEach(function (name) {
    document.addEventListener(name, function () { clearTimeout(holdTimer); }, { passive: true });
  });
  document.addEventListener('click', function (e) {
    if (Date.now() < suppressClickUntil) { suppressClickUntil = 0; e.preventDefault(); e.stopPropagation(); }
  }, true);

  // ── anything that moves the page out from under the tooltip ──────────────────
  window.addEventListener('scroll', function () { if (anchor) release(); }, true);
  window.addEventListener('resize', function () { if (anchor) release(); });
  document.addEventListener('pointerdown', function (e) {
    if (anchor && !(tip && tip.contains(e.target)) && e.pointerType !== 'touch') release();
  }, true);

  window.RPTooltip = {
    place: place,
    hide: release,
    visible: function () { return shown; },
  };
})();
