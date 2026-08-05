# Accessibility conformance statement

**What this is:** an honest, self-assessed account of how the RemotePower web
interface measures up against **WCAG 2.1 Level AA**, written so it can back a
VPAT / ACR without anyone having to re-derive the facts. **What it is not:** a
certification, a third-party audit, or a claim of full conformance. Where we do
not meet a success criterion we say so and say why, because a conformance
statement that overclaims is worse than no statement at all.

Same shape as [compliance.md](compliance.md), which does the equivalent job for
SOC 2 / ISO 27001 / PCI DSS / HIPAA: capabilities and evidence, not a badge.

**Scope:** the RemotePower operator web interface (`server/html`) — the login
page, the dashboard, and every page reachable from the sidebar. Out of scope:
the `rp` terminal CLI/TUI, the agents (no user interface), the embedded web
terminal (a terminal emulator; it inherits the accessibility characteristics of
xterm.js and of whatever shell you attach to it), and the generated PDF/CSV
exports.

**Standards referenced:** WCAG 2.1 Level A and AA. Section 508 and EN 301 549
both incorporate WCAG 2.1 AA by reference, so the per-criterion table below is
the substance of an answer to either — but neither has been formally assessed,
and we make no Section 508 or EN 301 549 conformance claim.

**Self-assessed conformance level: partially supports WCAG 2.1 AA.** The gap
that prevents a "supports" claim is a single, specific one — form errors are
not identified programmatically (SC 3.3.1) — and it is described in full below.

---

## How this was assessed

Three sources, all reproducible from the repository:

- **Automated, in the release gate.** `tests/test_a11y_axe.py` drives a real
  Chromium against a real gunicorn/`wsgi.py` stack and runs **axe-core** on the
  login page, the post-login dashboard, and **every sidebar page** (50+). The
  bar is **zero `critical` or `serious` violations with every default rule
  enabled** — there are no disabled rules and no exemptions. `color-contrast`
  and `nested-interactive` are both fully enforced; the last exemption was
  removed in v6.1.1, and `tests/test_v430_a11y.py` asserts it cannot come back.
- **Structural ratchets, no browser needed.** `tests/test_a11y_labels.py`
  re-implements the accessible-name computation and fails the build if the
  number of form controls without an accessible name in `index.html` rises
  above **0** (it was 313 before the sweep). `tests/test_v430_a11y.py` pins:
  every icon-only button carries `aria-label`/`title` (in static HTML **and**
  in the `innerHTML` templates JavaScript renders from), every modal overlay is
  `role="dialog" aria-modal="true"` *with* an accessible name, every
  `aria-labelledby` points at exactly one existing id, every placeholder-only
  filter/search input carries `aria-label`, and the global `:focus-visible`
  ring still exists.
- **Manual code review** for the keyboard and screen-reader behaviours that no
  static check covers — the results of which are the limitations section below.

Automated tooling catches roughly a third of WCAG issues. Read the limitations
as the more interesting half of this document.

---

## What is implemented

**Keyboard**

- A **skip link** (`Skip to main content`) is the first focusable element on the
  page and becomes visible on focus.
- A visible **focus ring** on every focusable element (`:focus-visible`, 2px
  accent outline), so it appears for keyboard users without adding a ring to
  mouse clicks.
- **Modals** opened through `openModal()` trap Tab and Shift-Tab inside the
  dialog, close on **Escape** (topmost first, tracked as a stack for nested
  dialogs), move focus to the first focusable control on open, and **restore
  focus to the opener** on close. Every dialog also gets an injected top-right
  close button labelled `Close dialog`.
- The **device drawer** does the same: `role="dialog"`, Tab trap, Escape to
  close, focus moved in on open and restored to the opener on close.
- **Sortable table headers** are focusable (`tabindex="0"`), activate on Enter
  or Space, and expose their state via `aria-sort`
  (`none`/`ascending`/`descending`). The sort glyphs themselves are
  `aria-hidden`, so they are not read as text. Shift-Enter adds a secondary
  sort column, matching Shift-click.
- A documented global shortcut set — see
  [keyboard-shortcuts.md](keyboard-shortcuts.md).

**Structure and naming**

- **Every form control in `index.html` has an accessible name** — a
  `<label for>`, a wrapping `<label>`, or an `aria-label` — enforced as a
  ratchet that can only go down.
- **Icon-only buttons** carry an `aria-label` or `title`; icons are inline SVG
  and are decorative, never the sole carrier of meaning.
- **Dialogs** are announced as dialogs and named: `role="dialog"`,
  `aria-modal="true"`, plus `aria-labelledby` pointing at the visible title (or
  an `aria-label`).
- **Active navigation** is exposed with `aria-current="page"`, not colour alone.
- **Table headers** in the static markup overwhelmingly use `scope="col"`
  (444 of 495 `<th>` elements when this was last measured) — see the
  limitations for the tables JavaScript renders.
- **Status messages** (toasts) live in a `role="status" aria-live="polite"`
  region, so a success or failure is announced without stealing focus.

**Presentation**

- **Colour contrast meets WCAG AA** across all shipped themes and is enforced
  by the axe `color-contrast` rule with no exemptions. Each theme's accent has
  a computed foreground (`--accent-contrast`) sized for it, and the muted text
  colour was retuned per theme where it fell short against the surface.
- **Reduced motion is respected.** `@media (prefers-reduced-motion: reduce)`
  blocks disable the status-dot pulse, page/row transitions, ring animations
  and every other informative-motion effect.
- **Text resizing and reflow** rely on the browser: the layout is
  flex/grid-based with a responsive sidebar (248px → 56px collapsed → off-canvas
  on mobile), and panels scroll internally rather than growing without bound.
- **Language and direction.** The interface ships in **7 languages** — English,
  Mandarin, Hindi, Spanish, Arabic, German, French. Switching language sets both
  `lang` and `dir` on `<html>`; **Arabic renders right-to-left**, with the
  sidebar and margins mirrored.

---

## Known limitations

These are real, current, and each one is a reason a criterion below is marked
*partially supports* or *does not support*.

### 1. Form errors are not identified programmatically — WCAG 2.1 AA failure (SC 3.3.1)

`aria-invalid` and `aria-describedby` appear **zero times** anywhere in the
interface, and there is no inline field-error presentation at all. Every
client-side validation failure — "Name is required", "Pick at least one
device", "Username and password required" — is delivered as a **toast**: a
transient message in the polite live region at the corner of the screen, which
**auto-dismisses after 3.5 seconds** and is not associated with the field that
caused it.

Two consequences, both bad for a screen-reader or cognitively-impaired user:

- The offending control is never marked invalid and never points at a
  description of what is wrong, so there is nothing to navigate back to. A user
  who tabs away and returns has no way to find the error.
- Validation toasts are additionally flagged `transient`, which is the one
  class the notification centre (the topbar bell, which replays the last 30
  toasts) deliberately drops. So the message is genuinely gone when it fades —
  it is not recoverable anywhere.

This is the gap that keeps the overall self-assessment at *partially supports*.

### 2. The automated gate only sees default-state pages

The axe sweep loads each page and audits it as rendered. It never opens a
modal, switches a tab panel, opens the device drawer or opens the command
palette — so **none of those surfaces has ever been machine-audited**, and any
violation that lives inside one is invisible to the gate. No test presses Tab,
either: the focus traps and focus-restore behaviour described above are
verified by code review, not by an automated keyboard walk.

### 3. Four dialogs bypass the modal manager and get no focus trap

Six call sites across four dynamically-built dialogs activate themselves with
`classList.add('active')` instead of going through `openModal()`: the **drift
detail** and **drift diff** dialogs (`app-drift.js`), and the **AI advisor** and
**runbook** dialogs (`app-ai.js`). They are correctly marked `role="dialog"`
and named, and they raise correctly above other overlays — but they get **no
Tab trap, no Escape-to-close from the modal stack, and no focus restore**. A
keyboard user can tab straight out of them into the page behind. (The
log-sweep dialog, built the same way, routes through `openModal()` and does not
have this problem.)

### 4. ~~The command palette is not exposed as a dialog~~ — fixed in v6.4.2

The palette is now a `role="dialog"` with `aria-modal="true"` and an accessible
name. Its input is a `role="combobox"` with its own `aria-label` (rather than
relying on the placeholder), `aria-controls` pointing at the results, and
`aria-activedescendant` tracking the highlighted row — which is what makes
arrow-key navigation audible, since focus deliberately stays in the input. The
results list is a `role="listbox"` of `role="option"` rows. Tab is trapped, and
closing restores focus to wherever it was opened from.

`aria-activedescendant` is re-pointed inside the render function itself, because
the list is rebuilt on every keystroke — set once at open time it would dangle
at the first re-render.

### 5. `data-action` is click-only

The interface routes events through a delegated `data-action` dispatcher bound
to `click`. On a `<button>` or `<a href>` that is fine — the browser
synthesises a click from Enter/Space. But a `data-action` placed on a
non-button element (a `<div>`, `<td>`, `<span>`) is **not keyboard reachable
and not keyboard activatable**, because nothing gives it a tab stop or a
keydown handler. Where that occurs, the action is mouse-only.

### 6. JavaScript-rendered table headers mostly lack `scope`

The static markup is good (444 of 495 headers scoped when last measured), but of
the ~500 `<th>` elements generated from JavaScript template strings only about
**twenty** carry `scope="col"`. Browsers infer column association for simple
tables, so this is
usually recoverable by assistive technology — but it is not stated explicitly
and is not guaranteed for the more complex tables.

### 7. Not assessed

No formal assessment has been done of: screen-reader behaviour with an actual
screen reader (NVDA/JAWS/VoiceOver), 400% zoom reflow (SC 1.4.10), text-spacing
overrides (SC 1.4.12), the embedded web terminal, or the PDF/CSV exports.
Absence from this document means untested, not passing.

---

## WCAG 2.1 AA, criterion by criterion

Levels: **Supports** — meets the criterion throughout the in-scope interface.
**Partially supports** — meets it in most places, with the named exception.
**Does not support** — fails. **Not evaluated** — no assessment performed;
do not read this as either a pass or a fail.

### Perceivable

| Criterion | Level | Assessment | Notes |
|---|---|---|---|
| 1.1.1 Non-text Content | A | Supports | Icon-only buttons carry `aria-label`/`title` (ratchet-tested in static HTML and JS templates); decorative SVG is `aria-hidden`. |
| 1.2.x Time-based Media | A/AA | Not applicable | The interface contains no audio or video. |
| 1.3.1 Info and Relationships | A | Partially supports | Labels, dialog roles, `aria-sort` and `aria-current` are in place; static table headers use `scope="col"`, JS-rendered ones largely do not (limitation 6). |
| 1.3.2 Meaningful Sequence | A | Supports | DOM order matches visual order; full-viewport overlays are body-level children by rule. |
| 1.3.3 Sensory Characteristics | A | Supports | Instructions never depend on shape, position or colour alone. |
| 1.3.4 Orientation | AA | Supports | No orientation lock; the layout reflows to mobile. |
| 1.3.5 Identify Input Purpose | AA | Partially supports | Login fields use standard `autocomplete`; most operational fields (device names, thresholds, filters) have no WCAG-defined input purpose to identify. |
| 1.4.1 Use of Colour | A | Supports | Status is carried by text/badges alongside colour; the active nav item uses `aria-current`, not colour alone. |
| 1.4.3 Contrast (Minimum) | AA | Supports | Enforced by the axe `color-contrast` rule with no exemptions, across every shipped theme. |
| 1.4.4 Resize Text | AA | Supports | Relative layout; no `user-scalable=no`. |
| 1.4.5 Images of Text | AA | Supports | All UI text is real text; icons are SVG. |
| 1.4.10 Reflow | AA | Not evaluated | The layout is responsive to mobile widths, but 400%-zoom reflow has not been formally tested. |
| 1.4.11 Non-text Contrast | AA | Partially supports | Covered by axe for what it can measure; the focus ring and hairline borders were tuned per theme but no separate manual pass was done. |
| 1.4.12 Text Spacing | AA | Not evaluated | No user-stylesheet spacing override test has been run. |
| 1.4.13 Content on Hover or Focus | AA | Partially supports | Hover cards and tooltips are dismissible by moving away and do not obscure the trigger; persistence and hoverability were not systematically verified. |

### Operable

| Criterion | Level | Assessment | Notes |
|---|---|---|---|
| 2.1.1 Keyboard | A | Partially supports | Buttons, links, form controls, sortable headers, modals and the drawer are all keyboard-operable; `data-action` on non-button elements is not (limitation 5). |
| 2.1.2 No Keyboard Trap | A | Supports | Modal and drawer traps are deliberate, scoped to an open dialog, and always escapable with Escape. The dialogs in limitation 3 do not trap at all — the failure is the opposite direction. |
| 2.1.4 Character Key Shortcuts | A | Supports | Single-character shortcuts are suppressed while a form field has focus. |
| 2.2.1 Timing Adjustable | A | Partially supports | Session idle timeout is operator-configurable; toast dismissal timing is not adjustable, which is the substance of limitation 1. |
| 2.2.2 Pause, Stop, Hide | A | Supports | The only continuous motion is the status-dot pulse, which stops under `prefers-reduced-motion`. No auto-updating content moves or scrolls on its own. |
| 2.3.1 Three Flashes | A | Supports | Nothing flashes more than three times per second. |
| 2.4.1 Bypass Blocks | A | Supports | Skip link to main content, visible on focus. |
| 2.4.2 Page Titled | A | Supports | Single-page app with a document title; each page carries a `.page-title` heading. |
| 2.4.3 Focus Order | A | Partially supports | Correct for the modal manager, the drawer and (since v6.4.2) the command palette, which traps Tab and restores focus on close; the four dialogs in limitation 3 do not manage focus order. |
| 2.4.4 Link Purpose (In Context) | A | Supports | Links and buttons are named in context; documentation pointers name their topic. |
| 2.4.5 Multiple Ways | AA | Supports | Sidebar navigation, the command palette (`Ctrl/Cmd-K`), the sidebar search index, and deep links (`#page`, `#device/<id>`). |
| 2.4.6 Headings and Labels | AA | Supports | One heading idiom (`.section-title`) per card; every control named. |
| 2.4.7 Focus Visible | AA | Supports | Global `:focus-visible` outline, ratchet-tested. |
| 2.5.1 Pointer Gestures | A | Supports | No path-based or multipoint gestures. |
| 2.5.2 Pointer Cancellation | A | Supports | Actions fire on click (up-event), not down-event. |
| 2.5.3 Label in Name | A | Partially supports | Visible-label/accessible-name agreement holds for labelled controls; icon-only buttons have no visible text, and the palette input is named by its placeholder. |
| 2.5.4 Motion Actuation | A | Supports | No device-motion input. |

### Understandable

| Criterion | Level | Assessment | Notes |
|---|---|---|---|
| 3.1.1 Language of Page | A | Supports | `<html lang>` is set and updated when the language is switched. |
| 3.1.2 Language of Parts | AA | Partially supports | The interface translates wholesale; individual untranslated strings falling back to English are not marked with their own `lang`. |
| 3.2.1 On Focus | A | Supports | Focus alone never changes context. |
| 3.2.2 On Input | A | Supports | Changing a control's value does not submit or navigate; explicit Save/Apply throughout. |
| 3.2.3 Consistent Navigation | AA | Supports | One sidebar, one topbar, same order on every page. |
| 3.2.4 Consistent Identification | AA | Supports | Actions with the same function use the same icon and label everywhere. |
| **3.3.1 Error Identification** | **A** | **Does not support** | Validation errors are auto-dismissing toasts with no `aria-invalid`, no `aria-describedby`, and no association to the offending field (limitation 1). |
| 3.3.2 Labels or Instructions | A | Supports | Every control in the static interface has an accessible name and most have hint text; the command palette input gained an `aria-label` in v6.4.2 rather than relying on its placeholder. |
| 3.3.3 Error Suggestion | AA | Partially supports | Message text usually says what to fix ("Pick at least one device"); it is not programmatically attached to the field. |
| 3.3.4 Error Prevention (Legal, Financial, Data) | AA | Supports | Destructive fan-out operations require explicit — sometimes typed — confirmation; low-risk deletes are deferred with Undo; configuration history allows rollback. |

### Robust

| Criterion | Level | Assessment | Notes |
|---|---|---|---|
| 4.1.2 Name, Role, Value | A | Partially supports | Names and roles are ratchet-enforced and `aria-sort`/`aria-current` carry state. v6.4.2 made the state attributes live rather than static: the sidebar accordion's `aria-expanded` and all 28 tabs' `aria-selected` are now written by the same function that sets the visual class, and the command palette exposes full combobox/listbox semantics. The four dialogs in limitation 3 still do not expose dialog semantics. |
| 4.1.3 Status Messages | AA | Partially supports | Toasts and ~17 per-action result regions announce through `role="status" aria-live="polite"`; table loading and empty states do not. |

*(SC 4.1.1 Parsing was removed in WCAG 2.2 and is obsolete; it is not assessed.)*

---

## Reporting an accessibility problem

Open an issue on the repository. Include the page, what you were trying to do,
your assistive technology and version, and what happened instead. Accessibility
defects are triaged like any other correctness defect, not as enhancements.

Related: [ux.md](ux.md) for how the interface behaves generally,
[keyboard-shortcuts.md](keyboard-shortcuts.md) for the shortcut set,
[compliance.md](compliance.md) for the security-control mappings this document
sits alongside.
