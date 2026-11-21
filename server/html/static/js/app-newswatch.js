// app-newswatch.js — the Security news tab of the CVE page (8.0.2): feeds of security news that raise an alert, and start a scan, when an item reports a critical flaw. Buildless
// classic script; every symbol is global like the rest of the client JS, and it is fetched the first time the tab shows (the hook list in app.js).
//
//   newsWatchEnter()   the tab was opened (app.js calls it whenever the tab shows): draw the card, at most every few seconds
//   newsWatchLoad()    fetch the settings, the state of each feed and the critical items, and draw them, form included (the Refresh button)
//   newsWatchSave()    send the settings as they stand (the platform operator's)
//   newsWatchRun()     read the feeds now (the platform operator's)
//   newsWatchClear()   clear the red ! of one item, or of every item that shows one (the platform operator's)
//   newsWatchRestore() bring the red ! back for one cleared item, or for every cleared one (the platform operator's)
//
// A headline, a link, a feed's name and the name of a program all came from outside, so they are only ever put in the page with escHtml, and a link only through _safeHttpHref.
// The form is filled from the server when the tab is first drawn, after a save and when Refresh is pressed, and never by a redraw that follows a visit: what an operator is
// typing is not written over.

let _nwSeq = 0;               // the newest load: an older answer that lands after it is dropped
let _nwAt = 0;                // when the tab was last drawn (ms), so showPage and the tab hook do not each fetch
let _nwFormLoaded = false;    // the form has been filled from the server once

// the server sends a code, the page holds the sentence, so it is translated like any other text (see _CVE_COVERAGE in app-cve.js)
const _NW_REASON = {
  critical: 'Called critical',
  cvss: 'CVSS score of 9 or more',
  zero_day: 'Zero-day',
  exploited: 'Exploited in attacks',
  unauth_exec: 'Code execution without signing in',
  kev: 'CVE that CISA lists as exploited',
  word: 'Matches a word you added',
};
const _NW_OUTCOME = {
  baseline: 'Seen when the feed was first read, so no alert',
  stale: 'More than three days old, so no alert',
  listed: 'Listed only',
  alerted: 'Alert raised',
  scanned: 'Alert raised and a scan of all hosts started',
  scan_waiting: 'Alert raised, no scan: one was started less than six hours ago',
  scan_refused: 'Alert raised, no scan: one is already running',
  over_limit: 'Listed only: five alerts is the most for one reading',
};

function _nwNote(text) {
  const el = document.getElementById('news-watch-note');
  if (el) el.textContent = text || '';
}

function _nwFeedHtml(f) {
  const name = f.title || f.url;
  const read = f.last_ok ? `<span class="hint">Last read</span> ${timeAgoHtml(f.last_ok)}` : `<span class="hint">Not read yet</span>`;
  const counts = f.last_ok ? ` · <span class="hint">New items</span> <span class="fw-500">${escHtml(String(f.last_new || 0))}</span> · <span class="hint">Critical</span> <span class="fw-500">${escHtml(String(f.last_critical || 0))}</span>` : '';
  const bad = f.last_error ? ` · <span class="c-red">Failed:</span> <span data-no-i18n>${escHtml(f.last_error)}</span>${f.fail_streak > 1 ? ` <span class="hint">(${escHtml(String(f.fail_streak))}×)</span>` : ''}` : '';
  return `<div class="mb-8"><span class="fw-500" data-no-i18n>${escHtml(name)}</span> <span class="hint mono-12" data-no-i18n>${escHtml(f.url)}</span><div>${read}${counts}${bad}</div></div>`;
}

// what runs on a host, from the server, which read the hosts as they are now: [{name, hosts, world}]
function _nwRunning(i) {
  return Array.isArray(i.running) ? i.running.filter(r => r && typeof r.name === 'string') : [];
}

// an item shows the red ! while it names software that runs on a host and nobody has cleared it (the server sends cleared_at, a number, for a cleared one)
function _nwCleared(i) {
  return typeof i.cleared_at === 'number';
}

function _nwBang(i) {
  return _nwRunning(i).length > 0 && !_nwCleared(i);
}

function _nwRunningHtml(runs) {
  return `<span class="hint">Running on your hosts:</span> ` + runs.map(r => {
    const n = Number.isFinite(r.hosts) ? r.hosts : 0;
    return `<span class="mono-12" data-no-i18n>${escHtml(r.name)}</span> <span class="hint">Hosts</span> <span class="fw-500">${escHtml(String(n))}</span>`
      + (r.world ? ' <span class="status-pill critical">reachable from the Internet</span>' : '');
  }).join(' · ');
}

function _nwItemHtml(i) {
  const href = _safeHttpHref(i.link);
  const title = escHtml(i.title || i.link || '');
  const runs = _nwRunning(i);
  const flagged = _nwBang(i);
  const bang = flagged ? '<span class="c-red fw-600" aria-hidden="true">!</span> ' : '';
  // the id goes through data-arg with a prefix: the data-action dispatcher turns an argument that looks like a number into one, and 16 hex digits can look like one
  const clear = flagged ? ` <button type="button" class="btn-icon" data-action="newsWatchClear" data-arg="nw-${escAttr(String(i.id || ''))}">Clear !</button>` : '';
  const cleared = runs.length > 0 && _nwCleared(i);
  const done = cleared ? `<span class="hint">! cleared</span> ${timeAgoHtml(i.cleared_at)}` : '';
  // a clear can be undone, on the item that shows it: same prefixed id as the button that clears
  const back = cleared ? ` <button type="button" class="btn-icon" data-action="newsWatchRestore" data-arg="nw-${escAttr(String(i.id || ''))}">Bring back !</button>` : '';
  const head = bang + (href
    ? `<a href="${href}" target="_blank" rel="noopener noreferrer" class="fw-500" data-no-i18n>${title}</a>`
    : `<span class="fw-500" data-no-i18n>${title}</span>`);
  const reasons = (i.reasons || []).filter(r => Object.prototype.hasOwnProperty.call(_NW_REASON, r))
    .map(r => `<span class="status-pill warn">${escHtml(_NW_REASON[r])}</span>`).join(' ');
  const outcome = Object.prototype.hasOwnProperty.call(_NW_OUTCOME, i.outcome) ? `<span class="status-pill info">${escHtml(_NW_OUTCOME[i.outcome])}</span>` : '';
  const ran = runs.length ? _nwRunningHtml(runs) : '';
  const soft = (i.software || []).length
    ? `<span class="hint">Names software on your hosts:</span> <span class="mono-12" data-no-i18n>${escHtml(i.software.join(', '))}</span>`
    : '';
  const cves = (i.cves || []).length ? `<span class="mono-12" data-no-i18n>${escHtml(i.cves.slice(0, 3).join(', '))}</span>` : '';
  const when = i.published || i.seen_at;
  const meta = [ran, soft, cves, i.feed ? `<span class="hint" data-no-i18n>${escHtml(i.feed)}</span>` : '', when ? timeAgoHtml(when) : '', done].filter(Boolean).join(' · ');
  return `<div class="mb-8"><div>${head}</div><div class="mt-6">${reasons} ${outcome}${clear}${back}</div><div class="hint mt-6">${meta}</div></div>`;
}

function _nwFillForm(d) {
  const set = (id, fn) => { const el = document.getElementById(id); if (el) fn(el); };
  set('nw-enabled', el => { el.defaultChecked = !!d.enabled; el.checked = !!d.enabled; });
  set('nw-feeds', el => { const v = (d.feeds || []).join('\n'); el.defaultValue = v; el.value = v; });
  set('nw-scope', el => { el.value = d.scope; });
  set('nw-words', el => { const v = (d.words || []).join('\n'); el.defaultValue = v; el.value = v; });
  set('nw-critical-words', el => { const v = (d.critical_words || []).join('\n'); el.defaultValue = v; el.value = v; });
  set('nw-action', el => { el.value = d.action; });
  _nwFormLoaded = true;
}

// The tab has shown what the mark counts: this browser remembers the newest of it, and the "!" on the sidebar and on the tab goes until a newer item comes (app.js _paintNewsMark).
function _nwSeen(at) {
  if (typeof at !== 'number') return;
  try { if (at > (Number(localStorage.getItem('rp_news_seen')) || 0)) localStorage.setItem('rp_news_seen', String(at)); } catch (_) { /* private window */ }
  if (typeof _paintNewsMark === 'function') _paintNewsMark();
}

function _nwPaint(d, force) {
  const form = document.getElementById('news-watch-form');
  const run = document.getElementById('news-watch-run');
  const feeds = document.getElementById('news-watch-feeds');
  const items = document.getElementById('news-watch-items');
  if (!d.editable) {
    // not the platform operator: the software an item names comes from every host of the installation, so there is nothing here to read or change
    if (form) form.hidden = true;
    if (run) run.hidden = true;
    if (feeds) feeds.innerHTML = '';
    if (items) items.innerHTML = '';
    const gone = document.getElementById('news-watch-running');
    if (gone) { gone.hidden = true; gone.innerHTML = ''; }
    _nwNote('The platform operator manages the security news watch.');
    return;
  }
  if (form) form.hidden = false;
  if (run) run.hidden = !d.enabled || !(d.feeds || []).length;
  if (force || !_nwFormLoaded) _nwFillForm(d);
  if (!d.enabled) _nwNote('The watch is off. Switch it on below and save.');
  else if (!d.last_run) _nwNote('No feed has been read yet. The first read runs within a few minutes and only records what the feeds hold.');
  else _nwNote('');
  if (feeds) feeds.innerHTML = (d.status || []).map(_nwFeedHtml).join('');
  const bangs = (d.items || []).filter(_nwBang).length;
  const cleared = (d.items || []).filter(i => _nwCleared(i) && _nwRunning(i).length > 0).length;
  const sum = document.getElementById('news-watch-running');
  if (sum) {
    sum.hidden = !bangs && !cleared;
    sum.innerHTML = (bangs
      ? `<span class="c-red fw-600" aria-hidden="true">!</span> <span class="hint">Items about software running on your hosts:</span> <strong>${escHtml(String(bangs))}</strong>`
        + ` <button type="button" class="btn-icon" data-action="newsWatchClear" data-arg="all">Clear all !</button>`
      : '')
      + (bangs && cleared ? ' · ' : '')
      + (cleared
        ? `<span class="hint">! cleared</span> <strong>${escHtml(String(cleared))}</strong>`
          + ` <button type="button" class="btn-icon" data-action="newsWatchRestore" data-arg="all">Bring back all !</button>`
        : '');
  }
  if (items) items.innerHTML = (d.items || []).length ? d.items.map(_nwItemHtml).join('') : '<div class="c-muted">No critical items yet.</div>';
  _nwSeen(d.attention_at);
}

async function _nwLoad(force) {
  const wrap = document.getElementById('news-watch-wrap');
  if (!wrap) return;
  const seq = ++_nwSeq;
  const d = await api('GET', '/news-watch').catch(() => null);
  if (seq !== _nwSeq) return;
  if (!d || d.error) { _nwNote('The security news watch could not be loaded.'); return; }
  _nwPaint(d, force === true);
}

function newsWatchLoad() { return _nwLoad(true); }

function newsWatchEnter() {
  if (!document.getElementById('news-watch-wrap')) return;
  if (Date.now() - _nwAt < 4000) return;      // showPage and the tab hook both pass through here
  _nwAt = Date.now();
  _nwLoad(false);
}

async function newsWatchSave() {
  const body = {
    enabled: !!document.getElementById('nw-enabled').checked,
    feeds: document.getElementById('nw-feeds').value,
    scope: document.getElementById('nw-scope').value,
    action: document.getElementById('nw-action').value,
    words: document.getElementById('nw-words').value,
    critical_words: document.getElementById('nw-critical-words').value,
  };
  const r = await api('POST', '/news-watch/config', body);
  if (!r || r.error) { failToast(r); return; }
  toast('Saved', 'success');
  ++_nwSeq;
  _nwPaint(r, true);
}

// Clear the ! of one item ('nw-<id>') or of every item that shows one ('all'). Anything else is not sent: the argument comes from a data-arg attribute, and the server's answer is the
// page, drawn as it is. An id is letters, digits, '_' and '-' up to 32 characters, which is whatever the server sends for an item (the watch makes 16 hex digits, the demo seed 16
// letters and digits): a tighter rule would leave a listed item with a button that does nothing. The sidebar's poll is asked again so the mark there agrees at once.
async function newsWatchClear(arg) {
  if (arg !== 'all' && !(typeof arg === 'string' && /^nw-[A-Za-z0-9_-]{1,32}$/.test(arg))) return;
  await _nwSend(arg === 'all' ? { all: true } : { ids: [arg.slice(3)] });
}

// Bring the ! back for one cleared item ('nw-<id>') or for every cleared item ('all'): the same route, the same argument rule, and `undo: true`.
async function newsWatchRestore(arg) {
  if (arg !== 'all' && !(typeof arg === 'string' && /^nw-[A-Za-z0-9_-]{1,32}$/.test(arg))) return;
  await _nwSend(arg === 'all' ? { all: true, undo: true } : { ids: [arg.slice(3)], undo: true });
}

async function _nwSend(body) {
  const r = await api('POST', '/news-watch/clear', body);
  if (!r || r.error) { failToast(r); return; }
  ++_nwSeq;
  _nwPaint(r, false);
  try { if (typeof refreshNavCounts === 'function') refreshNavCounts(); } catch (_) { /* the next poll will do it */ }
}

async function newsWatchRun() {
  const btn = document.getElementById('news-watch-run');
  if (btn) btn.disabled = true;
  try {
    const r = await api('POST', '/news-watch/run', {});
    if (!r || r.error) { failToast(r); return; }
    const res = r.result || {};
    toast(`Read ${plural(res.feeds || 0, 'feed', 'feeds')}: ${plural(res.new_critical || 0, 'new critical item', 'new critical items')}, ${plural(res.alerts || 0, 'alert', 'alerts')} raised`, res.failed ? 'warning' : 'success');
    ++_nwSeq;
    _nwPaint(r, false);
  } finally {
    if (btn) btn.disabled = false;
  }
}
