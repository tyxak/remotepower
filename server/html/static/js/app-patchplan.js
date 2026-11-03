// app-patchplan.js — the patch preview (7.4.9). Buildless classic script; every symbol is global like the rest of the
// client JS, and it loads on first use (the lazy map in app.js).
//
// A Linux host is asked for a dry run of the upgrade it would run, and this dialog shows what came back: the packages
// that move and from which version to which, the new ones an update needs, anything that would be removed, what apt
// keeps back or defers, a kernel flag and a reboot estimate. Nothing here decides anything: the server reads the host's
// answer (patch_plan.py), and every name and version in it is text from the host, so it goes through escHtml.

let _ppHost = null;         // {id, name} of the host the dialog is about
let _ppTimer = null;        // the poll while a request waits for the host
let _ppDeadline = 0;        // when to give up polling (ms since epoch)
let _ppToken = 0;           // bumped by every open, so a late answer for an earlier host is dropped

const _PP_FRESH_S = 600;    // a plan this young is shown as it is when the dialog opens
const _PP_POLL_MS = 3000;
const _PP_POLL_FOR_MS = 150000;

function _ppBody() { return document.getElementById('patch-plan-body'); }
// Shown or hidden with a style, not the hidden attribute: the dialog's button row has a display rule of its own.
function _ppShowActions(on) {
  const a = document.getElementById('patch-plan-actions');
  if (a) a.style.display = on ? '' : 'none';
}
function _ppHideRaw() {
  const pre = document.getElementById('patch-plan-raw');
  if (pre) pre.style.display = 'none';
}

function _ppStop() {
  if (_ppTimer) { clearTimeout(_ppTimer); _ppTimer = null; }
}

function _ppOpen() {
  const m = document.getElementById('patch-plan-modal');
  return !!(m && m.classList.contains('active'));
}

function _ppAgeText(sec) {
  const s = Math.max(0, Math.round(sec));
  if (s < 90) return _fmtAgo(s, 'second');
  if (s < 5400) return _fmtAgo(Math.round(s / 60), 'minute');
  if (s < 129600) return _fmtAgo(Math.round(s / 3600), 'hour');
  return _fmtAgo(Math.round(s / 86400), 'day');
}

async function patchPlanOpen(arg, name) {
  const id = String(arg).replace(/^host:/, '');
  _ppStop();
  const token = ++_ppToken;
  _ppHost = { id, name: String(name || id) };
  const title = document.getElementById('patch-plan-host');
  if (title) title.textContent = _ppHost.name;
  _ppBody().innerHTML = _skeletonBlock();
  _ppShowActions(false);
  openModal('patch-plan-modal');
  const data = await api('GET', `/devices/${encodeURIComponent(id)}/patch-preview`);
  if (token !== _ppToken) return;
  if (!data || data.error) { _ppFail((data && data.error) || 'Could not load the preview.'); return; }
  const fresh = data.plan && data.plan.at && (Date.now() / 1000 - data.plan.at) < _PP_FRESH_S;
  if (data.pending && !data.pending.timed_out) { _ppWaiting(data); _ppPoll(token); return; }
  if (data.applies && !fresh) { await patchPlanAsk(true); return; }
  _ppRender(data);
}

async function patchPlanAsk(quiet) {
  if (!_ppHost) return;
  const token = ++_ppToken;
  _ppStop();
  const r = await api('POST', `/devices/${encodeURIComponent(_ppHost.id)}/patch-preview`, {});
  if (token !== _ppToken) return;
  if (!r || r.error || !r.ok) {
    // a viewer may read a plan but not ask for one: show what there is, with the reason
    const data = await api('GET', `/devices/${encodeURIComponent(_ppHost.id)}/patch-preview`);
    if (token !== _ppToken) return;
    if (data && data.plan) { _ppRender(data, (r && r.error) || ''); return; }
    _ppFail((r && r.error) || 'Could not ask the host.');
    return;
  }
  const data = await api('GET', `/devices/${encodeURIComponent(_ppHost.id)}/patch-preview`);
  if (token !== _ppToken) return;
  _ppWaiting(data || {});
  _ppDeadline = Date.now() + _PP_POLL_FOR_MS;
  _ppPoll(token);
}

function _ppPoll(token) {
  if (!_ppDeadline || _ppDeadline < Date.now()) _ppDeadline = Date.now() + _PP_POLL_FOR_MS;
  _ppStop();
  _ppTimer = setTimeout(async () => {
    if (token !== _ppToken || !_ppOpen() || !_ppHost) return;
    const data = await api('GET', `/devices/${encodeURIComponent(_ppHost.id)}/patch-preview`);
    if (token !== _ppToken || !_ppOpen()) return;
    if (data && !data.error && !(data.pending && !data.pending.timed_out)) { _ppRender(data); return; }
    if (Date.now() > _ppDeadline) { _ppGaveUp(); return; }
    _ppPoll(token);
  }, _PP_POLL_MS);
}

function _ppWaiting(data) {
  const p = (data && data.pending) || null;
  const who = p && p.by ? `<span>by</span> <b>${escHtml(p.by)}</b> ` : '';
  _ppBody().innerHTML = `<div class="empty-state"><div>Waiting for the host to answer…</div>
    <div class="hint">${who}</div>
    <div class="hint">The host reports every few seconds and the dry run takes a moment. This page checks for the answer by itself.</div></div>`;
  _ppShowActions(false);
}

function _ppGaveUp() {
  _ppBody().innerHTML = `<div class="empty-state"><div>The host has not answered yet.</div>
    <div class="hint">It may be offline, or busy with another command. The answer shows up here when it arrives.</div></div>`;
  _ppShowActions(true);
}

function _ppFail(msg) {
  _ppBody().innerHTML = `<div class="empty-state-error">${escHtml(msg)}</div>`;
  _ppShowActions(true);
}

function _ppChip(n, label, cls) {
  return `<div class="sysinfo-pill"><div class="label"><span>${escHtml(label)}</span></div><div class="value ${cls || ''}">${escHtml(String(n))}</div></div>`;
}

function _ppSrc(r) {
  const sec = r.security ? ' <span class="sev-pill sev-high">security</span>' : '';
  return `${escHtml(r.source || '')}${sec}`;
}

function _ppTable(titleKey, head, rows, rowFn) {
  if (!rows || !rows.length) return '';
  const th = head.map(h => `<th>${h}</th>`).join('');
  return `<div class="section-title">${titleKey} <span class="hint">${rows.length}</span></div>
    <div class="scrollable-table-wrap mb-16"><table><thead><tr>${th}</tr></thead><tbody>${rows.map(rowFn).join('')}</tbody></table></div>`;
}

function _ppRender(data, askNote) {
  const body = _ppBody();
  const plan = data && data.plan;
  _ppShowActions(true);
  if (!data || data.applies === false) {
    body.innerHTML = `<div class="empty-state">${escHtml((data && data.reason_text) || 'The preview is not available for this host.')}</div>`;
    _ppShowActions(false);
    return;
  }
  if (!plan) {
    body.innerHTML = '<div class="empty-state">No preview has been taken for this host yet.</div>'
      + (askNote ? `<div class="hint">${escHtml(askNote)}</div>` : '');
    return;
  }
  if (plan.status !== 'done') {
    body.innerHTML = `<div class="empty-state-error"><div>The preview could not be taken.</div><div class="hint">${escHtml(plan.error || '')}</div></div>`
      + _ppFoot(data, plan) + _ppRawLink(plan);
    _ppHideRaw();
    return;
  }
  const c = plan.counts || {};
  let html = '<div class="sysinfo-row mb-16">'
    + _ppChip(c.upgrade || 0, 'to upgrade')
    + _ppChip(c.install || 0, 'new packages')
    + _ppChip(c.remove || 0, 'removed', (c.remove || 0) > 0 ? 'c-red' : '')
    + _ppChip(c.security || 0, 'security updates', (c.security || 0) > 0 ? 'c-red' : '')
    + _ppChip(c.kept_back || 0, 'kept back')
    + '</div>';
  if (plan.kernel) html += '<div class="mb-16"><span class="sev-pill sev-medium">kernel update</span> <span class="hint">The new kernel runs after a reboot.</span></div>';
  else if (plan.reboot_likely) html += '<div class="mb-16"><span class="sev-pill sev-medium">reboot likely</span> <span class="hint">An update to a core library or service usually asks for a reboot.</span></div>';
  if (plan.reboot_reasons && plan.reboot_reasons.length) html += `<div class="hint mb-16"><code>${escHtml(plan.reboot_reasons.join(', '))}</code></div>`;
  if (plan.partial) html += '<div class="c-amber mb-16">The list below does not match the counts the package manager printed, so it may be incomplete.</div>';
  if (plan.truncated) html += `<div class="c-amber mb-16">The host's answer was cut off, so the list is the first part of the plan.</div>`;
  const nothing = !(plan.upgrades || []).length && !(plan.installs || []).length && !(plan.removals || []).length;
  if (nothing && !plan.partial) html += '<div class="empty-state">Nothing to upgrade.</div>';
  html += _ppTable('<span>Upgrades</span>', ['<span>Package</span>', '<span>From</span>', '<span>To</span>', '<span>Source</span>'], plan.upgrades,
    r => `<tr><td class="mono-12">${escHtml(r.name)}</td><td class="mono-12 hint">${escHtml(r.from || '—')}</td><td class="mono-12">${escHtml(r.to || '')}</td><td>${_ppSrc(r)}</td></tr>`);
  html += _ppTable('<span>New packages</span>', ['<span>Package</span>', '<span>Version</span>', '<span>Source</span>'], plan.installs,
    r => `<tr><td class="mono-12">${escHtml(r.name)}</td><td class="mono-12">${escHtml(r.to || '')}</td><td>${_ppSrc(r)}</td></tr>`);
  html += _ppTable('<span>Removed</span>', ['<span>Package</span>', '<span>Version</span>'], plan.removals,
    r => `<tr><td class="mono-12 c-red">${escHtml(r.name)}</td><td class="mono-12 hint">${escHtml(r.from || '')}</td></tr>`);
  const held = (plan.kept_back || []).filter(r => r.held).map(r => r.name);
  const needs = (plan.kept_back || []).filter(r => !r.held).map(r => r.name);
  if (needs.length) {
    html += `<div class="section-title"><span>Kept back</span> <span class="hint">${needs.length}</span></div>
      <div class="mb-16"><code>${escHtml(needs.join(', '))}</code>
      <div class="hint">${plan.mode === 'extended' ? 'The upgrade could not install these.' : 'They need a package that is not installed yet. The Extended upgrade mode installs it.'}</div></div>`;
  }
  if (held.length) {
    html += `<div class="section-title"><span>On hold</span> <span class="hint">${held.length}</span></div>
      <div class="mb-16"><code>${escHtml(held.join(', '))}</code><div class="hint">Held on purpose, so the upgrade leaves them.</div></div>`;
  }
  if ((plan.deferred || []).length) {
    html += `<div class="section-title"><span>Deferred</span> <span class="hint">${plan.deferred.length}</span></div>
      <div class="mb-16"><code>${escHtml(plan.deferred.join(', '))}</code><div class="hint">The distribution is rolling these out in stages. They arrive on their own.</div></div>`;
  }
  if ((plan.autoremove || []).length) {
    html += `<div class="section-title"><span>Cleaned up afterwards</span> <span class="hint">${plan.autoremove.length}</span></div>
      <div class="mb-16"><code>${escHtml(plan.autoremove.join(', '))}</code><div class="hint">No longer needed once the upgrade is done. The run removes them.</div></div>`;
  }
  if (askNote) html += `<div class="hint mb-16">${escHtml(askNote)}</div>`;
  body.innerHTML = html + _ppFoot(data, plan) + _ppRawLink(plan);
  _ppHideRaw();
}

function _ppFoot(data, plan) {
  const bits = [];
  if (plan.at) bits.push(`<span>Taken</span> ${timeAgoHtml(plan.at)}`);
  if (plan.by) bits.push(`<span>by</span> <b>${escHtml(plan.by)}</b>`);
  if (plan.mode) bits.push(`<span>Upgrade mode</span> <b>${escHtml(plan.mode)}</b>`);
  if (plan.lists_age_s != null && plan.manager !== 'dnf') bits.push(`<span>Package lists refreshed</span> <b>${escHtml(_ppAgeText(plan.lists_age_s))}</b>`);
  return `<div class="hint mb-16">${bits.join(' · ')}</div>
    <div class="hint mb-16">The upgrade refreshes the package lists first, so the real list can be longer. Nothing was changed on the host.</div>`;
}

function _ppRawLink(plan) {
  return plan.manager ? `<div class="mb-16"><button class="btn-secondary" data-action="patchPlanRaw">Show the host's output</button><pre id="patch-plan-raw" class="journal-wrap"></pre></div>` : '';
}

async function patchPlanRaw() {
  const pre = document.getElementById('patch-plan-raw');
  if (!pre || !_ppHost) return;
  if (pre.style.display !== 'none') { pre.style.display = 'none'; return; }
  const data = await api('GET', `/devices/${encodeURIComponent(_ppHost.id)}/patch-preview?raw=1`);
  pre.textContent = (data && data.plan && data.plan.raw) || '(nothing kept)';
  pre.style.display = '';
}

// From a button that carries the host in data attributes (the Patch Report dialog and a parked upgrade on Approvals):
// the id and name are read raw from the element, so a host named like a number is not turned into one.
function _patchPlanBtn(btn) {
  return patchPlanOpen('host:' + btn.dataset.devId, btn.dataset.devName || '');
}

function patchPlanClose() {
  _ppStop();
  _ppToken++;
  closeModal('patch-plan-modal');
}
