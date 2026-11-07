// app-wizard.js — guided wizards and the step-by-step mode of long forms (8.0.0). Buildless classic script; every symbol is global like the
// rest of the client JS, and it is fetched on first use (the lazy map in app.js). Both parts are options beside the dialogs that already
// exist: nothing here replaces a form.
//
//   wizStart(name)    a wizard in a dialog of its own. 'enroll' adds a host: what kind, the group and tags it gets, the install command, and
//                     a wait that says when the host has checked in. 'notify' adds a notification destination: the service, what it needs,
//                     a test whose answer is shown on the spot, and what it should receive.
//   _wizFormSync(id)  puts one of the long forms (new maintenance window, monitor, backup job, auto-patch policy) into steps, or back into
//                     the single form. The form stays the one in index.html, with its own fields and its own button that saves: this
//                     shows its blocks one step at a time and ends in a list of the choices.
//
// Text a person typed is only ever set as a property or as textContent, never put into markup.

function _wizNode(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = text;
  return n;
}

// ── the runner ──────────────────────────────────────────────────────────────────────────────────────────────────────────────
let _wiz = null;            // the wizard that is open: {def, i, st, busy, finished, timers}

function wizStart(name, arg) {
  const make = _WIZARDS[name];
  if (!make || document.getElementById('wizard-modal')) return;
  const def = make();
  _wiz = { def, i: 0, st: def.init(arg), busy: false, finished: false, timers: [] };
  const o = _wizNode('div', 'modal-overlay');
  o.id = 'wizard-modal';
  o.setAttribute('role', 'dialog');
  o.setAttribute('aria-modal', 'true');
  o.setAttribute('aria-labelledby', 'wiz-title');
  o.setAttribute('data-dispose', '');
  const panel = _wizNode('div', 'modal modal-wide');
  const title = _wizNode('div', 'modal-title', def.title);
  title.id = 'wiz-title';
  const steps = _wizNode('ol', 'wiz-steps');
  steps.id = 'wiz-steps';
  steps.setAttribute('aria-label', 'Steps');
  const body = _wizNode('div', 'wiz-body');
  body.id = 'wiz-body';
  const msg = _wizNode('div', 'wiz-msg');
  msg.id = 'wiz-msg';
  msg.setAttribute('role', 'alert');
  const live = _wizNode('div', 'visually-hidden');
  live.id = 'wiz-live';
  live.setAttribute('role', 'status');
  const acts = _wizNode('div', 'modal-actions');
  const cancel = _wizNode('button', 'btn-secondary', 'Cancel');
  cancel.id = 'wiz-cancel';
  const back = _wizNode('button', 'btn-secondary', 'Back');
  back.id = 'wiz-back';
  const next = _wizNode('button', 'btn-primary', 'Next');
  next.id = 'wiz-next';
  [[cancel, 'wizCancel'], [back, 'wizBack'], [next, 'wizNext']].forEach(([b, action]) => { b.type = 'button'; b.setAttribute('data-action', action); acts.appendChild(b); });
  panel.append(title, steps, body, msg, live, acts);
  o.appendChild(panel);
  o.addEventListener('keydown', _wizKey);
  document.body.appendChild(o);
  openModal('wizard-modal');
  _wizShow(0);
}

// Enter in a text box goes on, like the button does (a checkbox, a radio button and a button keep their own Enter).
function _wizKey(e) {
  if (e.key !== 'Enter' || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;
  const t = e.target;
  if (!t || t.tagName !== 'INPUT' || ['checkbox', 'radio', 'button', 'submit'].includes(t.type)) return;
  e.preventDefault();
  wizNext();
}

// The steps that apply to what has been chosen so far (a step may say it is not needed), as {s, n}: the step and its place in the list.
function _wizSteps() {
  const w = _wiz;
  return w.def.steps.map((s, n) => ({ s, n })).filter(x => !(x.s.skip && x.s.skip(w.st)));
}

function _wizMsg(text, focusId) {
  const m = document.getElementById('wiz-msg');
  if (!m) return;
  m.textContent = text || '';
  document.querySelectorAll('#wiz-body [aria-invalid]').forEach(n => n.removeAttribute('aria-invalid'));
  if (text && focusId) {
    const f = document.getElementById(focusId);
    if (f) { f.setAttribute('aria-invalid', 'true'); f.focus(); }
  }
}

function _wizBusy(on) {
  const w = _wiz;
  if (!w) return;
  w.busy = on;
  ['wiz-next', 'wiz-back', 'wiz-cancel'].forEach(id => {
    const b = document.getElementById(id);
    if (b) b.disabled = on;
  });
  const p = document.getElementById('wizard-modal');
  if (p) { if (on) p.setAttribute('aria-busy', 'true'); else p.removeAttribute('aria-busy'); }
}

function _wizShow(i) {
  const w = _wiz;
  if (!w) return;
  w.i = i;
  const vis = _wizSteps();
  const step = w.def.steps[i];
  _wizStepper(document.getElementById('wiz-steps'), vis.map(x => ({ label: x.s.label, n: x.n })), i, !w.finished);
  const body = document.getElementById('wiz-body');
  body.textContent = '';
  step.render(w.st, body);
  _wizMsg('');
  const first = vis[0].n === i, last = vis[vis.length - 1].n === i;
  document.getElementById('wiz-back').classList.toggle('wiz-off', first || !!step.noBack);
  document.getElementById('wiz-cancel').classList.toggle('wiz-off', last && !!step.closeOnly);
  const next = document.getElementById('wiz-next');
  next.textContent = typeof step.primary === 'function' ? step.primary(w.st) : (step.primary || (last ? 'Close' : 'Next'));
  document.getElementById('wiz-live').textContent = step.label;
  requestAnimationFrame(() => _wizFocus(body));
}

// The numbered list at the top. items: [{label, n}] in order; `at` is the number of the step that is showing. A step that is done
// is a button that goes back to it (`jump`), so a choice can be changed without stepping back through the others.
function _wizStepper(ol, items, at, canJump, jump) {
  ol.textContent = '';
  items.forEach((it, pos) => {
    const li = _wizNode('li', 'wiz-step' + (it.n === at ? ' active' : it.n < at ? ' done' : ''));
    if (it.n === at) li.setAttribute('aria-current', 'step');
    const holder = (it.n < at && canJump) ? _wizNode('button', 'wiz-jump') : _wizNode('span', 'wiz-jump-off');
    if (holder.tagName === 'BUTTON') {
      holder.type = 'button';
      holder.setAttribute('data-action', jump || 'wizGoto');
      holder.setAttribute('data-arg', String(it.n));
    }
    const num = _wizNode('span', 'wiz-num', String(pos + 1));
    num.setAttribute('aria-hidden', 'true');
    holder.append(num, _wizNode('span', 'wiz-lbl', it.label));
    li.appendChild(holder);
    ol.appendChild(li);
  });
}

// Focus goes to the first thing to answer on the step: the chosen radio button of a group, else the first box, else the first button.
function _wizFocus(body) {
  const f = body.querySelector('input[type=radio]:checked')
    || body.querySelector('input:not([type=hidden]):not([type=radio]):not([disabled]), select:not([disabled]), textarea:not([disabled])')
    || body.querySelector('input[type=radio]')
    || body.querySelector('button:not([disabled])')
    || document.getElementById('wiz-next');
  if (f && typeof f.focus === 'function') { try { f.focus(); } catch (_) { /* gone */ } }
}

function wizCancel() { closeModal('wizard-modal'); }

function wizBack() {
  const w = _wiz;
  if (!w || w.busy) return;
  const before = _wizSteps().map(x => x.n).filter(n => n < w.i);
  if (before.length) _wizShow(before[before.length - 1]);
}

function wizGoto(n) {
  const w = _wiz;
  if (!w || w.busy || w.finished) return;
  const to = Number(n);
  if (to < w.i && _wizSteps().some(x => x.n === to)) _wizShow(to);
}

async function wizNext() {
  const w = _wiz;
  if (!w || w.busy) return;
  const step = w.def.steps[w.i];
  _wizMsg('');
  const bad = step.validate ? step.validate(w.st) : null;
  if (bad) { _wizMsg(bad.msg, bad.focus); return; }
  if (step.next) {
    _wizBusy(true);
    let ok = false;
    try { ok = await step.next(w.st, w); } catch (_) { ok = false; _wizMsg('Something went wrong. Try again.'); }
    if (_wiz !== w) return;                     // closed while it waited
    _wizBusy(false);
    if (ok === false) return;
  }
  const after = _wizSteps().map(x => x.n).filter(n => n > w.i);
  if (!after.length) { w.finished = true; closeModal('wizard-modal'); return; }
  _wizShow(after[0]);
}

// closeModal calls this when the wizard's dialog goes (Escape, the corner button, Cancel, or the last step): the waits stop, and the
// wizard says what to do with what it made.
function _wizOnClose() {
  const w = _wiz;
  _wiz = null;
  if (!w) return;
  w.timers.forEach(t => { clearInterval(t); clearTimeout(t); });
  if (w.def.onClose) w.def.onClose(w.st, w.finished);
  // the Getting started checklist, if it is on screen, shows what the wizard did (a host that joined, a destination that delivered)
  if (document.getElementById('setup-steps') && typeof loadSetup === 'function') loadSetup();
}

// ── building blocks ─────────────────────────────────────────────────────────────────────────────────────────────────────────

// A group of radio buttons drawn as cards. o: {legend, name, value, items:[{v, t, d} or {g}], onPick}; {g} starts a titled group.
function _wizChoices(host, o) {
  const fs = _wizNode('fieldset', 'wiz-set');
  fs.appendChild(_wizNode('legend', 'wiz-q', o.legend));
  let grid = null;
  o.items.forEach(it => {
    if (it.g) { fs.appendChild(_wizNode('div', 'wiz-grp', it.g)); grid = null; return; }
    if (!grid) { grid = _wizNode('div', 'wiz-choices'); fs.appendChild(grid); }
    const lab = _wizNode('label', 'wiz-choice' + (it.v === o.value ? ' on' : ''));
    const inp = document.createElement('input');
    inp.type = 'radio';
    inp.name = o.name;
    inp.value = it.v;
    inp.checked = it.v === o.value;
    const txt = _wizNode('span', 'wiz-choice-txt');
    txt.appendChild(_wizNode('span', 'wiz-choice-t', it.t));
    if (it.d) txt.appendChild(_wizNode('span', 'wiz-choice-d', it.d));
    lab.append(inp, txt);
    inp.addEventListener('change', () => {
      fs.querySelectorAll('.wiz-choice').forEach(l => l.classList.toggle('on', l === lab));
      o.onPick(it.v);
    });
    grid.appendChild(lab);
  });
  host.appendChild(fs);
}

// A label and a box. o: {id, label, value, type, placeholder, hint, options:[[v, text]], rows, list, maxlength, onInput}.
function _wizField(host, o) {
  const g = _wizNode('div', 'form-group');
  const lab = _wizNode('label', 'form-label', o.label);
  lab.htmlFor = o.id;
  g.appendChild(lab);
  let c;
  if (o.options) {
    c = document.createElement('select');
    o.options.forEach(([v, t]) => { const op = _wizNode('option', '', t); op.value = v; c.appendChild(op); });
    c.value = o.value;
  } else if (o.rows) {
    c = document.createElement('textarea');
    c.rows = o.rows;
    c.value = o.value || '';
  } else {
    c = document.createElement('input');
    c.type = o.type || 'text';
    c.value = o.value || '';
  }
  c.id = o.id;
  c.className = 'form-input';
  if (o.placeholder) c.placeholder = o.placeholder;
  if (o.maxlength) c.maxLength = o.maxlength;
  if (o.list) c.setAttribute('list', o.list);
  c.autocomplete = 'off';
  c.addEventListener(c.tagName === 'SELECT' ? 'change' : 'input', () => o.onInput(c.value));
  g.appendChild(c);
  if (o.hint) g.appendChild(_wizNode('div', 'meta-sm', o.hint));
  host.appendChild(g);
  return c;
}

// A list of label and value pairs.
function _wizList(host, rows) {
  const dl = _wizNode('dl', 'wiz-list');
  rows.forEach(([k, v]) => {
    dl.appendChild(_wizNode('dt', '', k));
    const dd = _wizNode('dd', '', v);
    dl.appendChild(dd);
  });
  host.appendChild(dl);
  return dl;
}

// ── "Add a host" ────────────────────────────────────────────────────────────────────────────────────────────────────────────
const _WIZ_ENROLL_TTL = [['3600', '1 hour'], ['86400', '24 hours'], ['604800', '7 days']];
const _WIZ_PIN_LIFE_S = 600;            // how long a PIN lives (the server's PIN_TTL; the classic dialog counts the same ten minutes)
const _WIZ_WATCH_MS = 3000;
const _WIZ_WATCH_LIMIT_S = 300;         // after five minutes the wait says something is wrong

function _wizEnrollDef() {
  return {
    title: 'Add a host',
    init: () => ({ kind: 'linux', group: '', tags: '', cidrs: '', ttl: '86400', sig: '', token: '', ca: '', pin: '', pinAt: 0, pinSince: 0, tokenSince: 0, since: 0,
                   arrived: null, arrivedCount: 0, watching: false, watchFrom: 0, late: false, groups: null }),
    steps: [
      { label: 'Type', render: _wizEnrollType, next: _wizEnrollTypeNext },
      { label: 'Settings', skip: st => st.kind === 'pin', render: _wizEnrollSettings, next: _wizEnrollMint },
      { label: 'Install', render: _wizEnrollInstall, primary: 'Continue' },
      { label: 'Done', render: _wizEnrollDone, closeOnly: true, noBack: true },
    ],
  };
}

function _wizEnrollType(st, body) {
  _wizChoices(body, {
    legend: 'What kind of host is it?', name: 'wiz-kind', value: st.kind, onPick: v => { st.kind = v; },
    items: [
      { v: 'linux', t: 'Linux or macOS', d: 'One command, run as root.' },
      { v: 'windows', t: 'Windows', d: 'One command in an elevated PowerShell.' },
      { v: 'docker', t: 'Docker host', d: 'Runs the agent as a container. Nothing to install.' },
      { v: 'pin', t: 'Interactive install (PIN)', d: 'The installer asks for a six-digit PIN. You get it on the next screens.' },
      { v: 'other', t: 'Cannot run the agent', d: 'A switch, printer, camera or UPS. Added by address and checked without an agent.' },
    ],
  });
}

async function _wizEnrollTypeNext(st, w) {
  if (st.kind === 'other') {                    // a device with no agent has a form of its own
    w.finished = true;
    closeModal('wizard-modal');
    if (typeof agentlessAddOpen === 'function') agentlessAddOpen();
    return false;
  }
  if (st.kind !== 'pin') return true;
  if (st.pin && st.pinSince && Date.now() - st.pinAt < (_WIZ_PIN_LIFE_S - 60) * 1000) {   // came back to the step: the PIN on screen is still good
    st.since = st.pinSince;
    return true;
  }
  const r = await api('POST', '/enroll/pin');
  if (!r || r.error || !r.pin) { _wizMsg((r && r.error) || 'Could not create a PIN. Try again.'); return false; }
  st.pin = r.pin;
  st.pinAt = Date.now();
  st.pinSince = r.expires ? Number(r.expires) - _WIZ_PIN_LIFE_S : Math.floor(Date.now() / 1000) - 5;   // never zero: that would count every host
  st.since = st.pinSince;
  st.arrived = null; st.arrivedCount = 0; st.late = false;
  return true;
}

function _wizEnrollSettings(st, body) {
  body.appendChild(_wizNode('div', 'wiz-q', 'What should the host get when it joins?'));
  const dl = document.createElement('datalist');
  dl.id = 'wiz-groups';
  body.appendChild(dl);
  const fill = rows => {
    const names = [...new Set((rows || []).map(d => String(d.group || '').trim()).filter(Boolean))].sort();
    names.forEach(n => { const o = document.createElement('option'); o.value = n; dl.appendChild(o); });
  };
  if (st.groups) fill(st.groups);
  else api('GET', '/devices?slim=1').then(r => { st.groups = Array.isArray(r) ? r : (r && r.devices) || []; if (document.getElementById('wiz-groups')) fill(st.groups); }).catch(() => {});
  _wizField(body, { id: 'wiz-group', label: 'Group (optional)', value: st.group, list: 'wiz-groups', maxlength: 64, onInput: v => { st.group = v; } });
  _wizField(body, { id: 'wiz-tags', label: 'Tags (optional)', value: st.tags, placeholder: 'prod, web',
                    hint: 'Comma-separated. The group and tags are applied when the host enrolls. You can change them later.',
                    onInput: v => { st.tags = v; } });
  _wizField(body, { id: 'wiz-cidrs', label: 'Only from these networks (optional)', value: st.cidrs, placeholder: '10.0.0.0/24',
                    hint: 'Addresses or networks the install may connect from, such as 10.0.0.0/24. Leave empty to allow any address.',
                    onInput: v => { st.cidrs = v; } });
  _wizField(body, { id: 'wiz-ttl', label: 'Valid for', value: st.ttl, options: _WIZ_ENROLL_TTL, onInput: v => { st.ttl = v; } });
}

// Makes the one-time token with what the person chose. The same settings give the same token: going back and forward does not make another.
async function _wizEnrollMint(st) {
  const tags = st.tags.split(',').map(s => s.trim()).filter(Boolean);
  const sig = JSON.stringify([st.kind, st.group.trim(), tags, st.cidrs.trim(), st.ttl]);
  if (st.token && st.sig === sig) { st.since = st.tokenSince; return true; }
  const body = { label: 'guided-add-host', expires_in: Number(st.ttl) };
  if (st.group.trim()) body.default_group = st.group.trim();
  if (tags.length) body.default_tags = tags;
  if (st.cidrs.trim()) body.allowed_cidrs = st.cidrs.trim();
  const r = await api('POST', '/enrollment-tokens', body);
  if (!r || r.error || !r.token) { _wizMsg((r && r.error) || 'Could not create the install command. Try again.', r && r.error ? 'wiz-cidrs' : ''); return false; }
  st.tokenSince = r.created ? Number(r.created) : Math.floor(Date.now() / 1000) - 5;
  Object.assign(st, { token: r.token, ca: r.ca_fingerprint || '', since: st.tokenSince, sig, arrived: null, arrivedCount: 0, late: false });
  return true;
}

// One command with its label, a hint and a Copy button. The text is kept on the element so a test (and Copy) read it back unchanged.
function _wizCommand(host, id, label, hint, text) {
  const wrap = _wizNode('div', 'mb-12');
  wrap.appendChild(_wizNode('div', 'form-label', label));
  if (hint) wrap.appendChild(_wizNode('div', 'hint mb-6', hint));
  const pre = _wizNode('pre', 'ff-mono fs-12 enroll-docker-pre', text);
  pre.id = id;
  pre.dataset.rawText = text;
  wrap.appendChild(pre);
  const b = _wizNode('button', 'btn-secondary mt-6', 'Copy');
  b.type = 'button';
  b.setAttribute('data-action', 'wizCopy');
  b.setAttribute('data-arg', id);
  wrap.appendChild(b);
  host.appendChild(wrap);
}

function wizCopy(id) {
  const pre = document.getElementById(id);
  if (!pre || !navigator.clipboard || !navigator.clipboard.writeText) return;
  navigator.clipboard.writeText(pre.dataset.rawText || pre.textContent || '').then(() => toast('Copied', 'success')).catch(() => {});
}

function _wizEnrollInstall(st, body) {
  const server = window.location.origin;
  body.appendChild(_wizNode('div', 'wiz-q', 'Run this on the host'));
  if (st.kind === 'pin') {
    body.appendChild(_wizNode('div', 'form-label', 'Enrollment PIN'));
    const pin = _wizNode('div', 'pin-code wiz-pin', st.pin);
    pin.id = 'wiz-pin';
    body.appendChild(pin);
    body.appendChild(_wizNode('div', 'hint mb-6', 'Run the client installer on the target host and enter this PIN when prompted.'));
    body.appendChild(_wizNode('div', 'hint', 'The PIN works once and expires after 10 minutes.'));
  } else {
    const lines = quickInstallLines(server, st.token, st.ca);
    if (st.kind === 'linux') {
      _wizCommand(body, 'wiz-cmd-linux', 'Linux / macOS', 'Run on the target host as root.', lines.linux);
      if (lines.linuxPinned) {
        _wizCommand(body, 'wiz-cmd-pinned', 'Linux / macOS (self-signed certificate)',
          'Use this one if your browser warned about the certificate. It checks the CA of the server against its fingerprint first, and trusts nothing from the server until they match.',
          lines.linuxPinned);
      }
    } else if (st.kind === 'windows') {
      _wizCommand(body, 'wiz-cmd-windows', 'Windows', 'Run in an elevated PowerShell (Win+X → Terminal (Admin)). Needs Python 3.8+.', lines.win);
    } else {
      _wizCommand(body, 'wiz-cmd-docker', 'Docker host', 'Save as docker-compose.yml on the host, then run docker compose up -d.', dockerComposeText(server, st.token));
    }
    body.appendChild(_wizNode('div', 'hint', 'The command works once and stops working after the time you chose.'));
  }
  const watch = _wizNode('div', 'wiz-watch');
  watch.id = 'wiz-watch';
  watch.setAttribute('role', 'status');
  body.appendChild(watch);
  _wizEnrollWatch();
  _wizEnrollPaint();
}

// What the wait says right now: still waiting (and for how long), checked in, or no sign after five minutes.
function _wizEnrollPaint() {
  const el = document.getElementById('wiz-watch');
  const w = _wiz;
  if (!el || !w) return;
  const st = w.st;
  el.textContent = '';
  if (st.arrived) {
    el.className = 'wiz-watch c-green';
    el.appendChild(_wizNode('span', 'wiz-state', 'Checked in'));
    el.appendChild(_wizNode('span', 'wiz-chip', st.arrived.name || st.arrived.id));
  } else if (st.late) {
    el.className = 'wiz-watch c-amber';
    el.appendChild(_wizNode('span', '', 'No host has checked in after 5 minutes. Check the installer output on the target, that it can reach this server, and that the token has not been used already.'));
  } else {
    el.className = 'wiz-watch c-muted';
    el.appendChild(_wizNode('span', '', 'Waiting for the host to check in…'));
    const s = st.watchFrom ? Math.round((Date.now() - st.watchFrom) / 1000) : 0;
    if (s > 0) el.appendChild(_wizNode('span', 'ff-mono', s + ' s'));
  }
}

// Looks for a host that enrolled after the token (or the PIN) was made, every few seconds, and stops when one is there, after five
// minutes, or when the dialog goes. The server's own clock is the baseline (`since`), not this browser's.
function _wizEnrollWatch() {
  const w = _wiz;
  if (!w || w.st.watching || w.st.arrived) return;
  const st = w.st;
  st.watching = true;
  st.watchFrom = Date.now();
  const stop = () => { st.watching = false; clearInterval(timer); };
  const tick = async () => {
    if (_wiz !== w) { stop(); return; }
    if ((Date.now() - st.watchFrom) / 1000 > _WIZ_WATCH_LIMIT_S) { st.late = true; stop(); _wizEnrollPaint(); return; }
    const r = await api('GET', '/devices?slim=1').catch(() => null);
    if (_wiz !== w || !st.watching) return;
    const rows = Array.isArray(r) ? r : (r && r.devices) || [];
    const fresh = rows.filter(d => Number(d.enrolled || 0) >= st.since).sort((a, b) => Number(b.enrolled || 0) - Number(a.enrolled || 0));
    if (fresh.length) {
      st.arrived = fresh[0];
      st.arrivedCount = fresh.length;
      stop();
      _wizEnrollPaint();
      if (typeof loadDevices === 'function') loadDevices();
      if (w.def.steps[w.i].label === 'Done') _wizShow(w.i);
      return;
    }
    _wizEnrollPaint();
  };
  const timer = setInterval(tick, _WIZ_WATCH_MS);
  w.timers.push(timer);
}

function _wizEnrollDone(st, body) {
  const d = st.arrived;
  if (d) {
    body.appendChild(_wizNode('div', 'wiz-q c-green', 'The host has joined'));
    _wizList(body, [
      ['Name', d.name || d.id],
      ['Group', d.group || 'No group'],
      ['Tags', (d.tags && d.tags.length) ? d.tags.join(', ') : '—'],
      ['OS', d.os || '—'],
      ['IP address', d.ip || '—'],
    ]);
  } else {
    body.appendChild(_wizNode('div', 'wiz-q', 'Nothing has checked in yet'));
    body.appendChild(_wizNode('div', 'hint', 'Keep this window open, or close it: the host shows up on the Hosts page when it checks in.'));
  }
  const row = _wizNode('div', 'row-8 mt-12');
  if (d) {
    const open = _wizNode('button', 'btn-primary', 'Open host');
    open.type = 'button';
    open.setAttribute('data-action', 'wizOpenHost');
    row.appendChild(open);
  }
  const again = _wizNode('button', 'btn-secondary', 'Add another host');
  again.type = 'button';
  again.setAttribute('data-action', 'wizAddAnother');
  row.appendChild(again);
  body.appendChild(row);
}

function wizOpenHost() {
  const w = _wiz;
  const d = w && w.st.arrived;
  if (!d) return;
  w.finished = true;
  closeModal('wizard-modal');
  if (typeof openDeviceDrawer === 'function') openDeviceDrawer(d.id, d.name);
}

// Starts again from the first step with the same group, tags, networks and time; the next host gets a command of its own.
function wizAddAnother() {
  const w = _wiz;
  if (!w) return;
  const st = w.st;
  w.timers.forEach(t => clearInterval(t));
  w.timers = [];
  Object.assign(st, { sig: '', token: '', pin: '', pinAt: 0, pinSince: 0, tokenSince: 0, since: 0, arrived: null, arrivedCount: 0, watching: false, late: false });
  _wizShow(0);
}

// ── "Add a notification destination" ──────────────────────────────────────────────────────────────────────────────────────
// The fields each service needs beyond a name and an address. A field is [key, label, input type, example, required]; the keys are the
// ones the destination editor in Settings reads and the server stores, and the examples are the editor's own. `url` is filled in for a
// service that has one fixed address.
const _WIZ_NOTIFY = {
  pushover:   { hint: 'Needs the application token and your user or group key from pushover.net.', url: 'https://api.pushover.net/1/messages.json',
                fields: [['pushover_token', 'App token', 'text', 'App token (apXXX...)', true], ['pushover_user', 'User or group key', 'text', 'User/group key (uXXX...)', true]] },
  github:     { hint: 'Needs an access token that may write issues in the repository.',
                fields: [['token', 'Access token', 'text', 'GitHub PAT (fine-grained, issues:write)', true]] },
  pagerduty:  { hint: 'Needs the integration key of a PagerDuty service (Events API v2).', url: 'https://events.pagerduty.com/v2/enqueue',
                fields: [['token', 'Integration key', 'text', 'PagerDuty integration/routing key', true]] },
  opsgenie:   { hint: 'Needs an API key from an Opsgenie API integration. Use the EU address if your account is in the EU.', url: 'https://api.opsgenie.com/v2/alerts',
                fields: [['token', 'API key', 'text', 'Opsgenie API key (GenieKey)', true]] },
  jira:       { hint: 'Opens a ticket when an alert is acknowledged. Needs an account that may create tickets.',
                fields: [['itsm_user', 'Account (email or username)', 'text', 'Atlassian account email', true], ['itsm_secret', 'API token or password', 'password', 'API token', true],
                         ['jira_project', 'Project key', 'text', 'Project key (e.g. OPS)', true], ['jira_issuetype', 'Issue type (optional)', 'text', 'Issue type (default Task)', false]] },
  servicenow: { hint: 'Opens a ticket when an alert is acknowledged. Needs an account that may create tickets.',
                fields: [['itsm_user', 'Account (email or username)', 'text', 'ServiceNow username', true], ['itsm_secret', 'API token or password', 'password', 'Password', true]] },
  zendesk:    { hint: 'Opens a ticket when an alert is acknowledged. Needs an account that may create tickets.',
                fields: [['itsm_user', 'Account (email or username)', 'text', 'Zendesk agent email', true], ['itsm_secret', 'API token or password', 'password', 'API token', true]] },
  telegram:   { hint: 'The bot token is part of the address. The chat ID is the chat the bot writes to.',
                fields: [['telegram_chat_id', 'Chat ID', 'text', 'Chat ID (e.g. -1001234567890)', true]] },
  matrix:     { hint: 'The access token is sent as a bearer header.',
                fields: [['matrix_token', 'Access token', 'password', 'Access token (syt_...)', true]] },
  generic:    { hint: 'Optional: each message is signed with a secret so the receiver can check where it came from.',
                fields: [['hmac_secret', 'Signing secret (optional)', 'password', 'Optional HMAC signing secret', false]] },
  ntfy:       { hint: 'The topic name is part of the address. Pick one nobody else will guess.' },
};
// Where each service sits on the first step.
const _WIZ_NOTIFY_GROUPS = [
  ['Chat', ['discord', 'slack', 'mattermost', 'rocketchat', 'googlechat', 'teams', 'telegram', 'matrix']],
  ['Push', ['ntfy', 'pushover', 'gotify']],
  ['On-call', ['pagerduty', 'opsgenie']],
  ['Tickets', ['github', 'jira', 'servicenow', 'zendesk']],
  ['Anything else', ['generic']],
];
const _WIZ_NOTIFY_PRIO = [['', 'any'], ['3', 'normal and up'], ['4', 'high and up'], ['5', 'urgent only']];

function _wizNotifyFormat(fmt) { return _WEBHOOK_FORMATS.find(f => f[0] === fmt) || ['generic', 'Generic JSON', 'https://']; }

function _wizNotifyDef() {
  return {
    title: 'Add a notification destination',
    init: () => ({ fmt: 'discord', name: '', url: '', vals: {}, id: 'wh_' + Math.random().toString(36).slice(2, 10), saved: false,
                   verdict: null, prio: '', named: false }),
    steps: [
      { label: 'Service', render: _wizNotifyService },
      { label: 'Connection', render: _wizNotifyConnection, validate: _wizNotifyCheck },
      { label: 'Test', render: _wizNotifyTest },
      { label: 'Finish', render: _wizNotifyFinish, primary: 'Turn it on', next: _wizNotifyOn },
    ],
    onClose: _wizNotifyClosed,
  };
}

function _wizNotifyService(st, body) {
  const items = [];
  _WIZ_NOTIFY_GROUPS.forEach(([g, list]) => {
    items.push({ g });
    list.forEach(v => items.push({ v, t: _wizNotifyFormat(v)[1] }));
  });
  _wizChoices(body, {
    legend: 'Where should alerts go?', name: 'wiz-fmt', value: st.fmt, items,
    onPick: v => {
      if (v === st.fmt) return;
      st.fmt = v; st.vals = {}; st.verdict = null;
      const fixed = (_WIZ_NOTIFY[v] || {}).url;
      st.url = fixed || '';
      if (!st.named) st.name = '';
    },
  });
}

function _wizNotifyConnection(st, body) {
  const spec = _WIZ_NOTIFY[st.fmt] || {};
  const label = _wizNotifyFormat(st.fmt)[1];
  if (!st.name) st.name = label + ' alerts';
  if (!st.url && spec.url) st.url = spec.url;
  if (spec.hint) body.appendChild(_wizNode('div', 'hint mb-12', spec.hint));
  _wizField(body, { id: 'wiz-name', label: 'Name', value: st.name, maxlength: 64, onInput: v => { st.name = v; st.named = true; st.verdict = null; } });
  _wizField(body, { id: 'wiz-url', label: 'URL', type: 'url', value: st.url, placeholder: _wizNotifyFormat(st.fmt)[2], onInput: v => { st.url = v; st.verdict = null; } });
  (spec.fields || []).forEach(([key, lab, type, example]) => {
    _wizField(body, { id: 'wiz-f-' + key, label: lab, type, value: st.vals[key] || '', placeholder: example, onInput: v => { st.vals[key] = v; st.verdict = null; } });
  });
}

function _wizNotifyCheck(st) {
  if (!st.name.trim()) return { msg: 'Name required', focus: 'wiz-name' };
  if (!st.url.trim()) return { msg: 'Set a URL first', focus: 'wiz-url' };
  if (!/^https?:\/\//i.test(st.url.trim())) return { msg: 'The URL must start with http:// or https://', focus: 'wiz-url' };
  const spec = _WIZ_NOTIFY[st.fmt] || {};
  for (const [key, , , , required] of (spec.fields || [])) {
    if (required && !String(st.vals[key] || '').trim()) return { msg: 'This field is needed', focus: 'wiz-f-' + key };
  }
  return null;
}

// The destination as the editor in Settings keeps it. Secrets that were left empty are not sent.
function _wizNotifyDest(st, extra) {
  const d = { id: st.id, name: st.name.trim(), url: st.url.trim(), format: st.fmt, enabled: false };
  ((_WIZ_NOTIFY[st.fmt] || {}).fields || []).forEach(([key]) => {
    const v = String(st.vals[key] || '').trim();
    if (v) d[key] = v;
  });
  return Object.assign(d, extra || {});
}

// The editor in Settings keeps its list in _webhookDests, edits that are not saved yet included. The server takes the whole list on a save, so
// the list that goes is the server's own, fresh (a destination somebody else added meanwhile is not lost) with this change in it, saved the
// way the editor saves. The editor's list is put back as it was and gets the same change, from the server's answer: an edit that was waiting in
// the editor is neither saved by the wizard nor thrown away by it.
async function _wizNotifySave(d) {
  const cfg = await api('GET', '/config');
  if (!cfg || cfg.error) return false;
  const fresh = Array.isArray(cfg.webhook_urls) ? cfg.webhook_urls.map(x => ({ ...x })) : [];
  const at = fresh.findIndex(x => x.id === d.id);
  if (d._remove) { if (at < 0) return true; fresh.splice(at, 1); }
  else if (at >= 0) fresh[at] = d;
  else fresh.push(d);
  const editor = _webhookDests;
  let ok = false;
  _webhookDests = fresh;
  try { ok = await saveWebhookDests(); } finally { _webhookDests = editor; }
  if (!ok) return false;
  const after = await api('GET', '/config');
  const mine = after && Array.isArray(after.webhook_urls) ? after.webhook_urls.find(x => x.id === d.id) : null;
  const i = editor.findIndex(x => x.id === d.id);
  if (mine) { if (i >= 0) editor[i] = { ...mine }; else editor.push({ ...mine }); }
  else if (i >= 0) editor.splice(i, 1);
  return true;
}

// What the log entry of the test says, in words. The status is an HTTP code, or one of the words the server logs.
function _wizNotifyVerdict(r) {
  if (!r) return { kind: 'none' };
  if (r.error) return { kind: 'error', detail: String(r.error) };
  const e = r.result;
  if (!e || e.event !== 'test') return { kind: 'none' };
  const s = String(e.status || '');
  if (/^2\d\d$/.test(s)) return { kind: 'ok', code: s };
  if (/^4\d\d$/.test(s)) return { kind: 'refused', code: s };
  if (/^5\d\d$/.test(s)) return { kind: 'down', code: s };
  if (s === 'suppressed') return { kind: 'held', detail: String(e.detail || '') };
  return { kind: 'error', detail: String(e.detail || s) };
}

function _wizNotifyTest(st, body) {
  body.appendChild(_wizNode('div', 'wiz-q', 'Send a message to check that it arrives.'));
  const row = _wizNode('div', 'row-8');
  const b = _wizNode('button', 'btn-primary', 'Send a test message');
  b.type = 'button';
  b.id = 'wiz-test';
  b.setAttribute('data-action', 'wizNotifyTest');
  row.appendChild(b);
  body.appendChild(row);
  const out = _wizNode('div', 'wiz-result');
  out.id = 'wiz-result';
  out.setAttribute('role', 'status');
  body.appendChild(out);
  _wizNotifyPaint();
}

function _wizNotifyPaint() {
  const out = document.getElementById('wiz-result');
  const w = _wiz;
  if (!out || !w) return;
  const v = w.st.verdict;
  out.textContent = '';
  if (w.st.sending) { out.className = 'wiz-result c-muted'; out.textContent = 'Sending…'; return; }
  if (!v) { out.className = 'wiz-result'; return; }
  const line = (cls, state, code, text) => {
    out.className = 'wiz-result ' + cls;
    const top = _wizNode('div', 'row-8-center');
    top.appendChild(_wizNode('span', 'wiz-state', state));
    if (code) top.appendChild(_wizNode('span', 'wiz-chip ff-mono', code));
    out.appendChild(top);
    if (text) out.appendChild(_wizNode('div', 'hint mt-6', text));
  };
  if (v.kind === 'ok') line('c-green', 'Delivered', v.code, 'The service accepted the test message. Check that it arrived in the place you chose.');
  else if (v.kind === 'refused') line('c-red', 'Not delivered', v.code, 'The service refused it. The address or the key is usually wrong, or has been revoked.');
  else if (v.kind === 'down') line('c-red', 'Not delivered', v.code, 'The service had a problem on its side. Try again in a minute.');
  else if (v.kind === 'held') {
    line('c-amber', 'Held back', '', 'Tests are held back during maintenance windows and quiet hours. Try again later.');
    if (v.detail) out.appendChild(_wizNode('div', 'hint ff-mono', v.detail));
  } else if (v.kind === 'error') {
    line('c-red', 'Not delivered', '', 'Check the address and that this server can reach it.');
    if (v.detail) out.appendChild(_wizNode('div', 'hint ff-mono', v.detail));
  } else line('c-red', 'Not delivered', '', 'The test could not be run. Try again.');
}

// Saves the destination as a draft that is switched off, then asks the server to send one test message to it. The test works on a
// destination that is switched off, so nothing real can reach the channel before the person says so on the last step.
async function wizNotifyTest() {
  const w = _wiz;
  if (!w || w.busy) return;
  const st = w.st;
  st.verdict = null;                      // the answer of the last test goes, so a new one is not mistaken for it
  st.sending = true;
  _wizNotifyPaint();
  const btn = document.getElementById('wiz-test');
  if (btn) btn.disabled = true;
  _wizBusy(true);
  let r = null, saved = false;
  try {
    saved = await _wizNotifySave(_wizNotifyDest(st));
    if (saved) { st.saved = true; r = await api('POST', '/webhook/test', { id: st.id }); }
  } finally {
    st.sending = false;
    if (_wiz === w) _wizBusy(false);
    const again = document.getElementById('wiz-test');
    if (again) again.disabled = false;
  }
  if (_wiz !== w) return;
  st.verdict = saved ? _wizNotifyVerdict(r) : { kind: 'none' };
  _wizNotifyPaint();
  // the log under the editor is drawn again a moment later, if the Settings page is the one on screen (it is built when it is first opened)
  setTimeout(() => { if (document.getElementById('webhook-log-tbody')) loadWebhookLog(); }, 800);
}

function _wizNotifyFinish(st, body) {
  body.appendChild(_wizNode('div', 'wiz-q', 'What should it receive?'));
  _wizField(body, { id: 'wiz-prio', label: 'Minimum severity', value: st.prio, options: _WIZ_NOTIFY_PRIO, onInput: v => { st.prio = v; } });
  let host = '';
  try { host = new URL(st.url).origin; } catch (_) { host = ''; }
  const ok = st.verdict && st.verdict.kind === 'ok';
  _wizList(body, [
    ['Service', _wizNotifyFormat(st.fmt)[1]],
    ['Name', st.name],
    ['Address', host || '—'],
    ['Test', ok ? 'Delivered' : 'Not tested'],
  ]);
  if (!ok) body.appendChild(_wizNode('div', 'hint mt-8', 'It was not tested. A wrong address fails without a sign until the first alert needs it.'));
}

async function _wizNotifyOn(st, w) {
  const extra = { enabled: true, min_priority: st.prio === '' ? null : Number(st.prio) };
  const done = await _wizNotifySave(_wizNotifyDest(st, extra));
  if (!done) { _wizMsg('Save failed', ''); return false; }
  w.finished = true;
  if (typeof renderWebhookDests === 'function' && document.getElementById('webhook-dests')) renderWebhookDests();
  toast('Notification destination added', 'success');
  return true;
}

// A wizard that is closed before the last step leaves nothing behind that was never checked: a draft that never delivered is removed. A
// draft that did deliver stays, switched off, and the toast says where to turn it on.
function _wizNotifyClosed(st, finished) {
  if (finished || !st.saved) return;
  if (st.verdict && st.verdict.kind === 'ok') { toast('Saved, but switched off. Turn it on under Settings, Notifications.', 'info'); return; }
  _wizNotifySave({ id: st.id, _remove: true });
}

const _WIZARDS = { enroll: _wizEnrollDef, notify: _wizNotifyDef };

// ── step-by-step mode of the long forms ──────────────────────────────────────────────────────────────────────────────────
// Each form lists its steps. A step names the controls (or the blocks of the form) it holds by id; the block of the form that holds the
// control is the unit that is shown or hidden, so a heading, a hint and the control stay together. A block that no step names goes with
// the last step (a test holds that to none). `check` is what the form's own save refuses, said before the last step instead of after:
// the same words, so the message is the one that is already translated.
const _WIZ_FORMS = {
  'new-maint-modal': {
    steps: [
      { label: 'What', ids: ['maint-reason', 'maint-scope', 'maint-target-row'] },
      { label: 'When', ids: ['maint-type', 'maint-period-row', 'maint-oneshot-row', 'maint-cron-row'] },
      { label: 'Effects', ids: ['maint-events-box', 'maint-suppress', 'maint-gate-exec'] },
    ],
    check(n, q) {
      if (n !== 1) return null;
      const type = q('maint-type').value;
      if (type === 'oneshot' && (!q('maint-start').value || !q('maint-end').value)) {
        return { msg: 'Start and end are required', focus: q('maint-start').value ? q('maint-end') : q('maint-start') };
      }
      if (type === 'period' && !q('maint-period').value) return { msg: 'Choose a time period', focus: q('maint-period') };
      return null;
    },
  },
  'monitor-add-modal': {
    steps: [
      { label: 'What', ids: ['mon-label', 'mon-type', 'mon-flow-grp', 'mon-dbkind-grp'] },
      { label: 'Target', ids: ['mon-kind-grp', 'mon-target', 'mon-port-grp', 'mon-expect-grp'] },
      { label: 'Checks', ids: ['mon-status-grp', 'mon-method-grp', 'mon-tls-grp', 'mon-latency-grp', 'mon-loss-grp', 'mon-body-grp', 'mon-json-grp'] },
      { label: 'Alerting', ids: ['mon-failures-before-alert', 'mon-satellite', 'mon-slo-grp'] },
    ],
    check(n, q) {
      if (n !== 1) return null;
      const type = q('mon-type').value, target = q('mon-target').value.trim();
      if (type === 'http_flow') return null;
      if (!target) return { msg: 'Target is required', focus: q('mon-target') };
      if (type === 'http') {
        try { const u = new URL(target); if (!/^https?:$/.test(u.protocol)) throw 0; }
        catch (_) { return { msg: 'HTTP target must be a full URL (https://host/path)', focus: q('mon-target') }; }
      }
      return null;
    },
  },
  'backupjob-modal': {
    steps: [
      { label: 'What', ids: ['backupjob-name', 'backupjob-devices'] },
      { label: 'How', ids: ['backupjob-type', 'backupjob-command-group', 'backupjob-file-group'] },
      { label: 'When', ids: ['backupjob-cron'] },
    ],
    // leaving the first step: the filter above the list is emptied, so the list the review reads shows every host that is ticked
    leave(n, q) {
      if (n === 0 && q('backupjob-devfilter').value) { q('backupjob-devfilter').value = ''; _backupRenderDeviceChecks(''); }
    },
    check(n, q, panel) {
      if (n === 0) {
        if (!q('backupjob-name').value.trim()) return { msg: 'Name is required', focus: q('backupjob-name') };
        if (!_backupSelectedIds().length) return { msg: 'Select at least one host', focus: panel.querySelector('.backupjob-devchk') || q('backupjob-devfilter') };
      }
      if (n === 1) {
        if (q('backupjob-type').value === 'file') {
          if (!q('backupjob-paths').value.split('\n').some(s => s.trim())) return { msg: 'Add at least one source path', focus: q('backupjob-paths') };
          if (!q('backupjob-host').value.trim() || !q('backupjob-remotepath').value.trim()) {
            return { msg: 'Host and remote path are required', focus: q('backupjob-host').value.trim() ? q('backupjob-remotepath') : q('backupjob-host') };
          }
        } else if (!q('backupjob-command').value.trim()) {
          return { msg: 'A command is required', focus: q('backupjob-command') };
        }
      }
      return null;
    },
  },
  'autopatch-modal': {
    steps: [
      { label: 'What', ids: ['autopatch-name', 'autopatch-target-type'] },
      { label: 'When', ids: ['autopatch-cron', 'autopatch-reboot'] },
      { label: 'Safety', ids: ['autopatch-staged', 'autopatch-rings-box'] },
    ],
    check(n, q) {
      if (n === 0) {
        if (!q('autopatch-name').value.trim()) return { msg: 'Name required', focus: q('autopatch-name') };
        if (q('autopatch-target-type').value === 'device' && !q('autopatch-target-device').value) return { msg: 'Pick a host for this policy', focus: q('autopatch-target-device') };
      }
      if (n === 2 && q('autopatch-staged').checked && !_autopatchParseRings().length) {
        return { msg: 'Staged rollout needs at least one ring (e.g. "canary = tag:canary")', focus: q('autopatch-rings') };
      }
      return null;
    },
  },
};

const _wizForms = new Map();       // modal id -> the state of the form that is in steps

// The form's own hiding: a class (d-none, hidden), the hidden attribute or an inline display, on the block or on what holds it.
function _wizHidden(n, stop) {
  for (let x = n; x && x !== stop; x = x.parentElement) {
    if (x.classList.contains('d-none') || x.classList.contains('hidden') || x.hidden || x.style.display === 'none') return true;
  }
  return false;
}

// Synced with the person's choice: in steps if they chose steps, back to the one form if not.
function _wizFormSync(id) {
  let want = false;
  try { want = localStorage.getItem('rp_formsteps') === '1'; } catch (_) { want = false; }
  if (want) _wizFormAttach(id); else _wizFormDetach(id);
}

function _wizFormBlocks(panel) {
  return [...panel.children].filter(n => !n.matches('.modal-title, .modal-subtitle, .modal-actions, .modal-close, .wiz-switch, .wiz-steps, .wiz-msg, .wiz-live, .wiz-review, input[type=hidden]'));
}

// Which block belongs to which step, from the ids each step names (the first step to name a block has it). A block that no step names
// goes with the last one. The blocks are read in the order they stand in the form, so each step's blocks keep that order.
function _wizFormAssign(panel, def) {
  const blocks = _wizFormBlocks(panel);
  const owner = new Map();
  def.steps.forEach((s, n) => s.ids.forEach(id => {
    const t = panel.querySelector('#' + id);
    const b = t && blocks.find(k => k === t || k.contains(t));
    if (b && !owner.has(b)) owner.set(b, n);
  }));
  const groups = def.steps.map(() => []);
  blocks.forEach(b => groups[owner.has(b) ? owner.get(b) : groups.length - 1].push(b));
  return groups;
}

function _wizFormAttach(id) {
  const el = document.getElementById(id), def = _WIZ_FORMS[id];
  if (!el || !def) return;
  const panel = el.querySelector(':scope > .modal');
  if (!panel) return;
  let F = _wizForms.get(id);
  if (!F) {
    const actions = panel.querySelector(':scope > .modal-actions');
    const submit = actions && actions.querySelector('.btn-primary');
    if (!actions || !submit) return;
    const ol = _wizNode('ol', 'wiz-steps');
    ol.setAttribute('aria-label', 'Steps');
    const sw = panel.querySelector(':scope > .wiz-switch');
    (sw || panel.querySelector(':scope > .modal-title')).after(ol);
    const msg = _wizNode('div', 'wiz-msg');
    msg.setAttribute('role', 'alert');
    const review = _wizNode('div', 'wiz-review');
    const live = _wizNode('div', 'visually-hidden wiz-live');
    live.setAttribute('role', 'status');
    actions.before(review, msg, live);
    const nav = (cls, action, label) => { const b = _wizNode('button', 'wiz-nav ' + cls, label); b.type = 'button'; b.setAttribute('data-action', action); b.setAttribute('data-arg', id); return b; };
    const back = nav('btn-secondary', 'wizFormBack', 'Back'), next = nav('btn-primary', 'wizFormNext', 'Next');
    submit.before(back, next);
    F = { id, el, panel, def, ol, msg, live, review, back, next, submit, blocks: _wizFormAssign(panel, def), i: 0 };
    panel.addEventListener('keydown', _wizFormKey);
    _wizForms.set(id, F);
  }
  F.blocks = _wizFormAssign(F.panel, F.def);       // the form may have added rows since it was last opened
  _wizFormShow(F, _wizFormVisible(F)[0]);
}

function _wizFormDetach(id) {
  const F = _wizForms.get(id);
  if (!F) return;
  F.panel.removeEventListener('keydown', _wizFormKey);
  F.blocks.forEach(g => g.forEach(b => b.classList.remove('wiz-off')));
  F.submit.classList.remove('wiz-off');
  [F.ol, F.msg, F.live, F.review, F.back, F.next].forEach(n => n.remove());
  _wizForms.delete(id);
}

// The steps that have something to show right now (a form hides rows by what was chosen), then the review, which always shows.
function _wizFormVisible(F) {
  const out = [];
  F.blocks.forEach((g, n) => { if (g.some(b => !_wizHidden(b, F.panel))) out.push(n); });
  out.push(F.def.steps.length);
  return out;
}

function _wizFormShow(F, i) {
  const R = F.def.steps.length, vis = _wizFormVisible(F);
  F.i = i;
  F.blocks.forEach((g, n) => g.forEach(b => b.classList.toggle('wiz-off', n !== i)));
  F.review.classList.toggle('wiz-off', i !== R);
  F.submit.classList.toggle('wiz-off', i !== R);
  F.next.classList.toggle('wiz-off', i === R);
  F.back.classList.toggle('wiz-off', i === vis[0]);
  F.msg.textContent = '';
  if (i === R) _wizFormReview(F);
  _wizStepper(F.ol, vis.map(n => ({ label: n === R ? 'Review' : F.def.steps[n].label, n })), i, true, 'wizFormGoto');
  F.ol.dataset.modal = F.id;
  F.live.textContent = i === R ? 'Review' : F.def.steps[i].label;
  requestAnimationFrame(() => {
    if (i === R) { try { F.submit.focus(); } catch (_) { /* hidden */ } return; }
    const c = F.blocks[i].map(b => b.querySelector('input:not([type=hidden]):not([disabled]), select:not([disabled]), textarea:not([disabled])'))
      .find(x => x && !_wizHidden(x, F.panel));
    if (c) { try { c.focus(); } catch (_) { /* hidden */ } }
  });
}

function _wizFormKey(e) {
  if (e.key !== 'Enter' || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;
  const t = e.target;
  if (!t || t.tagName !== 'INPUT' || ['checkbox', 'radio', 'button', 'submit'].includes(t.type)) return;
  const F = [..._wizForms.values()].find(f => f.panel.contains(t));
  if (!F || F.i === F.def.steps.length) return;
  e.preventDefault();
  wizFormNext(F.id);
}

function _wizFormQuery(F) { return id => F.panel.querySelector('#' + id); }

function wizFormNext(id) {
  const F = _wizForms.get(id);
  if (!F) return;
  const bad = F.def.check ? F.def.check(F.i, _wizFormQuery(F), F.panel) : null;
  if (bad) {
    F.msg.textContent = bad.msg;
    if (bad.focus) { bad.focus.setAttribute('aria-invalid', 'true'); bad.focus.focus(); }
    return;
  }
  F.panel.querySelectorAll('[aria-invalid]').forEach(n => n.removeAttribute('aria-invalid'));
  if (F.def.leave) F.def.leave(F.i, _wizFormQuery(F), F.panel);
  const vis = _wizFormVisible(F).filter(n => n > F.i);
  if (vis.length) _wizFormShow(F, vis[0]);
}

function wizFormBack(id) {
  const F = _wizForms.get(id);
  if (!F) return;
  const vis = _wizFormVisible(F).filter(n => n < F.i);
  if (vis.length) _wizFormShow(F, vis[vis.length - 1]);
}

// The step indicator's buttons go back to a step that is done. Going forward is only by Next, which checks the step on the way.
function wizFormGoto(n, id) {
  const modal = id || (document.querySelector('.modal-overlay.active .wiz-steps[data-modal]') || {dataset: {}}).dataset.modal;
  const F = _wizForms.get(modal);
  if (F && Number(n) < F.i) _wizFormShow(F, Number(n));
}

// The label and value of every block that shows, step by step. What the person sees is what they get: the labels and the chosen
// option's text are read from the form, so they are in the language of the page already.
function _wizFormReview(F) {
  F.review.textContent = '';
  F.blocks.forEach((g, n) => {
    const units = [];
    g.forEach(b => {
      if (_wizHidden(b, F.panel)) return;
      if (b.classList.contains('form-group')) { units.push(b); return; }
      const inner = [...b.querySelectorAll('.form-group')].filter(u => !_wizHidden(u, F.panel));
      if (inner.length) inner.forEach(u => units.push(u)); else units.push(b);
    });
    const rows = units.map(u => [_wizUnitLabel(u), _wizUnitValue(u, F.panel)]).filter(r => r[0]);
    if (!rows.length) return;
    F.review.appendChild(_wizNode('div', 'wiz-review-h', F.def.steps[n].label));
    _wizList(F.review, rows);
  });
}

function _wizUnitLabel(u) {
  const l = u.querySelector('label, .form-label');
  if (!l) return '';
  const c = l.cloneNode(true);
  c.querySelectorAll('input, select, textarea, button, .hint, .meta-sm').forEach(n => n.remove());
  return c.textContent.replace(/\s+/g, ' ').trim();
}

// Boxes that hold a search the person typed, not a choice: the filter above a long list and the text box of a host picker (the select
// behind it holds the choice).
const _WIZ_NOT_A_CHOICE = '.select-filter, .dev-combo-input, [id$="-devfilter"], input[type=search]';

function _wizUnitValue(u, panel) {
  const controls = [...u.querySelectorAll('input, select, textarea')]
    .filter(c => !['hidden', 'button', 'submit'].includes(c.type) && !c.disabled && !c.matches(_WIZ_NOT_A_CHOICE) && !_wizHidden(c, panel));
  if (!controls.length) return '—';
  if (controls.length === 1 && controls[0].type === 'checkbox') return controls[0].checked ? 'Yes' : 'No';
  const parts = [];
  controls.forEach(c => {
    if (c.type === 'checkbox' || c.type === 'radio') {
      if (!c.checked) return;
      const l = c.closest('label');
      const t = l ? l.textContent.replace(/\s+/g, ' ').trim() : c.value;
      if (t) parts.push(t);
    } else if (c.tagName === 'SELECT') {
      const o = c.selectedOptions && c.selectedOptions[0];
      if (o && o.textContent.trim()) parts.push(o.textContent.trim());
    } else if (c.type === 'password') {
      if (c.value) parts.push('••••');
    } else if (c.value.trim()) {
      parts.push(c.type === 'datetime-local' ? c.value.replace('T', ' ') : c.value.trim().replace(/\s*\n\s*/g, ', '));
    }
  });
  if (!parts.length) return '—';
  return parts.length > 8 ? parts.slice(0, 8).join(', ') + ' +' + (parts.length - 8) : parts.join(', ');
}
