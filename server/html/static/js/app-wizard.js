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
  const make = _WIZARDS[name] || (typeof _WIZARDS_MORE !== 'undefined' ? _WIZARDS_MORE[name] : null);     // _WIZARDS_MORE: the sidecar wizards (app-wizard-sidecars.js)
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
  _wizShow(_wizSteps()[0].n);           // the first step that applies (a wizard started from an app an agent found has no use for the first)
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
  c.autocomplete = o.type === 'password' ? 'new-password' : 'off';      // a password box that says 'off' is filled with this site's own sign-in by some browsers
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
  apprise:    { hint: 'The key is part of the address. Set up the services behind it in Apprise itself.' },
};
// Where each service sits on the first step.
const _WIZ_NOTIFY_GROUPS = [
  ['Chat', ['discord', 'slack', 'mattermost', 'rocketchat', 'googlechat', 'teams', 'telegram', 'matrix']],
  ['Push', ['ntfy', 'pushover', 'gotify']],
  ['Email', ['email']],
  ['On-call', ['pagerduty', 'opsgenie']],
  ['Tickets', ['github', 'jira', 'servicenow', 'zendesk']],
  ['Anything else', ['apprise', 'generic']],
];
const _WIZ_NOTIFY_PRIO = [['', 'any'], ['3', 'normal and up'], ['4', 'high and up'], ['5', 'urgent only']];

function _wizNotifyFormat(fmt) { return _WEBHOOK_FORMATS.find(f => f[0] === fmt) || ['generic', 'Generic JSON', 'https://']; }

function _wizNotifyDef() {
  return {
    title: 'Add a notification destination',
    init: () => ({ fmt: 'discord', name: '', url: '', vals: {}, id: 'wh_' + Math.random().toString(36).slice(2, 10), saved: false,
                   verdict: null, prio: '', named: false }),
    steps: [
      { label: 'Service', render: _wizNotifyService, next: _wizNotifyHandOver },
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
    list.forEach(v => items.push(v === 'email' ? { v, t: 'Email (SMTP)', d: 'Opens the email guide.' } : { v, t: _wizNotifyFormat(v)[1] }));
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

// Email is not a webhook: it has its own guide (the mail server, a login, who receives it), and the Service step goes there.
function _wizNotifyHandOver(st) {
  if (st.fmt !== 'email') return true;
  closeModal('wizard-modal');
  wizStart('smtp');
  return false;
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

// ── "Add an integration" ──────────────────────────────────────────────────────────────────────────────────────────────────
// A service from the catalog the server holds (every connector it has, built in or a plugin, so a plugin shows up here without a change),
// then the address and the credentials that connector asks for, a test, and the instance added to the list. The list of Settings,
// Integrations is _integrations, edits that are not saved yet included. The server takes the whole list on a save, so the list that goes is
// the server's own with the new instance in it, and the page's list gets the instance from the server's answer with nothing else of it
// touched: an edit waiting in the page is neither saved by the wizard nor thrown away by it. Nothing is saved before the last step.
const _WIZ_INTEG_GROUPS = [['apps', 'Apps'], ['media', 'Media'], ['download', 'Downloads'], ['request', 'Requests'], ['dns', 'DNS'], ['proxy', 'Proxies'],
  ['network', 'Network'], ['observability', 'Monitoring'], ['orchestration', 'Orchestration'], ['storage', 'Storage'], ['backup', 'Backup'],
  ['security', 'Security'], ['custom', 'Your own']];

function _wizIntegCatalog(list) { return (Array.isArray(list) ? list : []).filter(c => c && c.category !== 'virtualization'); }   // those have their own page

function _wizIntegDef() {
  return {
    title: 'Add an integration',
    init: (arg) => {
      const known = _wizIntegCatalog(typeof _integrationCatalog !== 'undefined' ? _integrationCatalog : []);
      // 8.0.0: started from an app an agent found ({type, url, name, device_id}): the service and its address are known, so it begins at the connection, and the
      // instance is bound to the host ("Runs on host")
      const pre = arg && typeof arg === 'object' && typeof arg.type === 'string' && arg.type ? arg : null;
      const c = pre ? known.find(x => x.type === pre.type) : null;
      return { type: pre ? pre.type : '', name: pre ? String(pre.name || (c && c.label) || pre.type) : '', named: !!pre, url: pre ? String(pre.url || '') : '', urlSet: !!(pre && pre.url),
               device_id: pre ? String(pre.device_id || '') : '', preset: !!pre, verify: true, vals: {}, verdict: null, testing: false, catalog: known, loaded: known.length > 0 };
    },
    onClose: (st, finished) => { if (finished && typeof appsRefresh === 'function') appsRefresh(); },
    steps: [
      { label: 'Service', skip: st => st.preset, render: _wizIntegService, validate: st => (st.type ? null : { msg: 'Choose a service', focus: 'wiz-search' }) },
      { label: 'Connection', render: _wizIntegConnection, validate: _wizIntegCheck },
      { label: 'Test', render: _wizIntegTest },
      { label: 'Finish', render: _wizIntegFinish, primary: 'Add it', next: _wizIntegAdd },
    ],
  };
}

function _wizIntegOf(st) { return st.catalog.find(x => x.type === st.type) || { fields: [], notes: '', default_url: '' }; }

function _wizIntegService(st, body) {
  if (!st.loaded) {
    body.appendChild(_wizNode('div', 'hint', 'Loading…'));
    api('GET', '/integrations').then(d => {
      st.catalog = _wizIntegCatalog(d && d.catalog);
      st.loaded = true;
      if (_wiz && _wiz.st === st && _wiz.i === 0) _wizShow(0);
    });
    return;
  }
  const by = new Map();
  st.catalog.forEach(c => { const k = c.category || 'other'; if (!by.has(k)) by.set(k, []); by.get(k).push(c); });
  const known = _WIZ_INTEG_GROUPS.map(g => g[0]);
  const order = known.filter(k => by.has(k)).concat([...by.keys()].filter(k => !known.includes(k)).sort());
  const title = k => (_WIZ_INTEG_GROUPS.find(g => g[0] === k) || [k, k.charAt(0).toUpperCase() + k.slice(1)])[1];
  const items = [];
  order.forEach(k => {
    items.push({ g: title(k) });
    by.get(k).slice().sort((a, b) => String(a.label).localeCompare(String(b.label))).forEach(c => items.push({ v: c.type, t: c.label }));
  });
  _wizField(body, { id: 'wiz-search', label: 'Search', value: '', placeholder: 'Type a service name', onInput: _wizIntegFilter });
  _wizChoices(body, {
    legend: 'What do you want to connect?', name: 'wiz-type', value: st.type, items,
    onPick: v => {
      if (v === st.type) return;
      st.type = v; st.vals = {}; st.verdict = null;
      const c = _wizIntegOf(st);
      if (!st.named) st.name = c.label || v;
      if (!st.urlSet) st.url = c.default_url || '';
    },
  });
  const none = _wizNode('div', 'hint mt-8 d-none', 'No service matches.');
  none.id = 'wiz-nomatch';
  body.appendChild(none);
}

// The search box hides what does not match, and a heading with nothing left under it.
function _wizIntegFilter(q) {
  const needle = String(q || '').trim().toLowerCase();
  const fs = document.querySelector('#wiz-body fieldset.wiz-set');
  if (!fs) return;
  let shown = 0;
  fs.querySelectorAll('.wiz-choices').forEach(grid => {
    let here = 0;
    grid.querySelectorAll('.wiz-choice').forEach(l => {
      const hit = !needle || l.textContent.toLowerCase().includes(needle) || String(l.querySelector('input').value).toLowerCase().includes(needle);
      l.hidden = !hit;
      if (hit) here++;
    });
    grid.hidden = here === 0;
    const head = grid.previousElementSibling;
    if (head && head.classList.contains('wiz-grp')) head.hidden = here === 0;
    shown += here;
  });
  const none = document.getElementById('wiz-nomatch');
  if (none) none.classList.toggle('d-none', shown > 0);
}

function _wizIntegConnection(st, body) {
  if (!st.loaded) {                     // started from an app an agent found: the list of services has not been fetched yet
    body.appendChild(_wizNode('div', 'hint', 'Loading…'));
    api('GET', '/integrations').then(d => {
      st.catalog = _wizIntegCatalog(d && d.catalog);
      st.loaded = true;
      if (_wiz && _wiz.st === st) _wizShow(_wiz.i);
    });
    return;
  }
  const c = _wizIntegOf(st);
  if (c.notes) body.appendChild(_wizNode('div', 'hint mb-12', c.notes));
  _wizField(body, { id: 'wiz-name', label: 'Name', value: st.name, maxlength: 80, onInput: v => { st.name = v; st.named = true; st.verdict = null; } });
  _wizField(body, { id: 'wiz-url', label: 'URL', type: 'url', value: st.url, placeholder: c.default_url || 'https://', onInput: v => { st.url = v; st.urlSet = true; st.verdict = null; } });
  (c.fields || []).forEach(f => {
    _wizField(body, {
      id: 'wiz-f-' + f.key, label: f.label, type: f.kind === 'password' ? 'password' : 'text', rows: f.kind === 'textarea' ? 4 : 0,
      value: st.vals[f.key] || '', placeholder: f.placeholder || '', hint: f.optional ? 'Optional' : '',
      onInput: v => { st.vals[f.key] = v; st.verdict = null; },
    });
  });
  _wizVerifyBox(st, body);
}

// The "check the certificate" box of a connection step: on unless it is turned off, and a change drops the answer of the last test.
function _wizVerifyBox(st, body) {
  const g = _wizNode('div', 'form-group');
  const lab = _wizNode('label', 'form-label');
  const box = document.createElement('input');
  box.type = 'checkbox';
  box.id = 'wiz-verify';
  box.checked = st.verify;
  box.addEventListener('change', () => { st.verify = box.checked; st.verdict = null; if (st.touched) st.touched.verify = true; });
  lab.append(box, document.createTextNode(' Check the TLS certificate'));
  g.appendChild(lab);
  g.appendChild(_wizNode('div', 'meta-sm', 'Turn it off for a service with a self-signed certificate on your network.'));
  body.appendChild(g);
}

function _wizIntegCheck(st) {
  if (!st.name.trim()) return { msg: 'Name required', focus: 'wiz-name' };
  const u = st.url.trim();
  if (!u) return { msg: 'Set a URL first', focus: 'wiz-url' };
  if (!/^https?:\/\//i.test(u)) return { msg: 'The URL must start with http:// or https://', focus: 'wiz-url' };
  for (const f of (_wizIntegOf(st).fields || [])) {
    if (!f.optional && !String(st.vals[f.key] || '').trim()) return { msg: 'This field is needed', focus: 'wiz-f-' + f.key };
  }
  return null;
}

// The instance as the page keeps it. A credential left empty is not sent.
function _wizIntegInst(st) {
  const inst = { type: st.type, label: st.name.trim(), url: st.url.trim(), enabled: true, verify_tls: st.verify };
  if (st.device_id) inst.device_id = st.device_id;
  (_wizIntegOf(st).fields || []).forEach(f => {
    const v = String(st.vals[f.key] || '').trim();
    if (v) inst[f.key] = v;
  });
  return inst;
}

function _wizIntegTest(st, body) {
  body.appendChild(_wizNode('div', 'wiz-q', 'Check that this server can reach it and that the key works.'));
  const row = _wizNode('div', 'row-8');
  const b = _wizNode('button', 'btn-primary', 'Test the connection');
  b.type = 'button';
  b.id = 'wiz-test';
  b.setAttribute('data-action', 'wizIntegTest');
  row.appendChild(b);
  body.appendChild(row);
  const out = _wizNode('div', 'wiz-result');
  out.id = 'wiz-result';
  out.setAttribute('role', 'status');
  body.appendChild(out);
  _wizIntegPaint();
}

function _wizIntegPaint() {
  const out = document.getElementById('wiz-result');
  const w = _wiz;
  if (!out || !w) return;
  const v = w.st.verdict;
  out.textContent = '';
  if (w.st.testing) { out.className = 'wiz-result c-muted'; out.textContent = 'Testing…'; return; }
  if (!v) { out.className = 'wiz-result'; return; }
  const top = _wizNode('div', 'row-8-center');
  out.className = 'wiz-result ' + (!v.ok ? 'c-red' : v.problem ? 'c-amber' : 'c-green');
  top.appendChild(_wizNode('span', 'wiz-state', v.ok ? 'Reachable' : 'Not reachable'));
  if (v.version) top.appendChild(_wizNode('span', 'wiz-chip ff-mono', 'v' + v.version));
  out.appendChild(top);
  out.appendChild(_wizNode('div', 'hint mt-6', !v.ok ? 'Check the address and the key, and that this server can reach it.'
    : v.problem ? 'The service answered and reports a problem. That is what its tile will show.' : 'The service answered.'));
  if (v.detail) out.appendChild(_wizNode('div', 'hint ff-mono', v.detail));
}

// The test works on the instance as it stands in the form, and saves nothing.
async function wizIntegTest() {
  const w = _wiz;
  if (!w || w.busy) return;
  const st = w.st;
  st.verdict = null;
  st.testing = true;
  _wizIntegPaint();
  const btn = document.getElementById('wiz-test');
  if (btn) btn.disabled = true;
  _wizBusy(true);
  let r = null;
  try { r = await api('POST', '/integrations/test', _wizIntegInst(st)); } catch (_) { r = null; }
  st.testing = false;
  if (_wiz === w) _wizBusy(false);
  const again = document.getElementById('wiz-test');
  if (again) again.disabled = false;
  if (_wiz !== w) return;
  // "ok" is the connector's own verdict (its status is ok or warning). A service that answered and reports a problem of its own (an Uptime Kuma
  // with a monitor down) is critical with its numbers in hand: it was reached, which is what the test is asking. One that was not reached says
  // critical with no numbers, only why.
  const reached = !!r && !r.error && (!!r.ok || (r.status === 'critical' && !!r.metrics && Object.keys(r.metrics).length > 0));
  st.verdict = r && !r.error ? { ok: reached, problem: reached && !r.ok, detail: String(r.detail || r.status || ''), version: String(r.version || '') }
    : { ok: false, problem: false, detail: String((r && r.error) || ''), version: '' };
  _wizIntegPaint();
}

function _wizIntegFinish(st, body) {
  const c = _wizIntegOf(st);
  let host = '';
  try { host = new URL(st.url).origin; } catch (_) { host = ''; }
  const v = st.verdict;
  _wizList(body, [
    ['Service', c.label || st.type],
    ['Name', st.name],
    ['Address', host || '—'],
    ['Test', v ? (v.ok ? 'Reachable' : 'Not reachable') : 'Not tested'],
  ]);
  if (!v) body.appendChild(_wizNode('div', 'hint mt-8', 'It was not tested. A wrong address shows up as a red tile at the first check.'));
  else if (!v.ok) body.appendChild(_wizNode('div', 'hint mt-8', 'The test did not pass. You can still add it and fix it from its card.'));
}

async function _wizIntegAdd(st, w) {
  const data = await api('GET', '/integrations');
  if (!data || data.error) { _wizMsg('Save failed', ''); return false; }
  const list = Array.isArray(data.integrations) ? data.integrations.slice() : [];
  list.push(_wizIntegInst(st));
  const r = await api('POST', '/integrations', { integrations: list });
  if (!r || !r.ok) { _wizMsg((r && r.error) || 'Save failed', ''); return false; }
  w.finished = true;
  // the page's own list gets the instance the server made (it has its id now) and nothing else of it is touched
  if (document.getElementById('integrations-list') && typeof _integrations !== 'undefined') {
    try {
      _readIntegrationCards();
      const after = await api('GET', '/integrations');
      const have = new Set(_integrations.map(x => x.id).filter(Boolean));
      ((after && after.integrations) || []).forEach(x => { if (x && !have.has(x.id)) _integrations.push(x); });
      renderIntegrations();
    } catch (_) { /* the page shows it at the next load */ }
  }
  toast('Integration added', 'success');
  return true;
}

// ── "Set up email" ────────────────────────────────────────────────────────────────────────────────────────────────────────
// Which mail service sends the alerts, its address and login, who receives them, a test that sends a real message with what was typed, and which
// events are e-mailed. The server tests settings that are not saved, so nothing is stored before the last step: a wrong password or port never
// replaces settings that work. The last step saves the keys the form in Settings saves and puts them in that form's boxes, so a later Save there
// does not undo them. host, port and tls are what the service documents. `user` is a login that is the same for everyone, `auth: false` marks a
// server that may take mail with no login, `verify: false` one whose certificate is its own, `match` how a saved host is recognised.
const _WIZ_SMTP = {
  gmail: { name: 'Gmail or Google Workspace', host: 'smtp.gmail.com', port: 587, tls: 'starttls', example: 'you@gmail.com', match: /^smtp\.gmail\.com$/i,
    note: 'Google asks for an app password here, not your account password. Turn on 2-Step Verification for the account, then create an app password for mail. The user name is the full address.' },
  microsoft: { name: 'Microsoft 365', host: 'smtp.office365.com', port: 587, tls: 'starttls', example: 'mailbox@your-company.com', match: /^smtp\.office365\.com$/i,
    note: 'An administrator has to switch on SMTP sign-in for the mailbox. Microsoft announced on 27 January 2026 that password sign-in for SMTP is switched off by default in existing tenants at the end of December 2026 (an administrator can switch it back on), is not available by default in tenants created after that, where OAuth is the supported method, and gets a final removal date in the second half of 2027. This server signs in with a password only. The user name is the mailbox address, and the From address must be that mailbox.' },
  fastmail: { name: 'Fastmail', host: 'smtp.fastmail.com', port: 587, tls: 'starttls', example: 'you@fastmail.com', match: /^smtp\.fastmail\.com$/i,
    note: 'Create an app password with SMTP access under Settings, Privacy & Security. Your normal password does not work here. The user name is the full address.' },
  proton: { name: 'Proton Mail Bridge', host: '127.0.0.1', port: 1025, tls: 'starttls', verify: false, example: 'you@proton.me', port_match: 1025,
    note: 'Proton Mail Bridge has to run on the machine this server runs on. Use the user name and password that Bridge shows for the account, not your Proton password. If the connection fails, copy the host, port and security setting from Bridge.' },
  brevo: { name: 'Brevo', host: 'smtp-relay.brevo.com', port: 587, tls: 'starttls', example: 'a1b2c3001@smtp-brevo.com', match: /^smtp-relay\.brevo\.com$/i,
    note: "Use the SMTP login and an SMTP key from the SMTP tab of Brevo's SMTP & API settings. An API key does not work. The From address must be a sender you verified in Brevo." },
  mailgun: { name: 'Mailgun', host: 'smtp.mailgun.org', port: 587, tls: 'starttls', example: 'postmaster@mg.example.com', match: /^smtp\.(eu\.)?mailgun\.org$/i,
    note: 'Use the SMTP login of your sending domain, which looks like postmaster@your-domain, and its SMTP password. An API key does not work. An account in the EU region uses the server smtp.eu.mailgun.org.' },
  sendgrid: { name: 'SendGrid', host: 'smtp.sendgrid.net', port: 587, tls: 'starttls', user: 'apikey', example: 'apikey', match: /^smtp\.sendgrid\.net$/i,
    note: 'The user name is the word apikey. The password is an API key that may send mail. The From address must be a sender you verified in SendGrid.' },
  ses: { name: 'Amazon SES', host: 'email-smtp.us-east-1.amazonaws.com', port: 587, tls: 'starttls', example: 'AKIAXXXXXXXXXXXXXXXX', match: /^email-smtp\.[a-z0-9-]+\.amazonaws\.com$/i,
    note: 'Replace the region in the server name with yours. Use the SMTP credentials made in the SES console, not your AWS access keys. The From address has to be verified in SES, and a new account can only send to verified addresses until AWS lifts that limit.' },
  own: { name: 'Another mail server', host: '', port: 587, tls: 'starttls', auth: false, example: 'ops@example.com',
    note: 'Use the address of your mail server and the login it gave you. Leave the user name empty if it takes mail from this server without one. If its certificate is self-signed, turn the certificate check off.' },
  local: { name: 'A mail relay on this server', host: '127.0.0.1', port: 25, tls: 'plain', auth: false, example: '', port_match: 25,
    note: 'A mail server on this machine that takes local mail without a login, such as Postfix or Exim. Nothing is encrypted on the way, so use it only for the machine itself.' },
};
const _WIZ_SMTP_GROUPS = [
  ['Mail accounts', ['gmail', 'microsoft', 'fastmail', 'proton']],
  ['Sending services', ['brevo', 'mailgun', 'sendgrid', 'ses']],
  ['Your own server', ['own', 'local']],
];
const _WIZ_SMTP_TLS = [['starttls', 'STARTTLS (587)'], ['tls', 'Implicit TLS (465)'], ['plain', 'Plain (25)']];
const _WIZ_SMTP_PORT = { starttls: 587, tls: 465, plain: 25 };
const _WIZ_SMTP_EVENTS = [
  { v: 'serious', t: 'Only the serious events', d: 'The ones the Alerts page rates critical or high, such as a host offline or a service down, and their recoveries.' },
  { v: 'all', t: 'Every event the webhooks send', d: 'A lot of mail: every event that goes to a webhook is sent by email too.' },
  { v: 'keep', t: 'Only the events I choose in Settings', d: 'Nothing is sent until you tick events in the table under Settings, Notifications.' },
];
const _WIZ_SMTP_ADDR = /^[^\s@]+@[^\s@]+$/;

function _wizSmtpDef() {
  return {
    title: 'Set up email',
    init: () => ({ cfg: null, provider: '', host: '', port: 587, tls: 'starttls', verify: true, user: '', pass: '', from: '', rec: '', events: 'serious',
                   touched: {}, saved: null, passSaved: false, passEnv: false, verdict: null, sending: false }),
    steps: [
      { label: 'Service', render: _wizSmtpService, validate: st => (st.provider ? null : { msg: 'Choose a service', focus: 'wiz-svc' }) },
      { label: 'Connection', render: _wizSmtpConnection, validate: _wizSmtpCheck },
      { label: 'Recipients', render: _wizSmtpRecipients, validate: _wizSmtpCheckRecipients },
      { label: 'Test', render: _wizSmtpTest },
      { label: 'Finish', render: _wizSmtpFinish, primary: 'Turn it on', next: _wizSmtpOn },
    ],
  };
}

// Which service a saved server belongs to: the one whose address it is, else "another mail server".
function _wizSmtpGuess(host, port) {
  const h = String(host || '').trim();
  if (!h) return '';
  for (const k of Object.keys(_WIZ_SMTP)) {
    const p = _WIZ_SMTP[k];
    if (p.match && p.match.test(h)) return k;
    if (p.port_match && p.host === h.toLowerCase() && p.port_match === Number(port)) return k;
  }
  return 'own';
}

// The saved settings become the starting point, as values that were not typed: a service picked later replaces them.
function _wizSmtpFill(st) {
  const c = st.cfg || {};
  st.passSaved = !!c.smtp_password_set;
  st.passEnv = !!c.smtp_password_from_env;
  if (Object.values(c.email_events || {}).some(Boolean)) st.events = 'keep';       // events that are ticked already are the person's choice
  if (!String(c.smtp_host || '').trim()) return;
  st.saved = { host: String(c.smtp_host).trim(), user: String(c.smtp_username || '').trim() };
  st.host = st.saved.host;
  st.port = Number(c.smtp_port) || 587;
  st.tls = c.smtp_tls || 'starttls';
  st.verify = c.smtp_verify_tls !== false;
  st.user = st.saved.user;
  st.from = String(c.smtp_from || '');
  st.rec = String(c.smtp_recipients || '');
  st.provider = _wizSmtpGuess(st.host, st.port);
}

function _wizSmtpService(st, body) {
  if (!st.cfg) {
    body.appendChild(_wizNode('div', 'hint', 'Loading…'));
    api('GET', '/config').catch(() => null).then(c => {
      st.cfg = (c && !c.error) ? c : {};
      _wizSmtpFill(st);
      if (_wiz && _wiz.st === st && _wiz.i === 0) _wizShow(0);
    });
    return;
  }
  if (st.saved) body.appendChild(_wizNode('div', 'hint mb-12', 'Email is already set up. This guide replaces those settings.'));
  const items = [];
  _WIZ_SMTP_GROUPS.forEach(([g, list]) => { items.push({ g }); list.forEach(k => items.push({ v: k, t: _WIZ_SMTP[k].name })); });
  _wizChoices(body, {
    legend: 'Which service sends the mail?', name: 'wiz-svc', value: st.provider, items,
    onPick: v => {
      if (v === st.provider) return;
      st.provider = v;
      st.verdict = null;
      const p = _WIZ_SMTP[v], t = st.touched;      // what was typed on the next step stays
      if (!t.host) st.host = p.host;
      if (!t.port) st.port = p.port;
      if (!t.tls) st.tls = p.tls;
      if (!t.verify) st.verify = p.verify !== false;
      if (!t.user) st.user = p.user || '';
    },
  });
}

// A password may be left empty when one is saved for this same server and user, or when the server's environment holds it.
function _wizSmtpPassOk(st) {
  if (st.pass !== '' || st.passEnv) return true;
  return st.passSaved && !!st.saved && st.host.trim() === st.saved.host && st.user.trim() === st.saved.user;
}

function _wizSmtpConnection(st, body) {
  const p = _WIZ_SMTP[st.provider];
  body.appendChild(_wizNode('div', 'hint mb-12', p.note));
  const typed = k => v => { st[k] = v; st.touched[k] = true; st.verdict = null; };
  _wizField(body, { id: 'wiz-host', label: 'SMTP host', value: st.host, placeholder: 'smtp.example.com', maxlength: 255, onInput: typed('host') });
  const row = _wizNode('div', 'settings-row');
  const portBox = _wizField(row, { id: 'wiz-port', label: 'Port', type: 'number', value: String(st.port), onInput: typed('port') });
  portBox.min = 1;
  portBox.max = 65535;
  _wizField(row, {
    id: 'wiz-tls', label: 'TLS mode', value: st.tls, options: _WIZ_SMTP_TLS,
    onInput: v => {
      typed('tls')(v);
      // the port follows the mode while it is still one of the usual ports, so 465 does not stay with STARTTLS
      if (!st.touched.port || Object.values(_WIZ_SMTP_PORT).includes(Number(st.port))) { st.port = _WIZ_SMTP_PORT[v]; portBox.value = String(st.port); }
    },
  });
  Array.from(row.children).forEach(g => g.classList.add('flex-1'));
  body.appendChild(row);
  _wizField(body, {
    id: 'wiz-user', label: 'Username', value: st.user, placeholder: p.example, maxlength: 255, onInput: typed('user'),
    hint: p.auth === false ? 'Leave empty if the server needs no login.' : '',
  });
  const hint = st.passEnv ? "The password is read from the server's environment (RP_SMTP_PASSWORD), so this box is not used."
    : (st.passSaved ? 'Leave empty to keep the saved password. Type it again if you change the server or the user name.' : '');
  _wizField(body, { id: 'wiz-pass', label: 'Password', type: 'password', value: st.pass, maxlength: 1024, onInput: typed('pass'), hint });
  _wizField(body, { id: 'wiz-from', label: 'From address', type: 'email', value: st.from, placeholder: 'remotepower@example.com', maxlength: 255, onInput: typed('from') });
  _wizVerifyBox(st, body);
}

function _wizSmtpCheck(st) {
  const p = _WIZ_SMTP[st.provider] || {};
  if (!st.host.trim()) return { msg: 'Set the server first', focus: 'wiz-host' };
  const port = Number(st.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return { msg: 'Set a port from 1 to 65535', focus: 'wiz-port' };
  const user = st.user.trim();
  if (p.auth !== false && !user) return { msg: 'This field is needed', focus: 'wiz-user' };
  if (user && !_wizSmtpPassOk(st)) return { msg: 'This field is needed', focus: 'wiz-pass' };
  const from = st.from.trim();
  if (!from) return { msg: 'Set the From address first', focus: 'wiz-from' };
  if (!_WIZ_SMTP_ADDR.test(from)) return { msg: 'That is not an address', focus: 'wiz-from' };
  return null;
}

function _wizSmtpList(st) { return String(st.rec || '').split(/[,;\s]+/).map(x => x.trim()).filter(Boolean); }

function _wizSmtpRecipients(st, body) {
  body.appendChild(_wizNode('div', 'wiz-q', 'Who should get the alerts?'));
  _wizField(body, {
    id: 'wiz-rec', label: 'Recipients', value: st.rec, placeholder: 'ops@example.com, admin@example.com', maxlength: 2000,
    hint: 'Separate addresses with a comma. The test message goes to the first one.', onInput: v => { st.rec = v; st.verdict = null; },
  });
}

function _wizSmtpCheckRecipients(st) {
  const list = _wizSmtpList(st);
  if (!list.length) return { msg: 'Add an address to send alerts to', focus: 'wiz-rec' };
  if (list.some(a => !_WIZ_SMTP_ADDR.test(a))) return { msg: 'That is not an address', focus: 'wiz-rec' };
  return null;
}

// The connection as the settings form keeps it. A password that was not typed is not sent, so the saved one stays.
function _wizSmtpSettings(st) {
  const o = { smtp_host: st.host.trim(), smtp_port: Number(st.port), smtp_tls: st.tls, smtp_verify_tls: !!st.verify, smtp_from: st.from.trim(), smtp_username: st.user.trim() };
  if (o.smtp_username && st.pass !== '') o.smtp_password = st.pass;
  return o;
}

function _wizSmtpTest(st, body) {
  body.appendChild(_wizNode('div', 'wiz-q', 'Send a real message to the first address to check that the settings work.'));
  const row = _wizNode('div', 'row-8');
  const b = _wizNode('button', 'btn-primary', 'Send test email');
  b.type = 'button';
  b.id = 'wiz-test';
  b.setAttribute('data-action', 'wizSmtpTest');
  row.appendChild(b);
  body.appendChild(row);
  const out = _wizNode('div', 'wiz-result');
  out.id = 'wiz-result';
  out.setAttribute('role', 'status');
  body.appendChild(out);
  _wizSmtpPaint();
}

// What the server said, as one hint. A message that two causes can produce names neither: a timeout and a closed connection are both what a
// port with the wrong TLS mode looks like, so those hints list what to check.
function _wizSmtpHint(detail) {
  const t = String(detail || '').toLowerCase();
  if (/auth failed|authentication|\b53[045]\b|username and password/.test(t) && !/starttls/.test(t)) return 'The server refused the user name or password, or wants one. Check them against the note on the Connection step.';
  if (/auth extension not supported/.test(t)) return 'The server offers no login on this connection. Try STARTTLS or Implicit TLS, or leave the user name empty.';
  if (/does not advertise starttls/.test(t)) return 'The server does not offer STARTTLS on this port. Try Implicit TLS on port 465, or check the port.';
  if (/certificate|verify failed|self.signed/.test(t)) return "The server's certificate is not trusted. If the server is your own, turn off the certificate check.";
  if (/timed out|timeout/.test(t)) return 'No answer in time. Check the server name and the port, that a firewall does not block the port from this server (many hosting providers block port 25), and that the TLS mode fits the port.';
  if (/wrong_version_number|wrong version number|eof occurred|unexpectedly closed|sslerror|ssl:/.test(t)) return 'The connection was closed or the TLS handshake failed. Check that the TLS mode fits the port: 587 usually takes STARTTLS and 465 Implicit TLS.';
  if (/gaierror|name or service not known|nodename nor servname|name resolution|getaddrinfo/.test(t)) return 'The server name was not found from this server. Check how it is spelled.';
  if (/connection refused|errno 111|connectionrefused/.test(t)) return 'Nothing answered on that port. Check the port, and that the mail server is running.';
  if (/senderrefused|sender address|sender not|not authori[sz]ed to send|from address/.test(t)) return 'The server did not accept the From address. Use an address this account may send from.';
  if (/recipientsrefused|relay access denied|recipient/.test(t)) return 'The server did not accept the recipient. It may not relay mail for this account or this address.';
  return 'Check the settings, and that this server can reach the mail server.';
}

function _wizSmtpPaint() {
  const out = document.getElementById('wiz-result');
  const w = _wiz;
  if (!out || !w) return;
  const v = w.st.verdict;
  out.textContent = '';
  if (w.st.sending) { out.className = 'wiz-result c-muted'; out.textContent = 'Sending…'; return; }
  if (!v) { out.className = 'wiz-result'; return; }
  const top = (cls, state, chip) => {
    out.className = 'wiz-result ' + cls;
    const row = _wizNode('div', 'row-8-center');
    row.appendChild(_wizNode('span', 'wiz-state', state));
    if (chip) row.appendChild(_wizNode('span', 'wiz-chip ff-mono', chip));
    out.appendChild(row);
  };
  if (v.kind === 'ok') {
    top('c-green', 'Sent', v.to);
    out.appendChild(_wizNode('div', 'hint mt-6', 'The server accepted the message. Check the inbox, and the spam folder.'));
  } else if (v.kind === 'fail') {
    top('c-red', 'Not sent', '');
    out.appendChild(_wizNode('div', 'hint mt-6', _wizSmtpHint(v.detail)));
    if (v.detail) out.appendChild(_wizNode('div', 'hint ff-mono', v.detail));
  } else {
    top('c-red', 'Not sent', '');
    out.appendChild(_wizNode('div', 'hint mt-6', 'The test could not be run. Try again.'));
  }
}

// Sends one message through what was typed. The server lays the settings over a copy of the saved ones and stores nothing.
async function wizSmtpTest() {
  const w = _wiz;
  if (!w || w.busy) return;
  const st = w.st;
  const to = _wizSmtpList(st)[0];
  st.verdict = null;                      // the answer of the last test goes, so a new one is not mistaken for it
  st.sending = true;
  _wizSmtpPaint();
  const btn = document.getElementById('wiz-test');
  if (btn) btn.disabled = true;
  _wizBusy(true);
  let r = null;
  try {
    r = await api('POST', '/smtp/test', { recipient: to, settings: _wizSmtpSettings(st) });
  } catch (_) {
    r = null;
  } finally {
    st.sending = false;
    if (_wiz === w) _wizBusy(false);
    const again = document.getElementById('wiz-test');
    if (again) again.disabled = false;
  }
  if (_wiz !== w) return;
  if (r && r.ok === true) st.verdict = { kind: 'ok', to };
  else if (r && (r.error || r.ok === false)) st.verdict = { kind: 'fail', detail: String(r.error || '') };
  else st.verdict = { kind: 'none' };
  _wizSmtpPaint();
}

function _wizSmtpFinish(st, body) {
  _wizChoices(body, { legend: 'What should be sent by email?', name: 'wiz-ev', value: st.events, items: _WIZ_SMTP_EVENTS, onPick: v => { st.events = v; } });
  const ok = st.verdict && st.verdict.kind === 'ok';
  _wizList(body, [
    ['Service', _WIZ_SMTP[st.provider].name],
    ['Server', st.host.trim() + ':' + st.port],
    ['From address', st.from.trim()],
    ['Recipients', _wizSmtpList(st).join(', ')],
    ['Test', ok ? 'Sent' : 'Not tested'],
  ]);
  if (!ok) body.appendChild(_wizNode('div', 'hint mt-8', 'It was not tested. A wrong setting goes unnoticed until the first alert needs it.'));
}

// Saves what the form in Settings saves for email, with email switched on, and the events that were asked for.
async function _wizSmtpOn(st, w) {
  const cfg = await api('GET', '/config');
  if (!cfg || cfg.error) { _wizMsg('Save failed', ''); return false; }
  const body = Object.assign({ smtp_enabled: true, smtp_recipients: _wizSmtpList(st).join(', ') }, _wizSmtpSettings(st));
  let events = null;
  if (st.events !== 'keep') {
    events = Object.assign({}, cfg.email_events || {});
    const meta = cfg._meta || {};
    const pick = st.events === 'all' ? Object.keys(cfg.webhook_events || {}).filter(ev => cfg.webhook_events[ev]) : (meta.serious_events || []);
    pick.forEach(ev => { events[ev] = true; });
    body.email_events = events;
  }
  const r = await api('POST', '/config', body);
  if (!r || r.error || r.ok === false) { _wizMsg((r && r.error) || 'Save failed', ''); return false; }
  w.finished = true;
  _wizSmtpSync(st, events);
  toast('Email turned on', 'success');
  return true;
}

// The boxes of the Settings form take what was saved, so a later Save of that form writes the same values and not the ones it showed before.
function _wizSmtpSync(st, events) {
  const set = (id, v) => { const e = document.getElementById(id); if (e) e.value = v; };
  const on = (id, v) => { const e = document.getElementById(id); if (e) e.checked = !!v; };
  on('cfg-smtp-enabled', true);
  set('cfg-smtp-host', st.host.trim());
  set('cfg-smtp-port', String(Number(st.port)));
  set('cfg-smtp-tls', st.tls);
  on('cfg-smtp-verify-tls', st.verify);
  set('cfg-smtp-from', st.from.trim());
  set('cfg-smtp-username', st.user.trim());
  set('cfg-smtp-password', '');
  set('cfg-smtp-recipients', _wizSmtpList(st).join(', '));
  const badge = document.getElementById('cfg-smtp-pw-set-badge');
  if (badge && (st.pass !== '' || st.passSaved)) badge.classList.remove('d-none');
  if (events) document.querySelectorAll('#event-toggle-table .toggle-email').forEach(cb => { cb.checked = events[cb.dataset.event] === true; });
}

// ── "Set up single sign-on" ───────────────────────────────────────────────────────────────────────────────────────────────
// OpenID Connect against the identity provider the person runs: which one (a note on what to create there), the values to copy into it, the issuer
// and the client, who is an administrator, and a check that this server can read the provider's settings. The server checks an issuer that is not
// saved yet, so nothing is stored before the last step. RemotePower reads the user name, the email and the groups from the ID token, and sends the
// client secret in the request body: the notes say what each provider needs for that. An account is made for everyone the provider lets in, as a
// viewer, and the guide says so twice. `match` is how a saved issuer is recognised.
const _WIZ_OIDC = {
  authentik: { name: 'Authentik', issuer: 'https://authentik.example.com/application/o/remotepower/', match: /\/application\/o\//i,
    note: 'In authentik, create an OAuth2/OpenID provider and an application that uses it, with client type Confidential and the redirect address below. The issuer is https://your-authentik/application/o/<slug>/ with the slash at the end. authentik sends the groups with the profile scope, and puts them in the ID token only when Include claims in id_token is on for the provider, so check that setting.' },
  authelia: { name: 'Authelia', issuer: 'https://auth.example.com',
    note: 'In Authelia, add a client under identity_providers, oidc, clients with the redirect address below and token_endpoint_auth_method client_secret_post, because RemotePower sends the secret in the request body. Add a claims policy that puts the groups into the ID token. The issuer is the address of Authelia itself.' },
  keycloak: { name: 'Keycloak', issuer: 'https://keycloak.example.com/realms/home', match: /\/realms\//i,
    note: 'In Keycloak, create an OpenID Connect client with Client authentication on, the standard flow and the redirect address below. Add a Group Membership mapper to it with the claim name groups, full group path off and Add to ID token on. The issuer is https://your-keycloak/realms/<realm>.' },
  pocketid: { name: 'Pocket ID', issuer: 'https://id.example.com',
    note: 'In Pocket ID, add an OIDC client with the callback address below. The client secret is shown once, so copy it before you leave the page. A new client lets nobody in: on its Access tab, choose the groups whose members may sign in, or All Users. Pocket ID sends the names of the groups, not their display names, in the groups claim. The issuer is the address of Pocket ID itself.' },
  zitadel: { name: 'Zitadel', issuer: 'https://your-instance.zitadel.cloud', match: /zitadel/i,
    note: 'In Zitadel, create a Web application with the authorization code flow and the redirect address below, and choose Post as the authentication method, because RemotePower sends the secret in the request body. Zitadel does not send a claim named groups or roles by itself, so everyone stays a viewer here until an Action adds one. The issuer is the address of your Zitadel instance.' },
  other: { name: 'Another OpenID Connect provider', issuer: 'https://auth.example.com',
    note: 'Create a confidential client, a server-side web application with a client secret, that uses the authorization code flow with the redirect address below. RemotePower sends the secret in the request body and reads the user name, the email and the groups from the ID token. The issuer is the address that serves /.well-known/openid-configuration.' },
};
const _WIZ_OIDC_SCOPES = 'openid profile email groups';

function _wizOidcDef() {
  return {
    title: 'Set up single sign-on',
    init: () => ({ cfg: null, provider: '', issuer: '', cid: '', secret: '', scopes: _WIZ_OIDC_SCOPES, admin: '', map: '', saved: null, secretSaved: false,
                   touched: {}, verdict: null, sending: false }),
    steps: [
      { label: 'Provider', render: _wizOidcProvider, validate: st => (st.provider ? null : { msg: 'Choose a service', focus: 'wiz-idp' }) },
      { label: 'Register', render: _wizOidcRegister },
      { label: 'Connection', render: _wizOidcConnection, validate: _wizOidcCheck },
      { label: 'Roles', render: _wizOidcRoles, validate: _wizOidcCheckRoles },
      { label: 'Test', render: _wizOidcTest },
      { label: 'Finish', render: _wizOidcFinish, primary: 'Turn it on', next: _wizOidcOn },
    ],
  };
}

function _wizOidcGuess(issuer) {
  const i = String(issuer || '').trim();
  if (!i) return '';
  for (const k of Object.keys(_WIZ_OIDC)) if (_WIZ_OIDC[k].match && _WIZ_OIDC[k].match.test(i)) return k;
  return 'other';
}

// The saved settings become the starting point, as values that were not typed.
function _wizOidcFill(st) {
  const c = st.cfg || {};
  st.secretSaved = !!c.oidc_client_secret_set;
  const m = c.sso_group_roles && typeof c.sso_group_roles === 'object' ? c.sso_group_roles : {};
  st.map = Object.keys(m).map(g => g + '=' + m[g]).join('\n');
  if (!String(c.oidc_issuer || '').trim()) return;
  st.saved = { issuer: String(c.oidc_issuer).trim(), cid: String(c.oidc_client_id || '').trim() };
  st.issuer = st.saved.issuer;
  st.cid = st.saved.cid;
  st.scopes = String(c.oidc_scopes || '').trim() || _WIZ_OIDC_SCOPES;
  st.admin = String(c.oidc_admin_group || '');
  st.provider = _wizOidcGuess(st.issuer);
}

function _wizOidcProvider(st, body) {
  if (!st.cfg) {
    body.appendChild(_wizNode('div', 'hint', 'Loading…'));
    api('GET', '/config').catch(() => null).then(c => {
      st.cfg = (c && !c.error) ? c : {};
      _wizOidcFill(st);
      if (_wiz && _wiz.st === st && _wiz.i === 0) _wizShow(0);
    });
    return;
  }
  if (st.saved) body.appendChild(_wizNode('div', 'hint mb-12', 'Single sign-on is already set up. This guide replaces those settings.'));
  _wizChoices(body, {
    legend: 'Which identity provider do you use?', name: 'wiz-idp', value: st.provider,
    items: Object.keys(_WIZ_OIDC).map(k => ({ v: k, t: _WIZ_OIDC[k].name })),
    onPick: v => { if (v !== st.provider) { st.provider = v; st.verdict = null; } },
  });
}

function _wizOidcRegister(st, body) {
  body.appendChild(_wizNode('div', 'wiz-q', 'Create an application for RemotePower in your identity provider with these values.'));
  body.appendChild(_wizNode('div', 'hint mb-12', _WIZ_OIDC[st.provider].note));
  _wizCommand(body, 'wiz-oidc-redirect', 'Redirect address', '', window.location.origin + '/api/auth/oidc/callback');
  _wizCommand(body, 'wiz-oidc-scopes', 'Scopes', '', _WIZ_OIDC_SCOPES);
  body.appendChild(_wizNode('div', 'hint', 'The client is confidential: it has a client secret that you copy into the next step.'));
  body.appendChild(_wizNode('div', 'hint mt-8', 'Everyone the provider lets in gets a viewer account here. Limit who may use the application in the provider.'));
}

// The secret may stay empty when one is saved for this same issuer and client, so a secret is never sent to another provider by accident.
function _wizOidcSecretOk(st) {
  if (st.secret !== '') return true;
  return st.secretSaved && !!st.saved && st.issuer.trim() === st.saved.issuer && st.cid.trim() === st.saved.cid;
}

function _wizOidcConnection(st, body) {
  const p = _WIZ_OIDC[st.provider];
  const typed = k => v => { st[k] = v; st.touched[k] = true; st.verdict = null; };
  _wizField(body, { id: 'wiz-issuer', label: 'Issuer URL', value: st.issuer, placeholder: p.issuer, maxlength: 500, onInput: typed('issuer') });
  _wizField(body, { id: 'wiz-cid', label: 'Client ID', value: st.cid, maxlength: 255, onInput: typed('cid') });
  _wizField(body, {
    id: 'wiz-secret', label: 'Client Secret', type: 'password', value: st.secret, maxlength: 1024, onInput: typed('secret'),
    hint: st.secretSaved ? 'Leave empty to keep the saved secret. Type it again if you change the issuer or the client ID.' : '',
  });
  _wizField(body, { id: 'wiz-scopes', label: 'Scopes', value: st.scopes, placeholder: _WIZ_OIDC_SCOPES, maxlength: 255, onInput: typed('scopes') });
}

function _wizOidcCheck(st) {
  const issuer = st.issuer.trim();
  if (!issuer) return { msg: 'Set the issuer first', focus: 'wiz-issuer' };
  if (!/^https?:\/\/[^\s/]+/i.test(issuer)) return { msg: 'The issuer must start with http:// or https://', focus: 'wiz-issuer' };
  if (!st.cid.trim()) return { msg: 'Set the client ID first', focus: 'wiz-cid' };
  if (!_wizOidcSecretOk(st)) return { msg: 'This field is needed', focus: 'wiz-secret' };
  if (!st.scopes.split(/[\s,]+/).includes('openid')) return { msg: 'The scopes must include openid', focus: 'wiz-scopes' };
  return null;
}

function _wizOidcRoles(st, body) {
  body.appendChild(_wizNode('div', 'wiz-q', 'Who is an administrator?'));
  body.appendChild(_wizNode('div', 'hint mb-12', 'RemotePower reads the groups from the ID token, from a claim named groups or roles. Check in your provider that it puts them there.'));
  _wizField(body, {
    id: 'wiz-admin', label: 'Admin group (optional)', value: st.admin, placeholder: 'remotepower-admins', maxlength: 255, onInput: v => { st.admin = v; },
    hint: 'Members of this group get the admin role. Everyone else gets viewer unless the map below says otherwise.',
  });
  _wizField(body, {
    id: 'wiz-map', label: 'Group → role map (optional)', value: st.map, rows: 3, placeholder: 'sec-ops=auditor\nfinance-team=finance', onInput: v => { st.map = v; },
    hint: 'One group=role per line, for example sec-ops=auditor. The same map is used for SAML.',
  });
}

function _wizOidcCheckRoles(st) {
  const bad = String(st.map || '').split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#')).some(l => l.indexOf('=') <= 0 || l.slice(l.indexOf('=') + 1).trim() === '');
  return bad ? { msg: 'Each line needs group=role', focus: 'wiz-map' } : null;
}

function _wizOidcTest(st, body) {
  body.appendChild(_wizNode('div', 'wiz-q', 'Check that this server can reach the provider and read its settings.'));
  const row = _wizNode('div', 'row-8');
  const b = _wizNode('button', 'btn-primary', 'Test discovery');
  b.type = 'button';
  b.id = 'wiz-test';
  b.setAttribute('data-action', 'wizOidcTest');
  row.appendChild(b);
  body.appendChild(row);
  const out = _wizNode('div', 'wiz-result');
  out.id = 'wiz-result';
  out.setAttribute('role', 'status');
  body.appendChild(out);
  _wizOidcPaint();
}

// What the discovery document says about the things RemotePower depends on, as lines to show. A list that the provider does not give says
// nothing, so nothing is claimed about it.
function _wizOidcChecks(st, r) {
  const out = [];
  const want = st.scopes.split(/[\s,]+/).filter(Boolean);
  if (Array.isArray(r.scopes_supported)) {
    const missing = want.filter(s => !r.scopes_supported.includes(s));
    if (missing.length) out.push({ text: 'The provider does not list these scopes:', mono: missing.join(' ') });
  }
  const methods = r.token_endpoint_auth_methods_supported;
  if (Array.isArray(methods) && methods.length && !methods.includes('client_secret_post')) {
    out.push({ text: 'The provider does not list client_secret_post for the token request, and RemotePower sends the secret in the request body.' });
  }
  const grants = r.grant_types_supported;
  if (Array.isArray(grants) && grants.length && !grants.includes('authorization_code')) out.push({ text: 'The provider does not list the authorization code flow.' });
  const mine = window.location.origin + '/api/auth/oidc/callback';
  if (r.redirect_uri_needed && r.redirect_uri_needed !== mine) {
    out.push({ text: 'The server sees the callback address differently from this page. Register the one below if it is not the address on the second step.', mono: r.redirect_uri_needed });
  }
  return out;
}

function _wizOidcPaint() {
  const out = document.getElementById('wiz-result');
  const w = _wiz;
  if (!out || !w) return;
  const v = w.st.verdict;
  out.textContent = '';
  if (w.st.sending) { out.className = 'wiz-result c-muted'; out.textContent = 'Testing…'; return; }
  if (!v) { out.className = 'wiz-result'; return; }
  const top = (cls, state) => {
    out.className = 'wiz-result ' + cls;
    const row = _wizNode('div', 'row-8-center');
    row.appendChild(_wizNode('span', 'wiz-state', state));
    out.appendChild(row);
  };
  if (v.kind === 'ok') {
    top(v.checks.length ? 'c-amber' : 'c-green', 'Reachable');
    out.appendChild(_wizNode('div', 'hint mt-6', 'The provider answered and its settings were read.'));
    v.checks.forEach(c => {
      out.appendChild(_wizNode('div', 'hint mt-6', c.text));
      if (c.mono) out.appendChild(_wizNode('div', 'hint ff-mono', c.mono));
    });
  } else {
    top('c-red', 'Not reachable');
    out.appendChild(_wizNode('div', 'hint mt-6', 'Check the issuer, and that this server can reach it.'));
    if (v.detail) out.appendChild(_wizNode('div', 'hint ff-mono', v.detail));
  }
}

// Asks the server to read the discovery document of the issuer as typed. Nothing is saved.
async function wizOidcTest() {
  const w = _wiz;
  if (!w || w.busy) return;
  const st = w.st;
  st.verdict = null;
  st.sending = true;
  _wizOidcPaint();
  const btn = document.getElementById('wiz-test');
  if (btn) btn.disabled = true;
  _wizBusy(true);
  let r = null;
  try {
    r = await api('POST', '/auth/oidc/test', { issuer: st.issuer.trim() });
  } catch (_) {
    r = null;
  } finally {
    st.sending = false;
    if (_wiz === w) _wizBusy(false);
    const again = document.getElementById('wiz-test');
    if (again) again.disabled = false;
  }
  if (_wiz !== w) return;
  if (r && r.ok === true) st.verdict = { kind: 'ok', checks: _wizOidcChecks(st, r) };
  else st.verdict = { kind: 'fail', detail: String((r && r.error) || '') };
  _wizOidcPaint();
}

function _wizOidcFinish(st, body) {
  const v = st.verdict;
  const mapLines = String(st.map || '').split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#')).length;
  _wizList(body, [
    ['Service', _WIZ_OIDC[st.provider].name],
    ['Issuer URL', st.issuer.trim()],
    ['Client ID', st.cid.trim()],
    ['Admin group (optional)', st.admin.trim() || '—'],
    ['Group → role map (optional)', String(mapLines)],
    ['Test', v && v.kind === 'ok' ? 'Reachable' : 'Not tested'],
  ]);
  if (!(v && v.kind === 'ok')) body.appendChild(_wizNode('div', 'hint mt-8', 'It was not tested. A wrong issuer shows up as a failed sign-in.'));
  body.appendChild(_wizNode('div', 'hint mt-8', 'Turning it on adds a Sign in with SSO button to the sign-in page. Local accounts keep working, and anyone the provider lets in gets a viewer account.'));
  body.appendChild(_wizNode('div', 'hint mt-8', 'To try it, open the sign-in page in a private window. Keep this window signed in until it works.'));
}

// Saves what the OIDC card in Settings saves, with sign-in switched on. A secret that was not typed is not sent, so the saved one stays.
async function _wizOidcOn(st, w) {
  const body = { oidc_enabled: true, oidc_issuer: st.issuer.trim(), oidc_client_id: st.cid.trim(), oidc_scopes: st.scopes.trim() || _WIZ_OIDC_SCOPES,
                 oidc_admin_group: st.admin.trim(), sso_group_roles: _parseGroupRoleMap(st.map) };
  if (st.secret !== '') body.oidc_client_secret = st.secret;
  const r = await api('POST', '/config', body);
  if (!r || r.error || r.ok === false) { _wizMsg((r && r.error) || 'Save failed', ''); return false; }
  w.finished = true;
  _wizOidcSync(st, body);
  toast('Single sign-on turned on', 'success');
  return true;
}

// The OIDC card takes what was saved, so a later Save of that card writes the same values and not the ones it showed before.
function _wizOidcSync(st, body) {
  const set = (id, v) => { const e = document.getElementById(id); if (e) e.value = v; };
  const en = document.getElementById('oidc-enabled');
  if (en) en.checked = true;
  set('oidc-issuer', body.oidc_issuer);
  set('oidc-client-id', body.oidc_client_id);
  set('oidc-client-secret', '');
  set('oidc-scopes', body.oidc_scopes);
  set('oidc-admin-group', body.oidc_admin_group);
  set('sso-group-roles', Object.keys(body.sso_group_roles).map(g => g + '=' + body.sso_group_roles[g]).join('\n'));
}

const _WIZARDS = { enroll: _wizEnrollDef, notify: _wizNotifyDef, integration: _wizIntegDef, smtp: _wizSmtpDef, oidc: _wizOidcDef };

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
      { label: 'Checks', ids: ['mon-status-grp', 'mon-method-grp', 'mon-tls-grp', 'mon-latency-grp', 'mon-loss-grp', 'mon-body-grp', 'mon-json-grp', 'mon-mailtls-grp', 'mon-ntp-grp'] },
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
  'new-rollout-modal': {
    steps: [
      { label: 'What', ids: ['ro-name', 'ro-action', 'ro-script-row'] },
      { label: 'Rings', ids: ['ro-rings'] },
      { label: 'Safety', ids: ['ro-verify', 'ro-auto', 'ro-health-gate'] },
    ],
    check(n, q, panel) {
      if (n === 0) {
        if (!q('ro-name').value.trim()) return { msg: 'Name is required', focus: q('ro-name') };
        if (q('ro-action').value === 'script' && !q('ro-script').value) return { msg: 'Pick a saved script', focus: q('ro-script') };
      }
      if (n === 1) {
        // the rows the form's own save keeps: a value to resolve, or the ring that takes whatever the others left
        const rows = [...panel.querySelectorAll('#ro-rings .ro-ring')];
        if (!rows.some(r => r.querySelector('.ro-ring-value').value.trim() || r.querySelector('.ro-ring-type').value === 'remaining')) {
          const first = rows.find(r => r.querySelector('.ro-ring-type').value !== 'remaining');
          return { msg: 'Add at least one ring with a target', focus: first ? first.querySelector('.ro-ring-value') : null };
        }
      }
      return null;
    },
  },
  'device-profile-modal': {
    steps: [
      { label: 'What', ids: ['dp-name', 'dp-poll'] },
      { label: 'Watches', ids: ['dp-units', 'dp-logs', 'dp-drift'] },
      { label: 'Thresholds', ids: ['dp-mem-warn', 'dp-disk-warn', 'dp-diskio-warn', 'dp-iowait-warn', 'dp-steal-warn'] },
    ],
    check(n, q) {
      if (n === 0 && !q('dp-name').value.trim()) return { msg: 'Name required', focus: q('dp-name') };
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
