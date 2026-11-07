// app-imageautoupdate.js — the Automatic updates card on Containers, Image updates (8.0.0). Lazy: the Containers page loads it beside the hardening
// audit. Off by default; the card edits the policy, shows what the policy would do now, and lists the receipts of what it did.
// Text that came from a host or a registry is only ever put in with textContent or escHtml, never as markup.

let _iau = null;                      // the last answer of GET /api/image-updates/auto
let _iauRegistered = false;
let _iauWatched = false;
let _iauSeq = 0;                      // the number of the newest load: an older answer that lands after it is dropped
let _iauDirty = false;                // the form was changed by hand since the page was entered: a late answer does not overwrite it

// The words for the state of a receipt: [label, badge class].
const _IAU_STATE = {
  shadow:            ['Shadow', ''],
  queued:            ['Queued', ''],
  awaiting_approval: ['Waiting for approval', ''],
  ok:                ['Updated', 'ok'],
  not_updated:       ['Not updated', 'crit'],
  unhealthy:         ['Unhealthy', 'crit'],
  unverified:        ['Not verified', 'warn'],
  declined:          ['Declined', 'warn'],
  rollback_awaiting_approval: ['Waiting for approval to roll back', 'warn'],
  rolling_back:      ['Rolling back', 'warn'],
  rolled_back:       ['Rolled back', 'ok'],
  rollback_failed:   ['Rollback failed', 'crit'],
};

function _iauRegister() {
  if (_iauRegistered) return;
  _iauRegistered = true;
  tableCtl.register({
    name: 'iau-receipts',
    tbody: 'iau-receipts-tbody',
    sortHeaders: 'iau-receipts-thead',
    colspan: 5,
    columns: ['when', 'host', 'images', 'state', 'detail'],
    getColumns: (r) => ({ when: r.ts || 0, host: r.device_name || '', images: (r.refs || []).join(' '), state: r.state || '', detail: r.detail || '' }),
    match: () => true,
    row: (r) => {
      const st = _IAU_STATE[r.state] || [r.state || '', ''];
      return `<tr>
        <td class="hint-nowrap">${r.ts ? timeAgoHtml(r.ts) : '—'}</td>
        <td class="fw-500">${escHtml(r.device_name || r.device_id || '')}</td>
        <td class="mono-12">${(r.refs || []).map(escHtml).join('<br>')}</td>
        <td><span class="patch-badge ${st[1]}">${escHtml(st[0])}</span></td>
        <td class="hint">${escHtml(r.detail || '')}</td>
      </tr>`;
    },
    emptyMsg: 'No automatic update has been recorded yet.',
  });
}

// The first part of a reason from the server is a fixed phrase and the rest is an image: only the phrase is translated.
const _IAU_REASONS = ['not on the list', 'excluded', 'agentless host', 'host offline', 'outside the time period', 'the agent on this host cannot roll back an update'];

function _iauReason(reason) {
  const text = String(reason || '');
  const head = _IAU_REASONS.find(p => text === p || text.startsWith(p + ': '));
  const span = document.createElement('span');
  if (!head) { span.textContent = text; return span; }
  const phrase = document.createElement('span');
  phrase.textContent = head;
  span.appendChild(phrase);
  if (text.length > head.length) span.appendChild(document.createTextNode(text.slice(head.length)));
  return span;
}

function _iauPaintPreview(d) {
  const box = document.getElementById('iau-preview');
  if (!box) return;
  box.textContent = '';
  const rows = d.preview || [];
  if (!rows.length) {
    const none = document.createElement('div');
    none.textContent = (d.policy && d.policy.mode !== 'off') ? 'Nothing is waiting.' : 'Switch it to shadow or on to see what it would do.';
    box.appendChild(none);
    return;
  }
  rows.forEach(r => {
    const line = document.createElement('div');
    line.className = 'mb-6';
    const who = document.createElement('strong');
    who.textContent = r.device_name || r.device_id || '';
    line.appendChild(who);
    line.appendChild(document.createTextNode(' · ' + (r.dir || '') + ' · ' + (r.refs || []).join(', ') + ' — '));
    if (r.action === 'queue') {
      const go = document.createElement('span');
      go.textContent = 'Would update';
      line.appendChild(go);
    } else {
      line.appendChild(_iauReason(r.reason));
    }
    box.appendChild(line);
  });
}

function _iauPaintLastRun(d) {
  const box = document.getElementById('iau-lastrun');
  if (!box) return;
  box.textContent = '';
  const lr = d.last_run;
  if (!lr || !lr.ts) return;
  const label = document.createElement('span');
  label.textContent = 'Last run';
  box.appendChild(label);
  box.appendChild(document.createTextNode(' ' + timeAgo(lr.ts) + ' · ' + (lr.made || 0) + ' '));
  const made = document.createElement('span');
  made.textContent = 'queued';
  box.appendChild(made);
  box.appendChild(document.createTextNode(' · ' + (lr.held || []).length + ' '));
  const held = document.createElement('span');
  held.textContent = 'held back';
  box.appendChild(held);
}

// keep: leave what the operator typed alone and only bring the list of time periods up to date
function _iauFill(d, keep) {
  const p = d.policy || {};
  const set = (id, v) => { const e = document.getElementById(id); if (e && !keep) e.value = v; };
  set('iau-mode', p.mode || 'off');
  set('iau-include', (p.include || []).join('\n'));
  set('iau-exclude', (p.exclude || []).join('\n'));
  set('iau-max', p.max_hosts_per_run || 2);
  set('iau-verify', p.verify_after_min || 10);
  const rb = document.getElementById('iau-rollback');
  if (rb && !keep) rb.checked = !!p.rollback;
  const sel = document.getElementById('iau-period');
  if (sel) {
    const chosen = keep ? sel.value : (p.period || '');
    while (sel.options.length > 1) sel.remove(1);
    (d.periods || []).forEach(x => {
      const o = document.createElement('option');
      o.value = x.id;
      o.textContent = x.name || x.id;
      sel.appendChild(o);
    });
    if (chosen && !Array.from(sel.options).some(o => o.value === chosen)) {
      const o = document.createElement('option');       // a period that was deleted stays visible, so the save does not drop it unseen
      o.value = chosen;
      o.textContent = chosen;
      sel.appendChild(o);
    }
    sel.value = chosen;
  }
}

// A change to any field of the form marks it as the operator's. The answer of a slow load must not wipe it.
function _iauWatchForm(card) {
  if (_iauWatched) return;
  _iauWatched = true;
  const mark = e => { if (e.target && /^iau-(mode|period|include|exclude|max|verify|rollback)$/.test(e.target.id || '')) _iauDirty = true; };
  card.addEventListener('input', mark);
  card.addEventListener('change', mark);
}

// fresh: the page was just entered, or a save went through, so the form shows what is stored. Without it, a form the operator has changed keeps
// their text, because the answer may be one they asked for before they began typing.
async function loadImageAutoupdate(fresh) {
  _iauRegister();
  const card = document.getElementById('image-autoupdate-card');
  if (!card) return;
  _iauWatchForm(card);
  if (fresh) _iauDirty = false;
  const mine = ++_iauSeq;
  const d = await api('GET', '/image-updates/auto');
  if (mine !== _iauSeq) return;          // a newer load was started while this one waited, and its answer is the one to show
  if (!d || d.error) return;
  _iau = d;
  _iauFill(d, _iauDirty);
  _iauPaintPreview(d);
  _iauPaintLastRun(d);
  tableCtl.render('iau-receipts', d.receipts || []);
  const admin = !!(typeof _meCache !== 'undefined' && _meCache && _meCache.admin);
  const save = document.getElementById('iau-save');
  if (save) save.disabled = !admin;
}

function _iauLines(id) {
  return String((document.getElementById(id) || {}).value || '').split('\n').map(x => x.trim()).filter(Boolean);
}

async function saveImageAutoupdate() {
  const num = id => parseInt((document.getElementById(id) || {}).value, 10);
  const body = {
    mode: document.getElementById('iau-mode').value,
    include: _iauLines('iau-include'),
    exclude: _iauLines('iau-exclude'),
    period: document.getElementById('iau-period').value,
    max_hosts_per_run: num('iau-max'),
    verify_after_min: num('iau-verify'),
    rollback: !!(document.getElementById('iau-rollback') || {}).checked,
  };
  const out = document.getElementById('iau-result');
  if (out) out.textContent = '';
  // switching it on (or changing a policy that is on) asks for a fresh sign-in, as the settings that decide who can do what do
  const r = await withStepUp(() => api('POST', '/image-updates/auto', body));
  if (r && r.ok) {
    toast('Automatic updates saved', 'success');
    loadImageAutoupdate(true);
  } else {
    if (out && r && r.error) out.textContent = r.error;
    failToast(r);
  }
}
