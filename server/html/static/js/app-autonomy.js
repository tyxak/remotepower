// RemotePower — Autonomy page (v7.0.0): remediation receipts + the safety
// envelope editor.
//
// Its OWN lazy module, per the house rule that a new page gets a new
// app-<page>.js rather than a bolt-on. The first cut appended this to
// app-self.js, which is EAGER — that both blew the eager-JS budget (by 21
// bytes, which is the ratchet doing exactly its job) and, once it was also
// listed as lazy, loaded the file twice and re-declared its top-level consts.

// ─── Autonomy (v7.0.0) ──────────────────────────────────────────────────────
// The receipts page. In shadow mode this is the entire product: a list of
// decisions an operator can grade before granting the loop anything.
//
// api() RESOLVES rather than throwing on 403/404 (a module that is switched off
// 404s the whole prefix), so every outcome is detected on the resolved body. A
// .catch here would be dead code — the documented trap that root-caused three
// "the feature does nothing" bugs in one session.

const _AUTONOMY_VERDICT_CLASS = {
  act: 'chk-warning', escalate: 'chk-unknown',
  shadow: 'chk-ok', refuse: 'chk-ok',
};

function _autonomyPolicyFields() {
  return {
    mode: document.getElementById('autonomy-mode'),
    radius: document.getElementById('autonomy-max-radius'),
    rate: document.getElementById('autonomy-rate'),
    backup: document.getElementById('autonomy-require-backup'),
    window: document.getElementById('autonomy-require-window'),
    approval: document.getElementById('autonomy-approval'),
  };
}

async function loadAutonomy() {
  const body = document.getElementById('autonomy-receipts-body');
  if (!body) return;
  tableCtl.wireSortOnly('autonomy-receipts-head', 'autonomyReceipts', loadAutonomy);

  const pol = await api('GET', '/autonomy/policy');
  if (!pol || !pol.ok) {
    // Module off, or the caller cannot see it. Say so plainly rather than
    // rendering an empty page that looks like "nothing has happened".
    body.innerHTML = `<tr><td colspan="7" class="hint">${escHtml(
      'Autonomous remediation is switched off for this instance. Enable it in Settings → Advanced.')}</td></tr>`;
    return;
  }

  const f = _autonomyPolicyFields();
  const p = pol.policy || {};
  if (f.mode) f.mode.value = p.mode || 'off';
  if (f.radius) f.radius.value = p.max_blast_radius;
  if (f.rate) f.rate.value = p.max_actions_per_hour;
  if (f.backup) f.backup.checked = !!p.require_verified_backup;
  if (f.window) f.window.checked = !!p.require_window;
  if (f.approval) f.approval.checked = !!p.approval_for_destructive;

  const pill = document.getElementById('autonomy-mode-pill');
  if (pill) {
    const m = p.mode || 'off';
    const cls = m === 'enabled' ? 'chk-warning' : (m === 'shadow' ? 'chk-ok' : 'chk-unknown');
    pill.innerHTML = `<span class="chk-pill ${cls}">${escHtml(m)}</span>`;
  }

  const acts = document.getElementById('autonomy-actions');
  if (acts) {
    const allowed = p.allowed_actions || [];
    acts.innerHTML = Object.entries(pol.action_classes || {}).map(([name, spec]) => {
      const on = allowed.includes(name) ? ' checked' : '';
      const d = spec && spec.destructive
        ? ` <span class="chk-pill chk-warning">${escHtml('destructive')}</span>` : '';
      return `<div class="settings-row"><label class="form-label">` +
             `<input type="checkbox" class="autonomy-act" data-act="${escAttr(name)}"${on}> ` +
             `<code>${escHtml(name)}</code>${d}</label></div>`;
    }).join('');
  }

  const r = await api('GET', '/autonomy/receipts');
  if (!r || !r.ok) return;

  const reasons = document.getElementById('autonomy-reasons');
  if (reasons) {
    const rows = Object.entries(r.by_reason || {}).sort((a, b) => b[1] - a[1]);
    reasons.innerHTML = rows.length
      ? rows.map(([k, n]) => `<div class="settings-row"><span class="chk-pill ${
          k === 'ok' ? 'chk-ok' : 'chk-unknown'}">${escHtml(String(n))}</span> ` +
          `<code>${escHtml(k)}</code></div>`).join('')
      : `<div class="hint">${escHtml('No decisions recorded yet.')}</div>`;
  }

  const list = r.receipts || [];
  if (!list.length) {
    body.innerHTML = `<tr><td colspan="7" class="hint">${escHtml(
      'No decisions recorded yet. In shadow mode receipts appear as alerts arrive.')}</td></tr>`;
    return;
  }
  const sorted = tableCtl.sortRows('autonomyReceipts', list, x => ({
    ts: x.ts || 0,
    device: x.device_name || '',
    trigger: x.trigger || '',
    action: x.action || '',
    verdict: x.verdict || '',
    reason: x.reason || '',
    radius: (x.blast_radius || {}).score || 0,
  }));
  body.innerHTML = sorted.map(x => {
    const br = x.blast_radius || {};
    const cls = _AUTONOMY_VERDICT_CLASS[x.verdict] || 'chk-unknown';
    const red = br.redundant ? ` <span class="hint">${escHtml('(redundant)')}</span>` : '';
    return `<tr>
      <td>${escHtml(_fmtTs(x.ts))}</td>
      <td>${escHtml(x.device_name || '')}</td>
      <td><code>${escHtml(x.trigger || '')}</code></td>
      <td><code>${escHtml(x.action || '')}</code></td>
      <td><span class="chk-pill ${cls}">${escHtml(x.verdict || '')}</span></td>
      <td><code>${escHtml(x.reason || '')}</code></td>
      <td>${escHtml(String(br.score != null ? br.score : ''))}${red}</td>
    </tr>`;
  }).join('');
}

async function saveAutonomyPolicy() {
  const f = _autonomyPolicyFields();
  const allowed = [...document.querySelectorAll('.autonomy-act')]
    .filter(el => el.checked).map(el => el.dataset.act);
  const policy = {
    mode: f.mode ? f.mode.value : 'off',
    allowed_actions: allowed,
    max_blast_radius: f.radius ? Number(f.radius.value) : 0,
    max_actions_per_hour: f.rate ? Number(f.rate.value) : 0,
    require_verified_backup: !!(f.backup && f.backup.checked),
    require_window: !!(f.window && f.window.checked),
    approval_for_destructive: !!(f.approval && f.approval.checked),
  };
  const r = await api('PUT', '/autonomy/policy', { policy });
  if (r && r.ok) { toast('Safety envelope saved', 'success'); loadAutonomy(); }
  else { toast('Save failed: ' + ((r && r.error) || ''), 'error'); }
}
