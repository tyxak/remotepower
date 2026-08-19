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

// The receipt carries the precedent that justified the decision — the whole
// reason it is self-contained — and the page rendered every other field and not
// that one. In shadow mode, reading receipts IS the product, and "no_precedent"
// in the reason column tells you nothing about how close it was.
function _autonomyPrecedent(p) {
  p = p || {};
  const n = Number(p.samples) || 0;
  if (!n) return `<span class="hint">${escHtml('none')}</span>`;
  const conf = p.confidence == null ? '' : `${Math.round(Number(p.confidence) * 100)}%`;
  const what = p.action
    ? ` <span class="hint" title="${escAttr(String(p.action))}">${
        escHtml(String(p.action).slice(0, 40))}</span>` : '';
  return `${escHtml(String(n))}× ${escHtml(conf)}${what}`;
}

// What HAPPENED, which the receipt has always carried and the table never
// showed: queued, parked for approval, already awaiting approval, the exit code
// the agent came back with. On an ACT row it is the most consequential field
// there is — "queued" and "the command exited 127" were the same picture.
function _autonomyOutcome(x) {
  const parts = [];
  if (x.outcome) parts.push(String(x.outcome));
  if (x.rc != null && x.rc !== 0) parts.push(`rc ${x.rc}`);
  if (!parts.length) return '';
  const full = parts.join(' · ') + (x.command_output ? `\n\n${x.command_output}` : '');
  const cls = (x.rc != null && x.rc !== 0) ? 'c-red' : 'hint';
  return `<div class="${cls} fs-11" title="${escAttr(full)}">${
    escHtml(parts.join(' · ').slice(0, 60))}</div>`;
}

function _autonomyPolicyFields() {
  return {
    mode: document.getElementById('autonomy-mode'),
    radius: document.getElementById('autonomy-max-radius'),
    rate: document.getElementById('autonomy-rate'),
    backup: document.getElementById('autonomy-require-backup'),
    window: document.getElementById('autonomy-require-window'),
    approval: document.getElementById('autonomy-approval'),
    precedent: document.getElementById('autonomy-require-precedent'),
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
    body.innerHTML = `<tr><td colspan="9" class="hint">${escHtml(
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
  // Absent on a policy stored before this field existed, and the server
  // defaults it to true — so read it the same way rather than letting an old
  // policy render as "precedent not required".
  //
  // `!== false` disagreed with the server for every falsy-but-not-`false`
  // value: a hand-edited or GitOps policy carrying 0, '' or null had the loop
  // treat precedent as WAIVED while this box showed it ticked. Match Python's
  // `policy.get('require_precedent', True)` exactly — absent is on, anything
  // else is its truthiness.
  if (f.precedent) {
    f.precedent.checked = ('require_precedent' in p) ? !!p.require_precedent : true;
  }

  const pill = document.getElementById('autonomy-mode-pill');
  if (pill) {
    const m = p.mode || 'off';
    const cls = m === 'enabled' ? 'chk-warning' : (m === 'shadow' ? 'chk-ok' : 'chk-unknown');
    pill.innerHTML = `<span class="chk-pill ${cls}">${escHtml(m)}</span>`;
  }

  const acts = document.getElementById('autonomy-actions');
  if (acts) {
    const allowed = p.allowed_actions || [];
    // Grouped, because 25 machine names in one column is a wall. The groups and
    // their order come from the SERVER (`action_groups`), so the page and the
    // catalog cannot drift into two different taxonomies.
    const groups = pol.action_groups || [['', '']];
    const byGroup = new Map(groups.map(([g, label]) => [g, {label, rows: []}]));
    Object.entries(pol.action_classes || {}).forEach(([name, spec]) => {
      const on = allowed.includes(name) ? ' checked' : '';
      const d = spec && spec.destructive
        ? ` <span class="chk-pill chk-warning">${escHtml('destructive')}</span>` : '';
      // Separate from `destructive`, because they are separate questions: this
      // one says a proven-recoverable backup is what stands between the action
      // and losing data. Restarting networking is destructive and needs no
      // backup; patching needs one.
      const bk = spec && (spec.requires_backup === undefined
                            ? spec.destructive : spec.requires_backup)
        ? ` <span class="chk-pill chk-unknown" title="${escAttr(
            'Refused unless a restore drill has restored and verified within 30 days')
          }">${escHtml('needs backup')}</span>` : '';
      // Which agents can actually carry it out. Ticking an action for a fleet
      // that cannot run it is the success-toast-then-silence shape, so say so
      // here rather than only in the refusal after the fact.
      const plats = (spec && spec.platforms) || [];
      const p = plats.length && plats.length < 3
        ? ` <span class="chk-pill chk-unknown">${escHtml(plats.join(' / '))}</span>` : '';
      const lbl = spec && spec.label ? escHtml(spec.label) : '';
      const bucket = byGroup.get((spec && spec.group) || '') || byGroup.values().next().value;
      bucket.rows.push(
        `<label class="form-label autonomy-act-row">` +
        `<input type="checkbox" class="autonomy-act" data-act="${escAttr(name)}"${on}>` +
        `<span class="autonomy-act-name"><code>${escHtml(name)}</code>${d}${bk}${p}</span>` +
        `<span class="hint">${lbl}</span></label>`);
    });
    acts.innerHTML = [...byGroup.entries()]
      .filter(([, g]) => g.rows.length)
      .map(([key, g]) => `<div class="autonomy-act-group" data-group="${escAttr(key)}">` +
                         `${escHtml(g.label)} <span class="c-muted">${g.rows.length}</span></div>` +
                         g.rows.join(''))
      .join('');
    const cnt = document.getElementById('autonomy-act-permitted');
    if (cnt) {
      cnt.textContent = `${allowed.length} of ${
        Object.keys(pol.action_classes || {}).length} permitted`;
    }
    filterAutonomyActions(document.getElementById('autonomy-act-filter'));
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
    body.innerHTML = `<tr><td colspan="9" class="hint">${escHtml(
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
    precedent: (x.precedent || {}).samples || 0,
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
      <td><span class="chk-pill ${cls}">${escHtml(x.verdict || '')}</span>${
        _autonomyOutcome(x)}</td>
      <td><code>${escHtml(x.reason || '')}</code>${
        x.backup_evidence
          ? `<div class="hint fs-11" title="${escAttr(String(x.backup_evidence))}">${
              escHtml(String(x.backup_evidence).slice(0, 48))}</div>`
          : ''}</td>
      <td>${_autonomyPrecedent(x.precedent)}</td>
      <td>${escHtml(String(br.score != null ? br.score : ''))}${red}</td>
      <td>${x.id
        ? `<button class="btn-icon btn-xs c-danger-outline" data-action="deleteAutonomyReceipt" ` +
          `data-arg="${escAttr(x.id)}" title="${escAttr('Delete this receipt')}">${_icon('trash', 14)}</button>`
        : ''}</td>
    </tr>`;
  }).join('');
}

// Admin-only and audited server-side; both of these detect the outcome on the
// RESOLVED body, because api() resolves rather than throwing on a 403 or a 404.
async function clearAutonomyReceipts() {
  const n = (document.querySelectorAll('#autonomy-receipts-body tr') || []).length;
  if (!await uiConfirm({
        title: 'Clear receipts',
        message: `Remove every receipt this account can see${n ? ` (${n})` : ''}? `
               + 'The decisions themselves are not undone and the loop keeps running. '
               + 'Anything still awaiting its verification sample loses that second half.',
        confirmText: 'Clear'})) return;
  const r = await api('DELETE', '/autonomy/receipts');
  if (r && r.ok) {
    toast(`Cleared ${r.removed} receipt(s)`, 'success');
    loadAutonomy();
  } else toast((r && r.error) || 'Could not clear the receipts', 'error');
}

async function deleteAutonomyReceipt(id) {
  if (!id) return;
  const r = await api('DELETE', `/autonomy/receipts?id=${encodeURIComponent(id)}`);
  if (r && r.ok) {
    toast('Receipt deleted', 'success');
    loadAutonomy();
  } else toast((r && r.error) || 'Could not delete that receipt', 'error');
}

// The shared filter hides ROWS; a group heading whose rows all vanished would
// sit there labelling nothing. Same helper, one extra pass.
function filterAutonomyActions(el) {
  if (!el) return;
  if (typeof filterRows === 'function') filterRows(el);
  const q = (el.value || '').trim();
  document.querySelectorAll('#autonomy-actions .autonomy-act-group').forEach(h => {
    let n = 0;
    for (let sib = h.nextElementSibling;
         sib && !sib.classList.contains('autonomy-act-group');
         sib = sib.nextElementSibling) {
      if (sib.classList.contains('autonomy-act-row')
          && !sib.classList.contains('row-hidden')) n++;
    }
    h.classList.toggle('row-hidden', q !== '' && n === 0);
  });
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
    require_precedent: !!(f.precedent && f.precedent.checked),
  };
  const r = await api('PUT', '/autonomy/policy', { policy });
  if (r && r.ok) { toast('Safety envelope saved', 'success'); loadAutonomy(); }
  else { toast('Save failed: ' + ((r && r.error) || ''), 'error'); }
}
