// app-containeraudit.js — the container hardening audit, a section of the Containers page (7.4.9). Buildless classic script;
// every symbol is global like the rest of the client JS, and it loads with the Containers page (the lazy map in app.js).
//
// The agent reports how each container was started; the server works out what that allows (container_audit.py) and this section
// lists it: one row per container with its findings, worst first, and each finding with its evidence. An administrator can accept
// a finding for one container (a metrics agent mounts "/", a manager mounts the engine socket): it stays listed, marked, and stops
// counting. Nothing here decides a severity, and every name and path in it is text from a host, so it goes through escHtml.

let _caData = null;                 // the last answer of GET /api/containers/audit
const _caOpen = new Set();          // rows that are expanded ("<device_id>|<container>")

const _CA_PILL = { critical: 'sev-critical', high: 'sev-high', medium: 'sev-medium', low: 'sev-low' };

function _caKey(r) { return r.device_id + '|' + r.container; }

function _caPill(sev, n) {
  const num = (n == null) ? '' : `<b>${escHtml(String(n))}</b> `;
  return `<span class="sev-pill ${_CA_PILL[sev] || 'sev-low'}">${num}<span>${escHtml(sev)}</span></span>`;
}

async function loadContainerAudit() {
  const tbody = document.getElementById('ca-tbody');
  if (!tbody) return;
  tableCtl.wireSortOnly('ca-thead', 'container_audit', renderContainerAudit);
  if (!_caData) tbody.innerHTML = _skeletonRows(4);
  const min = (document.getElementById('ca-min') || {}).value || 'medium';
  const data = await api('GET', `/containers/audit?min=${encodeURIComponent(min)}`);
  if (!data || data.error) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty-state-error">${escHtml((data && data.error) || 'Could not load the audit.')}</td></tr>`;
    return;
  }
  _caData = data;
  renderContainerAudit();
}

function renderContainerAudit() {
  const tbody = document.getElementById('ca-tbody');
  if (!tbody || !_caData) return;
  const s = _caData.summary || {};
  const sum = document.getElementById('ca-summary');
  if (sum) {
    sum.innerHTML = ['critical', 'high', 'medium', 'low'].map(k => (s[k] ? _caPill(k, s[k]) : '')).join(' ')
      + (s.clean ? ` <span class="hint"><b>${escHtml(String(s.clean))}</b> <span>clean</span></span>` : '')
      + (_caData.not_audited ? ` <span class="hint"><b>${escHtml(String(_caData.not_audited))}</b> <span>not audited</span></span>` : '');
  }
  const q = (document.getElementById('ca-filter')?.value || '').trim().toLowerCase();
  let rows = (_caData.containers || []).filter(r => !q
    || `${r.device} ${r.container} ${r.image}`.toLowerCase().includes(q));
  rows = tableCtl.sortRows('container_audit', rows, (r) => ({
    device: (r.device || '').toLowerCase(), container: (r.container || '').toLowerCase(), image: (r.image || '').toLowerCase(),
    findings: (r.counts.critical * 1e6) + (r.counts.high * 1e4) + (r.counts.medium * 100) + r.counts.low,
  }));
  if (!rows.length) {
    const none = !(_caData.containers || []).length;
    tbody.innerHTML = `<tr><td colspan="4" class="empty-state">${none
      ? (s.clean || _caData.not_audited ? 'No container has a finding at this level.' : 'Nothing is audited yet. A container is audited once its agent reports how it was started: update the agent.')
      : 'No container matches the filter.'}</td></tr>`;
    return;
  }
  const admin = !!(typeof _meCache !== 'undefined' && _meCache && _meCache.admin);
  const capped = _capFleetRows(rows, 4, 'containers');
  tbody.innerHTML = capped.rows.map(r => {
    const key = _caKey(r);
    const open = _caOpen.has(key);
    const pills = ['critical', 'high', 'medium', 'low'].filter(k => r.counts[k]).map(k => _caPill(k, r.counts[k])).join(' ');
    const accepted = r.findings.filter(f => f.accepted).length;
    const head = `<tr data-ca-row="${escAttr(key)}">
      <td class="fw-500">${escHtml(r.device)}${r.monitored ? '' : ' <span class="hint">· <span>not monitored</span></span>'}</td>
      <td><a href="#" data-action-btn="_caToggleBtn" data-prevent-default data-key="${escAttr(key)}" aria-expanded="${open}">${escHtml(r.container)}</a></td>
      <td class="hint"><code>${escHtml(r.image)}${r.tag ? ':' + escHtml(r.tag) : ''}</code></td>
      <td>${pills || '<span class="hint">—</span>'}${accepted ? ` <span class="hint">· <b>${accepted}</b> <span>accepted</span></span>` : ''}</td>
    </tr>`;
    if (!open) return head;
    const items = r.findings.map(f => `<li class="ca-finding">
        ${_caPill(f.severity)} <span class="fw-500">${escHtml(f.title)}</span>
        ${f.detail ? `<span class="hint"> — <code>${escHtml(f.detail)}</code></span>` : ''}
        ${f.accepted ? ' <span class="hint">· <span>accepted</span></span>' : ''}
        ${admin ? `<button class="btn-icon cell-sm" data-action-btn="_caAcceptBtn" data-dev-id="${escAttr(r.device_id)}" data-container="${escAttr(r.container)}" data-rule="${escAttr(f.rule)}" data-accepted="${f.accepted ? '0' : '1'}">${f.accepted ? 'Take back' : 'Accept'}</button>` : ''}
      </li>`).join('');
    return head + `<tr class="ca-detail"><td colspan="4"><ul class="ca-findings">${items}</ul></td></tr>`;
  }).join('') + capped.note;
}

function _caToggleBtn(btn) {
  const key = btn.dataset.key;
  if (_caOpen.has(key)) _caOpen.delete(key); else _caOpen.add(key);
  renderContainerAudit();
  const again = document.querySelector(`#ca-tbody [data-key="${CSS.escape(key)}"]`);
  if (again) again.focus();
}

async function _caAcceptBtn(btn) {
  const accept = btn.dataset.accepted === '1';
  let note = '';
  if (accept) {
    const asked = await uiPrompt({ title: 'Accept this finding', message: 'Why is this acceptable for this container?', confirmText: 'Accept' });
    if (asked === null || asked === undefined) return;
    note = String(asked);
  }
  const r = await api('PUT', `/devices/${encodeURIComponent(btn.dataset.devId)}/container-audit`,
    { container: btn.dataset.container, rule: btn.dataset.rule, accepted: accept, note });
  if (!r || r.error || !r.ok) { toast((r && r.error) || 'Could not save the change', 'error'); return; }
  await loadContainerAudit();
}
