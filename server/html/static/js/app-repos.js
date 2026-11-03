// app-repos.js — the package repository inventory, a card of the Patches page (7.4.9). Buildless classic script; every symbol is
// global like the rest of the client JS, and it loads with the Patches page (the lazy map in app.js).
//
// Each Linux agent sends its repository definition files and the server reads them (repo_inventory.py): one row per repository,
// with how many hosts use it and what is wrong with it. This card lists them, worst first, and a click opens a row to its hosts and
// its findings. Nothing here decides a severity, and every address and name in it is text from a host, so it goes through escHtml.

let _repoData = null;               // the last answer of GET /api/repositories
let _repoSeq = 0;                  // bumped by every load, so a slow answer to an earlier one cannot replace a later one
const _repoOpen = new Set();        // rows that are expanded (the server's key for the repository)

const _REPO_KIND = { apt: 'apt', deb822: 'apt', yum: 'dnf / yum', pacman: 'pacman' };

async function loadRepositories() {
  const body = document.getElementById('repo-tbody');
  if (!body) return;
  tableCtl.wireSortOnly('repo-thead', 'repositories', renderRepositories);
  if (!_repoData) body.innerHTML = _skeletonRows(4);
  const min = (document.getElementById('repo-min') || {}).value || 'low';
  const seq = ++_repoSeq;
  const data = await api('GET', `/repositories?min=${encodeURIComponent(min)}`);
  if (seq !== _repoSeq) return;
  if (!data || data.error) {
    body.innerHTML = `<tr><td colspan="4" class="empty-state-error">${escHtml((data && data.error) || 'Could not load the repositories.')}</td></tr>`;
    return;
  }
  _repoData = data;
  renderRepositories();
}

function _repoPill(sev, n) {
  const num = (n == null) ? '' : `<b>${escHtml(String(n))}</b> `;
  return `<span class="sev-pill sev-${escAttr(sev)}">${num}<span>${escHtml(sev)}</span></span>`;
}

function renderRepositories() {
  const body = document.getElementById('repo-tbody');
  if (!body || !_repoData) return;
  const s = _repoData.summary || {};
  const sum = document.getElementById('repo-summary');
  if (sum) {
    sum.innerHTML = ['critical', 'high', 'medium', 'low'].map(k => (s[k] ? _repoPill(k, s[k]) : '')).join(' ')
      + (s.third_party ? ` <span class="hint"><b>${escHtml(String(s.third_party))}</b> <span>third party</span></span>` : '')
      + ` <span class="hint"><b>${escHtml(String(_repoData.hosts_reporting || 0))}</b> <span>hosts reporting</span></span>`;
  }
  const q = (document.getElementById('repo-filter')?.value || '').trim().toLowerCase();
  let rows = (_repoData.repositories || []).filter(r => !q
    || `${r.url} ${r.host} ${(r.hosts || []).map(h => h.device).join(' ')}`.toLowerCase().includes(q));
  rows = tableCtl.sortRows('repositories', rows, (r) => ({
    url: (r.url || '').toLowerCase(), kind: r.kind || '', hosts: r.host_count || 0,
    findings: (r.counts.critical * 1e6) + (r.counts.high * 1e4) + (r.counts.medium * 100) + r.counts.low,
  }));
  if (!rows.length) {
    const none = !(_repoData.repositories || []).length && !_repoData.hosts_reporting;
    body.innerHTML = `<tr><td colspan="4" class="empty-state">${none
      ? 'No host has reported its repositories yet. Update the agents.' : 'No repository matches the filter.'}</td></tr>`;
    return;
  }
  const capped = _capFleetRows(rows, 4, 'repositories');
  body.innerHTML = capped.rows.map(r => {
    const open = _repoOpen.has(r.key);
    const pills = ['critical', 'high', 'medium', 'low'].filter(k => r.counts[k]).map(k => _repoPill(k, r.counts[k])).join(' ');
    const dis = r.enabled ? '' : ' <span class="hint">· <span>disabled</span></span>';
    const label = r.suite ? `${r.url} ${r.suite}` : (r.id ? `${r.id} · ${r.url}` : r.url);
    const head = `<tr data-repo-row="${escAttr(r.key)}">
      <td><a href="#" data-action-btn="_repoToggleBtn" data-prevent-default data-key="${escAttr(r.key)}" aria-expanded="${open}"><code>${escHtml(label)}</code></a>${dis}</td>
      <td class="hint"><code>${escHtml(_REPO_KIND[r.kind] || r.kind)}${r.types && r.types[0] === 'deb-src' ? ' src' : ''}</code></td>
      <td>${escHtml(String(r.host_count))}</td>
      <td>${pills || '<span class="hint">—</span>'}</td>
    </tr>`;
    if (!open) return head;
    const hosts = (r.hosts || []).map(h => `<code>${escHtml(h.device)}</code>`).join(', ')
      + (r.host_count > (r.hosts || []).length ? ` <span class="hint">+${escHtml(String(r.host_count - r.hosts.length))}</span>` : '');
    const files = [...new Set((r.hosts || []).map(h => h.file))].slice(0, 4).map(f => `<code>${escHtml(f)}</code>`).join(', ');
    const finds = (r.findings || []).map(f => `<li class="ca-finding">${_repoPill(f.severity)} <span class="fw-500">${escHtml(f.title)}</span>
        ${f.detail ? `<span class="hint"> — <code>${escHtml(f.detail)}</code></span>` : ''}</li>`).join('');
    const meta = [
      r.suite ? `<span>Suite</span> <code>${escHtml(r.suite)}</code>` : '',
      (r.components || []).length ? `<span>Components</span> <code>${escHtml(r.components.join(' '))}</code>` : '',
      files ? `<span>Defined in</span> ${files}` : '',
    ].filter(Boolean).join(' · ');
    return head + `<tr class="ca-detail"><td colspan="4">
      ${meta ? `<div class="hint mb-6">${meta}</div>` : ''}
      <div class="mb-6"><span class="hint">Used by</span> ${hosts}</div>
      ${finds ? `<ul class="ca-findings">${finds}</ul>` : ''}
    </td></tr>`;
  }).join('') + capped.note;
}

function _repoToggleBtn(btn) {
  const key = btn.dataset.key;
  if (_repoOpen.has(key)) _repoOpen.delete(key); else _repoOpen.add(key);
  renderRepositories();
  const again = document.querySelector(`#repo-tbody [data-key="${CSS.escape(key)}"]`);
  if (again) again.focus();
}
