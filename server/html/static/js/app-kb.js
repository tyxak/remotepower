// app-kb.js — Knowledge base page (structured IT documentation).
// Buildless classic script; every symbol stays global like the rest of the
// client JS. Operator-authored markdown articles (SOPs, how-tos, runbooks)
// organised in a category folder tree, searchable, and fed to the AI as a RAG
// source. Reads are any-role; create/edit/delete are admin (server-enforced).
// Opt-in: the page + nav hide unless the `kb_enabled` instance flag is on.
// (v5.6.0)

let _kbArticles = [];   // list-view metadata (no body) from GET /kb
let _kbSelId = '';       // currently-open article id

async function loadKb() {
  const list = document.getElementById('kb-list');
  if (list) list.innerHTML = _skeletonBlock(5);
  const d = await api('GET', '/kb').catch(() => null);
  if (!d) return;
  if (!d.ok) {
    _kbArticles = [];
    if (list) list.innerHTML = '<div class="empty-state">Knowledge base is disabled. Enable it under Settings → Advanced.</div>';
    return;
  }
  _kbArticles = d.articles || [];
  _renderKbList();
  _loadKbRunbooks();
}

// W1-23: alert→KB runbook mapping (config.alert_runbooks). Admin-only card.
let _kbRunbookMap = {};
let _kbEventLabels = {};
async function _loadKbRunbooks() {
  if (!document.getElementById('kb-runbook-list')) return;
  try {
    const cfg = await api('GET', '/config');
    _kbRunbookMap = (cfg && cfg.alert_runbooks && typeof cfg.alert_runbooks === 'object') ? cfg.alert_runbooks : {};
    _kbEventLabels = (cfg && cfg._meta && cfg._meta.webhook_event_descriptions) || {};
    _renderKbRunbooks(Object.keys(cfg?.webhook_events || _kbEventLabels));
  } catch (e) { /* non-admin can't read config — card stays inert */ }
}
function _renderKbRunbooks(eventNames) {
  const list = document.getElementById('kb-runbook-list');
  const evSel = document.getElementById('kb-runbook-event');
  const arSel = document.getElementById('kb-runbook-article');
  if (!list) return;
  const artTitle = id => (_kbArticles.find(a => a.id === id) || {}).title || id;
  const entries = Object.entries(_kbRunbookMap);
  list.innerHTML = entries.length
    ? entries.map(([ev, aid]) =>
        `<div class="row-6-center mb-4"><code class="fs-12">${escHtml(_kbEventLabels[ev] || ev)}</code>`
        + `<span class="meta-sm-nm ellipsis flex-1">→ ${escHtml(artTitle(aid))}</span>`
        + `<button class="btn-icon c-danger-outline cell-sm" data-action="deleteKbRunbookLink" data-arg="${escAttr(ev)}">Unlink</button></div>`).join('')
    : '<div class="meta-sm-nm">No runbook links yet. Link an alert type to an article below.</div>';
  if (evSel && eventNames) {
    evSel.innerHTML = eventNames.sort().map(ev =>
      `<option value="${escAttr(ev)}">${escHtml(_kbEventLabels[ev] || ev)}</option>`).join('');
  }
  if (arSel) {
    arSel.innerHTML = _kbArticles.length
      ? _kbArticles.map(a => `<option value="${escAttr(a.id)}">${escHtml(a.title || a.id)}</option>`).join('')
      : '<option value="">(no articles yet)</option>';
  }
}
async function _saveKbRunbooks(map, okMsg) {
  const r = await api('POST', '/config', { alert_runbooks: map });
  const res = document.getElementById('kb-runbook-result');
  if (r && !r.error) {
    _kbRunbookMap = map; _renderKbRunbooks();
    toast(okMsg, 'success'); if (res) res.textContent = '';
  } else {
    toast(r?.error || 'Failed', 'error'); if (res) res.textContent = r?.error || 'Failed';
  }
}
function addKbRunbookLink() {
  const ev = document.getElementById('kb-runbook-event')?.value;
  const aid = document.getElementById('kb-runbook-article')?.value;
  if (!ev || !aid) { toast('Pick an alert type and an article', 'error'); return; }
  _saveKbRunbooks({ ..._kbRunbookMap, [ev]: aid }, 'Runbook linked');
}
function deleteKbRunbookLink(ev) {
  const map = { ..._kbRunbookMap };
  delete map[ev];
  _saveKbRunbooks(map, 'Runbook unlinked');
}

function filterKb() { _renderKbList(); }

function _renderKbList() {
  const list = document.getElementById('kb-list');
  if (!list) return;
  const q = (document.getElementById('kb-filter')?.value || '').trim().toLowerCase();
  let arts = _kbArticles.slice();
  if (q) arts = arts.filter(a =>
    (`${a.title} ${a.category || ''} ${(a.tags || []).join(' ')}`).toLowerCase().includes(q));
  if (!arts.length) {
    list.innerHTML = '<div class="empty-state">' +
      (q ? 'No articles match your search.'
         : 'No articles yet. Click <b>New article</b> to document a procedure.') + '</div>';
    return;
  }
  // Group by category folder; pinned articles float to the top within "(pinned)".
  const groups = {};
  arts.forEach(a => {
    const k = a.pinned ? '★ Pinned' : (a.category || 'Uncategorised');
    (groups[k] = groups[k] || []).push(a);
  });
  const keys = Object.keys(groups).sort((x, y) =>
    (x === '★ Pinned' ? -1 : y === '★ Pinned' ? 1 : x.localeCompare(y)));
  let html = '';
  keys.forEach(k => {
    html += `<div class="kb-cat-head">${escHtml(k)}</div>`;
    groups[k].sort((a, b) => (a.title || '').toLowerCase().localeCompare((b.title || '').toLowerCase()));
    groups[k].forEach(a => {
      const sel = a.id === _kbSelId ? ' kb-item-sel' : '';
      const tags = (a.tags || []).slice(0, 4).map(t =>
        `<span class="chip chip-sm">${escHtml(t)}</span>`).join('');
      html += `<button class="kb-item${sel}" data-action="openKbArticle" data-arg="${escAttr(a.id)}">`
        + `<span class="kb-item-title">${escHtml(a.title || 'Untitled')}</span>`
        + (tags ? `<span class="kb-item-tags">${tags}</span>` : '')
        + `</button>`;
    });
  });
  list.innerHTML = html;
}

// W1-23: open a KB article from OUTSIDE the KB page (e.g. an alert's Runbook
// link) — switch to the KB page first, then select the article.
function openKbFromAlert(id) {
  showPage('kb', document.querySelector('.nav-btn[data-page="kb"]') || undefined);
  openKbArticle(id);
}
async function openKbArticle(id) {
  _kbSelId = id;
  _renderKbList();
  const view = document.getElementById('kb-view');
  if (view) view.innerHTML = _skeletonBlock(6);
  const d = await api('GET', '/kb/' + encodeURIComponent(id)).catch(() => null);
  if (!d || !d.ok || !d.article) {
    if (view) view.innerHTML = '<div class="empty-state">Could not load this article.</div>';
    return;
  }
  const a = d.article;
  const when = a.updated_at ? new Date(a.updated_at * 1000).toLocaleString() : '';
  const meta = [
    a.category ? escHtml(a.category) : '',
    a.author ? 'by ' + escHtml(a.author) : '',
    when ? 'updated ' + escHtml(when) : '',
  ].filter(Boolean).join(' · ');
  const tags = (a.tags || []).map(t => `<span class="chip chip-sm">${escHtml(t)}</span>`).join(' ');
  view.innerHTML =
    `<div class="kb-view-head">`
    + `<div><div class="section-title">${escHtml(a.title || 'Untitled')}</div>`
    +   `<div class="meta-sm-nm">${meta}</div>${tags ? `<div class="mt-4">${tags}</div>` : ''}</div>`
    + `<div class="row-8-center">`
    +   `<button class="btn-icon" title="Edit" data-action="openKbEdit" data-arg="${escAttr(a.id)}">${_icon('edit', 14)} Edit</button>`
    +   `<button class="btn-icon c-danger-outline" title="Delete" data-action="deleteKbArticle" data-arg="${escAttr(a.id)}">${_icon('trash', 14)}</button>`
    + `</div></div>`
    + `<div class="kb-view-body ai-content">${renderMarkdown(a.body || '_(empty)_')}</div>`;
}

function openKbCreate() {
  document.getElementById('kb-edit-id').value = '';
  document.getElementById('kb-edit-title').textContent = 'New article';
  document.getElementById('kb-edit-title-input').value = '';
  document.getElementById('kb-edit-category').value = '';
  document.getElementById('kb-edit-tags').value = '';
  document.getElementById('kb-edit-pinned').checked = false;
  document.getElementById('kb-edit-body').value = '';
  const btn = document.getElementById('kb-save-btn');
  if (btn) btn.textContent = 'Create';
  openModal('kb-edit-modal');
}

async function openKbEdit(id) {
  const d = await api('GET', '/kb/' + encodeURIComponent(id)).catch(() => null);
  if (!d || !d.ok || !d.article) { toast('Could not load the article', 'error'); return; }
  const a = d.article;
  document.getElementById('kb-edit-id').value = a.id;
  document.getElementById('kb-edit-title').textContent = 'Edit article';
  document.getElementById('kb-edit-title-input').value = a.title || '';
  document.getElementById('kb-edit-category').value = a.category || '';
  document.getElementById('kb-edit-tags').value = (a.tags || []).join(', ');
  document.getElementById('kb-edit-pinned').checked = !!a.pinned;
  document.getElementById('kb-edit-body').value = a.body || '';
  const btn = document.getElementById('kb-save-btn');
  if (btn) btn.textContent = 'Save';
  openModal('kb-edit-modal');
}

async function saveKbArticle() {
  const id = document.getElementById('kb-edit-id').value;
  const title = document.getElementById('kb-edit-title-input').value.trim();
  if (!title) { toast('Title is required', 'error'); return; }
  const payload = {
    title,
    category: document.getElementById('kb-edit-category').value.trim(),
    tags: document.getElementById('kb-edit-tags').value.split(',').map(s => s.trim()).filter(Boolean),
    pinned: document.getElementById('kb-edit-pinned').checked,
    body: document.getElementById('kb-edit-body').value,
  };
  const r = id
    ? await api('PATCH', '/kb/' + encodeURIComponent(id), payload).catch(() => null)
    : await api('POST', '/kb', payload).catch(() => null);
  if (!r || r.error) { toast((r && r.error) || 'Save failed', 'error'); return; }
  toast('Article saved', 'success');
  closeModal('kb-edit-modal');
  const openId = id || r.id;
  await loadKb();
  if (openId) openKbArticle(openId);
}

async function deleteKbArticle(id) {
  if (!await uiConfirm('Delete this article? This cannot be undone.')) return;
  const r = await api('DELETE', '/kb/' + encodeURIComponent(id)).catch(() => null);
  if (!r || r.error) { toast((r && r.error) || 'Delete failed', 'error'); return; }
  toast('Article deleted', 'success');
  if (_kbSelId === id) {
    _kbSelId = '';
    const view = document.getElementById('kb-view');
    if (view) view.innerHTML = '<div class="empty-state"><div class="empty-title">No article selected</div></div>';
  }
  loadKb();
}
