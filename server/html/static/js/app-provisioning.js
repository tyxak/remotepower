// app-provisioning.js — Provisioning blueprints page (catalog + render).
// Buildless classic script; every symbol stays global like the rest of the
// client JS. A folder-tree catalog of IaC / boot templates (Terraform,
// cloud-init, Ansible, iPXE). Fill in a blueprint's declared variables, render
// it (the server does pure ${var} string substitution — NOTHING is executed)
// and copy / download the result. Opt-in: the page + nav hide unless the
// `show_provisioning` instance flag is on. (v5.6.0)

let _provisioningCache = [];
let _bpRenderState = null;   // { id, filename } of the blueprint open in the render modal
let _bpRunState = null;      // { id, name } of the blueprint open in the run modal
let _provExec = false;       // terraform plan/apply/destroy available (enabled + binary present)

async function loadProvisioning() {
  const tree = document.getElementById('provisioning-tree');
  if (tree) tree.innerHTML = '<div class="empty-state">Loading…</div>';
  const d = await api('GET', '/provisioning/blueprints');
  if (!d) return;
  if (!d.enabled) {
    _provisioningCache = [];
    if (tree) tree.innerHTML = '<div class="empty-state">Provisioning is disabled. Enable it under Settings → Advanced.</div>';
    return;
  }
  _provExec = !!(d.execute_enabled && d.terraform_available);
  _provisioningCache = d.blueprints || [];
  // Also load the Ansible playbooks card (consolidated under Provisioning).
  if (typeof loadAnsible === 'function') { try { loadAnsible(); } catch (_) {} }
  _renderProvisioningTree();
}

function filterProvisioning() { _renderProvisioningTree(); }

function _renderProvisioningTree() {
  const tree = document.getElementById('provisioning-tree');
  if (!tree) return;
  const q = (document.getElementById('provisioning-filter')?.value || '').trim().toLowerCase();
  let bps = _provisioningCache.slice();
  if (q) bps = bps.filter(b => (`${b.name} ${b.folder || ''} ${b.kind}`).toLowerCase().includes(q));
  if (!bps.length) {
    tree.innerHTML = '<div class="empty-state">' +
      (q ? 'No blueprints match the filter.'
         : 'No blueprints yet. Create one to spin up machines from a click.') + '</div>';
    return;
  }
  // Group by folder path; render a header per folder, items indented beneath.
  const folders = {};
  bps.forEach(b => { const f = b.folder || ''; (folders[f] = folders[f] || []).push(b); });
  const names = Object.keys(folders).sort((a, b) => a.localeCompare(b));
  let html = '';
  names.forEach(f => {
    const label = f === '' ? '/' : f;
    html += `<div class="bp-folder">${_icon('layers', 14)} ${escHtml(label)}</div>`;
    folders[f].sort((a, b) => a.name.localeCompare(b.name)).forEach(b => { html += _bpRow(b); });
  });
  tree.innerHTML = html;
}

function _bpRow(b) {
  // terraform blueprints can be executed server-side when the gate is on.
  const runBtn = (b.kind === 'terraform' && _provExec)
    ? `<button class="btn-icon" data-action-btn="_blueprintRunBtn" data-id="${escAttr(b.id)}" title="Run on the server — plan / apply / destroy">${_icon('terminal', 13)} Run</button>`
    : '';
  const lastRc = (b.last_rc === 0) ? '<span class="patch-badge ok fs-11">ok</span>'
    : (typeof b.last_rc === 'number') ? `<span class="patch-badge c-red fs-11">${escHtml(b.last_op || 'run')} rc=${b.last_rc}</span>` : '';
  return `<div class="bp-item">
    <span class="bp-item-name">${_icon('fileCode', 13)} ${escHtml(b.name)}</span>
    <span class="bp-kind">${escHtml(b.kind)}</span>
    ${lastRc}
    <span class="bp-item-actions">
      ${runBtn}
      <button class="btn-icon" data-action-btn="_blueprintRenderBtn" data-id="${escAttr(b.id)}" title="Fill variables and render">${_icon('play', 13)} Render</button>
      <button class="btn-icon" data-action-btn="_blueprintEditBtn" data-id="${escAttr(b.id)}" title="Edit">${_icon('edit', 13)} Edit</button>
      <button class="btn-icon c-danger-outline" data-action="deleteBlueprint" data-arg="${escAttr(b.id)}" title="Delete">${_icon('trash', 13)}</button>
    </span>
  </div>`;
}

// ── create / edit ───────────────────────────────────────────────────────────

// Variables textarea ⇄ array. One per line: `name | Label | default | secret`
// (the `| secret` flag is optional and may also be the literal word "secret").
function _bpVarsToText(vars) {
  return (vars || []).map(v => {
    const parts = [v.name, v.label || '', v.default || ''];
    if (v.secret) parts.push('secret');
    return parts.join(' | ');
  }).join('\n');
}

function _bpVarsFromText(text) {
  const out = [];
  (text || '').split('\n').forEach(line => {
    if (!line.trim()) return;
    const parts = line.split('|').map(s => s.trim());
    const name = (parts[0] || '').replace(/[^A-Za-z0-9_]/g, '');
    if (!name) return;
    const secret = parts.slice(1).some(p => /^secret$/i.test(p));
    out.push({ name, label: parts[1] || '', default: secret ? '' : (parts[2] || ''), secret });
  });
  return out;
}

function openBlueprintCreate() {
  document.getElementById('blueprint-edit-id').value = '';
  document.getElementById('blueprint-name').value = '';
  document.getElementById('blueprint-folder').value = '';
  document.getElementById('blueprint-kind').value = 'terraform';
  document.getElementById('blueprint-content').value = '';
  document.getElementById('blueprint-vars').value = '';
  document.getElementById('blueprint-modal-title').textContent = 'New blueprint';
  document.getElementById('blueprint-save-btn').textContent = 'Create';
  openModal('blueprint-modal');
}

function _blueprintEditBtn(btn) {
  const b = _provisioningCache.find(x => x.id === btn.dataset.id);
  if (!b) return;
  document.getElementById('blueprint-edit-id').value = b.id;
  document.getElementById('blueprint-name').value = b.name || '';
  document.getElementById('blueprint-folder').value = b.folder || '';
  document.getElementById('blueprint-kind').value = b.kind || 'terraform';
  document.getElementById('blueprint-content').value = b.content || '';
  document.getElementById('blueprint-vars').value = _bpVarsToText(b.variables);
  document.getElementById('blueprint-modal-title').textContent = 'Edit blueprint';
  document.getElementById('blueprint-save-btn').textContent = 'Save';
  openModal('blueprint-modal');
}

async function saveBlueprint() {
  const id = document.getElementById('blueprint-edit-id').value;
  const body = {
    name: document.getElementById('blueprint-name').value.trim(),
    folder: document.getElementById('blueprint-folder').value.trim(),
    kind: document.getElementById('blueprint-kind').value,
    content: document.getElementById('blueprint-content').value,
    variables: _bpVarsFromText(document.getElementById('blueprint-vars').value),
  };
  if (!body.name || !body.content.trim()) { toast('Name and template content are required', 'error', {transient: true}); return; }
  const d = id ? await api('PUT', '/provisioning/blueprints/' + encodeURIComponent(id), body)
               : await api('POST', '/provisioning/blueprints', body);
  if (d?.ok) { toast(id ? 'Blueprint saved' : 'Blueprint created', 'success'); closeModal('blueprint-modal'); loadProvisioning(); }
  else toast(d?.error || 'Failed', 'error');
}

async function deleteBlueprint(id) {
  id = String(id);
  if (!await uiConfirm('Delete this blueprint?')) return;
  const d = await api('DELETE', '/provisioning/blueprints/' + encodeURIComponent(id));
  if (d?.ok) { toast('Blueprint deleted', 'info'); loadProvisioning(); }
  else toast(d?.error || 'Failed', 'error');
}

// ── render ────────────────────────────────────────────────────────────────

function _blueprintRenderBtn(btn) {
  const b = _provisioningCache.find(x => x.id === btn.dataset.id);
  if (!b) return;
  _bpRenderState = { id: b.id, filename: b.name };
  document.getElementById('blueprint-render-id').value = b.id;
  document.getElementById('blueprint-render-modal-title').textContent = 'Render — ' + b.name;
  document.getElementById('blueprint-render-out').value = '';
  // Build one input per declared variable.
  const host = document.getElementById('blueprint-render-vars');
  const vars = b.variables || [];
  if (!vars.length) {
    host.innerHTML = '<div class="hint mb-8">This blueprint declares no variables — just click Render. The ${rp_server_url} and ${rp_agent_install} macros are always available.</div>';
  } else {
    host.innerHTML = vars.map(v => {
      const ph = v.secret ? (v.default_set ? '(stored sample hidden)' : '') : (v.default || '');
      return `<div class="form-group"><label class="form-label">${escHtml(v.label || v.name)} <span class="hint">\${${escHtml(v.name)}}</span></label>
        <input type="${v.secret ? 'password' : 'text'}" class="form-input bp-var-input" data-var="${escAttr(v.name)}" value="${escAttr(v.secret ? '' : (v.default || ''))}" placeholder="${escAttr(ph)}"${v.secret ? ' autocomplete="new-password"' : ''}></div>`;
    }).join('');
  }
  openModal('blueprint-render-modal');
}

async function renderBlueprint() {
  if (!_bpRenderState) return;
  const vars = {};
  document.querySelectorAll('#blueprint-render-vars .bp-var-input').forEach(inp => {
    vars[inp.dataset.var] = inp.value;
  });
  const d = await api('POST', '/provisioning/blueprints/' + encodeURIComponent(_bpRenderState.id) + '/render', { vars });
  if (!d?.ok) { toast(d?.error || 'Render failed', 'error'); return; }
  document.getElementById('blueprint-render-out').value = d.rendered || '';
  if (d.filename) _bpRenderState.filename = d.filename;
  if (d.missing && d.missing.length) toast('Unfilled placeholders left as-is: ' + d.missing.join(', '), 'info');
}

function copyBlueprintRender() {
  const out = document.getElementById('blueprint-render-out').value;
  if (!out) { toast('Nothing to copy — render first', 'info'); return; }
  navigator.clipboard?.writeText(out).then(
    () => toast('Copied to clipboard', 'success'),
    () => toast('Copy failed', 'error'));
}

function downloadBlueprintRender() {
  const out = document.getElementById('blueprint-render-out').value;
  if (!out) { toast('Nothing to download — render first', 'info'); return; }
  const name = (_bpRenderState && _bpRenderState.filename) || 'blueprint.txt';
  const blob = new Blob([out], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = name; document.body.appendChild(a); a.click();
  a.remove(); URL.revokeObjectURL(url);
}

// ── execute (terraform: plan / apply / destroy) ─────────────────────────────

function _blueprintRunBtn(btn) {
  const b = _provisioningCache.find(x => x.id === btn.dataset.id);
  if (!b) return;
  _bpRunState = { id: b.id, name: b.name };
  document.getElementById('blueprint-run-id').value = b.id;
  document.getElementById('blueprint-run-name').textContent = b.name;
  document.getElementById('blueprint-run-out').value = '';
  const host = document.getElementById('blueprint-run-vars');
  const vars = b.variables || [];
  host.innerHTML = vars.length ? vars.map(v =>
    `<div class="form-group"><label class="form-label">${escHtml(v.label || v.name)} <span class="hint">var.${escHtml(v.name)}</span></label>
      <input type="${v.secret ? 'password' : 'text'}" class="form-input bp-run-input" data-var="${escAttr(v.name)}" value="${escAttr(v.secret ? '' : (v.default || ''))}"${v.secret ? ' autocomplete="new-password" placeholder="(secret — passed as env, never written to disk)"' : ''}></div>`
  ).join('') : '<div class="hint mb-8">No declared variables — the blueprint runs as-is.</div>';
  openModal('blueprint-run-modal');
}

async function runBlueprintOp(op) {
  if (!_bpRunState) return;
  if ((op === 'apply' || op === 'destroy') &&
      !await uiConfirm(`terraform ${op} will change real infrastructure for "${_bpRunState.name}". Continue?`)) return;
  const vars = {};
  document.querySelectorAll('#blueprint-run-vars .bp-run-input').forEach(inp => { vars[inp.dataset.var] = inp.value; });
  const outEl = document.getElementById('blueprint-run-out');
  // Disable every run button while terraform is executing — a second click
  // would launch a concurrent plan/apply/destroy against the same state.
  const runBtns = document.querySelectorAll('#blueprint-run-modal [data-action="runBlueprintOp"], [data-action="runBlueprintOp"]');
  runBtns.forEach(b => { b.disabled = true; });
  outEl.value = `Running terraform ${op}…`;
  let r;
  try {
    r = await api('POST', '/provisioning/blueprints/' + encodeURIComponent(_bpRunState.id) + '/run', { op, vars });
  } finally {
    runBtns.forEach(b => { b.disabled = false; });
  }
  if (!r) { outEl.value = 'Request failed.'; return; }
  if (r.error) { outEl.value = r.error; toast(r.error, 'error'); return; }
  outEl.value = r.output || '(no output)';
  toast(`terraform ${op} ${r.ok ? 'succeeded' : 'exited rc=' + r.rc}`, r.ok ? 'success' : 'error');
  loadProvisioning();   // refresh the last-run badge
}
