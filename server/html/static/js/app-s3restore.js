// app-s3restore.js — restore the server from an archive in the S3 bucket (7.4.9). Buildless classic script; every symbol is global like the
// rest of the client JS. It is loaded on demand (the lazy map in app.js) the first time Restore from S3… is pressed; app.js holds the two
// functions the buttons call (openS3Restore, restoreFromS3) and loads this file before calling into it.
//
// A name that comes back from the bucket is data from outside: it is escaped as text and as an attribute, and the server has already
// refused every name that is not one the copy would have written.

// The list comes from the bucket named in the form as it stands (a rebuilt server has no saved settings), the restore is the one an
// upload uses, and the passphrase is asked for in the same way.
async function _s3RestoreOpen() {
  const list = document.getElementById('s3-restore-list'), err = document.getElementById('s3-restore-error');
  if (list) list.innerHTML = '<div class="empty-state">Loading…</div>';
  if (err) err.textContent = '';
  openModal('s3-restore-modal');
  const r = await api('POST', '/backup/s3-archives', { s3: _backupS3Form() });
  if (!list) return;
  if (!r || r.error || r.ok === false) { list.innerHTML = ''; if (err) err.textContent = failText(r); return; }
  const rows = r.archives || [];
  list.innerHTML = rows.length
    ? `<table class="data-table w-full"><thead><tr><th>Archive</th><th>Size</th><th>Date</th><th></th></tr></thead><tbody>${rows.map(a =>
        `<tr><td class="ff-mono">${escHtml(a.name)}</td><td class="hint">${escHtml(_fmtBytes(a.size))}</td>`
        + `<td class="hint">${a.mtime ? escHtml(_fmtAbsTs(a.mtime)) : '—'}</td>`
        + `<td><button class="btn-secondary" data-action="restoreFromS3" data-arg="${escAttr(a.name)}">Restore</button></td></tr>`).join('')}</tbody></table>`
      + (r.total > rows.length ? '<div class="hint mt-6">Older archives are not shown.</div>' : '')
    : '<div class="empty-state">No archives in the bucket.</div>';
}
async function _s3RestoreRun(name) {
  if (!await uiConfirm({ message: `Restore from "${name}" in the S3 bucket?\n\nThis OVERWRITES the current RemotePower data (hosts, config, all state, the credentials vault). A safety snapshot of the current data is taken automatically first. Continue?`, confirmText: 'Restore', danger: true })) return;
  const pass = await uiPrompt({
    title: 'Encrypted backup',
    message: `"${name}" is encrypted. Enter the backup passphrase (RP_BACKUP_PASSPHRASE on the server that wrote it).`,
    type: 'password', confirmText: 'Restore',
  });
  if (pass === null) return;                         // cancelled; an empty one is allowed through: the server falls back to its own
  const headers = { 'X-Token': getToken(), 'Content-Type': 'application/json' };
  if (pass) headers['X-RP-Backup-Passphrase'] = pass;
  const res = document.getElementById('backup-result');
  if (res) { res.hidden = false; res.textContent = 'Reading from the bucket & restoring…'; }
  closeModal('s3-restore-modal');
  try {
    const r = await fetch('/api/backup/s3-restore', { method: 'POST', headers, body: JSON.stringify({ name, s3: _backupS3Form() }) });
    const data = await r.json().catch(() => ({}));
    if (r.ok && data.ok) {
      if (res) res.textContent = `Restored ${data.restored} files. Safety snapshot: ${data.snapshot}. Reload the page to see the restored state.`;
      toast(`Restored ${data.restored} files`, 'success');
    } else {
      const msg = (data && data.error) || ('HTTP ' + r.status);
      if (res) res.textContent = 'Restore failed: ' + msg;
      toast('Restore failed: ' + msg, 'error');
    }
  } catch (e) {
    if (res) res.textContent = 'Restore failed: ' + e;
    toast('Restore failed', 'error');
  }
}

