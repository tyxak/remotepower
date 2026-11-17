// app-enrol.js — the install commands that are still open, at the foot of the Enroll dialog. Buildless classic script; every symbol is global like the
// rest of the client JS, and it is fetched when the dialog opens (the lazy map in app.js). The wizards are a separate module that the dialog does not fetch.
//
//   enrolOpenList()   what GET /enrollment-tokens lists: each command that can still enroll a host, as "used 2 of 10" with the time it has left and
//                     a Revoke. A token is never shown beyond the prefix the server sends.
//   enrolRevoke(arg)  asks, then DELETE /enrollment-tokens/<prefix>, then draws the list again.
//
// The words are separate text nodes so that the translation engine can match them; the prefix, the label and the numbers are set as text, never as markup.

function _enrolNode(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = text;
  return n;
}

async function enrolOpenList() {
  const box = document.getElementById('enroll-open-list');
  if (!box) return;
  const rows = await api('GET', '/enrollment-tokens').catch(() => null);
  if (document.getElementById('enroll-open-list') !== box) return;       // the dialog was redrawn while this waited
  box.textContent = '';
  if (!Array.isArray(rows)) return;                                       // not allowed to list them: the section stays empty
  if (!rows.length) { box.appendChild(_enrolNode('div', 'hint', 'No install commands are open.')); return; }
  rows.forEach(r => {
    const row = _enrolNode('div', 'enroll-open-row');
    const main = _enrolNode('div', 'enroll-open-main');
    const prefix = _enrolNode('span', 'ff-mono', String(r.prefix || ''));
    prefix.setAttribute('data-no-i18n', '');
    main.appendChild(prefix);
    if (r.label) {
      const label = _enrolNode('span', 'wiz-chip', String(r.label));
      label.setAttribute('data-no-i18n', '');
      main.append(' ', label);
    }
    const used = _enrolNode('div', 'hint');
    used.append(_enrolNode('span', '', 'used'), ' ', _enrolNode('span', 'ff-mono', String(r.uses)), ' ', _enrolNode('span', '', 'of'), ' ', _enrolNode('span', 'ff-mono', String(r.max_uses)));
    const left = _enrolNode('div', 'hint');
    left.append(_enrolNode('span', '', 'Expires in'), ' ', _enrolNode('span', 'ff-mono', _fmtDuration(r.remaining_seconds)));
    const revoke = _enrolNode('button', 'btn-icon btn-xs c-danger-outline', 'Revoke');
    revoke.type = 'button';
    revoke.setAttribute('data-action', 'enrolRevoke');
    revoke.setAttribute('data-arg', 'tk-' + String(r.prefix || '').replace(/…$/, ''));     // marked so that a prefix of digits is not read as a number
    row.append(main, used, left, revoke);
    box.appendChild(row);
  });
}

async function enrolRevoke(arg) {
  const prefix = String(arg || '').replace(/^tk-/, '');
  if (!prefix) return;
  if (!await uiConfirm({ message: 'Revoke this install command? It stops working at once, for hosts that have not enrolled with it yet.', confirmText: 'Revoke', danger: true })) return;
  const r = await api('DELETE', '/enrollment-tokens/' + encodeURIComponent(prefix));
  if (r && r.ok) toast('Install command revoked', 'success');
  else toast((r && r.error) || 'Could not revoke the install command', 'error');
  enrolOpenList();
}
