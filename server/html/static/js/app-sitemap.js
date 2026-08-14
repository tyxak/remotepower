// app-sitemap.js — the product map ("All pages").
//
// Lazy on purpose: it renders only when the dialog is opened, and the eager JS
// payload carries a hard budget that this would otherwise have blown by 4,221
// bytes. `openSitemap()` stays in app.js as a four-line loader stub because the
// sidebar button is reachable from every page, so the module is not page-scoped
// and cannot ride _LAZY_PAGE_MODULES.
//
// Everything here is DERIVED FROM THE SIDEBAR DOM. See
// tests/test_v700_sitemap.py for why that matters more than it looks.

// 89 pages across 12 domains, with the sidebar showing one domain at a time,
// left no surface answering "what is in this product and where". The command
// palette and the sidebar search both require already knowing what to type.
//
// DERIVED FROM THE SIDEBAR, not from a list. Every nav button already carries a
// one-line `title`, so a hand-kept copy would be a second registry — and every
// recurring bug in this project's notes is two registries drifting apart. It
// also means a page hidden by a module gate is absent here for free, because it
// is hidden there, and a page added tomorrow appears with no edit to this code.
function _sitemapGroups() {
  return [...document.querySelectorAll('.sidebar-group')].map(g => {
    const head = g.querySelector('.sidebar-group-toggle span:not(.nav-group-badge)');
    const pages = [...g.querySelectorAll('.nav-btn[data-page]')]
      .filter(b => !b.classList.contains('hidden')
                   && getComputedStyle(b).display !== 'none')
      .map(b => {
        const lbl = [...b.querySelectorAll('span')].find(
          x => !x.classList.contains('nav-badge')
               && !x.classList.contains('nav-group-badge'));
        return {
          page: b.dataset.page,
          label: (lbl ? lbl.textContent : b.textContent).trim(),
          desc: (b.getAttribute('title') || '').trim(),
        };
      });
    return { group: g.dataset.group,
             title: (head ? head.textContent : g.dataset.group).trim(),
             pages };
  }).filter(x => x.pages.length);
}

function renderSitemap(filter) {
  const body = document.getElementById('sitemap-body');
  if (!body) return;
  const q = (filter || '').trim().toLowerCase();
  const groups = _sitemapGroups();
  let shown = 0;
  const html = groups.map(g => {
    const hits = g.pages.filter(p => !q
      || p.label.toLowerCase().includes(q)
      || p.desc.toLowerCase().includes(q)
      || g.title.toLowerCase().includes(q));
    if (!hits.length) return '';
    shown += hits.length;
    return `<div class="sitemap-group">`
      + `<div class="section-title">${escHtml(g.title)}`
      + ` <span class="chk-pill chk-unknown">${hits.length}</span></div>`
      + `<div class="sitemap-cards">` + hits.map(p =>
          `<button class="sitemap-card" data-action="sitemapGo" `
          + `data-arg="${escAttr(p.page)}">`
          + `<span class="sitemap-card-name">${escHtml(p.label)}</span>`
          + `<span class="sitemap-card-desc">${escHtml(p.desc)}</span></button>`
        ).join('') + `</div></div>`;
  }).join('');
  body.innerHTML = html || `<div class="empty-state">${
    escHtml('No page matches that.')}</div>`;
  const t = document.getElementById('sitemap-title');
  if (t) {
    const total = groups.reduce((n, g) => n + g.pages.length, 0);
    t.textContent = q ? `All pages — ${shown} of ${total}` : `All pages — ${total}`;
  }
}

function sitemapGo(page) {
  closeModal('sitemap-modal');
  try { showPage(page); } catch (_) {}
}

document.addEventListener('input', (e) => {
  if (e.target && e.target.id === 'sitemap-filter') renderSitemap(e.target.value);
});
document.addEventListener('keydown', (e) => {
  if (e.key !== 'Enter' || !e.target || e.target.id !== 'sitemap-filter') return;
  const first = document.querySelector('#sitemap-body .sitemap-card');
  if (!first) return;
  // Call the action directly and stop the event, rather than synthesising a
  // click. Measured: the click DID navigate but left the dialog open, because
  // the keydown carried on to another handler after closeModal had run. A
  // mouse click on the same card closed it correctly, which is what made the
  // difference visible — worth keeping in mind when a keyboard path behaves
  // differently from the pointer path that shares its handler.
  e.preventDefault();
  e.stopPropagation();
  sitemapGo(first.getAttribute('data-arg'));
});


