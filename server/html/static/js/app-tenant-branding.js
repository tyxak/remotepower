// app-tenant-branding.js — the name and accent colour of a tenant (8.0.0). Buildless classic script, fetched by the click dispatcher the first time the Branding button is used.
//
// GET and PUT /api/tenants/<id>/branding have existed since 6.1.1 (a platform superadmin may brand any tenant, a tenant's own administrator may brand theirs) and nothing in the page
// called them, so a tenant could be branded only by calling the API. The Tenants list now has a Branding button on each row, and a tenant's own administrator has a card under the
// installation's Branding in Settings → General. Both open this one dialog. What the server would refuse stays the server's call: the dialog only says why (api() does, once; failToast adds the case of no answer at all). Text that comes from the
// server is set as a property or as textContent, never put into markup.

let _tenantBrandingId = '';

async function openTenantBranding(id, name) {
  if (!id) return;
  const r = await api('GET', `/tenants/${encodeURIComponent(id)}/branding`).catch(() => null);
  if (!r || r.error || r.ok === false) { failToast(r); return; }
  _tenantBrandingId = id;
  document.getElementById('tenant-branding-who').textContent = name ? `${name} (${id})` : id;
  document.getElementById('tenant-branding-name').value = r.name || '';
  const accent = document.getElementById('tenant-branding-accent');
  accent.value = [...accent.options].some(o => o.value === r.accent) ? r.accent : '';
  openModal('tenant-branding-modal');
}

async function saveTenantBranding() {
  const id = _tenantBrandingId;
  if (!id) return;
  const name = document.getElementById('tenant-branding-name').value.trim();
  const accent = document.getElementById('tenant-branding-accent').value;
  const r = await api('PUT', `/tenants/${encodeURIComponent(id)}/branding`, {name, accent}).catch(() => null);
  if (!r || r.error || r.ok === false) { failToast(r); return; }   // api() has already said why when the server answered; this is for a request that never did
  toast('Branding saved', 'success');
  closeModal('tenant-branding-modal');
  if (_meCache && _meCache.tenant === id) loadMe();     // the caller's own tenant: the shell shows it at once, as it does for the installation's branding
}
