/* 7.4.9: the Home hero of the Pilot look. Lazy: it is fetched only when the page draws Home under the Pilot look, so Classic never
 * loads it (app.js has the one eager function that asks for it, _renderHomeHero).
 *
 * Two things, side by side. On the left the number of hosts online as a dot-matrix readout (each digit is a 5 by 7 grid of dots, the
 * unlit ones faintly visible, like a display). On the right the fleet as a field of lights, one dot per host, grouped by host group,
 * coloured by the same facts the Fleet health card uses: a host is critical when it is offline or has a critical finding, a warning
 * when it has a warning, otherwise fine, and a hollow dot when it is not monitored.
 *
 * It requests nothing. The host list and the per-host counts are what loadHome already holds. Everything is drawn with
 * createElement, textContent and dataset: host names are other people's text and never reach innerHTML.
 */
const _PILOT_GLYPHS = {
  '0': ['01110', '10001', '10011', '10101', '11001', '10001', '01110'],
  '1': ['00100', '01100', '00100', '00100', '00100', '00100', '01110'],
  '2': ['01110', '10001', '00001', '00010', '00100', '01000', '11111'],
  '3': ['11110', '00001', '00001', '01110', '00001', '00001', '11110'],
  '4': ['00010', '00110', '01010', '10010', '11111', '00010', '00010'],
  '5': ['11111', '10000', '11110', '00001', '00001', '10001', '01110'],
  '6': ['00110', '01000', '10000', '11110', '10001', '10001', '01110'],
  '7': ['11111', '00001', '00010', '00100', '01000', '01000', '01000'],
  '8': ['01110', '10001', '10001', '01110', '10001', '10001', '01110'],
  '9': ['01110', '10001', '10001', '01111', '00001', '00010', '01100'],
};
const _PILOT_SVG_NS = 'http://www.w3.org/2000/svg';
// The class of a dot for each state, written out so the stylesheet's rules can be found from the code that uses them.
const _PILOT_STATE_CLASS = { ok: 'is-ok', warn: 'is-warn', crit: 'is-crit', none: 'is-none' };
// A fleet this large is drawn as far as this many dots and then says how many more there are: the field is a picture, and past a
// thousand and a half dots it stops being one.
const _PILOT_MAX_DOTS = 1500;

// The text as a grid of dots: an SVG with one circle per cell, class "on" for a lit one and "off" for the rest. Characters that are
// not digits are left out. The colour is the element's own, so the readout takes the state colour from its container.
function _pilotDotMatrix(text, pitch = 8, radius = 3.15) {
  const chars = [...String(text)].filter(c => _PILOT_GLYPHS[c]);
  const svg = document.createElementNS(_PILOT_SVG_NS, 'svg');
  svg.setAttribute('class', 'dm');
  svg.setAttribute('viewBox', `0 0 ${Math.max(chars.length * 6 - 1, 1) * pitch} ${7 * pitch}`);
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('focusable', 'false');
  chars.forEach((ch, i) => {
    _PILOT_GLYPHS[ch].forEach((row, y) => {
      [...row].forEach((bit, x) => {
        const c = document.createElementNS(_PILOT_SVG_NS, 'circle');
        c.setAttribute('class', bit === '1' ? 'on' : 'off');
        c.setAttribute('cx', String((i * 6 + x + 0.5) * pitch));
        c.setAttribute('cy', String((y + 0.5) * pitch));
        c.setAttribute('r', String(radius));
        svg.appendChild(c);
      });
    });
  });
  return svg;
}

// 'none' (not monitored), 'crit' (offline, or a critical finding), 'warn' (a warning) or 'ok', for one host. `rec` is the host's
// row of the Fleet health payload ({critical, warning, ...}), absent for a host the health score leaves out.
function _pilotHostState(d, rec) {
  if (d.monitored === false) return 'none';
  if (!d.online || (rec && rec.critical > 0)) return 'crit';
  if (rec && rec.warning > 0) return 'warn';
  return 'ok';
}

function _pilotEl(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}

// Draws the hero into `host` (the #home-hero element). `devs` is the slim host list of /api/home, `health` its health payload.
// A fleet with no hosts has no hero: there is nothing to read yet, and an empty panel on a fresh install says nothing.
function _pilotHeroRender(host, devs, health) {
  const list = Array.isArray(devs) ? devs : [];
  if (!list.length) {
    host.replaceChildren();
    host.hidden = true;
    host.classList.remove('is-ready');
    return;
  }
  const per = new Map(((health && Array.isArray(health.devices)) ? health.devices : []).map(h => [h.device_id, h]));
  const monitored = list.filter(d => d.monitored !== false);
  const online = monitored.filter(d => d.online).length;
  const offline = monitored.length - online;

  // the readout: how many are online, in dots, and the same sentence the tile under it used to carry
  const readout = _pilotEl('div', 'pilot-readout');
  readout.setAttribute('role', 'button');
  readout.setAttribute('tabindex', '0');
  readout.dataset.action = 'statNav';
  readout.dataset.arg = 'devices';
  readout.appendChild(_pilotEl('div', 'pilot-eyebrow', 'Hosts online'));
  const num = _pilotEl('div', 'pilot-num ' + (offline === 0 ? 'is-ok' : (offline * 4 > monitored.length ? 'is-crit' : 'is-warn')));
  num.appendChild(_pilotDotMatrix(online));
  num.appendChild(_pilotEl('span', 'visually-hidden', String(online)));    // the dots are for the eye; this is what is read out
  readout.appendChild(num);
  readout.appendChild(_pilotEl('div', 'pilot-cap',
    offline === 0 ? 'All hosts reporting in' : (offline === 1 ? '1 host offline' : `${offline} hosts offline`)));

  // the field: clusters by host group, a dot per host
  const shown = list.slice(0, _PILOT_MAX_DOTS);
  const groups = new Map();
  shown.forEach(d => {
    const g = String(d.group || '');
    if (!groups.has(g)) groups.set(g, []);
    groups.get(g).push(d);
  });
  const order = [...groups.keys()].sort((a, b) => (a === '') - (b === '') || a.localeCompare(b));   // unnamed last
  const size = shown.length <= 48 ? '' : (shown.length <= 160 ? ' is-md' : ' is-sm');
  const matrix = _pilotEl('div', 'pilot-matrix' + size);
  matrix.setAttribute('aria-hidden', 'true');
  const tally = { ok: 0, warn: 0, crit: 0, none: 0 };
  order.forEach(g => {
    const cluster = _pilotEl('div', 'pilot-cluster');
    const row = _pilotEl('div', 'pilot-row');
    groups.get(g).slice().sort((a, b) => String(a.name).localeCompare(String(b.name))).forEach(d => {
      const rec = per.get(d.id);
      const state = _pilotHostState(d, rec);
      tally[state]++;
      const dot = _pilotEl('span', 'pilot-dot ' + _PILOT_STATE_CLASS[state]);
      dot.dataset.dev = String(d.id);
      dot.dataset.name = String(d.name);
      let title = String(d.name);
      if (rec && rec.critical > 0) title += ` · ${rec.critical} critical`;
      if (rec && rec.warning > 0) title += ` · ${rec.warning} warning`;
      if (d.monitored !== false && !d.online) title += ' · offline';
      dot.title = title;
      row.appendChild(dot);
    });
    cluster.appendChild(row);
    if (!size && g) cluster.appendChild(_pilotEl('div', 'pilot-glabel', g));
    matrix.appendChild(cluster);
  });

  const legend = _pilotEl('div', 'pilot-legend');
  [['ok', 'Healthy'], ['warn', 'Warning'], ['crit', 'Critical'], ['none', 'Unmonitored']].forEach(([state, word]) => {
    if (!tally[state]) return;
    const key = _pilotEl('span', 'pilot-key');
    key.appendChild(_pilotEl('i', 'pilot-dot ' + _PILOT_STATE_CLASS[state]));
    key.appendChild(_pilotEl('span', null, word));
    key.appendChild(_pilotEl('span', 'pilot-count', String(tally[state])));
    legend.appendChild(key);
  });
  if (list.length > shown.length) legend.appendChild(_pilotEl('span', 'pilot-cap', `+${list.length - shown.length}`));

  const field = _pilotEl('div', 'pilot-field');
  field.appendChild(_pilotEl('div', 'pilot-eyebrow', 'Fleet'));
  field.appendChild(matrix);
  field.appendChild(legend);

  const hero = _pilotEl('div', 'pilot-hero');
  hero.appendChild(readout);
  hero.appendChild(field);
  host.replaceChildren(hero);
  host.hidden = false;
  host.classList.add('is-ready');
  // A field that is taller than its box scrolls. It is a picture for the eye and hidden from a screen reader, but a region that
  // scrolls has to be reachable from the keyboard and to have a name, so it becomes a labelled, focusable group only when it overflows.
  if (matrix.scrollHeight > matrix.clientHeight + 1) {
    matrix.removeAttribute('aria-hidden');
    matrix.setAttribute('role', 'group');
    matrix.setAttribute('aria-label', 'Fleet');
    matrix.setAttribute('tabindex', '0');
  }

  // a click on a dot opens that host; bound once, however often the hero is drawn again
  if (!host.dataset.pilotBound) {
    host.dataset.pilotBound = '1';
    host.addEventListener('click', e => {
      const dot = e.target && e.target.closest ? e.target.closest('.pilot-dot[data-dev]') : null;
      if (dot && host.contains(dot)) {
        try { openDeviceDrawer(dot.dataset.dev, dot.dataset.name); } catch (_) { /* the drawer is a convenience here */ }
      }
    });
  }
}
