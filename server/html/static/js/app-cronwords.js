// app-cronwords.js — the words for a cron expression (lazy; the pages that draw a schedule load it first).
// cronHtml() and cronInline() stay in app.js and call cronWords() only when it is there, so a schedule drawn before this file has
// loaded shows the expression alone. tests/test_cron_words.py holds the words.

// A cron expression in plain words, for the tables that show a schedule: `*/15 9-17 * * 1-5` reads
// "Every 15 minutes from 09:00 to 17:59, weekdays". It words the common shapes exactly and returns '' for anything else, so
// the caller shows the expression alone: wrong words are worse than none. Two things it never guesses. A day of the month
// together with a weekday (cron runs on either, which no short phrase says), and a step that does not divide its field
// (`*/7` minutes starts again every hour). A day of the month past the 28th is left alone too: the months without it are skipped. Times are 24-hour, in the server's time zone like the schedule itself.
function cronWords(expr) {
  const src = String(expr == null ? '' : expr).trim().toLowerCase();
  if (!src) return '';
  if (src === '@reboot') return 'At boot';
  const MACROS = { '@hourly': '0 * * * *', '@daily': '0 0 * * *', '@midnight': '0 0 * * *', '@weekly': '0 0 * * 0',
    '@monthly': '0 0 1 * *', '@yearly': '0 0 1 1 *', '@annually': '0 0 1 1 *' };
  const parts = (MACROS[src] || src).split(/\s+/);
  if (parts.length !== 5) return '';
  const MON = ['jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];
  const DOW = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'];
  const DOW_LONG = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
  const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);
  const pad = (n) => (n < 10 ? '0' : '') + n;
  const hhmm = (h, m) => pad(h) + ':' + pad(m);
  const and = (items) => items.length < 2 ? items.join('') : items.slice(0, -1).join(', ') + ' and ' + items[items.length - 1];
  // One field: {any: true}, {step: n} for `*/n`, or {vals: [...], range: [a, b] when the whole field is one a-b range}.
  const field = (text, lo, hi, names, sevenIsZero) => {
    if (text === '*') return { any: true };
    const stepM = /^\*\/(\d+)$/.exec(text);
    if (stepM) { const n = Number(stepM[1]); return n >= 1 && n <= hi ? { step: n } : null; }
    const num = (t) => {
      if (/^\d+$/.test(t)) return Number(t);
      const i = names ? names.indexOf(t) : -1;
      return i < 0 ? NaN : i + (names === MON ? 1 : 0);
    };
    const vals = [];
    let range = null;
    const items = text.split(',');
    for (const it of items) {
      const r = /^([a-z0-9]+)-([a-z0-9]+)$/.exec(it);
      if (r) {
        let a = num(r[1]), b = num(r[2]);
        if (!(a >= lo && b <= hi && a <= b)) return null;
        for (let v = a; v <= b; v++) vals.push(v);
        if (items.length === 1) range = [a, b];
      } else {
        const v = num(it);
        if (!(v >= lo && v <= hi)) return null;
        vals.push(v);
      }
    }
    const set = Array.from(new Set(vals.map(v => (sevenIsZero && v === 7 ? 0 : v)))).sort((x, y) => x - y);
    if (!set.length) return null;
    return { vals: set, range: range && range[0] !== range[1] ? range : null };
  };
  let M = field(parts[0], 0, 59), H = field(parts[1], 0, 23);
  const D = field(parts[2], 1, 31), N = field(parts[3], 1, 12, MON), W = field(parts[4], 0, 7, DOW, true);
  if (!M || !H || !D || !N || !W) return '';
  // A list that is a step written out (`0,30` is `*/30`, `0,6,12,18` is `*/6`) reads as the step, so one schedule has one reading.
  const asStep = (f, limit) => {
    const v = f.vals;
    if (!v || v.length < 2 || v[0] !== 0) return f;
    const d = v[1] - v[0];
    for (let i = 1; i < v.length; i++) if (v[i] - v[i - 1] !== d) return f;
    return limit % d === 0 && v[v.length - 1] + d === limit ? { step: d } : f;
  };
  M = asStep(M, 60);
  H = asStep(H, 24);
  if (M.step === 1) M = { any: true };                                  // `*/1`, `0-59` and every value listed are `*`
  if (H.step === 1) H = { any: true };
  const full = (f, n, lo) => f.vals && f.vals.length === n && f.vals[0] === lo;   // every value listed is the same as `*`
  if (full(N, 12, 1)) { delete N.vals; N.any = true; }
  // Not for the day fields while the other one is restricted: `1-31` is not `*` to cron, so `0 3 1-31 * 1` runs every day, not on Mondays.
  const dayAny = D.any, weekAny = W.any;
  if (weekAny && full(D, 31, 1)) { delete D.vals; D.any = true; }
  if (dayAny && full(W, 7, 0)) { delete W.vals; W.any = true; }
  if (D.step || N.step || W.step) return '';
  if (D.vals && D.vals[D.vals.length - 1] > 28) return '';             // day 29 to 31 is skipped in the months that lack it
  if (M.step && (60 % M.step !== 0)) return '';
  if (H.step && (24 % H.step !== 0)) return '';
  if (!D.any && !W.any) return '';                                    // either matches: no short phrase says that
  // The time of day: `times` for a list of clock times, or an interval phrase.
  let times = null, interval = null;
  if (H.any) {
    if (M.any) interval = 'Every minute';
    else if (M.step) interval = 'Every ' + M.step + ' minutes';
    else interval = M.vals.length === 1 && M.vals[0] === 0 ? 'Every hour'
      : M.vals.length === 1 ? 'Every hour at :' + pad(M.vals[0]) : 'Every hour at ' + and(M.vals.map(m => ':' + pad(m)));
  } else if (H.step) {
    if (!M.vals || M.vals.length !== 1) return '';
    const every = 'Every ' + H.step + ' hours';
    interval = M.vals[0] === 0 ? every : every + ' at :' + pad(M.vals[0]);
  } else if (H.range) {
    const [a, b] = H.range;
    if (M.any || M.step) interval = (M.any ? 'Every minute' : 'Every ' + M.step + ' minutes') + ' from ' + hhmm(a, 0) + ' to ' + hhmm(b, 59);
    else if (M.vals.length === 1) interval = 'Every hour from ' + hhmm(a, M.vals[0]) + ' to ' + hhmm(b, M.vals[0]);
    else return '';
  } else if (H.vals.length === 1 && (M.any || M.step)) {
    const h = H.vals[0];
    interval = (M.any ? 'Every minute' : 'Every ' + M.step + ' minutes') + ' from ' + hhmm(h, 0) + ' to ' + hhmm(h, 59);
  } else {
    const mins = M.vals || (M.step ? Array.from({ length: 60 / M.step }, (_, i) => i * M.step) : null);
    if (!mins) return '';
    times = [];
    for (const h of H.vals) for (const m of mins) times.push(hhmm(h, m));
    if (times.length > 6) return '';
  }
  // The days.
  const monthsOf = (f) => f.vals.map(v => cap(MON[v - 1]));
  const dowPhrase = () => {
    const v = W.vals;
    if (v.length === 5 && v.join() === '1,2,3,4,5') return 'weekdays';
    if (v.length === 2 && v.join() === '0,6') return 'weekends';
    if (v.length === 1) return DOW_LONG[v[0]] + 's';
    return and(v.map(d => cap(DOW[d])));
  };
  if (interval) {
    if (D.any && N.any && W.any) return interval;
    if (D.any && N.any && !W.any) {
      const p = dowPhrase();
      return interval + ', ' + (p === 'weekdays' || p === 'weekends' ? p : 'on ' + p);
    }
    return '';
  }
  const at = ' at ' + and(times);
  if (D.any && N.any && W.any) return 'Daily' + at;
  if (D.any && N.any) return cap(dowPhrase()) + at;
  if (D.any && !N.any && W.any) return 'Daily in ' + and(monthsOf(N)) + at;
  if (D.any && !N.any) return cap(dowPhrase()) + ' in ' + and(monthsOf(N)) + at;
  // a day of the month (the weekday is `*` by the guard above)
  if (N.any) return (D.vals.length === 1 ? 'Monthly on day ' + D.vals[0] : 'Days ' + and(D.vals.map(String)) + ' of the month') + at;
  if (D.vals.length === 1) {
    const ds = monthsOf(N).map(m => D.vals[0] + ' ' + m);
    return (ds.length === 1 ? 'Yearly on ' : 'On ') + and(ds) + at;
  }
  return '';
}
