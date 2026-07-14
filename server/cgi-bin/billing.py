"""Pure billing / time-tracking helpers for RemotePower (v5.4.0 "RackMatters").

No I/O, no api imports, no global state — every function operates on plain
dicts/lists passed in, so the whole module is unit-testable with fixtures
(mirrors the sibling pure modules: integrations.py, rag_index.py, wg_access.py).
api.py owns storage, auth and routing; this module owns the *math*:

  - hour validation/quantisation (the 0.25 step),
  - rate resolution (rate-card name -> per-site default -> global default),
  - VAT / currency resolution,
  - worksheet aggregation (billable hours x rate + recurring fees -> totals),
  - invoice totals,
  - calendar helpers (month bounds, ISO-week dates).

The single source of truth for the data shapes lives here in the docstrings:

time entry (TIME_ENTRIES_FILE -> {entries:[...], seq:int}):
  { id, number, date:'YYYY-MM-DD', user, hours:float(0.25 step), billable:bool,
    site_id,               # the PAYER (customer) — required when billable
    device_id, tag,        # finer attribution within the site (labels only)
    ticket_id, category, rate_name, note,
    invoice_id, locked:bool, created_at, updated_at }

billing config (BILLING_FILE):
  { currency, default_rate, default_vat, invoice_prefix,
    rate_card:[{name, rate}],
    sites:{ <site_id>: { default_rate?, vat?, billing_contact?, billing_address?,
                         recurring:[{id, label, kind, amount, qty, cadence, active}] } } }

invoice (INVOICES_FILE -> {invoices:[...], invoice_seq:int}):
  { id, number, site_id, period:{from,to}, status, currency, vat_rate,
    line_items:[{kind, label, qty, unit, amount}], snapshot_entry_ids:[...],
    subtotal, vat_amount, total, issued_at, created_by, notes }
"""

import calendar
import datetime
import re

HOURS_STEP = 0.25
MAX_ENTRY_HOURS = 24.0  # a single entry can't exceed one day
FEE_KINDS = ("license", "operation", "service", "other")
# Non-billable buckets the timesheet offers (billable ticket/site work uses
# the scope, not a category). Kept short and stable — the UI mirrors this list.
TIME_CATEGORIES = (
    "project",
    "meeting",
    "admin",
    "education",
    "travel",
    "internal",
    "support",
    "other",
)
DEFAULT_RATE_CARD = (
    {"name": "Standard", "rate": 0.0},
    {"name": "After-hours", "rate": 0.0},
    {"name": "Project", "rate": 0.0},
)


def _num(value, default=0.0):
    """Coerce to a finite float, else `default`. Rejects NaN/inf."""
    try:
        f = float(value)
    except (TypeError, ValueError):
        return default
    if f != f or f in (float("inf"), float("-inf")):
        return default
    return f


def quantize_hours(value):
    """Round to the nearest 0.25 and clamp to [0, MAX_ENTRY_HOURS]. Always a float.

    Any typed number snaps onto the 0.25 grid, so the UI can let people type
    `1.3` and store `1.25`. A bad/negative/NaN value collapses to 0.0 (the
    caller rejects a 0-hour entry)."""
    h = _num(value, 0.0)
    h = round(h / HOURS_STEP) * HOURS_STEP
    if h < 0:
        h = 0.0
    elif h > MAX_ENTRY_HOURS:
        h = MAX_ENTRY_HOURS
    return round(h, 2)


def rate_card_map(cfg):
    """{name: rate} from a billing config's rate_card (bad rows dropped)."""
    out = {}
    for r in cfg.get("rate_card") or []:
        name = str(r.get("name") or "").strip()
        if name:
            out[name] = max(0.0, _num(r.get("rate"), 0.0))
    return out


def site_billing(cfg, site_id):
    """The per-site billing sub-config dict (never None)."""
    return (cfg.get("sites") or {}).get(site_id) or {}


def resolve_rate(cfg, site_id, rate_name=None):
    """Effective hourly rate for (site, rate_name). Resolution order:
      1. the named rate from the rate card (if rate_name is given AND found),
      2. the site's own default_rate,
      3. the global default_rate.
    Returns a float >= 0 (0.0 if nothing is configured)."""
    if rate_name:
        card = rate_card_map(cfg)
        if rate_name in card:
            return card[rate_name]
    sb = site_billing(cfg, site_id)
    for cand in (sb.get("default_rate"), cfg.get("default_rate")):
        if cand is not None:
            v = _num(cand, -1.0)
            if v >= 0:
                return v
    return 0.0


def site_vat(cfg, site_id):
    """Effective VAT/tax percentage for a site (site override -> global default)."""
    sb = site_billing(cfg, site_id)
    for cand in (sb.get("vat"), cfg.get("default_vat")):
        if cand is not None:
            v = _num(cand, -1.0)
            if v >= 0:
                return v
    return 0.0


def currency(cfg):
    """Install currency code (defaults to USD); clamped to 8 chars."""
    return (str(cfg.get("currency") or "USD").strip()[:8]) or "USD"


def invoice_totals(line_items, vat_rate):
    """(subtotal, vat_amount, total) from line items + a VAT percentage.
    Each line's `amount` is summed; VAT is applied to the subtotal."""
    subtotal = round(sum(_num(li.get("amount")) for li in (line_items or [])), 2)
    vat_amount = round(subtotal * (_num(vat_rate) / 100.0), 2)
    total = round(subtotal + vat_amount, 2)
    return subtotal, vat_amount, total


def entry_in_period(entry, period_from, period_to):
    """True if an entry's date falls within [period_from, period_to] (inclusive).
    Empty bounds are open-ended. Dates are 'YYYY-MM-DD' strings (lexicographic
    compare is correct for that fixed format)."""
    d = str(entry.get("date") or "")
    if not d:
        return False
    if period_from and d < period_from:
        return False
    if period_to and d > period_to:
        return False
    return True


def billable_for_site(entries, site_id, period_from="", period_to="", include_locked=False):
    """Filter `entries` to the billable, in-period entries that belong to a site
    and are not yet invoiced (unless include_locked)."""
    out = []
    for e in entries or []:
        if not e.get("billable"):
            continue
        if (e.get("site_id") or "") != site_id:
            continue
        if not include_locked and (e.get("locked") or e.get("invoice_id")):
            continue
        if not entry_in_period(e, period_from, period_to):
            continue
        out.append(e)
    return out


def compute_worksheet(cfg, site_id, entries, period_from="", period_to="", include_fees=True):
    """Build a pre-invoice billing worksheet for ONE site over a period.

    `entries` is the full ledger; we select the billable, in-period, un-invoiced
    entries for `site_id`, group them by resolved rate into hour line items, then
    append the site's active recurring fees. Returns a dict carrying the line
    items, the contributing entry ids (so an invoice can snapshot+lock them), and
    subtotal / VAT / total. No money ever leaks here that the caller didn't gate —
    this function is only called from finance/admin handlers."""
    selected = billable_for_site(entries, site_id, period_from, period_to)
    groups = {}  # (rate_name, rate) -> {hours, amount, entry_ids}
    for e in selected:
        rate = resolve_rate(cfg, site_id, e.get("rate_name"))
        name = (e.get("rate_name") or "").strip() or "Standard"
        hrs = quantize_hours(e.get("hours"))
        if hrs <= 0:
            continue
        slot = groups.setdefault((name, rate), {"hours": 0.0, "amount": 0.0, "entry_ids": []})
        slot["hours"] = round(slot["hours"] + hrs, 2)
        slot["amount"] = round(slot["amount"] + hrs * rate, 2)
        slot["entry_ids"].append(e.get("id"))

    line_items = []
    entry_ids = []
    for (name, rate), slot in sorted(groups.items(), key=lambda kv: kv[0][0].lower()):
        line_items.append(
            {
                "kind": "hours",
                "label": "Billable hours — " + name,
                "qty": slot["hours"],
                "unit": rate,
                "amount": slot["amount"],
            }
        )
        entry_ids.extend(slot["entry_ids"])

    fee_lines = []
    if include_fees:
        for f in site_billing(cfg, site_id).get("recurring") or []:
            if not f.get("active", True):
                continue
            amount = _num(f.get("amount"))
            qty = _num(f.get("qty"), 1.0) or 1.0
            fee_lines.append(
                {
                    "kind": (
                        str(f.get("kind") or "other")
                        if str(f.get("kind") or "other") in FEE_KINDS
                        else "other"
                    ),
                    "label": str(f.get("label") or "Fee")[:120],
                    "qty": qty,
                    "unit": amount,
                    "amount": round(amount * qty, 2),
                }
            )
        line_items.extend(fee_lines)

    vat_rate = site_vat(cfg, site_id)
    subtotal, vat_amount, total = invoice_totals(line_items, vat_rate)
    return {
        "site_id": site_id,
        "currency": currency(cfg),
        "vat_rate": vat_rate,
        "period_from": period_from,
        "period_to": period_to,
        "line_items": line_items,
        "entry_ids": entry_ids,
        "hours_total": round(sum(s["hours"] for s in groups.values()), 2),
        "subtotal": subtotal,
        "vat_amount": vat_amount,
        "total": total,
    }


def month_bounds(month):
    """'YYYY-MM' -> ('YYYY-MM-01', 'YYYY-MM-<lastday>'). (None, None) on bad input."""
    m = re.match(r"^(\d{4})-(\d{2})$", str(month or ""))
    if not m:
        return None, None
    y, mo = int(m.group(1)), int(m.group(2))
    if not (1 <= mo <= 12):
        return None, None
    last = calendar.monthrange(y, mo)[1]
    return "%04d-%02d-01" % (y, mo), "%04d-%02d-%02d" % (y, mo, last)


def week_dates(week_str):
    """'YYYY-Www' (ISO week) -> list of 7 'YYYY-MM-DD' (Mon..Sun). [] on bad input."""
    m = re.match(r"^(\d{4})-W(\d{2})$", str(week_str or ""))
    if not m:
        return []
    y, w = int(m.group(1)), int(m.group(2))
    if not (1 <= w <= 53):
        return []
    try:
        monday = datetime.date.fromisocalendar(y, w, 1)
    except (ValueError, AttributeError, OverflowError):
        return []
    return [(monday + datetime.timedelta(days=i)).isoformat() for i in range(7)]


def iso_week_of(date_str):
    """'YYYY-MM-DD' -> 'YYYY-Www' ISO week label, or '' on bad input."""
    try:
        d = datetime.date.fromisoformat(str(date_str))
    except (ValueError, TypeError):
        return ""
    y, w, _ = d.isocalendar()
    return "%04d-W%02d" % (y, w)


# ── quotes (v6.2.0) ───────────────────────────────────────────────────────────
# A quote is the mirror image of an invoice. An invoice looks BACKWARD and is
# derived from time already logged; a quote looks FORWARD and is authored by
# hand — labour estimate, hardware, licences. The money maths is identical
# (invoice_totals), so it is reused rather than reimplemented: two subtly
# different VAT calculations in one product is a bug waiting to be found by a
# customer.

# 'invoiced' is terminal and is what makes conversion idempotent — see
# quote_can_convert.
QUOTE_STATUSES = ("draft", "sent", "accepted", "declined", "expired", "invoiced")
QUOTE_TERMINAL = ("accepted", "declined", "invoiced")


def quote_effective_status(quote, now):
    """The quote's status, with expiry applied AT READ TIME.

    A quote that has passed its validity date is expired the moment it passes it —
    not whenever a sweep next happens to run. A sweep that had not yet run would
    otherwise let a customer accept a price that lapsed last Tuesday.

    Accepted/declined/invoiced are TERMINAL: an accepted quote must not expire out
    from under a customer who accepted it in time. The deal is done; the clock
    stops.
    """
    status = str(quote.get("status") or "draft")
    if status in QUOTE_TERMINAL:
        return status
    valid_until = _num(quote.get("valid_until"))
    if valid_until and now > valid_until:
        return "expired"
    return status


def quote_can_convert(quote, now):
    """(ok, reason) — may this quote become an invoice?

    Two rules, both of which protect the CUSTOMER:
      1. Only an ACCEPTED quote converts. Invoicing a draft or a declined quote
         means billing someone for work they never agreed to.
      2. It converts exactly ONCE. A quote that already produced an invoice is
         'invoiced' and is refused — otherwise a double-click bills the customer
         twice, which is the worst bug a billing module can have.
    """
    status = quote_effective_status(quote, now)
    if quote.get("invoice_id") or status == "invoiced":
        return False, "this quote has already been converted to an invoice"
    if status != "accepted":
        return False, f"only an accepted quote can be invoiced (this one is {status})"
    return True, ""
