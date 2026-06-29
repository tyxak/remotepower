#!/usr/bin/env bash
# remotepower-app-server.sh — switch an EXISTING RemotePower install between the
# CGI/fcgiwrap (or SCGI worker) app tier and the persistent gunicorn WSGI tier
# (v5.5.0), back and forth, idempotently. Also manages the out-of-band scheduler.
#
#   sudo bash packaging/remotepower-app-server.sh wsgi [--no-scheduler]
#   sudo bash packaging/remotepower-app-server.sh cgi  [--keep-scheduler]
#        bash packaging/remotepower-app-server.sh status
#
# Usually via the Makefile: `sudo make app-server-wsgi`, `sudo make app-server-cgi`,
# `make app-server-status`.
#
# NGINX CONFIG LOCATION — works with custom vhosts, not just the shared snippet:
#   1. $RP_NGINX_CONF (or $RP_NGINX_SNIPPET) if you set it — point it at the file
#      that holds your `location /api/ { … }` blocks (e.g. a hand-tuned
#      /etc/nginx/sites-available/<vhost>).
#   2. else the shared snippet /etc/nginx/snippets/remotepower-locations.conf.
#   3. else AUTO-DETECT: the nginx file under /etc/nginx that defines the
#      RemotePower /api backend (fcgiwrap, the RP scgi socket, or gunicorn:8090).
#
# The WSGI switch is SURGICAL: in every ACTIVE RemotePower `/api` location it
# swaps only the backend directives (fastcgi_pass/scgi_pass + their *_param /
# *_params / *_read_timeout lines) for `proxy_pass http://127.0.0.1:8090` + the
# proxy headers, and PRESERVES every other line in the block (your
# `include …/fw_private_rp`, `modsecurity off`, `limit_except`, `auth_request`,
# add_header, …). A `location` that doesn't drive the RP backend (e.g. the
# webterm websocket proxy to :8765) is left untouched. The pristine file is saved
# to <file>.cgi.bak first, so the switch back is byte-lossless. PATH_INFO
# overrides (e.g. /install → /api/agent/install) are carried onto proxy_pass.
#
# Validated with `nginx -t`; on failure it auto-reverts. Data is never touched.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # repo root
SNIP_DEFAULT="/etc/nginx/snippets/remotepower-locations.conf"
CANON_SNIP="$SCRIPT_DIR/server/conf/remotepower-locations.conf"
ENVFILE="/etc/remotepower/api.env"
WSGI_UNIT="remotepower-wsgi.service"
SCHED_UNIT="remotepower-scheduler.service"
GUNICORN_BIND="127.0.0.1:8090"
SNIP=""   # resolved by init_conf()
BAK=""    # backup path, set by init_conf() — OUTSIDE any nginx include dir
BAK_DIR="/var/backups/remotepower-app-server"

c_g=$'\033[0;32m'; c_y=$'\033[1;33m'; c_r=$'\033[0;31m'; c_n=$'\033[0m'
info()  { echo "${c_g}==>${c_n} $*"; }
warn()  { echo "${c_y}WARN:${c_n} $*" >&2; }
die()   { echo -e "${c_r}ERROR:${c_n} $*" >&2; exit 1; }

need_root() { [[ ${EUID:-$(id -u)} -eq 0 ]] || die "run as root (sudo)"; }

# Resolve which nginx file holds the RemotePower /api backend (see header).
init_conf() {
  if   [[ -n "${RP_NGINX_CONF:-}"    ]]; then SNIP="$RP_NGINX_CONF"
  elif [[ -n "${RP_NGINX_SNIPPET:-}" ]]; then SNIP="$RP_NGINX_SNIPPET"
  elif [[ -f "$SNIP_DEFAULT"         ]]; then SNIP="$SNIP_DEFAULT"
  else
    local cands=() uniq=() c r
    mapfile -t cands < <(grep -rlsE \
      'fcgiwrap\.socket|scgi_pass[[:space:]]+unix:/run/remotepower/|proxy_pass[[:space:]]+http://127\.0\.0\.1:8090|cgi-bin/api(_cgi)?\.py' \
      /etc/nginx/ 2>/dev/null || true)
    for c in "${cands[@]}"; do
      grep -qE '^[[:space:]]*location[[:space:]].*\/api' "$c" 2>/dev/null || continue
      r=$(readlink -f "$c" 2>/dev/null || echo "$c")
      [[ " ${uniq[*]-} " == *" $r "* ]] || uniq+=("$r")
    done
    if   [[ ${#uniq[@]} -eq 1 ]]; then SNIP="${uniq[0]}"; info "auto-detected nginx config: $SNIP"
    elif [[ ${#uniq[@]} -eq 0 ]]; then SNIP="$SNIP_DEFAULT"   # keep a value for the error message
    else die "multiple nginx files define the RemotePower /api backend:\n$(printf '  %s\n' "${uniq[@]}")\n  → re-run with RP_NGINX_CONF=<the right file>"
    fi
  fi
  # Resolve symlinks (sites-enabled/* is often a symlink) so we edit + back up the
  # REAL file — otherwise `cp -a` would copy the symlink, not its contents.
  [[ -n "$SNIP" && -e "$SNIP" ]] && SNIP="$(readlink -f "$SNIP" 2>/dev/null || echo "$SNIP")"
  # Backup lives OUTSIDE any nginx include dir. CRITICAL: nginx.conf often globs
  # `include sites-enabled/*` (no .conf filter), so a backup written next to the
  # vhost (the old `${SNIP}.cgi.bak`) gets loaded as a SECOND server block →
  # "conflicting server name … ignored". Keep backups in /var/backups instead.
  BAK="$BAK_DIR/$(basename "$SNIP").cgi.bak"
}

# Migrate (and clean up) a legacy backup that an older version of this script
# wrote next to the vhost — it may be inside an `include`d dir and cause a
# duplicate-server_name conflict. Move it to the safe backup dir.
migrate_legacy_bak() {
  local legacy="${SNIP}.cgi.bak"
  [[ -f "$legacy" ]] || return 0
  mkdir -p "$BAK_DIR"
  [[ -f "$BAK" ]] || cp -a "$legacy" "$BAK"
  rm -f "$legacy"
  warn "moved a stale adjacent backup out of nginx's path: $legacy → $BAK"
}

current_mode() {   # echoes "wsgi" / "cgi" / "unknown" for the resolved file
  [[ -f "$SNIP" ]] || { echo "unknown"; return; }
  if grep -q "proxy_pass http://${GUNICORN_BIND}" "$SNIP"; then echo "wsgi"; else echo "cgi"; fi
}

reload_nginx() {   # validate then reload; restore arg-file on failure
  local restore="${1:-}"
  if nginx -t >/dev/null 2>&1; then systemctl reload nginx && return 0; fi
  warn "nginx -t failed"
  if [[ -n "$restore" && -f "$restore" ]]; then
    warn "restoring previous config ($restore)"
    cp -a "$restore" "$SNIP"
    nginx -t >/dev/null 2>&1 && systemctl reload nginx || true
  fi
  return 1
}

ensure_gunicorn() {
  command -v gunicorn >/dev/null 2>&1 && return 0
  info "installing gunicorn (not a RemotePower dependency)"
  if   command -v pacman  >/dev/null 2>&1; then pacman -S --noconfirm gunicorn 2>/dev/null || pip install gunicorn 2>/dev/null || true
  elif command -v apt-get >/dev/null 2>&1; then apt-get install -y --no-install-recommends gunicorn 2>/dev/null || pip3 install gunicorn --break-system-packages 2>/dev/null || true
  elif command -v dnf     >/dev/null 2>&1; then dnf install -y -q python3-gunicorn 2>/dev/null || pip3 install gunicorn 2>/dev/null || true
  else pip3 install gunicorn 2>/dev/null || true; fi
  command -v gunicorn >/dev/null 2>&1 || die "gunicorn install failed — install it then re-run"
  [[ -x /usr/bin/gunicorn ]] || ln -sf "$(command -v gunicorn)" /usr/bin/gunicorn
}

# Poll the gunicorn worker until it actually answers — so we never repoint nginx
# at a dead :8090 and 502 the live API. Any HTTP status (200/401/403/404) means
# the socket served a response; "000" means connection refused / not up.
wait_gunicorn_healthy() {
  command -v curl >/dev/null 2>&1 || { warn "curl not found — skipping the gunicorn health gate"; return 0; }
  local i code
  for i in $(seq 1 15); do
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://${GUNICORN_BIND}/api/health" 2>/dev/null || echo 000)
    [[ "$code" =~ ^[234][0-9][0-9]$ ]] && { info "gunicorn healthy on ${GUNICORN_BIND} (HTTP $code)"; return 0; }
    sleep 1
  done
  return 1
}

# Surgically rewrite the RP /api backend blocks in $SNIP to gunicorn proxy_pass.
rewrite_nginx_to_wsgi() {
  [[ -f "$SNIP" ]] || die "nginx config not found at $SNIP — set RP_NGINX_CONF=<your vhost> (the file with your 'location /api/ {…}' blocks)"
  grep -qE 'fcgiwrap\.socket|scgi_pass[[:space:]]+unix:/run/remotepower/' "$SNIP" \
    || die "no active fcgiwrap/SCGI RemotePower /api block found in $SNIP — already on WSGI, or set RP_NGINX_CONF to the right file"
  mkdir -p "$BAK_DIR"
  cp -a "$SNIP" "$BAK"                 # pristine backend config (in /var/backups, never include'd)
  migrate_legacy_bak                  # clean up any old adjacent backup that nginx would load
  python3 - "$SNIP" "$GUNICORN_BIND" <<'PYEOF'
import re, sys
from pathlib import Path
p = Path(sys.argv[1]); bind = sys.argv[2]; text = p.read_text()
RP_SCGI = re.compile(r'scgi_pass\s+unix:/run/remotepower/')
def is_backend(b):                      # an ACTIVE RemotePower CGI/SCGI block?
    return ('fcgiwrap.socket' in b) or bool(RP_SCGI.search(b))
loc_re = re.compile(r'(?m)^[ \t]*location\b[^{]*')
out, pos = [], 0
while True:
    m = loc_re.search(text, pos)
    if not m:
        out.append(text[pos:]); break
    out.append(text[pos:m.start()]); sel = m.group(0)
    # depth-aware brace match (handles the nested `limit_except { … }`)
    bopen = text.index('{', m.start()); depth, j = 0, bopen
    while j < len(text):
        if text[j] == '{': depth += 1
        elif text[j] == '}':
            depth -= 1
            if depth == 0: break
        j += 1
    block = text[bopen:j + 1]
    if not is_backend(block) or ('proxy_pass http://' + bind) in block:
        out.append(sel + block); pos = j + 1; continue
    inner = block[1:-1]
    lines = inner.split('\n')
    # pass 1 — capture PATH_INFO override + the backend read-timeout
    suffix, timeout = '', '130s'
    for ln in lines:
        s = ln.strip()
        mm = re.match(r'(?:fastcgi|scgi)_param\s+PATH_INFO\s+(\S+?);', s)
        if mm and mm.group(1) != '$uri': suffix = mm.group(1)
        mt = re.match(r'(?:fastcgi|scgi)_read_timeout\s+(\S+?);', s)
        if mt: timeout = mt.group(1)
    # pass 2 — drop backend directives, inject proxy_pass where the pass line was,
    # keep every other line (fw_private_rp, modsecurity, limit_except, …) verbatim
    new, injected = [], False
    for ln in lines:
        s = ln.strip()
        if re.match(r'include\s+(?:fastcgi|scgi)_params\s*;', s):       continue
        if re.match(r'(?:fastcgi|scgi)_param\b', s):                    continue
        if re.match(r'(?:fastcgi|scgi)_read_timeout\b', s):             continue
        if re.match(r'(?:fastcgi|scgi)_pass\b', s):
            ind = re.match(r'[ \t]*', ln).group(0)
            new += [ind + 'proxy_pass http://' + bind + suffix + ';',
                    ind + 'proxy_set_header Host $host;',
                    ind + 'proxy_set_header X-Real-IP $remote_addr;',
                    ind + 'proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;',
                    ind + 'proxy_set_header X-Forwarded-Proto $scheme;',
                    ind + 'proxy_read_timeout ' + timeout + ';']
            injected = True
            continue
        new.append(ln)
    out.append(sel + '{' + '\n'.join(new) + '}')
    pos = j + 1
Path(sys.argv[1]).write_text(''.join(out))
PYEOF
}

restore_nginx_to_cgi() {
  migrate_legacy_bak   # pull in (and clear) any old adjacent backup first
  if [[ -f "$BAK" ]]; then
    info "restoring the original backend config from $BAK"
    cp -a "$BAK" "$SNIP"
  elif [[ "$SNIP" == "$SNIP_DEFAULT" && -f "$CANON_SNIP" ]]; then
    warn "no backup — installing the canonical fcgiwrap snippet from the checkout"
    cp -a "$CANON_SNIP" "$SNIP"
  else
    die "no backup at $BAK to restore — this looks like a custom vhost that wasn't switched by this tool; revert the /api proxy_pass block to your fcgiwrap/scgi block by hand"
  fi
}

set_env_flag() {   # set_env_flag KEY VALUE | set_env_flag KEY ""  (remove)
  local key="$1" val="${2:-}"
  install -d -m 755 -o root -g root /etc/remotepower
  touch "$ENVFILE"; chmod 600 "$ENVFILE"
  sed -i "/^${key}=/d" "$ENVFILE"
  [[ -n "$val" ]] && echo "${key}=${val}" >> "$ENVFILE" || true
}

enable_scheduler() {
  info "enabling the out-of-band scheduler"
  install -m 644 "$SCRIPT_DIR/server/conf/$SCHED_UNIT" "/etc/systemd/system/$SCHED_UNIT"
  set_env_flag RP_EXTERNAL_SCHEDULER 1
  systemctl daemon-reload
  systemctl enable --now "$SCHED_UNIT" \
    && info "scheduler running (leader-elected; cadence off the request path)" \
    || warn "could not start $SCHED_UNIT — check: systemctl status $SCHED_UNIT"
}

disable_scheduler() {
  info "disabling the out-of-band scheduler (cadence returns to the request path)"
  systemctl disable --now "$SCHED_UNIT" 2>/dev/null || true
  set_env_flag RP_EXTERNAL_SCHEDULER ""
}

restart_worker() {   # restart whichever persistent worker is active (if any)
  systemctl is-enabled "$WSGI_UNIT" >/dev/null 2>&1 && systemctl restart "$WSGI_UNIT" || true
  systemctl is-enabled remotepower-api.service >/dev/null 2>&1 && systemctl restart remotepower-api.service || true
}

do_status() {
  init_conf
  echo "Active app tier:  $(current_mode)   (nginx config: $SNIP)"
  local u act en
  for u in "$WSGI_UNIT" "$SCHED_UNIT" remotepower-api.service fcgiwrap.service; do
    act=$(systemctl is-active "$u" 2>/dev/null | head -n1 || true);  act=${act:-unknown}
    en=$(systemctl is-enabled "$u" 2>/dev/null | head -n1 || true);  en=${en:-n/a}
    printf '  %-30s %s / %s\n' "$u" "$act" "$en"
  done
  if [[ -f "$ENVFILE" ]] && grep -q '^RP_EXTERNAL_SCHEDULER=1' "$ENVFILE"; then
    echo "  RP_EXTERNAL_SCHEDULER=1  (request path does NOT run the cadence)"
  else
    echo "  RP_EXTERNAL_SCHEDULER unset  (request path runs the cadence)"
  fi
}

cmd="${1:-}"; shift || true
case "$cmd" in
  wsgi)
    need_root; init_conf
    want_sched=1
    for a in "$@"; do [[ "$a" == "--no-scheduler" ]] && want_sched=0; done
    ensure_gunicorn
    install -m 644 "$SCRIPT_DIR/server/conf/$WSGI_UNIT" "/etc/systemd/system/$WSGI_UNIT"
    systemctl daemon-reload
    systemctl enable --now "$WSGI_UNIT" \
      && info "$WSGI_UNIT running (gunicorn on $GUNICORN_BIND)" \
      || warn "could not start $WSGI_UNIT — check: systemctl status $WSGI_UNIT"
    if [[ "$(current_mode)" == "wsgi" ]]; then
      info "nginx /api/ already proxies to the WSGI tier — leaving $SNIP as-is"
    else
      # Health gate: never repoint nginx at a dead gunicorn (that's a guaranteed 502).
      wait_gunicorn_healthy \
        || die "gunicorn on $GUNICORN_BIND is not answering — NOT touching nginx (you're still on CGI/SCGI).\n  Check: systemctl status remotepower-wsgi ; journalctl -u remotepower-wsgi -n 40\n  (most common cause: the served code in /var/www/remotepower isn't v5.5.0 — run deploy-server.sh)"
      rewrite_nginx_to_wsgi
      reload_nginx "$BAK" \
        && info "nginx /api/ now proxies to gunicorn (backup: $BAK)" \
        || die "nginx validation failed — reverted to the previous config; WSGI switch aborted"
    fi
    [[ "$want_sched" == 1 ]] && enable_scheduler || warn "scheduler left as-is (--no-scheduler)"
    restart_worker
    info "Done — app tier is WSGI. Roll back with: sudo make app-server-cgi"
    ;;
  cgi)
    need_root; init_conf
    keep_sched=0
    for a in "$@"; do [[ "$a" == "--keep-scheduler" ]] && keep_sched=1; done
    if [[ "$(current_mode)" == "cgi" ]]; then
      info "nginx /api/ already on the CGI/SCGI backend — leaving $SNIP as-is"
    else
      restore_nginx_to_cgi
      reload_nginx \
        && info "nginx /api/ restored to the original backend (backup: $BAK)" \
        || die "nginx validation failed after restoring — inspect $SNIP"
    fi
    systemctl disable --now "$WSGI_UNIT" 2>/dev/null && info "stopped $WSGI_UNIT" || true
    [[ "$keep_sched" == 1 ]] \
      && warn "scheduler left enabled (--keep-scheduler) — only safe with the SCGI worker (it reads api.env)" \
      || disable_scheduler
    info "Done — app tier is CGI/SCGI. Switch with: sudo make app-server-wsgi"
    ;;
  status) do_status ;;
  *)
    echo "usage: $0 {wsgi [--no-scheduler] | cgi [--keep-scheduler] | status}" >&2
    echo "  custom vhost? set RP_NGINX_CONF=/etc/nginx/sites-available/<your-vhost>" >&2
    exit 2 ;;
esac
