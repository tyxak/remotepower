#!/usr/bin/env bash
# remotepower-app-server.sh — switch an EXISTING RemotePower install between the
# default CGI/fcgiwrap app tier and the persistent gunicorn WSGI tier (v5.5.0),
# back and forth, idempotently. Also manages the out-of-band scheduler.
#
#   sudo bash packaging/remotepower-app-server.sh wsgi [--no-scheduler]
#   sudo bash packaging/remotepower-app-server.sh cgi  [--keep-scheduler]
#   bash      packaging/remotepower-app-server.sh status
#
# Usually invoked via the Makefile: `sudo make app-server-wsgi`,
# `sudo make app-server-cgi`, `make app-server-status`.
#
# - wsgi: install gunicorn (if missing), enable remotepower-wsgi.service, and
#   repoint the deployed nginx /api/ snippet from fcgiwrap to gunicorn proxy_pass
#   (validated with `nginx -t`, auto-reverted on failure). The pristine CGI
#   snippet is saved to <snippet>.cgi.bak so the switch back is lossless. By
#   default ALSO enables the out-of-band scheduler (recommended pairing) — pass
#   --no-scheduler to leave the cadence on the request path.
# - cgi: restore the fcgiwrap snippet from the backup, stop remotepower-wsgi, and
#   (by default) disable the scheduler + drop RP_EXTERNAL_SCHEDULER so the request
#   path resumes the cadence (avoids a double-run). Pass --keep-scheduler to leave
#   the scheduler enabled (only sensible if you run the SCGI worker, which reads
#   api.env). Data is never touched.
# - status: show the active app tier, unit states and scheduler mode.
#
# Safe to re-run: each mode detects the current state and only changes what differs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # repo root
SNIP="/etc/nginx/snippets/remotepower-locations.conf"
CANON_SNIP="$SCRIPT_DIR/server/conf/remotepower-locations.conf"
ENVFILE="/etc/remotepower/api.env"
WSGI_UNIT="remotepower-wsgi.service"
SCHED_UNIT="remotepower-scheduler.service"
GUNICORN_BIND="127.0.0.1:8090"

c_g=$'\033[0;32m'; c_y=$'\033[1;33m'; c_r=$'\033[0;31m'; c_n=$'\033[0m'
info()  { echo "${c_g}==>${c_n} $*"; }
warn()  { echo "${c_y}WARN:${c_n} $*" >&2; }
die()   { echo "${c_r}ERROR:${c_n} $*" >&2; exit 1; }

need_root() { [[ ${EUID:-$(id -u)} -eq 0 ]] || die "run as root (sudo)"; }

current_mode() {   # echoes "wsgi" or "cgi" based on the deployed snippet
  [[ -f "$SNIP" ]] || { echo "unknown"; return; }
  if grep -q "proxy_pass http://${GUNICORN_BIND}" "$SNIP"; then echo "wsgi"; else echo "cgi"; fi
}

reload_nginx() {   # validate then reload; restore arg-file on failure
  local restore="${1:-}"
  if nginx -t >/dev/null 2>&1; then
    systemctl reload nginx && return 0
  fi
  warn "nginx -t failed"
  if [[ -n "$restore" && -f "$restore" ]]; then
    warn "restoring previous snippet ($restore)"
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
  # The unit hardcodes /usr/bin/gunicorn; symlink if pip put it elsewhere.
  [[ -x /usr/bin/gunicorn ]] || ln -sf "$(command -v gunicorn)" /usr/bin/gunicorn
}

rewrite_nginx_to_wsgi() {   # fcgiwrap → gunicorn proxy_pass on the DEPLOYED snippet
  [[ -f "$SNIP" ]] || die "deployed snippet not found at $SNIP — is the server installed?"
  cp -a "$SNIP" "${SNIP}.cgi.bak"     # pristine CGI snippet for a lossless switch back
  python3 - "$SNIP" "$GUNICORN_BIND" <<'PYEOF'
import re, sys
from pathlib import Path
p = Path(sys.argv[1]); bind = sys.argv[2]; text = p.read_text()
# Rewrite every ACTIVE (non-commented) location block that drives fcgiwrap into a
# gunicorn proxy_pass block. Commented example blocks start with '#' so the
# line-anchored matcher skips them; brace matching is depth-aware so the nested
# `limit_except { … }` doesn't confuse it. (Same transform install-server.sh uses.)
loc_re = re.compile(r'(?m)^[ \t]*location\b[^{]*')
out, pos = [], 0
while True:
    m = loc_re.search(text, pos)
    if not m:
        out.append(text[pos:]); break
    out.append(text[pos:m.start()])
    sel = m.group(0)
    bopen = text.index('{', m.start())
    depth, j = 0, bopen
    while j < len(text):
        if text[j] == '{': depth += 1
        elif text[j] == '}':
            depth -= 1
            if depth == 0: break
        j += 1
    block = text[bopen:j + 1]
    if 'fcgiwrap.socket' in block:
        pim = re.search(r'PATH_INFO\s+(\S+);', block)
        suffix = pim.group(1) if (pim and pim.group(1) != '$uri') else ''
        le = re.search(r'limit_except[^{]*\{[^}]*\}', block)
        le_line = ('\n    ' + le.group(0)) if le else ''
        indent = re.match(r'[ \t]*', sel).group(0)
        out.append(
            sel.rstrip() + ' {\n'
            '    proxy_pass http://' + bind + suffix + ';\n'
            '    proxy_set_header Host $host;\n'
            '    proxy_set_header X-Real-IP $remote_addr;\n'
            '    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n'
            '    proxy_set_header X-Forwarded-Proto $scheme;\n'
            '    proxy_read_timeout 130s;' + le_line + '\n' + indent + '}')
    else:
        out.append(sel + block)
    pos = j + 1
p.write_text(''.join(out))
PYEOF
}

restore_nginx_to_cgi() {
  if [[ -f "${SNIP}.cgi.bak" ]]; then
    info "restoring fcgiwrap snippet from ${SNIP}.cgi.bak"
    cp -a "${SNIP}.cgi.bak" "$SNIP"
  elif [[ -f "$CANON_SNIP" ]]; then
    warn "no .cgi.bak backup — installing the canonical snippet from the checkout"
    cp -a "$CANON_SNIP" "$SNIP"
  else
    die "no CGI snippet to restore (neither ${SNIP}.cgi.bak nor $CANON_SNIP)"
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
  echo "Active app tier:  $(current_mode)   (snippet: $SNIP)"
  local u act en
  for u in "$WSGI_UNIT" "$SCHED_UNIT" remotepower-api.service fcgiwrap.service; do
    act=$(systemctl is-active "$u" 2>/dev/null | head -n1 || true);   act=${act:-unknown}
    en=$(systemctl is-enabled "$u" 2>/dev/null | head -n1 || true);   en=${en:-n/a}
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
    need_root
    want_sched=1
    for a in "$@"; do [[ "$a" == "--no-scheduler" ]] && want_sched=0; done
    ensure_gunicorn
    install -m 644 "$SCRIPT_DIR/server/conf/$WSGI_UNIT" "/etc/systemd/system/$WSGI_UNIT"
    systemctl daemon-reload
    systemctl enable --now "$WSGI_UNIT" \
      && info "$WSGI_UNIT running (gunicorn on $GUNICORN_BIND)" \
      || warn "could not start $WSGI_UNIT — check: systemctl status $WSGI_UNIT"
    if [[ "$(current_mode)" == "wsgi" ]]; then
      info "nginx /api/ already proxies to the WSGI tier — leaving the snippet as-is"
    else
      rewrite_nginx_to_wsgi
      reload_nginx "${SNIP}.cgi.bak" \
        && info "nginx /api/ now proxies to gunicorn (backup: ${SNIP}.cgi.bak)" \
        || die "nginx validation failed — reverted to fcgiwrap; WSGI switch aborted"
    fi
    [[ "$want_sched" == 1 ]] && enable_scheduler || warn "scheduler left as-is (--no-scheduler)"
    restart_worker
    info "Done — app tier is WSGI. Roll back with: sudo make app-server-cgi"
    ;;
  cgi)
    need_root
    keep_sched=0
    for a in "$@"; do [[ "$a" == "--keep-scheduler" ]] && keep_sched=1; done
    if [[ "$(current_mode)" == "cgi" ]]; then
      info "nginx /api/ already on fcgiwrap — leaving the snippet as-is"
    else
      restore_nginx_to_cgi
      reload_nginx \
        && info "nginx /api/ restored to fcgiwrap (CGI)" \
        || die "nginx validation failed after restoring the CGI snippet — inspect $SNIP"
    fi
    systemctl disable --now "$WSGI_UNIT" 2>/dev/null \
      && info "stopped $WSGI_UNIT" || true
    systemctl enable --now fcgiwrap.socket 2>/dev/null || systemctl enable --now fcgiwrap 2>/dev/null || true
    [[ "$keep_sched" == 1 ]] \
      && warn "scheduler left enabled (--keep-scheduler) — only safe with the SCGI worker" \
      || disable_scheduler
    info "Done — app tier is CGI/fcgiwrap. Switch with: sudo make app-server-wsgi"
    ;;
  status) do_status ;;
  *)
    echo "usage: $0 {wsgi [--no-scheduler] | cgi [--keep-scheduler] | status}" >&2
    exit 2 ;;
esac
