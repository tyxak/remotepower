#!/bin/bash
# install-demo.sh — set up a separate read-only demo at e.g. demoremote.tvipper.com
#
# Architecture: the demo runs the SAME code as your main install (shared
# htdocs/cgi-bin, root-owned, read-only at the filesystem level), but under a
# SEPARATE gunicorn process (its own systemd unit, its own port, its own
# RP_DATA_DIR + RP_READ_ONLY=1 in the unit's Environment=) — a persistent app
# server can't take a per-request data-dir override the way classic CGI could,
# so each vhost gets its own process instead. nginx routes by Host header to
# the matching port. Two completely separate state stores share one set of
# code on disk.
#
#   /var/www/remotepower/           — shared code, dashboard HTML/JS/CSS
#   /var/lib/remotepower/           — REAL fleet data (your production install,
#                                      served by remotepower-wsgi on :8090)
#   /var/lib/remotepower-demo/      — FAKE demo data (this script populates it,
#                                      served by remotepower-wsgi-demo on :$DEMO_PORT)
#
# Usage:
#   sudo bash packaging/install-demo.sh demoremote.tvipper.com
#   sudo bash packaging/install-demo.sh demoremote.example.com --cgi-user nginx
#
# Idempotent: re-running re-seeds the demo data and re-renders the nginx
# config + systemd unit. Won't touch the production install.

set -euo pipefail

# ─── Defaults — overridable via flags ─────────────────────────────────────────

DEMO_HOST=""
CGI_USER=""             # auto-detect if empty
DEMO_DATA_DIR="/var/lib/remotepower-demo"
PROD_HTDOCS="/var/www/remotepower"   # shared with production
DEMO_PORT="${RP_DEMO_PORT:-8091}"    # gunicorn port for the demo's own process
NGINX_SITES_AVAIL="/etc/nginx/sites-available"
NGINX_SITES_ENABL="/etc/nginx/sites-enabled"
DRY_RUN=0
SKIP_RESEED=0
WITH_POSTGRES=0

# ─── Args ────────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
Usage: sudo bash $0 <demo-hostname> [options]

Required:
  <demo-hostname>      e.g. demoremote.tvipper.com — the public DNS name
                       you'll point at this server. Configure DNS + TLS
                       cert separately.

Options:
  --cgi-user USER      User the CGI runs as. Auto-detected if not set
                       (www-data on Debian/Ubuntu, nginx on RHEL, etc).
  --data-dir DIR       Demo state dir (default: /var/lib/remotepower-demo).
                       Must be different from production /var/lib/remotepower/.
  --htdocs DIR         Where the shared CGI lives (default: /var/www/remotepower).
                       Don't change unless your install is non-standard.
  --skip-reseed        Don't re-run the seed script. Useful if you've
                       customised the demo data and don't want it overwritten.
  --postgres           Provision a SEPARATE PostgreSQL database + role for the
                       demo (packaging/postgres-setup.sh, database
                       remotepower_demo / role rp_demo by default) and migrate
                       the seeded data into it, matching the main install's
                       default backend. Off by default (the demo stays on the
                       lightweight flat-JSON backend unless you ask for this).
  --dry-run            Print what would happen without doing anything.
  -h, --help           This help.
EOF
}

if [[ $# -eq 0 ]] || [[ "${1:-}" == "-h" ]] || [[ "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

# ─── Uninstall (sudo bash install-demo.sh --uninstall [--data-dir DIR]) ──────
if [[ "${1:-}" == "--uninstall" ]]; then
  shift
  while [[ $# -gt 0 ]]; do
    case "$1" in --data-dir) DEMO_DATA_DIR="$2"; shift 2 ;; *) shift ;; esac
  done
  [[ "$EUID" -ne 0 ]] && { echo "Run as root: sudo bash $0 --uninstall"; exit 1; }
  [[ "$DEMO_DATA_DIR" == "/var/lib/remotepower" ]] && { echo "✗ refusing to touch the PRODUCTION data dir"; exit 1; }
  echo "── Uninstalling RemotePower demo…"
  # If the demo was migrated to Postgres, its marker names the database —
  # surface that BEFORE the data dir (and the marker with it) is removed, so
  # the operator knows to drop it manually (not done automatically here).
  if [[ -f "$DEMO_DATA_DIR/storage_backend.json" ]]; then
    _pg_db="$(sed -n 's/.*"dsn":\s*"[^\/]*\/\/[^\/]*\/\([^"]*\)".*/\1/p' "$DEMO_DATA_DIR/storage_backend.json" 2>/dev/null | head -1)"
    if [[ -n "$_pg_db" ]]; then
      echo "  (demo was PostgreSQL-backed: database '$_pg_db' is left in place —"
      echo "   drop it yourself if you're done with it: sudo -u postgres dropdb $_pg_db)"
    fi
  fi
  # Safety: only remove a dir that carries the demo marker (never real data).
  if [[ -e "$DEMO_DATA_DIR/.rp-demo-marker" ]]; then
    rm -rf "$DEMO_DATA_DIR" && echo "  removed demo data: $DEMO_DATA_DIR"
  else
    echo "  (no .rp-demo-marker at $DEMO_DATA_DIR — left it alone)"
  fi
  rm -f "$NGINX_SITES_AVAIL/remotepower-demo" "$NGINX_SITES_ENABL/remotepower-demo" \
        /etc/nginx/conf.d/remotepower-demo.conf 2>/dev/null || true
  echo "  removed demo nginx vhost"
  nginx -t >/dev/null 2>&1 && systemctl reload nginx 2>/dev/null || true
  echo "✓ Demo uninstalled."
  exit 0
fi

DEMO_HOST="$1"; shift
while [[ $# -gt 0 ]]; do
  case "$1" in
    --cgi-user)    CGI_USER="$2"; shift 2 ;;
    --data-dir)    DEMO_DATA_DIR="$2"; shift 2 ;;
    --htdocs)      PROD_HTDOCS="$2"; shift 2 ;;
    --skip-reseed) SKIP_RESEED=1; shift ;;
    --postgres)    WITH_POSTGRES=1; shift ;;
    --dry-run)     DRY_RUN=1; shift ;;
    -h|--help)     usage; exit 0 ;;
    *)             echo "Unknown flag: $1"; usage; exit 1 ;;
  esac
done

# Sanity check the hostname looks like a hostname
if ! [[ "$DEMO_HOST" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$ ]]; then
  echo "✗ '$DEMO_HOST' doesn't look like a hostname" >&2
  exit 1
fi

# Refuse to clobber the production data dir
if [[ "$DEMO_DATA_DIR" == "/var/lib/remotepower" ]]; then
  echo "✗ Demo data dir must NOT be /var/lib/remotepower (that's production)" >&2
  exit 1
fi

# ─── Helpers ─────────────────────────────────────────────────────────────────

run() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "DRY-RUN: $*"
  else
    echo "+ $*"
    "$@"
  fi
}

die() {
  echo "✗ $*" >&2
  exit 1
}

if [[ "$EUID" -ne 0 && "$DRY_RUN" -eq 0 ]]; then
  die "Run as root: sudo bash $0 $DEMO_HOST"
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SEED_SCRIPT="$SCRIPT_DIR/seed-demo-data.py"
if [[ ! -f "$SEED_SCRIPT" ]]; then
  # Try a couple of plausible alternative locations
  for candidate in "$(pwd)/packaging/seed-demo-data.py" "$(pwd)/seed-demo-data.py"; do
    [[ -f "$candidate" ]] && SEED_SCRIPT="$candidate" && break
  done
  [[ ! -f "$SEED_SCRIPT" ]] && die "Can't find seed-demo-data.py (looked in $SCRIPT_DIR/)"
fi

# ─── Detect the app-server user ───────────────────────────────────────────────

if [[ -z "$CGI_USER" ]]; then
  echo "── Detecting app-server user…"
  for candidate in www-data nginx http rp-www apache; do
    if id "$candidate" &>/dev/null; then
      if pgrep -u "$candidate" -f '(gunicorn|fcgi|nginx|cgi|php-fpm)' &>/dev/null; then
        CGI_USER="$candidate"
        echo "  → found $CGI_USER (running web/app-server processes)"
        break
      fi
    fi
  done
fi
if [[ -z "$CGI_USER" ]]; then
  for candidate in www-data nginx http rp-www; do
    if id "$candidate" &>/dev/null; then
      CGI_USER="$candidate"
      echo "  → using $CGI_USER (no web process detected, but user exists)"
      break
    fi
  done
fi
[[ -z "$CGI_USER" ]] && die "Couldn't detect the app-server user. Pass --cgi-user explicitly."
CGI_GROUP=$(id -gn "$CGI_USER")

# ─── Sanity-check the production install ──────────────────────────────────────

if [[ ! -d "$PROD_HTDOCS" ]]; then
  die "Production htdocs not found at $PROD_HTDOCS. Run install-server.sh first, or pass --htdocs."
fi
if [[ ! -d "$PROD_HTDOCS/cgi-bin" ]]; then
  die "$PROD_HTDOCS doesn't look like a remotepower install (no cgi-bin/)."
fi

# ─── Step 1: create demo data dir ────────────────────────────────────────────

echo "── Setting up demo data dir at $DEMO_DATA_DIR…"
run mkdir -p "$DEMO_DATA_DIR"
run chown "$CGI_USER:$CGI_GROUP" "$DEMO_DATA_DIR"
run chmod 700 "$DEMO_DATA_DIR"
# Mark this as a sanctioned demo dir so the seeder's safety guard allows
# (re-)seeding even if the demo vhost has already served a request and the app
# auto-created its default admin / token files here.
run touch "$DEMO_DATA_DIR/.rp-demo-marker"
run chown "$CGI_USER:$CGI_GROUP" "$DEMO_DATA_DIR/.rp-demo-marker"

# ─── Step 2: seed the demo data ──────────────────────────────────────────────

if [[ "$SKIP_RESEED" -eq 1 ]]; then
  echo "── Skipping seed (--skip-reseed)"
else
  echo "── Seeding fake homelab data…"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "DRY-RUN: would run: sudo -u $CGI_USER python3 $SEED_SCRIPT --data-dir $DEMO_DATA_DIR --apply"
  else
    sudo -u "$CGI_USER" python3 "$SEED_SCRIPT" --data-dir "$DEMO_DATA_DIR" --apply
  fi
fi

# ─── Step 2a: optional PostgreSQL backend for the demo (--postgres) ─────────
# seed-demo-data.py only ever writes flat JSON (it has no storage-backend
# awareness) — so a Postgres-backed demo means seeding into JSON as usual,
# then migrating that JSON into a SEPARATE demo database, the same two-step
# pattern install-server.sh uses for the main install (provision, generate
# our own password so we know the DSN without scraping it back out of
# postgres-setup.sh's human-readable output, then api._migrate_storage_pg()).
# No systemd unit changes needed: the migration writes
# $DEMO_DATA_DIR/storage_backend.json, and remotepower-wsgi-demo already runs
# with RP_DATA_DIR=$DEMO_DATA_DIR — _storage_backend() picks the marker up on
# its own, exactly like a bare-metal main install (which also pins Postgres
# via the marker, not an env var — only the Docker/Compose path pins via env).
if [[ "$WITH_POSTGRES" -eq 1 ]]; then
  echo "── Provisioning a separate demo PostgreSQL database…"
  RP_DB_NAME="${RP_DEMO_DB_NAME:-remotepower_demo}"
  RP_DB_USER="${RP_DEMO_DB_USER:-rp_demo}"
  RP_DB_PASS="${RP_DEMO_DB_PASS:-}"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "DRY-RUN: would run: RP_DB_NAME=$RP_DB_NAME RP_DB_USER=$RP_DB_USER RP_DB_PASS=<generated> bash $SCRIPT_DIR/postgres-setup.sh --install"
    echo "DRY-RUN: would migrate $DEMO_DATA_DIR (JSON) -> postgres via api._migrate_storage_pg"
  else
    [[ -n "$RP_DB_PASS" ]] || RP_DB_PASS="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
    [[ -f "$SCRIPT_DIR/postgres-setup.sh" ]] || die "packaging/postgres-setup.sh not found — can't provision the demo database"
    RP_DB_NAME="$RP_DB_NAME" RP_DB_USER="$RP_DB_USER" RP_DB_PASS="$RP_DB_PASS" \
      bash "$SCRIPT_DIR/postgres-setup.sh" --install \
      || die "postgres-setup.sh failed — demo stays on the flat-JSON backend"
    PG_DSN="postgresql://${RP_DB_USER}:${RP_DB_PASS}@localhost:5432/${RP_DB_NAME}"
    echo "── Migrating demo data into Postgres ($RP_DB_NAME)…"
    # RP_STORAGE_BACKEND intentionally unset here so the migration reads its
    # SOURCE data from the JSON files just seeded, not from (empty) Postgres.
    if RP_DATA_DIR="$DEMO_DATA_DIR" RP_PG_DSN="$PG_DSN" python3 - <<PYEOF
import os, sys
sys.path.insert(0, '$PROD_HTDOCS/cgi-bin')
import api
result = api._migrate_storage_pg('postgres', os.environ['RP_PG_DSN'], log=print)
print('[migrate]', result)
sys.exit(0 if result.get('ok') else 1)
PYEOF
    then
      chown "$CGI_USER:$CGI_GROUP" "$DEMO_DATA_DIR/storage_backend.json" 2>/dev/null || true
      echo "  → demo data migrated — PostgreSQL is now the demo's active backend"
    else
      die "demo migration into Postgres failed — see output above"
    fi
  fi
fi

# ─── Step 2b: dedicated gunicorn unit for the demo (its own port + data dir) ─

UNIT_PATH="/etc/systemd/system/remotepower-wsgi-demo.service"
UNIT_BODY=$(cat <<EOF
# RemotePower demo app server — auto-generated by install-demo.sh
# Same code as remotepower-wsgi (shared $PROD_HTDOCS/cgi-bin), separate
# process so it can run its own RP_DATA_DIR + RP_READ_ONLY.
[Unit]
Description=RemotePower demo app server (gunicorn, read-only)
After=network.target

[Service]
Type=simple
User=$CGI_USER
Group=$CGI_GROUP
WorkingDirectory=$PROD_HTDOCS/cgi-bin
Environment=RP_DATA_DIR=$DEMO_DATA_DIR
Environment=RP_READ_ONLY=1
ExecStart=/usr/bin/gunicorn --workers 2 --threads 4 --timeout 120 \\
          --bind 127.0.0.1:$DEMO_PORT wsgi:application
Restart=always
RestartSec=2
NoNewPrivileges=true
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$DEMO_DATA_DIR

[Install]
WantedBy=multi-user.target
EOF
)

echo "── Writing $UNIT_PATH…"
if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "DRY-RUN: would write to $UNIT_PATH:"
  echo "$UNIT_BODY" | sed 's/^/  | /'
  echo "DRY-RUN: would run: systemctl daemon-reload && systemctl enable --now remotepower-wsgi-demo"
else
  command -v gunicorn >/dev/null 2>&1 || die "gunicorn not found — install it first (see install-server.sh)"
  [[ -x /usr/bin/gunicorn ]] || ln -sf "$(command -v gunicorn)" /usr/bin/gunicorn
  printf '%s\n' "$UNIT_BODY" > "$UNIT_PATH"
  chmod 644 "$UNIT_PATH"
  systemctl daemon-reload
  systemctl enable --now remotepower-wsgi-demo \
    || die "remotepower-wsgi-demo failed to start — check: systemctl status remotepower-wsgi-demo"
fi

# ─── Step 3: render nginx vhost ──────────────────────────────────────────────

# Where to put the nginx config. Prefer sites-available/sites-enabled style
# (Debian/Ubuntu); fall back to a single conf.d snippet if that scheme isn't
# in use (Fedora/RHEL/Alpine often use /etc/nginx/conf.d/ directly).
NGINX_CONF=""
NGINX_LINK=""
if [[ -d "$NGINX_SITES_AVAIL" ]]; then
  NGINX_CONF="$NGINX_SITES_AVAIL/remotepower-demo"
  NGINX_LINK="$NGINX_SITES_ENABL/remotepower-demo"
elif [[ -d "/etc/nginx/conf.d" ]]; then
  NGINX_CONF="/etc/nginx/conf.d/remotepower-demo.conf"
elif [[ "$DRY_RUN" -eq 1 ]]; then
  # Pretend it's the Debian-style layout for the preview output.
  NGINX_CONF="$NGINX_SITES_AVAIL/remotepower-demo"
  NGINX_LINK="$NGINX_SITES_ENABL/remotepower-demo"
  echo "  (nginx not installed; using Debian-style paths for dry-run preview)"
else
  die "Can't find nginx config dir. Looked for $NGINX_SITES_AVAIL and /etc/nginx/conf.d/"
fi

echo "── Writing nginx config to $NGINX_CONF…"

# Generate the config. Note: we leave TLS to the user (certbot, acme.sh, etc.).
# The skeleton listens on port 80 only and includes a hint for HTTPS at the
# bottom. If the user already has TLS termination configured for their main
# remote.tvipper.com, they can copy those listen + ssl_* directives.
NGINX_BODY=$(cat <<EOF
# RemotePower demo vhost — auto-generated by install-demo.sh
#
# This is a READ-ONLY public sandbox. It serves the same code as the main
# install but proxies to its OWN gunicorn process (remotepower-wsgi-demo,
# 127.0.0.1:$DEMO_PORT) with a separate data dir (\$DEMO_DATA_DIR) and the
# RP_READ_ONLY flag. Mutations get a friendly 403; everything else works.
#
# After enabling: run \`sudo nginx -t && sudo systemctl reload nginx\`,
# then point DNS at this server and run certbot --nginx -d $DEMO_HOST.

server {
    listen      80;
    listen      [::]:80;
    server_name $DEMO_HOST;

    # Shared htdocs with the main install; static assets only — /api/ goes
    # to the demo's own app-server process (proxy_pass below).
    root        $PROD_HTDOCS;
    index       index.html;

    # Static assets (logos, css, js)
    location /static/ {
        try_files \$uri =404;
    }

    # The demo's OWN gunicorn process (remotepower-wsgi-demo.service) — same
    # code, its own RP_DATA_DIR + RP_READ_ONLY=1 baked into that unit.
    location ~ ^/api/ {
        proxy_pass         http://127.0.0.1:$DEMO_PORT;
        proxy_set_header   Host              \$host;
        proxy_set_header   X-Real-IP         \$remote_addr;
        proxy_set_header   X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto \$scheme;
        proxy_read_timeout 130s;
    }

    # Static dashboard pages
    location = / {
        try_files /index.html =404;
    }
    location ~ \\.html\$ {
        try_files \$uri =404;
    }

    # Block access to anything else (data files, dotfiles, etc.)
    location / {
        return 404;
    }

    # ── HTTPS reminder ──────────────────────────────────────────────────
    # Once DNS resolves $DEMO_HOST to this server, get a cert:
    #     sudo certbot --nginx -d $DEMO_HOST
    # certbot will rewrite this server block to add 443 listen + ssl_*
    # directives + auto-renewal. Or copy the relevant lines from your
    # existing main vhost.
}
EOF
)

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "DRY-RUN: would write to $NGINX_CONF:"
  echo "── nginx config preview ────"
  echo "$NGINX_BODY" | sed 's/^/  | /'
  echo "── /preview ────────────────"
else
  printf '%s\n' "$NGINX_BODY" > "$NGINX_CONF"
  chmod 644 "$NGINX_CONF"
fi

# Symlink into sites-enabled if that scheme is in use
if [[ -n "${NGINX_LINK:-}" ]]; then
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "DRY-RUN: would symlink $NGINX_CONF → $NGINX_LINK"
  elif [[ ! -L "$NGINX_LINK" ]]; then
    ln -sf "$NGINX_CONF" "$NGINX_LINK"
    echo "  → enabled via $NGINX_LINK"
  else
    echo "  → $NGINX_LINK already linked"
  fi
fi

# ─── Step 4: validate + reload nginx ─────────────────────────────────────────

echo "── Validating nginx config…"
if [[ "$DRY_RUN" -eq 0 ]]; then
  if ! nginx -t; then
    echo "✗ nginx -t failed. Inspect $NGINX_CONF, fix, then:"
    echo "    sudo nginx -t && sudo systemctl reload nginx"
    exit 1
  fi
  run systemctl reload nginx
fi

# ─── Final summary ───────────────────────────────────────────────────────────

cat <<EOF

────────────────────────────────────────────────────────────────────
✓ Demo vhost installed.

   Hostname:    $DEMO_HOST
   Code:        $PROD_HTDOCS  (shared with production)
   Data dir:    $DEMO_DATA_DIR  (separate from production)
   Mode:        read-only (RP_READ_ONLY=1, its own gunicorn process on :$DEMO_PORT)
   Backend:     $([ "$WITH_POSTGRES" -eq 1 ] && echo "PostgreSQL (${RP_DEMO_DB_NAME:-remotepower_demo}, separate from production)" || echo "flat-JSON (pass --postgres to use PostgreSQL instead)")
   systemd:     $UNIT_PATH
   nginx conf:  $NGINX_CONF

   Demo login:  demo / demo  (viewer role; can't do anything anyway)

Next steps:
  1. Point DNS for $DEMO_HOST at this server's public IP.
  2. Get a TLS cert:
       sudo certbot --nginx -d $DEMO_HOST
     Or copy the listen 443 + ssl_* directives from your existing
     server block at remote.<your-domain>.
  3. Visit https://$DEMO_HOST and log in as demo / demo.

To re-seed the demo data later (e.g. after a code update):
  sudo bash $0 $DEMO_HOST$([ "$WITH_POSTGRES" -eq 1 ] && echo " --postgres")
  (re-running this script is idempotent — it re-seeds and, with --postgres,
  re-migrates into the same demo database)

To remove:
  sudo systemctl disable --now remotepower-wsgi-demo
  sudo rm $UNIT_PATH
  sudo rm $NGINX_CONF
  $([ -n "${NGINX_LINK:-}" ] && echo "sudo rm $NGINX_LINK")
  sudo rm -rf $DEMO_DATA_DIR
  sudo systemctl daemon-reload
  sudo nginx -t && sudo systemctl reload nginx
$([ "$WITH_POSTGRES" -eq 1 ] && cat <<PGEOF
  # Demo used PostgreSQL — drop its database/role too if you're done with it
  # (left in place by default; not touched by the removal steps above):
  sudo -u postgres dropdb ${RP_DEMO_DB_NAME:-remotepower_demo}
  sudo -u postgres dropuser ${RP_DEMO_DB_USER:-rp_demo}
PGEOF
)
────────────────────────────────────────────────────────────────────
EOF
