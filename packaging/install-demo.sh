#!/bin/bash
# install-demo.sh — set up a separate read-only demo at e.g. demoremote.tvipper.com
#
# Architecture: the demo runs the SAME CGI code as your main install, just
# with a different data directory and the read-only flag set. nginx
# routes by Host header and passes the right env vars to fcgiwrap, which
# forwards them to the CGI process. Two completely separate state stores
# share one set of code on disk.
#
#   /var/www/remotepower/           — shared CGI code, dashboard HTML/JS/CSS
#   /var/lib/remotepower/           — REAL fleet data (your production install)
#   /var/lib/remotepower-demo/      — FAKE demo data (this script populates it)
#
# Per-vhost env vars set by nginx (`fastcgi_param RP_DATA_DIR ...`) tell the
# CGI which data dir to use for that request. Same Python process can serve
# both vhosts because fcgiwrap reads env from each request, not from its
# own startup environment.
#
# Usage:
#   sudo bash packaging/install-demo.sh demoremote.tvipper.com
#   sudo bash packaging/install-demo.sh demoremote.example.com --cgi-user nginx
#
# Idempotent: re-running re-seeds the demo data and re-renders the nginx
# config. Won't touch the production install.

set -euo pipefail

# ─── Defaults — overridable via flags ─────────────────────────────────────────

DEMO_HOST=""
CGI_USER=""             # auto-detect if empty
DEMO_DATA_DIR="/var/lib/remotepower-demo"
PROD_HTDOCS="/var/www/remotepower"   # shared with production
NGINX_SITES_AVAIL="/etc/nginx/sites-available"
NGINX_SITES_ENABL="/etc/nginx/sites-enabled"
DRY_RUN=0
SKIP_RESEED=0

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

# ─── Detect CGI user ──────────────────────────────────────────────────────────

if [[ -z "$CGI_USER" ]]; then
  echo "── Detecting CGI user…"
  for candidate in www-data nginx http rp-www apache; do
    if id "$candidate" &>/dev/null; then
      if pgrep -u "$candidate" -f '(fcgi|nginx|cgi|php-fpm)' &>/dev/null; then
        CGI_USER="$candidate"
        echo "  → found $CGI_USER (running web/CGI processes)"
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
[[ -z "$CGI_USER" ]] && die "Couldn't detect CGI user. Pass --cgi-user explicitly."
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
# This is a READ-ONLY public sandbox. It serves the same CGI code as the
# main install but uses a separate data dir (\$DEMO_DATA_DIR) and the
# RP_READ_ONLY flag. Mutations get a friendly 403; everything else works.
#
# After enabling: run \`sudo nginx -t && sudo systemctl reload nginx\`,
# then point DNS at this server and run certbot --nginx -d $DEMO_HOST.

server {
    listen      80;
    listen      [::]:80;
    server_name $DEMO_HOST;

    # Shared htdocs with the main install. Code is read-only at the
    # filesystem level; per-vhost behaviour comes from RP_DATA_DIR +
    # RP_READ_ONLY, set as fastcgi_param below.
    root        $PROD_HTDOCS;
    index       index.html;

    # Static assets (logos, css, js)
    location /static/ {
        try_files \$uri =404;
    }

    # The CGI. Note the two extra fastcgi_params: those tell the CGI to
    # operate on the demo data dir, in read-only mode.
    location ~ ^/api/ {
        fastcgi_pass            unix:/var/run/fcgiwrap.socket;
        fastcgi_split_path_info ^(/api)(/.*)\$;
        fastcgi_param           SCRIPT_FILENAME  $PROD_HTDOCS/cgi-bin/api_cgi.py;
        fastcgi_param           PATH_INFO        \$fastcgi_path_info;
        include                 /etc/nginx/fastcgi_params;

        # Per-vhost overrides — the magic that makes this a separate demo:
        fastcgi_param           RP_DATA_DIR       $DEMO_DATA_DIR;
        fastcgi_param           RP_READ_ONLY      1;
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
   Mode:        read-only (RP_READ_ONLY=1 set per-vhost)
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
  sudo -u $CGI_USER python3 $SEED_SCRIPT --data-dir $DEMO_DATA_DIR --apply

To remove:
  sudo rm $NGINX_CONF
  $([ -n "${NGINX_LINK:-}" ] && echo "sudo rm $NGINX_LINK")
  sudo rm -rf $DEMO_DATA_DIR
  sudo nginx -t && sudo systemctl reload nginx
────────────────────────────────────────────────────────────────────
EOF
