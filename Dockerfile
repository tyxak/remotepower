FROM python:3.12-slim

LABEL maintainer="tyxak"
LABEL description="RemotePower - Self-hosted remote device management"
LABEL version="1.11.11"

# Install nginx, fcgiwrap and runtime deps
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        nginx fcgiwrap spawn-fcgi procps && \
    pip install --no-cache-dir bcrypt reportlab cryptography dnspython && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Directories
RUN mkdir -p /var/www/remotepower/cgi-bin \
             /var/www/remotepower/agent \
             /var/lib/remotepower && \
    chown -R www-data:www-data /var/lib/remotepower && \
    chmod 700 /var/lib/remotepower

# Copy server files
# v1.9.0+: copy ALL cgi-bin files (api.py + sibling modules cmdb_vault,
# cve_scanner, prometheus_export, openapi_spec, containers, tls_monitor).
# Pre-v1.9 only copied api.py which silently broke the CMDB feature in Docker.
COPY server/html/                   /var/www/remotepower/
COPY server/cgi-bin/                /var/www/remotepower/cgi-bin/
COPY server/remotepower-passwd      /var/www/remotepower/cgi-bin/remotepower-passwd
COPY client/remotepower-agent       /var/www/remotepower/agent/remotepower-agent
RUN chmod 755 /var/www/remotepower/cgi-bin/api.py \
              /var/www/remotepower/cgi-bin/remotepower-passwd \
              /var/www/remotepower/agent/remotepower-agent && \
    # v1.11.0: helper scripts need +x too
    if [ -f /var/www/remotepower/cgi-bin/remotepower-tls-check ]; then \
        chmod 755 /var/www/remotepower/cgi-bin/remotepower-tls-check; \
    fi

# Nginx config (Docker variant - listens on 8080, no IPv6 listen)
COPY docker/nginx-docker.conf /etc/nginx/sites-available/remotepower
RUN ln -sf /etc/nginx/sites-available/remotepower /etc/nginx/sites-enabled/remotepower && \
    rm -f /etc/nginx/sites-enabled/default

# Entrypoint script
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

EXPOSE 8080

VOLUME ["/var/lib/remotepower"]

HEALTHCHECK --interval=60s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:8080/ > /dev/null || exit 1

ENTRYPOINT ["/entrypoint.sh"]
