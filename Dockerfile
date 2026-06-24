FROM python:3.12-slim

# Real version is injected at build time (the ghcr.io release workflow passes
# --build-arg VERSION=<tag>); defaults to "dev" for a local `docker build`.
ARG VERSION=dev

LABEL maintainer="tyxak"
LABEL description="RemotePower - Self-hosted remote device management"
LABEL version="${VERSION}"
LABEL org.opencontainers.image.source="https://github.com/tyxak/remotepower"

# Install nginx, fcgiwrap and runtime deps.
# xmlsec1 = the system binary pysaml2 shells out to for SAML signature
# verification (v4.2.0 B1); without it SAML SSO reports unavailable.
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        nginx fcgiwrap spawn-fcgi procps xmlsec1 openssl && \
    pip install --no-cache-dir bcrypt reportlab 'cryptography>=44.0.1' dnspython webauthn pysaml2 && \
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
# Publish product docs under the web root so the in-app "Documentation" links
# (href="docs/<name>.md") resolve. (Also indexed for RAG from the data dir.)
COPY docs/                          /var/www/remotepower/docs/
RUN chmod 755 /var/www/remotepower/cgi-bin/api.py \
              /var/www/remotepower/cgi-bin/api_cgi.py \
              /var/www/remotepower/cgi-bin/remotepower-passwd \
              /var/www/remotepower/agent/remotepower-agent && \
    # v1.11.0: helper scripts need +x too
    if [ -f /var/www/remotepower/cgi-bin/remotepower-tls-check ]; then \
        chmod 755 /var/www/remotepower/cgi-bin/remotepower-tls-check; \
    fi && \
    # Precompile so the CGI user loads cached bytecode: api_cgi.py imports api,
    # and a CGI main script never uses the .pyc cache, so without this the
    # ~50k-line module is recompiled on every request.
    python3 -m compileall -q /var/www/remotepower/cgi-bin/

# Nginx config (Docker variant - listens on 8080, no IPv6 listen). The shared
# location snippet + the opt-in TLS variant ride along for RP_TLS_SELFSIGNED.
COPY docker/nginx-docker.conf            /etc/nginx/sites-available/remotepower
COPY docker/nginx-docker-tls.conf        /etc/nginx/sites-available/remotepower-tls
RUN mkdir -p /etc/nginx/snippets
COPY docker/nginx-docker-locations.conf  /etc/nginx/snippets/remotepower-docker-locations.conf
RUN ln -sf /etc/nginx/sites-available/remotepower /etc/nginx/sites-enabled/remotepower && \
    rm -f /etc/nginx/sites-enabled/default

# v4.5.0: the self-signed CA generator, used by the entrypoint when
# RP_TLS_SELFSIGNED=1 (openssl is installed above).
COPY tools/gen-ca.sh /usr/local/bin/rp-gen-ca
RUN chmod 755 /usr/local/bin/rp-gen-ca

# Entrypoint script
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

EXPOSE 8080 8443

VOLUME ["/var/lib/remotepower"]

# v2.2.6: healthcheck uses Python (always present in this image) instead
# of curl, which was never installed — the old healthcheck could never
# succeed and the container always went "unhealthy" even when nginx was
# serving fine.
# v3.0.6: probe /api/health instead of `/`. The new endpoint is a few
# bytes of JSON and doesn't load the whole SPA on every poll.
HEALTHCHECK --interval=60s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8080/api/health',timeout=4).status==200 else 1)" || exit 1

ENTRYPOINT ["/entrypoint.sh"]
