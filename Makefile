# RemotePower developer Makefile.
# Convenience targets for tests, formatting, and the lint pipeline.
# Nothing here is required for a deployment — install-server.sh handles
# everything the running server needs.

.PHONY: help test format lint typecheck bandit bandit-baseline codeql check clean install-dev dist release version scan-demo app-server-wsgi app-server-cgi app-server-status

PY      ?= python3
PIP     ?= pip3
# Lint/format scope: the modules that are explicitly maintained under
# black + isort + strict mypy. The bulk of api.py predates the formatter
# pass and reformatting it in one go would produce an unreviewable diff;
# expanding the scope is a deliberate, separate effort.
# v4.3.0: every NEW module gets added here at creation (api_worker.py is the
# template). The legacy monolith files (api.py, app.js-era tests) stay out —
# reformatting them is an unreviewable diff for zero behavior change.
LINT_SRC := server/cgi-bin/cmdb_vault.py \
            server/cgi-bin/openapi_spec.py \
            server/cgi-bin/api_worker.py \
            server/cgi-bin/integrations.py \
            server/cgi-bin/hypervisor.py \
            server/cgi-bin/dns_resolve.py \
            server/cgi-bin/resolver_health.py \
            server/cgi-bin/backup_crypto.py \
            server/cgi-bin/wg_access.py \
            server/cgi-bin/billing.py \
            server/cgi-bin/notify.py \
            server/cgi-bin/checks.py \
            tests/test_v190.py \
            tests/test_v1100.py \
            tests/test_v430_worker.py
TYPECHECK_SRC := server/cgi-bin/cmdb_vault.py \
                 server/cgi-bin/openapi_spec.py \
                 server/cgi-bin/integrations.py \
                 server/cgi-bin/hypervisor.py \
                 server/cgi-bin/dmarc_monitor.py \
                 server/cgi-bin/ip_reputation.py \
                 server/cgi-bin/dns_resolve.py \
                 server/cgi-bin/resolver_health.py \
                 server/cgi-bin/backup_crypto.py \
                 server/cgi-bin/wg_access.py \
                 server/cgi-bin/billing.py \
                 server/cgi-bin/notify.py \
                 server/cgi-bin/checks.py
PIP_FLAGS ?= --break-system-packages

# v2.1.0: extract the canonical version from api.py so `make dist` and the
# release tarball name stay in sync with the running code. Single source
# of truth means nobody has to remember to bump it in two places.
VERSION := $(shell awk -F"'" '/^SERVER_VERSION/ {print $$2; exit}' \
                   server/cgi-bin/api.py)
DIST_NAME := remotepower-$(VERSION)
DIST_DIR  := dist

# GPG key the release tarball is detach-signed with (`make release`). Defaults
# to the key git already uses for signed tags/commits, so the tarball signature
# and the signed git tag come from the same identity. Override:
#   make release SIGN_KEY=<keyid>
SIGN_KEY  ?= $(shell git config --get user.signingkey)

help:
	@echo "RemotePower dev targets"
	@echo "  make test        - run the full unit-test suite (1064+ tests)"
	@echo "  make format      - black + isort over the lint baseline"
	@echo "  make lint        - format-check + isort-check + mypy"
	@echo "  make typecheck   - mypy only"
	@echo "  make check       - test + lint (CI gate)"
	@echo "  make dist        - build dist/$(DIST_NAME).tar.gz (release tarball)"
	@echo "  make version     - print the current version ($(VERSION))"
	@echo "  make tls-selfsigned HOST=rp.internal [NGINX=1] - self-signed CA + leaf (prefer a real cert)"
	@echo "  make tls-renew   - re-issue the server leaf from the existing CA (clients unaffected)"
	@echo "  sudo make app-server-wsgi  - switch this install to the gunicorn WSGI tier + scheduler (NO_SCHEDULER=1 to skip)"
	@echo "  sudo make app-server-cgi   - switch back to the CGI/fcgiwrap tier (KEEP_SCHEDULER=1 to keep the scheduler)"
	@echo "  make app-server-status     - show the active app tier + unit/scheduler state"
	@echo "  make install-dev - install black, isort, mypy locally"
	@echo "  make scan-demo   - drive a B5 security scan to completion (needs a running server)"
	@echo "  make clean       - drop __pycache__ trees + dist/"

version:
	@echo $(VERSION)

# v4.2.0 (B5): drive a security scan end-to-end against a RUNNING server (e.g.
# the docker compose stack) — logs in, mints a scanner satellite, queues a scan,
# fake-claims it and posts findings, so you watch it reach `done`. Override the
# target with RP_URL / RP_USER / RP_PASS (defaults: http://localhost:8085,
# admin, changeme).
scan-demo:
	@echo "==> Security-scan demo against $${RP_URL:-http://localhost:8085} (server must be up)"
	$(PY) tools/scan-demo.py

# Pinned versions (see [tool.remotepower-dev-deps] in pyproject.toml): an
# unpinned `black` drifts with every release and starts flagging files the
# previous version formatted — which is exactly how `make lint` silently
# broke between v4.2.0 and v4.3.0.
install-dev:
	$(PIP) install $(PIP_FLAGS) 'black==26.5.1' 'isort==8.0.1' 'mypy==2.1.0'

test:
	$(PY) -m unittest discover -s tests -v

# v4.3.0: automate the mechanical version-bump steps (CLAUDE.md checklist).
# Usage: make bump VERSION=4.4.0  (add DRY=1 for a dry run)
bump:
	$(PY) tools/bump_version.py $(VERSION) $(if $(DRY),--dry-run,)

# v4.5.0 "TrustMatters": generate a self-signed CA + server leaf for instances
# that can't use a real (Let's Encrypt) cert. Agents trust the CA via
# RP_CA_BUNDLE; renew the leaf without touching clients. PREFER A REAL CERT —
# see docs/tls-selfsigned.md. Usage: make tls-selfsigned HOST=rp.internal
tls-selfsigned:
	@test -n "$(HOST)" || { echo "usage: make tls-selfsigned HOST=<dns-or-ip> [NGINX=1]"; exit 1; }
	sudo bash tools/gen-ca.sh --host $(HOST) $(if $(NGINX),--nginx --reload,)

# Re-issue ONLY the server leaf from the existing CA (clients keep trust).
tls-renew:
	sudo bash tools/gen-ca.sh --renew $(if $(NGINX),--reload,)

# v5.5.0: switch an EXISTING install between the persistent gunicorn WSGI app
# tier and the default CGI/fcgiwrap tier, idempotently and reversibly. The WSGI
# switch saves the CGI nginx snippet to .cgi.bak so the way back is lossless.
# `app-server-wsgi` also enables the out-of-band scheduler (pass NO_SCHEDULER=1
# to skip); `app-server-cgi` disables it (KEEP_SCHEDULER=1 to leave it on).
app-server-wsgi:
	sudo bash packaging/remotepower-app-server.sh wsgi $(if $(NO_SCHEDULER),--no-scheduler,)

app-server-cgi:
	sudo bash packaging/remotepower-app-server.sh cgi $(if $(KEEP_SCHEDULER),--keep-scheduler,)

app-server-status:
	@bash packaging/remotepower-app-server.sh status

# v4.3.0: browser smoke suite (Playwright + Chromium). Self-skips when
# playwright isn't installed: pip install playwright && python -m playwright
# install chromium. Boots the real stack (static + SCGI worker) headless.
e2e:
	cd tests && $(PY) -m unittest test_v430_e2e -v

# v3.12.0: run the full suite against the SQLite storage backend. The flat-JSON
# storage-internals tests (flock/.bak/.tmp) are skipped via @skip_under_sqlite;
# everything else must pass on both backends. `test-both` is the CI gate.
test-sqlite:
	RP_STORAGE_BACKEND=sqlite $(PY) -m unittest discover -s tests -v

test-both: test test-sqlite

# v3.14.0 (#1): Postgres backend integration tests. They self-skip unless a DSN
# is provided (RP_PG_TEST_DSN env or ~/.rp_pg_test_dsn) and psycopg is installed,
# so this is safe to run anywhere — it just no-ops without a target database.
test-pg:
	$(PY) -m unittest tests.test_pg -v

# Full matrix: JSON + SQLite + (when a DSN is configured) Postgres.
test-all: test-both test-pg

format:
	$(PY) -m isort $(LINT_SRC)
	$(PY) -m black $(LINT_SRC)

lint:
	$(PY) -m isort --check-only $(LINT_SRC)
	$(PY) -m black --check $(LINT_SRC)
	$(PY) -m mypy $(TYPECHECK_SRC)

typecheck:
	$(PY) -m mypy $(TYPECHECK_SRC)

# v5.4.1 (C7): CycloneDX SBOM of the SERVER's OWN Python supply chain (distinct
# from the FLEET SBOM at /api/sbom). Documents the control plane for supply-chain
# transparency / SLSA. Stdlib-only generator, runs anywhere.
sbom-self:
	@mkdir -p $(DIST_DIR)
	$(PY) tools/gen-self-sbom.py $(VERSION) > $(DIST_DIR)/remotepower-server-$(VERSION).sbom.json
	@echo "wrote $(DIST_DIR)/remotepower-server-$(VERSION).sbom.json"

# v5.4.1 (E5): Postman v2.1 collection generated from the (route-table-driven,
# fully-covering) OpenAPI spec. Import into Postman/Insomnia/Bruno.
postman:
	@mkdir -p $(DIST_DIR)
	$(PY) tools/gen-postman.py > $(DIST_DIR)/remotepower.postman_collection.json
	@echo "wrote $(DIST_DIR)/remotepower.postman_collection.json"

# Fast SAST proxy for GitHub Code Scanning: bandit at medium+ severity AND
# confidence over the shipped server + agent Python. The codebase has a large
# INTENTIONAL sink surface (a fleet manager runs subprocesses / opens URLs), so
# this runs against a committed baseline (tools/bandit-baseline.json) and only
# fails on NEW findings — the "did I just add something" pre-push smoke. NOT a
# CodeQL substitute (see `make codeql` for the faithful run). Regenerate the
# baseline after an intentional, triaged change:
#   make bandit-baseline
BANDIT_SRC := server/cgi-bin client/remotepower-agent.py \
              client/remotepower-agent-win.py client/remotepower-agent-mac.py
bandit:
	$(PY) -m bandit -ll -ii -b tools/bandit-baseline.json -r $(BANDIT_SRC)

bandit-baseline:
	$(PY) -m bandit -ll -ii -r $(BANDIT_SRC) -f json -o tools/bandit-baseline.json -q || true
	@echo "wrote tools/bandit-baseline.json"

# Faithful local reproduction of GitHub's "CodeQL default setup" code scanning
# (python + javascript, the default code-scanning query suite). First run
# downloads the CodeQL bundle into .codeql-cache/ (gitignored). Run this before a
# release push to see exactly what GitHub Code Scanning would flag.
codeql:
	tools/codeql-local.sh

check: test-both lint

# Release tarball. Builds a clean copy of the tree into a versioned
# directory inside dist/, drops everything that has no business shipping
# (caches, editor swap files, the docs holding pen, the test suite is
# included because we ship it; .git is excluded by default — see the tar
# exclude list below), and produces both .tar.gz and SHA-256.
#
# The exclude list is intentionally explicit rather than a .distignore
# file: when the next contributor adds a `secrets/` or `private_keys/`
# directory, they'll see the exclude list here and have to think about
# whether it should ship. A blanket `git ls-files` would silently ship
# anything new that wasn't deliberately gitignored.
dist: clean
	@echo "==> Building $(DIST_NAME).tar.gz"
	@rm -rf $(DIST_DIR)
	@mkdir -p $(DIST_DIR)
	@# Build with tar's --exclude (works on every Linux + macOS without
	@# rsync as a build dep). --transform renames the top-level directory
	@# inside the archive so the user gets `remotepower-X.Y.Z/...` when
	@# they untar, regardless of the source-tree name.
	@tar -czf $(DIST_DIR)/$(DIST_NAME).tar.gz \
	  --transform 's,^\.,$(DIST_NAME),' \
	  --exclude='./.git' \
	  --exclude='./.gitignore' \
	  --exclude='./.github' \
	  --exclude='__pycache__' \
	  --exclude='*.pyc' \
	  --exclude='*.pyo' \
	  --exclude='*.swp' \
	  --exclude='*.swo' \
	  --exclude='.DS_Store' \
	  --exclude='Thumbs.db' \
	  --exclude='./dist' \
	  --exclude='./build' \
	  --exclude='.cache' \
	  --exclude='.codeql-cache' \
	  --exclude='.mypy_cache' \
	  --exclude='.pytest_cache' \
	  --exclude='.ruff_cache' \
	  --exclude='.venv' \
	  --exclude='venv' \
	  --exclude='node_modules' \
	  --exclude='./site' \
	  --exclude='./deploy' \
	  --exclude='./docs/*-internal.md' \
	  --exclude='./CLAUDE.md' \
	  --exclude='./opencode.md' \
	  --exclude='./AGENTS.md' \
	  --exclude='./.claude' \
	  --exclude='./design' \
	  --exclude='./packaging/aur/*/src' \
	  --exclude='./packaging/aur/*/pkg' \
	  --exclude='*.tar.gz' \
	  --exclude='*.tar.gz.asc' \
	  --exclude='*.tar.xz' \
	  --exclude='*.pkg.tar.zst' \
	  --exclude='*.env' \
	  --exclude='.env' \
	  --exclude='*.pem' \
	  --exclude='*.key' \
	  --exclude='*.enc' \
	  --exclude='.ssh' \
	  --exclude='scan-*' \
	  .
	@# Leak gate (v5.8.0): the tarball packs the WORKING TREE, so untracked/
	@# gitignored local files ship unless the exclude list above names them —
	@# .claude/ (session tooling) rode into the published v5.2.0–v5.7.0
	@# tarballs exactly this way. Fail the build LOUDLY if any forbidden
	@# path is in the file list; a new local tool dir means a new exclude.
	@echo "==> Leak-checking the tarball file list"
	@! tar -tzf $(DIST_DIR)/$(DIST_NAME).tar.gz | grep -E \
	  '(^|/)(\.claude/|\.git/|CLAUDE\.md|opencode\.md|AGENTS\.md|site/|deploy/|api\.env|\.ssh/|\.codeql-cache/)|-internal\.md$$|\.enc$$' \
	  || { echo "==> LEAK: forbidden files in the tarball (listed above) — add an exclude"; exit 1; }
	@# Verify the smoke test passes against the staged tree. Extract into
	@# a scratch dir, run the tests, then nuke it. This catches the kind
	@# of release-time bug where someone forgets to commit a new file —
	@# the tarball is missing it and the tests blow up.
	@echo "==> Running tests against staged tree"
	@mkdir -p $(DIST_DIR)/.verify
	@tar -xzf $(DIST_DIR)/$(DIST_NAME).tar.gz -C $(DIST_DIR)/.verify
	@(cd $(DIST_DIR)/.verify/$(DIST_NAME) && $(PY) -m unittest discover -s tests) \
	  > $(DIST_DIR)/$(DIST_NAME).test.log 2>&1 || \
	  (echo "==> TESTS FAILED — see $(DIST_DIR)/$(DIST_NAME).test.log"; \
	   rm -rf $(DIST_DIR)/.verify; exit 1)
	@tail -3 $(DIST_DIR)/$(DIST_NAME).test.log
	@rm -rf $(DIST_DIR)/.verify $(DIST_DIR)/$(DIST_NAME).test.log
	@# Checksum
	@(cd $(DIST_DIR) && sha256sum $(DIST_NAME).tar.gz > $(DIST_NAME).tar.gz.sha256)
	@echo
	@echo "==> Built $(DIST_DIR)/$(DIST_NAME).tar.gz"
	@ls -lh $(DIST_DIR)/$(DIST_NAME).tar.gz $(DIST_DIR)/$(DIST_NAME).tar.gz.sha256

# Production release artifacts: the verified tarball + sha256 (from `dist`) plus
# a detached, ASCII-armoured GPG signature. Signing is LOCAL on purpose — the
# private key never goes near CI. Publishing the GitHub release (with these three
# assets) triggers the ghcr.io image push (.github/workflows/release.yml).
release: dist
	@command -v gpg >/dev/null 2>&1 || \
	  { echo "==> gpg not found — install gnupg or sign the tarball manually"; exit 1; }
	@test -n "$(SIGN_KEY)" || \
	  { echo "==> No signing key. Set one: git config user.signingkey <keyid>  (or make release SIGN_KEY=<keyid>)"; exit 1; }
	@echo "==> Signing $(DIST_NAME).tar.gz with key $(SIGN_KEY)"
	@rm -f $(DIST_DIR)/$(DIST_NAME).tar.gz.asc
	@gpg --local-user $(SIGN_KEY) --armor --output $(DIST_DIR)/$(DIST_NAME).tar.gz.asc \
	     --detach-sign $(DIST_DIR)/$(DIST_NAME).tar.gz
	@gpg --verify $(DIST_DIR)/$(DIST_NAME).tar.gz.asc $(DIST_DIR)/$(DIST_NAME).tar.gz
	@echo
	@echo "==> Release artifacts:"
	@ls -lh $(DIST_DIR)/$(DIST_NAME).tar.gz \
	        $(DIST_DIR)/$(DIST_NAME).tar.gz.sha256 \
	        $(DIST_DIR)/$(DIST_NAME).tar.gz.asc
	@echo
	@echo "==> Recipients verify with:"
	@echo "      sha256sum -c $(DIST_NAME).tar.gz.sha256"
	@echo "      gpg --verify $(DIST_NAME).tar.gz.asc $(DIST_NAME).tar.gz"
	@echo
	@echo "==> Publish (signed tag must already be pushed to the remotepower remote):"
	@echo "      gh release create v$(VERSION) \\"
	@echo "        $(DIST_DIR)/$(DIST_NAME).tar.gz \\"
	@echo "        $(DIST_DIR)/$(DIST_NAME).tar.gz.sha256 \\"
	@echo "        $(DIST_DIR)/$(DIST_NAME).tar.gz.asc \\"
	@echo "        --repo tyxak/remotepower --title 'v$(VERSION)' --notes-file docs/v$(VERSION).md"
	@echo "    Publishing the release pushes ghcr.io/tyxak/remotepower:$(VERSION) (+ :latest)."

clean:
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete
	# Also drop the tool caches. They're kept out of the release tarball by the
	# hand-maintained `dist` --exclude list; removing them here is a second line
	# of defence so a typo'd exclude can't silently bloat the release.
	rm -rf .mypy_cache .pytest_cache .ruff_cache .cache
	rm -rf $(DIST_DIR)
