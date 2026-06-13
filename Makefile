# RemotePower developer Makefile.
# Convenience targets for tests, formatting, and the lint pipeline.
# Nothing here is required for a deployment — install-server.sh handles
# everything the running server needs.

.PHONY: help test format lint typecheck check clean install-dev dist version scan-demo

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
            tests/test_v190.py \
            tests/test_v1100.py \
            tests/test_v430_worker.py
TYPECHECK_SRC := server/cgi-bin/cmdb_vault.py \
                 server/cgi-bin/openapi_spec.py
PIP_FLAGS ?= --break-system-packages

# v2.1.0: extract the canonical version from api.py so `make dist` and the
# release tarball name stay in sync with the running code. Single source
# of truth means nobody has to remember to bump it in two places.
VERSION := $(shell awk -F"'" '/^SERVER_VERSION/ {print $$2; exit}' \
                   server/cgi-bin/api.py)
DIST_NAME := remotepower-$(VERSION)
DIST_DIR  := dist

help:
	@echo "RemotePower dev targets"
	@echo "  make test        - run the full unit-test suite (1064+ tests)"
	@echo "  make format      - black + isort over the lint baseline"
	@echo "  make lint        - format-check + isort-check + mypy"
	@echo "  make typecheck   - mypy only"
	@echo "  make check       - test + lint (CI gate)"
	@echo "  make dist        - build dist/$(DIST_NAME).tar.gz (release tarball)"
	@echo "  make version     - print the current version ($(VERSION))"
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
	  --exclude='./__pycache__' \
	  --exclude='*.pyc' \
	  --exclude='*.pyo' \
	  --exclude='*.swp' \
	  --exclude='*.swo' \
	  --exclude='./.DS_Store' \
	  --exclude='./Thumbs.db' \
	  --exclude='./dist' \
	  --exclude='./build' \
	  --exclude='./.cache' \
	  --exclude='./.mypy_cache' \
	  --exclude='./.pytest_cache' \
	  --exclude='./.venv' \
	  --exclude='./venv' \
	  --exclude='./node_modules' \
	  --exclude='./site' \
	  --exclude='./deploy' \
	  --exclude='./docs/*-internal.md' \
	  --exclude='./CLAUDE.md' \
	  .
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

clean:
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete
	rm -rf $(DIST_DIR)
