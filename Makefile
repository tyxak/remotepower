# RemotePower developer Makefile.
# Convenience targets for tests, formatting, and the lint pipeline.
# Nothing here is required for a deployment — install-server.sh handles
# everything the running server needs.

.PHONY: help test format lint typecheck check clean install-dev

PY      ?= python3
PIP     ?= pip3
# Lint/format scope: the modules that are explicitly maintained under
# black + isort + strict mypy. The bulk of api.py predates the formatter
# pass and reformatting it in one go would produce an unreviewable diff;
# expanding the scope is a deliberate, separate effort.
LINT_SRC := server/cgi-bin/cmdb_vault.py \
            server/cgi-bin/openapi_spec.py \
            tests/test_v190.py \
            tests/test_v1100.py
TYPECHECK_SRC := server/cgi-bin/cmdb_vault.py \
                 server/cgi-bin/openapi_spec.py
PIP_FLAGS ?= --break-system-packages

help:
	@echo "RemotePower dev targets"
	@echo "  make test        - run the full unit-test suite (268+ tests)"
	@echo "  make format      - black + isort over the lint baseline"
	@echo "  make lint        - format-check + isort-check + mypy"
	@echo "  make typecheck   - mypy only"
	@echo "  make check       - test + lint (CI gate)"
	@echo "  make install-dev - install black, isort, mypy locally"
	@echo "  make clean       - drop __pycache__ trees"

install-dev:
	$(PIP) install $(PIP_FLAGS) black isort mypy

test:
	$(PY) -m unittest discover -s tests -v

format:
	$(PY) -m isort $(LINT_SRC)
	$(PY) -m black $(LINT_SRC)

lint:
	$(PY) -m isort --check-only $(LINT_SRC)
	$(PY) -m black --check $(LINT_SRC)
	$(PY) -m mypy $(TYPECHECK_SRC)

typecheck:
	$(PY) -m mypy $(TYPECHECK_SRC)

check: test lint

clean:
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete
