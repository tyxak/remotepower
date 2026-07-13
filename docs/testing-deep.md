# Deep-testing workflow

Beyond `make test` (the unittest gate), these tools *find* bugs rather than
re-checking known cases. All install + run out of the box.

## Property-based / fuzz (highest value)
`pip install hypothesis` then `python3 -m pytest tests/test_hypothesis_props.py -q`.
States INVARIANTS (round-trips, idempotence, backend-agreement, "never 500") and
generates thousands of inputs to break them; prints a minimal counterexample.
CI-safe: the module skips cleanly when hypothesis is absent.

## Test-isolation leaks
`pip install pytest-randomly` then `python3 -m pytest tests/ -p randomly` — shuffles
order to expose tests that leak global state (found the `subprocess.run` stub leak).
The printed `--randomly-seed=N` reproduces a failing order.

## Coverage (untested paths)
`pip install coverage` then
`python3 -m coverage run -m pytest tests/ && python3 -m coverage report -m`.

## Mutation testing (weak tests)
`pip install mutmut` — mutates code, checks the suite catches it. Slow; scope to a
module: `mutmut run --paths-to-mutate server/cgi-bin/sanitize.py`.

## API fuzzing (from the OpenAPI spec)
`pip install schemathesis`. The server serves its own spec at `/api/openapi.json`;
point schemathesis at a running instance to hammer every documented endpoint for
crashes / schema violations.

## Static (already wired, keep at zero)
`tools/codeql-local.sh` (the real gate), `bandit -r server/cgi-bin client -b
.bandit-baseline.json`, `gitleaks detect -c .gitleaks.toml`, plus
`ruff check --select F,B` and `vulture` for dead code.
