---
name: building-integration
description: "Runs the local build and validation pipeline for an Autohive integration — structure validation, code quality checks, linting, formatting, security scanning, and unit tests. Use when asked to build, validate, check, or verify an integration before pushing."
---

# Building & Validating an Integration Locally

Run the same checks CI runs, locally, before pushing.

## Prerequisites

The tooling repo must be cloned alongside the integrations repo:

```
parent-dir/
├── autohive-integrations/          ← you are here
└── autohive-integrations-tooling/  ← must exist
```

The integrations repo must have a `.venv` with Python 3.13+ and test dependencies installed:

```bash
source .venv/bin/activate
uv pip install -r requirements-test.txt
```

## Build Pipeline

Run these steps in order from the integrations repo root. Replace `<name>` with the integration folder name (e.g., `clickup`).

### Step 1 — Install integration dependencies

```bash
source .venv/bin/activate
uv pip install -r <name>/requirements.txt
```

### Step 2 — Structure validation

```bash
python ../autohive-integrations-tooling/scripts/validate_integration.py <name>
```

Checks: folder naming, required files (`config.json`, `requirements.txt`, `README.md`, icon, tests/`), config.json schema, auth config, action definitions, SDK version pinning, test structure.

Exit codes: `0` = passed, `1` = errors found, `2` = processing error.

### Step 3 — Code quality checks

```bash
python ../autohive-integrations-tooling/scripts/check_code.py <name>
```

Runs (in order): dependency install, Python syntax, import resolution, JSON validity, ruff lint, ruff format, bandit security scan, pip-audit, config-code sync, fetch pattern check.

Exit codes: `0` = passed, `1` = failures found.

### Step 4 — Unit tests

```bash
pytest <name>/ -v
```

Only runs tests in `test_*_unit.py` files (configured in `pyproject.toml`).

### Step 5 — Auto-fix lint and formatting issues

If steps 2–4 report ruff errors, auto-fix with:

```bash
ruff check --fix --config ../autohive-integrations-tooling/ruff.toml <name>
ruff format --config ../autohive-integrations-tooling/ruff.toml <name>
```

Then re-run steps 2–4 to confirm.

## Ruff Configuration

CI uses the `ruff.toml` from the tooling repo — always pass `--config ../autohive-integrations-tooling/ruff.toml` to match CI behavior.

Key settings:
- `target-version = "py313"`
- `line-length = 120`
- Rules: `E` (pycodestyle errors), `F` (Pyflakes), `W` (pycodestyle warnings)
- `__init__.py`: `F401` ignored (re-exports)
- `**/tests/context.py`: `F401`, `E402` ignored

## Workflow Summary

1. Install deps → `uv pip install -r <name>/requirements.txt`
2. Validate structure → `python ../autohive-integrations-tooling/scripts/validate_integration.py <name>`
3. Check code → `python ../autohive-integrations-tooling/scripts/check_code.py <name>`
4. Run tests → `pytest <name>/ -v`
5. Fix issues → `ruff check --fix ...` / `ruff format ...`
6. Re-run until all pass

## Interpreting Output

### validate_integration.py
- `❌` = Error — must fix before PR
- `⚠️` = Warning — review but won't block CI
- Final summary shows total errors/warnings across all integrations

### check_code.py
- Each check prints `✅` or `❌` with details
- All checks run even if one fails (no short-circuit)
- Final line: `✅ CODE CHECK PASSED` or `❌ CODE CHECK FAILED`

### Common Failures and Fixes

| Failure | Fix |
|---|---|
| Ruff lint errors | `ruff check --fix --config ../autohive-integrations-tooling/ruff.toml <name>` |
| Ruff format errors | `ruff format --config ../autohive-integrations-tooling/ruff.toml <name>` |
| Bandit security issue | Add `# nosec B105` for test credential strings; fix real issues |
| Config-code sync | Ensure actions in `config.json` match handlers in source code |
| Missing test files | Create `tests/test_<name>_unit.py` (see `writing-unit-tests` skill) |
| Import errors | Check `requirements.txt` has all dependencies; check `__init__.py` exports |
