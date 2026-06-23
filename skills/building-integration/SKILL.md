---
name: building-integration
description: "Runs the local build and validation pipeline for an Autohive integration — structure validation, code quality checks, linting, formatting, security scanning, and unit tests. Use when asked to build, validate, check, or verify an integration before pushing."
---

# Building & Validating an Integration Locally

Run the same checks CI runs, locally, before pushing.

## Preflight Checks

Run these checks **before** starting the build pipeline. Fix any that fail.

### 1. Tooling repo

The tooling repo must be cloned alongside the integrations repo:

```
parent-dir/
├── autohive-integrations/          ← you are here
└── autohive-integrations-tooling/  ← must exist
```

Check: `ls ../autohive-integrations-tooling/scripts/validate_integration.py`

If missing, clone it:

```bash
git clone https://github.com/autohive-ai/autohive-integrations-tooling.git ../autohive-integrations-tooling
```

### 2. Python 3.13+

Check: `python3 --version` (must be 3.13+)

If not available, install with uv:

```bash
uv python install 3.13
```

Or use your system package manager / pyenv.

### 3. Virtual environment

Check: `ls .venv/bin/python`

If missing, create it:

```bash
uv venv --python 3.13 .venv
```

Or without uv:

```bash
python3.13 -m venv .venv
```

Always activate before running any commands:

```bash
source .venv/bin/activate
```

### 4. Package installer

Check: `which uv` or `which pip`

uv is preferred. If neither is available, install uv:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### 5. Test dependencies

Check: `python -c "import pytest"` (from within the activated venv)

If missing, install:

```bash
uv pip install -r requirements-test.txt
```

Or with pip:

```bash
pip install -r requirements-test.txt
```

### 6. Ruff

Check: `ruff --version` (from within the activated venv)

If missing, install:

```bash
uv pip install ruff
```

Note: `check_code.py` auto-installs ruff when it runs, but you need it locally for the manual auto-fix commands in Step 5.

## Build Pipeline

Run these steps in order from the integrations repo root. Replace `<name>` with the integration folder name (e.g., `clickup`).

### Step 1 — Install integration dependencies

```bash
source .venv/bin/activate
uv pip install -r <name>/requirements.txt
# Or with pip: pip install -r <name>/requirements.txt
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

### Step 5 — Verify `.env.example` for integration-test env vars

If the integration has `test_*_integration.py` files, check whether they reference environment variables via `env_credentials(...)`, `os.environ.get(...)`, `os.getenv(...)`, `os.environ[...]`, or equivalent helpers. Every referenced variable must appear as a blank template entry in the repository root `.env.example`.

This is a manual review/build requirement: `.env` stays local and uncommitted, but `.env.example` is the committed contract that tells humans, reviewers, and automation what to provide. Missing entries should be treated as a validation failure for PRs adding or changing integration tests.

Use a focused cross-check:

```bash
grep -RInE 'env_credentials\(|os\.environ|getenv\(' <name>/tests/test_*_integration.py
grep -nE 'INTEGRATION_PREFIX|SERVICE_PREFIX' .env.example
```

Document required credentials, optional test IDs, and destructive-test-only variables. If an env var read is unused, remove it rather than documenting unnecessary setup.

### Step 6 — Auto-fix lint and formatting issues

If steps 2–5 report ruff errors, auto-fix with:

```bash
ruff check --fix --config ../autohive-integrations-tooling/ruff.toml <name>
ruff format --config ../autohive-integrations-tooling/ruff.toml <name>
```

Then re-run steps 2–5 to confirm.

## Ruff Configuration

CI uses the `ruff.toml` from the tooling repo — always pass `--config ../autohive-integrations-tooling/ruff.toml` to match CI behavior.

Key settings:
- `target-version = "py313"`
- `line-length = 120`
- Rules: `E` (pycodestyle errors), `F` (Pyflakes), `W` (pycodestyle warnings)
- `__init__.py`: `F401` ignored (re-exports)
- `**/tests/context.py`: `F401`, `E402` ignored

## Workflow Summary

1. Install deps → `uv pip install -r <name>/requirements.txt` (or `pip install -r <name>/requirements.txt`)
2. Validate structure → `python ../autohive-integrations-tooling/scripts/validate_integration.py <name>`
3. Check code → `python ../autohive-integrations-tooling/scripts/check_code.py <name>`
4. Run tests → `pytest <name>/ -v`
5. Verify integration-test env vars are listed in root `.env.example` (if applicable)
6. Fix issues → `ruff check --fix ...` / `ruff format ...`
7. Re-run until all pass

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
| Integration tests use env vars but `.env.example` missing entries | Add blank entries for every referenced env var to root `.env.example`; treat as blocking for PRs adding/changing integration tests |
