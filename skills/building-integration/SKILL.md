---
name: building-integration
description: "Runs the local build and validation pipeline for an Autohive integration — structure validation, code quality checks, linting, formatting, security scanning, and unit tests. Use when asked to build, validate, check, or verify an integration before pushing."
---

# Build and validate an integration locally

Use the installed Python HiveUp CLI, not the legacy .NET CLI or Tooling scripts. For new integrations and explicit SDK upgrades, recommend `autohive-integrations-sdk~=2.1.0`. Keep existing dependency pins and runtime behavior unchanged during a pure private-to-public migration.

## Prerequisites

- Install HiveUp with Python 3.13+ using the [local-build installation instructions](https://github.com/Autohive-AI/autohive-integrations-tooling#install-hiveup-from-a-local-build). HiveUp is **not published to PyPI**; do not use `pip install hiveup` or `uv tool install hiveup` as an index install.
- Verify the installed command with `hiveup --version`.
- Read the integration repository's guidance and testing configuration.
- For PR checks, identify the actual PR base ref and make sure it resolves locally. Do not assume `main` or `master`.

HiveUp installs integration dependencies in isolated environments from each integration's `requirements.txt`. You do not need to install all integrations into one shared virtual environment. A Tooling checkout is needed to build HiveUp, not to invoke its installed validation commands.

## Validation workflow

Run these commands from the integrations repository root. Replace `<name>` with the integration directory, such as `clickup`, and `<base-ref>` with the fetched PR base ref, such as `origin/main` if that is the PR target.

### 1. Check structure

```bash
hiveup check structure --base-ref <base-ref> <name>
```

This checks required files, schemas, auth configuration, SDK pinning, test structure, and the 512×512 PNG/JPG/JPEG icon. SDK lower bounds below 2.1.0 warn without rewriting the pin or failing solely for that advisory. A missing canonical `test_*_unit.py` warns for an existing integration but fails for a new one when the base ref is supplied.

### 2. Run the full profile

```bash
hiveup validate --base-ref <base-ref> <name>
```

The available checks are `structure`, `syntax`, `imports`, `json`, `lint`, `format`, `security`, `audit`, `sync`, `fetch`, `tests`, `readme`, and `version`. The default runs all of them, including unit tests. `readme` and `version` skip without a base ref; config/input drift fails for new integrations with a base ref but warns for existing ones. Action mismatches fail in either case.

To validate all changed integrations instead of naming them:

```bash
hiveup validate --changed --base-ref <base-ref>
```

`hiveup ci --base-ref <base-ref>` selects changed integrations and runs the same checks grouped for CI. Neither command runs live integration tests.

### 3. Iterate with focused checks

```bash
hiveup test <name>
hiveup check sync --base-ref <base-ref> <name>
hiveup check fetch <name>
```

`hiveup test` runs `tests/test_*_unit.py` with isolated dependencies and coverage. It warns and skips integrations without canonical unit-test files; a successful exit is not proof that tests ran. Inspect the test counts.

### 4. Verify `.env.example` for integration-test env vars

If the integration has `test_*_integration.py` files, check whether they reference environment variables via `env_credentials(...)`, `os.environ.get(...)`, `os.getenv(...)`, `os.environ[...]`, or equivalent helpers. Every referenced variable must appear as a blank template entry in the repository root `.env.example`.

This is a manual review/build requirement: `.env` stays local and uncommitted, but `.env.example` is the committed contract that tells humans, reviewers, and automation what to provide. Missing entries should be treated as a validation failure for PRs adding or changing integration tests.

Search the live test files for `env_credentials(...)`, `os.environ`, `os.getenv(...)`, and equivalent helpers, then compare the variables with root `.env.example`.

Document required credentials, optional test IDs, and destructive-test-only variables. If an env var read is unused, remove it rather than documenting unnecessary setup.

### 5. Fix lint and formatting, then revalidate

```bash
hiveup validate --only lint,format --fix <name>
hiveup validate --base-ref <base-ref> <name>
```

HiveUp uses its bundled Ruff configuration, including Python 3.13 and a 120-character line length. For standalone Ruff, pass `--config ../autohive-integrations-tooling/ruff.toml` to both `ruff check` and `ruff format` when the Tooling checkout is a sibling.

For local work without a PR base, omit `--base-ref`; report that history-aware checks were skipped. Do not invent a base ref just to suppress a processing error.

## Interpret results

HiveUp exits `0` for passed, warning, or skipped results; `1` for check failures; and `2` for processing errors. Inspect warnings and skipped results even when the exit code is zero. Use `hiveup validate --json <name>` for structured output. Fix failures or document intentional exceptions, then rerun the full profile.

## Common failures and fixes

| Failure | Fix |
|---|---|
| Ruff lint errors | `hiveup check lint --fix <name>` |
| Ruff format errors | `hiveup check format --fix <name>` |
| Bandit security issue | Add `# nosec B105` for test credential strings; fix real issues |
| Config-code sync | Ensure actions in `config.json` match handlers in source code |
| Missing test files | Create `tests/test_<name>_unit.py` using the [unit-test reference](../writing-tests/unit-tests.md); preserve scope for pure migrations |
| Import errors | Check `requirements.txt` has all dependencies; keep the root `__init__.py` empty |
| Integration tests use env vars but `.env.example` missing entries | Add blank entries for every referenced env var to root `.env.example`; treat as blocking for PRs adding/changing integration tests |
