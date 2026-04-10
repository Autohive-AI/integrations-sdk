# Agents Guidelines — Integrations SDK

## API Documentation

- API docs are generated with `pdoc` and live in `docs/apidocs/`.
- These files are **tracked in version control** — do not add them to `.gitignore`.
- Regenerate whenever the public API surface changes (new/modified classes, functions, or docstrings in `src/autohive_integrations_sdk/`):
  ```
  pdoc -o docs/apidocs src/autohive_integrations_sdk
  ```
- Always commit the regenerated docs alongside the code changes that caused them.

## Testing

- Tests live in `tests/` and use **pytest** with **pytest-asyncio** and **aioresponses**.
- After any code change in `src/autohive_integrations_sdk/`, run the test suite:
  ```
  python -m pytest tests/ -v
  ```
- Run with coverage to check for regressions:
  ```
  python -m pytest tests/ -v --cov=autohive_integrations_sdk --cov-report=term-missing
  ```
- Add or update tests for any new or modified functionality. Aim to maintain ≥95% coverage.
- CI runs automatically on PRs via GitHub Actions (`.github/workflows/tests.yml`).

## Releasing

- Follow the process in [RELEASING.md](RELEASING.md).
- API docs must be regenerated and committed before a release.
