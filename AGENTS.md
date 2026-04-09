# Agents Guidelines — Integrations SDK

## API Documentation

- API docs are generated with `pdoc` and live in `docs/apidocs/`.
- These files are **tracked in version control** — do not add them to `.gitignore`.
- Regenerate whenever the public API surface changes (new/modified classes, functions, or docstrings in `src/autohive_integrations_sdk/`):
  ```
  pdoc -o docs/apidocs src/autohive_integrations_sdk
  ```
- Always commit the regenerated docs alongside the code changes that caused them.

## Releasing

- Follow the process in [RELEASING.md](RELEASING.md).
- API docs must be regenerated and committed before a release.
