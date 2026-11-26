# Integrations SDK for Autohive

[![Tests](https://github.com/Autohive-AI/integrations-sdk/actions/workflows/tests.yml/badge.svg)](https://github.com/Autohive-AI/integrations-sdk/actions/workflows/tests.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/TheRealAgentK/e8adf35c8508876ab8ba09422ddc2535/raw/coverage-badge.json)](https://github.com/Autohive-AI/integrations-sdk/actions/workflows/tests.yml)
[![PyPI version](https://img.shields.io/pypi/v/autohive-integrations-sdk)](https://pypi.org/project/autohive-integrations-sdk/)
[![Python](https://img.shields.io/pypi/pyversions/autohive-integrations-sdk)](https://pypi.org/project/autohive-integrations-sdk/)
[![License: MIT](https://img.shields.io/pypi/l/autohive-integrations-sdk)](https://github.com/Autohive-AI/integrations-sdk/blob/master/LICENSE)

## Overview

This is the SDK for building integrations into Autohive's AI agent platform.

## Getting Started

Start with the **[Building Your First Integration](docs/manual/building_your_first_integration.md)** tutorial, or copy the **[starter template](samples/template/)** to hit the ground running.

The integration guides, samples, and skills target released **SDK 2.1.0**, using `autohive-integrations-sdk~=2.1.0` (`>=2.1.0, <2.2.0`). They cover `FetchResponse`, the platform auth envelope, and response headers on `HTTPError` and `RateLimitError`.

This branch is based on released SDK 2.1.0. The `master` branch tracks SDK 3.x development; installing that branch with `pip install -e .` does not test an integration against released 2.1.0. Use a separate virtual environment with the released package or `hiveup test` for that check. The generated API reference follows the source on its branch, so use this branch's reference rather than development `master` for SDK 2.1.0.

## Documentation

| Guide | Description |
|-------|-------------|
| [Building Your First Integration](docs/manual/building_your_first_integration.md) | End-to-end tutorial covering config, actions, auth, testing |
| [Integration Structure](docs/manual/integration_structure.md) | Directory layout, `config.json` schema reference, naming conventions |
| [Patterns & Best Practices](docs/manual/patterns.md) | Pagination, API helpers, multi-field auth |
| [Billing & Cost Tracking](docs/manual/billing.md) | Reporting per-action costs via `ActionResult.cost_usd` |
| [Connected Accounts](docs/manual/connected_account.md) | Fetching and displaying external account info |
| [API Reference](docs/apidocs/) | Generated API docs (pdoc) |

For action result types, use the [execution result contract](docs/manual/building_your_first_integration.md#reading-execution-results), including the `ACTION_ERROR` and `VALIDATION_ERROR` clarifications for generated reference prose.

## Samples

| Sample | Description |
|--------|-------------|
| [`samples/template/`](samples/template/) | Clean starter template — copy this to begin a new integration |
| [`samples/api-fetch/`](samples/api-fetch/) | Working example with unauthenticated, Basic Auth, and Bearer token API calls |
| [`samples/action-error-demo/`](samples/action-error-demo/) | Demonstrates `ActionError` for expected application-level errors |

## Testing the SDK

Install test dependencies:
```bash
pip install -e ".[test]"
```

Run tests:
```bash
python -m pytest tests/ -v
```

Run with coverage:
```bash
python -m pytest tests/ -v --cov=autohive_integrations_sdk --cov-report=term-missing
```

CI runs automatically on PRs via GitHub Actions — see [`.github/workflows/tests.yml`](.github/workflows/tests.yml).

### Testing the samples against SDK 2.1.0

In a separate Python 3.13+ virtual environment, from the repository root:

```bash
python -m pip install "autohive-integrations-sdk==2.1.0" pytest pytest-asyncio
for sample in samples/*/; do
    python -m pytest -c "$sample/pytest.ini" "$sample/tests/" -m unit -v || exit 1
done
```

These are offline unit tests, not live provider checks. CI runs them against exactly 2.1.0 separately from the SDK source test suite.

## Validation & CI

Integration validation is handled by [HiveUp in autohive-integrations-tooling](https://github.com/Autohive-AI/autohive-integrations-tooling). Install it using the Tooling README; it is not published to PyPI. From an integrations repository, use `hiveup validate <integration-directory>`, `hiveup test <integration-directory>`, or `hiveup check <check-name> <integration-directory>` for a focused check. For a sample here, pass its path, such as `samples/template`.

## Agent Skills

The [`skills/`](skills/) directory contains agent skills for AI coding assistants (Amp, Claude Code, etc.) that automate common SDK tasks.

| Skill | Description |
|-------|-------------|
| [`building-integration`](skills/building-integration/) | Runs the local build and validation pipeline (structure, lint, format, security, tests) |
| [`upgrading-sdk-v2`](skills/upgrading-sdk-v2/) | Upgrades an integration from SDK 1.x or earlier 2.x to 2.1.0 — covers source code, tests, requirements, and config |
| [`writing-unit-tests`](skills/writing-unit-tests/) | Writes pytest unit tests using mock_context + FetchResponse |
| [`writing-integration-tests`](skills/writing-integration-tests/) | Writes pytest e2e tests that call real APIs using SDK ExecutionContext live fixtures |

To use a skill, copy or symlink it into your workspace's `.agents/skills/` directory or your global `~/.config/agents/skills/` directory. See [`skills/README.md`](skills/README.md) for setup instructions.

## Additional Information

- [Release Notes](RELEASENOTES.md)
- SDK source: [`src/autohive_integrations_sdk`](src/autohive_integrations_sdk/)
