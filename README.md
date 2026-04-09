# Integrations SDK for Autohive

## Overview

This is the SDK for building integrations into Autohive's AI agent platform.

## Getting Started

Start with the **[Building Your First Integration](docs/manual/building_your_first_integration.md)** tutorial, or copy the **[starter template](samples/template/)** to hit the ground running.

## Documentation

| Guide | Description |
|-------|-------------|
| [Building Your First Integration](docs/manual/building_your_first_integration.md) | End-to-end tutorial covering config, actions, auth, testing |
| [Integration Structure](docs/manual/integration_structure.md) | Directory layout, `config.json` schema reference, naming conventions |
| [Patterns & Best Practices](docs/manual/patterns.md) | Pagination, API helpers, multi-field auth |
| [Billing & Cost Tracking](docs/manual/billing.md) | Reporting per-action costs via `ActionResult.cost_usd` |
| [Connected Accounts](docs/manual/connected_account.md) | Fetching and displaying external account info |
| [API Reference](docs/apidocs/) | Generated API docs (pdoc) |

## Samples

| Sample | Description |
|--------|-------------|
| [`samples/template/`](samples/template/) | Clean starter template — copy this to begin a new integration |
| [`samples/api-fetch/`](samples/api-fetch/) | Working example with unauthenticated, Basic Auth, and Bearer token API calls |

## Testing

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

## Validation & CI

Integration validation is handled by the [autohive-integrations-tooling](https://github.com/Autohive-AI/autohive-integrations-tooling) repo. See its README for CI pipeline setup and the integration checklist.

## Additional Information

- [Release Notes](RELEASENOTES.md)
- SDK source: [`src/autohive_integrations_sdk`](src/autohive_integrations_sdk/)
