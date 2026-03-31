# Integrations SDK for Autohive

## Overview

This is the SDK for building integrations into Autohive's AI agent platform.

## Getting Started

Start with the **[Building Your First Integration](https://github.com/Autohive-AI/integrations-sdk/blob/master/docs/manual/building_your_first_integration.md)** tutorial, or copy the **[starter template](https://github.com/Autohive-AI/integrations-sdk/tree/master/samples/template)** to hit the ground running.

## Documentation

| Guide | Description |
|-------|-------------|
| [Building Your First Integration](https://github.com/Autohive-AI/integrations-sdk/blob/master/docs/manual/building_your_first_integration.md) | End-to-end tutorial covering config, actions, auth, testing |
| [Integration Structure](https://github.com/Autohive-AI/integrations-sdk/blob/master/docs/manual/integration_structure.md) | Directory layout, `config.json` schema reference, naming conventions |
| [Patterns & Best Practices](https://github.com/Autohive-AI/integrations-sdk/blob/master/docs/manual/patterns.md) | Pagination, API helpers, multi-field auth |
| [Billing & Cost Tracking](https://github.com/Autohive-AI/integrations-sdk/blob/master/docs/manual/billing.md) | Reporting per-action costs via `ActionResult.cost_usd` |
| [Connected Accounts](https://github.com/Autohive-AI/integrations-sdk/blob/master/docs/manual/connected_account.md) | Fetching and displaying external account info |
| [API Reference](https://github.com/Autohive-AI/integrations-sdk/tree/master/docs/apidocs) | Generated API docs (pdoc) |

## Samples

| Sample | Description |
|--------|-------------|
| [samples/template](https://github.com/Autohive-AI/integrations-sdk/tree/master/samples/template) | Clean starter template — copy this to begin a new integration |
| [samples/api-fetch](https://github.com/Autohive-AI/integrations-sdk/tree/master/samples/api-fetch) | Working example with unauthenticated, Basic Auth, and Bearer token API calls |

## Validation & CI

Integration validation is handled by the [autohive-integrations-tooling](https://github.com/Autohive-AI/autohive-integrations-tooling) repo. See its README for CI pipeline setup and the integration checklist.

## Additional Information

- [Release Notes](https://github.com/Autohive-AI/integrations-sdk/blob/master/RELEASENOTES.md)
- [SDK source](https://github.com/Autohive-AI/integrations-sdk/tree/master/src/autohive_integrations_sdk)
- [GitHub Repository](https://github.com/Autohive-AI/integrations-sdk)
