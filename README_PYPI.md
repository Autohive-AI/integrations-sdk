# Integrations SDK for Autohive

[![Tests](https://github.com/Autohive-AI/integrations-sdk/actions/workflows/tests.yml/badge.svg)](https://github.com/Autohive-AI/integrations-sdk/actions/workflows/tests.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/TheRealAgentK/e8adf35c8508876ab8ba09422ddc2535/raw/coverage-badge.json)](https://github.com/Autohive-AI/integrations-sdk/actions/workflows/tests.yml)
[![PyPI version](https://img.shields.io/pypi/v/autohive-integrations-sdk)](https://pypi.org/project/autohive-integrations-sdk/)
[![Python](https://img.shields.io/pypi/pyversions/autohive-integrations-sdk)](https://pypi.org/project/autohive-integrations-sdk/)
[![License: MIT](https://img.shields.io/pypi/l/autohive-integrations-sdk)](https://github.com/Autohive-AI/integrations-sdk/blob/master/LICENSE)

Build integrations for [Autohive](https://autohive.ai)'s AI agent platform. Define actions that Autohive agents can execute — call APIs, process data, and connect to third-party services.

## Installation

Requires Python 3.13 or later.

```bash
pip install "autohive-integrations-sdk~=2.1.0"
```

The integration examples target released SDK 2.1.0. This compatible-release pin accepts 2.1 patch updates but excludes 2.2 and development SDK 3 releases.

## Quick Example

```python
from pathlib import Path

from autohive_integrations_sdk import (
    Integration, ExecutionContext, ActionHandler, ActionResult
)
from typing import Dict, Any

integration = Integration.load(Path(__file__).with_name("config.json"))

@integration.action("fetch_data")
class FetchData(ActionHandler):
    async def execute(self, inputs: Dict[str, Any], context: ExecutionContext) -> ActionResult:
        response = await context.fetch(
            "https://api.example.com/data",
            headers={"Authorization": f"Bearer {context.auth['credentials']['api_key']}"}
        )
        return ActionResult(data=response.data)
```

Place `config.json` next to the entry point, with a `fetch_data` action and a custom-auth fields schema requiring `api_key`. At runtime, auth uses `{"auth_type": "Custom", "credentials": {"api_key": "..."}}`; the SDK validates the inner credentials object. See the tutorial for the complete configuration and offline tests.

## Key Features

- **Action handlers** — async handlers with typed inputs/outputs and built-in HTTP client
- **Authentication** — flexible auth config (API keys, OAuth, custom fields)
- **Billing support** — report per-action costs via `ActionResult.cost_usd`
- **Error handling** — `ActionError` for expected application-level errors
- **HTTP error headers** — SDK 2.1.0 preserves headers on `HTTPError` and `RateLimitError`; match names case-insensitively and expose only values the caller needs
- **Connected accounts** — expose authorized user identity back to the platform
- **Validation** — JSON Schema input/output validation with detailed error reporting

## Documentation

These maintained guides on `release/2.1.0` target SDK 2.1.0. The SDK implementation and generated API reference on `master` are development 3.x; use the [released 2.1.0 source](https://github.com/Autohive-AI/integrations-sdk/tree/2.1.0/src/autohive_integrations_sdk) for immutable API contracts.

| Guide | Description |
|-------|-------------|
| [Building Your First Integration](https://github.com/Autohive-AI/integrations-sdk/blob/release/2.1.0/docs/manual/building_your_first_integration.md) | End-to-end tutorial covering config, actions, auth, testing |
| [Integration Structure](https://github.com/Autohive-AI/integrations-sdk/blob/release/2.1.0/docs/manual/integration_structure.md) | Directory layout, `config.json` schema reference |
| [Patterns & Best Practices](https://github.com/Autohive-AI/integrations-sdk/blob/release/2.1.0/docs/manual/patterns.md) | Pagination, API helpers, multi-field auth |
| [Starter Template](https://github.com/Autohive-AI/integrations-sdk/tree/release/2.1.0/samples/template) | Copy this to begin a new integration |

## Links

- [GitHub Repository](https://github.com/Autohive-AI/integrations-sdk)
- [SDK 2.1.0 Release Notes](https://github.com/Autohive-AI/integrations-sdk/blob/2.1.0/RELEASENOTES.md)
- [Public Integrations](https://github.com/Autohive-AI/autohive-integrations) — examples of production integrations built with this SDK
