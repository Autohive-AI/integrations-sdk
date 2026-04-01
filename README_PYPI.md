# Integrations SDK for Autohive

[![PyPI version](https://img.shields.io/pypi/v/autohive-integrations-sdk)](https://pypi.org/project/autohive-integrations-sdk/)
[![Python](https://img.shields.io/pypi/pyversions/autohive-integrations-sdk)](https://pypi.org/project/autohive-integrations-sdk/)
[![License: MIT](https://img.shields.io/pypi/l/autohive-integrations-sdk)](https://github.com/Autohive-AI/integrations-sdk/blob/master/LICENSE)

Build integrations for [Autohive](https://autohive.ai)'s AI agent platform. Define actions that Autohive agents can execute — call APIs, process data, and connect to third-party services.

## Installation

```bash
pip install autohive-integrations-sdk
```

## Quick Example

```python
from autohive_integrations_sdk import (
    Integration, ExecutionContext, ActionHandler, ActionResult
)
from typing import Dict, Any

integration = Integration.load()

@integration.action("fetch_data")
class FetchData(ActionHandler):
    async def execute(self, inputs: Dict[str, Any], context: ExecutionContext) -> ActionResult:
        response = await context.fetch(
            "https://api.example.com/data",
            headers={"Authorization": f"Bearer {context.auth['api_key']}"}
        )
        return ActionResult(data=response)
```

## Key Features

- **Action handlers** — async handlers with typed inputs/outputs and built-in HTTP client
- **Authentication** — flexible auth config (API keys, OAuth, custom fields)
- **Billing support** — report per-action costs via `ActionResult.cost_usd`
- **Error handling** — `ActionError` for expected application-level errors
- **Connected accounts** — expose authorized user identity back to the platform
- **Validation** — JSON Schema input/output validation with detailed error reporting

## Documentation

| Guide | Description |
|-------|-------------|
| [Building Your First Integration](https://github.com/Autohive-AI/integrations-sdk/blob/master/docs/manual/building_your_first_integration.md) | End-to-end tutorial covering config, actions, auth, testing |
| [Integration Structure](https://github.com/Autohive-AI/integrations-sdk/blob/master/docs/manual/integration_structure.md) | Directory layout, `config.json` schema reference |
| [Patterns & Best Practices](https://github.com/Autohive-AI/integrations-sdk/blob/master/docs/manual/patterns.md) | Pagination, API helpers, multi-field auth |
| [Starter Template](https://github.com/Autohive-AI/integrations-sdk/tree/master/samples/template) | Copy this to begin a new integration |

## Links

- [GitHub Repository](https://github.com/Autohive-AI/integrations-sdk)
- [Release Notes](https://github.com/Autohive-AI/integrations-sdk/blob/master/RELEASENOTES.md)
- [Public Integrations](https://github.com/Autohive-AI/autohive-integrations) — examples of production integrations built with this SDK
