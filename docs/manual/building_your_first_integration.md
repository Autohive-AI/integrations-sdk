# Building Your First Integration

This guide walks you through building an Autohive integration from scratch. By the end, you'll have a working integration with configuration, action handlers, and tests.

## Prerequisites

- **Python 3.13+** — the SDK enforces this version
- **pip** or [uv](https://docs.astral.sh/uv/) for package management
- A code editor

## Integration Structure

Every Autohive integration lives in its own directory and follows this structure:

```
my-integration/
├── config.json              # Integration metadata and action definitions
├── my_integration.py        # Main implementation (entry point)
├── __init__.py              # Package init — only import and __all__
├── requirements.txt         # Dependencies (must include autohive-integrations-sdk)
├── README.md                # Documentation
├── icon.png or icon.svg     # Integration icon (512×512 pixels)
└── tests/
    ├── __init__.py           # Can be empty
    ├── context.py            # Import setup
    └── test_my_integration.py
```

### Naming Conventions

- **Directory name**: lowercase with hyphens (`my-integration`, `google-sheets`)
- **Python module**: lowercase with underscores (`my_integration.py`)
- **Action names**: snake_case (`list_items`, `create_record`)

## Step 1: Create Your Directory

```bash
mkdir my-integration
cd my-integration
```

## Step 2: Set Up Dependencies

Create a `requirements.txt`:

```
autohive-integrations-sdk~=1.0.2
```

The `~=` (compatible release) operator means `>=1.0.2, <1.1.0` — you'll get patch updates with bug fixes, but won't be surprised by minor version changes that could alter SDK behaviour.

Add any additional libraries your integration needs beyond the SDK (e.g., `feedparser` for RSS parsing, `stripe` for the Stripe client library).

Install your dependencies:

```bash
pip install -r requirements.txt
```

## Step 3: Define Your Configuration

Create `config.json`. This file defines your integration's metadata, authentication, and actions.

### Minimal Example (No Auth)

For public APIs that don't require authentication:

```json
{
    "name": "my-integration",
    "version": "1.0.0",
    "description": "Fetches data from the Example API",
    "entry_point": "my_integration.py",
    "actions": {
        "get_items": {
            "display_name": "Get Items",
            "description": "Retrieves a list of items from the Example API",
            "input_schema": {
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of items to return (1-100)",
                        "default": 10,
                        "minimum": 1,
                        "maximum": 100
                    }
                },
                "required": []
            },
            "output_schema": {
                "type": "object",
                "properties": {
                    "items": {
                        "type": "array",
                        "description": "List of items"
                    },
                    "count": {
                        "type": "integer",
                        "description": "Number of items returned"
                    },
                    "result": {
                        "type": "boolean",
                        "description": "Whether the operation succeeded"
                    },
                    "error": {
                        "type": "string",
                        "description": "Error message if result is false"
                    }
                }
            }
        }
    }
}
```

### Required Top-Level Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Integration name |
| `version` | string | Semantic version (`MAJOR.MINOR.PATCH`) |
| `description` | string | What the integration does |
| `entry_point` | string | Main Python file name (must end in `.py`) |
| `actions` | object | At least one action definition |

### Optional Top-Level Fields

| Field | Type | Description |
|-------|------|-------------|
| `display_name` | string | Human-readable name for the UI (recommended) |
| `auth` | object | Authentication configuration (see [Authentication](#authentication)) |
| `supports_billing` | boolean | Enable cost tracking via `ActionResult.cost_usd` (see [billing docs](billing.md)) |
| `supports_connected_account` | boolean | Enable connected account display (see [connected account docs](connected_account.md)) |

### Action Definitions

Each action in the `actions` object must have:

| Field | Required | Description |
|-------|----------|-------------|
| `description` | Yes | What the action does |
| `input_schema` | Yes | JSON Schema defining accepted inputs |
| `output_schema` | Yes | JSON Schema defining the response structure |
| `display_name` | Recommended | Human-readable action name for the UI |

The `input_schema` and `output_schema` must be valid [JSON Schema](https://json-schema.org/). The SDK validates inputs and outputs against these schemas at runtime.

## Authentication

### Custom Auth (API Key / Token)

For integrations where users provide their own credentials. Use `title` to label the auth section in the UI:

```json
"auth": {
    "type": "custom",
    "title": "API Token Authentication",
    "fields": {
        "type": "object",
        "properties": {
            "api_token": {
                "type": "string",
                "format": "password",
                "label": "API Token",
                "help_text": "Find your API token at https://example.com/settings"
            }
        },
        "required": ["api_token"]
    }
}
```

The `fields` value must be valid JSON Schema. The `format`, `label`, and `help_text` properties are used to render the authentication UI in Autohive.

At runtime, credentials are nested under `context.auth["credentials"]`. For custom auth, access fields like: `context.auth.get("credentials", {}).get("api_token")`.

### Platform Auth (OAuth2)

For integrations using Autohive's built-in OAuth2 providers:

```json
"auth": {
    "type": "platform",
    "provider": "github",
    "scopes": ["repo", "read:user"]
}
```

With platform auth, the SDK automatically injects the `Authorization` header into requests made via `context.fetch()`. You generally don't need to handle tokens yourself.

### No Auth

For public APIs, omit the `auth` field entirely.

## Step 4: Write Your Integration Code

Create `my_integration.py`:

```python
from autohive_integrations_sdk import (
    Integration, ExecutionContext, ActionHandler, ActionResult
)
from typing import Dict, Any

# Load integration configuration
my_integration = Integration.load()

BASE_URL = "https://api.example.com/v1"


@my_integration.action("get_items")
class GetItemsAction(ActionHandler):
    """Retrieves items from the Example API."""

    async def execute(self, inputs: Dict[str, Any], context: ExecutionContext) -> ActionResult:
        limit = inputs.get("limit", 10)

        try:
            response = await context.fetch(
                f"{BASE_URL}/items",
                method="GET",
                params={"limit": limit}
            )

            items = response.get("data", [])

            return ActionResult(
                data={
                    "items": items,
                    "count": len(items),
                    "result": True,
                },
                cost_usd=0.0
            )
        except Exception as e:
            return ActionResult(
                data={
                    "items": [],
                    "count": 0,
                    "result": False,
                    "error": str(e),
                },
                cost_usd=0.0
            )
```

### Key Concepts

**`Integration.load()`** — Loads your `config.json` and creates the integration instance. Call this at module level.

**`@integration.action("action_name")`** — Decorator that registers a handler class for the named action. The name must match a key in your `config.json` `actions` object.

**`ActionHandler`** — Base class for all action handlers. You must implement the `async def execute()` method.

**`ExecutionContext`** — Provided to every handler. Gives you:
- `context.fetch(url, ...)` — Make HTTP requests with automatic auth handling
- `context.auth` — Access authentication credentials

**`ActionResult`** — The required return type for all action handlers. Contains:
- `data` — Your response data (validated against `output_schema`)
- `cost_usd` — Optional cost in USD for billing tracking (see [billing docs](billing.md))

### Making HTTP Requests

Use `context.fetch()` for all HTTP calls. It handles authentication headers, retries, timeouts, and response parsing automatically.

```python
# GET with query parameters
response = await context.fetch(
    f"{BASE_URL}/items",
    method="GET",
    params={"limit": 10, "status": "active"}
)

# POST with JSON body
response = await context.fetch(
    f"{BASE_URL}/items",
    method="POST",
    headers={"Content-Type": "application/json"},
    json={"name": "New Item", "status": "active"}
)

# POST with form-encoded body
response = await context.fetch(
    f"{BASE_URL}/items",
    method="POST",
    headers={"Content-Type": "application/x-www-form-urlencoded"},
    data={"name": "New Item"}
)
```

### Handling Inputs

Use `inputs.get()` with a default for optional fields. Use `inputs["key"]` for required fields (the SDK validates required fields against your `input_schema` before calling your handler).

```python
# Optional field — safe access with default
limit = inputs.get("limit", 10)

# Required field — safe because the SDK validates required fields first
customer_id = inputs["customer_id"]

# Optional field — check before using
email = inputs.get("email")
if email:
    body["email"] = email
```

### Returning Errors from Actions

Action handlers normally return an `ActionResult` whose `data` is validated against the action's `output_schema`. When your action encounters an expected error condition (e.g. a resource not found, an API quota exceeded), you can return an `ActionError` instead. This bypasses output schema validation and returns the error message to the caller:

```python
from autohive_integrations_sdk import ActionError, HTTPError

@my_integration.action("my_action_handler")
class MyActionHandler(ActionHandler):
    async def execute(self, inputs: Dict[str, Any], context: ExecutionContext):
        try:
            response = await context.fetch(url)
        except HTTPError as e:
            return ActionError(
                message=f"API call failed: {e.message}",
                cost_usd=0.01  # API call was made, cost was still incurred
            )

        return ActionResult(data=response)
```

Use `ActionError` for expected, application-level failures. For unexpected infrastructure errors, let exceptions propagate normally.

### Handler Class Naming

Use `PascalCase` with an `Action` suffix:

```python
@integration.action("list_customers")
class ListCustomersAction(ActionHandler):
    ...

@integration.action("create_invoice")
class CreateInvoiceAction(ActionHandler):
    ...
```

## Step 5: Add Package Files

### `__init__.py`

Can be empty, or contain a minimal import and export:

```python
# Option 1: empty file (sufficient)

# Option 2: import and export
from .my_integration import my_integration

__all__ = ["my_integration"]
```

Do not add any logic, logging, or additional code to this file.

### `icon.png` or `icon.svg`

Add a 512×512 pixel icon for your integration.

### `README.md`

Document your integration: what it does, how to authenticate, what each action accepts and returns. See the `samples/` directory for a reference README.

## Step 6: Write Tests

### `tests/__init__.py`

Can be empty.

### `tests/context.py`

Sets up the import path so tests can find your integration:

```python
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from my_integration import my_integration  # noqa: F401
```

### `tests/test_my_integration.py`

```python
import asyncio
from context import my_integration
from autohive_integrations_sdk import ExecutionContext


async def test_get_items():
    """Test fetching items."""
    inputs = {"limit": 5}

    async with ExecutionContext(auth={}) as context:
        result = await my_integration.execute_action("get_items", inputs, context)

        # execute_action returns an IntegrationResult
        # result.result contains the ActionResult
        # result.result.data contains your response data
        data = result.result.data
        assert "items" in data
        assert "count" in data
        assert data["result"] is True
        print(f"Got {data['count']} items")


if __name__ == "__main__":
    asyncio.run(test_get_items())
```

For integrations that require authentication, pass credentials matching your `auth.fields` schema:

```python
auth = {
    "api_token": "your-test-token"
}
async with ExecutionContext(auth=auth) as context:
    result = await my_integration.execute_action("get_items", inputs, context)
```

> **Note:** In production, the platform wraps credentials as `{"auth_type": "...", "credentials": {"api_token": "..."}}`. That's why production action handlers access `context.auth.get("credentials", {}).get("api_token")`. When testing locally with `execute_action`, the SDK validates `context.auth` directly against your `auth.fields` schema, so pass credentials flat.

For **platform OAuth** integrations (where `context.fetch()` auto-injects the Bearer token), pass the full wrapped structure in tests:

```python
auth = {
    "auth_type": "PlatformOauth2",
    "credentials": {"access_token": "your-test-token"}
}
async with ExecutionContext(auth=auth) as context:
    result = await my_integration.execute_action("list_repos", inputs, context)
```

## Multi-File Integrations

For integrations with many actions, split handlers into an `actions/` directory:

```
my-integration/
├── config.json
├── my_integration.py         # Loads integration, imports action modules
├── helpers.py                # Shared utilities
├── requirements.txt
├── README.md
├── icon.png
├── actions/
│   ├── __init__.py
│   ├── items.py              # Item-related actions
│   └── users.py              # User-related actions
└── tests/
    ├── __init__.py
    ├── context.py
    └── test_my_integration.py
```

**Main entry point (`my_integration.py`):**

```python
from autohive_integrations_sdk import Integration

# Explicit path is required for multi-file integrations so that
# config.json is found regardless of which submodule triggers the load
import os
config_path = os.path.join(os.path.dirname(__file__), "config.json")
my_integration = Integration.load(config_path)

# Import action modules to register their handlers
import actions
```

**Action module (`actions/items.py`):**

```python
from my_integration import my_integration
from helpers import get_headers
from autohive_integrations_sdk import ActionHandler, ActionResult, ExecutionContext
from typing import Dict, Any

@my_integration.action("list_items")
class ListItemsAction(ActionHandler):
    async def execute(self, inputs: Dict[str, Any], context: ExecutionContext) -> ActionResult:
        ...
```

When using this modular pattern, the root `__init__.py` is optional.

## Validation

Before submitting, validate your integration using the [autohive-integrations-tooling](https://github.com/autohive-ai/autohive-integrations-tooling):

```bash
# Validate structure and config
python scripts/validate_integration.py my-integration

# Run all code quality checks
python scripts/check_code.py my-integration
```

See the tooling repo's documentation for setup instructions and the full list of checks.

## Next Steps

- [Billing and cost tracking](billing.md) — report per-action costs via `ActionResult.cost_usd`
- [Connected account information](connected_account.md) — display which account authorized the integration
- [autohive-integrations-tooling](https://github.com/autohive-ai/autohive-integrations-tooling) — CI/CD validation, checklist, and script reference
