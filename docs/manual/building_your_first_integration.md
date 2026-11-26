# Building Your First Integration

This guide walks you through building an Autohive integration from scratch. By the end, you'll have a working integration with configuration, action handlers, and tests.

The examples target released **SDK 2.1.0**. Use an integration environment with `autohive-integrations-sdk~=2.1.0`, not an editable SDK 3.x checkout from `master`.

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
├── __init__.py              # Empty file; no re-exports
├── requirements.txt         # Dependencies (must include autohive-integrations-sdk)
├── README.md                # Documentation
├── icon.png                 # PNG or JPEG icon (512×512 pixels)
├── pytest.ini               # Standalone only; omit in an integrations monorepo
└── tests/
    ├── __init__.py           # Can be empty
    ├── conftest.py           # Import setup and offline context fixture
    └── test_my_integration_unit.py
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
autohive-integrations-sdk~=2.1.0
```

The `~=` (compatible release) operator means `>=2.1.0, <2.2.0`: you get SDK 2.1 patch updates, but not later minor or major versions.

Add any additional libraries your integration needs beyond the SDK (e.g., `feedparser` for RSS parsing, `stripe` for the Stripe client library).

Create and activate a virtual environment, then install your dependencies:

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install -r requirements.txt
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
                        "items": {"type": "object"},
                        "description": "List of items"
                    },
                    "count": {
                        "type": "integer",
                        "description": "Number of items returned"
                    }
                },
                "required": ["items", "count"]
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

At runtime, credentials are nested under `context.auth["credentials"]`. For custom auth, access fields like `context.auth["credentials"].get("api_token")`. The `auth.fields` schema validates this inner credentials object, not the whole envelope. Keep `required` for credentials the handler needs.

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
from pathlib import Path

from autohive_integrations_sdk import (
    Integration, ExecutionContext, ActionHandler, ActionResult
)
from typing import Dict, Any

# Use an explicit path with either an installed or vendored SDK.
my_integration = Integration.load(Path(__file__).with_name("config.json"))

BASE_URL = "https://api.example.com/v1"


@my_integration.action("get_items")
class GetItemsAction(ActionHandler):
    """Retrieves items from the Example API."""

    async def execute(self, inputs: Dict[str, Any], context: ExecutionContext) -> ActionResult:
        limit = inputs.get("limit", 10)

        response = await context.fetch(
            f"{BASE_URL}/items",
            method="GET",
            params={"limit": limit}
        )
        items = response.data.get("data", [])

        return ActionResult(data={"items": items, "count": len(items)})
```

### Key Concepts

**`Integration.load(config_path)`** — Loads your `config.json` and creates the integration instance. Call this at module level with a path relative to the entry point, not the working directory. Without an explicit path, the SDK infers the configuration location from its own installation path; that layout is intended for vendored deployment dependencies, not a normal virtual-environment install.

**`@integration.action("action_name")`** — Decorator that registers a handler class for the named action. The name must match a key in your `config.json` `actions` object.

**`ActionHandler`** — Base class for all action handlers. You must implement the `async def execute()` method.

**`ExecutionContext`** — Provided to every handler. Gives you:
- `context.fetch(url, ...)` — Make HTTP requests with automatic auth handling; returns a `FetchResponse` with `.status`, `.headers`, and `.data` attributes
- `context.auth` — Access authentication credentials

**`ActionResult`** — The successful return type for action handlers. Use `ActionError` for expected application errors. `ActionResult` contains:
- `data` — Your response data (validated against `output_schema`)
- `cost_usd` — Optional cost in USD for billing tracking (see [billing docs](billing.md))

### Reading execution results

`execute_action()` wraps the handler's return value in an `IntegrationResult`. Check its `type` before reading the payload:

| Result type | Payload |
|-------------|---------|
| `ResultType.ACTION` | `result.result.data` and optional `result.result.cost_usd` |
| `ResultType.ACTION_ERROR` | `result.result.message` and optional `result.result.cost_usd` |
| `ResultType.VALIDATION_ERROR` | A dictionary at `result.result`, including `source` (`input`, `auth`, or `output`) and the validation message |

Return an `ActionError` rather than raising it. It bypasses the success output schema. Unexpected exceptions still propagate. Some generated API descriptions use `ERROR` for application errors or omit the validation-error dictionary; use the result types above for `execute_action()`.

### Making HTTP Requests

Use `context.fetch()` for HTTP calls. It handles platform OAuth headers, retries, timeouts, and response parsing. Custom auth headers remain the handler's responsibility. It returns a `FetchResponse` object — access the parsed body via `.data`, the HTTP status via `.status`, and response headers via `.headers`.

In SDK 2.1.0, set a custom `User-Agent` through `headers`:

```python
response = await context.fetch(
    f"{BASE_URL}/items",
    headers={"User-Agent": "MyIntegration/1.0"}
)
```

SDK 2.1.0 has no `user_agent` convenience argument or SDK-specific default User-Agent. Use the explicit header form above.

**Development SDK 3.x only:** When no `User-Agent` header is provided, the development SDK sends a versioned default using the SDK version and, when the request is made from a registered integration handler, the integration `name` and `version` from `config.json`:

```text
AutohiveIntegrationsSDK/<sdk-version> <integration-name>/<integration-version>
```

The development SDK also accepts a `user_agent` convenience argument:

```python
response = await context.fetch(
    f"{BASE_URL}/items",
    user_agent="MyIntegration/1.0"
)
```

Existing `headers={"User-Agent": "..."}` usage is also supported and takes precedence over `user_agent` when both are provided. Do not use the convenience argument with released SDK 2.1.0. The request examples below use arguments supported by both versions.

```python
# GET with query parameters
response = await context.fetch(
    f"{BASE_URL}/items",
    method="GET",
    params={"limit": 10, "status": "active"}
)
items = response.data  # parsed response body

# POST with JSON body
response = await context.fetch(
    f"{BASE_URL}/items",
    method="POST",
    headers={"Content-Type": "application/json"},
    json={"name": "New Item", "status": "active"}
)
new_item = response.data

# POST with form-encoded body
response = await context.fetch(
    f"{BASE_URL}/items",
    method="POST",
    content_type="application/x-www-form-urlencoded",
    data={"name": "New Item"}
)
result = response.data
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
    async def execute(self, inputs: Dict[str, Any], context: ExecutionContext) -> ActionResult | ActionError:
        try:
            response = await context.fetch(url)
        except HTTPError as exc:
            if exc.status != 404:
                raise
            return ActionError(
                message="The requested resource was not found.",
                cost_usd=0.01  # API call was made, cost was still incurred
            )

        return ActionResult(data=response.data)
```

Use `ActionError` for expected, application-level failures. For unexpected infrastructure errors, let exceptions propagate normally.

SDK 2.1.0 also preserves response headers on `HTTPError` and `RateLimitError`. Read only the values your caller needs, matching header names case-insensitively. See [HTTP error headers](patterns.md#http-error-headers-sdk-210) for an example that handles a provider's duplicate-record override without exposing all headers.

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

Create an empty root `__init__.py`. Do not re-export `my_integration` from this file: pytest can import it without a package context in the hyphenated `my-integration/` directory, causing relative imports to fail.

### Integration icon

Add a 512×512 pixel `icon.png`, `icon.jpg`, or `icon.jpeg`. HiveUp does not accept SVG icons.

### `README.md`

Document your integration: what it does, how to authenticate, what each action accepts and returns. See the `samples/` directory for a reference README.

## Step 6: Write Tests

### `tests/__init__.py`

Can be empty.

### `pytest.ini` (standalone only)

For a standalone integration, create this configuration to keep offline tests discoverable by both pytest and HiveUp. In an integrations monorepo, omit this file and inherit the repository-root pytest configuration instead. A local `pytest.ini` prevents discovery of shared root fixtures such as `env_credentials` and `make_context`.

```ini
[pytest]
python_files = test_*_unit.py
asyncio_mode = auto
markers =
    unit: Offline unit tests
```

### `tests/conftest.py`

Set up imports and mock HTTP calls. The tutorial's configuration has no auth, so this fixture uses `auth={}`:

```python
import sys
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from autohive_integrations_sdk import ExecutionContext

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture
def mock_context():
    context = ExecutionContext(auth={})
    context.fetch = AsyncMock()
    return context
```

### `tests/test_my_integration_unit.py`

```python
import pytest
from autohive_integrations_sdk import FetchResponse, ResultType
from my_integration import my_integration

pytestmark = [pytest.mark.unit, pytest.mark.asyncio]


async def test_get_items(mock_context):
    mock_context.fetch.return_value = FetchResponse(
        status=200, headers={}, data={"data": [{"id": "item-7"}]}
    )

    result = await my_integration.execute_action("get_items", {"limit": 5}, mock_context)

    # Validation errors are also IntegrationResult values, not raised exceptions.
    assert result.type == ResultType.ACTION
    assert result.result.data == {"items": [{"id": "item-7"}], "count": 1}
```

From your integration directory, run the tests without contacting a provider:

```bash
python -m pip install pytest pytest-asyncio
python -m pytest tests/ -m unit -v
```

For integrations that require authentication, pass the wrapped auth envelope. The `credentials` object must match your `auth.fields` schema, and `auth_type` must be present:

```python
auth = {
    "auth_type": "Custom",
    "credentials": {"api_token": "your-test-token"}
}
async with ExecutionContext(auth=auth) as context:
    result = await my_integration.execute_action("get_items", inputs, context)
```

> **Note:** When `auth.fields` is configured, the SDK requires the wrapped envelope and validates its inner `credentials` object. Flat auth or missing required credentials produce a `source="auth"` validation error before the handler runs. Handlers read credentials via `context.auth["credentials"]`; local wrapper tests must supply the same shape. Configurations without `auth.fields`, including the no-auth tutorial above, skip this schema check.

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
├── pytest.ini               # Standalone only; omit in an integrations monorepo
└── tests/
    ├── __init__.py
    ├── conftest.py
    └── test_my_integration_unit.py
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

Install HiveUp using the [Tooling installation instructions](https://github.com/Autohive-AI/autohive-integrations-tooling#install-hiveup-from-a-local-build). HiveUp is not published to PyPI. From the parent of your integration directory:

```bash
# Run validation, code-quality checks, and unit tests
hiveup validate my-integration

# Run unit tests or a focused config/code synchronization check
hiveup test my-integration
hiveup check sync my-integration
```

HiveUp creates isolated environments from each integration's `requirements.txt`; it does not use an editable SDK checkout. Unit tests must be named `tests/test_*_unit.py` and marked `unit`. Add live provider tests separately as `test_*_integration.py` and run them explicitly with test credentials.

## Next Steps

- [Billing and cost tracking](billing.md) — report per-action costs via `ActionResult.cost_usd`
- [Connected account information](connected_account.md) — display which account authorized the integration
- [autohive-integrations-tooling](https://github.com/autohive-ai/autohive-integrations-tooling) — HiveUp commands, CI validation, and the integration checklist
