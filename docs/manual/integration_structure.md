# Integration Structure Reference

> This is the canonical reference for Autohive integration file structure and `config.json` schema. For a step-by-step tutorial, see [Building Your First Integration](building_your_first_integration.md).

## Directory Layout

### Single-File Integration

Most integrations use this structure:

```
my-integration/
├── config.json
├── my_integration.py          # entry_point
├── __init__.py
├── requirements.txt
├── README.md
├── icon.png or icon.svg
└── tests/
    ├── __init__.py
    ├── context.py
    └── test_my_integration.py
```

### Modular Integration (with `actions/`)

Large integrations can split action handlers into an `actions/` subdirectory:

```
my-integration/
├── config.json
├── my_integration.py          # entry_point — creates Integration instance
├── helpers.py                 # shared utilities (optional)
├── requirements.txt
├── README.md
├── icon.png or icon.svg
├── actions/
│   ├── __init__.py            # imports sub-modules to register handlers
│   ├── items.py
│   └── users.py
└── tests/
    ├── __init__.py
    ├── context.py
    └── test_my_integration.py
```

In this pattern:
- The entry point creates the `Integration` instance and imports `actions` to trigger handler registration
- `actions/__init__.py` imports the sub-modules (e.g., `from . import items, users`)
- Each action sub-module imports the integration instance using an absolute import (e.g., `from my_integration import my_integration`) and registers handlers with the `@integration.action()` decorator
- `__init__.py` in the root directory is optional — adding it can cause circular imports when action files use absolute imports
- `Integration.load()` must be called with an explicit config path:
  ```python
  import os
  config_path = os.path.join(os.path.dirname(__file__), "config.json")
  my_integration = Integration.load(config_path)
  ```

## Required Files

| File | Description |
|------|-------------|
| `config.json` | Integration metadata, auth, and action definitions |
| Entry point (`.py`) | Main Python file referenced by `entry_point` in config |
| `requirements.txt` | Must include `autohive-integrations-sdk` with `~=` pin |
| `README.md` | Integration documentation |
| `icon.png` or `icon.svg` | Integration icon, must be 512×512 pixels |
| `tests/` | Test directory |

### `__init__.py`

- Required for single-file integrations (warning if missing)
- Optional for modular integrations with an `actions/` subdirectory
- Can be empty, or contain a minimal import and `__all__`

### `requirements.txt`

Must include the SDK with a compatible release pin:

```
autohive-integrations-sdk~=1.0.2
```

The `~=` operator means `>=1.0.2, <1.1.0` — you get patch updates but not minor version changes.

Add any additional libraries your integration needs (e.g., `feedparser`, `stripe`).

## Naming Conventions

| What | Convention | Example |
|------|-----------|---------|
| Directory name | lowercase, hyphens | `my-integration`, `google-sheets` |
| Python module | lowercase, underscores | `my_integration.py`, `google_sheets.py` |
| Action names | snake_case | `list_items`, `create_record` |
| `config.json` `name` | lowercase, hyphens | `my-integration` |

## `config.json` Schema

### Top-Level Fields

#### Required

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Integration identifier (lowercase) |
| `version` | string | Semantic version (`MAJOR.MINOR.PATCH`, e.g., `"1.0.0"`) |
| `description` | string | What the integration does |
| `entry_point` | string | Main Python file name (e.g., `"my_integration.py"`) |
| `actions` | object | Action definitions (at least one required) |

#### Optional

| Field | Type | Description |
|-------|------|-------------|
| `display_name` | string | Human-readable name for the UI (recommended) |
| `auth` | object | Authentication configuration (omit for public APIs) |
| `supports_billing` | boolean | Enable cost tracking via `ActionResult.cost_usd` (see [billing docs](billing.md)) |
| `supports_connected_account` | boolean | Enable connected account display (see [connected account docs](connected_account.md)) |

### Auth Configuration

#### Custom Auth (API Key / Token)

For integrations where users provide their own credentials:

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

Required fields:
- `type`: must be `"custom"`
- `fields`: JSON Schema object with `properties`

The `title` field labels the auth section in the UI.

Each property in `fields.properties` supports:

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Data type (typically `"string"`) |
| `format` | string | UI hint (e.g., `"password"` to mask input) |
| `label` | string | Display label in the auth form |
| `help_text` | string | Help text shown below the field |
| `default` | any | Default value |

At runtime, credentials are nested under `context.auth["credentials"]`: `context.auth.get("credentials", {}).get("api_token")`.

#### Platform Auth (OAuth2)

For integrations using Autohive's built-in OAuth2 providers:

```json
"auth": {
    "type": "platform",
    "provider": "github",
    "scopes": ["repo", "read:user"]
}
```

Required fields:
- `type`: must be `"platform"`
- `provider`: OAuth provider name

Optional fields:
- `scopes`: array of OAuth scopes to request

With platform auth, `context.fetch()` automatically injects the `Authorization` header.

#### No Auth

For public APIs, omit the `auth` field entirely from `config.json`.

### Action Definitions

Each key in the `actions` object defines one action. Action names must be snake_case.

```json
"actions": {
    "get_items": {
        "display_name": "Get Items",
        "description": "Retrieves a list of items",
        "input_schema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of items to return",
                    "default": 10
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
                }
            }
        }
    }
}
```

#### Action Fields

| Field | Required | Description |
|-------|----------|-------------|
| `description` | Yes | What the action does |
| `input_schema` | Yes | JSON Schema defining accepted inputs |
| `output_schema` | Yes | JSON Schema defining the response structure |
| `display_name` | Recommended | Human-readable action name for the UI |

The `input_schema` and `output_schema` must be valid [JSON Schema (Draft 7)](https://json-schema.org/). The SDK validates inputs and outputs against these schemas at runtime.

## Validation

The [autohive-integrations-tooling](https://github.com/autohive-ai/autohive-integrations-tooling) validates all of the above:

```bash
# Validate structure and config
python scripts/validate_integration.py my-integration

# Check that config.json actions match Python code
python scripts/check_config_sync.py my-integration
```

See the tooling repo's documentation for setup instructions and the full list of checks.
