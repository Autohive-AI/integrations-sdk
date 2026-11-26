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
├── icon.png                  # or icon.jpg / icon.jpeg, 512×512 pixels
├── pytest.ini                # Standalone only; omit in an integrations monorepo
└── tests/
    ├── __init__.py
    ├── conftest.py
    └── test_my_integration_unit.py
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
├── icon.png                  # or icon.jpg / icon.jpeg, 512×512 pixels
├── pytest.ini                # Standalone only; omit in an integrations monorepo
├── actions/
│   ├── __init__.py            # imports sub-modules to register handlers
│   ├── items.py
│   └── users.py
└── tests/
    ├── __init__.py
    ├── conftest.py
    └── test_my_integration_unit.py
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
| `icon.png`, `icon.jpg`, or `icon.jpeg` | Exactly one integration icon, 512×512 pixels; SVG is not accepted by HiveUp |
| `tests/` | Test directory |

### `__init__.py`

- Required for single-file integrations (warning if missing)
- Optional for modular integrations with an `actions/` subdirectory
- Keep the root file empty in hyphenated integration directories. Relative re-exports can fail when pytest imports it without a package context.

### `requirements.txt`

For new integrations and SDK upgrades, use a compatible release pin targeting SDK 2.1.0:

```
autohive-integrations-sdk~=2.1.0
```

The `~=` operator means `>=2.1.0, <2.2.0` — you get patch updates but not minor version changes. A pin such as `~=2.0.0` excludes 2.1.0. HiveUp's advisory for earlier SDK pins is nonblocking; upgrade existing integrations separately with tests rather than changing pins during an unrelated migration.

Add any additional libraries your integration needs (e.g., `feedparser`, `stripe`).

### Unit tests

Name offline tests `tests/test_*_unit.py` and mark them `unit`; HiveUp uses both the filename pattern and marker. Put fixtures and import setup in `tests/conftest.py`. Mock `context.fetch()` with `FetchResponse`, use the platform auth envelope when auth is configured, and assert `ResultType.ACTION` before inspecting successful output. See [the tutorial's test setup](building_your_first_integration.md#step-6-write-tests) for `pytest.ini` and runnable examples. Live provider tests use `test_*_integration.py` and are run explicitly, not by HiveUp's unit test command.

Use an integration-local `pytest.ini` only for standalone projects. When copying a sample into an integrations monorepo, omit or remove that file and inherit the repository-root pytest configuration so shared fixtures such as `env_credentials` and `make_context` remain available.

## Naming Conventions

| What | Convention | Example |
|------|-----------|---------|
| Directory name | lowercase, hyphens | `my-integration`, `google-sheets` |
| Python module | lowercase, underscores | `my_integration.py`, `google_sheets.py` |
| Action names | snake_case | `list_items`, `create_record` |
| `config.json` `name` | human-readable name | `My Integration` |

## `config.json` Schema

### Top-Level Fields

#### Required

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Integration name |
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
- `fields`: a JSON Schema describing the **credentials object only** (the inner
  `credentials` the platform passes at runtime), with `properties` and an
  optional `required` list. `required` is allowed and recommended — it is
  enforced against the credentials object.

The `title` field labels the auth section in the UI.

Each property in `fields.properties` supports:

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Data type (typically `"string"`) |
| `format` | string | UI hint (e.g., `"password"` to mask input) |
| `label` | string | Display label in the auth form |
| `help_text` | string | Help text shown below the field |
| `default` | any | Default value |

At runtime `context.auth` is the wrapped platform envelope
(`{"auth_type": ..., "credentials": {...}}`). Handlers should read individual
credentials directly from the envelope via
`context.auth["credentials"]`: `context.auth["credentials"].get("api_token")`.

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

With a `PlatformOauth2` runtime envelope, `context.fetch()` automatically injects the `Authorization` header unless you supply one. Local tests must use `{"auth_type": "PlatformOauth2", "credentials": {"access_token": "..."}}`. Successful requests return a `FetchResponse` object with `.status`, `.headers`, and `.data`. SDK 2.1.0 also preserves headers on `HTTPError` and `RateLimitError`; see [HTTP error headers](patterns.md#http-error-headers-sdk-210).

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

Install HiveUp using the [Tooling installation instructions](https://github.com/Autohive-AI/autohive-integrations-tooling#install-hiveup-from-a-local-build); it is not published to PyPI. From the parent of the integration directory:

```bash
# Run validation, code-quality checks, and unit tests
hiveup validate my-integration

# Check that config.json actions match Python code
hiveup check sync my-integration

# Run only unit tests, using the integration's dependency pins
hiveup test my-integration
```

See the tooling repo's documentation for setup instructions and the full list of checks.
