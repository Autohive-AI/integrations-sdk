---
name: writing-unit-tests
description: "Writes pytest unit tests for an Autohive integration using the mock_context + FetchResponse pattern. Use when asked to write tests, add test coverage, create unit tests, or test an integration. Covers file structure, test categories, and coverage expectations."
---

# Writing Unit Tests for an Integration

## Prerequisites

- The integration must be on **SDK 2.0.0** (`autohive-integrations-sdk~=2.0.0` in `requirements.txt`)
- If the integration is still on SDK 1.x, upgrade it first using the `upgrading-sdk-v2` skill

## File Structure

### Naming Convention

Test files live in `<integration>/tests/` and follow the pattern `test_<integration>_<domain>_unit.py`.

For small integrations (1–10 actions), a single file is fine:

```
myintegration/tests/
├── __init__.py
└── test_myintegration_unit.py
```

For large integrations (10+ actions), split by domain:

```
hubspot/tests/
├── __init__.py
├── test_hubspot_helpers_unit.py
├── test_hubspot_contacts_unit.py
├── test_hubspot_companies_unit.py
├── test_hubspot_deals_unit.py
├── test_hubspot_notes_unit.py
├── test_hubspot_tickets_unit.py
└── test_hubspot_misc_unit.py
```

The `_unit.py` suffix is required — CI uses it to discover unit tests.

### File Header (boilerplate)

Every test file must start with this exact boilerplate. Replace `myintegration` with the actual integration name and `myintegration.py` with the actual entry point file:

```python
import os
import sys
import importlib

_parent = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_deps = os.path.abspath(os.path.join(os.path.dirname(__file__), "../dependencies"))
sys.path.insert(0, _parent)
sys.path.insert(0, _deps)

import pytest  # noqa: E402
from unittest.mock import AsyncMock, MagicMock  # noqa: E402
from autohive_integrations_sdk import FetchResponse  # noqa: E402
from autohive_integrations_sdk.integration import ResultType  # noqa: E402

_spec = importlib.util.spec_from_file_location("myintegration_mod", os.path.join(_parent, "myintegration.py"))
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

myintegration = _mod.myintegration  # the Integration instance
# Also import any helper functions you need to test directly:
# parse_response = _mod.parse_response
# my_helper = _mod.my_helper

pytestmark = pytest.mark.unit
```

Add `from unittest.mock import patch` if you need to patch `asyncio.sleep` or environment variables.

### mock_context Fixture

Every test file needs this fixture:

```python
@pytest.fixture
def mock_context():
    ctx = MagicMock(name="ExecutionContext")
    ctx.fetch = AsyncMock(name="fetch")
    ctx.auth = {}
    return ctx
```

If the integration reads credentials from `context.auth`, populate it:

```python
ctx.auth = {
    "auth_type": "PlatformOauth2",
    "credentials": {"access_token": "test_token"},  # nosec B105
}
```

## Test Categories

Every action should have tests from **all applicable** categories below. Aim for 4–8 tests per action.

### 1. Happy Path (functional correctness)

Tests that verify the action works end-to-end with valid inputs and a successful API response.

```python
class TestGetContact:
    @pytest.mark.asyncio
    async def test_contact_found(self, mock_context):
        mock_context.fetch.return_value = FetchResponse(
            status=200,
            headers={},
            data={"results": [{"id": "123", "properties": {"email": "test@example.com"}}]},
        )

        result = await myintegration.execute_action(
            "get_contact", {"email": "test@example.com"}, mock_context
        )

        assert result.result.data["contact"]["id"] == "123"
```

### 2. Request Verification (are we calling the API correctly?)

Tests that verify the exact HTTP request being sent — URL, method, headers, payload structure.

```python
    @pytest.mark.asyncio
    async def test_request_url_and_method(self, mock_context):
        mock_context.fetch.return_value = FetchResponse(status=200, headers={}, data={"results": []})

        await myintegration.execute_action(
            "get_contact", {"email": "test@example.com"}, mock_context
        )

        call_args = mock_context.fetch.call_args
        assert call_args.args[0] == "https://api.hubapi.com/crm/v3/objects/contacts/search"
        assert call_args.kwargs["method"] == "POST"

    @pytest.mark.asyncio
    async def test_request_payload(self, mock_context):
        mock_context.fetch.return_value = FetchResponse(status=200, headers={}, data={"results": []})

        await myintegration.execute_action(
            "get_contact", {"email": "test@example.com"}, mock_context
        )

        payload = mock_context.fetch.call_args.kwargs["json"]
        assert payload["filterGroups"][0]["filters"][0]["value"] == "test@example.com"
        assert payload["limit"] == 1
```

### 3. Error Paths (exception handling)

Tests that verify exceptions are caught and returned as `ActionError`.

```python
    @pytest.mark.asyncio
    async def test_exception_returns_action_error(self, mock_context):
        mock_context.fetch.side_effect = Exception("Connection refused")

        result = await myintegration.execute_action(
            "get_contact", {"email": "test@example.com"}, mock_context
        )

        assert result.type == ResultType.ACTION_ERROR
        assert "Connection refused" in result.result.message
```

Not all actions have try/except blocks. Only write error path tests for actions that catch exceptions. Read the implementation first.

### 4. Edge Cases (boundary conditions)

Tests for unusual-but-valid inputs, empty results, default values, limit clamping.

```python
    @pytest.mark.asyncio
    async def test_contact_not_found(self, mock_context):
        mock_context.fetch.return_value = FetchResponse(
            status=200, headers={}, data={"results": []}
        )

        result = await myintegration.execute_action(
            "get_contact", {"email": "nobody@example.com"}, mock_context
        )

        assert result.type == ResultType.ACTION_ERROR

    @pytest.mark.asyncio
    async def test_default_limit(self, mock_context):
        mock_context.fetch.return_value = FetchResponse(status=200, headers={}, data={"results": []})

        await myintegration.execute_action("search_contacts", {"query": "test"}, mock_context)

        payload = mock_context.fetch.call_args.kwargs["json"]
        assert payload["limit"] == 100  # verify the default

    @pytest.mark.asyncio
    async def test_limit_clamped_to_200(self, mock_context):
        mock_context.fetch.return_value = FetchResponse(status=200, headers={}, data={"results": []})

        await myintegration.execute_action(
            "get_notes", {"contact_id": "1", "limit": 150}, mock_context
        )

        payload = mock_context.fetch.call_args.kwargs["json"]
        assert payload["limit"] == 150  # within max, passed through
```

### 5. Response Shape (contract verification)

Tests that verify the response data has the expected keys and structure.

```python
    @pytest.mark.asyncio
    async def test_response_data_structure(self, mock_context):
        mock_context.fetch.return_value = FetchResponse(
            status=200, headers={}, data={"id": "123", "properties": {}}
        )

        result = await myintegration.execute_action(
            "get_company", {"company_id": "123"}, mock_context
        )

        assert "company" in result.result.data
        assert result.result.data["company"]["id"] == "123"
```

### 6. Business Logic (domain-specific behavior)

Tests for integration-specific behavior like timestamp conversion, date parsing, association type IDs, data transformation.

```python
    @pytest.mark.asyncio
    async def test_timestamps_converted_to_utc(self, mock_context):
        mock_context.fetch.return_value = FetchResponse(
            status=200,
            headers={},
            data={"results": [{"properties": {"hs_timestamp": "2025-01-15T10:30:00.000Z"}}]},
        )

        result = await myintegration.execute_action(
            "get_notes", {"contact_id": "1"}, mock_context
        )

        assert "UTC" in result.result.data["notes"][0]["properties"]["hs_timestamp"]
```

## Mocking Patterns

### Single fetch call

```python
mock_context.fetch.return_value = FetchResponse(status=200, headers={}, data={...})
```

### Multiple sequential fetches (e.g., get thread ID then get messages)

```python
mock_context.fetch.side_effect = [
    FetchResponse(status=200, headers={}, data={"properties": {"thread_id": "t-1"}}),
    FetchResponse(status=200, headers={}, data={"results": [{"text": "Hello"}]}),
]
```

### Exception from fetch

```python
mock_context.fetch.side_effect = Exception("HTTP 500: Internal Server Error")
```

### DELETE responses (204 No Content)

```python
mock_context.fetch.return_value = FetchResponse(status=204, headers={}, data=None)
```

### Patching asyncio.sleep (for actions with delays)

```python
from unittest.mock import patch

@patch("asyncio.sleep", new_callable=AsyncMock)
async def test_paginated_fetch(self, mock_sleep, mock_context):
    mock_context.fetch.return_value = FetchResponse(...)
    result = await myintegration.execute_action("get_all_items", {...}, mock_context)
    # mock_sleep prevents real delay during tests
```

### Patching environment variables

```python
from unittest.mock import patch

@patch.dict(os.environ, {"MY_API_KEY": "test-key-123"})  # nosec B105
async def test_api_key_in_header(self, mock_context):
    ...
```

## Testing Helper Functions

Pure helper functions (no async, no context) should be tested directly without `mock_context`:

```python
class TestMyDateParser:
    def test_iso_format(self):
        result = parse_date("2025-01-15")
        assert result.year == 2025

    def test_none_returns_none(self):
        assert parse_date(None) is None

    def test_invalid_raises(self):
        with pytest.raises(ValueError, match="Unable to parse"):
            parse_date("not-a-date")
```

Async helpers like `parse_response` need `@pytest.mark.asyncio`:

```python
class TestParseResponse:
    @pytest.mark.asyncio
    async def test_dict_data(self):
        response = FetchResponse(status=200, headers={}, data={"key": "value"})
        result = await parse_response(response)
        assert result == {"key": "value"}
```

## Test Organization

### One class per action

```python
class TestGetContact:
    # all get_contact tests here

class TestCreateContact:
    # all create_contact tests here
```

### Group related tests with comment headers

```python
# ---- Contact Management ----

class TestGetContact:
    ...

class TestCreateContact:
    ...

# ---- Note Management ----

class TestCreateNote:
    ...
```

### Sample test data at module level

```python
SAMPLE_CONTACT = {
    "id": "123",
    "properties": {"email": "test@example.com", "firstname": "John"},
}

SAMPLE_NOTE_RESPONSE = {
    "id": "456",
    "properties": {"hs_note_body": "Test note"},
}
```

## Coverage Expectations

| Integration Size | Actions | Target Tests | Tests/Action |
|---|---|---|---|
| Small | 1–5 | 20–40 | 5–8 |
| Medium | 6–15 | 40–100 | 4–7 |
| Large | 16–50 | 100–300 | 4–6 |

Every action should have at minimum:
1. One **happy path** test
2. One **request verification** test (URL + method)
3. One **error path** test (if the action has try/except)
4. One **edge case** or **response shape** test

## Workflow

1. **Read the integration source** — understand each action's implementation
2. **Identify helper functions** — test pure functions first (easiest)
3. **Create test file(s)** with boilerplate header and `mock_context` fixture
4. **Write tests action by action** — go through each test category
5. **Run tests**: `python -m pytest <integration>/tests/test_*_unit.py -v`
6. **Lint and format**:
   ```bash
   ruff check --fix <integration>/tests
   ruff format --config ../autohive-integrations-tooling/ruff.toml <integration>/tests
   ```
7. **Verify all pass** before committing

## Common Gotchas

1. **Actions that make multiple fetches**: Use `side_effect` with a list, not `return_value`. The list must have exactly the right number of `FetchResponse` objects in the right order.

2. **asyncio.gather in actions**: When an action runs fetches in parallel with `asyncio.gather`, the mock's `side_effect` list still works — each `await context.fetch(...)` pops the next item.

3. **SDK input validation**: The SDK validates inputs against `config.json` schemas before the action handler runs. If you pass invalid inputs (wrong type, missing required field), the result will have `type == ResultType.VALIDATION_ERROR` and the handler never executes. This means `mock_context.fetch` is never called.

4. **ActionError vs ActionResult**: Error paths return `ActionError(message=...)` which results in `result.type == ResultType.ACTION_ERROR` and `result.result.message` containing the error. Happy paths return `ActionResult(data=...)` which results in `result.result.data` containing the response.

5. **Silent exception blocks**: Some actions have `except Exception: continue` or `except Exception: pass` — these are intentional skip-on-failure patterns. Don't write error tests for these; they don't return ActionError.

6. **The `nosec` comment**: Use `# nosec B105` after test token strings to suppress Bandit false positives on hardcoded credentials in tests.

7. **Unused variables**: If you call `execute_action` only to verify `mock_context.fetch.call_args`, don't assign the result to a variable — ruff will flag it as unused. Use `await integration.execute_action(...)` without assignment.

## Reference Implementations

Look at these integrations for well-tested examples:
- `perplexity/tests/test_perplexity_unit.py` — single-action integration, thorough coverage
- `hackernews/tests/test_hackernews_unit.py` — multi-action with helper function tests
- `bitly/tests/test_bitly_unit.py` — pure function tests + action tests
- `hubspot/tests/test_hubspot_*_unit.py` — large integration split across 7 domain files
