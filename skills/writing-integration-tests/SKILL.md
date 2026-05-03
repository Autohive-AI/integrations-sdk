---
name: writing-integration-tests
description: "Writes pytest end-to-end integration tests for an Autohive integration that call real APIs using the live_context fixture pattern. Use when asked to write integration tests, add e2e tests, create live API tests, or test an integration against a real service. Covers file structure, live_context fixture variants, environment variable handling, destructive markers, and test organization."
---

# Writing Integration Tests for an Integration

## Prerequisites

- The integration must be on **SDK 2.0.0** (`autohive-integrations-sdk~=2.0.0` in `requirements.txt`)
- If the integration is still on SDK 1.x, upgrade it first using the `upgrading-sdk-v2` skill
- `aiohttp` must be available in the test environment (used by the `live_context` fixture)
- A valid API key or OAuth token for the target service

## How Integration Tests Differ from Unit Tests

| Aspect | Unit Tests | Integration Tests |
|---|---|---|
| Network calls | Mocked via `mock_context` | Real via `live_context` + aiohttp |
| File suffix | `_unit.py` | `_integration.py` |
| Marker | `pytest.mark.unit` | `pytest.mark.integration` |
| CI | Runs by default | Never runs in CI |
| Credentials | Fake test tokens | Real API keys/tokens from env vars |
| Speed | Milliseconds | Seconds (network I/O) |

## File Structure

### Naming Convention

Test files live in `<integration>/tests/` and follow the pattern `test_<integration>_integration.py`.

Integration tests are always a single file per integration — do not split by domain.

```
myintegration/tests/
├── __init__.py
├── test_myintegration_unit.py
└── test_myintegration_integration.py
```

### Double Exclusion from CI

Integration tests are excluded from CI and default `pytest` runs by **two mechanisms**:

1. **File naming**: `pyproject.toml` has `python_files = ["test_*_unit.py"]`, so `test_*_integration.py` files are never collected
2. **Marker**: `addopts = "-m unit"` in `pyproject.toml` filters to unit-only by default

This double exclusion ensures integration tests never run accidentally.

### File Header (boilerplate)

With `sys.path` set up in `tests/conftest.py` (see the unit tests skill for the standard shape), an integration test file can use plain imports:

```python
"""
End-to-end integration tests for the MyIntegration integration.

These tests call the real MyService API and require a valid access token
set in the MYINTEGRATION_ACCESS_TOKEN environment variable (via .env or export).

Run with:
    pytest myintegration/tests/test_myintegration_integration.py -m integration

Never runs in CI — the default pytest marker filter (-m unit) excludes these,
and the file naming (test_*_integration.py) is not matched by python_files.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from autohive_integrations_sdk import FetchResponse
from autohive_integrations_sdk.integration import ResultType

from myintegration import myintegration

pytestmark = pytest.mark.integration
```

Use the `importlib` fallback boilerplate from the unit tests skill only when plain imports won't work for the integration's layout.

## Environment Variables

### env_credentials Fixture (preferred)

The repo-wide [`conftest.py`](https://github.com/Autohive-AI/autohive-integrations/blob/master/conftest.py) provides an `env_credentials` fixture that auto-loads the project `.env` and reads variables on demand:

```python
@pytest.fixture
def live_context(env_credentials, make_context):
    api_key = env_credentials("MYINTEGRATION_API_KEY")
    if not api_key:
        pytest.skip("MYINTEGRATION_API_KEY not set — skipping integration tests")
    return make_context(auth={"credentials": {"api_key": api_key}})
```

This is the recommended pattern for any test that needs API credentials: it skips automatically when the env var is missing, integrates with the project `.env`, and avoids per-test boilerplate.

### Module-level constants (when you need them everywhere)

If multiple fixtures or helpers need the same env var, define them at module level — but still drive skip behaviour off `env_credentials` inside the fixture, not at import time:

```python
TEST_ITEM_ID = os.environ.get("MYINTEGRATION_TEST_ITEM_ID", "")
TEST_PROJECT_ID = os.environ.get("MYINTEGRATION_TEST_PROJECT_ID", "")
```

### require_* Skip Helpers

For tests that need specific object IDs (which `env_credentials` doesn't model directly), create `require_*` helpers that skip gracefully:

```python
def require_item_id():
    if not TEST_ITEM_ID:
        pytest.skip("MYINTEGRATION_TEST_ITEM_ID not set")
```

Call these at the start of any test method that needs the ID:

```python
class TestGetItem:
    async def test_returns_item(self, live_context):
        require_item_id()
        result = await myintegration.execute_action("get_item", {"id": TEST_ITEM_ID}, live_context)
        ...
```

### .env.example Documentation

Document all required and optional environment variables in the integration's `.env.example`:

```bash
# -- MyIntegration --
MYINTEGRATION_ACCESS_TOKEN=
MYINTEGRATION_TEST_ITEM_ID=
MYINTEGRATION_TEST_PROJECT_ID=
```

## The live_context Fixture

The `live_context` fixture provides a `MagicMock` of the SDK's `ExecutionContext` but replaces the `fetch` method with a real async HTTP client using `aiohttp`. This lets the integration code run unchanged while making real network calls.

### Variant 1: No Auth (public APIs)

For integrations that call public APIs with no authentication (e.g., Hacker News):

```python
@pytest.fixture
def live_context():
    import aiohttp

    async def real_fetch(url, *, method="GET", json=None, headers=None, **kwargs):
        async with aiohttp.ClientSession() as session:
            async with session.request(method, url, json=json, headers=headers) as resp:
                data = await resp.json(content_type=None)
                return FetchResponse(
                    status=resp.status,
                    headers=dict(resp.headers),
                    data=data,
                )

    ctx = MagicMock(name="ExecutionContext")
    ctx.fetch = AsyncMock(side_effect=real_fetch)
    ctx.auth = {}
    return ctx
```

### Variant 2: API Key Auth

For integrations where the action handler adds the API key to headers itself (e.g., Perplexity):

```python
@pytest.fixture
def live_context():
    if not API_KEY:
        pytest.skip("MYINTEGRATION_API_KEY not set — skipping integration tests")

    import aiohttp

    async def real_fetch(url, *, method="GET", json=None, headers=None, **kwargs):
        async with aiohttp.ClientSession() as session:
            async with session.request(method, url, json=json, headers=headers) as resp:
                data = await resp.json()
                return FetchResponse(status=resp.status, headers=dict(resp.headers), data=data)

    ctx = MagicMock(name="ExecutionContext")
    ctx.fetch = AsyncMock(side_effect=real_fetch)
    ctx.auth = {}
    return ctx
```

### Variant 3: Platform OAuth (token injection)

For integrations that rely on the SDK's platform auth layer to inject the OAuth token. In tests, bypass the SDK auth by manually adding the `Authorization` header:

```python
@pytest.fixture
def live_context():
    if not ACCESS_TOKEN:
        pytest.skip("MYINTEGRATION_ACCESS_TOKEN not set — skipping integration tests")

    import aiohttp

    async def real_fetch(url, *, method="GET", json=None, headers=None, params=None, **kwargs):
        merged_headers = dict(headers or {})
        merged_headers["Authorization"] = f"Bearer {ACCESS_TOKEN}"
        async with aiohttp.ClientSession() as session:
            async with session.request(method, url, json=json, headers=merged_headers, params=params) as resp:
                data = await resp.json(content_type=None)
                return FetchResponse(
                    status=resp.status,
                    headers=dict(resp.headers),
                    data=data,
                )

    ctx = MagicMock(name="ExecutionContext")
    ctx.fetch = AsyncMock(side_effect=real_fetch)
    ctx.auth = {
        "auth_type": "PlatformOauth2",
        "credentials": {"access_token": ACCESS_TOKEN},
    }
    return ctx
```

### Variant 4: External Python SDK (no `context.fetch`)

Some integrations don't go through `context.fetch` at all — instead they instantiate a third-party Python SDK and let it make the HTTP calls (e.g. `from supadata import Supadata`). For these, the `aiohttp` wrapper is irrelevant: the SDK does its own networking. Just inject the credentials via `make_context` and the upstream library handles the rest:

```python
@pytest.fixture
def live_context(env_credentials, make_context):
    api_key = env_credentials("MYINTEGRATION_API_KEY")
    if not api_key:
        pytest.skip("MYINTEGRATION_API_KEY not set — skipping integration tests")
    return make_context(auth={"credentials": {"api_key": api_key}})
```

This variant is the simplest of the four — no `real_fetch` definition needed. Use it whenever the integration's source imports a vendor SDK and calls it directly rather than calling `context.fetch`.

**How to choose**:

| Auth shape | Networking | Variant |
|---|---|---|
| None (public API) | `context.fetch` | 1 — No auth |
| API key in `context.auth` or env | `context.fetch` | 2 — API key |
| Platform OAuth (`config.auth.type == "platform"`) | `context.fetch` | 3 — Platform OAuth |
| Any | External Python SDK call | 4 — External SDK |

## The Destructive Marker

### When to Use

Tests that **create, update, or delete** real data must be marked `@pytest.mark.destructive`. This prevents accidental data mutation when running integration tests.

```python
@pytest.mark.destructive
class TestCreateItem:
    async def test_creates_item(self, live_context):
        result = await myintegration.execute_action(
            "create_item", {"name": f"Integration Test {os.getpid()}"}, live_context
        )
        data = result.result.data
        assert "item" in data
        assert data["item"]["id"] is not None
```

### Registering the Marker

The `destructive` marker must be registered in `pyproject.toml`:

```toml
[tool.pytest.ini_options]
markers = [
    "unit: unit tests (mocked, no network)",
    "integration: integration tests (real API calls)",
    "destructive: tests that create, update, or delete real data",
]
```

### Running Commands

```bash
# Read-only integration tests only
pytest myintegration/tests/test_myintegration_integration.py -m "integration and not destructive"

# Destructive tests only
pytest myintegration/tests/test_myintegration_integration.py -m "integration and destructive"

# All integration tests
pytest myintegration/tests/test_myintegration_integration.py -m integration
```

## Test Organization

### Section Headers by Domain

Group tests with comment headers matching the integration's domains:

```python
# ---- Read-Only Tests ----

class TestGetItem:
    ...

class TestSearchItems:
    ...

# ---- Destructive Tests (Write Operations) ----
# These create, update, or delete real data.
# Only run with: pytest -m "integration and destructive"

@pytest.mark.destructive
class TestCreateItem:
    ...
```

### One Class per Action (or Logical Group)

```python
class TestGetContact:
    async def test_returns_contact(self, live_context):
        ...

    async def test_contact_has_expected_fields(self, live_context):
        ...
```

### Chained Tests (Dynamic IDs)

When an action requires an ID from another action's response, chain them within the test:

```python
class TestGetBitlink:
    async def test_fetches_bitlink_details(self, live_context):
        # First get a real ID from a list action
        list_result = await myintegration.execute_action("list_items", {"size": 1}, live_context)
        items = list_result.result.data["items"]

        if not items:
            pytest.skip("No items in account to test with")

        item_id = items[0]["id"]

        # Then test the action that needs the ID
        result = await myintegration.execute_action("get_item", {"id": item_id}, live_context)
        data = result.result.data
        assert "item" in data
```

### Lifecycle Tests (CRUD Workflows)

For destructive tests, a lifecycle test that creates, reads, updates, and deletes ensures cleanup:

```python
@pytest.mark.destructive
class TestItemLifecycle:
    """End-to-end workflow: create → read → update → delete."""

    async def test_full_lifecycle(self, live_context):
        # Step 1: Create
        create_result = await myintegration.execute_action(
            "create_item", {"name": f"Integration test {os.getpid()}"}, live_context
        )
        item_id = create_result.result.data["item"]["id"]
        assert item_id is not None

        # Step 2: Read
        read_result = await myintegration.execute_action("get_item", {"id": item_id}, live_context)
        assert read_result.result.data["item"]["id"] == item_id

        # Step 3: Update
        update_result = await myintegration.execute_action(
            "update_item", {"id": item_id, "name": "Updated name"}, live_context
        )
        assert update_result.result.data["success"] is True

        # Step 4: Delete (cleanup)
        delete_result = await myintegration.execute_action("delete_item", {"id": item_id}, live_context)
        assert delete_result.result.data["success"] is True
```

## What to Assert

Integration tests validate that the integration works against the real API. Focus on:

1. **Response structure** — expected keys exist in the result data
2. **Non-empty results** — list actions return items, get actions return the object
3. **ID round-trips** — the ID you pass in appears in the response
4. **Limits respected** — passing `limit: 2` returns ≤ 2 items
5. **Error handling** — nonexistent IDs return `ActionError` (if the action handles it)

Do **not** assert on specific data values from the live API — data changes over time.

```python
# ✅ Good — structural assertions
assert "contacts" in data
assert data["contact_id"] == TEST_CONTACT_ID
assert len(data["results"]) <= 5

# ❌ Bad — brittle value assertions
assert data["contacts"][0]["email"] == "john@acme.com"
assert data["total"] == 42
```

## Coverage Expectations

| Integration Size | Actions | Target Integration Tests |
|---|---|---|
| Small (1–5 actions) | All | 5–15 |
| Medium (6–15 actions) | All | 15–30 |
| Large (16+ actions) | All read-only + key write flows | 30–50 |

Every action should have at minimum:
1. One test proving it **works against the real API**
2. One test verifying the **response structure**

Write actions (create/update/delete) need at least:
1. One `@pytest.mark.destructive` test proving it works
2. Cleanup of created data where possible (lifecycle tests)

## Workflow

1. **Read the integration source** — understand each action and its auth mechanism
2. **Check `config.json`** — determine auth type (none / API key / platform OAuth)
3. **Choose the right `live_context` variant** — see the three variants above
4. **Document env vars** in `.env.example`
5. **Write read-only tests first** — these are safe to run repeatedly
6. **Add destructive tests** with `@pytest.mark.destructive` for write actions
7. **Run read-only tests**:
   ```bash
   pytest <integration>/tests/test_*_integration.py -m "integration and not destructive"
   ```
8. **Run destructive tests** (only when you're sure):
   ```bash
   pytest <integration>/tests/test_*_integration.py -m "integration and destructive"
   ```

## Common Gotchas

1. **content_type=None in resp.json()**: Some APIs return JSON without a proper `Content-Type` header. Always use `await resp.json(content_type=None)` in the `real_fetch` function to avoid `ContentTypeError`.

2. **Test isolation**: Each test creates a new `aiohttp.ClientSession`. This is intentional — integration tests should not share session state.

3. **Rate limiting**: If the API has rate limits, add a small `asyncio.sleep` between tests or reduce the number of tests that hit the same endpoint.

4. **Dynamic test data**: Never hardcode IDs from the live API. Use environment variables for pre-existing objects, or chain actions (list → get) within the test.

5. **Destructive test cleanup**: Always clean up created data at the end of lifecycle tests. Use `os.getpid()` in created object names to avoid collisions when running tests in parallel.

6. **OAuth token expiry**: Platform OAuth tokens expire. Document the refresh process in the integration's README or `.env.example`.

## Reference Implementations

Look at these integrations for well-tested examples:
- `hackernews/tests/test_hackernews_integration.py` — public API, no auth, multiple action types
- `perplexity/tests/test_perplexity_integration.py` — API key auth, single action, thorough parameter coverage
- `bitly/tests/test_bitly_integration.py` — platform OAuth, chained tests (list → get), read-only
- `hubspot/tests/test_hubspot_integration.py` — platform OAuth, require_* helpers, destructive marker, lifecycle tests
