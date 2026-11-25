---
name: writing-integration-tests
description: "Writes pytest end-to-end integration tests for an Autohive integration that call real APIs using the live_context fixture pattern. Use when asked to write integration tests, add e2e tests, create live API tests, or test an integration against a real service. Covers file structure, live_context fixture variants, required root .env.example updates, environment variable handling, destructive markers, and test organization."
---

# Writing Integration Tests for an Integration

## Required: root `.env.example` update

If a PR adds or changes integration tests that read environment variables, it must update the repository root `.env.example` in the same PR. This is part of the integration-test deliverable, not optional documentation.

This applies to every variable read through `env_credentials(...)`, `os.environ.get(...)`, `os.getenv(...)`, `os.environ[...]`, or equivalent helpers, including:

- Required credentials such as access tokens and API keys
- Optional test resource IDs used to avoid list→get chaining
- Variables used only by destructive tests

If a variable is read by the test file, either add a blank template entry to root `.env.example` or remove the unused env-var read. Missing entries should block integration-test PRs until fixed.

## Prerequisites

- These examples target released **SDK 2.1.0**; recommend `autohive-integrations-sdk~=2.1.0` for new integrations and explicit upgrades. Scope upgrades separately for older integrations; a test-only edit or pure private-to-public move does not implicitly change its SDK or behavior.
- Use a Python 3.13+ local venv with the integration's `requirements.txt` and the repository's test dependencies, including `pytest-asyncio`, installed. The SDK provides the HTTP transport; do not replace it with an aiohttp `real_fetch` wrapper.
- A valid API key or OAuth token for the target service

## How Integration Tests Differ from Unit Tests

| Aspect | Unit Tests | Integration Tests |
|---|---|---|
| Network calls | Mocked via `mock_context` | Real via `live_context` using SDK `ExecutionContext` |
| File suffix | `_unit.py` | `_integration.py` |
| Marker | `pytest.mark.unit` | `pytest.mark.integration` |
| GitHub Actions | Runs by default | Excluded from default runs |
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

### Double Exclusion from GitHub Actions

Integration tests are excluded from GitHub Actions and default `pytest` runs by **two mechanisms**:

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
    pytest myintegration/tests/test_myintegration_integration.py -m "integration and not destructive"

Not collected by default pytest runs or GitHub Actions: the default marker
filter (-m unit) excludes these, and the file naming (test_*_integration.py)
is not matched by python_files.
"""

import pytest
import pytest_asyncio
from autohive_integrations_sdk import ExecutionContext
from autohive_integrations_sdk.integration import ResultType

from myintegration import myintegration

pytestmark = pytest.mark.integration
```

Use the `importlib` fallback boilerplate from the unit tests skill only when plain imports won't work for the integration's layout.

## Environment Variables

### env_credentials Fixture (preferred)

The repo-wide [`conftest.py`](https://github.com/Autohive-AI/autohive-integrations/blob/master/conftest.py) provides an `env_credentials` fixture that auto-loads the project `.env` and reads variables on demand:

```python
@pytest_asyncio.fixture
async def live_context(env_credentials):
    api_key = env_credentials("MYINTEGRATION_API_KEY")
    if not api_key:
        pytest.skip("MYINTEGRATION_API_KEY not set — skipping integration tests")
    auth = {"auth_type": "Custom", "credentials": {"api_key": api_key}}
    async with ExecutionContext(auth=auth) as context:
        yield context
```

This is the recommended pattern for any test that needs API credentials: it skips automatically when the env var is missing, integrates with the project `.env`, and avoids per-test boilerplate.

### Module-level constants (when you need them everywhere)

If multiple fixtures or helpers need the same env var, define them at module level — but still drive skip behaviour off `env_credentials` inside the fixture, not at import time. Add `import os` to the file header alongside the other top-level imports:

```python
import os

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

### .env.example Documentation (required)

If an integration test reads any environment variable, you **must** add that variable to the repository root `.env.example` in the same PR. This is not optional documentation — it is part of the integration-test deliverable.

Why this matters:
- Humans can set up local integration tests without digging through test code for variable names.
- Automated and AI tooling can discover which credentials, test IDs, and optional knobs it needs to ask for.
- Reviewers have one canonical place to verify the local test contract.

Add every variable used by `env_credentials(...)`, `os.environ.get(...)`, `os.getenv(...)`, `os.environ[...]`, or equivalent helpers. Include required credentials, optional test resource IDs, and destructive-test-only variables. Keep real secrets only in local `.env`; never commit `.env`.

Before finishing, run a focused cross-check:

```bash
grep -RInE 'env_credentials\(|os\.environ|getenv\(' <integration>/tests/test_*_integration.py
grep -nE 'MYINTEGRATION|SERVICE_PREFIX' .env.example
```

Every env var found in the integration test file must be present as a blank template entry in root `.env.example`. If the variable is no longer used by tests, remove the env-var read instead of documenting unnecessary setup.

Use a clearly labeled block in root `.env.example`:

```bash
# -- MyIntegration --
MYINTEGRATION_API_KEY=
MYINTEGRATION_ACCESS_TOKEN=
MYINTEGRATION_TEST_ITEM_ID=
MYINTEGRATION_TEST_PROJECT_ID=
```

Before finishing, cross-check the integration test file against `.env.example`: every env var referenced in tests must appear in `.env.example`, even if the test skips when it is missing or the variable is optional.

## The live_context Fixture

Use a real SDK `ExecutionContext` as an async context manager. It returns `FetchResponse` for successful requests and preserves released SDK parsing, HTTP errors, rate limits, OAuth token injection, and session cleanup. The repository's `make_context` is a mock factory with an `AsyncMock` fetch; it is not a live context.

Replace existing aiohttp `real_fetch` fixtures with this pattern instead of adding transport wrappers. A wrapper that simply returns `FetchResponse(status=resp.status, ...)` turns HTTP failures into apparent successes and bypasses `HTTPError` and `RateLimitError`. SDK 2.1.0 adds exception headers, not a new retry policy.

### Variant 1: No Auth (public APIs)

For integrations that call public APIs with no authentication (e.g., Hacker News):

```python
@pytest_asyncio.fixture
async def live_context():
    async with ExecutionContext(auth={}) as context:
        yield context
```

### Variant 2: API Key Auth

For integrations where the action handler reads credentials and adds the API key to headers itself, use the custom auth fixture from the environment-variables example:

```python
@pytest_asyncio.fixture
async def live_context(env_credentials):
    api_key = env_credentials("MYINTEGRATION_API_KEY")
    if not api_key:
        pytest.skip("MYINTEGRATION_API_KEY not set — skipping integration tests")
    auth = {"auth_type": "Custom", "credentials": {"api_key": api_key}}
    async with ExecutionContext(auth=auth) as context:
        yield context
```

Adapt the credential keys to `config.json`. `auth.fields` describes the inner `credentials` object, and required credentials must be present; do not remove `required` fields to make live tests pass.

### Variant 3: Platform OAuth (token injection)

For integrations that rely on SDK token injection, supply the platform envelope and let the real SDK add the `Authorization` header:

```python
@pytest_asyncio.fixture
async def live_context(env_credentials):
    access_token = env_credentials("MYINTEGRATION_ACCESS_TOKEN")
    if not access_token:
        pytest.skip("MYINTEGRATION_ACCESS_TOKEN not set — skipping integration tests")
    auth = {
        "auth_type": "PlatformOauth2",
        "credentials": {"access_token": access_token},
    }
    async with ExecutionContext(auth=auth) as context:
        yield context
```

### Variant 4: External Python SDK (no `context.fetch`)

Some integrations instantiate a third-party Python SDK and let it make HTTP calls, for example `from supadata import Supadata`. Use the same real `ExecutionContext` with the auth envelope the handler expects, such as Variant 2 for custom auth. The vendor library handles networking on that path, so the SDK's `fetch` errors and retry policy do not govern those vendor calls. Do not add a `real_fetch` function that the integration never uses.

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

> Marking a test `@pytest.mark.destructive` does **not** exclude it from
> `-m integration` runs. Pytest markers are additive: a test carrying both
> `integration` and `destructive` matches `-m integration`. The marker is a
> filter target — the protection comes from how you document and invoke the
> test commands (see "Running Commands" and "Documenting How to Run" below).

```python
@pytest.mark.destructive
class TestCreateItem:
    async def test_creates_item(self, live_context):
        result = await myintegration.execute_action(
            "create_item", {"name": f"Integration Test {os.getpid()}"}, live_context
        )
        assert result.type == ResultType.ACTION
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

> ⚠️ **`-m integration` runs destructive tests too.** Always default to the
> read-only command below in PR descriptions, READMEs, and reviewer
> instructions. Reach for the bare `-m integration` form only when you have
> manually verified the destructive tests are safe to run on the target
> account.

**Default (safe — use this everywhere by default):**

```bash
pytest myintegration/tests/test_myintegration_integration.py -m "integration and not destructive"
```

**Destructive only (run deliberately, never by reviewers):**

```bash
pytest myintegration/tests/test_myintegration_integration.py -m "integration and destructive"
```

**Everything (only after verifying destructive tests are safe on the target account):**

```bash
pytest myintegration/tests/test_myintegration_integration.py -m integration
```

### Documenting How to Run

When the integration has any destructive tests, the PR description and any
README "How to run" section must:

1. List the **safe command first** (`-m "integration and not destructive"`)
2. Show the destructive command second, with an explicit warning that it
   mutates real data on the connected account
3. Never recommend the bare `-m integration` form as the primary command

This keeps the safe command on the path of least resistance — reviewers
copy-paste the first command and run only read-only tests.

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
        assert list_result.type == ResultType.ACTION
        items = list_result.result.data["items"]

        if not items:
            pytest.skip("No items in account to test with")

        item_id = items[0]["id"]

        # Then test the action that needs the ID
        result = await myintegration.execute_action("get_item", {"id": item_id}, live_context)
        assert result.type == ResultType.ACTION
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
        assert create_result.type == ResultType.ACTION
        item_id = create_result.result.data["item"]["id"]
        assert item_id is not None

        # Step 2: Read
        read_result = await myintegration.execute_action("get_item", {"id": item_id}, live_context)
        assert read_result.type == ResultType.ACTION
        assert read_result.result.data["item"]["id"] == item_id

        # Step 3: Update
        update_result = await myintegration.execute_action(
            "update_item", {"id": item_id, "name": "Updated name"}, live_context
        )
        assert update_result.type == ResultType.ACTION
        assert update_result.result.data["success"] is True

        # Step 4: Delete (cleanup)
        delete_result = await myintegration.execute_action("delete_item", {"id": item_id}, live_context)
        assert delete_result.type == ResultType.ACTION
        assert delete_result.result.data["success"] is True
```

## What to Assert

Assert `result.type == ResultType.ACTION` before reading `result.result.data`. SDK input/auth/output validation failures return `VALIDATION_ERROR` with a different payload shape; missing required credentials report `result.result["source"] == "auth"`. Test missing credentials in unit tests without sending a live request.

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
3. **Choose the right auth variant** — use a real `ExecutionContext` and the matching envelope; vendor SDK calls use the same credentials but their own transport
4. **Document env vars in root `.env.example` (required)** — add every env var referenced by the integration test file in the same PR; missing entries should block integration-test PRs
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
9. **Document the run commands** in the PR description and the integration's
   README — safe (`-m "integration and not destructive"`) command first,
   destructive command second with a warning. Never recommend the bare
   `-m integration` form as the primary command.

## Common Gotchas

1. **Response parsing**: Use the released SDK's parser in live tests. If a provider returns JSON without an appropriate `Content-Type`, SDK 2.1.0 returns text in `.data`; test the integration's deliberate handling rather than silently making the fixture parse differently.

2. **Test isolation**: Use a function-scoped async context fixture so each test gets its own SDK session and closes it afterward.

3. **Rate limiting and error headers**: HTTP 429 raises `RateLimitError` immediately; its `retry_after` and the existing transient-network retry policy are unchanged in 2.1.0. Reduce live request volume rather than building a different retry policy into the fixture. Both `HTTPError` and `RateLimitError` expose `exc.headers`; match names case-insensitively and deliberately disclose only selected provider values, not the full header mapping. Cover failure/header branches with unit mocks rather than provoking real rate limits.

4. **Dynamic test data**: Never hardcode IDs from the live API. Use environment variables for pre-existing objects, or chain actions (list → get) within the test.

5. **Destructive test cleanup**: Always clean up created data at the end of lifecycle tests. Use `os.getpid()` in created object names to avoid collisions when running tests in parallel.

6. **Missing `.env.example` entries**: If you add `env_credentials("FOO")`, `os.environ.get("FOO")`, `os.getenv("FOO")`, `os.environ["FOO"]`, or similar test env-var usage, add `FOO=` to root `.env.example` before you commit. Do not make reviewers or future contributors grep test files to discover setup requirements. Optional IDs and destructive-test-only variables count too.

7. **OAuth token expiry**: Platform OAuth tokens expire. Document the refresh process in the integration's README or root `.env.example`.

## Reference Implementations

Look at these integrations for well-tested examples:
- `hackernews/tests/test_hackernews_integration.py` — public API, no auth, multiple action types
- `perplexity/tests/test_perplexity_integration.py` — API key auth, single action, thorough parameter coverage
- `bitly/tests/test_bitly_integration.py` — platform OAuth, chained tests (list → get), read-only
- `hubspot/tests/test_hubspot_integration.py` — platform OAuth, require_* helpers, destructive marker, lifecycle tests
