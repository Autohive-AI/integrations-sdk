# Writing Integration Tests for an Integration

## Required: root `.env.example` update

If a PR adds or changes integration tests that read environment variables, it must update the repository root `.env.example` in the same PR. This is part of the integration-test deliverable, not optional documentation.

This applies to every variable read through `env_credentials(...)`, `os.environ.get(...)`, `os.getenv(...)`, `os.environ[...]`, or equivalent helpers, including:

- Required credentials such as access tokens and API keys
- Optional test resource IDs used to avoid list→get chaining
- Variables used only by destructive tests

If a variable is read by the test file, either add a blank template entry to root `.env.example` or remove the unused env-var read. Missing entries should block integration-test PRs until fixed.

To run the tests in TeamCity, the same variables must also be supplied through `<integration>/tests/teamcity.env`. See [Running Live Tests in TeamCity](#running-live-tests-in-teamcity).

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
| CI | GitHub Actions on every PR | Never in GitHub Actions; non-destructive tests run in TeamCity |
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

Integration tests are excluded from GitHub Actions CI and default `pytest` runs by **two mechanisms**:

1. **File naming**: `pyproject.toml` has `python_files = ["test_*_unit.py"]`, so `test_*_integration.py` files are never collected
2. **Marker**: `addopts = "-m unit"` in `pyproject.toml` filters to unit-only by default

This double exclusion ensures integration tests never run accidentally.

### File Header (boilerplate)

With `sys.path` set up in `tests/conftest.py` (see [`unit-tests.md`](unit-tests.md) for the standard shape), an integration test file can use plain imports:

```python
"""
End-to-end integration tests for the MyIntegration integration.

These tests call the real MyService API and require a valid access token
set in the MYINTEGRATION_ACCESS_TOKEN environment variable (via .env or export).

Run with:
    pytest myintegration/tests/test_myintegration_integration.py -m "integration and not destructive"

Not collected by default pytest runs or GitHub Actions: the default marker
filter (-m unit) excludes these, and the file naming (test_*_integration.py)
is not matched by python_files. The TeamCity Live Tests build runs the
non-destructive ones.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock
from autohive_integrations_sdk import FetchResponse
from autohive_integrations_sdk.integration import ResultType

from myintegration import myintegration

pytestmark = pytest.mark.integration
```

Use the `importlib` fallback boilerplate from [`unit-tests.md`](unit-tests.md) only when plain imports won't work for the integration's layout.

## Environment Variables

### env_credentials Fixture (preferred)

The repo-wide [`conftest.py`](https://github.com/Autohive-AI/autohive-integrations/blob/master/conftest.py) provides an `env_credentials` fixture that auto-loads the project `.env` and reads variables on demand:

```python
@pytest.fixture
def live_context(env_credentials, make_context):
    api_key = env_credentials("MYINTEGRATION_API_KEY")
    if not api_key:
        pytest.skip("MYINTEGRATION_API_KEY not set — skipping integration tests")
    return make_context(auth={"auth_type": "Custom", "credentials": {"api_key": api_key}})
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
MYINTEGRATION_ACCESS_TOKEN=
MYINTEGRATION_TEST_ITEM_ID=
MYINTEGRATION_TEST_PROJECT_ID=
```

Before finishing, cross-check the integration test file against `.env.example`: every env var referenced in tests must appear in `.env.example`, even if the test skips when it is missing or the variable is optional.

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
    return make_context(auth={"auth_type": "Custom", "credentials": {"api_key": api_key}})
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

## Running Live Tests in TeamCity

The TeamCity **Live Tests** build runs the non-destructive integration tests for pull requests from the Autohive team. It tests each top-level integration directory that the pull request changes, with the same command as a local safe run:

```bash
pytest <integration>/tests/test_*_integration.py -m "integration and not destructive"
```

The build posts one comment on the pull request that shows the result for each integration.

TeamCity does not use `.env`. The tests get their variables from two sources:

1. **Platform OAuth integrations** get an access token automatically (see [Platform OAuth integrations](#platform-oauth-integrations)).
2. All other variables come from **`<integration>/tests/teamcity.env`**, which you commit with the integration. This includes custom auth credentials (see [Custom auth credentials](#custom-auth-credentials)).

The tests must read every credential and test ID from environment variables, including the `<INTEGRATION>_ACCESS_TOKEN` of a platform OAuth integration, and skip cleanly when a variable is missing. Every variable in `teamcity.env` must also be in root `.env.example`.

### What is a secret

**The integrations repository is public.** Everything in `teamcity.env` is public, so the only question is whether a value can be public.

A value is a **secret** if a person who has it can get access to something, or can act as someone. Examples:

- API keys, access tokens, refresh tokens, bot tokens
- Client secrets, consumer secrets, signing secrets, passwords
- Service-role keys and other admin keys
- A URL that contains a credential, or that identifies a private tenant of the test account (for example, a Ghost site URL or a Supabase project URL)

A value is **not a secret** if it gives no access without a credential. Examples:

- IDs of records in the test account (job, contact, project, task, or customer IDs)
- Public or sandbox API base URLs that are the same for all customers
- Fixed test configuration, such as a table name, a function name, or an app name
- Shared support addresses and other public contact details

When you are not sure, treat the value as a secret.

Only use a dedicated test or sandbox account at the provider. Never put a real customer's data or credentials in a test variable.

### Where each value goes

| Value | `teamcity.env` line |
|---|---|
| Not a secret: write the value directly | `JOBADDER_TEST_JOB_ID=21722` |
| A credential that a user enters in Autohive for a **custom auth** integration (a field in `config.json` `auth.fields.properties`) | `NZ_LEGISLATION_API_KEY=ah:customAuth:api_key` |
| Any other secret, for example a bot token, an admin key, a tenant URL, or a credential for an integration that has no custom auth | `AGNO_AGENT_API_TOKEN=ah:secret` |
| The OAuth access token of a **platform OAuth** integration | Do not add a line. The build sets `<INTEGRATION>_ACCESS_TOKEN`. |

For a custom auth credential, use `ah:customAuth` in preference to `ah:secret`. The credential is then supplied the same way that users connect the integration in Autohive.

The real values for `ah:customAuth` and `ah:secret` are stored outside the repository by the Autohive team. You only commit the marker.

### The `teamcity.env` file

**Location:** `<integration>/tests/teamcity.env`, next to the test files. For example, `nz-legislation/tests/teamcity.env`. Each integration has its own file. There is no file at the repository root.

**Format:**

```bash
# Comment lines and blank lines are ignored.
NAME=value
```

- Write one `NAME=value` on each line.
- `NAME` must match `[A-Z][A-Z0-9_]*`. Use the exact name that the tests read.
- The build trims spaces around the name and the value. It removes one pair of matching quotes around the value (`"..."` or `'...'`).
- Do not use `export`, `${VAR}` expansion, or comments at the end of a line. A `#` after the `=` is part of the value.
- If a line is not in this format, the build does not run that integration's tests. It reports `Could not read tests/teamcity.env (line N is not NAME=value with an upper-case name)`.
- Every name in the file must also be in the root `.env.example`.

For optional fixtures that are not ready yet, add the line as a comment and explain what it enables:

```bash
# Optional fixtures: set only for a dedicated test account.
# GHOST_TEST_POST_ID=
```

### Plain values

Write the value directly. The build gives it to pytest without a change.

```bash
JOBADDER_API_URL=https://sandboxapi.jobadder.com/v2
JOBADDER_TEST_JOB_ID=21722
```

A test ID belongs to the provider account that created it. Use IDs from the same test account whose credentials the build uses. If you do not, the tests will find no records.

### Custom auth credentials

Use `ah:customAuth:<field>` for an integration whose `config.json` has `"auth": {"type": "custom", ...}`. `<field>` is a key in `auth.fields.properties`:

```json
"auth": {
  "type": "custom",
  "title": "New Zealand Legislation API key",
  "fields": {
    "type": "object",
    "properties": {
      "api_key": {"type": "string", "format": "password", "label": "API key"}
    }
  }
}
```

```bash
NZ_LEGISLATION_API_KEY=ah:customAuth:api_key
```

The build sets each variable to that field of the test credentials that the Autohive team connected for the integration's custom auth. The integration does not have to be published.

#### First-time setup

1. Add the `ah:customAuth` lines to `tests/teamcity.env` and open the pull request.
2. The first build reports that no connection exists for the auth definition's `title`. This result is expected.
3. Ask the Autohive team to connect the test account's credentials for the integration, then run the build again.

#### Rules

- Every `<field>` must be in `auth.fields.properties`. If it is not, the build reports `tests/teamcity.env asks for custom auth fields config.json does not declare`.
- If you use `ah:customAuth` in an integration whose auth type is not `custom`, the build reports `tests/teamcity.env uses ah:customAuth but config.json does not declare custom auth`.
- If the connected credentials have no value for a requested field, the integration does not run and the build names the field.
- **If a pull request changes `auth.title` or `auth.fields`, the credentials must be connected again** before the tests can pass. Ask the Autohive team when you change the auth definition.

### Other secrets

Use `ah:secret` for secrets that a custom auth connection does not hold.

```bash
AGNO_AGENT_API_TOKEN=ah:secret
```

The build reads the value from the Autohive team's secret store, by the integration's directory name and the variable name.

#### First-time setup

1. Add the `ah:secret` lines to `tests/teamcity.env`.
2. Ask the Autohive team to add each secret for the integration. Give them the integration directory name and the variable names, and send the test-account values through a secure channel.
3. Never put a real value in a commit, a pull request, an issue, or a chat message.

If a secret has not been added, the integration does not run and the build names the missing variable.

### Platform OAuth integrations

For an integration with `"auth": {"type": "platform", "provider": "<Provider>"}`, the build supplies an access token as `<INTEGRATION>_ACCESS_TOKEN`. `<INTEGRATION>` is the directory name in upper case, with each character that is not a letter or a digit changed to `_`. For example, `google-calendar` becomes `GOOGLE_CALENDAR_ACCESS_TOKEN`.

- The tests must read that exact variable name.
- Do not add `<INTEGRATION>_ACCESS_TOKEN` to `teamcity.env`. The build ignores it, uses its own token, and writes a warning in the build log.
- If the build cannot get a token for the provider, the integration does not run. Ask the Autohive team to connect a test account for the provider.
- Other variables that a platform OAuth integration's tests need, such as test IDs, go in `teamcity.env` as usual.

### Reading the result

The pull request comment has one collapsible block for each integration:

| Summary | Meaning |
|---|---|
| `N/N tests pass` | All tests that ran passed. Skipped tests are counted and listed. |
| `M/N tests pass` with a cross | One or more tests failed. The failed tests are listed. |
| `did not run` | A problem before or outside the tests. The block shows the reason, for example a malformed `teamcity.env`, a missing secret or connection, or failed dependency installation. The build fails. |
| `all N tests were skipped` | The tests skipped, usually because a variable is missing. The build does **not** fail. Check that `teamcity.env` sets every variable that the tests need. |
| `no live tests ran` | Every live test is marked `destructive`, so the build collected none. |

The comment shows only test names. Assertion messages and skip reasons are in the TeamCity build. The build never prints the values of credentials.

## Workflow

1. **Read the integration source** — understand each action and its auth mechanism
2. **Check `config.json`** — determine auth type (none / API key / platform OAuth)
3. **Choose the right `live_context` variant** — see the three variants above
4. **Document env vars in root `.env.example` (required)** — add every env var referenced by the integration test file in the same PR; missing entries should block integration-test PRs
5. **Add `tests/teamcity.env`** — see [Running Live Tests in TeamCity](#running-live-tests-in-teamcity)
6. **Write read-only tests first** — these are safe to run repeatedly
7. **Add destructive tests** with `@pytest.mark.destructive` for write actions
8. **Run read-only tests**:
   ```bash
   pytest <integration>/tests/test_*_integration.py -m "integration and not destructive"
   ```
9. **Run destructive tests** (only when you're sure):
   ```bash
   pytest <integration>/tests/test_*_integration.py -m "integration and destructive"
   ```
10. **Document the run commands** in the PR description and the integration's
   README — safe (`-m "integration and not destructive"`) command first,
   destructive command second with a warning. Never recommend the bare
   `-m integration` form as the primary command.

## Common Gotchas

1. **content_type=None in resp.json()**: Some APIs return JSON without a proper `Content-Type` header. Always use `await resp.json(content_type=None)` in the `real_fetch` function to avoid `ContentTypeError`.

2. **Test isolation**: Each test creates a new `aiohttp.ClientSession`. This is intentional — integration tests should not share session state.

3. **Rate limiting**: If the API has rate limits, add a small `asyncio.sleep` between tests or reduce the number of tests that hit the same endpoint.

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
