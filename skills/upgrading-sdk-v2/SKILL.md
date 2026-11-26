---
name: upgrading-sdk-v2
description: "Upgrades an Autohive integration from SDK 1.x or 2.0.x to released SDK 2.1.0. Use when asked to upgrade or update an integration's SDK version to v2 or 2.1. Covers FetchResponse, wrapped auth, error headers, tests, requirements.txt, and the integration version bump."
---

# Upgrade an integration to SDK 2.1.0

Target `autohive-integrations-sdk~=2.1.0` (`>=2.1.0,<2.2.0`). Use the [released 2.1.0 source](https://github.com/Autohive-AI/integrations-sdk/tree/2.1.0/src/autohive_integrations_sdk) and [release notes](https://github.com/Autohive-AI/integrations-sdk/blob/2.1.0/RELEASENOTES.md), not unreleased `master` behavior. Do not perform an SDK upgrade as part of a pure private-to-public move; preserve the pin and behavior there and scope this work separately.

## Changes to account for

### SDK 1.1.0 — ActionError (adopt during upgrade)

SDK 1.1.0 introduced `ActionError`, a dedicated error return type that bypasses output schema validation. During an upgrade from 1.0.x, convert error-only `ActionResult` returns to `ActionError`. For integrations already using it, preserve that behavior.

```python
from autohive_integrations_sdk import ActionError

# Before — 1.0.x error pattern (fails output schema validation)
return ActionResult(data={"error": str(e)}, cost_usd=0.0)
return ActionResult(data={"result": False, "error": str(e), "items": []}, cost_usd=0.0)

# After — ActionError (returns ResultType.ACTION_ERROR, skips schema validation)
return ActionError(message=str(e))

# After — ActionError with cost (when a billable API call was made before the error)
return ActionError(message=str(e), cost_usd=0.01)
```

`ActionError` is a dataclass, not an exception — **return it, do not raise it.**

Convert ALL of these patterns:
- `return ActionResult(data={"error": ...})` → `return ActionError(message=...)`
- `return ActionResult(data={"result": False, "error": ..., <extra keys>})` → `return ActionError(message=...)` (extra keys like `"items": []` are dropped — ActionError only carries a message)
- Exception catch blocks: `return ActionResult(data={"error": str(e)})` → `return ActionError(message=str(e))`
- Cost-bearing error paths: `return ActionResult(data={"error": str(e)}, cost_usd=0.01)` → `return ActionError(message=str(e), cost_usd=0.01)` — preserve the cost so billing is accurate

### SDK 2.0.0 — FetchResponse (breaking change)

SDK 2.0.0 has **one breaking change**: `context.fetch()` now returns a `FetchResponse` object instead of the parsed body directly.

```python
# SDK 1.x — fetch() returns dict/list/str (the body)
response = await context.fetch(url)
response["key"]              # response IS the body

# SDK 2.0.0 — fetch() returns FetchResponse
response = await context.fetch(url)
response.data["key"]         # body is at .data
response.status              # HTTP status code (new)
response.headers             # response headers (new)
```

The `FetchResponse` dataclass:

```python
@dataclass
class FetchResponse:
    status: int                # e.g. 200, 201, 204
    headers: Dict[str, str]    # response headers
    data: Any                  # parsed JSON body, raw text, or None
```

`fetch()` raises for HTTP errors rather than returning an error-status `FetchResponse`. The wrapper's fields describe successful responses; use exceptions to test failure paths.

### SDK 2.0.1 — wrapped auth validation

The platform passes `context.auth` as `{"auth_type": "Custom", "credentials": {...}}`. Since 2.0.1, the SDK validates the inner `credentials` object against `auth.fields`, not the envelope. Keep `auth.fields.required`, wrap local test credentials, and read credentials through `context.auth["credentials"]`. Missing required fields produce `ResultType.VALIDATION_ERROR` with `result.result["source"] == "auth"` before the handler runs.

### SDK 2.1.0 — headers on HTTP exceptions

`HTTPError` and `RateLimitError` expose `exc.headers`. The optional constructor argument is keyword-only, existing positional calls still work, and omitted headers default to `{}`. Header names in this plain dictionary must be matched case-insensitively. If a caller needs a provider override code, disclose only that selected value after checking the status and provider semantics:

```python
from autohive_integrations_sdk import ActionError, HTTPError

try:
    await context.fetch(url, method="PUT", json=body)
except HTTPError as exc:
    code = next(
        (value for name, value in exc.headers.items() if name.lower() == "x-allow-duplicates"),
        None,
    )
    if exc.status == 409 and code:
        return ActionError(message=f"{exc}. Retry with allow_duplicates={code} if intended.")
    raise
```

This is an opt-in provider-specific use, not a reason to return or log every header. `str(exc)` remains `HTTP {status}: {message}` and does not include headers. `RateLimitError.retry_after` and fetch retry behavior are unchanged: HTTP 429 raises immediately, while transient network errors retain the existing retries.

## Upgrade Workflow

Read the current pin first. For a 2.0.x integration, verify the existing `FetchResponse` and `ActionError` handling rather than rewriting it. The auth and test corrections still apply when upgrading from 2.0.0.

### Step 1 — Read the integration source

Read the main Python file and understand how `context.fetch()` is used. Common patterns:

| 1.x pattern | 2.x pattern |
|---|---|
| `response = await context.fetch(url)` then `response["key"]` | `response = await context.fetch(url)` then `response.data["key"]` |
| `response = await context.fetch(url)` then `response.get("key", default)` | `response = await context.fetch(url)` then `response.data.get("key", default)` |
| `return await context.fetch(url)` (returning body directly) | `return (await context.fetch(url)).data` |
| `data = await context.fetch(url)` then `ActionResult(data=data)` | `response = await context.fetch(url)` then `ActionResult(data=response.data)` |
| `isinstance(response, list)` | `isinstance(response.data, list)` |

### Step 2 — Update the source code

**A. FetchResponse — add `.data` to all fetch call sites:**

For every `context.fetch()` call site:

1. If the result is used as a dict/list (accessing keys, iterating), add `.data`
2. If the result is returned directly or passed to `ActionResult(data=...)`, add `.data`
3. If the result is checked with `isinstance()`, check `.data` instead
4. If the result is stored then accessed later, trace all access points
5. If the result is checked with `hasattr(response, "status_code")` or `hasattr(response, "json")`, replace with `.status` and `.data` — `FetchResponse` always has these fields

**B. ActionError — convert all error returns:**

1. Add `ActionError` to the SDK import: `from autohive_integrations_sdk import ..., ActionError`
2. Convert every `return ActionResult(data={"error": ...})` to `return ActionError(message=...)`
3. Convert every `return ActionResult(data={"result": False, "error": ...})` to `return ActionError(message=...)`
4. Convert every `except Exception as e: return ActionResult(data={"error": str(e)})` to `return ActionError(message=str(e))`
5. Remove the `"error"` property (and any `"result": bool` property used only for error signalling) from each action's output schema in `config.json` — these fields are no longer returned in the action output

**C. Verify auth handling:**

1. Keep the credential schema under `config.json` `auth.fields`; do not add envelope keys there.
2. Declare credential keys under `properties` and require the ones handlers need with `required`.
3. Read custom credentials from `context.auth["credentials"]`, not flat `context.auth` keys.
4. Use the same wrapped shape in tests and manual `ExecutionContext` construction.

**Keep unchanged:**
- Retry policy — 2.1.0 does not add retries for HTTP 429 or other HTTP failures
- The `context.fetch()` call signature — parameters are unchanged
- `ActionResult`, `ActionHandler` — unchanged

Inspect `exc.status` for HTTP failures. Use `exc.headers` only where the integration needs a specific provider header; `.status` and `.headers` on a successful `FetchResponse` are not a substitute for catching exceptions.

### Step 3 — Update requirements.txt

Change the SDK pin:

```
# Before
autohive-integrations-sdk~=1.0.2

# After
autohive-integrations-sdk~=2.1.0
```

Keep all other dependencies unchanged. An existing `~=2.0.0` range accepts 2.0.x only, not 2.1.0; change it explicitly for this upgrade.

### Step 4 — Bump config.json version

For a 1.x SDK upgrade that changes action/error contracts, increment the integration's own major version, for example:

```json
// Before
"version": "1.0.1"

// After
"version": "2.0.0"
```

Use the next major of the integration's current version; do not reset a higher integration version to `2.0.0`. For a compatible 2.0.x → 2.1.0 dependency-only update, a patch bump is appropriate. Auth or action contract changes can require a larger bump; review the actual diff and HiveUp's recommendation.

This step applies to existing integrations. A new integration written against SDK 2.1.0 starts at `"version": "1.0.0"`; its version reflects its release history, not the SDK version.

### Step 5 — Update unit tests (if they exist)

**A. Wrap fetch mocks in FetchResponse:**

Unit tests that mock `context.fetch` must return `FetchResponse` instead of bare dicts.

```python
from autohive_integrations_sdk import FetchResponse

# Before — 1.x mock
mock_context.fetch.return_value = {"id": 123, "name": "Test"}

# After — 2.x mock
mock_context.fetch.return_value = FetchResponse(
    status=200,
    headers={},
    data={"id": 123, "name": "Test"},
)
```

For every `mock_context.fetch.return_value = ...` in the test file:
1. Wrap the existing value in `FetchResponse(status=200, headers={}, data=...)`
2. Match successful status codes, such as 201 for creation and 204 with `data=None` for empty deletion responses
3. For HTTP failures, set `side_effect` to `HTTPError(...)` or `RateLimitError(...)`, with `headers={...}` when testing 2.1.0 header handling
4. A successful SDK fetch does not return bare `None`. Keep `None` only for a separately tested helper that explicitly catches failures and returns it
5. Preserve other exception mocks when they represent the implementation's failure path

**B. Update error assertions for ActionError:**

Error paths now return `ActionError` instead of `ActionResult` with error data. Test assertions must change:

```python
from autohive_integrations_sdk import FetchResponse, ResultType  # noqa: E402

# Before — 1.0.x error assertion
result = await integration.execute_action("some_action", inputs, mock_context)
assert result.result.data["error"] == "Not found"
assert result.result.data["result"] is False

# After — ActionError assertion
result = await integration.execute_action("some_action", inputs, mock_context)
assert result.type == ResultType.ACTION_ERROR
assert "Not found" in result.result.message
```

**C. Assert action result types and validation results:**

Check `result.type == ResultType.ACTION` before accessing successful `result.result.data`. `execute_action` returns schema failures as `IntegrationResult(type=ResultType.VALIDATION_ERROR)` rather than raising them:

```python
# Before — 1.0.x
with pytest.raises(ValidationError):
    await integration.execute_action("some_action", bad_inputs, mock_context)

# After — released 2.x
result = await integration.execute_action("some_action", bad_inputs, mock_context)
assert result.type == ResultType.VALIDATION_ERROR
assert result.result["source"] == "input"
```

Remove unused `ValidationError` imports and add `ResultType` where needed. For custom auth, add an `execute_action` success test with wrapped credentials and a missing-required-credential test that asserts `VALIDATION_ERROR`, source `auth`, and no fetch call. See the [unit-test reference](../writing-tests/unit-tests.md).

### Step 6 — Update integration tests (if they exist)

Use the real SDK `ExecutionContext` for live tests, including when replacing an existing aiohttp `real_fetch` wrapper. That preserves released HTTP error, response parsing, OAuth injection, and rate-limit behavior, and closes the session after the test:

```python
import pytest
import pytest_asyncio
from autohive_integrations_sdk import ExecutionContext

@pytest_asyncio.fixture
async def live_context(env_credentials):
    api_key = env_credentials("MYINTEGRATION_API_KEY")
    if not api_key:
        pytest.skip("MYINTEGRATION_API_KEY not set")
    auth = {"auth_type": "Custom", "credentials": {"api_key": api_key}}
    async with ExecutionContext(auth=auth) as context:
        yield context
```

Adapt the credentials to `config.json`; use `{}` for no auth or `PlatformOauth2` with `credentials.access_token` for platform OAuth. The repo's `make_context` fixture is a mock factory, not a live HTTP context. See the [integration-test reference](../writing-tests/integration-tests.md) for each auth mode.

If the integration tests read credentials or test resource IDs from environment variables, also verify the repository root `.env.example` lists every variable used by those tests. Add missing entries in the same PR. This applies to variables read through `env_credentials(...)`, `os.environ.get(...)`, `os.getenv(...)`, `os.environ[...]`, or equivalent helpers. Required credentials, optional test IDs, and destructive-test-only variables all count. The local `.env` file remains uncommitted; `.env.example` is the committed setup contract for humans and tooling. Missing entries should block SDK-upgrade PRs that add or change integration tests.

### Step 7 — Local validation (required before pushing)

Install the Python HiveUp CLI (Python 3.13+) using the [local-build instructions](https://github.com/Autohive-AI/autohive-integrations-tooling#install-hiveup-from-a-local-build); it is **not published to PyPI**. Run from the integrations repository root. Replace `<integration>` with the integration directory and `<base-ref>` with its fetched PR target ref.

**A. Apply supported Ruff fixes:**

```bash
hiveup validate --only lint,format --fix <integration>
```

HiveUp uses its bundled CI Ruff configuration. For standalone Ruff, pass `--config ../autohive-integrations-tooling/ruff.toml` to both lint and format commands when the checkout is a sibling.

**B. Run unit tests:**

```bash
hiveup test <integration>
```

**C. Run read-only integration tests (if present and credentials are available):**

```bash
python -m pytest <integration>/tests/test_*_integration.py -m "integration and not destructive" -v
```

Use a local Python 3.13+ venv with the integration's requirements and the repository's test dependencies installed for live pytest runs. Run destructive tests only deliberately against a dedicated test account, using `-m "integration and destructive"`.

**D. Run the full validation profile:**

```bash
hiveup validate --base-ref <base-ref> <integration>
```

This includes structure, syntax, imports, JSON, lint, format, security, audit, sync, fetch, unit tests, README, and version checks. History checks need a resolvable base ref; do not assume a branch name. Report skipped checks and test counts, not just the exit code. For details, read [building-integration](../building-integration/SKILL.md).

**E. Fetch pattern linter caveat:**

`hiveup check fetch <integration>` uses AST tracking of variables assigned from `context.fetch(...)`; it is not a regex check tied to the name `response`. Trace helper return values yourself, because the check does not follow every helper or alias across functions.

## Checklist

Before considering an integration upgraded, verify:

- [ ] All `context.fetch()` return values access `.data` for the body
- [ ] All error paths return `ActionError(message=...)` instead of `ActionResult` with error data
- [ ] `ActionError` is imported from the SDK
- [ ] `"error"` and error-only `"result"` properties removed from output schemas in `config.json`
- [ ] `requirements.txt` pins `autohive-integrations-sdk~=2.1.0`
- [ ] The integration's own version increases appropriately (new integrations start at `1.0.0`)
- [ ] Unit test mocks wrap return values in `FetchResponse(...)`
- [ ] HTTP failure mocks raise SDK exceptions; selected error-header tests cover case-insensitive lookup without blanket disclosure
- [ ] Auth fixtures use the wrapped envelope; `auth.fields` describes inner credentials and keeps required fields
- [ ] Missing required credentials return `VALIDATION_ERROR` with source `auth` before any fetch
- [ ] Success assertions check `ResultType.ACTION` before reading data
- [ ] Unit test error assertions use `result.type == ResultType.ACTION_ERROR` and `result.result.message`
- [ ] `pytest.raises(ValidationError)` replaced with `result.type == ResultType.VALIDATION_ERROR`
- [ ] Live tests use a real `ExecutionContext` with session cleanup, not an aiohttp fetch replacement
- [ ] Integration test env vars are documented in root `.env.example` (if integration tests read env vars, including optional and destructive-test-only variables)
- [ ] `FetchResponse` and `ResultType` are imported where needed
- [ ] All unit tests pass
- [ ] `hiveup validate --base-ref <base-ref> <integration>` passes; warnings and skips are reviewed

## Common Gotchas

1. **Helper functions that return fetch results**: If a helper like `fetch_json()` returns `await context.fetch(url)`, every caller of that helper is affected. Either update the helper to return `.data`, or update all callers — pick one, be consistent.

2. **Connected account handlers**: These also use `context.fetch()`. Don't forget to update `get_account_info()` methods.

3. **Chained fetches**: Some integrations fetch a resource, extract an ID, then fetch again. Trace the full chain — the first `.data` access often cascades.

4. **Response used as ActionResult data directly**: `ActionResult(data=response)` becomes `ActionResult(data=response.data)`. The response object itself is not serializable.

5. **Empty response bodies**: A successful fetch still returns a `FetchResponse`. Check `response.data is None` for an empty body; `if not response` does not test the body.

6. **Tests with `return_value = None`**: Reserve this for a helper whose contract explicitly returns `None` on failure. Direct SDK fetch mocks use `FetchResponse(..., data=None)` for empty successes or `side_effect` for failures.

7. **Fetch-check scope**: The AST check tracks direct assignments from `context.fetch`. Inspect helpers and connected-account paths manually rather than relying only on the check.

8. **Ruff config mismatch**: Use HiveUp's bundled lint/format checks, or pass the Tooling `ruff.toml` to standalone Ruff to match CI's 120-character line length.

9. **Audit auth lookup defaults during the upgrade**: 1.0.x integrations sometimes shipped with the wrong default type in their auth lookup, e.g. `context.auth.get("credentials", {}).get("api_key", {})`. The default `{}` returns a dict when the field is unset, which then crashes the upstream API client that expects a string — surfacing as a Lambda 500 / Raygun crash rather than the user-facing auth error it actually is. Fix to a string default that matches the field type:

    ```python
    # Before — returns {} on missing field, crashes upstream SDK with TypeError
    api_key = context.auth.get("credentials", {}).get("api_key", {})

    # After — use a string default for an optional string credential
    api_key = context.auth["credentials"].get("api_key", "")
    ```

    Required credentials belong in `auth.fields.required`; in SDK 2.1.0, a missing required credential fails validation before an upstream client is called. Defaults are for optional fields, not a way to bypass required auth validation.

10. **PyPI package name collision**: If your integration folder name matches a PyPI package the source imports (e.g. an integration in `supadata/` that does `from supadata import Supadata`), an empty `<integration>/__init__.py` will shadow the real PyPI package and every test fails with `ImportError`. Drop `<integration>/__init__.py` — the validator's "missing __init__.py" warning is correct to ignore in this case, and the Lambda runtime is unaffected (the entry point is the action source file, not the package). See `unit-tests.md` in the `writing-tests` skill for the matching test-side guidance.

11. **Missing `.env.example` entries after touching integration tests**: SDK upgrades often touch `live_context` and credential handling. If the integration test file references `FOO_ACCESS_TOKEN`, `FOO_TEST_ID`, or similar, root `.env.example` must contain `FOO_ACCESS_TOKEN=`, `FOO_TEST_ID=`, etc. Optional IDs and destructive-test-only variables count too. Do not rely on future contributors or automation to grep test code for setup requirements; missing entries should block PRs that add or change those tests.
