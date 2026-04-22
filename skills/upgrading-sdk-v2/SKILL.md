---
name: upgrading-sdk-v2
description: "Upgrades an Autohive integration from SDK 1.0.x or 1.1.x to 2.0.0. Use when asked to upgrade, migrate, or update an integration's SDK version to v2. Covers source code, tests, requirements.txt, and config.json version bump."
---

# Upgrading an Integration to SDK 2.0.0

## What Changed Between 1.0.x and 2.0.0

### SDK 1.1.0 — ActionError (adopt during upgrade)

SDK 1.1.0 introduced `ActionError`, a dedicated error return type that bypasses output schema validation. Integrations still on 1.0.x never adopted it. **During the 2.0.0 upgrade, also convert all error paths to use `ActionError`.**

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
    status: int                # e.g. 200, 201, 404
    headers: Dict[str, str]    # response headers
    data: Any                  # parsed JSON body, raw text, or None
```

## Upgrade Workflow

For each integration, follow these steps **in order**. Do not skip steps.

### Step 1 — Read the integration source

Read the main Python file and understand how `context.fetch()` is used. Common patterns:

| 1.x Pattern | 2.0.0 Pattern |
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

**Do NOT change:**
- Error handling (`try/except`) — exceptions are raised the same way
- The `context.fetch()` call signature — parameters are unchanged
- `ActionResult`, `ActionHandler` — unchanged

**Optionally leverage** `.status` and `.headers` for richer error handling if the integration currently parses status from exception messages.

### Step 3 — Update requirements.txt

Change the SDK pin:

```
# Before
autohive-integrations-sdk~=1.0.2

# After
autohive-integrations-sdk~=2.0.0
```

Keep all other dependencies unchanged.

### Step 4 — Bump config.json version

Increment the **major** version since the SDK dependency is a breaking change:

```json
// Before
"version": "1.0.1"

// After
"version": "2.0.0"
```

If the integration was already at a higher version (e.g. `1.1.0`), bump to `2.0.0`.

### Step 5 — Update unit tests (if they exist)

**A. Wrap fetch mocks in FetchResponse:**

Unit tests that mock `context.fetch` must return `FetchResponse` instead of bare dicts.

```python
from autohive_integrations_sdk import FetchResponse

# Before — 1.x mock
mock_context.fetch.return_value = {"id": 123, "name": "Test"}

# After — 2.0.0 mock
mock_context.fetch.return_value = FetchResponse(
    status=200,
    headers={},
    data={"id": 123, "name": "Test"},
)
```

For every `mock_context.fetch.return_value = ...` in the test file:
1. Wrap the existing value in `FetchResponse(status=200, headers={}, data=...)`
2. For error scenarios returning non-200 responses, use the appropriate status code
3. For `return_value = None` (simulating fetch failure), keep as `None` — the integration handles this before accessing `.data`
4. For `side_effect = Exception(...)` mocks, keep unchanged — exceptions bypass `FetchResponse`

**B. Update error assertions for ActionError:**

Error paths now return `ActionError` instead of `ActionResult` with error data. Test assertions must change:

```python
from autohive_integrations_sdk import FetchResponse, ResultType  # noqa: E402

# Before — 1.0.x error assertion
result = await integration.execute_action("some_action", inputs, mock_context)
assert result.result.data["error"] == "Not found"
assert result.result.data["result"] is False

# After — 2.0.0 ActionError assertion
result = await integration.execute_action("some_action", inputs, mock_context)
assert result.type == ResultType.ACTION_ERROR
assert "Not found" in result.result.message
```

**C. Replace `pytest.raises(ValidationError)` with result type checks:**

SDK 2.0.0 changed `execute_action` to no longer raise `ValidationError`. It now returns an `IntegrationResult` with `type=ResultType.VALIDATION_ERROR`:

```python
# Before — 1.0.x
with pytest.raises(ValidationError):
    await integration.execute_action("some_action", bad_inputs, mock_context)

# After — 2.0.0
result = await integration.execute_action("some_action", bad_inputs, mock_context)
assert result.type == ResultType.VALIDATION_ERROR
```

Remove `ValidationError` imports and add `ResultType` where needed.

### Step 6 — Update integration tests (if they exist)

Integration tests (`test_*_integration.py`) that use a `live_context` fixture with a real HTTP client need to return `FetchResponse` from their `real_fetch` function:

```python
from autohive_integrations_sdk import FetchResponse

async def real_fetch(url, *, method="GET", json=None, headers=None, **kwargs):
    async with aiohttp.ClientSession() as session:
        async with session.request(method, url, json=json, headers=headers) as resp:
            data = await resp.json(content_type=None)
            return FetchResponse(
                status=resp.status,
                headers=dict(resp.headers),
                data=data,
            )
```

### Step 7 — Local validation (required before pushing)

Run the **same checks CI runs** locally. Skipping this step will result in CI failures. The tooling repo must be cloned alongside the integrations repo (see [CONTRIBUTING.md](CONTRIBUTING.md) for setup).

**A. Lint and format (must use the CI ruff config):**

```bash
ruff check --fix <integration>
ruff format --config ../autohive-integrations-tooling/ruff.toml <integration>
```

⚠️ **Always use `--config ../autohive-integrations-tooling/ruff.toml`** for formatting. The tooling config uses `line-length = 120`. Running `ruff format` without it uses the default 88-char width and will fail CI.

**B. Run unit tests:**

```bash
source .venv/bin/activate
python -m pytest <integration>/tests/test_*_unit.py -v
```

**C. Run integration tests (if they exist and credentials are available):**

```bash
python -m pytest <integration>/tests/test_*_integration.py -m integration -v
```

**D. Run the CI validation scripts:**

```bash
python ../autohive-integrations-tooling/scripts/validate_integration.py <integration>
python ../autohive-integrations-tooling/scripts/check_code.py <integration>
```

These scripts run the same checks as CI — structure validation, config-code sync, fetch pattern linting, import checks, bandit security scan, and pip-audit. Fix any issues they report before pushing.

**E. Fetch pattern linter caveat:**

The CI fetch pattern linter (`check_fetch_pattern.py`) does a **naive regex match** on variables named `response` accessed with `.get()` or `["..."]`. If a helper function (like `execute_graphql()`) already returns `response.data`, callers hold a plain dict in a variable named `response` — the linter will false-positive on this. Fix by renaming the variable (e.g. `gql_result`, `body`, `data`).

## Checklist

Before considering an integration upgraded, verify:

- [ ] All `context.fetch()` return values access `.data` for the body
- [ ] All error paths return `ActionError(message=...)` instead of `ActionResult` with error data
- [ ] `ActionError` is imported from the SDK
- [ ] `"error"` and error-only `"result"` properties removed from output schemas in `config.json`
- [ ] `requirements.txt` pins `autohive-integrations-sdk~=2.0.0`
- [ ] `config.json` version is bumped to `2.0.0`
- [ ] Unit test mocks wrap return values in `FetchResponse(...)`
- [ ] Unit test error assertions use `result.type == ResultType.ACTION_ERROR` and `result.result.message`
- [ ] `pytest.raises(ValidationError)` replaced with `result.type == ResultType.VALIDATION_ERROR`
- [ ] Integration test `real_fetch` returns `FetchResponse(...)` (if applicable)
- [ ] `FetchResponse` and `ResultType` are imported where needed
- [ ] All unit tests pass
- [ ] `ruff check` and `ruff format --config ../autohive-integrations-tooling/ruff.toml` pass
- [ ] `validate_integration.py` and `check_code.py` pass

## Common Gotchas

1. **Helper functions that return fetch results**: If a helper like `fetch_json()` returns `await context.fetch(url)`, every caller of that helper is affected. Either update the helper to return `.data`, or update all callers — pick one, be consistent.

2. **Connected account handlers**: These also use `context.fetch()`. Don't forget to update `get_account_info()` methods.

3. **Chained fetches**: Some integrations fetch a resource, extract an ID, then fetch again. Trace the full chain — the first `.data` access often cascades.

4. **Response used as ActionResult data directly**: `ActionResult(data=response)` becomes `ActionResult(data=response.data)`. The response object itself is not serializable.

5. **`None` return values**: Some integrations check `if not response:` after fetch. With `FetchResponse`, this check needs to be `if response is None:` or `if response.data is None:` depending on intent.

6. **Tests with `return_value = None`**: If the integration code checks `if not result:` after a fetch wrapped in try/except that returns `None` on failure, keep the mock as `None` — the code never reaches `.data` on that path.

7. **CI fetch pattern linter false positives**: The linter flags any variable named `response` accessed with `.get()` or `["..."]`. If a helper already unwraps `.data` and returns a plain dict, rename the variable in callers to avoid the match (e.g. `gql_result`, `body`, `api_data`).

8. **Ruff config mismatch**: CI uses `../autohive-integrations-tooling/ruff.toml` with `line-length = 120`. Always pass `--config` when formatting or local results will differ from CI.
