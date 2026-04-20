---
name: upgrading-sdk-v2
description: "Upgrades an Autohive integration from SDK 1.0.x or 1.1.x to 2.0.0. Use when asked to upgrade, migrate, or update an integration's SDK version to v2. Covers source code, tests, requirements.txt, and config.json version bump."
---

# Upgrading an Integration to SDK 2.0.0

## The Breaking Change

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

For every `context.fetch()` call site:

1. If the result is used as a dict/list (accessing keys, iterating), add `.data`
2. If the result is returned directly or passed to `ActionResult(data=...)`, add `.data`
3. If the result is checked with `isinstance()`, check `.data` instead
4. If the result is stored then accessed later, trace all access points

**Do NOT change:**
- Error handling (`try/except`) — exceptions are raised the same way
- The `context.fetch()` call signature — parameters are unchanged
- `ActionResult`, `ActionError`, `ActionHandler` — unchanged

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

Add the `FetchResponse` import at the top of the test file:

```python
from autohive_integrations_sdk import FetchResponse  # noqa: E402
```

Place this import next to the existing SDK imports (e.g. `ValidationError`).

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

### Step 7 — Verify

Run the unit tests to confirm everything passes:

```bash
source .venv/bin/activate
uv pip install -r <integration>/requirements.txt
pytest <integration>/
```

If integration tests exist, run those too:

```bash
pytest <integration>/tests/test_*_integration.py -m integration
```

### Step 8 — Lint and format

```bash
ruff check --fix <integration>
ruff format --config ../autohive-integrations-tooling/ruff.toml <integration>
```

## Checklist

Before considering an integration upgraded, verify:

- [ ] All `context.fetch()` return values access `.data` for the body
- [ ] `requirements.txt` pins `autohive-integrations-sdk~=2.0.0`
- [ ] `config.json` version is bumped to `2.0.0`
- [ ] Unit test mocks wrap return values in `FetchResponse(...)`
- [ ] Integration test `real_fetch` returns `FetchResponse(...)` (if applicable)
- [ ] `FetchResponse` is imported where needed
- [ ] All unit tests pass
- [ ] Lint and format pass

## Common Gotchas

1. **Helper functions that return fetch results**: If a helper like `fetch_json()` returns `await context.fetch(url)`, every caller of that helper is affected. Either update the helper to return `.data`, or update all callers — pick one, be consistent.

2. **Connected account handlers**: These also use `context.fetch()`. Don't forget to update `get_account_info()` methods.

3. **Chained fetches**: Some integrations fetch a resource, extract an ID, then fetch again. Trace the full chain — the first `.data` access often cascades.

4. **Response used as ActionResult data directly**: `ActionResult(data=response)` becomes `ActionResult(data=response.data)`. The response object itself is not serializable.

5. **`None` return values**: Some integrations check `if not response:` after fetch. With `FetchResponse`, this check needs to be `if response is None:` or `if response.data is None:` depending on intent.

6. **Tests with `return_value = None`**: If the integration code checks `if not result:` after a fetch wrapped in try/except that returns `None` on failure, keep the mock as `None` — the code never reaches `.data` on that path.
