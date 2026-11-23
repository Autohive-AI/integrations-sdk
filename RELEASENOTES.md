# Release Notes

## 2.1.1

### Security and reliability fixes

- `ExecutionContext.fetch()` no longer emits provider error bodies, raw URLs,
  response headers, or exception text in its HTTP, parsing, transport-retry,
  or unexpected-error diagnostics. Logs retain method, status where available,
  and a locally generated request identifier. SDK-generated `HTTPError`
  messages are now generic (`HTTP <status>: Request failed`); use
  `response_data` to inspect provider details explicitly rather than parsing
  exception text, and never log or return those details wholesale. Explicit
  `HTTPError(...)` constructor messages remain caller-controlled and unchanged.
- Response headers from 2.1.0 remain available on `HTTPError` and
  `RateLimitError`. Malformed, negative or excessively large `Retry-After`
  values fall back to the existing 60-second rate-limit default without
  exposing the provider header in a parsing exception.
- SDK network retries preserve the original URL, parameters and body, avoiding
  duplicate query options and repeated JSON/form serialization.
- SDK-created aiohttp sessions disable aiohttp's implicit connection replay.
  The SDK retry policy is now authoritative: `max_retries=0`, or starting
  `retry_count` at the configured maximum, also prevents a hidden DELETE
  replay after a server accepted a deletion but disconnected before replying.
  A transport exception still means the write outcome is uncertain; check
  the provider before retrying. SDK defaults still permit network retries;
  write actions must deliberately opt out when replay is inappropriate.
- The supported transport range is `aiohttp>=3.11,<4`. aiohttp currently has no
  public replay-control option, so the SDK isolates its per-session private
  `_retry_connection` compatibility dependency and fails closed if that
  control is unavailable. Real loopback tests cover connection reuse,
  accepted DELETE disconnects and SDK-controlled GET backoff.

### Adoption

Use `autohive-integrations-sdk~=2.1.1` for the patched supported 2.x baseline.
`~=2.0.1` does not select 2.1.x. The integration's encode-once workaround remains
valid and can be retained as a defense while consumers adopt the SDK fix.
Regenerate and validate deployment packages after dependency changes.

## 2.1.0

### New Feature

`HTTPError` and `RateLimitError` now keep the response headers from the
failed request. `ExecutionContext.fetch()` already exposed headers on
successful `FetchResponse` objects; it now also sets `exc.headers` when it
raises. Integrations can read provider headers that are needed to handle a
failure, for example the `X-Allow-Duplicates` override code that JobAdder
returns with HTTP 409.

```python
try:
    await context.fetch(url, method="PUT", json=body)
except HTTPError as exc:
    code = next(
        (v for k, v in exc.headers.items() if k.lower() == "x-allow-duplicates"),
        None,
    )
    if exc.status == 409 and code:
        return ActionError(message=f"{exc}. Retry with allow_duplicates={code} if intended.")
    raise
```

### Compatibility

- `headers` is an optional, keyword-only constructor argument. Existing
  `HTTPError(status, message, response_data)` calls are unchanged, and
  `exc.headers` is `{}` when no headers are given.
- The exception message is unchanged (`HTTP {status}: {message}`). Headers are
  never added to `str(exc)`, so they do not reach the platform error result,
  logs or the agent unless an integration returns them on purpose. Return only
  the specific header values a caller needs, and match header names
  case-insensitively.
- `RateLimitError.retry_after` and the retry behaviour of `fetch()` are
  unchanged.

## 2.0.1

### Behavior Change

Auth validation now expects the platform auth envelope only. Flat auth is no
longer accepted. Production runtime behavior is unchanged (the platform has
always sent the envelope); this release fixes the SDK to validate the object
production actually sends. Local tests and scripts that construct flat auth
contexts must migrate to the wrapped shape.

The platform delivers integration auth as a wrapped envelope:

```json
{"auth_type": "Custom", "credentials": {"api_key": "...", "api_url": "..."}}
```

The `auth.fields` schema in `config.json` describes the inner `credentials`
object. Previously the SDK validated the *entire* envelope against
`auth.fields`, so any non-empty `required` list failed before the handler ran
(the ActiveCampaign outage), while an empty `required` list passed vacuously
even with empty credentials.

As of 2.0.1 the SDK validates only `context.auth["credentials"]` against
`auth.fields`. `auth.fields.required` is now honoured and recommended. If
`context.auth` is not a wrapped envelope with a `credentials` dict, validation
fails with a `VALIDATION_ERROR` whose `source` is `"auth"`.

**Before (2.x local test):**
```python
ctx = ExecutionContext(auth={"api_key": "..."})  # flat
```

**After (2.0.1):**
```python
ctx = ExecutionContext(auth={"auth_type": "Custom", "credentials": {"api_key": "..."}})
```

### Migration Guide

1. **Wrap auth in local tests and any manual `ExecutionContext` construction**
   in the `{"auth_type": ..., "credentials": {...}}` envelope. Production
   traffic is already wrapped by the platform.
2. **Read credentials directly from the envelope** via
   `context.auth["credentials"]`:
   ```python
   # Before
   api_key = context.auth.get("api_key", "")
   # After
   api_key = context.auth["credentials"].get("api_key", "")
   ```
3. **Keep `auth.fields.required`** — it is now enforced against the credentials
   object and is the recommended way to require credentials.
4. **Note on pins:** `~=2.0.0` pins resolve to 2.0.1 automatically on the next
   rebuild; there is no flat-auth backward compatibility, so migrate tests
   before rebuilding. Pin `~=2.0.1` to express the requirement explicitly.

## 2.0.0

### ⚠️ Breaking Change

`ExecutionContext.fetch()` now returns a `FetchResponse` object instead of the raw parsed body.

**Before (1.x):**
```python
data = await context.fetch("https://api.example.com/items")
# data was the parsed JSON dict/list or text string directly
items = data["results"]
```

**After (2.0):**
```python
response = await context.fetch("https://api.example.com/items")
# response is a FetchResponse with .status, .headers, and .data
items = response.data["results"]
```

`FetchResponse` attributes:
- `status` — HTTP status code (e.g. `200`, `201`)
- `headers` — response headers as a plain `dict`
- `data` — parsed JSON (`dict`/`list`) for `application/json` responses, raw text otherwise, `None` for empty 200/201/204 responses

### Migration Guide

1. **Find all `context.fetch()` calls** in your integration code
2. **Access the response body via `.data`** — the return value is now a `FetchResponse` object, not the raw body:
   ```python
   # Before
   result = await context.fetch(url)
   return ActionResult(data=result)

   # After
   result = await context.fetch(url)
   return ActionResult(data=result.data)
   ```
3. **Optional: use `.status` and `.headers`** for richer error handling or response inspection:
   ```python
   response = await context.fetch(url)
   if response.status == 201:
       log.info(f"Created, location: {response.headers.get('Location')}")
   ```

### Other Changes
- Add `FetchResponse` class, exported from the package
- Add pytest test suite (72 tests, 99% coverage) with `pytest-asyncio` and `aioresponses`
- Add GitHub Actions CI workflow with coverage reporting on PRs
- Add coverage badge and CI status badges to READMEs

## 1.1.1
- Export HTTPError and RateLimitError from package for direct import
- Added PyPI-optimised README with absolute links and best practices
- Documentation: updated SDK version pins and compatible release ranges

## 1.1.0
- Add ActionError for expected application-level errors
- Documentation improvements: unified integration docs, billing/cost tracking manual, code quality conventions, integration callouts linked to source code
- Removed name-folder match rule, mark display_name as recommended

## 1.0.2
- Removed raygun4py dependency

## 1.0.1

- Missed version update in init file.

## 1.0.0 
- Add ActionResult and IntegrationResult classes to provide standardized result handling with optional billing/cost tracking capabilities for the integrations SDK
- Introduce SDK support for connected account information so integrations can expose the authorized user's identity; add documentation and public exports.

## 0.1.4
- Internal Raygun4Py configuration change

## 0.1.3
- Added Raygun integration for internal crash reporting

## 0.1.2
- README cosmetics

## 0.1.1
- Fix for dependency issue manifesting on beta/production

## 0.1.0
- Cleanup, samples and documentation improvements

## 0.0.6
- Module cleanup, move dependencies into SDK

## 0.0.5
- Fixes for production execution

## 0.0.3
- PDoc support

## 0.0.2
- Module structure changes

## 0.0.1
- Initial Release