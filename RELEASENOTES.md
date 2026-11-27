# Release Notes

## 3.0.0

### New Feature: files

An action can now declare a file field explicitly, and the SDK moves the file
content. See [Files](docs/manual/files.md).

- **A file type.** A field is a file when its schema in `config.json` is
  `{"$ref": "https://cdn.autohive.com/schemas/sdk/file/v1.json"}`. The property
  name no longer matters. The reference is also exported as `FILE_SCHEMA_ID`.
  The SDK validates against its own copy of the schema; nothing is fetched.
- **`File` objects.** A handler receives a `File` for each file input and
  returns a `File` for each file output. `File.read()` returns the content, and
  `File.iter_chunks(n)` yields it in pieces of exactly `n` bytes (the last can
  be shorter).
- **Large files without the memory cost.** The platform sends a large input as
  a URL, and the SDK downloads it only when the handler reads it. An output file
  over 3 MB is uploaded to the platform's storage after the handler returns, as
  a stream. `File.from_request(url, ...)` returns a file from another service
  without holding it in memory.
- **Transfer failures are action errors.** When the SDK cannot download or
  upload a file, the action returns an `ActionError` that names the file and the
  cause.

```python
@integration.action("get_file")
class GetFile(ActionHandler):
    async def execute(self, inputs, context):
        metadata = (await context.fetch(f"{API}/files/{inputs['file_id']}")).data
        return ActionResult(data={
            "file": File.from_request(
                f"{API}/files/{inputs['file_id']}/content",
                name=metadata["name"],
                content_type=metadata["mimeType"],
                size=metadata["size"],
            ),
        })
```

### New: `fetch()` options for chunked uploads

- `send_auth=False` sends no platform OAuth token. Use it for a URL that
  carries its own authorisation.
- `accept_statuses=[...]` returns a response with one of these non-2xx statuses
  as a normal `FetchResponse` and does not raise `HTTPError`. For example, a
  resumable upload can answer `308` between chunks.

### New: `ExecutionContext(file_transport=...)`

The platform passes its file transport settings here. Integration code does not
set it. Without it, an output file over 3 MB fails with an `ActionError`.

### Compatibility

- Only a field declared with the file reference gets a `File`. A field that
  uses the older convention (an object with `content`, `name` and
  `contentType`) is passed to the handler unchanged, as a `dict`. Change the
  schema and the handler of an action together.
- On SDK 3, the platform can deliver a large file input in its URL form. A
  field that still uses the older convention is not downloaded for the handler.
  Declare each file field with the reference before moving an integration to
  SDK 3.
- `fetch()` behaves as before when the new options are not used.

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
