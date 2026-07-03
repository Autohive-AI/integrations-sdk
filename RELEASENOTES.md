# Release Notes

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