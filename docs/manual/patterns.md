# Integration Patterns

> Common patterns used across Autohive integrations. For the basics, see [Building Your First Integration](building_your_first_integration.md). For file structure and config.json schema, see [Integration Structure Reference](integration_structure.md).

## Pagination

Many APIs return results in pages. Here are the pagination patterns used by real integrations.

### Page-Number Pagination

Increment a `page` parameter until the API returns fewer items than the page size:

```python
@integration.action("list_items")
class ListItemsAction(ActionHandler):
    async def execute(self, inputs: Dict[str, Any], context: ExecutionContext) -> ActionResult:
        params = {"per_page": 100, "page": 1}
        all_items = []

        while True:
            response = await context.fetch(
                f"{BASE_URL}/items",
                method="GET",
                params=params
            )

            items = response if isinstance(response, list) else response.get("data", [])
            if not items:
                break

            all_items.extend(items)

            if len(items) < params["per_page"]:
                break

            params["page"] += 1

        return ActionResult(data={"items": all_items, "count": len(all_items)})
```

This is the pattern used by the [GitHub integration's](https://github.com/Autohive-AI/autohive-integrations/tree/master/github) `paginated_fetch` helper.

### Cursor/Offset Pagination

Some APIs return a cursor or offset to pass in the next request:

```python
@integration.action("list_projects")
class ListProjectsAction(ActionHandler):
    async def execute(self, inputs: Dict[str, Any], context: ExecutionContext) -> ActionResult:
        all_projects = []
        offset = None

        while True:
            params = {"limit": 100}
            if offset:
                params["offset"] = offset

            response = await context.fetch(
                f"{BASE_URL}/projects",
                method="GET",
                params=params
            )

            data = response.get("data", [])
            all_projects.extend(data)

            next_page = response.get("next_page")
            if next_page and next_page.get("offset"):
                offset = next_page["offset"]
            else:
                break

        return ActionResult(data={"projects": all_projects, "count": len(all_projects)})
```

This matches the pattern used by the [Asana integration](https://github.com/Autohive-AI/autohive-integrations/tree/master/asana).

### Returning Pagination to the Caller

Some actions return the cursor to the caller and let them paginate, rather than fetching all pages internally:

```python
@integration.action("list_videos")
class ListVideosAction(ActionHandler):
    async def execute(self, inputs: Dict[str, Any], context: ExecutionContext) -> ActionResult:
        request_body = {"max_count": inputs.get("max_count", 20)}

        cursor = inputs.get("cursor")
        if cursor is not None:
            request_body["cursor"] = cursor

        response = await context.fetch(f"{BASE_URL}/videos", method="POST", json=request_body)

        return ActionResult(data={
            "videos": response.get("videos", []),
            "cursor": response.get("cursor"),
            "has_more": response.get("has_more", False),
        })
```

This matches the pattern used by the [TikTok integration](https://github.com/Autohive-AI/autohive-integrations/tree/master/tiktok).

## Centralized API Helpers

Integrations that make many API calls benefit from centralizing request logic. There are two common approaches.

### Helper Module (`helpers.py`)

Used by modular integrations ([Instagram](https://github.com/Autohive-AI/autohive-integrations/tree/master/instagram), [Facebook](https://github.com/Autohive-AI/autohive-integrations/tree/master/facebook), [Humanitix](https://github.com/Autohive-AI/autohive-integrations/tree/master/humanitix)). Put shared constants and utility functions in a `helpers.py` file alongside the entry point:

```python
# helpers.py
from autohive_integrations_sdk import ExecutionContext

API_VERSION = "v2"
BASE_URL = f"https://api.example.com/{API_VERSION}"


async def get_account_id(context: ExecutionContext) -> str:
    """Fetch the authenticated user's account ID."""
    response = await context.fetch(f"{BASE_URL}/me", method="GET")
    account_id = response.get("id")
    if not account_id:
        raise Exception("Failed to retrieve account ID")
    return account_id
```

Action files import from it directly:

```python
# actions/items.py
from helpers import BASE_URL, get_account_id
```

### Static API Class

Used by large single-file integrations ([GitHub](https://github.com/Autohive-AI/autohive-integrations/tree/master/github), [Zoom](https://github.com/Autohive-AI/autohive-integrations/tree/master/zoom), [YouTube](https://github.com/Autohive-AI/autohive-integrations/tree/master/youtube)). Group all API methods into a class with static methods:

```python
class ExampleAPI:
    """Helper class for Example API operations."""
    BASE_URL = "https://api.example.com/v2"

    @staticmethod
    def get_headers(context: ExecutionContext) -> Dict[str, str]:
        credentials = context.auth.get("credentials", {})
        token = credentials.get("access_token", "")
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }

    @staticmethod
    async def paginated_fetch(context: ExecutionContext, url: str,
                              params: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        if params is None:
            params = {}
        params.setdefault("per_page", 100)
        params.setdefault("page", 1)

        all_items = []
        headers = ExampleAPI.get_headers(context)

        while True:
            response = await context.fetch(url, params=params, headers=headers)
            items = response if isinstance(response, list) else []
            if not items:
                break
            all_items.extend(items)
            if len(items) < params["per_page"]:
                break
            params["page"] += 1

        return all_items
```

Action handlers then call the class methods:

```python
@integration.action("list_items")
class ListItemsAction(ActionHandler):
    async def execute(self, inputs: Dict[str, Any], context: ExecutionContext) -> ActionResult:
        items = await ExampleAPI.paginated_fetch(context, f"{ExampleAPI.BASE_URL}/items")
        return ActionResult(data={"items": items, "count": len(items)})
```

## Multi-Field Custom Auth

Some integrations need more than one credential — for example, an API key plus a subdomain, or a client ID plus a client secret.

### Config

Define multiple properties in the `auth.fields` schema:

```json
"auth": {
    "type": "custom",
    "title": "Freshdesk API Credentials",
    "fields": {
        "type": "object",
        "properties": {
            "api_key": {
                "type": "string",
                "format": "password",
                "label": "API Key",
                "help_text": "Your API key from Profile Settings"
            },
            "domain": {
                "type": "string",
                "label": "Subdomain",
                "help_text": "Your subdomain (e.g., 'yourcompany' from yourcompany.freshdesk.com)"
            }
        }
    }
}
```

### Accessing Credentials

Credentials are nested under `context.auth["credentials"]`:

```python
def get_base_url(context: ExecutionContext) -> str:
    credentials = context.auth.get("credentials", {})
    domain = credentials.get("domain", "")
    return f"https://{domain}.freshdesk.com/api/v2"

def get_headers(context: ExecutionContext) -> Dict[str, str]:
    credentials = context.auth.get("credentials", {})
    api_key = credentials.get("api_key", "")
    auth_bytes = f"{api_key}:X".encode("ascii")
    return {
        "Authorization": f"Basic {base64.b64encode(auth_bytes).decode('ascii')}",
        "Content-Type": "application/json",
    }
```

This pattern is used by integrations like [Freshdesk](https://github.com/Autohive-AI/autohive-integrations/tree/master/freshdesk) (API key + domain), [Trello](https://github.com/Autohive-AI/autohive-integrations/tree/master/trello) (API key + token), and [Google Looker](https://github.com/Autohive-AI/autohive-integrations/tree/master/google-looker) (base URL + client ID + client secret).

## Code Quality Conventions

### Constants and Configuration

Define API base URLs, version strings, and other constants at module level:

```python
BASE_URL = "https://api.example.com/v2"
API_VERSION = "v2"
DEFAULT_PAGE_SIZE = 100
```

### Type Hints

Add type hints to all function parameters and return types:

```python
async def execute(self, inputs: Dict[str, Any], context: ExecutionContext) -> ActionResult:
    ...
```

### Credentials

Never hardcode API keys, tokens, or secrets. Always read them from `context.auth`:

```python
# WRONG
headers = {"Authorization": "Bearer sk-abc123"}

# CORRECT
credentials = context.auth.get("credentials", {})
api_key = credentials.get("api_key", "")
headers = {"Authorization": f"Bearer {api_key}"}
```

## Linting and CI

Integration repos use the [autohive-integrations-tooling](https://github.com/Autohive-AI/autohive-integrations-tooling) CI pipeline. Understanding the lint configuration helps avoid common CI failures.

### Ruff Rules

CI runs [ruff](https://docs.astral.sh/ruff/) with rules `E` (pycodestyle errors), `F` (pyflakes), and `W` (pycodestyle warnings). Line length is 120 characters. Target version is Python 3.13.

### Per-File Lint Suppressions

The tooling repo's `ruff.toml` automatically suppresses certain rules for specific files:

| File | Suppressed | Why |
|------|-----------|-----|
| `__init__.py` | `F401` (unused import) | Import-and-re-export is the expected pattern |
| `tests/context.py` | `F401` (unused import), `E402` (import not at top of file) | The `sys.path` setup must come before the integration import |

This means you **don't** need `# noqa` comments in these two files. However, if you have intentional "unused" imports in other files (e.g., re-exporting from a helpers module), you must add `# noqa: F401` inline:

```python
# helpers.py — re-exporting for convenience
from .utils import format_date, parse_response  # noqa: F401
```

### Security Scanning

CI runs [bandit](https://bandit.readthedocs.io/) for security checks. It skips rule `B101` (assert_used), so assertions in test files are fine. Common bandit flags to watch for:

- `B105` / `B106` — hardcoded passwords or credentials
- `B108` — insecure temp file usage
- `B310` — `urllib.urlopen` with user-controlled input

### Dependency Auditing

CI runs `pip-audit` against your `requirements.txt` to check for known CVEs. If a dependency has a vulnerability, update to the fixed version listed in the audit output.
