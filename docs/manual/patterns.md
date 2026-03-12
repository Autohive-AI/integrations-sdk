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

This is the pattern used by the GitHub integration's `paginated_fetch` helper.

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

This matches the pattern used by the Asana integration.

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

This matches the pattern used by the TikTok integration.

## Centralized API Helpers

Integrations that make many API calls benefit from centralizing request logic. There are two common approaches.

### Helper Module (`helpers.py`)

Used by modular integrations (Instagram, Facebook, Humanitix). Put shared constants and utility functions in a `helpers.py` file alongside the entry point:

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

Used by large single-file integrations (GitHub, Zoom, YouTube). Group all API methods into a class with static methods:

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

This pattern is used by integrations like Freshdesk (API key + domain), Trello (API key + token), and Google Looker (base URL + client ID + client secret).
