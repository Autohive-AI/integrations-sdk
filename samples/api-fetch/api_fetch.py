"""
Sample integration demonstrating API calls with different authentication methods.

Actions:
- call_api: Simple unauthenticated API call
- call_api_un_pw: API call with Basic Authentication
- call_api_header: API call with Bearer token header
"""
from autohive_integrations_sdk import (
    Integration, ExecutionContext, ActionHandler, ActionResult
)
from typing import Dict, Any

api_fetch = Integration.load()


@api_fetch.action("call_api")
class APIFetchAction(ActionHandler):
    """Handles simple API calls without authentication."""

    async def execute(self, inputs: Dict[str, Any], context: ExecutionContext) -> ActionResult:
        url = inputs["url"]
        response = await context.fetch(url)

        return ActionResult(
            data=response.data,
            cost_usd=0.01
        )


@api_fetch.action("call_api_un_pw")
class APIFetchActionBasicAuth(ActionHandler):
    """Handles API calls using Basic Authentication (username/password)."""

    async def execute(self, inputs: Dict[str, Any], context: ExecutionContext) -> ActionResult:
        url = inputs["url"]
        username = context.auth.get("user_name", "")
        password = context.auth.get("password", "")

        # Inject credentials into the URL for Basic Auth
        if url.startswith("https://"):
            url = f"https://{username}:{password}@{url[8:]}"
        elif url.startswith("http://"):
            url = f"http://{username}:{password}@{url[7:]}"

        response = await context.fetch(url)

        return ActionResult(
            data=response.data,
            cost_usd=0.01
        )


@api_fetch.action("call_api_header")
class APIFetchActionHeader(ActionHandler):
    """Handles API calls using header-based authentication (Bearer token)."""

    async def execute(self, inputs: Dict[str, Any], context: ExecutionContext) -> ActionResult:
        url = inputs["url"]
        api_key = context.auth.get("api_key", "")

        response = await context.fetch(
            url,
            headers={"Authorization": f"Bearer {api_key}"}
        )

        return ActionResult(
            data=response.data,
            cost_usd=0.01
        )
