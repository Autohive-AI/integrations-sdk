"""
This module provides an AutoHive integration for fetching data from various APIs.

It includes actions for making simple API calls, calls with basic authentication,
and calls using header-based authentication (e.g., Bearer tokens).
"""
# rss-reader.py
from autohive_integrations_sdk import (
    Integration, ExecutionContext, ActionHandler, ActionResult,
    ConnectedAccountHandler, ConnectedAccountInfo
)
from typing import Dict, Any

# Create the integration using the config.yml
api_fetch = Integration.load()

# ---- Action Handlers ----
@api_fetch.action("call_api")
class APIFetchAction(ActionHandler):
    """
    Handles simple API calls without authentication.

    Retrieves data from the specified URL.
    """
    async def execute(self, inputs: Dict[str, Any], context: ExecutionContext):
        url = inputs["url"]

        # Do the API call here
        response = await context.fetch(url)

        print("Response: ", response)

        # Return ActionResult with billing information
        return ActionResult(
            data=response,
            cost_usd=0.01  # Example: track $0.01 per call
        )


@api_fetch.action("call_api_un_pw")
class APIFetchActionBasicAuth(ActionHandler):
    """
    Handles API calls using Basic Authentication (username/password).

    Injects username and password from the context's auth details into the URL
    before making the request.
    """
    async def execute(self, inputs: Dict[str, Any], context: ExecutionContext):
        url = inputs["url"]
        username = context.auth["user_name"]
        password = context.auth["password"]

        # Split the URL to inject username and password
        if url.startswith('http://'):
            protocol = 'http://'
            domain_part = url[7:]  # Remove 'http://'
        elif url.startswith('https://'):
            protocol = 'https://'
            domain_part = url[8:]  # Remove 'https://'
        else:
            protocol = 'http://'
            domain_part = url
            
        # Create URL with auth credentials
        sendingUrl = f"{protocol}{username}:{password}@{domain_part}"

        # Do the API call here
        response = await context.fetch(sendingUrl)

        print("Response: ", response)

        # Return ActionResult with billing information
        return ActionResult(
            data=response,
            cost_usd=0.01  # Example: track $0.01 per call
        )

@api_fetch.action("call_api_header")
class APIFetchActionHeader(ActionHandler):
    """
    Handles API calls using Header-based Authentication (e.g., Bearer Token).

    Adds an 'Authorization' header with the API key from the context's auth
    details to the request.
    """
    async def execute(self, inputs: Dict[str, Any], context: ExecutionContext):
        url = inputs["url"]
        api_key = context.auth["api_key"]

        # Do the API call here
        response = await context.fetch(url, headers={"Authorization": f"Bearer {api_key}"})

        print("Response: ", response)

        # Return ActionResult with billing information
        return ActionResult(
            data=response,
            cost_usd=0.01  # Example: track $0.01 per call
        )


# ---- Connected Account Handler ----
@api_fetch.connected_account()
class APIFetchConnectedAccountHandler(ConnectedAccountHandler):
    """
    Provides information about the connected account.

    For this demo integration, returns static account information based on
    the username from the auth credentials.
    """
    async def get_account_info(self, context: ExecutionContext) -> ConnectedAccountInfo:
        # In a real integration, you would fetch this from an API
        # For this demo, we'll return information based on the username
        username = context.auth.get("user_name", "demo_user")

        return ConnectedAccountInfo(
            username=username,
            email=f"{username}@example.com",
            first_name="Demo",
            last_name="User",
            user_id=username
        )