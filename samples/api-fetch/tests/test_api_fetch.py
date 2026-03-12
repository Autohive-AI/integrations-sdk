"""Test suite for the api-fetch sample integration."""
import asyncio
from context import integration
from autohive_integrations_sdk import ExecutionContext


async def test_call_api():
    """Test simple API call."""
    auth = {
        "user_name": "test_user",
        "password": "test_password",
        "api_key": "test_api_key"
    }
    inputs = {"url": "https://httpbin.org/get"}

    async with ExecutionContext(auth=auth) as context:
        result = await integration.execute_action("call_api", inputs, context)
        print(f"call_api result: {result.result}")


async def test_call_api_un_pw():
    """Test API call with Basic Auth."""
    auth = {
        "user_name": "test_user",
        "password": "test_password",
        "api_key": "test_api_key"
    }
    inputs = {"url": "https://httpbin.org/basic-auth/test_user/test_password"}

    async with ExecutionContext(auth=auth) as context:
        result = await integration.execute_action("call_api_un_pw", inputs, context)
        print(f"call_api_un_pw result: {result.result}")


async def test_call_api_header():
    """Test API call with Bearer token header."""
    auth = {
        "user_name": "test_user",
        "password": "test_password",
        "api_key": "test_api_key"
    }
    inputs = {"url": "https://httpbin.org/bearer"}

    async with ExecutionContext(auth=auth) as context:
        result = await integration.execute_action("call_api_header", inputs, context)
        print(f"call_api_header result: {result.result}")


if __name__ == "__main__":
    asyncio.run(test_call_api())
    asyncio.run(test_call_api_un_pw())
    asyncio.run(test_call_api_header())
