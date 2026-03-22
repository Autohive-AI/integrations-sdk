# Testbed for a simple integration.
# The IUT (integration under test) is the api_fetch file.
"""
Test suite for the api_fetch integration sample.

This module contains tests for the actions defined in the api_fetch integration,
ensuring they function correctly within the AutoHive execution context.
"""
import asyncio
from context import api_fetch
from autohive_integrations_sdk import ExecutionContext

# Some simple mock classes to make this test work.
async def test_api_fetch():
    """
    Tests the various API calling actions within the api_fetch integration.

    It sets up mock authentication and inputs, then calls each action
    ('call_api', 'call_api_un_pw', 'call_api_header') using the
    ExecutionContext and prints the results or any errors encountered.
    """
    auth = {
        "user_name": "test_user",
        "password": "test_password",
        "api_key": "test_api_key"
    }

    # Use the ExecutionContext as an async context manager
    async with ExecutionContext(auth=auth) as context:

        # Define test configuration
        inputs = {
            "url": "http://localhost:8000/test"
        }

        try:
            # execute_action returns IntegrationResult with structure:
            # IntegrationResult(version=..., type='action', result={'data': ..., 'billing': ...})
            result = await api_fetch.execute_action("call_api", inputs, context)
            print("Result from call_api in test_api_fetch.py:")
            print(f"  Data: {result.result['data']}")
            print(f"  Billing: {result.result['billing']}\n")
        except Exception as e:
            print(f"Error testing call_api: {str(e)}")
            raise e

        try:
            result = await api_fetch.execute_action("call_api_un_pw", inputs, context)
            print("Result from call_api_un_pw in test_api_fetch.py:")
            print(f"  Data: {result.result['data']}")
            print(f"  Billing: {result.result['billing']}\n")
        except Exception as e:
            print(f"Error testing call_api_un_pw: {str(e)}")
            raise e

        try:
            result = await api_fetch.execute_action("call_api_header", inputs, context)
            print("Result from call_api_header in test_api_fetch.py:")
            print(f"  Data: {result.result['data']}")
            print(f"  Billing: {result.result['billing']}\n")
        except Exception as e:
            print(f"Error testing call_api_header: {str(e)}")
            raise e

async def test_connected_account():
    """
    Tests the connected account handler in the api_fetch integration.

    Verifies that the handler correctly returns account information
    based on the authentication credentials.
    """
    auth = {
        "user_name": "test_user",
        "password": "test_password",
        "api_key": "test_api_key"
    }

    async with ExecutionContext(auth=auth) as context:
        try:
            # get_connected_account returns IntegrationResult with structure:
            # IntegrationResult(version=..., type='connected_account', result={...account data...})
            result = await api_fetch.get_connected_account(context)
            print("Connected Account Information:")
            print(f"  Account Data: {result.result}")
            print(f"  SDK Version: {result.version}\n")
        except Exception as e:
            print(f"Error testing connected account: {str(e)}")
            raise e

async def main():
    """Runs the test suite for the API Fetch integration."""
    print("Testing API Fetch Integration")
    print("=============================")

    await test_api_fetch()
    await test_connected_account()

if __name__ == "__main__":
    asyncio.run(main())
