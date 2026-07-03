"""Test suite for my-integration."""
import asyncio
from context import integration
from autohive_integrations_sdk import ExecutionContext


async def test_my_action():
    """Test the my_action action."""
    # Auth is the platform envelope. The credentials object matches the
    # config.json fields schema. This is the same shape the platform sends
    # in production.
    auth = {
        "auth_type": "Custom",
        "credentials": {
            "api_key": "test_api_key"
        }
    }

    inputs = {
        "example_input": "test_value"
    }

    async with ExecutionContext(auth=auth) as context:
        result = await integration.execute_action("my_action", inputs, context)
        print(f"my_action result: {result.result}")


if __name__ == "__main__":
    asyncio.run(test_my_action())
