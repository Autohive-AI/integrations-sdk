"""
My Integration — brief description of what this integration does.

Actions:
- my_action: Describe what this action does.
"""
from autohive_integrations_sdk import (
    Integration, ExecutionContext, ActionHandler, ActionResult
)
from typing import Dict, Any

integration = Integration.load()


@integration.action("my_action")
class MyAction(ActionHandler):
    """Handles the my_action action."""

    async def execute(self, inputs: Dict[str, Any], context: ExecutionContext) -> ActionResult:
        example_input = inputs["example_input"]
        api_key = context.auth.get("api_key", "")

        response = await context.fetch(
            "https://api.example.com/endpoint",
            headers={"Authorization": f"Bearer {api_key}"}
        )

        return ActionResult(data=response.data)
