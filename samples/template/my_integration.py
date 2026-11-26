"""
My Integration — brief description of what this integration does.

Actions:
- my_action: Describe what this action does.
"""

from pathlib import Path

from autohive_integrations_sdk import Integration, ExecutionContext, ActionHandler, ActionResult
from typing import Dict, Any

my_integration = Integration.load(Path(__file__).with_name("config.json"))


@my_integration.action("my_action")
class MyAction(ActionHandler):
    """Handles the my_action action."""

    async def execute(self, inputs: Dict[str, Any], context: ExecutionContext) -> ActionResult:
        example_input = inputs["example_input"]
        api_key = context.auth["credentials"].get("api_key", "")

        response = await context.fetch(
            "https://api.example.com/endpoint",
            method="POST",
            headers={"Authorization": f"Bearer {api_key}"},
            json={"example_input": example_input},
        )

        return ActionResult(data={"result": response.data})
