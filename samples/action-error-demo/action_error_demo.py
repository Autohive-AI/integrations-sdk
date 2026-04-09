"""
Action Error Demo — demonstrates the three possible result types from an action handler.

Actions:
- get_user: Returns ActionResult (success) for a given user_id.
- get_user_billing: Returns ActionResult with a cost_usd billing charge.
- lookup_user: Returns ActionError when the user is not found (expected app-level error).
- lookup_user_with_cost: Returns ActionError with cost_usd when a chargeable lookup fails.
"""
from autohive_integrations_sdk import (
    Integration, ExecutionContext, ActionHandler, ActionResult, ActionError
)
from typing import Dict, Any

action_error_demo = Integration.load()

# Simulated user database
USERS = {
    "1": {"id": "1", "name": "Alice Smith", "email": "alice@example.com"},
    "2": {"id": "2", "name": "Bob Jones", "email": "bob@example.com"},
}


@action_error_demo.action("get_user")
class GetUserAction(ActionHandler):
    """Returns user data for an existing user_id, or raises if not found.

    Use this action to demonstrate a plain ActionResult success path.
    Pass user_id "1" or "2" for a success; any other value causes an unhandled
    KeyError (exception-based error path — NOT an ActionError).
    """

    async def execute(self, inputs: Dict[str, Any], context: ExecutionContext) -> ActionResult:
        user_id = inputs["user_id"]
        user = USERS[user_id]  # Raises KeyError for unknown IDs — unhandled exception path
        return ActionResult(data=user)


@action_error_demo.action("get_user_billing")
class GetUserBillingAction(ActionHandler):
    """Returns user data with a billing charge attached.

    Use this action to demonstrate ActionResult with cost_usd.
    Pass user_id "1" or "2" for a success with billing.
    """

    async def execute(self, inputs: Dict[str, Any], context: ExecutionContext) -> ActionResult:
        user_id = inputs["user_id"]
        user = USERS[user_id]  # Raises KeyError for unknown IDs — unhandled exception path
        return ActionResult(data=user, cost_usd=0.001)


@action_error_demo.action("lookup_user")
class LookupUserAction(ActionHandler):
    """Looks up a user by user_id, returning ActionError for unknown IDs.

    Use this action to demonstrate ActionError — an expected, application-level
    error that the agent should receive as content so it can act on the message,
    rather than being treated as an infrastructure failure.

    Pass user_id "1" or "2" for success; any other value returns ActionError.
    """

    async def execute(self, inputs: Dict[str, Any], context: ExecutionContext) -> ActionResult:
        user_id = inputs["user_id"]
        user = USERS.get(user_id)

        if user is None:
            return ActionError(message=f"User '{user_id}' not found.")

        return ActionResult(data=user)


@action_error_demo.action("lookup_user_with_cost")
class LookupUserWithCostAction(ActionHandler):
    """Looks up a user, returning ActionError with cost_usd for chargeable failed lookups.

    Use this action to demonstrate ActionError with a billing charge — for when
    the integration incurred a third-party cost even though the lookup failed.

    Pass user_id "1" or "2" for success; any other value returns ActionError + cost.
    """

    async def execute(self, inputs: Dict[str, Any], context: ExecutionContext) -> ActionResult:
        user_id = inputs["user_id"]
        user = USERS.get(user_id)

        if user is None:
            return ActionError(
                message=f"User '{user_id}' not found.",
                cost_usd=0.001  # Lookup was billed even though the user wasn't found
            )

        return ActionResult(data=user, cost_usd=0.001)
