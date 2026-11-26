"""Demonstrate success, expected action errors, and unhandled exceptions."""

import pytest
from autohive_integrations_sdk import ExecutionContext, ResultType
from action_error_demo import action_error_demo

pytestmark = [pytest.mark.unit, pytest.mark.asyncio]


@pytest.mark.parametrize(
    ("action", "cost"),
    [
        ("get_user", None),
        ("get_user_billing", 0.001),
        ("lookup_user", None),
        ("lookup_user_with_cost", 0.001),
    ],
)
async def test_success(action, cost):
    result = await action_error_demo.execute_action(action, {"user_id": "2"}, ExecutionContext(auth={}))

    assert result.type == ResultType.ACTION
    assert result.result.data == {"id": "2", "name": "Bob Jones", "email": "bob@example.com"}
    assert result.result.cost_usd == cost


@pytest.mark.parametrize(("action", "cost"), [("lookup_user", None), ("lookup_user_with_cost", 0.001)])
async def test_expected_error(action, cost):
    result = await action_error_demo.execute_action(action, {"user_id": "missing"}, ExecutionContext(auth={}))

    assert result.type == ResultType.ACTION_ERROR
    assert result.result.message == "User 'missing' not found."
    assert result.result.cost_usd == cost


async def test_unhandled_error():
    with pytest.raises(KeyError, match="missing"):
        await action_error_demo.execute_action("get_user", {"user_id": "missing"}, ExecutionContext(auth={}))
