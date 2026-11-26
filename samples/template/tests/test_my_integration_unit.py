"""Unit tests for the starter action; no provider credentials or network needed."""

import pytest
from autohive_integrations_sdk import FetchResponse, ResultType
from my_integration import my_integration

pytestmark = [pytest.mark.unit, pytest.mark.asyncio]


async def test_my_action(mock_context):
    mock_context.fetch.return_value = FetchResponse(status=200, headers={}, data={"id": "record-7"})

    result = await my_integration.execute_action("my_action", {"example_input": "sample-value"}, mock_context)

    assert result.type == ResultType.ACTION
    assert result.result.data == {"result": {"id": "record-7"}}
    mock_context.fetch.assert_awaited_once_with(
        "https://api.example.com/endpoint",
        method="POST",
        headers={"Authorization": "Bearer test-only-api-key"},
        json={"example_input": "sample-value"},
    )


async def test_missing_input(mock_context):
    result = await my_integration.execute_action("my_action", {}, mock_context)

    assert result.type == ResultType.VALIDATION_ERROR
    assert result.result["source"] == "input"


async def test_missing_credentials(mock_context):
    mock_context.auth = {"auth_type": "Custom", "credentials": {}}

    result = await my_integration.execute_action("my_action", {"example_input": "sample-value"}, mock_context)

    assert result.type == ResultType.VALIDATION_ERROR
    assert result.result["source"] == "auth"
    mock_context.fetch.assert_not_awaited()
