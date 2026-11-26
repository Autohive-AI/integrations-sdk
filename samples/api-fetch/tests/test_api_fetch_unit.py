"""Exercise API actions without making real HTTP requests."""

import pytest
from autohive_integrations_sdk import FetchResponse, HTTPError, ResultType
from api_fetch import api_fetch

pytestmark = [pytest.mark.unit, pytest.mark.asyncio]


@pytest.mark.parametrize(
    ("action", "expected_url", "expected_options"),
    [
        ("call_api", "https://api.example.com/items", {}),
        (
            "call_api_un_pw",
            "https://test-user:test-only-password@api.example.com/items",
            {},
        ),
        (
            "call_api_header",
            "https://api.example.com/items",
            {"headers": {"Authorization": "Bearer test-only-api-key"}},
        ),
    ],
)
async def test_api_call(mock_context, action, expected_url, expected_options):
    mock_context.fetch.return_value = FetchResponse(
        status=200, headers={"X-Request-ID": "request-7"}, data={"items": [{"id": "7"}]}
    )

    result = await api_fetch.execute_action(action, {"url": "https://api.example.com/items"}, mock_context)

    assert result.type == ResultType.ACTION
    assert result.result.data == {"items": [{"id": "7"}]}
    assert result.result.cost_usd == 0.01
    mock_context.fetch.assert_awaited_once_with(expected_url, **expected_options)


async def test_http_error_propagates_with_headers(mock_context):
    mock_context.fetch.side_effect = HTTPError(409, "Conflict", headers={"x-REQUEST-id": "request-7"})

    with pytest.raises(HTTPError) as error:
        await api_fetch.execute_action("call_api", {"url": "https://api.example.com/items"}, mock_context)

    assert error.value.status == 409
    assert error.value.headers == {"x-REQUEST-id": "request-7"}
