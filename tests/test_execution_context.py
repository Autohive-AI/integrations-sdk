"""Tests for ExecutionContext — HTTP fetching, auth injection, retries."""

from unittest.mock import patch

import aiohttp
import pytest
from aioresponses import aioresponses
from yarl import URL

from autohive_integrations_sdk import (
    ExecutionContext,
    HTTPError,
    RateLimitError,
)


BASE_URL = "https://api.example.com/resource"


@pytest.fixture
def mock_aio():
    with aioresponses() as m:
        yield m


# ── Basic HTTP ───────────────────────────────────────────────────────────────


async def test_fetch_get_json(mock_aio):
    mock_aio.get(BASE_URL, payload={"ok": True})

    async with ExecutionContext() as ctx:
        data = await ctx.fetch(BASE_URL)

    assert data.data == {"ok": True}
    assert data.status == 200
    assert "Content-Type" in data.headers


async def test_fetch_post_json(mock_aio):
    mock_aio.post(BASE_URL, payload={"id": 1})

    async with ExecutionContext() as ctx:
        data = await ctx.fetch(BASE_URL, method="POST", json={"name": "test"})

    assert data.data == {"id": 1}


async def test_fetch_text_response(mock_aio):
    mock_aio.get(BASE_URL, body="plain text", content_type="text/plain")

    async with ExecutionContext() as ctx:
        data = await ctx.fetch(BASE_URL)

    assert data.data == "plain text"


async def test_fetch_empty_response_204(mock_aio):
    mock_aio.get(BASE_URL, body="", status=204, content_type="text/plain")

    async with ExecutionContext() as ctx:
        data = await ctx.fetch(BASE_URL)

    assert data.data is None
    assert data.status == 204


# ── Error handling ───────────────────────────────────────────────────────────


async def test_fetch_rate_limit(mock_aio):
    mock_aio.get(
        BASE_URL,
        status=429,
        body="rate limited",
        headers={"Retry-After": "120"},
        content_type="text/plain",
    )

    async with ExecutionContext() as ctx:
        with pytest.raises(RateLimitError) as exc_info:
            await ctx.fetch(BASE_URL)

    assert exc_info.value.retry_after == 120
    assert exc_info.value.status == 429


async def test_fetch_http_error(mock_aio):
    mock_aio.get(BASE_URL, status=500, body="server error", content_type="text/plain")

    async with ExecutionContext() as ctx:
        with pytest.raises(HTTPError) as exc_info:
            await ctx.fetch(BASE_URL)

    assert exc_info.value.status == 500


# ── Auth injection ───────────────────────────────────────────────────────────


async def test_fetch_oauth_bearer_token(mock_aio):
    mock_aio.get(BASE_URL, payload={"ok": True})

    auth = {
        "auth_type": "PlatformOauth2",
        "credentials": {"access_token": "tok_abc"},
    }
    async with ExecutionContext(auth=auth) as ctx:
        await ctx.fetch(BASE_URL)

    key = ("GET", URL(BASE_URL))
    request = mock_aio.requests[key][0]
    assert request.kwargs["headers"]["Authorization"] == "Bearer tok_abc"


async def test_fetch_no_auth_injection_when_header_provided(mock_aio):
    mock_aio.get(BASE_URL, payload={"ok": True})

    auth = {
        "auth_type": "PlatformOauth2",
        "credentials": {"access_token": "tok_abc"},
    }
    async with ExecutionContext(auth=auth) as ctx:
        await ctx.fetch(BASE_URL, headers={"Authorization": "Custom xyz"})

    key = ("GET", URL(BASE_URL))
    request = mock_aio.requests[key][0]
    assert request.kwargs["headers"]["Authorization"] == "Custom xyz"


# ── Query params ─────────────────────────────────────────────────────────────


async def test_fetch_query_params(mock_aio):
    # The SDK appends params to the URL string before making the request,
    # so we need to register the mock with a pattern or the full URL.
    url_with_params = f"{BASE_URL}?page=1&limit=10"
    mock_aio.get(url_with_params, payload={"ok": True})

    async with ExecutionContext() as ctx:
        data = await ctx.fetch(BASE_URL, params={"page": 1, "limit": 10})

    assert data.data == {"ok": True}


# ── Retry logic ──────────────────────────────────────────────────────────────


async def test_fetch_retry_on_client_error(mock_aio):
    mock_aio.get(BASE_URL, exception=aiohttp.ClientError("connection reset"))
    mock_aio.get(BASE_URL, payload={"ok": True})

    cfg = {"max_retries": 1, "timeout": 1}
    async with ExecutionContext(request_config=cfg) as ctx:
        with patch("asyncio.sleep", return_value=None) as mock_sleep:
            data = await ctx.fetch(BASE_URL)

    assert data.data == {"ok": True}
    mock_sleep.assert_awaited_once()


# ── Context manager ──────────────────────────────────────────────────────────


async def test_context_manager():
    ctx = ExecutionContext()
    assert ctx._session is None

    async with ctx:
        assert ctx._session is not None
        assert not ctx._session.closed

    assert ctx._session is None


# ── Form-encoded body ────────────────────────────────────────────────────────


async def test_fetch_form_encoded_body(mock_aio):
    mock_aio.post(BASE_URL, payload={"ok": True})

    async with ExecutionContext() as ctx:
        await ctx.fetch(
            BASE_URL,
            method="POST",
            data={"username": "alice", "password": "secret"},
            content_type="application/x-www-form-urlencoded",
        )

    key = ("POST", URL(BASE_URL))
    request = mock_aio.requests[key][0]
    body = request.kwargs["data"]
    # urlencode produces "username=alice&password=secret" (order may vary)
    assert "username=alice" in body
    assert "password=secret" in body


# ── Nested params ────────────────────────────────────────────────────────────


async def test_fetch_nested_params(mock_aio):
    """Dicts/lists in params are JSON-serialized."""
    import json as _json

    expected_url = f"{BASE_URL}?filter=%7B%22status%22%3A+%22active%22%7D"
    mock_aio.get(expected_url, payload={"ok": True})

    async with ExecutionContext() as ctx:
        data = await ctx.fetch(BASE_URL, params={"filter": {"status": "active"}})

    assert data.data == {"ok": True}


# ── URL with existing query string ──────────────────────────────────────────


async def test_fetch_params_appended_with_ampersand(mock_aio):
    """When URL already has '?', params are joined with '&'."""
    base_with_query = f"{BASE_URL}?existing=1"
    full_url = f"{base_with_query}&page=2"
    mock_aio.get(full_url, payload={"ok": True})

    async with ExecutionContext() as ctx:
        data = await ctx.fetch(base_with_query, params={"page": 2})

    assert data.data == {"ok": True}


# ── Timeout triggers retry ──────────────────────────────────────────────────


async def test_fetch_retry_on_timeout(mock_aio):
    """asyncio.TimeoutError triggers a retry just like ClientError."""
    import asyncio

    mock_aio.get(BASE_URL, exception=asyncio.TimeoutError())
    mock_aio.get(BASE_URL, payload={"ok": True})

    cfg = {"max_retries": 1, "timeout": 1}
    async with ExecutionContext(request_config=cfg) as ctx:
        with patch("asyncio.sleep", return_value=None):
            data = await ctx.fetch(BASE_URL)

    assert data.data == {"ok": True}


# ── Max retries exhausted ───────────────────────────────────────────────────


async def test_fetch_max_retries_exhausted(mock_aio):
    """After all retries fail, the error propagates."""
    mock_aio.get(BASE_URL, exception=aiohttp.ClientError("fail"))
    mock_aio.get(BASE_URL, exception=aiohttp.ClientError("fail again"))

    cfg = {"max_retries": 1, "timeout": 1}
    async with ExecutionContext(request_config=cfg) as ctx:
        with patch("asyncio.sleep", return_value=None):
            with pytest.raises(aiohttp.ClientError):
                await ctx.fetch(BASE_URL)


# ── Non-OAuth auth types ────────────────────────────────────────────────────


async def test_fetch_no_bearer_for_apikey_auth(mock_aio):
    """ApiKey auth type should not auto-inject a Bearer token."""
    mock_aio.get(BASE_URL, payload={"ok": True})

    auth = {"auth_type": "ApiKey", "credentials": {"access_token": "tok_abc"}}
    async with ExecutionContext(auth=auth) as ctx:
        await ctx.fetch(BASE_URL)

    key = ("GET", URL(BASE_URL))
    request = mock_aio.requests[key][0]
    assert "Authorization" not in request.kwargs["headers"]


async def test_fetch_no_bearer_for_custom_auth(mock_aio):
    """Custom auth type should not auto-inject a Bearer token."""
    mock_aio.get(BASE_URL, payload={"ok": True})

    auth = {"auth_type": "Custom", "credentials": {"api_key": "xyz"}}
    async with ExecutionContext(auth=auth) as ctx:
        await ctx.fetch(BASE_URL)

    key = ("GET", URL(BASE_URL))
    request = mock_aio.requests[key][0]
    assert "Authorization" not in request.kwargs["headers"]


async def test_fetch_no_bearer_for_basic_auth(mock_aio):
    """Basic auth type should not auto-inject a Bearer token."""
    mock_aio.get(BASE_URL, payload={"ok": True})

    auth = {"auth_type": "Basic", "credentials": {"username": "u", "password": "p"}}
    async with ExecutionContext(auth=auth) as ctx:
        await ctx.fetch(BASE_URL)

    key = ("GET", URL(BASE_URL))
    request = mock_aio.requests[key][0]
    assert "Authorization" not in request.kwargs["headers"]


# ── Session auto-created ────────────────────────────────────────────────────


async def test_fetch_creates_session_without_context_manager(mock_aio):
    """fetch() creates a session if called without 'async with'."""
    mock_aio.get(BASE_URL, payload={"ok": True})

    ctx = ExecutionContext()
    assert ctx._session is None

    data = await ctx.fetch(BASE_URL)
    assert data.data == {"ok": True}
    assert ctx._session is not None

    # Clean up
    await ctx._session.close()


# ── JSON error response ─────────────────────────────────────────────────────


async def test_fetch_http_error_json_body(mock_aio):
    """Non-2xx with JSON body stores parsed dict in response_data."""
    mock_aio.get(
        BASE_URL,
        status=400,
        payload={"error": "bad request", "code": "INVALID"},
    )

    async with ExecutionContext() as ctx:
        with pytest.raises(HTTPError) as exc_info:
            await ctx.fetch(BASE_URL)

    assert exc_info.value.status == 400
    assert exc_info.value.response_data == {"error": "bad request", "code": "INVALID"}
