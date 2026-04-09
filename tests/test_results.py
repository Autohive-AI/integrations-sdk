"""Tests for result dataclasses, exceptions, and enums."""

import pytest

from autohive_integrations_sdk import (
    ActionResult,
    ActionError,
    ConnectedAccountInfo,
    IntegrationResult,
    ResultType,
    ValidationError,
    HTTPError,
    RateLimitError,
    FetchResponse,
)
from autohive_integrations_sdk.integration import AuthType


# ── ActionResult ─────────────────────────────────────────────────────────────


def test_action_result_defaults():
    r = ActionResult(data={"key": "value"})
    assert r.data == {"key": "value"}
    assert r.cost_usd is None


def test_action_result_with_cost():
    r = ActionResult(data={}, cost_usd=1.23)
    assert r.cost_usd == 1.23


# ── ActionError ──────────────────────────────────────────────────────────────


def test_action_error():
    e = ActionError(message="boom", cost_usd=0.01)
    assert e.message == "boom"
    assert e.cost_usd == 0.01


# ── ConnectedAccountInfo ────────────────────────────────────────────────────


def test_connected_account_info_defaults():
    info = ConnectedAccountInfo()
    assert info.email is None
    assert info.first_name is None
    assert info.last_name is None
    assert info.username is None
    assert info.user_id is None
    assert info.avatar_url is None
    assert info.organization is None


def test_connected_account_info_fields():
    info = ConnectedAccountInfo(
        email="a@b.com",
        first_name="Alice",
        last_name="Smith",
        username="asmith",
        user_id="42",
        avatar_url="https://img.example.com/a.png",
        organization="Acme",
    )
    assert info.email == "a@b.com"
    assert info.first_name == "Alice"
    assert info.organization == "Acme"


# ── IntegrationResult ───────────────────────────────────────────────────────


def test_integration_result():
    ar = ActionResult(data={"x": 1})
    ir = IntegrationResult(version="1.0.0", type=ResultType.ACTION, result=ar)
    assert ir.version == "1.0.0"
    assert ir.type == ResultType.ACTION
    assert ir.result is ar


# ── Exceptions ───────────────────────────────────────────────────────────────


def test_validation_error():
    err = ValidationError(
        message="bad input",
        schema="the_schema",
        inputs="the_inputs",
        source="input",
    )
    assert err.message == "bad input"
    assert err.schema == "the_schema"
    assert err.inputs == "the_inputs"
    assert err.source == "input"
    assert str(err) == "bad input"


def test_http_error():
    err = HTTPError(status=404, message="not found", response_data={"detail": "nope"})
    assert err.status == 404
    assert err.message == "not found"
    assert err.response_data == {"detail": "nope"}
    assert "404" in str(err)


def test_rate_limit_error():
    err = RateLimitError(retry_after=30, status=429, message="slow down")
    assert isinstance(err, HTTPError)
    assert err.retry_after == 30
    assert err.status == 429


# ── Enums ────────────────────────────────────────────────────────────────────


def test_result_type_enum():
    assert ResultType.ACTION.value == "action"
    assert ResultType.ACTION_ERROR.value == "action_error"
    assert ResultType.CONNECTED_ACCOUNT.value == "connected_account"
    assert ResultType.ERROR.value == "error"
    assert ResultType.VALIDATION_ERROR.value == "validation_error"


def test_auth_type_enum():
    assert AuthType.PlatformOauth2.value == "PlatformOauth2"
    assert AuthType.PlatformTeams.value == "PlatformTeams"
    assert AuthType.ApiKey.value == "ApiKey"
    assert AuthType.Basic.value == "Basic"
    assert AuthType.Custom.value == "Custom"


# ── FetchResponse ───────────────────────────────────────────────────────────


def test_fetch_response_json():
    r = FetchResponse(status=200, headers={"Content-Type": "application/json"}, data={"ok": True})
    assert r.status == 200
    assert r.data == {"ok": True}
    assert r.headers["Content-Type"] == "application/json"


def test_fetch_response_none_data():
    r = FetchResponse(status=204, headers={}, data=None)
    assert r.status == 204
    assert r.data is None


def test_fetch_response_text_data():
    r = FetchResponse(status=200, headers={"Content-Type": "text/plain"}, data="hello")
    assert r.data == "hello"
