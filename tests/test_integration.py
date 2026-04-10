"""Tests for the Integration class — config loading, handler registration, and execution."""

import json
from datetime import timedelta

import pytest

from autohive_integrations_sdk import (
    Integration,
    ExecutionContext,
    ActionHandler,
    ActionResult,
    ActionError,
    ConnectedAccountHandler,
    ConnectedAccountInfo,
    IntegrationResult,
    ResultType,
    ValidationError,
)
from autohive_integrations_sdk.integration import (
    ConfigurationError,
    PollingTriggerHandler,
)


# ── Config loading ───────────────────────────────────────────────────────────


def test_load_config(integration, config_dict):
    assert integration.config.name == config_dict["name"]
    assert integration.config.version == config_dict["version"]
    assert integration.config.description == config_dict["description"]
    assert "test_action" in integration.config.actions
    assert "test_trigger" in integration.config.polling_triggers


def test_load_config_missing_file(tmp_path):
    with pytest.raises(ConfigurationError, match="not found"):
        Integration.load(tmp_path / "nonexistent.json")


def test_load_config_invalid_json(tmp_path):
    bad_file = tmp_path / "config.json"
    bad_file.write_text("{invalid json")
    with pytest.raises(ConfigurationError, match="Invalid JSON"):
        Integration.load(bad_file)


# ── Action handler registration ─────────────────────────────────────────────


def test_register_action_handler(integration):
    @integration.action("test_action")
    class Handler(ActionHandler):
        async def execute(self, inputs, context):
            return ActionResult(data={})

    assert "test_action" in integration._action_handlers


def test_register_action_not_in_config(integration):
    with pytest.raises(ConfigurationError, match="not defined in config"):

        @integration.action("nonexistent_action")
        class Handler(ActionHandler):
            async def execute(self, inputs, context):
                return ActionResult(data={})


# ── Action execution ────────────────────────────────────────────────────────


async def test_execute_action_success(integration):
    @integration.action("test_action")
    class Handler(ActionHandler):
        async def execute(self, inputs, context):
            return ActionResult(data={"greeting": f"Hello {inputs['name']}"})

    ctx = ExecutionContext(auth={"api_key": "k"})
    result = await integration.execute_action("test_action", {"name": "World"}, ctx)

    assert result.type == ResultType.ACTION
    assert result.result.data == {"greeting": "Hello World"}
    assert result.version is not None


async def test_execute_action_with_cost(integration):
    @integration.action("test_action")
    class Handler(ActionHandler):
        async def execute(self, inputs, context):
            return ActionResult(data={"greeting": "hi"}, cost_usd=0.05)

    ctx = ExecutionContext(auth={"api_key": "k"})
    result = await integration.execute_action("test_action", {"name": "x"}, ctx)

    assert result.type == ResultType.ACTION
    assert result.result.cost_usd == 0.05


async def test_execute_action_invalid_inputs(integration):
    @integration.action("test_action")
    class Handler(ActionHandler):
        async def execute(self, inputs, context):
            return ActionResult(data={"greeting": "hi"})

    ctx = ExecutionContext(auth={"api_key": "k"})
    result = await integration.execute_action("test_action", {}, ctx)

    assert result.type == ResultType.VALIDATION_ERROR


async def test_execute_action_invalid_output(integration):
    @integration.action("test_action")
    class Handler(ActionHandler):
        async def execute(self, inputs, context):
            return ActionResult(data={"wrong_key": 123})

    ctx = ExecutionContext(auth={"api_key": "k"})
    result = await integration.execute_action("test_action", {"name": "x"}, ctx)

    assert result.type == ResultType.VALIDATION_ERROR


async def test_execute_action_wrong_return_type(integration):
    @integration.action("test_action")
    class Handler(ActionHandler):
        async def execute(self, inputs, context):
            return {"greeting": "plain dict"}

    ctx = ExecutionContext(auth={"api_key": "k"})
    result = await integration.execute_action("test_action", {"name": "x"}, ctx)

    assert result.type == ResultType.VALIDATION_ERROR


async def test_execute_action_not_registered(integration):
    ctx = ExecutionContext(auth={"api_key": "k"})
    result = await integration.execute_action("test_action", {"name": "x"}, ctx)

    assert result.type == ResultType.VALIDATION_ERROR


async def test_execute_action_error(integration):
    @integration.action("test_action")
    class Handler(ActionHandler):
        async def execute(self, inputs, context):
            return ActionError(message="something went wrong", cost_usd=0.01)

    ctx = ExecutionContext(auth={"api_key": "k"})
    result = await integration.execute_action("test_action", {"name": "x"}, ctx)

    assert result.type == ResultType.ACTION_ERROR
    assert result.result.message == "something went wrong"
    assert result.result.cost_usd == 0.01


# ── Polling trigger ─────────────────────────────────────────────────────────


def test_register_polling_trigger(integration):
    @integration.polling_trigger("test_trigger")
    class Handler(PollingTriggerHandler):
        async def poll(self, inputs, last_poll_ts, context):
            return []

    assert "test_trigger" in integration._polling_handlers


async def test_execute_polling_trigger_success(integration):
    @integration.polling_trigger("test_trigger")
    class Handler(PollingTriggerHandler):
        async def poll(self, inputs, last_poll_ts, context):
            return [{"id": "1", "data": {"message": "hello"}}]

    ctx = ExecutionContext(auth={"api_key": "k"})
    records = await integration.execute_polling_trigger(
        "test_trigger", {"channel": "general"}, None, ctx
    )

    assert len(records) == 1
    assert records[0]["id"] == "1"
    assert records[0]["data"]["message"] == "hello"


async def test_execute_polling_trigger_missing_id(integration):
    @integration.polling_trigger("test_trigger")
    class Handler(PollingTriggerHandler):
        async def poll(self, inputs, last_poll_ts, context):
            return [{"data": {"message": "no id"}}]

    ctx = ExecutionContext(auth={"api_key": "k"})
    with pytest.raises(ValidationError, match="id"):
        await integration.execute_polling_trigger(
            "test_trigger", {"channel": "general"}, None, ctx
        )


# ── Connected account ───────────────────────────────────────────────────────


def test_register_connected_account(integration):
    @integration.connected_account()
    class Handler(ConnectedAccountHandler):
        async def get_account_info(self, context):
            return ConnectedAccountInfo()

    assert integration._connected_account_handler is not None


async def test_get_connected_account_success(integration):
    @integration.connected_account()
    class Handler(ConnectedAccountHandler):
        async def get_account_info(self, context):
            return ConnectedAccountInfo(email="a@b.com", first_name="Alice")

    ctx = ExecutionContext(auth={"api_key": "k"})
    result = await integration.get_connected_account(ctx)

    assert result.type == ResultType.CONNECTED_ACCOUNT
    assert result.result.email == "a@b.com"
    assert result.result.first_name == "Alice"


async def test_get_connected_account_wrong_type(integration):
    @integration.connected_account()
    class Handler(ConnectedAccountHandler):
        async def get_account_info(self, context):
            return {"email": "raw dict"}

    ctx = ExecutionContext(auth={"api_key": "k"})
    with pytest.raises(ValidationError, match="ConnectedAccountInfo"):
        await integration.get_connected_account(ctx)


# ── Interval parsing ────────────────────────────────────────────────────────


def test_parse_interval():
    assert Integration._parse_interval("30s") == timedelta(seconds=30)
    assert Integration._parse_interval("5m") == timedelta(minutes=5)
    assert Integration._parse_interval("2h") == timedelta(hours=2)
    assert Integration._parse_interval("1d") == timedelta(days=1)


def test_parse_interval_invalid():
    with pytest.raises(ConfigurationError, match="Invalid interval"):
        Integration._parse_interval("10x")


# ── Auth validation in actions ──────────────────────────────────────────────


async def test_execute_action_auth_validation_failure(integration):
    """Invalid auth credentials (missing required api_key) → VALIDATION_ERROR."""

    @integration.action("test_action")
    class Handler(ActionHandler):
        async def execute(self, inputs, context):
            return ActionResult(data={"greeting": "hi"})

    ctx = ExecutionContext(auth={})  # missing required api_key
    result = await integration.execute_action("test_action", {"name": "x"}, ctx)

    assert result.type == ResultType.VALIDATION_ERROR


async def test_execute_action_no_auth_fields_in_config(tmp_path):
    """Config without auth.fields skips auth validation entirely."""
    config = {
        "name": "no-auth",
        "version": "1.0.0",
        "description": "No auth fields",
        "auth": {},
        "actions": {
            "simple": {
                "description": "A simple action",
                "input_schema": {
                    "type": "object",
                    "properties": {"x": {"type": "string"}},
                    "required": ["x"],
                },
                "output_schema": {
                    "type": "object",
                    "properties": {"y": {"type": "string"}},
                    "required": ["y"],
                },
            }
        },
    }
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(config))
    intg = Integration.load(config_file)

    @intg.action("simple")
    class Handler(ActionHandler):
        async def execute(self, inputs, context):
            return ActionResult(data={"y": "ok"})

    ctx = ExecutionContext()  # no auth at all
    result = await intg.execute_action("simple", {"x": "test"}, ctx)

    assert result.type == ResultType.ACTION


# ── Polling trigger edge cases ──────────────────────────────────────────────


async def test_execute_polling_trigger_not_registered(integration):
    ctx = ExecutionContext(auth={"api_key": "k"})
    with pytest.raises(ValidationError, match="not registered"):
        await integration.execute_polling_trigger(
            "test_trigger", {"channel": "general"}, None, ctx
        )


async def test_execute_polling_trigger_missing_data(integration):
    """Record has 'id' but no 'data' field → ValidationError."""

    @integration.polling_trigger("test_trigger")
    class Handler(PollingTriggerHandler):
        async def poll(self, inputs, last_poll_ts, context):
            return [{"id": "1"}]  # missing 'data'

    ctx = ExecutionContext(auth={"api_key": "k"})
    with pytest.raises(ValidationError, match="data"):
        await integration.execute_polling_trigger(
            "test_trigger", {"channel": "general"}, None, ctx
        )


async def test_execute_polling_trigger_output_schema_mismatch(integration):
    """Record data doesn't match output_schema → ValidationError."""

    @integration.polling_trigger("test_trigger")
    class Handler(PollingTriggerHandler):
        async def poll(self, inputs, last_poll_ts, context):
            return [{"id": "1", "data": {"wrong_field": 123}}]

    ctx = ExecutionContext(auth={"api_key": "k"})
    with pytest.raises(ValidationError):
        await integration.execute_polling_trigger(
            "test_trigger", {"channel": "general"}, None, ctx
        )


async def test_execute_polling_trigger_multiple_records(integration):
    @integration.polling_trigger("test_trigger")
    class Handler(PollingTriggerHandler):
        async def poll(self, inputs, last_poll_ts, context):
            return [
                {"id": "1", "data": {"message": "first"}},
                {"id": "2", "data": {"message": "second"}},
                {"id": "3", "data": {"message": "third"}},
            ]

    ctx = ExecutionContext(auth={"api_key": "k"})
    records = await integration.execute_polling_trigger(
        "test_trigger", {"channel": "general"}, None, ctx
    )

    assert len(records) == 3
    assert [r["id"] for r in records] == ["1", "2", "3"]


# ── Connected account edge cases ────────────────────────────────────────────


async def test_get_connected_account_no_handler(integration):
    ctx = ExecutionContext(auth={"api_key": "k"})
    with pytest.raises(ValidationError, match="No connected account handler"):
        await integration.get_connected_account(ctx)


async def test_get_connected_account_auth_validation_failure(integration):
    @integration.connected_account()
    class Handler(ConnectedAccountHandler):
        async def get_account_info(self, context):
            return ConnectedAccountInfo(email="a@b.com")

    ctx = ExecutionContext(auth={})  # missing required api_key
    with pytest.raises(ValidationError):
        await integration.get_connected_account(ctx)


async def test_get_connected_account_no_auth_fields(tmp_path):
    """Config without auth.fields skips auth validation for connected accounts."""
    config = {
        "name": "no-auth",
        "version": "1.0.0",
        "description": "No auth",
        "auth": {},
        "actions": {},
    }
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(config))
    intg = Integration.load(config_file)

    @intg.connected_account()
    class Handler(ConnectedAccountHandler):
        async def get_account_info(self, context):
            return ConnectedAccountInfo(email="a@b.com")

    ctx = ExecutionContext()
    result = await intg.get_connected_account(ctx)

    assert result.type == ResultType.CONNECTED_ACCOUNT
    assert result.result.email == "a@b.com"


# ── Config loading edge cases ───────────────────────────────────────────────


def test_load_config_default_path():
    """Integration.load() with no args uses __file__-relative default path."""
    with pytest.raises(ConfigurationError, match="not found"):
        Integration.load()  # no config.json at the default location


def test_load_config_no_actions_no_triggers(tmp_path):
    config = {
        "name": "empty",
        "version": "1.0.0",
        "description": "No actions or triggers",
        "auth": {},
        "actions": {},
    }
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(config))
    intg = Integration.load(config_file)

    assert intg.config.name == "empty"
    assert intg.config.actions == {}
    assert intg.config.polling_triggers == {}


# ── Multiple actions / re-registration ──────────────────────────────────────


async def test_multiple_actions(tmp_path):
    """Register and execute two different actions independently."""
    config = {
        "name": "multi",
        "version": "1.0.0",
        "description": "Multi-action",
        "auth": {},
        "actions": {
            "greet": {
                "description": "Greet",
                "input_schema": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}},
                    "required": ["name"],
                },
                "output_schema": {
                    "type": "object",
                    "properties": {"msg": {"type": "string"}},
                    "required": ["msg"],
                },
            },
            "add": {
                "description": "Add",
                "input_schema": {
                    "type": "object",
                    "properties": {"a": {"type": "integer"}, "b": {"type": "integer"}},
                    "required": ["a", "b"],
                },
                "output_schema": {
                    "type": "object",
                    "properties": {"sum": {"type": "integer"}},
                    "required": ["sum"],
                },
            },
        },
    }
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(config))
    intg = Integration.load(config_file)

    @intg.action("greet")
    class GreetHandler(ActionHandler):
        async def execute(self, inputs, context):
            return ActionResult(data={"msg": f"Hi {inputs['name']}"})

    @intg.action("add")
    class AddHandler(ActionHandler):
        async def execute(self, inputs, context):
            return ActionResult(data={"sum": inputs["a"] + inputs["b"]})

    ctx = ExecutionContext()

    r1 = await intg.execute_action("greet", {"name": "Alice"}, ctx)
    assert r1.type == ResultType.ACTION
    assert r1.result.data == {"msg": "Hi Alice"}

    r2 = await intg.execute_action("add", {"a": 2, "b": 3}, ctx)
    assert r2.type == ResultType.ACTION
    assert r2.result.data == {"sum": 5}


def test_register_polling_trigger_not_in_config(integration):
    with pytest.raises(ConfigurationError, match="not defined in config"):

        @integration.polling_trigger("nonexistent_trigger")
        class Handler(PollingTriggerHandler):
            async def poll(self, inputs, last_poll_ts, context):
                return []


async def test_execute_polling_trigger_invalid_inputs(integration):
    """Invalid inputs against trigger input_schema → ValidationError."""

    @integration.polling_trigger("test_trigger")
    class Handler(PollingTriggerHandler):
        async def poll(self, inputs, last_poll_ts, context):
            return []

    ctx = ExecutionContext(auth={"api_key": "k"})
    with pytest.raises(ValidationError):
        await integration.execute_polling_trigger(
            "test_trigger", {}, None, ctx  # missing required 'channel'
        )


async def test_execute_polling_trigger_auth_failure(integration):
    """Invalid auth credentials for polling trigger → ValidationError."""

    @integration.polling_trigger("test_trigger")
    class Handler(PollingTriggerHandler):
        async def poll(self, inputs, last_poll_ts, context):
            return []

    ctx = ExecutionContext(auth={})  # missing required api_key
    with pytest.raises(ValidationError):
        await integration.execute_polling_trigger(
            "test_trigger", {"channel": "general"}, None, ctx
        )


def test_re_register_handler_overwrites(integration):
    """Decorating the same action name twice overwrites the first handler."""

    @integration.action("test_action")
    class First(ActionHandler):
        async def execute(self, inputs, context):
            return ActionResult(data={"greeting": "first"})

    @integration.action("test_action")
    class Second(ActionHandler):
        async def execute(self, inputs, context):
            return ActionResult(data={"greeting": "second"})

    assert integration._action_handlers["test_action"] is Second
