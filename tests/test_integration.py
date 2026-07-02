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

    ctx = ExecutionContext(auth={"auth_type": "Custom", "credentials": {"api_key": "k"}})
    result = await integration.execute_action("test_action", {"name": "World"}, ctx)

    assert result.type == ResultType.ACTION
    assert result.result.data == {"greeting": "Hello World"}
    assert result.version is not None


async def test_execute_action_with_cost(integration):
    @integration.action("test_action")
    class Handler(ActionHandler):
        async def execute(self, inputs, context):
            return ActionResult(data={"greeting": "hi"}, cost_usd=0.05)

    ctx = ExecutionContext(auth={"auth_type": "Custom", "credentials": {"api_key": "k"}})
    result = await integration.execute_action("test_action", {"name": "x"}, ctx)

    assert result.type == ResultType.ACTION
    assert result.result.cost_usd == 0.05


async def test_execute_action_invalid_inputs(integration):
    @integration.action("test_action")
    class Handler(ActionHandler):
        async def execute(self, inputs, context):
            return ActionResult(data={"greeting": "hi"})

    ctx = ExecutionContext(auth={"auth_type": "Custom", "credentials": {"api_key": "k"}})
    result = await integration.execute_action("test_action", {}, ctx)

    assert result.type == ResultType.VALIDATION_ERROR


async def test_execute_action_invalid_output(integration):
    @integration.action("test_action")
    class Handler(ActionHandler):
        async def execute(self, inputs, context):
            return ActionResult(data={"wrong_key": 123})

    ctx = ExecutionContext(auth={"auth_type": "Custom", "credentials": {"api_key": "k"}})
    result = await integration.execute_action("test_action", {"name": "x"}, ctx)

    assert result.type == ResultType.VALIDATION_ERROR


async def test_execute_action_wrong_return_type(integration):
    @integration.action("test_action")
    class Handler(ActionHandler):
        async def execute(self, inputs, context):
            return {"greeting": "plain dict"}

    ctx = ExecutionContext(auth={"auth_type": "Custom", "credentials": {"api_key": "k"}})
    result = await integration.execute_action("test_action", {"name": "x"}, ctx)

    assert result.type == ResultType.VALIDATION_ERROR


async def test_execute_action_not_registered(integration):
    ctx = ExecutionContext(auth={"auth_type": "Custom", "credentials": {"api_key": "k"}})
    result = await integration.execute_action("test_action", {"name": "x"}, ctx)

    assert result.type == ResultType.VALIDATION_ERROR


async def test_execute_action_error(integration):
    @integration.action("test_action")
    class Handler(ActionHandler):
        async def execute(self, inputs, context):
            return ActionError(message="something went wrong", cost_usd=0.01)

    ctx = ExecutionContext(auth={"auth_type": "Custom", "credentials": {"api_key": "k"}})
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

    ctx = ExecutionContext(auth={"auth_type": "Custom", "credentials": {"api_key": "k"}})
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

    ctx = ExecutionContext(auth={"auth_type": "Custom", "credentials": {"api_key": "k"}})
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

    ctx = ExecutionContext(auth={"auth_type": "Custom", "credentials": {"api_key": "k"}})
    result = await integration.get_connected_account(ctx)

    assert result.type == ResultType.CONNECTED_ACCOUNT
    assert result.result.email == "a@b.com"
    assert result.result.first_name == "Alice"


async def test_get_connected_account_wrong_type(integration):
    @integration.connected_account()
    class Handler(ConnectedAccountHandler):
        async def get_account_info(self, context):
            return {"email": "raw dict"}

    ctx = ExecutionContext(auth={"auth_type": "Custom", "credentials": {"api_key": "k"}})
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
    """Wrapped auth missing a required credential → VALIDATION_ERROR (source 'auth')."""

    @integration.action("test_action")
    class Handler(ActionHandler):
        async def execute(self, inputs, context):
            return ActionResult(data={"greeting": "hi"})

    # Wrapped envelope, but credentials are missing the required api_key.
    ctx = ExecutionContext(auth={"auth_type": "Custom", "credentials": {}})
    result = await integration.execute_action("test_action", {"name": "x"}, ctx)

    assert result.type == ResultType.VALIDATION_ERROR
    assert result.result["source"] == "auth"


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
    ctx = ExecutionContext(auth={"auth_type": "Custom", "credentials": {"api_key": "k"}})
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

    ctx = ExecutionContext(auth={"auth_type": "Custom", "credentials": {"api_key": "k"}})
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

    ctx = ExecutionContext(auth={"auth_type": "Custom", "credentials": {"api_key": "k"}})
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

    ctx = ExecutionContext(auth={"auth_type": "Custom", "credentials": {"api_key": "k"}})
    records = await integration.execute_polling_trigger(
        "test_trigger", {"channel": "general"}, None, ctx
    )

    assert len(records) == 3
    assert [r["id"] for r in records] == ["1", "2", "3"]


# ── Connected account edge cases ────────────────────────────────────────────


async def test_get_connected_account_no_handler(integration):
    ctx = ExecutionContext(auth={"auth_type": "Custom", "credentials": {"api_key": "k"}})
    with pytest.raises(ValidationError, match="No connected account handler"):
        await integration.get_connected_account(ctx)


async def test_get_connected_account_auth_validation_failure(integration):
    @integration.connected_account()
    class Handler(ConnectedAccountHandler):
        async def get_account_info(self, context):
            return ConnectedAccountInfo(email="a@b.com")

    # Wrapped envelope, but credentials are missing the required api_key.
    ctx = ExecutionContext(auth={"auth_type": "Custom", "credentials": {}})
    with pytest.raises(ValidationError) as exc_info:
        await integration.get_connected_account(ctx)
    assert exc_info.value.source == "auth"


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

    ctx = ExecutionContext(auth={"auth_type": "Custom", "credentials": {"api_key": "k"}})
    with pytest.raises(ValidationError):
        await integration.execute_polling_trigger(
            "test_trigger", {}, None, ctx  # missing required 'channel'
        )


async def test_execute_polling_trigger_auth_failure(integration):
    """Wrapped auth missing a required credential for polling trigger → ValidationError."""

    @integration.polling_trigger("test_trigger")
    class Handler(PollingTriggerHandler):
        async def poll(self, inputs, last_poll_ts, context):
            return []

    # Wrapped envelope, but credentials are missing the required api_key.
    ctx = ExecutionContext(auth={"auth_type": "Custom", "credentials": {}})
    with pytest.raises(ValidationError) as exc_info:
        await integration.execute_polling_trigger(
            "test_trigger", {"channel": "general"}, None, ctx
        )
    assert exc_info.value.source == "auth"


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


# ── Abstract base class pass-through ───────────────────────────────────────


async def test_action_handler_abstract_execute_returns_none():
    """super().execute() on the ABC body executes the `pass` and returns None."""

    class Concrete(ActionHandler):
        async def execute(self, inputs, context):
            return await super().execute(inputs, context)

    result = await Concrete().execute({}, None)
    assert result is None


async def test_polling_trigger_handler_abstract_poll_returns_none():
    """super().poll() on the ABC body executes the `pass` and returns None."""

    class Concrete(PollingTriggerHandler):
        async def poll(self, inputs, last_poll_ts, context):
            return await super().poll(inputs, last_poll_ts, context)

    result = await Concrete().poll({}, None, None)
    assert result is None


async def test_connected_account_handler_abstract_get_account_info_returns_none():
    """super().get_account_info() on the ABC body executes the `pass` and returns None."""

    class Concrete(ConnectedAccountHandler):
        async def get_account_info(self, context):
            return await super().get_account_info(context)

    result = await Concrete().get_account_info(None)
    assert result is None


# ── Strict wrapped-auth validation (SDK 3.0.0) ──────────────────────────────


def _no_required_auth_config():
    """Config whose auth.fields has properties but no required list."""
    return {
        "name": "no-required-auth",
        "version": "1.0.0",
        "description": "Auth fields without a required list",
        "auth": {
            "auth_type": "Custom",
            "fields": {
                "type": "object",
                "properties": {"api_key": {"type": "string"}},
            },
        },
        "actions": {
            "test_action": {
                "description": "A simple test action",
                "input_schema": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}},
                    "required": ["name"],
                },
                "output_schema": {
                    "type": "object",
                    "properties": {"greeting": {"type": "string"}},
                    "required": ["greeting"],
                },
            }
        },
        "polling_triggers": {
            "test_trigger": {
                "description": "A simple test trigger",
                "polling_interval": "5m",
                "input_schema": {
                    "type": "object",
                    "properties": {"channel": {"type": "string"}},
                    "required": ["channel"],
                },
                "output_schema": {
                    "type": "object",
                    "properties": {"message": {"type": "string"}},
                    "required": ["message"],
                },
            }
        },
    }


async def test_execute_action_wrapped_auth_success(integration):
    """Wrapped auth with a non-empty required credential passes and runs the action."""

    @integration.action("test_action")
    class Handler(ActionHandler):
        async def execute(self, inputs, context):
            return ActionResult(data={"greeting": f"Hello {inputs['name']}"})

    ctx = ExecutionContext(
        auth={"auth_type": "Custom", "credentials": {"api_key": "k"}}
    )
    result = await integration.execute_action("test_action", {"name": "World"}, ctx)

    assert result.type == ResultType.ACTION
    assert result.result.data == {"greeting": "Hello World"}


async def test_execute_action_flat_auth_rejected(integration):
    """Flat auth (no credentials key) fails with the explicit envelope error."""

    @integration.action("test_action")
    class Handler(ActionHandler):
        async def execute(self, inputs, context):
            return ActionResult(data={"greeting": "hi"})

    ctx = ExecutionContext(auth={"api_key": "k"})  # flat, no envelope
    result = await integration.execute_action("test_action", {"name": "x"}, ctx)

    assert result.type == ResultType.VALIDATION_ERROR
    assert result.result["source"] == "auth"
    assert "envelope" in result.result["message"]
    assert "3.0.0" in result.result["message"]


async def test_execute_action_missing_auth_type_rejected(integration):
    """Envelope without auth_type is rejected with the explicit envelope error."""

    @integration.action("test_action")
    class Handler(ActionHandler):
        async def execute(self, inputs, context):
            return ActionResult(data={"greeting": "hi"})

    # Has credentials but no auth_type — the undocumented third shape.
    ctx = ExecutionContext(auth={"credentials": {"api_key": "k"}})
    result = await integration.execute_action("test_action", {"name": "x"}, ctx)

    assert result.type == ResultType.VALIDATION_ERROR
    assert result.result["source"] == "auth"
    assert "auth_type" in result.result["message"]


async def test_execute_action_empty_auth_type_rejected(integration):
    """Envelope with an empty-string auth_type is rejected."""

    @integration.action("test_action")
    class Handler(ActionHandler):
        async def execute(self, inputs, context):
            return ActionResult(data={"greeting": "hi"})

    ctx = ExecutionContext(auth={"auth_type": "", "credentials": {"api_key": "k"}})
    result = await integration.execute_action("test_action", {"name": "x"}, ctx)

    assert result.type == ResultType.VALIDATION_ERROR
    assert result.result["source"] == "auth"


async def test_execute_polling_trigger_missing_auth_type_rejected(integration):
    """Envelope without auth_type is rejected for polling triggers via the shared helper."""

    @integration.polling_trigger("test_trigger")
    class Handler(PollingTriggerHandler):
        async def poll(self, inputs, last_poll_ts, context):
            return []

    ctx = ExecutionContext(auth={"credentials": {"api_key": "k"}})
    with pytest.raises(ValidationError) as exc_info:
        await integration.execute_polling_trigger(
            "test_trigger", {"channel": "general"}, None, ctx
        )
    assert exc_info.value.source == "auth"
    assert "auth_type" in exc_info.value.message


async def test_get_connected_account_missing_auth_type_rejected(integration):
    """Envelope without auth_type is rejected for connected accounts via the shared helper."""

    @integration.connected_account()
    class Handler(ConnectedAccountHandler):
        async def get_account_info(self, context):
            return ConnectedAccountInfo(email="a@b.com")

    ctx = ExecutionContext(auth={"credentials": {"api_key": "k"}})
    with pytest.raises(ValidationError) as exc_info:
        await integration.get_connected_account(ctx)
    assert exc_info.value.source == "auth"
    assert "auth_type" in exc_info.value.message


async def test_execute_action_empty_credentials_no_required_passes(tmp_path):
    """Empty credentials pass when auth.fields has no required list."""
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(_no_required_auth_config()))
    intg = Integration.load(config_file)

    @intg.action("test_action")
    class Handler(ActionHandler):
        async def execute(self, inputs, context):
            return ActionResult(data={"greeting": "hi"})

    ctx = ExecutionContext(auth={"auth_type": "Custom", "credentials": {}})
    result = await intg.execute_action("test_action", {"name": "x"}, ctx)

    assert result.type == ResultType.ACTION


async def test_execute_polling_trigger_wrapped_auth_success(integration):
    """Wrapped auth with a required credential passes for polling triggers."""

    @integration.polling_trigger("test_trigger")
    class Handler(PollingTriggerHandler):
        async def poll(self, inputs, last_poll_ts, context):
            return [{"id": "1", "data": {"message": "hello"}}]

    ctx = ExecutionContext(
        auth={"auth_type": "Custom", "credentials": {"api_key": "k"}}
    )
    records = await integration.execute_polling_trigger(
        "test_trigger", {"channel": "general"}, None, ctx
    )

    assert len(records) == 1
    assert records[0]["id"] == "1"


async def test_execute_polling_trigger_flat_auth_rejected(integration):
    """Flat auth is rejected for polling triggers with the explicit envelope error."""

    @integration.polling_trigger("test_trigger")
    class Handler(PollingTriggerHandler):
        async def poll(self, inputs, last_poll_ts, context):
            return []

    ctx = ExecutionContext(auth={"api_key": "k"})  # flat, no envelope
    with pytest.raises(ValidationError) as exc_info:
        await integration.execute_polling_trigger(
            "test_trigger", {"channel": "general"}, None, ctx
        )
    assert exc_info.value.source == "auth"
    assert "envelope" in exc_info.value.message


async def test_execute_polling_trigger_empty_credentials_no_required_passes(tmp_path):
    """Empty credentials pass for polling triggers when auth.fields has no required."""
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(_no_required_auth_config()))
    intg = Integration.load(config_file)

    @intg.polling_trigger("test_trigger")
    class Handler(PollingTriggerHandler):
        async def poll(self, inputs, last_poll_ts, context):
            return [{"id": "1", "data": {"message": "hello"}}]

    ctx = ExecutionContext(auth={"auth_type": "Custom", "credentials": {}})
    records = await intg.execute_polling_trigger(
        "test_trigger", {"channel": "general"}, None, ctx
    )

    assert len(records) == 1


async def test_get_connected_account_wrapped_auth_success(integration):
    """Wrapped auth with a required credential passes for connected accounts."""

    @integration.connected_account()
    class Handler(ConnectedAccountHandler):
        async def get_account_info(self, context):
            return ConnectedAccountInfo(email="a@b.com")

    ctx = ExecutionContext(
        auth={"auth_type": "Custom", "credentials": {"api_key": "k"}}
    )
    result = await integration.get_connected_account(ctx)

    assert result.type == ResultType.CONNECTED_ACCOUNT
    assert result.result.email == "a@b.com"


async def test_get_connected_account_flat_auth_rejected(integration):
    """Flat auth is rejected for connected accounts with the explicit envelope error."""

    @integration.connected_account()
    class Handler(ConnectedAccountHandler):
        async def get_account_info(self, context):
            return ConnectedAccountInfo(email="a@b.com")

    ctx = ExecutionContext(auth={"api_key": "k"})  # flat, no envelope
    with pytest.raises(ValidationError) as exc_info:
        await integration.get_connected_account(ctx)
    assert exc_info.value.source == "auth"
    assert "envelope" in exc_info.value.message


async def test_get_connected_account_empty_credentials_no_required_passes(tmp_path):
    """Empty credentials pass for connected accounts when auth.fields has no required."""
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(_no_required_auth_config()))
    intg = Integration.load(config_file)

    @intg.connected_account()
    class Handler(ConnectedAccountHandler):
        async def get_account_info(self, context):
            return ConnectedAccountInfo(email="a@b.com")

    ctx = ExecutionContext(auth={"auth_type": "Custom", "credentials": {}})
    result = await intg.get_connected_account(ctx)

    assert result.type == ResultType.CONNECTED_ACCOUNT


# ── ExecutionContext.credentials property ───────────────────────────────────


def test_execution_context_credentials_unwraps_envelope():
    ctx = ExecutionContext(
        auth={"auth_type": "Custom", "credentials": {"api_key": "k", "api_url": "u"}}
    )
    assert ctx.credentials == {"api_key": "k", "api_url": "u"}


def test_execution_context_credentials_empty_when_no_auth():
    ctx = ExecutionContext()
    assert ctx.credentials == {}


def test_execution_context_credentials_empty_when_no_credentials_key():
    ctx = ExecutionContext(auth={"auth_type": "Custom"})
    assert ctx.credentials == {}


def test_execution_context_credentials_empty_when_auth_not_dict():
    ctx = ExecutionContext(auth=None)
    assert ctx.credentials == {}
