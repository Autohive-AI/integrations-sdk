"""Tests for the ActionError class and its integration with execute_action()."""
import asyncio
import sys
import os
from dataclasses import asdict
from pathlib import Path

# Add src to path so we can import the SDK
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from autohive_integrations_sdk import (
    ActionError, ActionResult, ActionHandler, Integration, ExecutionContext,
    IntegrationResult, ResultType, ValidationError
)
from autohive_integrations_sdk.integration import IntegrationConfig, Action


def make_integration_with_action(handler_class):
    """Helper to create an Integration with a single test action and strict output schema."""
    config = IntegrationConfig(
        name="test",
        version="1.0.0",
        description="test integration",
        auth={},
        actions={
            "test_action": Action(
                name="test_action",
                description="A test action",
                input_schema={
                    "type": "object",
                    "properties": {"input_val": {"type": "string"}},
                    "required": ["input_val"]
                },
                output_schema={
                    "type": "object",
                    "properties": {"result": {"type": "string"}},
                    "required": ["result"]
                }
            )
        },
        polling_triggers={}
    )
    integration = Integration(config)
    integration._action_handlers["test_action"] = handler_class
    return integration


# --- Dataclass tests ---

def test_action_error_construction():
    error = ActionError(message="Something went wrong")
    assert error.message == "Something went wrong"


def test_action_error_asdict():
    error = ActionError(message="User not found")
    result = asdict(error)
    assert result == {"message": "User not found"}


# --- execute_action tests ---

def test_action_error_returns_error_result():
    """ActionError should produce IntegrationResult with ResultType.ERROR."""
    class ErrorHandler(ActionHandler):
        async def execute(self, inputs, context):
            return ActionError(message="Something failed")

    integration = make_integration_with_action(ErrorHandler)

    async def run():
        async with ExecutionContext() as ctx:
            return await integration.execute_action("test_action", {"input_val": "test"}, ctx)

    result = asyncio.run(run())
    assert isinstance(result, IntegrationResult)
    assert result.type == ResultType.ERROR
    assert isinstance(result.result, ActionError)
    assert result.result.message == "Something failed"


def test_action_error_skips_output_schema_validation():
    """ActionError should bypass output schema validation (the whole point)."""
    class ErrorHandler(ActionHandler):
        async def execute(self, inputs, context):
            # This message string does NOT match the output schema (which requires {"result": "..."})
            return ActionError(message="API quota exceeded")

    integration = make_integration_with_action(ErrorHandler)

    async def run():
        async with ExecutionContext() as ctx:
            return await integration.execute_action("test_action", {"input_val": "test"}, ctx)

    # Should NOT raise ValidationError
    result = asyncio.run(run())
    assert result.type == ResultType.ERROR


def test_action_result_still_validates_output_schema():
    """Regression: ActionResult.data that doesn't match output schema should still raise."""
    class BadResultHandler(ActionHandler):
        async def execute(self, inputs, context):
            return ActionResult(data={"wrong_field": "value"})

    integration = make_integration_with_action(BadResultHandler)

    async def run():
        async with ExecutionContext() as ctx:
            return await integration.execute_action("test_action", {"input_val": "test"}, ctx)

    try:
        asyncio.run(run())
        assert False, "Should have raised ValidationError"
    except ValidationError:
        pass


def test_invalid_return_type_raises_validation_error():
    """Returning something other than ActionResult or ActionError should raise."""
    class PlainDictHandler(ActionHandler):
        async def execute(self, inputs, context):
            return {"result": "value"}

    integration = make_integration_with_action(PlainDictHandler)

    async def run():
        async with ExecutionContext() as ctx:
            return await integration.execute_action("test_action", {"input_val": "test"}, ctx)

    try:
        asyncio.run(run())
        assert False, "Should have raised ValidationError"
    except ValidationError as e:
        assert "ActionResult or ActionError" in str(e)


def test_action_result_success_path_still_works():
    """Regression: normal ActionResult flow should be unaffected."""
    class SuccessHandler(ActionHandler):
        async def execute(self, inputs, context):
            return ActionResult(data={"result": "success"}, cost_usd=0.01)

    integration = make_integration_with_action(SuccessHandler)

    async def run():
        async with ExecutionContext() as ctx:
            return await integration.execute_action("test_action", {"input_val": "test"}, ctx)

    result = asyncio.run(run())
    assert result.type == ResultType.ACTION
    assert isinstance(result.result, ActionResult)
    assert result.result.data == {"result": "success"}
    assert result.result.cost_usd == 0.01


def test_input_validation_still_runs_before_handler():
    """Input schema validation should still happen even if handler would return ActionError."""
    class ErrorHandler(ActionHandler):
        async def execute(self, inputs, context):
            return ActionError(message="Shouldn't get here")

    integration = make_integration_with_action(ErrorHandler)

    async def run():
        async with ExecutionContext() as ctx:
            # Missing required "input_val" field
            return await integration.execute_action("test_action", {}, ctx)

    try:
        asyncio.run(run())
        assert False, "Should have raised ValidationError for missing input"
    except ValidationError:
        pass


# --- Import test ---

def test_action_error_importable():
    """ActionError should be importable from the top-level package."""
    from autohive_integrations_sdk import ActionError as AE
    assert AE is ActionError


if __name__ == "__main__":
    print("Running ActionError tests...")

    test_action_error_construction()
    print("  PASS: test_action_error_construction")

    test_action_error_asdict()
    print("  PASS: test_action_error_asdict")

    test_action_error_returns_error_result()
    print("  PASS: test_action_error_returns_error_result")

    test_action_error_skips_output_schema_validation()
    print("  PASS: test_action_error_skips_output_schema_validation")

    test_action_result_still_validates_output_schema()
    print("  PASS: test_action_result_still_validates_output_schema")

    test_invalid_return_type_raises_validation_error()
    print("  PASS: test_invalid_return_type_raises_validation_error")

    test_action_result_success_path_still_works()
    print("  PASS: test_action_result_success_path_still_works")

    test_input_validation_still_runs_before_handler()
    print("  PASS: test_input_validation_still_runs_before_handler")

    test_action_error_importable()
    print("  PASS: test_action_error_importable")

    print("\nAll tests passed!")
