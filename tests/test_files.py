"""Tests for file values: the file schema and the File type."""

import base64
import json

import pytest

from autohive_integrations_sdk import (
    FILE_SCHEMA_ID,
    ActionError,
    ActionHandler,
    ActionResult,
    ExecutionContext,
    File,
    Integration,
    ResultType,
)
from autohive_integrations_sdk.files import FileTransferError

FILE_REF = {"$ref": FILE_SCHEMA_ID}
LEGACY_FILE_SCHEMA = {
    "type": "object",
    "properties": {"content": {"type": "string"}, "name": {"type": "string"}, "contentType": {"type": "string"}},
    "required": ["content", "name", "contentType"],
}


def make_integration(tmp_path, input_properties=None, output_properties=None) -> Integration:
    config = {
        "name": "files-test",
        "version": "1.0.0",
        "description": "Integration for the file tests",
        "auth": {},
        "actions": {
            "run": {
                "description": "The action under test",
                "input_schema": {"type": "object", "properties": input_properties or {}},
                "output_schema": {"type": "object", "properties": output_properties or {}},
            }
        },
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config))
    return Integration.load(path)


async def run_action(integration, execute, inputs=None):
    @integration.action("run")
    class Handler(ActionHandler):
        async def execute(self, action_inputs, context):
            return await execute(action_inputs, context)

    async with ExecutionContext() as context:
        return await integration.execute_action("run", inputs or {}, context)


def wire_content(data: bytes, name="a.bin") -> dict:
    return {"name": name, "contentType": "application/octet-stream", "content": base64.b64encode(data).decode()}


# ── File inputs ──────────────────────────────────────────────────────────────


async def test_inline_input_arrives_as_a_file(tmp_path):
    seen = {}

    async def execute(inputs, context):
        seen["file"] = inputs["doc"]
        seen["data"] = await inputs["doc"].read()
        return ActionResult(data={})

    integration = make_integration(tmp_path, {"doc": FILE_REF})
    result = await run_action(integration, execute, {"doc": wire_content(b"hello", "note.txt")})

    assert result.type == ResultType.ACTION
    assert isinstance(seen["file"], File)
    assert (seen["file"].name, seen["file"].content_type, seen["file"].size) == ("note.txt", "application/octet-stream", 5)
    assert seen["data"] == b"hello"
    assert "note.txt" in repr(seen["file"])


async def test_file_field_can_have_any_name_and_a_description(tmp_path):
    seen = {}

    async def execute(inputs, context):
        seen.update(inputs)
        return ActionResult(data={})

    field = {"$ref": FILE_SCHEMA_ID, "description": "The invoice PDF"}
    integration = make_integration(tmp_path, {"invoice": field})
    result = await run_action(integration, execute, {"invoice": wire_content(b"a")})

    assert result.type == ResultType.ACTION
    assert isinstance(seen["invoice"], File)


async def test_files_in_arrays_and_nested_objects_are_converted(tmp_path):
    seen = {}

    async def execute(inputs, context):
        seen.update(inputs)
        return ActionResult(data={})

    properties = {
        "attachments": {"type": "array", "items": {"type": "object", "properties": {"file": FILE_REF}}},
        "docs": {"type": "array", "items": FILE_REF},
    }
    integration = make_integration(tmp_path, properties)
    inputs = {
        "attachments": [{"file": wire_content(b"a"), "caption": "first"}],
        "docs": [wire_content(b"b"), wire_content(b"c")],
    }
    result = await run_action(integration, execute, inputs)

    assert result.type == ResultType.ACTION
    assert isinstance(seen["attachments"][0]["file"], File)
    assert seen["attachments"][0]["caption"] == "first"
    assert [type(doc) for doc in seen["docs"]] == [File, File]


async def test_file_shaped_value_outside_a_file_field_is_left_alone(tmp_path):
    """Only a field declared with the file schema is converted, whatever shape another value has."""
    seen = {}

    async def execute(inputs, context):
        seen.update(inputs)
        return ActionResult(data={})

    integration = make_integration(tmp_path, {"note": {"type": "object"}, "items": {"type": "array"}})
    shaped = {"name": "x", "contentType": "text/plain", "url": "https://example.com/x"}
    result = await run_action(integration, execute, {"note": shaped, "items": [shaped], "extra": shaped})

    assert result.type == ResultType.ACTION
    assert seen == {"note": shaped, "items": [shaped], "extra": shaped}


async def test_field_with_the_older_file_convention_keeps_its_dict(tmp_path):
    seen = {}

    async def execute(inputs, context):
        seen.update(inputs)
        return ActionResult(data={"file": inputs["file"]})

    integration = make_integration(tmp_path, {"file": LEGACY_FILE_SCHEMA}, {"file": LEGACY_FILE_SCHEMA})
    value = wire_content(b"hello", "note.txt")
    result = await run_action(integration, execute, {"file": value})

    assert result.type == ResultType.ACTION
    assert seen["file"] == value
    assert result.result.data == {"file": value}


async def test_input_that_matches_no_file_form_is_a_validation_error(tmp_path):
    async def execute(inputs, context):
        return ActionResult(data={})

    integration = make_integration(tmp_path, {"doc": FILE_REF})
    result = await run_action(integration, execute, {"doc": {"name": "a", "contentType": "text/plain"}})

    assert result.type == ResultType.VALIDATION_ERROR
    assert result.result["source"] == "input"


@pytest.mark.parametrize("value, expected", [
    ({"name": "a", "contentType": "text/plain", "key": "tool-outputs/x/a", "sizeBytes": 1}, "has no content"),
    ({"name": "a", "contentType": "text/plain", "content": "not base64!"}, "not valid base64"),
])
async def test_input_the_sdk_cannot_read_is_a_validation_error(tmp_path, value, expected):
    async def execute(inputs, context):
        return ActionResult(data={})

    integration = make_integration(tmp_path, {"doc": FILE_REF})
    result = await run_action(integration, execute, {"doc": value})

    assert result.type == ResultType.VALIDATION_ERROR
    assert result.result["source"] == "input"
    assert expected in result.result["message"]


# ── File outputs ─────────────────────────────────────────────────────────────


async def test_output_file_is_returned_inline(tmp_path):
    async def execute(inputs, context):
        return ActionResult(data={"doc": File.from_bytes(b"hello", "note.txt", "text/plain"), "count": 1})

    integration = make_integration(tmp_path, output_properties={"doc": FILE_REF})
    result = await run_action(integration, execute)

    assert result.type == ResultType.ACTION
    assert result.result.data == {
        "doc": {"name": "note.txt", "contentType": "text/plain", "content": base64.b64encode(b"hello").decode()},
        "count": 1,
    }


async def test_output_files_in_arrays_and_nested_objects_are_converted(tmp_path):
    async def execute(inputs, context):
        return ActionResult(data={
            "docs": [File.from_bytes(b"a", "a.txt", "text/plain")],
            "report": {"file": File.from_bytes(b"b", "b.txt", "text/plain")},
        })

    properties = {
        "docs": {"type": "array", "items": FILE_REF},
        "report": {"type": "object", "properties": {"file": FILE_REF}},
    }
    integration = make_integration(tmp_path, output_properties=properties)
    result = await run_action(integration, execute)

    assert result.type == ResultType.ACTION
    assert result.result.data["docs"][0]["name"] == "a.txt"
    assert base64.b64decode(result.result.data["report"]["file"]["content"]) == b"b"


async def test_input_file_can_be_returned_as_an_output(tmp_path):
    async def execute(inputs, context):
        return ActionResult(data={"doc": inputs["doc"]})

    integration = make_integration(tmp_path, {"doc": FILE_REF}, {"doc": FILE_REF})
    value = wire_content(b"hello", "note.txt")
    result = await run_action(integration, execute, {"doc": value})

    assert result.type == ResultType.ACTION
    assert result.result.data == {"doc": value}


async def test_action_error_from_the_handler_is_returned_unchanged(tmp_path):
    async def execute(inputs, context):
        return ActionError(message="not found")

    integration = make_integration(tmp_path, output_properties={"doc": FILE_REF})
    result = await run_action(integration, execute)

    assert result.type == ResultType.ACTION_ERROR
    assert result.result.message == "not found"


async def test_file_without_content_is_an_action_error(tmp_path):
    async def execute(inputs, context):
        return ActionResult(data={"doc": File("empty.bin", "a/b")})

    integration = make_integration(tmp_path, output_properties={"doc": FILE_REF})
    result = await run_action(integration, execute)

    assert result.type == ResultType.ACTION_ERROR
    assert "has no content" in result.result.message


async def test_cost_is_kept_when_an_output_file_cannot_be_read(tmp_path):
    async def execute(inputs, context):
        return ActionResult(data={"doc": File("empty.bin", "a/b")}, cost_usd=0.25)

    integration = make_integration(tmp_path, output_properties={"doc": FILE_REF})
    result = await run_action(integration, execute)

    assert result.type == ResultType.ACTION_ERROR
    assert result.result.cost_usd == 0.25


async def test_file_error_raised_inside_the_handler_is_an_action_error_without_a_cost(tmp_path):
    async def execute(inputs, context):
        await File("empty.bin", "a/b").read()
        return ActionResult(data={}, cost_usd=0.25)

    integration = make_integration(tmp_path)
    result = await run_action(integration, execute)

    assert result.type == ResultType.ACTION_ERROR
    assert "has no content" in result.result.message
    assert result.result.cost_usd is None


async def test_file_transfer_error_is_not_exported():
    import autohive_integrations_sdk

    assert not hasattr(autohive_integrations_sdk, "FileTransferError")
    assert issubclass(FileTransferError, Exception)


# ── The file schema ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("value", [
    {"name": "a", "contentType": "text/plain", "content": "aGk="},
    {"name": "a", "contentType": "text/plain", "url": "https://example.com/a", "sizeBytes": 2},
    {"name": "a", "contentType": "text/plain", "key": "tool-outputs/x/a", "sizeBytes": 2},
])
def test_file_schema_accepts_each_wire_form(value):
    from autohive_integrations_sdk.integration import _schema_validator

    assert list(_schema_validator(FILE_REF).iter_errors(value)) == []


@pytest.mark.parametrize("value", [
    {"name": "a", "contentType": "text/plain"},
    {"name": "a", "content": "aGk="},
    {"name": "a", "contentType": "text/plain", "content": "aGk=", "url": "https://example.com/a"},
    "a path string",
])
def test_file_schema_rejects_other_values(value):
    from autohive_integrations_sdk.integration import _schema_validator

    assert list(_schema_validator(FILE_REF).iter_errors(value)) != []


async def test_output_that_is_not_a_file_fails_output_validation(tmp_path):
    async def execute(inputs, context):
        return ActionResult(data={"doc": {"name": "a"}})

    integration = make_integration(tmp_path, output_properties={"doc": FILE_REF})
    result = await run_action(integration, execute)

    assert result.type == ResultType.VALIDATION_ERROR
    assert result.result["source"] == "output"
