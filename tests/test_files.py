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
    assert [await doc.read() for doc in seen["docs"]] == [b"b", b"c"]


async def run_and_capture(tmp_path, input_schema, inputs):
    """Run an action whose whole input schema is ``input_schema``, and return the result and the inputs it saw."""
    seen = {}

    async def execute(action_inputs, context):
        seen.update(action_inputs)
        return ActionResult(data={})

    integration = make_integration(tmp_path)
    integration.config.actions["run"].input_schema = input_schema
    result = await run_action(integration, execute, inputs)
    return result, seen


async def test_nullable_file_declared_with_any_of_is_converted(tmp_path):
    schema = {"type": "object", "properties": {"doc": {"anyOf": [{"type": "null"}, FILE_REF]}}}

    result, seen = await run_and_capture(tmp_path, schema, {"doc": wire_content(b"a")})
    assert result.type == ResultType.ACTION
    assert await seen["doc"].read() == b"a"

    result, seen = await run_and_capture(tmp_path, schema, {"doc": None})
    assert result.type == ResultType.ACTION
    assert seen == {"doc": None}


async def test_file_in_the_branch_of_one_of_that_the_value_matches_is_converted(tmp_path):
    upload = {"type": "object", "properties": {"kind": {"const": "upload"}, "doc": FILE_REF}, "required": ["kind", "doc"]}
    link = {"type": "object", "properties": {"kind": {"const": "link"}, "href": {"type": "string"}}, "required": ["kind", "href"]}
    schema = {"type": "object", "properties": {"source": {"oneOf": [link, upload]}}}

    result, seen = await run_and_capture(tmp_path, schema, {"source": {"kind": "upload", "doc": wire_content(b"a")}})
    assert result.type == ResultType.ACTION
    assert await seen["source"]["doc"].read() == b"a"

    link_value = {"source": {"kind": "link", "href": "https://example.com"}}
    result, seen = await run_and_capture(tmp_path, schema, link_value)
    assert result.type == ResultType.ACTION
    assert seen == link_value


async def test_array_of_files_in_a_branch_of_any_of_is_converted(tmp_path):
    schema = {"type": "object", "properties": {"docs": {"anyOf": [FILE_REF, {"type": "array", "items": FILE_REF}]}}}

    result, seen = await run_and_capture(tmp_path, schema, {"docs": [wire_content(b"a"), wire_content(b"b")]})

    assert result.type == ResultType.ACTION
    assert [await doc.read() for doc in seen["docs"]] == [b"a", b"b"]


async def test_file_declared_inside_all_of_is_converted(tmp_path):
    schema = {"type": "object", "allOf": [{"properties": {"doc": FILE_REF}}, {"required": ["doc"]}]}

    result, seen = await run_and_capture(tmp_path, schema, {"doc": wire_content(b"a")})

    assert result.type == ResultType.ACTION
    assert await seen["doc"].read() == b"a"


async def test_file_in_properties_beside_any_of_is_converted_with_the_file_in_the_branch(tmp_path):
    schema = {
        "type": "object",
        "properties": {"invoice": FILE_REF},
        "anyOf": [{"properties": {"receipt": FILE_REF}, "required": ["receipt"]}],
    }

    inputs = {"invoice": wire_content(b"invoice"), "receipt": wire_content(b"receipt")}
    result, seen = await run_and_capture(tmp_path, schema, inputs)

    assert result.type == ResultType.ACTION
    assert await seen["invoice"].read() == b"invoice"
    assert await seen["receipt"].read() == b"receipt"


async def test_files_in_every_branch_of_any_of_that_the_value_matches_are_converted(tmp_path):
    schema = {
        "type": "object",
        "anyOf": [
            {"properties": {"invoice": FILE_REF}, "required": ["invoice"]},
            {"properties": {"receipt": FILE_REF}, "required": ["receipt"]},
            {"properties": {"other": FILE_REF}, "required": ["other"]},
        ],
    }

    inputs = {"invoice": wire_content(b"invoice"), "receipt": wire_content(b"receipt")}
    result, seen = await run_and_capture(tmp_path, schema, inputs)

    assert result.type == ResultType.ACTION
    assert await seen["invoice"].read() == b"invoice"
    assert await seen["receipt"].read() == b"receipt"


@pytest.mark.parametrize("union", ["oneOf", "anyOf"])
@pytest.mark.parametrize("union_first", [False, True])
async def test_branch_that_names_a_file_declared_elsewhere_is_still_matched(tmp_path, union, union_first):
    declared = {"properties": {"invoice": FILE_REF}}
    both = {union: [{"properties": {"invoice": FILE_REF, "receipt": FILE_REF}, "required": ["invoice", "receipt"]}]}
    schema = {"type": "object", "allOf": [both, declared] if union_first else [declared, both]}

    inputs = {"invoice": wire_content(b"invoice"), "receipt": wire_content(b"receipt")}
    result, seen = await run_and_capture(tmp_path, schema, inputs)

    assert result.type == ResultType.ACTION
    assert await seen["invoice"].read() == b"invoice"
    assert await seen["receipt"].read() == b"receipt"


async def test_input_without_files_is_passed_to_the_handler_as_it_is(tmp_path):
    schema = {"type": "object", "properties": {"doc": {"anyOf": [{"type": "null"}, FILE_REF]}, "tags": {"type": "array"}}}

    inputs = {"doc": None, "tags": ["a", {"b": 1}]}
    result, seen = await run_and_capture(tmp_path, schema, inputs)

    assert result.type == ResultType.ACTION
    assert seen == inputs


async def test_file_behind_a_reference_into_the_same_schema_is_converted(tmp_path):
    schema = {
        "type": "object",
        "definitions": {
            "attachment": {"type": "object", "properties": {"file": FILE_REF, "caption": {"type": "string"}}},
        },
        "properties": {"attachments": {"type": "array", "items": {"$ref": "#/definitions/attachment"}}},
    }

    result, seen = await run_and_capture(tmp_path, schema, {"attachments": [{"file": wire_content(b"a"), "caption": "c"}]})

    assert result.type == ResultType.ACTION
    assert await seen["attachments"][0]["file"].read() == b"a"
    assert seen["attachments"][0]["caption"] == "c"


async def test_files_in_a_recursive_schema_are_converted(tmp_path):
    schema = {
        "type": "object",
        "properties": {"doc": FILE_REF, "children": {"type": "array", "items": {"$ref": "#"}}},
    }
    inputs = {"doc": wire_content(b"a"), "children": [{"doc": wire_content(b"b"), "children": []}]}

    result, seen = await run_and_capture(tmp_path, schema, inputs)

    assert result.type == ResultType.ACTION
    assert await seen["doc"].read() == b"a"
    assert await seen["children"][0]["doc"].read() == b"b"


async def test_reference_that_points_at_itself_or_nowhere_is_left_alone(tmp_path):
    from autohive_integrations_sdk.files import convert_file_inputs

    value = wire_content(b"a")
    loop = {"definitions": {"a": {"$ref": "#/definitions/a"}}, "properties": {"doc": {"$ref": "#/definitions/a"}}}
    missing = {"properties": {"doc": {"$ref": "#/definitions/missing"}}}
    other_document = {"properties": {"doc": {"$ref": "https://example.invalid/other.json"}}}

    for schema in (loop, missing, other_document, "not a schema"):
        assert convert_file_inputs(schema, {"doc": value}) == {"doc": value}


async def test_files_in_additional_properties_are_converted(tmp_path):
    schema = {"type": "object", "properties": {"note": {"type": "string"}}, "additionalProperties": FILE_REF}

    result, seen = await run_and_capture(tmp_path, schema, {"note": "n", "first": wire_content(b"a")})

    assert result.type == ResultType.ACTION
    assert seen["note"] == "n"
    assert await seen["first"].read() == b"a"


async def test_files_at_fixed_positions_of_an_array_are_converted(tmp_path):
    pair = {"type": "array", "items": [{"type": "string"}, FILE_REF], "additionalItems": FILE_REF}
    schema = {"type": "object", "properties": {"pair": pair}}

    result, seen = await run_and_capture(tmp_path, schema, {"pair": ["label", wire_content(b"a"), wire_content(b"b")]})

    assert result.type == ResultType.ACTION
    assert seen["pair"][0] == "label"
    assert [await item.read() for item in seen["pair"][1:]] == [b"a", b"b"]


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
