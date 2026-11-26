"""Tests for file values: the file schema, the File type, and file transfer.

Transfers run against real local HTTP servers. A mocked session does not send a streamed request
body or follow a redirect, and those are the behaviours under test.
"""

import base64
import gzip
import hashlib
import json
import os
from urllib.parse import parse_qs

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer

from autohive_integrations_sdk import (
    FILE_SCHEMA_ID,
    ActionError,
    ActionHandler,
    ActionResult,
    ExecutionContext,
    File,
    HTTPError,
    Integration,
    ResultType,
)
from autohive_integrations_sdk import files
from autohive_integrations_sdk.files import FileTransferError, INLINE_LIMIT_BYTES

KEY_PREFIX = "tool-outputs/call-1/"
OAUTH = {"auth_type": "PlatformOauth2", "credentials": {"access_token": "secret-token"}}
FILE_REF = {"$ref": FILE_SCHEMA_ID}
LEGACY_FILE_SCHEMA = {
    "type": "object",
    "properties": {"content": {"type": "string"}, "name": {"type": "string"}, "contentType": {"type": "string"}},
    "required": ["content", "name", "contentType"],
}


# ── Test servers ─────────────────────────────────────────────────────────────


class Remote:
    """A local stand-in for another service and for the platform's file storage."""

    def __init__(self):
        self.files = {}
        self.requests = []
        self.uploads = []
        self.upload_status = 204
        self.other_origin = None
        app = web.Application(client_max_size=0)
        app.router.add_get("/download/{name}", self.download)
        app.router.add_get("/gzip/{name}", self.download_gzip)
        app.router.add_get("/no-length/{name}", self.download_without_length)
        app.router.add_get("/broken/{name}", self.download_broken)
        app.router.add_get("/redirect/{name}", self.redirect)
        app.router.add_get("/broken-error/{name}", self.error_with_a_broken_body)
        app.router.add_route("*", "/redirect-to-self", self.redirect_to_self)
        app.router.add_route("*", "/status/{status}", self.status)
        app.router.add_post("/storage", self.upload)
        self.server = TestServer(app)

    def url(self, path: str) -> str:
        return str(self.server.make_url(path))

    def record(self, request: web.Request) -> None:
        self.requests.append({"path": request.path_qs, "method": request.method, "headers": dict(request.headers)})

    async def download(self, request):
        self.record(request)
        name = request.match_info["name"]
        if name not in self.files:
            return web.Response(status=404, text="no such file")
        return web.Response(body=self.files[name], content_type="application/octet-stream")

    async def download_gzip(self, request):
        self.record(request)
        body = gzip.compress(self.files[request.match_info["name"]])
        return web.Response(body=body, headers={"Content-Encoding": "gzip"})

    async def download_without_length(self, request):
        self.record(request)
        response = web.StreamResponse()
        await response.prepare(request)
        data = self.files[request.match_info["name"]]
        for start in range(0, len(data), 100_000):
            await response.write(data[start:start + 100_000])
        await response.write_eof()
        return response

    async def download_broken(self, request):
        self.record(request)
        data = self.files[request.match_info["name"]]
        response = web.StreamResponse(headers={"Content-Length": str(len(data))})
        await response.prepare(request)
        await response.write(data[: len(data) // 2])
        request.transport.close()
        return response

    async def redirect(self, request):
        self.record(request)
        raise web.HTTPFound(self.other_origin.url(f"/download/{request.match_info['name']}"))

    async def error_with_a_broken_body(self, request):
        self.record(request)
        response = web.StreamResponse(status=404, headers={"Content-Length": "1000"})
        await response.prepare(request)
        await response.write(b"partial")
        request.transport.close()
        return response

    async def redirect_to_self(self, request):
        self.record(request)
        return web.Response(status=308, headers={"Location": str(request.url)}, text="resume incomplete")

    async def status(self, request):
        self.record(request)
        return web.json_response({"ok": True}, status=int(request.match_info["status"]))

    async def upload(self, request):
        """Accept an upload the way S3 accepts a pre-signed POST, and refuse what S3 refuses."""
        if request.headers.get("Transfer-Encoding", "").lower() == "chunked" or request.content_length is None:
            return web.Response(status=411, text="a length is required")
        reader = await request.multipart()
        fields = {}
        while True:
            part = await reader.next()
            if part is None:
                return web.Response(status=400, text="no file field")
            if part.name == "file":
                break
            fields[part.name] = await part.text()
        if not fields.get("key", "").startswith(KEY_PREFIX):
            return web.Response(status=403, text="key is outside the granted prefix")
        digest = hashlib.sha256()
        size = 0
        while chunk := await part.read_chunk(256 * 1024):
            digest.update(chunk)
            size += len(chunk)
        if await reader.next() is not None:
            return web.Response(status=400, text="the file must be the last field")
        self.uploads.append({
            "fields": fields, "filename": part.filename, "contentType": part.headers.get("Content-Type"),
            "size": size, "sha256": digest.hexdigest(),
        })
        return web.Response(status=self.upload_status, text="refused" if self.upload_status >= 400 else "")

    def grant(self, **extra) -> dict:
        upload = {"url": self.url("/storage"), "fields": {"key": KEY_PREFIX + "${filename}", "policy": "p"},
                  "keyPrefix": KEY_PREFIX}
        upload.update(extra)
        return {"upload": upload}


@pytest.fixture
async def remote():
    first, second = Remote(), Remote()
    first.other_origin = second
    await first.server.start_server()
    await second.server.start_server()
    yield first
    await first.server.close()
    await second.server.close()


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


async def run_action(integration, execute, inputs=None, auth=None, file_transport=None):
    @integration.action("run")
    class Handler(ActionHandler):
        async def execute(self, action_inputs, context):
            return await execute(action_inputs, context)

    async with ExecutionContext(auth=auth or {}, file_transport=file_transport) as context:
        return await integration.execute_action("run", inputs or {}, context)


def wire_content(data: bytes, name="a.bin") -> dict:
    return {"name": name, "contentType": "application/octet-stream", "content": base64.b64encode(data).decode()}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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


async def test_url_input_is_downloaded_only_when_read_and_without_credentials(tmp_path, remote):
    remote.files["big.bin"] = os.urandom(300_000)
    seen = {}

    async def execute(inputs, context):
        seen["requests_before_read"] = len(remote.requests)
        seen["size"] = inputs["doc"].size
        seen["data"] = await inputs["doc"].read()
        return ActionResult(data={})

    integration = make_integration(tmp_path, {"doc": FILE_REF})
    value = {"name": "big.bin", "contentType": "application/octet-stream",
             "url": remote.url("/download/big.bin"), "sizeBytes": 300_000}
    result = await run_action(integration, execute, {"doc": value}, auth=OAUTH)

    assert result.type == ResultType.ACTION
    assert seen["requests_before_read"] == 0
    assert seen["size"] == 300_000
    assert seen["data"] == remote.files["big.bin"]
    assert "Authorization" not in remote.requests[0]["headers"]


async def test_input_url_the_platform_filter_refuses_is_a_validation_error(tmp_path, remote):
    calls = []

    async def execute(inputs, context):
        calls.append("handler")
        return ActionResult(data={})

    integration = make_integration(tmp_path, {"doc": FILE_REF})
    value = {"name": "a.bin", "contentType": "text/plain", "url": remote.url("/download/a.bin")}
    result = await run_action(integration, execute, {"doc": value}, file_transport={"input_url_filter": lambda url: None})

    assert result.type == ResultType.VALIDATION_ERROR
    assert result.result["source"] == "input"
    assert "does not accept" in result.result["message"]
    assert calls == [] and remote.requests == []


async def test_input_is_downloaded_from_the_url_the_platform_filter_returns(tmp_path, remote):
    remote.files["checked.bin"] = b"checked content"
    seen = {}

    async def execute(inputs, context):
        seen["data"] = await inputs["doc"].read()
        return ActionResult(data={})

    integration = make_integration(tmp_path, {"doc": FILE_REF})
    value = {"name": "a.bin", "contentType": "text/plain", "url": "https://example.invalid/original"}
    transport = {"input_url_filter": lambda url: remote.url("/download/checked.bin")}
    result = await run_action(integration, execute, {"doc": value}, file_transport=transport)

    assert result.type == ResultType.ACTION
    assert seen["data"] == b"checked content"


async def test_iter_chunks_yields_exact_pieces(tmp_path, remote):
    remote.files["big.bin"] = os.urandom(250_000)
    sizes = {}

    async def execute(inputs, context):
        sizes["url"] = [len(chunk) async for chunk in inputs["from_url"].iter_chunks(64 * 1024)]
        sizes["inline"] = [len(chunk) async for chunk in inputs["inline"].iter_chunks(4)]
        return ActionResult(data={})

    integration = make_integration(tmp_path, {"from_url": FILE_REF, "inline": FILE_REF})
    inputs = {
        "from_url": {"name": "big.bin", "contentType": "application/octet-stream",
                     "url": remote.url("/no-length/big.bin")},
        "inline": wire_content(b"0123456789"),
    }
    result = await run_action(integration, execute, inputs)

    assert result.type == ResultType.ACTION
    assert sizes["url"] == [65536, 65536, 65536, 250_000 - 3 * 65536]
    assert sizes["inline"] == [4, 4, 2]


async def test_exact_chunks_regroups_pieces_of_any_size():
    async def pieces():
        for piece in (b"ab", b"cdefg", b"hij", b"klmn", b"o"):
            yield piece

    chunks = [chunk async for chunk in files._exact_chunks(pieces(), 4)]

    assert chunks == [b"abcd", b"efgh", b"ijkl", b"mno"]


async def test_iter_chunks_rejects_a_chunk_size_below_one():
    with pytest.raises(ValueError):
        async for _ in File.from_bytes(b"abc", "a", "text/plain").iter_chunks(0):
            pass


async def test_url_input_read_twice_is_an_action_error(tmp_path, remote):
    remote.files["a.bin"] = b"x" * 10

    async def execute(inputs, context):
        await inputs["doc"].read()
        await inputs["doc"].read()
        return ActionResult(data={})

    integration = make_integration(tmp_path, {"doc": FILE_REF})
    value = {"name": "a.bin", "contentType": "text/plain", "url": remote.url("/download/a.bin")}
    result = await run_action(integration, execute, {"doc": value})

    assert result.type == ResultType.ACTION_ERROR
    assert "already been read" in result.result.message


async def test_failed_input_download_is_an_action_error(tmp_path, remote):
    async def execute(inputs, context):
        await inputs["doc"].read()
        return ActionResult(data={})

    integration = make_integration(tmp_path, {"doc": FILE_REF})
    value = {"name": "gone.bin", "contentType": "text/plain", "url": remote.url("/download/gone.bin")}
    result = await run_action(integration, execute, {"doc": value})

    assert result.type == ResultType.ACTION_ERROR
    assert "HTTP 404" in result.result.message


async def test_input_download_that_stops_part_way_is_an_action_error(tmp_path, remote):
    remote.files["a.bin"] = os.urandom(400_000)

    async def execute(inputs, context):
        await inputs["doc"].read()
        return ActionResult(data={})

    integration = make_integration(tmp_path, {"doc": FILE_REF})
    value = {"name": "a.bin", "contentType": "text/plain", "url": remote.url("/broken/a.bin")}
    result = await run_action(integration, execute, {"doc": value})

    assert result.type == ResultType.ACTION_ERROR
    assert "stopped" in result.result.message


async def test_input_from_an_unreachable_host_is_an_action_error(tmp_path, remote):
    async def execute(inputs, context):
        await inputs["doc"].read()
        return ActionResult(data={})

    integration = make_integration(tmp_path, {"doc": FILE_REF})
    value = {"name": "a.bin", "contentType": "text/plain", "url": remote.other_origin.url("/download/a.bin")}
    await remote.other_origin.server.close()
    result = await run_action(integration, execute, {"doc": value})

    assert result.type == ResultType.ACTION_ERROR
    assert "Download of 'a.bin' failed" in result.result.message


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
        assert convert_file_inputs(schema, {"doc": value}, None) == {"doc": value}


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


async def test_file_shaped_value_outside_a_file_field_is_left_alone(tmp_path, remote):
    """Only a field declared with the file schema is converted, whatever shape another value has."""
    seen = {}

    async def execute(inputs, context):
        seen.update(inputs)
        return ActionResult(data={})

    integration = make_integration(tmp_path, {"note": {"type": "object"}, "items": {"type": "array"}})
    shaped = {"name": "x", "contentType": "text/plain", "url": remote.url("/download/x")}
    result = await run_action(integration, execute, {"note": shaped, "items": [shaped], "extra": shaped})

    assert result.type == ResultType.ACTION
    assert seen == {"note": shaped, "items": [shaped], "extra": shaped}
    assert remote.requests == []


async def test_input_that_matches_no_file_form_is_a_validation_error(tmp_path):
    async def execute(inputs, context):
        return ActionResult(data={})

    integration = make_integration(tmp_path, {"doc": FILE_REF})
    result = await run_action(integration, execute, {"doc": {"name": "a", "contentType": "text/plain"}})

    assert result.type == ResultType.VALIDATION_ERROR
    assert result.result["source"] == "input"


@pytest.mark.parametrize("value, expected", [
    ({"name": "a", "contentType": "text/plain", "key": "tool-outputs/x/a", "sizeBytes": 1}, "no content and no url"),
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


async def test_small_output_is_returned_inline(tmp_path):
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


async def test_inline_input_file_can_be_returned_as_an_output(tmp_path):
    async def execute(inputs, context):
        return ActionResult(data={"doc": inputs["doc"]})

    integration = make_integration(tmp_path, {"doc": FILE_REF}, {"doc": FILE_REF})
    value = wire_content(b"hello", "note.txt")
    result = await run_action(integration, execute, {"doc": value})

    assert result.type == ResultType.ACTION
    assert result.result.data == {"doc": value}


async def test_large_output_is_uploaded_with_the_grant(tmp_path, remote):
    data = os.urandom(INLINE_LIMIT_BYTES + 1)

    async def execute(inputs, context):
        return ActionResult(data={"docs": [File.from_bytes(data, 'my "big" résumé.bin', "application/pdf")]})

    integration = make_integration(tmp_path, output_properties={"docs": {"type": "array", "items": FILE_REF}})
    result = await run_action(integration, execute, file_transport=remote.grant())

    assert result.type == ResultType.ACTION
    output = result.result.data["docs"][0]
    assert output["name"] == 'my "big" résumé.bin'
    assert output["contentType"] == "application/pdf"
    assert output["sizeBytes"] == len(data)
    assert output["key"].startswith(KEY_PREFIX) and output["key"].endswith("/my _big_ résumé.bin")
    assert "content" not in output
    upload = remote.uploads[0]
    assert upload["fields"] == {"key": output["key"], "policy": "p"}
    assert (upload["size"], upload["sha256"]) == (len(data), sha256(data))
    assert upload["contentType"] == "application/pdf"


async def test_two_outputs_with_the_same_name_get_different_keys(tmp_path, remote):
    data = os.urandom(INLINE_LIMIT_BYTES + 1)

    async def execute(inputs, context):
        return ActionResult(data={"a": File.from_bytes(data, "same.bin", "a/b"),
                                  "b": File.from_bytes(data, "same.bin", "a/b")})

    integration = make_integration(tmp_path, output_properties={"a": FILE_REF, "b": FILE_REF})
    result = await run_action(integration, execute, file_transport=remote.grant())

    assert result.type == ResultType.ACTION
    assert result.result.data["a"]["key"] != result.result.data["b"]["key"]


async def test_grant_without_a_key_prefix_uses_the_filename_placeholder(tmp_path, remote):
    data = os.urandom(INLINE_LIMIT_BYTES + 1)

    async def execute(inputs, context):
        return ActionResult(data={"doc": File.from_bytes(data, "plain.bin", "a/b")})

    integration = make_integration(tmp_path, output_properties={"doc": FILE_REF})
    grant = remote.grant()
    del grant["upload"]["keyPrefix"]
    result = await run_action(integration, execute, file_transport=grant)

    assert result.type == ResultType.ACTION
    key = result.result.data["doc"]["key"]
    assert key.startswith(KEY_PREFIX) and key.endswith("/plain.bin")
    assert remote.uploads[0]["fields"]["key"] == key


async def test_two_outputs_with_the_same_name_get_different_keys_without_a_key_prefix(tmp_path, remote):
    data = os.urandom(INLINE_LIMIT_BYTES + 1)

    async def execute(inputs, context):
        return ActionResult(data={"a": File.from_bytes(data, "same.bin", "a/b"),
                                  "b": File.from_bytes(data, "same.bin", "a/b")})

    integration = make_integration(tmp_path, output_properties={"a": FILE_REF, "b": FILE_REF})
    grant = remote.grant()
    del grant["upload"]["keyPrefix"]
    result = await run_action(integration, execute, file_transport=grant)

    assert result.type == ResultType.ACTION
    assert result.result.data["a"]["key"] != result.result.data["b"]["key"]


async def test_grant_for_one_key_uploads_one_file_and_refuses_a_second(tmp_path, remote):
    data = os.urandom(INLINE_LIMIT_BYTES + 1)
    grant = {"upload": {"url": remote.url("/storage"), "fields": {"key": KEY_PREFIX + "fixed.bin"}}}

    async def one_file(inputs, context):
        return ActionResult(data={"a": File.from_bytes(data, "a.bin", "a/b")})

    integration = make_integration(tmp_path, output_properties={"a": FILE_REF, "b": FILE_REF})
    result = await run_action(integration, one_file, file_transport=grant)

    assert result.type == ResultType.ACTION
    assert result.result.data["a"]["key"] == KEY_PREFIX + "fixed.bin"

    async def two_files(inputs, context):
        return ActionResult(data={"a": File.from_bytes(data, "a.bin", "a/b"),
                                  "b": File.from_bytes(data, "b.bin", "a/b")})

    result = await run_action(integration, two_files, file_transport=grant)

    assert result.type == ResultType.ACTION_ERROR
    assert "allows one file" in result.result.message
    assert len(remote.uploads) == 2


async def test_large_output_without_a_grant_is_an_action_error(tmp_path):
    async def execute(inputs, context):
        return ActionResult(data={"doc": File.from_bytes(bytes(INLINE_LIMIT_BYTES + 1), "big.bin", "a/b")})

    integration = make_integration(tmp_path, output_properties={"doc": FILE_REF})
    result = await run_action(integration, execute)

    assert result.type == ResultType.ACTION_ERROR
    assert "no upload grant" in result.result.message


async def test_output_over_the_grant_limit_is_an_action_error(tmp_path, remote):
    async def execute(inputs, context):
        return ActionResult(data={"doc": File.from_bytes(bytes(INLINE_LIMIT_BYTES + 1), "big.bin", "a/b")})

    integration = make_integration(tmp_path, output_properties={"doc": FILE_REF})
    result = await run_action(integration, execute, file_transport=remote.grant(maxBytes=INLINE_LIMIT_BYTES))

    assert result.type == ResultType.ACTION_ERROR
    assert "more than the" in result.result.message
    assert remote.uploads == []


async def test_refused_upload_is_an_action_error(tmp_path, remote):
    remote.upload_status = 403

    async def execute(inputs, context):
        return ActionResult(data={"doc": File.from_bytes(bytes(INLINE_LIMIT_BYTES + 1), "big.bin", "a/b")})

    integration = make_integration(tmp_path, output_properties={"doc": FILE_REF})
    result = await run_action(integration, execute, file_transport=remote.grant())

    assert result.type == ResultType.ACTION_ERROR
    assert "Upload of 'big.bin' failed with HTTP 403: refused" in result.result.message


async def test_upload_to_an_unreachable_host_is_an_action_error(tmp_path, remote):
    async def execute(inputs, context):
        return ActionResult(data={"doc": File.from_bytes(bytes(INLINE_LIMIT_BYTES + 1), "big.bin", "a/b")})

    integration = make_integration(tmp_path, output_properties={"doc": FILE_REF})
    grant = remote.other_origin.grant()
    await remote.other_origin.server.close()
    result = await run_action(integration, execute, file_transport=grant)

    assert result.type == ResultType.ACTION_ERROR
    assert "Upload of 'big.bin' failed" in result.result.message


async def test_action_error_from_the_handler_is_returned_unchanged(tmp_path):
    async def execute(inputs, context):
        return ActionError(message="not found")

    integration = make_integration(tmp_path, output_properties={"doc": FILE_REF})
    result = await run_action(integration, execute)

    assert result.type == ResultType.ACTION_ERROR
    assert result.result.message == "not found"


async def test_input_file_can_be_returned_as_an_output(tmp_path, remote):
    remote.files["big.bin"] = os.urandom(INLINE_LIMIT_BYTES + 5)

    async def execute(inputs, context):
        return ActionResult(data={"doc": inputs["doc"]})

    integration = make_integration(tmp_path, {"doc": FILE_REF}, {"doc": FILE_REF})
    value = {"name": "big.bin", "contentType": "a/b", "url": remote.url("/download/big.bin"),
             "sizeBytes": INLINE_LIMIT_BYTES + 5}
    result = await run_action(integration, execute, {"doc": value}, file_transport=remote.grant())

    assert result.type == ResultType.ACTION
    assert remote.uploads[0]["sha256"] == sha256(remote.files["big.bin"])


# ── File.from_request ────────────────────────────────────────────────────────


async def test_from_request_streams_a_large_download_to_storage(tmp_path, remote):
    remote.files["big.bin"] = os.urandom(INLINE_LIMIT_BYTES + 100_000)

    async def execute(inputs, context):
        return ActionResult(data={"doc": File.from_request(
            remote.url("/download/big.bin"), name="big.bin", content_type="a/b",
            params={"alt": "media", "skip": None}, headers={"X-Extra": "1"})})

    integration = make_integration(tmp_path, output_properties={"doc": FILE_REF})
    result = await run_action(integration, execute, auth=OAUTH, file_transport=remote.grant())

    assert result.type == ResultType.ACTION
    assert result.result.data["doc"]["sizeBytes"] == len(remote.files["big.bin"])
    assert remote.uploads[0]["sha256"] == sha256(remote.files["big.bin"])
    request = remote.requests[0]
    assert request["path"] == "/download/big.bin?alt=media"
    assert request["headers"]["Authorization"] == "Bearer secret-token"
    assert request["headers"]["X-Extra"] == "1"
    assert request["headers"]["Accept-Encoding"] == "identity"


async def test_from_request_small_download_is_returned_inline(tmp_path, remote):
    remote.files["small.txt"] = b"small content"

    async def execute(inputs, context):
        return ActionResult(data={"doc": File.from_request(
            remote.url("/download/small.txt?x=1"), name="small.txt", content_type="text/plain", params={"y": 2})})

    integration = make_integration(tmp_path, output_properties={"doc": FILE_REF})
    result = await run_action(integration, execute)

    assert result.type == ResultType.ACTION
    assert base64.b64decode(result.result.data["doc"]["content"]) == b"small content"
    assert remote.requests[0]["path"] == "/download/small.txt?x=1&y=2"


async def test_from_request_does_not_send_the_token_to_another_origin(tmp_path, remote):
    remote.other_origin.files["a.bin"] = b"redirected content"

    async def execute(inputs, context):
        return ActionResult(data={"doc": File.from_request(
            remote.url("/redirect/a.bin"), name="a.bin", content_type="a/b")})

    integration = make_integration(tmp_path, output_properties={"doc": FILE_REF})
    result = await run_action(integration, execute, auth=OAUTH)

    assert result.type == ResultType.ACTION
    assert base64.b64decode(result.result.data["doc"]["content"]) == b"redirected content"
    assert remote.requests[0]["headers"]["Authorization"] == "Bearer secret-token"
    assert "Authorization" not in remote.other_origin.requests[0]["headers"]


async def test_from_request_with_send_auth_false_sends_no_token(tmp_path, remote):
    remote.files["a.bin"] = b"content"

    async def execute(inputs, context):
        return ActionResult(data={"doc": File.from_request(
            remote.url("/download/a.bin"), name="a.bin", content_type="a/b", send_auth=False)})

    integration = make_integration(tmp_path, output_properties={"doc": FILE_REF})
    result = await run_action(integration, execute, auth=OAUTH)

    assert result.type == ResultType.ACTION
    assert "Authorization" not in remote.requests[0]["headers"]


async def test_from_request_without_a_length_is_inline_when_small(tmp_path, remote):
    remote.files["a.bin"] = os.urandom(200_000)

    async def execute(inputs, context):
        return ActionResult(data={"doc": File.from_request(
            remote.url("/no-length/a.bin"), name="a.bin", content_type="a/b")})

    integration = make_integration(tmp_path, output_properties={"doc": FILE_REF})
    result = await run_action(integration, execute, file_transport=remote.grant())

    assert result.type == ResultType.ACTION
    assert base64.b64decode(result.result.data["doc"]["content"]) == remote.files["a.bin"]
    assert remote.uploads == []


async def test_from_request_without_a_length_is_an_action_error_when_large(tmp_path, remote):
    remote.files["a.bin"] = bytes(INLINE_LIMIT_BYTES + 1)

    async def execute(inputs, context):
        return ActionResult(data={"doc": File.from_request(
            remote.url("/no-length/a.bin"), name="a.bin", content_type="a/b")})

    integration = make_integration(tmp_path, output_properties={"doc": FILE_REF})
    result = await run_action(integration, execute, file_transport=remote.grant())

    assert result.type == ResultType.ACTION_ERROR
    assert "its size is not known" in result.result.message


async def test_from_request_does_not_trust_the_length_of_a_compressed_response(tmp_path, remote):
    """A compressed body is longer than its Content-Length once it is decoded."""
    remote.files["a.txt"] = b"compressible " * 20_000

    async def execute(inputs, context):
        return ActionResult(data={"doc": File.from_request(
            remote.url("/gzip/a.txt"), name="a.txt", content_type="text/plain")})

    integration = make_integration(tmp_path, output_properties={"doc": FILE_REF})
    result = await run_action(integration, execute)

    assert result.type == ResultType.ACTION
    assert base64.b64decode(result.result.data["doc"]["content"]) == remote.files["a.txt"]


@pytest.mark.parametrize("declared, expected", [
    (INLINE_LIMIT_BYTES + 100, "not its size of"),
    (INLINE_LIMIT_BYTES + 1, "longer than its size of"),
])
async def test_upload_with_a_wrong_size_is_an_action_error(tmp_path, remote, declared, expected):
    remote.files["a.bin"] = bytes(INLINE_LIMIT_BYTES + 50)

    async def execute(inputs, context):
        return ActionResult(data={"doc": File.from_request(
            remote.url("/download/a.bin"), name="a.bin", content_type="a/b", size=declared)})

    integration = make_integration(tmp_path, output_properties={"doc": FILE_REF})
    result = await run_action(integration, execute, file_transport=remote.grant())

    assert result.type == ResultType.ACTION_ERROR
    assert expected in result.result.message


@pytest.mark.parametrize("declared, actual, expected", [
    (10, 20, "has 20 bytes, not its size of 10"),
    (10, INLINE_LIMIT_BYTES + 1, "longer than its size of 10"),
])
async def test_inline_file_with_a_wrong_size_is_an_action_error(tmp_path, remote, declared, actual, expected):
    remote.files["a.bin"] = bytes(actual)

    async def execute(inputs, context):
        return ActionResult(data={"doc": File.from_request(
            remote.url("/download/a.bin"), name="a.bin", content_type="a/b", size=declared)})

    integration = make_integration(tmp_path, output_properties={"doc": FILE_REF})
    result = await run_action(integration, execute)

    assert result.type == ResultType.ACTION_ERROR
    assert expected in result.result.message


async def test_from_request_download_that_stops_during_the_upload_is_an_action_error(tmp_path, remote):
    remote.files["a.bin"] = os.urandom(2 * INLINE_LIMIT_BYTES)

    async def execute(inputs, context):
        return ActionResult(data={"doc": File.from_request(
            remote.url("/broken/a.bin"), name="a.bin", content_type="a/b")})

    integration = make_integration(tmp_path, output_properties={"doc": FILE_REF})
    result = await run_action(integration, execute, file_transport=remote.grant())

    assert result.type == ResultType.ACTION_ERROR
    assert "Download of 'a.bin' stopped" in result.result.message


async def test_from_request_failed_download_is_an_action_error(tmp_path, remote):
    async def execute(inputs, context):
        return ActionResult(data={"doc": File.from_request(
            remote.url("/download/gone.bin"), name="gone.bin", content_type="a/b")})

    integration = make_integration(tmp_path, output_properties={"doc": FILE_REF})
    result = await run_action(integration, execute)

    assert result.type == ResultType.ACTION_ERROR
    assert "Download of 'gone.bin' failed with HTTP 404: no such file" in result.result.message


async def test_failed_download_with_an_error_body_that_cannot_be_read_is_an_action_error(tmp_path, remote):
    async def execute(inputs, context):
        return ActionResult(data={"doc": File.from_request(
            remote.url("/broken-error/a.bin"), name="a.bin", content_type="a/b")})

    integration = make_integration(tmp_path, output_properties={"doc": FILE_REF})
    result = await run_action(integration, execute)

    assert result.type == ResultType.ACTION_ERROR
    assert "Download of 'a.bin' failed with HTTP 404" in result.result.message


async def test_from_request_sends_structured_params_as_json_like_fetch(tmp_path, remote):
    remote.files["a.bin"] = b"content"
    params = {"filter": {"status": "active"}, "ids": [1, 2], "skip": None}

    async def execute(inputs, context):
        await context.fetch(remote.url("/status/200"), params=params)
        return ActionResult(data={"doc": File.from_request(
            remote.url("/download/a.bin"), name="a.bin", content_type="a/b", params=params)})

    integration = make_integration(tmp_path, output_properties={"doc": FILE_REF})
    result = await run_action(integration, execute)

    assert result.type == ResultType.ACTION
    fetch_query = remote.requests[0]["path"].split("?", 1)[1]
    download_query = remote.requests[1]["path"].split("?", 1)[1]
    assert download_query == fetch_query
    assert parse_qs(download_query) == {"filter": ['{"status": "active"}'], "ids": ["[1, 2]"]}


async def test_from_request_uses_the_callers_authorization_header_in_any_case(tmp_path, remote):
    remote.files["a.bin"] = b"content"

    async def execute(inputs, context):
        return ActionResult(data={"doc": File.from_request(
            remote.url("/download/a.bin"), name="a.bin", content_type="a/b",
            headers={"authorization": "Basic other-credentials"})})

    integration = make_integration(tmp_path, output_properties={"doc": FILE_REF})
    result = await run_action(integration, execute, auth=OAUTH)

    assert result.type == ResultType.ACTION
    assert remote.requests[0]["headers"]["Authorization"] == "Basic other-credentials"
    assert "secret-token" not in str(remote.requests[0]["headers"])


async def test_from_request_file_cannot_be_read_in_the_handler(tmp_path, remote):
    async def execute(inputs, context):
        await File.from_request(remote.url("/download/a.bin"), name="a.bin", content_type="a/b").read()
        return ActionResult(data={})

    integration = make_integration(tmp_path)
    result = await run_action(integration, execute)

    assert result.type == ResultType.ACTION_ERROR
    assert "cannot be read here" in result.result.message


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


async def test_cost_is_kept_when_an_upload_fails(tmp_path, remote):
    remote.upload_status = 403

    async def execute(inputs, context):
        file = File.from_bytes(bytes(INLINE_LIMIT_BYTES + 1), "big.bin", "a/b")
        return ActionResult(data={"doc": file}, cost_usd=0.25)

    integration = make_integration(tmp_path, output_properties={"doc": FILE_REF})
    result = await run_action(integration, execute, file_transport=remote.grant())

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


# ── fetch(): send_auth and accept_statuses ───────────────────────────────────


async def test_fetch_send_auth_false_sends_no_token(remote):
    async with ExecutionContext(auth=OAUTH) as context:
        await context.fetch(remote.url("/status/200"))
        await context.fetch(remote.url("/status/200"), send_auth=False)

    assert remote.requests[0]["headers"]["Authorization"] == "Bearer secret-token"
    assert "Authorization" not in remote.requests[1]["headers"]
    assert "User-Agent" in remote.requests[1]["headers"]


async def test_fetch_accept_statuses_returns_the_response(remote):
    async with ExecutionContext() as context:
        response = await context.fetch(remote.url("/status/308"), method="PUT", data=b"chunk", accept_statuses=[308])

    assert response.status == 308
    assert response.data == {"ok": True}


async def test_fetch_still_raises_for_a_status_that_is_not_accepted(remote):
    async with ExecutionContext() as context:
        with pytest.raises(HTTPError) as error:
            await context.fetch(remote.url("/status/404"), accept_statuses=[308])

    assert error.value.status == 404


async def test_fetch_uses_the_callers_authorization_header_in_any_case(remote):
    async with ExecutionContext(auth=OAUTH) as context:
        await context.fetch(remote.url("/status/200"), headers={"authorization": "Basic other-credentials"})

    assert remote.requests[0]["headers"]["Authorization"] == "Basic other-credentials"
    assert "secret-token" not in str(remote.requests[0]["headers"])


async def test_fetch_returns_an_accepted_error_status_and_raises_when_it_is_not_accepted(remote):
    async with ExecutionContext() as context:
        response = await context.fetch(remote.url("/status/409"), accept_statuses=[409])
        with pytest.raises(HTTPError) as error:
            await context.fetch(remote.url("/status/409"))
        with pytest.raises(HTTPError):
            await context.fetch(remote.url("/status/409"), accept_statuses=[429])

    assert (response.status, response.data) == (409, {"ok": True})
    assert error.value.status == 409


async def test_fetch_returns_an_accepted_redirect_status_and_does_not_follow_it(remote):
    async with ExecutionContext() as context:
        response = await context.fetch(
            remote.url("/redirect-to-self"), method="PUT", data=b"chunk", accept_statuses=[308])

    assert response.status == 308
    assert response.data == "resume incomplete"
    assert len(remote.requests) == 1


async def test_fetch_still_follows_a_redirect_when_no_redirect_status_is_accepted(remote):
    remote.other_origin.files["a.bin"] = b"redirected content"

    async with ExecutionContext() as context:
        response = await context.fetch(remote.url("/redirect/a.bin"), accept_statuses=[409])

    assert response.status == 200
    assert len(remote.other_origin.requests) == 1


async def test_fetch_accept_statuses_can_accept_429(remote):
    async with ExecutionContext() as context:
        response = await context.fetch(remote.url("/status/429"), accept_statuses={429})

    assert response.status == 429
