"""File values for actions.

A field of an action is a file when its schema in ``config.json`` is a reference to the SDK's
file schema::

    "invoice": {"$ref": "https://cdn.autohive.com/schemas/sdk/file/v1.json"}

A handler receives a :class:`File` for each such input, and returns a :class:`File` for each such
output.

On the wire, between the platform and the SDK, a file is a JSON object in one of three forms:

- ``{"name", "contentType", "content"}``: the content, base64-encoded.
- ``{"name", "contentType", "url", "sizeBytes"}``: a URL the content is downloaded from.
- ``{"name", "contentType", "key", "sizeBytes"}``: the storage key of content that was uploaded.

Handlers never see these forms. This version of the SDK reads and writes the first form only.
"""
import base64
from typing import Any, Dict, Optional, Tuple

from jsonschema import Draft7Validator, RefResolver

FILE_SCHEMA_ID = "https://cdn.autohive.com/schemas/sdk/file/v1.json"
"""The ``$ref`` that declares a file field in ``config.json``."""

FILE_SCHEMA: Dict[str, Any] = {
    "$id": FILE_SCHEMA_ID,
    "type": "object",
    "required": ["name", "contentType"],
    "properties": {
        "name": {"type": "string"},
        "contentType": {"type": "string"},
        "content": {"type": "string", "contentEncoding": "base64"},
        "url": {"type": "string", "format": "uri"},
        "key": {"type": "string"},
        "sizeBytes": {"type": "integer", "minimum": 0},
    },
    "oneOf": [
        {"required": ["content"]},
        {"required": ["url"]},
        {"required": ["key"]},
    ],
}
"""The file schema. The SDK resolves ``FILE_SCHEMA_ID`` to this object; nothing is fetched."""

SCHEMA_STORE: Dict[str, Any] = {FILE_SCHEMA_ID: FILE_SCHEMA}


class FileTransferError(Exception):
    """The content of a file could not be read or written."""


class File:
    """A file passed to an action, or returned from one.

    Attributes:
        name: The file name, for example ``"report.pdf"``.
        content_type: The media type, for example ``"application/pdf"``.
        size: The size in bytes, or ``None`` when it is not known.

    Read an input with :meth:`read`. Build an output with :meth:`from_bytes`.
    """

    def __init__(self, name: str, content_type: str, size: Optional[int] = None, *, _source: Any = None):
        self.name = name
        self.content_type = content_type
        self.size = size
        self._source = _source

    def __repr__(self) -> str:
        return f"File(name={self.name!r}, content_type={self.content_type!r}, size={self.size!r})"

    @classmethod
    def from_bytes(cls, data: bytes, name: str, content_type: str) -> "File":
        """A file whose content the handler holds in memory."""
        return cls(name, content_type, len(data), _source=bytes(data))

    async def read(self) -> bytes:
        """Return the whole content."""
        if isinstance(self._source, bytes):
            return self._source
        raise FileTransferError(f"File {self.name!r} has no content")


def is_file_schema(schema: Any) -> bool:
    return isinstance(schema, dict) and schema.get("$ref") == FILE_SCHEMA_ID


def file_from_wire(value: Dict[str, Any]) -> File:
    name = value["name"]
    content_type = value["contentType"]
    if "content" in value:
        try:
            data = base64.b64decode(value["content"], validate=True)
        except ValueError as error:
            raise FileTransferError(f"File {name!r} has content that is not valid base64") from error
        return File.from_bytes(data, name, content_type)
    raise FileTransferError(f"File {name!r} has no content. This version of the SDK reads inline content only")


def convert_file_inputs(schema: Any, value: Any) -> Any:
    """Replace each value at a file position of ``schema`` with a :class:`File`.

    ``value`` is valid against ``schema``. The file positions are found the way validation finds
    them: through ``properties``, ``additionalProperties``, ``items``, ``allOf``, ``anyOf``,
    ``oneOf`` and a reference to another part of the schema. A value at any other position is
    returned unchanged, whatever its shape.
    """
    if not isinstance(schema, dict):
        return value
    resolver = RefResolver.from_schema(schema, store=dict(SCHEMA_STORE))
    return _convert_inputs(schema, value, resolver, ())


def _convert_inputs(schema: Any, value: Any, resolver: RefResolver, followed: Tuple[str, ...]) -> Any:
    if is_file_schema(schema):
        return file_from_wire(value) if isinstance(value, dict) else value
    if not isinstance(schema, dict):
        return value

    reference = schema.get("$ref")
    if isinstance(reference, str):
        # A reference into the same schema. The keywords beside a reference do not apply.
        # A reference to any other document is not followed: that would be a network request.
        if not reference.startswith("#") or reference in followed:
            return value
        try:
            _, target = resolver.resolve(reference)
        except Exception:
            return value
        return _convert_inputs(target, value, resolver, followed + (reference,))

    for branch in _schemas(schema.get("allOf")):
        value = _convert_inputs(branch, value, resolver, followed)

    for keyword in ("anyOf", "oneOf"):
        for branch in _schemas(schema.get(keyword)):
            # A branch applies when the value is valid against it. The first one that has a file wins.
            if Draft7Validator(branch, resolver=resolver).is_valid(value):
                converted = _convert_inputs(branch, value, resolver, followed)
                if _has_file(converted):
                    return converted

    if isinstance(value, dict):
        properties = schema.get("properties")
        properties = properties if isinstance(properties, dict) else {}
        additional = schema.get("additionalProperties")
        if not properties and not isinstance(additional, dict):
            return value
        return {
            key: _convert_inputs(properties[key] if key in properties else additional, item, resolver, ())
            for key, item in value.items()
        }

    if isinstance(value, list):
        items = schema.get("items")
        if isinstance(items, dict):
            return [_convert_inputs(items, item, resolver, ()) for item in value]
        if isinstance(items, list):
            # One schema for each position, then additionalItems for the rest.
            rest = schema.get("additionalItems")
            return [
                _convert_inputs(items[index] if index < len(items) else rest, item, resolver, ())
                for index, item in enumerate(value)
            ]

    return value


def _schemas(value: Any) -> list:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _has_file(value: Any) -> bool:
    if isinstance(value, File):
        return True
    if isinstance(value, dict):
        return any(_has_file(item) for item in value.values())
    if isinstance(value, list):
        return any(_has_file(item) for item in value)
    return False


async def convert_file_outputs(value: Any) -> Any:
    """Replace each :class:`File` in a result with its wire form."""
    if isinstance(value, File):
        return await file_to_wire(value)
    if isinstance(value, dict):
        return {key: await convert_file_outputs(item) for key, item in value.items()}
    if isinstance(value, list):
        return [await convert_file_outputs(item) for item in value]
    return value


async def file_to_wire(file: File) -> Dict[str, Any]:
    data = await file.read()
    return {
        "name": file.name,
        "contentType": file.content_type,
        "content": base64.b64encode(data).decode("ascii"),
    }
