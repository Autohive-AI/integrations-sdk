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
from typing import Any, Dict, Optional, Set, Tuple, Union

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
    # First find every file position in the value as it arrived, then replace the values. A
    # branch of anyOf or oneOf is chosen by validation, and a File is not valid where a file is
    # declared. So nothing is replaced until every branch is chosen.
    resolver = RefResolver.from_schema(schema, store=dict(SCHEMA_STORE))
    positions: Set[_Position] = set()
    _find_files(schema, value, resolver, (), (), positions)
    return _replace_files(value, (), positions) if positions else value


_Position = Tuple[Union[str, int], ...]
"""The place of a value in the inputs: the property names and array indexes that lead to it."""


def _find_files(schema: Any, value: Any, resolver: RefResolver, position: _Position,
                followed: Tuple[str, ...], positions: Set[_Position]) -> None:
    """Add the position of each file in ``value`` to ``positions``. ``value`` is not changed."""
    if is_file_schema(schema):
        if isinstance(value, dict):
            positions.add(position)
        return
    if not isinstance(schema, dict):
        return

    reference = schema.get("$ref")
    if isinstance(reference, str):
        # A reference into the same schema. The keywords beside a reference do not apply.
        # A reference to any other document is not followed: that would be a network request.
        if not reference.startswith("#") or reference in followed:
            return
        try:
            _, target = resolver.resolve(reference)
        except Exception:
            return
        _find_files(target, value, resolver, position, followed + (reference,), positions)
        return

    # Every keyword below applies together, so each one adds its files.
    for branch in _schemas(schema.get("allOf")):
        _find_files(branch, value, resolver, position, followed, positions)

    for keyword in ("anyOf", "oneOf"):
        for branch in _schemas(schema.get(keyword)):
            # A branch applies when the value is valid against it. More than one branch of anyOf can apply.
            if Draft7Validator(branch, resolver=resolver).is_valid(value):
                _find_files(branch, value, resolver, position, followed, positions)

    if isinstance(value, dict):
        properties = schema.get("properties")
        properties = properties if isinstance(properties, dict) else {}
        additional = schema.get("additionalProperties")
        for key, item in value.items():
            _find_files(properties[key] if key in properties else additional, item, resolver,
                        position + (key,), (), positions)

    if isinstance(value, list):
        items = schema.get("items")
        # ``items`` is one schema for every item, or one schema for each position and then
        # additionalItems for the rest.
        rest = schema.get("additionalItems") if isinstance(items, list) else items
        fixed = items if isinstance(items, list) else []
        for index, item in enumerate(value):
            _find_files(fixed[index] if index < len(fixed) else rest, item, resolver,
                        position + (index,), (), positions)


def _replace_files(value: Any, position: _Position, positions: Set[_Position]) -> Any:
    if position in positions:
        return file_from_wire(value)
    if isinstance(value, dict):
        return {key: _replace_files(item, position + (key,), positions) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_files(item, position + (index,), positions) for index, item in enumerate(value)]
    return value


def _schemas(value: Any) -> list:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


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
