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
from typing import Any, Dict, Optional

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

    Follows ``properties`` and ``items``. A value at any other position is returned unchanged,
    whatever its shape.
    """
    if is_file_schema(schema):
        return file_from_wire(value) if isinstance(value, dict) else value
    if not isinstance(schema, dict):
        return value
    properties = schema.get("properties")
    if isinstance(value, dict) and isinstance(properties, dict):
        return {key: convert_file_inputs(properties.get(key), item) for key, item in value.items()}
    if isinstance(value, list) and isinstance(schema.get("items"), dict):
        return [convert_file_inputs(schema["items"], item) for item in value]
    return value


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
