"""File values for actions.

A field of an action is a file when its schema in ``config.json`` is a reference to the SDK's
file schema::

    "invoice": {"$ref": "https://cdn.autohive.com/schemas/sdk/file/v1.json"}

A handler receives a :class:`File` for each such input, and returns a :class:`File` for each such
output. The SDK moves the bytes: it downloads a large input only when the handler reads it, and it
uploads a large output after the handler returns. A file is never held in memory whole unless the
handler asks for that with :meth:`File.read`.

On the wire, between the platform and the SDK, a file is a JSON object in one of three forms:

- ``{"name", "contentType", "content"}``: the content, base64-encoded.
- ``{"name", "contentType", "url", "sizeBytes"}``: a URL the SDK downloads the content from.
- ``{"name", "contentType", "key", "sizeBytes"}``: the storage key of content the SDK uploaded.

Handlers never see these forms.
"""
import asyncio
import base64
import uuid
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Dict, Optional, Set, Tuple, Union

import aiohttp
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

INLINE_LIMIT_BYTES = 3 * 1024 * 1024
"""An output file up to this size is returned inline. A larger one is uploaded."""

DEFAULT_CHUNK_BYTES = 1024 * 1024

_CONNECT_TIMEOUT_SECONDS = 30
_READ_TIMEOUT_SECONDS = 60

# An error message quotes the start of the response body. The SDK reads no more of the body than
# this, and waits no longer than this for it.
_ERROR_TEXT_CHARACTERS = 500
_ERROR_BODY_BYTES = 4 * _ERROR_TEXT_CHARACTERS
_ERROR_BODY_SECONDS = 10


class FileTransferError(Exception):
    """A file could not be downloaded or uploaded.

    The SDK reports it as an ``ActionError``, so handlers do not need to catch it.
    """


class _PlatformUrl:
    """An input the platform delivered as a URL. The URL carries its own signature."""

    def __init__(self, url: str):
        self.url = url


class _Request:
    """An output whose content the SDK downloads from another service."""

    def __init__(self, url: str, method: str, params: Optional[Dict[str, Any]],
                 headers: Optional[Dict[str, str]], send_auth: bool):
        self.url = url
        self.method = method
        self.params = params
        self.headers = headers
        self.send_auth = send_auth


class File:
    """A file passed to an action, or returned from one.

    Attributes:
        name: The file name, for example ``"report.pdf"``.
        content_type: The media type, for example ``"application/pdf"``.
        size: The size in bytes, or ``None`` when it is not known yet.

    Read an input with :meth:`read` or :meth:`iter_chunks`. Build an output with
    :meth:`from_bytes` or :meth:`from_request`.
    """

    def __init__(self, name: str, content_type: str, size: Optional[int] = None, *, _source: Any = None):
        self.name = name
        self.content_type = content_type
        self.size = size
        self._source = _source
        self._context: Any = None
        self._requested = False

    def __repr__(self) -> str:
        return f"File(name={self.name!r}, content_type={self.content_type!r}, size={self.size!r})"

    @classmethod
    def from_bytes(cls, data: bytes, name: str, content_type: str) -> "File":
        """A file whose content the handler already holds in memory."""
        return cls(name, content_type, len(data), _source=bytes(data))

    @classmethod
    def from_request(
            cls,
            url: str,
            *,
            name: str,
            content_type: str,
            size: Optional[int] = None,
            method: str = "GET",
            params: Optional[Dict[str, Any]] = None,
            headers: Optional[Dict[str, str]] = None,
            send_auth: bool = True,
    ) -> "File":
        """A file whose content the SDK downloads from ``url`` after the handler returns.

        Use it to return a file from another service without holding it in memory. The SDK
        streams the response body to the platform.

        The request is made like ``ExecutionContext.fetch()``: for platform OAuth the access token
        is sent as a ``Bearer`` token, unless ``send_auth`` is false or ``headers`` has its own
        ``Authorization``. A redirect is followed; the credentials are not sent to another origin.

        Args:
            url: The URL to download.
            name: The file name.
            content_type: The media type.
            size: The size in bytes, if the handler knows it. If it is omitted, the SDK takes
                it from the response's ``Content-Length``. A file larger than the inline limit
                needs one or the other.
            method: The HTTP method.
            params: Query parameters added to the URL.
            headers: Additional request headers.
            send_auth: Set to false for a URL that carries its own authorisation, such as a
                pre-signed or pre-authenticated download URL.
        """
        return cls(name, content_type, size, _source=_Request(url, method, params, headers, send_auth))

    async def read(self) -> bytes:
        """Return the whole content. This holds the whole file in memory."""
        if isinstance(self._source, bytes):
            return self._source
        return b"".join([chunk async for chunk in self.iter_chunks()])

    async def iter_chunks(self, chunk_size: int = DEFAULT_CHUNK_BYTES) -> AsyncIterator[bytes]:
        """Yield the content in pieces of exactly ``chunk_size`` bytes. The last can be shorter.

        A large input is not kept in memory, so each read of it is a new download.
        """
        if chunk_size < 1:
            raise ValueError("chunk_size must be at least 1")
        async with self._open(chunk_size) as (_, chunks):
            async for chunk in chunks:
                yield chunk

    @asynccontextmanager
    async def _open(self, chunk_size: int) -> AsyncIterator[Tuple[Optional[int], AsyncIterator[bytes]]]:
        """Open the content. Yields the size, if it is known by then, and the chunks."""
        source = self._source
        if isinstance(source, bytes):
            yield len(source), _bytes_chunks(source, chunk_size)
            return

        if source is None:
            raise FileTransferError(f"File {self.name!r} has no content")
        if self._context is None:
            raise FileTransferError(
                f"File {self.name!r} is downloaded by the SDK after the action returns; it cannot be read here"
            )
        if isinstance(source, _Request):
            # A request to another service is made once: it can have an effect there.
            if self._requested:
                raise FileTransferError(
                    f"File {self.name!r} is in the result more than once, and its request has already been made")
            self._requested = True
        # An input that the platform delivered as a URL is downloaded again for each read.

        response = await self._request(source)
        try:
            if not 200 <= response.status < 300:
                text = await _error_text(response)
                raise FileTransferError(f"Download of {self.name!r} failed with HTTP {response.status}: {text}")
            # A compressed body does not have the length that Content-Length gives.
            if self.size is None and response.content_length is not None \
                    and "Content-Encoding" not in response.headers:
                self.size = response.content_length
            yield self.size, _exact_chunks(self._body(response, chunk_size), chunk_size)
        finally:
            response.release()

    async def _request(self, source: Any) -> aiohttp.ClientResponse:
        session = self._context._ensure_session()
        timeout = aiohttp.ClientTimeout(
            total=None, sock_connect=_CONNECT_TIMEOUT_SECONDS, sock_read=_READ_TIMEOUT_SECONDS)
        try:
            if isinstance(source, _PlatformUrl):
                # The URL carries its own signature: no credentials are sent, and no redirect is followed.
                return await session.get(
                    source.url, headers={"Accept-Encoding": "identity"}, timeout=timeout, allow_redirects=False)

            url = self._context._url_with_params(source.url, source.params)
            headers = self._context._default_headers(source.headers, None, source.send_auth)
            headers.update(source.headers or {})
            headers.setdefault("Accept-Encoding", "identity")
            return await session.request(source.method, url, headers=headers, timeout=timeout)
        except (aiohttp.ClientError, asyncio.TimeoutError) as error:
            raise FileTransferError(f"Download of {self.name!r} failed: {_describe(error)}") from error

    async def _body(self, response: aiohttp.ClientResponse, chunk_size: int) -> AsyncIterator[bytes]:
        try:
            async for piece in response.content.iter_chunked(chunk_size):
                yield piece
        except (aiohttp.ClientError, asyncio.TimeoutError) as error:
            raise FileTransferError(f"Download of {self.name!r} stopped: {_describe(error)}") from error


def _describe(error: BaseException) -> str:
    return str(error) or type(error).__name__


async def _error_text(response: aiohttp.ClientResponse) -> str:
    """The start of an error response's body, for a message.

    Only the start is read, and only for a limited time, so a large or slow error body costs
    little memory and little time. The rest of the body is not read: the connection is closed.
    The result is the part that arrived, which is empty when nothing could be read.
    """
    start = bytearray()

    async def read_start() -> None:
        while len(start) < _ERROR_BODY_BYTES:
            piece = await response.content.read(_ERROR_BODY_BYTES - len(start))
            if not piece:
                break
            start.extend(piece)

    try:
        await asyncio.wait_for(read_start(), _ERROR_BODY_SECONDS)
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
        pass
    finally:
        response.close()

    try:
        text = start.decode(response.charset or "utf-8", errors="replace")
    except LookupError:
        text = start.decode("utf-8", errors="replace")
    return text[:_ERROR_TEXT_CHARACTERS]


async def _bytes_chunks(data: bytes, chunk_size: int) -> AsyncIterator[bytes]:
    for start in range(0, len(data), chunk_size):
        yield data[start:start + chunk_size]


async def _exact_chunks(pieces: AsyncIterator[bytes], chunk_size: int) -> AsyncIterator[bytes]:
    """Regroup pieces of any size into chunks of exactly ``chunk_size`` bytes, except the last."""
    buffer = bytearray()
    async for piece in pieces:
        if not buffer and len(piece) == chunk_size:
            yield piece
            continue
        buffer += piece
        while len(buffer) >= chunk_size:
            yield bytes(buffer[:chunk_size])
            del buffer[:chunk_size]
    if buffer:
        yield bytes(buffer)


def is_file_schema(schema: Any) -> bool:
    return isinstance(schema, dict) and schema.get("$ref") == FILE_SCHEMA_ID


def file_from_wire(value: Dict[str, Any], context: Any) -> File:
    name = value["name"]
    content_type = value["contentType"]
    if "content" in value:
        try:
            data = base64.b64decode(value["content"], validate=True)
        except ValueError as error:
            raise FileTransferError(f"File {name!r} has content that is not valid base64") from error
        return File.from_bytes(data, name, content_type)
    if "url" in value:
        url = value["url"]
        # The platform can give a function that decides which input URLs are downloaded.
        url_filter = (getattr(context, "file_transport", None) or {}).get("input_url_filter")
        if url_filter is not None:
            url = url_filter(url)
            if url is None:
                raise FileTransferError(f"File {name!r} has a URL that the platform does not accept")
        file = File(name, content_type, value.get("sizeBytes"), _source=_PlatformUrl(url))
        file._context = context
        return file
    raise FileTransferError(f"File {name!r} has no content and no url")


def convert_file_inputs(schema: Any, value: Any, context: Any) -> Any:
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
    return _replace_files(value, (), positions, context) if positions else value


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


def _replace_files(value: Any, position: _Position, positions: Set[_Position], context: Any) -> Any:
    if position in positions:
        return file_from_wire(value, context)
    if isinstance(value, dict):
        return {key: _replace_files(item, position + (key,), positions, context) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_files(item, position + (index,), positions, context) for index, item in enumerate(value)]
    return value


def _schemas(value: Any) -> list:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


async def convert_file_outputs(value: Any, context: Any) -> Any:
    """Replace each :class:`File` in a result with its wire form."""
    if isinstance(value, File):
        return await file_to_wire(value, context)
    if isinstance(value, dict):
        return {key: await convert_file_outputs(item, context) for key, item in value.items()}
    if isinstance(value, list):
        return [await convert_file_outputs(item, context) for item in value]
    return value


async def file_to_wire(file: File, context: Any) -> Dict[str, Any]:
    if file._context is None:
        file._context = context

    async with file._open(DEFAULT_CHUNK_BYTES) as (size, chunks):
        if size is not None and size > INLINE_LIMIT_BYTES:
            return await _upload(file, size, chunks, context)

        data = bytearray()
        async for chunk in chunks:
            data += chunk
            if len(data) > INLINE_LIMIT_BYTES:
                if size is None:
                    raise FileTransferError(
                        f"File {file.name!r} is larger than {INLINE_LIMIT_BYTES} bytes and its size is not known. "
                        "Give the size, or use a download that returns Content-Length"
                    )
                raise FileTransferError(f"File {file.name!r} is longer than its size of {size} bytes")
        if size is not None and len(data) != size:
            raise FileTransferError(f"File {file.name!r} has {len(data)} bytes, not its size of {size}")

    return {
        "name": file.name,
        "contentType": file.content_type,
        "content": base64.b64encode(bytes(data)).decode("ascii"),
    }


async def _upload(file: File, size: int, chunks: AsyncIterator[bytes], context: Any) -> Dict[str, Any]:
    """Stream a file to storage with the platform's upload grant, and return its ``key`` form.

    The grant is an S3 pre-signed POST: ``{"url", "fields", "keyPrefix"?, "maxBytes"?}``. The body
    is built here so that its length is known before it starts, which a POST upload needs.
    """
    grant = (getattr(context, "file_transport", None) or {}).get("upload")
    if not grant:
        raise FileTransferError(
            f"File {file.name!r} is {size} bytes, more than the {INLINE_LIMIT_BYTES} bytes that can be returned "
            "inline, and the platform gave no upload grant"
        )
    max_bytes = grant.get("maxBytes")
    if max_bytes is not None and size > max_bytes:
        raise FileTransferError(f"File {file.name!r} is {size} bytes, more than the {max_bytes} bytes allowed")

    fields = dict(grant["fields"])
    # The name goes into a multipart header, so characters that would break the header are replaced.
    filename = "".join("_" if char in '"\\\r\n' else char for char in file.name)
    # A unique part keeps two files with the same name apart.
    unique_name = f"{uuid.uuid4().hex[:12]}/{filename}"
    placeholder = "${filename}"
    if grant.get("keyPrefix"):
        key = f"{grant['keyPrefix']}{unique_name}"
    elif fields["key"].endswith(placeholder):
        # A grant like this allows every key that starts with the part before the placeholder.
        key = fields["key"][:-len(placeholder)] + unique_name
    else:
        # The grant names one key. A second file would replace the first.
        key = fields["key"]
        if key in context._uploaded_file_keys:
            raise FileTransferError(
                f"File {file.name!r} cannot be uploaded: the upload grant allows one file, and it is used"
            )
    context._uploaded_file_keys.add(key)
    fields["key"] = key

    boundary = uuid.uuid4().hex
    prefix = b"".join(
        f'--{boundary}\r\nContent-Disposition: form-data; name="{field}"\r\n\r\n{field_value}\r\n'.encode()
        for field, field_value in fields.items()
    )
    # The file is the last field: fields after it are ignored.
    prefix += (
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: {file.content_type}\r\n\r\n"
    ).encode()
    suffix = f"\r\n--{boundary}--\r\n".encode()

    problem: Optional[str] = None

    async def body() -> AsyncIterator[bytes]:
        # The HTTP client reports a failure in here as a connection error, so the cause is kept.
        nonlocal problem
        sent = 0
        yield prefix
        try:
            async for chunk in chunks:
                sent += len(chunk)
                if sent > size:
                    raise FileTransferError(f"File {file.name!r} is longer than its size of {size} bytes")
                yield chunk
            if sent != size:
                raise FileTransferError(f"File {file.name!r} has {sent} bytes, not its size of {size}")
        except FileTransferError as error:
            problem = str(error)
            raise
        yield suffix

    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Content-Length": str(len(prefix) + size + len(suffix)),
    }
    timeout = aiohttp.ClientTimeout(
        total=None, sock_connect=_CONNECT_TIMEOUT_SECONDS, sock_read=2 * _READ_TIMEOUT_SECONDS)
    try:
        async with context._ensure_session().post(
                grant["url"], data=body(), headers=headers, timeout=timeout) as response:
            if response.status not in (200, 201, 204):
                text = await _error_text(response)
                raise FileTransferError(f"Upload of {file.name!r} failed with HTTP {response.status}: {text}")
    except FileTransferError:
        raise
    except (aiohttp.ClientError, asyncio.TimeoutError) as error:
        raise FileTransferError(problem or f"Upload of {file.name!r} failed: {_describe(error)}") from error
    if problem:
        raise FileTransferError(problem)

    return {"name": file.name, "contentType": file.content_type, "key": key, "sizeBytes": size}
