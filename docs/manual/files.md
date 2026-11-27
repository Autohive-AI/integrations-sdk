# Files

An action can take files as inputs and return files as outputs. The SDK moves the bytes, so a
handler works with `File` objects and never with base64 or URLs.

Files need SDK 3.0.0 or later.

## Declare a file field

A field is a file when its schema in `config.json` is a reference to the SDK's file schema. The
property name does not matter.

```json
"input_schema": {
  "type": "object",
  "properties": {
    "invoice": {
      "$ref": "https://cdn.autohive.com/schemas/sdk/file/v1.json",
      "description": "The invoice PDF"
    },
    "attachments": {
      "type": "array",
      "items": { "$ref": "https://cdn.autohive.com/schemas/sdk/file/v1.json" }
    }
  },
  "required": ["invoice"]
}
```

Use the same reference in `output_schema` for a file the action returns. In Python code and
tests, the reference is the constant `FILE_SCHEMA_ID`.

The reference is an identifier. The SDK has its own copy of the schema, and nothing is fetched
when an action runs.

Only a field declared this way is a file. A field that still uses the older convention (an object
with `content`, `name` and `contentType`) keeps its plain `dict` value, so change the schema and
the handler of an action together.

## Read an input file

A handler receives a `File` for each file input.

```python
from autohive_integrations_sdk import ActionHandler, ActionResult, File

@integration.action("upload_invoice")
class UploadInvoice(ActionHandler):
    async def execute(self, inputs, context):
        invoice: File = inputs["invoice"]
        invoice.name          # "invoice.pdf"
        invoice.content_type  # "application/pdf"
        invoice.size          # the size in bytes, or None if it is not known

        data = await invoice.read()
        ...
```

`read()` returns the whole content, so the whole file is in memory. For a file that can be large,
read it in pieces:

```python
async for chunk in invoice.iter_chunks(1024 * 1024):
    ...
```

`iter_chunks(n)` yields pieces of exactly `n` bytes; only the last can be shorter. The platform
sends a large file as a URL, and the SDK downloads it when the handler reads it. The SDK does not
keep the content, so each read of a large file is a new download. An input file can also be put in
the result, whether the handler read it or not.

## Return an output file

Put a `File` in the result. For content the handler already holds:

```python
return ActionResult(data={
    "report": File.from_bytes(pdf_bytes, "report.pdf", "application/pdf"),
})
```

For content that is on another service, let the SDK download it:

```python
return ActionResult(data={
    "file": File.from_request(
        f"https://api.example.com/files/{file_id}/content",
        name=metadata["name"],
        content_type=metadata["mimeType"],
        size=metadata["size"],
    ),
})
```

The SDK makes the request after the handler returns and streams the response to the platform, so
the file is never in memory whole. The request is made like `context.fetch()`:

- For platform OAuth, the access token is sent. Pass `send_auth=False` for a URL that carries its
  own authorisation, such as a pre-authenticated download URL.
- A redirect is followed. The token is not sent to another origin.
- `size` is optional. Without it, the SDK uses the response's `Content-Length`.

A `File.from_request` file is for the result only. It cannot be read in the handler.

### Small and large outputs

The SDK returns an output file of up to 3 MB inline. It uploads a larger file to the platform's
storage, which needs the file's size before the upload starts. If a large file has no size (the
handler gave none and the response has no `Content-Length`), the action fails with an error that
says so.

## Send a large input to another service

To send a large file without holding it in memory, use the other service's chunked or resumable
upload with `iter_chunks()` and `context.fetch()`. Two options of `fetch()` help here:

- `send_auth=False` sends no access token. Some upload URLs carry their own authorisation and
  reject a request that has a token.
- `accept_statuses=[308]` returns a response with that status and does not raise `HTTPError`. Some
  services answer `308` between the chunks of an upload. When a redirect status is accepted, the
  request follows no redirect, and any other redirect status raises `HTTPError`.

```python
CHUNK_BYTES = 8 * 256 * 1024

async def upload(context, file, session_url):
    offset = 0
    async for chunk in file.iter_chunks(CHUNK_BYTES):
        end = offset + len(chunk) - 1
        response = await context.fetch(
            session_url,
            method="PUT",
            data=chunk,
            headers={"Content-Range": f"bytes {offset}-{end}/{file.size}"},
            accept_statuses=[308],
        )
        offset += len(chunk)
    return response.data
```

## Errors

When the SDK cannot download or upload a file, the action returns an `ActionError` with a message
that names the file and the cause. A handler does not need to catch anything for this.

## Test an action that uses files

Give an input file in its inline form, and read an output file from the result:

```python
import base64
from autohive_integrations_sdk import ExecutionContext

async def test_upload_invoice():
    inputs = {"invoice": {
        "name": "invoice.pdf",
        "contentType": "application/pdf",
        "content": base64.b64encode(b"%PDF-1.4 ...").decode(),
    }}
    async with ExecutionContext(auth=auth) as context:
        result = await integration.execute_action("upload_invoice", inputs, context)

    assert result.result.data["receipt"]["name"] == "receipt.pdf"
    assert base64.b64decode(result.result.data["receipt"]["content"]) == expected
```

A test that calls a handler directly, without `execute_action`, passes a `File`:
`File.from_bytes(b"...", "invoice.pdf", "application/pdf")`.
