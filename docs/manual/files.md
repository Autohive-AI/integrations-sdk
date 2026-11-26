# Files

An action can take files as inputs and return files as outputs. A handler works with `File`
objects and never with base64.

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
        invoice.size          # the size in bytes

        data = await invoice.read()
        ...
```

## Return an output file

Put a `File` in the result:

```python
return ActionResult(data={
    "report": File.from_bytes(pdf_bytes, "report.pdf", "application/pdf"),
})
```

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
