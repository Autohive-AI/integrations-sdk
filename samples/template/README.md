# My Integration

<!-- Replace with a brief description of what this integration does. -->

## Description

<!-- What service does this integration connect to? What problems does it solve? -->

## Setup & Authentication

This integration uses custom authentication with the following fields:

- **API Key** — your API key from the service provider

<!-- Update the fields above to match your config.json auth fields. -->

## Actions

| Action | Description |
|--------|-------------|
| `my_action` | Describe what this action does |

<!-- For each action, document its inputs and outputs: -->

### `my_action`

**Inputs:**
- `example_input` (string, required) — an example input field

**Outputs:**
- `result` (object) — the result data

## Requirements

- Python 3.13+
- `autohive-integrations-sdk~=1.0.2`

## Testing

```bash
cd samples/template
pip install -r requirements.txt
python tests/test_my_integration.py
```

## Resources

- [Building Your First Integration](../../docs/manual/building_your_first_integration.md)
- [Integration Structure Reference](../../docs/manual/integration_structure.md)
- [Patterns & Best Practices](../../docs/manual/patterns.md)
