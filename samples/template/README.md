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

The starter sends `example_input` in a JSON POST body and returns the provider's JSON object under `result`. Replace the example endpoint, action, schemas, and tests together when adapting the template.

## Requirements

- Python 3.13+
- `autohive-integrations-sdk~=2.1.0` (SDK 2.1 patch releases)

## Testing

From this sample's directory, with a virtual environment active:

```bash
python -m pip install -r requirements.txt pytest pytest-asyncio
python -m pytest tests/ -m unit -v
```

The tests use dummy credentials in the platform auth envelope and mock `context.fetch()` with `FetchResponse`. They do not call the example endpoint. Success checks assert `ResultType.ACTION` before inspecting data; missing inputs or credentials return `ResultType.VALIDATION_ERROR`.

With [HiveUp installed](https://github.com/Autohive-AI/autohive-integrations-tooling#install-hiveup-from-a-local-build), run `hiveup validate .` and `hiveup test .` from the sample's directory. HiveUp discovers `tests/test_*_unit.py` and runs tests with the sample's SDK pin in an isolated environment.

## Resources

- [Building Your First Integration](../../docs/manual/building_your_first_integration.md)
- [Integration Structure Reference](../../docs/manual/integration_structure.md)
- [Patterns & Best Practices](../../docs/manual/patterns.md)
