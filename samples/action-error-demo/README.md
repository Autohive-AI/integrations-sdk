# Action error demo

An offline example of SDK 2.1.0 action results, expected application errors, and unhandled exceptions. It uses an in-memory user directory, needs no authentication, and makes no HTTP requests.

## Actions

Every action accepts a required `user_id` string. IDs `"1"` and `"2"` return a user object with `id`, `name`, and `email`.

| Action | Known user | Unknown user | Cost |
|--------|------------|--------------|------|
| `get_user` | `ResultType.ACTION` | Raises `KeyError` | None |
| `get_user_billing` | `ResultType.ACTION` | Raises `KeyError` | `0.001` on success |
| `lookup_user` | `ResultType.ACTION` | `ResultType.ACTION_ERROR` | None |
| `lookup_user_with_cost` | `ResultType.ACTION` | `ResultType.ACTION_ERROR` | `0.001` on success or expected error |

For successful actions, inspect `result.result.data`. For expected errors, inspect `result.result.message`; `ActionError` bypasses output schema validation. An unexpected exception propagates out of `execute_action()` rather than becoming an `ActionError`. Missing or invalid inputs return `ResultType.VALIDATION_ERROR`.

The costs illustrate billing behavior, not actual provider charges. See [Billing and cost tracking](../../docs/manual/billing.md).

## Requirements and tests

The included `pytest.ini` is for standalone use. When copying this sample into an integrations monorepo, omit or remove it and inherit the repository-root pytest configuration so shared fixtures such as `env_credentials` and `make_context` remain available.

Use Python 3.13+ and `autohive-integrations-sdk~=2.1.0`. From this sample's directory, with a virtual environment active:

```bash
python -m pip install -r requirements.txt pytest pytest-asyncio
python -m pytest tests/ -m unit -v
```

With [HiveUp installed](https://github.com/Autohive-AI/autohive-integrations-tooling#install-hiveup-from-a-local-build), run `hiveup validate .` and `hiveup test .` from this directory. The tests cover success, expected errors, billing, and exception propagation without credentials or network access.
