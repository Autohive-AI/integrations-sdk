# API Fetch Tester

A sample Autohive integration demonstrating API calls with different authentication methods.

## Actions

| Action | Description |
|--------|-------------|
| `call_api` | Call an API without authentication |
| `call_api_un_pw` | Call an API with Basic Authentication (username/password) |
| `call_api_header` | Call an API with header-based authentication (Bearer token) |

## Authentication

This integration uses custom auth with three fields:

- **User name** — username for Basic Auth
- **Password** — password for Basic Auth
- **API Key** — Bearer token for header-based auth

All three fields are required by the shared `auth.fields` schema, even when running `call_api`, which does not send authentication to the provider. Local contexts must use the platform envelope:

```python
auth = {
    "auth_type": "Custom",
    "credentials": {
        "user_name": "test-user",
        "password": "test-only-password",
        "api_key": "test-only-api-key",
    },
}
```

## Inputs and outputs

Each action accepts a required `url` string. Use an endpoint that returns a JSON object: that object becomes `ActionResult.data` directly, without an extra `data` property. The sample reports a demonstration `cost_usd` of `0.01`; this is not a provider pricing calculation.

`context.fetch()` returns a `FetchResponse`, so handlers read `response.data`. HTTP failures propagate as `HTTPError` or `RateLimitError`; SDK 2.1.0 preserves their response headers on `exc.headers`. See [HTTP error headers](../../docs/manual/patterns.md#http-error-headers-sdk-210) for selective, case-insensitive lookup.

## Requirements and tests

The included `pytest.ini` is for standalone use. When copying this sample into an integrations monorepo, omit or remove it and inherit the repository-root pytest configuration so shared fixtures such as `env_credentials` and `make_context` remain available.

Use Python 3.13+ and `autohive-integrations-sdk~=2.1.0`. From this sample's directory, with a virtual environment active:

```bash
python -m pip install -r requirements.txt pytest pytest-asyncio
python -m pytest tests/ -m unit -v
```

The tests mock `context.fetch()` and require no network access or provider credentials. They check action results, auth request construction, billing, and HTTP error propagation.

With [HiveUp installed](https://github.com/Autohive-AI/autohive-integrations-tooling#install-hiveup-from-a-local-build), run `hiveup validate .` and `hiveup test .` from this directory. The unit test filenames and markers follow HiveUp's discovery contract.

## Usage

This sample is part of the [Autohive Integrations SDK](https://github.com/autohive-ai/integrations-sdk). See the [Building Your First Integration](../../docs/manual/building_your_first_integration.md) guide.
