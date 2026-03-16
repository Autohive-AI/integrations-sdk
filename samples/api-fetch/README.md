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

## Usage

This sample is part of the [Autohive Integrations SDK](https://github.com/autohive-ai/integrations-sdk). See the [Building Your First Integration](../../docs/manual/building_your_first_integration.md) guide.
