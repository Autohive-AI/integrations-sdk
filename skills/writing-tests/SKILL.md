---
name: writing-tests
description: "Writes pytest tests for an Autohive integration: unit tests with the mock_context + FetchResponse pattern, and live integration tests that call real APIs with the live_context fixture. Use when asked to write tests, add test coverage, create unit, integration, e2e or live API tests, or make live tests run in TeamCity with a tests/teamcity.env file. Covers file structure, fixtures, test categories, required root .env.example updates, teamcity.env (what is a secret, ah:customAuth, ah:secret), destructive markers, and coverage expectations."
---

# Writing Tests for an Integration

An integration has two kinds of tests. Read the file for the kind you are writing:

| Kind | File | Read when |
|---|---|---|
| Unit tests (`tests/test_<integration>_unit.py`) | [`unit-tests.md`](unit-tests.md) | Writing or changing tests that mock `context.fetch`. Every integration needs these. |
| Integration tests (`tests/test_<integration>_integration.py`) | [`integration-tests.md`](integration-tests.md) | Writing or changing live tests that call the real API, updating root `.env.example`, or adding `tests/teamcity.env` so the live tests run in TeamCity. |

When asked to "write tests" for an integration without more detail, write the unit tests first. Add integration tests when the task asks for live, e2e, or integration tests, or when the integration already has them.

Both kinds require the integration to be on **SDK 2.0.0** (`autohive-integrations-sdk~=2.0.0` in `requirements.txt`). If it is still on SDK 1.x, upgrade it first with the `upgrading-sdk-v2` skill.
