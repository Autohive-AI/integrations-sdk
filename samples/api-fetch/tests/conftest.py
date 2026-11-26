"""Offline auth and fetch fixtures shared by the API examples."""

import sys
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from autohive_integrations_sdk import ExecutionContext

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture
def mock_context():
    # All three fields are required by this sample's shared auth schema.
    context = ExecutionContext(
        auth={
            "auth_type": "Custom",
            "credentials": {
                "user_name": "test-user",
                "password": "test-only-password",  # nosec B105: dummy offline test credential
                "api_key": "test-only-api-key",
            },
        }
    )
    context.fetch = AsyncMock()
    return context
