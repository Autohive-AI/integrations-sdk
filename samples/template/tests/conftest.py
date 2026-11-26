"""Offline fixtures using the same auth envelope as the platform."""

import sys
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from autohive_integrations_sdk import ExecutionContext

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture
def mock_context():
    context = ExecutionContext(auth={"auth_type": "Custom", "credentials": {"api_key": "test-only-api-key"}})
    context.fetch = AsyncMock()
    return context
