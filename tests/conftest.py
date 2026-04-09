"""Shared fixtures for the Autohive Integrations SDK test suite."""

import json
import pytest
from pathlib import Path

from autohive_integrations_sdk import Integration, ExecutionContext


@pytest.fixture
def config_dict():
    """Minimal config.json content with one action, one trigger, and auth fields."""
    return {
        "name": "test-integration",
        "version": "0.1.0",
        "description": "Integration used by the test suite",
        "auth": {
            "auth_type": "Custom",
            "fields": {
                "type": "object",
                "properties": {
                    "api_key": {"type": "string"}
                },
                "required": ["api_key"]
            }
        },
        "actions": {
            "test_action": {
                "description": "A simple test action",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"}
                    },
                    "required": ["name"]
                },
                "output_schema": {
                    "type": "object",
                    "properties": {
                        "greeting": {"type": "string"}
                    },
                    "required": ["greeting"]
                }
            }
        },
        "polling_triggers": {
            "test_trigger": {
                "description": "A simple test trigger",
                "polling_interval": "5m",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "channel": {"type": "string"}
                    },
                    "required": ["channel"]
                },
                "output_schema": {
                    "type": "object",
                    "properties": {
                        "message": {"type": "string"}
                    },
                    "required": ["message"]
                }
            }
        }
    }


@pytest.fixture
def tmp_config(tmp_path, config_dict):
    """Write the config dict to a temporary file and return its path."""
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(config_dict))
    return config_file


@pytest.fixture
def integration(tmp_config):
    """An Integration instance loaded from the temporary config."""
    return Integration.load(tmp_config)


@pytest.fixture
def execution_context():
    """A simple ExecutionContext with a Custom API key."""
    return ExecutionContext(
        auth={"api_key": "test-key-123"},
        request_config={"max_retries": 1, "timeout": 1},
    )
