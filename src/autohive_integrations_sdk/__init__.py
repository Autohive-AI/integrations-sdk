# Version
__version__ = "1.1.1"

# Re-export classes from integration module
from autohive_integrations_sdk.integration import (
    Integration, ExecutionContext, ActionHandler, PollingTriggerHandler, ConnectedAccountHandler,
    ConnectedAccountInfo, ValidationError, HTTPError, RateLimitError, 
    ActionResult, ActionError, IntegrationResult, ResultType, FetchResponse
)