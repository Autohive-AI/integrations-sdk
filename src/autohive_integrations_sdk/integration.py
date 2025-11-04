# Standard Library Imports
from abc import ABC, abstractmethod
import asyncio
from dataclasses import dataclass, field
from datetime import timedelta
from enum import Enum
import json
import json as jsonX  # Keep alias to avoid conflict with 'json' parameter in fetch
import logging
import os
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional, Union, Type, TypeVar, Generic, ClassVar
from urllib.parse import urlencode

# Third-Party Imports
import aiohttp
from jsonschema import validate, Draft7Validator
from raygun4py import raygunprovider


# ---- Type Definitions ----
T = TypeVar('T')

# ---- Auth Types ----
class AuthType(Enum):
    """The type of authentication to use"""
    PlatformOauth2 = "PlatformOauth2"
    PlatformTeams = "PlatformTeams"
    ApiKey = "ApiKey"
    Basic = "Basic"
    Custom = "Custom"

# ---- Exceptions ----
class ValidationError(Exception):
    """Raised when inputs/outputs validation fails"""
    def __init__(self, message: str, schema: str = None, inputs: str = None):
        self.schema = schema
        """The schema that failed validation"""
        self.inputs = inputs
        """The data that failed validation"""
        self.message = message
        """The error message"""
        super().__init__(message)

class ConfigurationError(Exception):
    """Raised when integration configuration is invalid"""
    pass

class HTTPError(Exception):
    """Custom HTTP error with detailed information"""
    def __init__(self, status: int, message: str, response_data: Any = None):
        self.status = status
        """Status code"""
        self.message = message
        """Error message"""
        self.response_data = response_data
        """Response data"""
        super().__init__(f"HTTP {status}: {message}")

class RateLimitError(HTTPError):
    """Raised when rate limited by the API"""
    def __init__(self, retry_after: int, *args, **kwargs):
        self.retry_after = retry_after
        """Retry after"""
        super().__init__(*args, **kwargs)

# ---- Result Classes ----
@dataclass
class ActionResult:
    """Result returned by action handlers.

    This class encapsulates the data returned by an action along with optional
    billing information for cost tracking.

    Args:
        data: The actual result data from the action
        cost_usd: Optional USD cost for billing purposes

    Example:
        ```python
        return ActionResult(
            data={"message": "Success", "result": 42},
            cost_usd=0.05
        )
        ```
    """
    data: Any
    cost_usd: Optional[float] = None

@dataclass
class IntegrationResult:
    """Result format sent from lambda wrapper to backend.

    This class represents the standardized format that the lambda wrapper
    sends to the Autohive backend, including SDK version and type-specific data.

    Args:
        version: SDK version (auto-populated)
        type: Type of result payload (e.g., "action", "connected_account")
        result: Polymorphic result data - structure varies by type.
                For "action": {'data': output, 'billing': billing_info}
                For "connected_account": {'data': account_info}

    Note:
        This type is returned by Integration methods and serialized by the lambda wrapper.
        Integration developers should use ActionResult for action handlers.
    """
    version: str
    type: str
    result: Any

# ---- Configuration Classes ----
@dataclass
class ConnectedAccountInfo:
    """Information about a connected account from an external service"""
    email: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    username: Optional[str] = None
    user_id: Optional[str] = None
    avatar_url: Optional[str] = None
    organization: Optional[str] = None

@dataclass
class Parameter:
    """Definition of a parameter"""
    name: str
    type: str
    description: str
    enum: Optional[List[str]] = None
    required: bool = True
    default: Any = None

@dataclass
class SchemaDefinition:
    """Base class for components that have input/output schemas"""
    name: str
    description: str
    input_schema: List[Parameter]
    output_schema: Optional[Dict[str, Any]] = None

@dataclass
class Action(SchemaDefinition):
    """Empty dataclass that inherits from SchemaDefinition"""
    pass

@dataclass
class PollingTrigger(SchemaDefinition):
    """Definition of a polling trigger"""
    polling_interval: timedelta = field(default_factory=timedelta)

@dataclass
class IntegrationConfig:
    """Configuration for an integration"""
    name: str
    version: str
    description: str
    auth: Dict[str, Any]
    actions: Dict[str, Action]
    polling_triggers: Dict[str, PollingTrigger]

# ---- Base Handler Classes ----
class ActionHandler(ABC):
    """Base class for action handlers"""
    @abstractmethod
    async def execute(self, inputs: Dict[str, Any], context: 'ExecutionContext') -> Any:
        """Execute the action"""
        pass

class PollingTriggerHandler(ABC):
    """Base class for polling trigger handlers"""
    @abstractmethod
    async def poll(self, inputs: Dict[str, Any], last_poll_ts: Optional[str], context: 'ExecutionContext') -> List[Dict[str, Any]]:
        """Execute the polling trigger"""
        pass

class ConnectedAccountHandler(ABC):
    """Base class for connected account handlers"""
    @abstractmethod
    async def get_account_info(self, context: 'ExecutionContext') -> ConnectedAccountInfo:
        """Get connected account information
        
        Returns:
            ConnectedAccountInfo with optional fields: email, first_name, last_name, 
            username, user_id, avatar_url, organization
        """
        pass

# ---- Core SDK Classes ----
class ExecutionContext:
    """Context provided to integration handlers for making authenticated HTTP requests.
    
    This class manages authentication, HTTP sessions, and provides a convenient interface
    for making API requests with automatic retries, error handling, and logging."""
    def __init__(
        self,
        auth: Dict[str, Any] = {}, 
        request_config: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        logger: Optional[logging.Logger] = None
    ):
        self.auth = auth
        """Authentication configuration"""
        self.config = request_config or {"max_retries": 3, "timeout": 30}
        """Request configuration"""
        self.metadata = metadata or {}
        """Additional metadata"""
        self.logger = logger or logging.getLogger(__name__)
        """Logger instance"""
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        if not self._session:
            self._session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._session:
            await self._session.close()
            self._session = None

    async def fetch(
            self,
            url: str,
            method: str = "GET",
            params: Optional[Dict[str, Any]] = None,
            data: Any = None,
            json: Any = None,
            headers: Optional[Dict[str, str]] = None,
            content_type: Optional[str] = None,
            timeout: Optional[int] = None,
            retry_count: int = 0
    ) -> Any:
        """Make an authenticated HTTP request.
        
        This method handles authentication, retries, error handling, and response parsing.
        
        Args:
            url: The URL to request
            method: HTTP method to use. Defaults to "GET".
            params: Query parameters
            data: Request body data
            json: JSON data to send (will set content_type to application/json)
            headers: Additional HTTP headers
            content_type: Content-Type header
            timeout: Request timeout in seconds
            retry_count: Current retry attempt (used internally)
            
        Returns:
            Response data, parsed as JSON if possible
            
        Raises:
            HTTPError: For HTTP error responses
            RateLimitError: When rate limited by the API
            Exception: For other request errors
        """
        if not self._session:
            self._session = aiohttp.ClientSession()

        # Prepare request
        if json is not None:
            data = json
            content_type = "application/json"

        final_headers = {}
        
        if self.auth and "Authorization" not in (headers or {}):
            auth_type = AuthType(self.auth.get("auth_type", "PlatformOauth2"))
            credentials = self.auth.get("credentials", {})
            
            if auth_type == AuthType.PlatformOauth2 and "access_token" in credentials:
                final_headers["Authorization"] = f"Bearer {credentials['access_token']}"

        if content_type:
            final_headers["Content-Type"] = content_type
        if headers:
            final_headers.update(headers)

        if params:
            # Handle nested dictionary parameters
            flat_params = {}
            for key, value in params.items():
                if isinstance(value, (dict, list)):
                    flat_params[key] = jsonX.dumps(value)
                elif value is not None:
                    flat_params[key] = str(value)
            query_string = urlencode(flat_params)
            url = f"{url}{'&' if '?' in url else '?'}{query_string}"

        # Prepare body
        if data is not None:
            if content_type == "application/json":
                data = jsonX.dumps(data)
            elif content_type == "application/x-www-form-urlencoded":
                data = urlencode(data) if isinstance(data, dict) else data

        # Store the original timeout numeric value
        original_timeout = timeout or self.config["timeout"]

        # Convert the numeric timeout to a ClientTimeout instance for this request
        client_timeout = aiohttp.ClientTimeout(total=original_timeout)

        try:
            async with self._session.request(
                method=method,
                url=url,
                data=data,
                headers=final_headers,
                timeout=client_timeout,
                ssl=True
            ) as response:
                content_type = response.headers.get("Content-Type", "")

                if response.status == 429:  # Rate limit
                    retry_after = int(response.headers.get("Retry-After", 60))
                    raise RateLimitError(
                        retry_after,
                        response.status,
                        "Rate limit exceeded",
                        await response.text()
                    )

                try:
                    if "application/json" in content_type:
                        result = await response.json()
                    else:
                        result = await response.text()
                        if not result and response.status in {200, 201, 204}:
                            return None
                except Exception as e:
                    self.logger.error(f"Error parsing response: {e}")
                    result = await response.text()

                if not response.ok:
                    print(f"HTTP error encountered. Status: {response.status}. Result: {result}")
                    raise HTTPError(response.status, str(result), result)

                return result

        except RateLimitError:
            raise
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            # Don't want to send this to Raygun here because this will be retried.
            print(f"Error encountered: {e}. Retry count: {retry_count}. Backing off.")
            if retry_count < self.config["max_retries"]:
                await asyncio.sleep(2 ** retry_count)  # Exponential backoff
                print("Retrying request...")
                # Use original_timeout (numeric) for recursive calls
                return await self.fetch(
                    url, method, params, data, json,
                    headers, content_type, original_timeout, retry_count + 1
                )
            else:
                print("Max retries reached. Raising error.")
                raise
        except Exception as e:
            self.logger.error(f"Unexpected error during {method} {url}: {e}")
            print(f"Unexpected error encountered: {e}")
            raise


class Integration:
    """Base integration class with handler registration and execution.
    
    This class manages the integration configuration, handler registration,
    and provides methods to execute actions and triggers.
    
    Args:
        config: Integration configuration
        
    Attributes:
        config: Integration configuration
    """

    def __init__(self, config: IntegrationConfig):
        self.config = config
        """Integration configuration"""
        self._action_handlers: Dict[str, Type[ActionHandler]] = {}
        """Action handlers"""
        self._polling_handlers: Dict[str, Type[PollingTriggerHandler]] = {}
        """Polling handlers"""
        self._connected_account_handler: Optional[Type[ConnectedAccountHandler]] = None
        """Connected account handler"""

    @classmethod
    def load(cls, config_path: Union[str, Path] = None) -> 'Integration':
        """Load integration from JSON configuration.
        
        Args:
            config_path: Path to the configuration file. Defaults to 'config.json' in the project root.
            
        Returns:
            Initialized integration instance
            
        Raises:
            ConfigurationError: If configuration is invalid or missing
        """
        if config_path is None:
            config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'config.json')
        
        config_path = Path(config_path)

        if not config_path.exists():
            raise ConfigurationError(f"Configuration file not found: {config_path}")

        try:
            with open(config_path, 'r') as f:
                config_data = json.load(f)
        except json.JSONDecodeError as e:
            raise ConfigurationError(f"Invalid JSON configuration: {e}")
        
        # Parse configuration sections
        actions = cls._parse_actions(config_data.get("actions", {}))
        polling_triggers = cls._parse_polling_triggers(config_data.get("polling_triggers", {}))

        config = IntegrationConfig(
            name=config_data["name"],
            version=config_data["version"],
            description=config_data["description"],
            auth=config_data.get("auth", {}),
            actions=actions,
            polling_triggers=polling_triggers
        )

        return cls(config)

    @staticmethod
    def _parse_interval(interval_str: str) -> timedelta:
        """Parse interval string into timedelta"""
        unit = interval_str[-1].lower()
        value = int(interval_str[:-1])

        if unit == 's':
            return timedelta(seconds=value)
        elif unit == 'm':
            return timedelta(minutes=value)
        elif unit == 'h':
            return timedelta(hours=value)
        elif unit == 'd':
            return timedelta(days=value)
        else:
            raise ConfigurationError(f"Invalid interval format: {interval_str}")

    @classmethod
    def _parse_actions(cls, actions_config: Dict[str, Any]) -> Dict[str, Action]:
        """Parse action configurations"""
        actions = {}
        for name, data in actions_config.items():
            actions[name] = Action(
                name=name,
                description=data["description"],
                input_schema=data["input_schema"],
                output_schema=data["output_schema"]
            )

        return actions

    @classmethod
    def _parse_polling_triggers(cls, triggers_config: Dict[str, Any]) -> Dict[str, PollingTrigger]:
        """Parse polling trigger configurations"""
        triggers = {}
        for name, data in triggers_config.items():
            interval = cls._parse_interval(data["polling_interval"])

            triggers[name] = PollingTrigger(
                name=name,
                description=data["description"],
                polling_interval=interval,
                input_schema=data["input_schema"],
                output_schema=data["output_schema"]
            )

        return triggers

    def action(self, name: str):
        """Decorator to register an action handler.
        
        Args:
            name: Name of the action to register
            
        Returns:
            Decorator function
            
        Raises:
            ConfigurationError: If action is not defined in config
            
        Example:
            ```python
            @integration.action("my_action")
            class MyActionHandler(ActionHandler):
                async def execute(self, inputs, context):
                    # Implementation
                    return result
            ```
        """
        def decorator(handler_class: Type[ActionHandler]):
            if name not in self.config.actions:
                raise ConfigurationError(f"Action '{name}' not defined in config")
            self._action_handlers[name] = handler_class
            return handler_class
        return decorator

    def polling_trigger(self, name: str):
        """Decorator to register a polling trigger handler
        
        Args:
            name: Name of the polling trigger to register
            
        Returns:
            Decorator function
        
        Raises:
            ConfigurationError: If polling trigger is not defined in config

        Example:
            ```python
            @integration.polling_trigger("my_polling_trigger")
            class MyPollingTriggerHandler(PollingTriggerHandler):
                async def poll(self, inputs, last_poll_ts, context):
                    # Implementation
                    return result
            ```
        """
        def decorator(handler_class: Type[PollingTriggerHandler]):
            if name not in self.config.polling_triggers:
                raise ConfigurationError(f"Polling trigger '{name}' not defined in config")
            self._polling_handlers[name] = handler_class
            return handler_class
        return decorator

    def connected_account(self):
        """Decorator to register a connected account handler
        
        Returns:
            Decorator function

        Example:
            ```python
            @integration.connected_account()
            class MyConnectedAccountHandler(ConnectedAccountHandler):
                async def get_account_info(self, context):
                    # Implementation
                    return {"email": "user@example.com", "name": "John Doe"}
            ```
        """
        def decorator(handler_class: Type[ConnectedAccountHandler]):
            self._connected_account_handler = handler_class
            return handler_class
        return decorator

    async def execute_action(self,
                           name: str,
                           inputs: Dict[str, Any],
                           context: ExecutionContext) -> IntegrationResult:
        """Execute a registered action.

        Args:
            name: Name of the action to execute
            inputs: Action inputs
            context: Execution context

        Returns:
            IntegrationResult with action data and optional billing information

        Raises:
            ValidationError: If inputs or outputs don't match schema, or if handler doesn't return ActionResult
        """
        if name not in self._action_handlers:
            raise ValidationError(f"Action '{name}' not registered")

        # Validate inputs against action schema
        action_config = self.config.actions[name]
        validator = Draft7Validator(action_config.input_schema)
        errors = sorted(validator.iter_errors(inputs), key=lambda e: e.path)
        if errors:
            message = ""
            for error in errors:
                message += f"{list(error.schema_path)}, {error.message},\n "
            raise ValidationError(message, action_config.input_schema, inputs)

        if "fields" in self.config.auth:
            auth_config = self.config.auth["fields"]
            validator = Draft7Validator(auth_config)
            errors = sorted(validator.iter_errors(context.auth), key=lambda e: e.path)
            if errors:
                message = ""
                for error in errors:
                    message += f"{list(error.schema_path)}, {error.message},\n "
                raise ValidationError(message, auth_config, context.auth)

        # Create handler instance and execute
        handler = self._action_handlers[name]()
        result = await handler.execute(inputs, context)

        # Validate that result is ActionResult
        if not isinstance(result, ActionResult):
            raise ValidationError(
                f"Action handler '{name}' must return ActionResult, got {type(result).__name__}"
            )

        # Validate output schema against the data inside ActionResult
        validator = Draft7Validator(action_config.output_schema)
        errors = sorted(validator.iter_errors(result.data), key=lambda e: e.path)
        if errors:
            message = ""
            for error in errors:
                message += f"{list(error.schema_path)}, {error.message},\n "
            raise ValidationError(message, action_config.output_schema, result.data)

        # Extract billing information
        billing = None
        if result.cost_usd is not None:
            billing = {'cost_usd': result.cost_usd}

        # Return IntegrationResult with action-specific data structure
        from . import __version__
        return IntegrationResult(
            version=__version__,
            type='action',
            result={
                'data': result.data,
                'billing': billing
            }
        )

    async def execute_polling_trigger(self,
                                    name: str,
                                    inputs: Dict[str, Any],
                                    last_poll_ts: Optional[str],
                                    context: ExecutionContext) -> List[Dict[str, Any]]:
        """Execute a registered polling trigger
        
        Args:
            name: Name of the polling trigger to execute
            inputs: Trigger inputs
            last_poll_ts: Last poll timestamp
            context: Execution context
            
        Returns:
            List of records
            
        Raises:
            ValidationError: If inputs or outputs don't match schema
        """
        if name not in self._polling_handlers:
            raise ValidationError(f"Polling trigger '{name}' not registered")

        # Validate trigger configuration
        trigger_config = self.config.polling_triggers[name]
        try:
            validate(inputs, trigger_config.input_schema)
        except Exception as e:
            raise ValidationError(e.message, e.schema, e.instance)

        try:
            auth_config = self.config.auth["fields"]
            validate(context.auth, auth_config)
        except Exception as e:
            raise ValidationError(e.message, e.schema, e.instance)
        
        # Create handler instance and execute
        handler = self._polling_handlers[name]()
        records = await handler.poll(inputs, last_poll_ts, context)
        # Validate each record
        for record in records:
            if "id" not in record:
                raise ValidationError(
                    f"Polling trigger '{name}' returned record without required 'id' field")
            if "data" not in record:
                raise ValidationError(
                    f"Polling trigger '{name}' returned record without required 'data' field")

            # Validate record data against output schema
            try:
                validate(record["data"], trigger_config.output_schema)
            except Exception as e:
                raise ValidationError(e.message, e.schema, e.instance)
            
        return records

    async def get_connected_account(self, context: ExecutionContext) -> IntegrationResult:
        """Get connected account information

        Args:
            context: Execution context

        Returns:
            IntegrationResult containing connected account data

        Raises:
            ValidationError: If no connected account handler is registered or auth is invalid
        """
        if not self._connected_account_handler:
            raise ValidationError("No connected account handler registered")

        if "fields" in self.config.auth:
            auth_config = self.config.auth["fields"]
            validator = Draft7Validator(auth_config)
            errors = sorted(validator.iter_errors(context.auth), key=lambda e: e.path)
            if errors:
                message = ""
                for error in errors:
                    message += f"{list(error.schema_path)}, {error.message},\n "
                raise ValidationError(message, auth_config, context.auth)

        handler = self._connected_account_handler()
        account_info = await handler.get_account_info(context)

        if not isinstance(account_info, ConnectedAccountInfo):
            raise ValidationError(
                f"Connected account handler must return ConnectedAccountInfo, got {type(account_info).__name__}"
            )

        # Convert ConnectedAccountInfo to dict and remove None values
        account_data = {
            'email': account_info.email,
            'username': account_info.username,
            'first_name': account_info.first_name,
            'last_name': account_info.last_name,
            'avatar_url': account_info.avatar_url,
            'organization': account_info.organization,
            'user_id': account_info.user_id
        }
        account_data = {k: v for k, v in account_data.items() if v is not None}

        # Return IntegrationResult with connected_account-specific data structure
        from . import __version__
        return IntegrationResult(
            version=__version__,
            type='connected_account',
            result={
                'data': account_data
            }
        )

# ---- Raygun Crash Reporting ----
RAYGUN_API_KEY = os.environ.get("RAYGUN_API_KEY")
raygun_client = None
if RAYGUN_API_KEY:
    raygun_client = raygunprovider.RaygunSender(RAYGUN_API_KEY)
   
def handle_exception(exc_type, exc_value, exc_traceback):
    if raygun_client:  
        raygun_client.send_exception(exc_info=(exc_type, exc_value, exc_traceback),tags=['excepthook'])         
    sys.__excepthook__(exc_type, exc_value, exc_traceback)

def initialize_exception_handler():
    """Initialize the custom exception handler."""
    sys.excepthook = handle_exception

initialize_exception_handler()