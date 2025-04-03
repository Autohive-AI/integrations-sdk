from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Union, Type, TypeVar, Generic, ClassVar
import aiohttp
import asyncio
import json as jsonX
from urllib.parse import urlencode
import logging
from datetime import datetime, timedelta
import yaml
from pathlib import Path
from abc import ABC, abstractmethod
import json
from jsonschema import validate
from enum import Enum
from jsonschema import Draft7Validator
import os

# ---- Type Definitions ----
T = TypeVar('T')

# ---- Auth Types ----
class AuthType(Enum):
    PlatformOauth2 = "PlatformOauth2"
    PlatformTeams = "PlatformTeams"
    ApiKey = "ApiKey"
    Basic = "Basic"
    Custom = "Custom"

# ---- Exceptions ----
class ValidationError(Exception):
    """Raised when input validation fails"""
    def __init__(self, message: str, schema: str = None, inputs: str = None):
        self.schema = schema
        self.inputs = inputs
        self.message = message
        super().__init__(message)

class ConfigurationError(Exception):
    """Raised when integration configuration is invalid"""
    pass

class HTTPError(Exception):
    """Custom HTTP error with detailed information"""
    def __init__(self, status: int, message: str, response_data: Any = None):
        self.status = status
        self.message = message
        self.response_data = response_data
        super().__init__(f"HTTP {status}: {message}")

class RateLimitError(HTTPError):
    """Raised when rate limited by the API"""
    def __init__(self, retry_after: int, *args, **kwargs):
        self.retry_after = retry_after
        super().__init__(*args, **kwargs)

# ---- Configuration Classes ----
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
class WebhookTrigger(SchemaDefinition):
    """Definition of a webhook trigger"""
    events: List[str] = field(default_factory=list)
    subscribe_config: Dict[str, Any] = field(default_factory=dict)
    unsubscribe_config: Dict[str, Any] = field(default_factory=dict)

@dataclass
class IntegrationConfig:
    """Configuration for an integration"""
    name: str
    version: str
    description: str
    auth: Dict[str, Any]
    actions: Dict[str, Action]
    polling_triggers: Dict[str, PollingTrigger]
    webhook_triggers: Dict[str, WebhookTrigger]

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

class WebhookTriggerHandler(ABC):
    """Base class for webhook trigger handlers"""
    @abstractmethod
    async def subscribe(self, webhook_url: str, context: 'ExecutionContext') -> Dict[str, Any]:
        """Subscribe to webhook events"""
        pass

    @abstractmethod
    async def unsubscribe(self, subscription_data: Dict[str, Any], context: 'ExecutionContext') -> None:
        """Unsubscribe from webhook events"""
        pass

    @abstractmethod
    async def handle(self, event: Dict[str, Any], context: 'ExecutionContext') -> Dict[str, Any]:
        """Handle an incoming webhook event"""
        pass

# ---- Core SDK Classes ----
class ExecutionContext:
    """Context provided to integration handlers for making authenticated HTTP requests"""
    def __init__(
        self,
        auth: Dict[str, Any] = {}, 
        request_config: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        logger: Optional[logging.Logger] = None
    ):
        self.auth = auth
        self.config = request_config or {"max_retries": 3, "timeout": 30}
        self.metadata = metadata or {}
        self.logger = logger or logging.getLogger(__name__)
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
        """Make an authenticated HTTP request"""
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
    """Base integration class with handler registration and execution"""

    def __init__(self, config: IntegrationConfig):
        self.config = config
        self._action_handlers: Dict[str, Type[ActionHandler]] = {}
        self._polling_handlers: Dict[str, Type[PollingTriggerHandler]] = {}
        self._webhook_handlers: Dict[str, Type[WebhookTriggerHandler]] = {}

    @classmethod
    def load(cls, config_path: Union[str, Path] = os.path.join(os.path.dirname(__file__), 'config.json')) -> 'Integration':
        """Load integration from JSON configuration"""
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
        webhook_triggers = cls._parse_webhook_triggers(config_data.get("webhook_triggers", {}))

        config = IntegrationConfig(
            name=config_data["name"],
            version=config_data["version"],
            description=config_data["description"],
            auth=config_data.get("auth", {}),
            actions=actions,
            polling_triggers=polling_triggers,
            webhook_triggers=webhook_triggers
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

    @classmethod
    def _parse_webhook_triggers(cls, triggers_config: Dict[str, Any]) -> Dict[str, WebhookTrigger]:
        """Parse webhook trigger configurations"""
        triggers = {}
        for name, data in triggers_config.items():
            triggers[name] = WebhookTrigger(
                name=name,
                description=data["description"],
                events=data["events"],
                subscribe_config=data["subscribe_config"],
                unsubscribe_config=data["unsubscribe_config"],
                input_schema=data["input_schema"],
                output_schema=data["output_schema"]
            )

        return triggers

    def action(self, name: str):
        """Decorator to register an action handler"""
        def decorator(handler_class: Type[ActionHandler]):
            if name not in self.config.actions:
                raise ConfigurationError(f"Action '{name}' not defined in config")
            self._action_handlers[name] = handler_class
            return handler_class
        return decorator

    def polling_trigger(self, name: str):
        """Decorator to register a polling trigger handler"""
        def decorator(handler_class: Type[PollingTriggerHandler]):
            if name not in self.config.polling_triggers:
                raise ConfigurationError(f"Polling trigger '{name}' not defined in config")
            self._polling_handlers[name] = handler_class
            return handler_class
        return decorator

    def webhook_trigger(self, name: str):
        """Decorator to register a webhook trigger handler"""
        def decorator(handler_class: Type[WebhookTriggerHandler]):
            if name not in self.config.webhook_triggers:
                raise ConfigurationError(f"Webhook trigger '{name}' not defined in config")
            self._webhook_handlers[name] = handler_class
            return handler_class
        return decorator

    async def execute_action(self,
                           name: str,
                           inputs: Dict[str, Any],
                           context: ExecutionContext) -> Any:
        """Execute a registered action"""
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

        # Validate output if schema is defined
        validator = Draft7Validator(action_config.output_schema)
        errors = sorted(validator.iter_errors(result), key=lambda e: e.path)
        if errors:
            message = ""
            for error in errors:
                message += f"{list(error.schema_path)}, {error.message},\n "
            raise ValidationError(message, action_config.output_schema, result)
     
        return result

    async def execute_polling_trigger(self,
                                    name: str,
                                    inputs: Dict[str, Any],
                                    last_poll_ts: Optional[str],
                                    context: ExecutionContext) -> List[Dict[str, Any]]:
        """Execute a registered polling trigger"""
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

    async def subscribe_webhook(self,
                              name: str,
                              webhook_url: str,
                              context: ExecutionContext) -> Dict[str, Any]:
        """Subscribe to a webhook trigger"""
        if name not in self._webhook_handlers:
            raise ValidationError(f"Webhook trigger '{name}' not registered")

        # Create handler instance and execute subscribe
        handler = self._webhook_handlers[name]()
        subscription_data = await handler.subscribe(webhook_url, context)

        if not isinstance(subscription_data, dict):
            raise ValidationError(
                f"Webhook subscribe for '{name}' must return a dictionary")

        return subscription_data

    async def unsubscribe_webhook(self,
                                 name: str,
                                 subscription_data: Dict[str, Any],
                                 context: ExecutionContext) -> None:
        """Unsubscribe from a webhook trigger"""
        if name not in self._webhook_handlers:
            raise ValidationError(f"Webhook trigger '{name}' not registered")

        # Create handler instance and execute unsubscribe
        handler = self._webhook_handlers[name]()
        await handler.unsubscribe(subscription_data, context)

    async def handle_webhook_event(self,
                                 name: str,
                                 event: Dict[str, Any],
                                 context: ExecutionContext) -> Dict[str, Any]:
        """Handle an incoming webhook event"""
        if name not in self._webhook_handlers:
            raise ValidationError(f"Webhook trigger '{name}' not registered")

        # Validate event type
        trigger_config = self.config.webhook_triggers[name]
        event_type = event.get("type")
        if event_type not in trigger_config.events:
            raise ValidationError(
                f"Received unexpected event type '{event_type}' for trigger '{name}'")

        # Create handler instance and process event
        handler = self._webhook_handlers[name]()
        result = await handler.handle(event, context)

        # Validate result against output schema
        # if trigger_config.output_schema:
        #   self._validate_schema(result, trigger_config.output_schema)

        return result
