# Building your first integration

This guide will walk you through the process of building and setting up your own integrations for AutoHive. We use code samples from the api-fetch example in the `samples` directory to guide you along the way.

## Table of Contents

1. [Introduction](#introduction)
2. [Integration Structure](#integration-structure)
3. [Step-by-Step Integration Development](#step-by-step-integration-development)
4. [Testing Your Integration](#testing-your-integration)
5. [Examples](#examples)

## Introduction

AutoHive integrations allow you to connect external services and data sources to the AutoHive platform. Each integration follows a consistent structure and pattern, making it straightforward to develop new ones once you understand the basics.

AutoHive integrations require Python 3.13+. The SDK installation enforces this version of Python. Future versions of this SDK might change the Python version requirements.

## Integration Structure

A typical AutoHive integration consists of the following components:

- **Integration Directory**: Named after your integration (e.g., `github`, `slack`, `rss-reader`)
- **Configuration File**: Define how your integration connects to external services
- **Your integration code with API handlers**: Code that interacts with external APIs

## Step-by-Step Integration Development

### 1. Create Your Integration Directory

#### Directory 

Start by creating a new directory for your integration:

```
mkdir my-integration
cd my-integration
```

#### Install autohive_integrations_sdk 

The current process of installing `autohive_integration_sdk` requires installing the package from the PyPi test environment. Because `autohive_integration_sdk` has internal dependencies on libraries that are not on PyPi's test environment, main PyPi has to be added as an extra platform. In your new directory, run:

`pip install -i https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ autohive-integrations-sdk==0.1.1 --target=dependencies` 

Replace the version `0.1.1` with what is currently the latest.

This command should create a `dependencies` subdirectory in `my-integration` and its output would look similar to:

```
Looking in indexes: https://test.pypi.org/simple/, https://pypi.org/simple/
Collecting autohive-integrations-sdk==0.0.6
  Using cached https://test-files.pythonhosted.org/packages/ed/d7/76522637d719d27db20bad3dfcd16b0a07e2e3a142ca553a21bfaa60eb3a/autohive_integrations_sdk-0.0.6-py3-none-any.whl.metadata (930 bytes)
Collecting aiohttp (from autohive-integrations-sdk==0.0.6)
  Using cached aiohttp-3.11.16-cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64.whl.metadata (7.7 kB)
Collecting jsonschema (from autohive-integrations-sdk==0.0.6)
  Using cached jsonschema-4.23.0-py3-none-any.whl.metadata (7.9 kB)
Collecting aiohappyeyeballs>=2.3.0 (from aiohttp->autohive-integrations-sdk==0.0.6)
  Using cached aiohappyeyeballs-2.6.1-py3-none-any.whl.metadata (5.9 kB)
Collecting aiosignal>=1.1.2 (from aiohttp->autohive-integrations-sdk==0.0.6)
  Using cached aiosignal-1.3.2-py2.py3-none-any.whl.metadata (3.8 kB)
Collecting attrs>=17.3.0 (from aiohttp->autohive-integrations-sdk==0.0.6)
  Using cached attrs-25.3.0-py3-none-any.whl.metadata (10 kB)
Collecting frozenlist>=1.1.1 (from aiohttp->autohive-integrations-sdk==0.0.6)
  Using cached frozenlist-1.5.0-cp313-cp313-manylinux_2_5_x86_64.manylinux1_x86_64.manylinux_2_17_x86_64.manylinux2014_x86_64.whl.metadata (13 kB)
Collecting multidict<7.0,>=4.5 (from aiohttp->autohive-integrations-sdk==0.0.6)
  Using cached multidict-6.3.2-cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64.whl.metadata (5.1 kB)
Collecting propcache>=0.2.0 (from aiohttp->autohive-integrations-sdk==0.0.6)
  Using cached propcache-0.3.1-cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64.whl.metadata (10 kB)
Collecting yarl<2.0,>=1.17.0 (from aiohttp->autohive-integrations-sdk==0.0.6)
  Using cached yarl-1.19.0-cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64.whl.metadata (71 kB)
Collecting jsonschema-specifications>=2023.03.6 (from jsonschema->autohive-integrations-sdk==0.0.6)
  Using cached jsonschema_specifications-2024.10.1-py3-none-any.whl.metadata (3.0 kB)
Collecting referencing>=0.28.4 (from jsonschema->autohive-integrations-sdk==0.0.6)
  Using cached referencing-0.36.2-py3-none-any.whl.metadata (2.8 kB)
Collecting rpds-py>=0.7.1 (from jsonschema->autohive-integrations-sdk==0.0.6)
  Using cached rpds_py-0.24.0-cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64.whl.metadata (4.1 kB)
Collecting idna>=2.0 (from yarl<2.0,>=1.17.0->aiohttp->autohive-integrations-sdk==0.0.6)
  Using cached idna-3.10-py3-none-any.whl.metadata (10 kB)
Downloading https://test-files.pythonhosted.org/packages/ed/d7/76522637d719d27db20bad3dfcd16b0a07e2e3a142ca553a21bfaa60eb3a/autohive_integrations_sdk-0.0.6-py3-none-any.whl (7.5 kB)
Using cached aiohttp-3.11.16-cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64.whl (1.7 MB)
Using cached jsonschema-4.23.0-py3-none-any.whl (88 kB)
Using cached aiohappyeyeballs-2.6.1-py3-none-any.whl (15 kB)
Using cached aiosignal-1.3.2-py2.py3-none-any.whl (7.6 kB)
Using cached attrs-25.3.0-py3-none-any.whl (63 kB)
Using cached frozenlist-1.5.0-cp313-cp313-manylinux_2_5_x86_64.manylinux1_x86_64.manylinux_2_17_x86_64.manylinux2014_x86_64.whl (267 kB)
Using cached jsonschema_specifications-2024.10.1-py3-none-any.whl (18 kB)
Using cached multidict-6.3.2-cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64.whl (248 kB)
Using cached propcache-0.3.1-cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64.whl (228 kB)
Using cached referencing-0.36.2-py3-none-any.whl (26 kB)
Using cached rpds_py-0.24.0-cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64.whl (393 kB)
Using cached yarl-1.19.0-cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64.whl (347 kB)
Using cached idna-3.10-py3-none-any.whl (70 kB)
Installing collected packages: rpds-py, propcache, multidict, idna, frozenlist, attrs, aiohappyeyeballs, yarl, referencing, aiosignal, jsonschema-specifications, aiohttp, jsonschema, autohive-integrations-sdk
Successfully installed aiohappyeyeballs-2.6.1 aiohttp-3.11.16 aiosignal-1.3.2 attrs-25.3.0 autohive-integrations-sdk-0.0.6 frozenlist-1.5.0 idna-3.10 jsonschema-4.23.0 jsonschema-specifications-2024.10.1 multidict-6.3.2 propcache-0.3.1 referencing-0.36.2 rpds-py-0.24.0 yarl-1.19.0
```

#### Role of `autohive_integrations_sdk`

The SDK contains a core file, `integration.py`, that provides a fundamental set of functionality for integration authors and internal users at AutoHive.

On a high level, the files content are:

- **Type Definitions**: Custom types and state management for integrations

- **Exception Classes**: Custom exceptions for validation, configuration and HTTP operations

- **Configuration Classes**: 
  - `Action`: Defines integration actions
  - `PollingTrigger`: Defines polling-based triggers
  - `IntegrationConfig`: Overall integration configuration
  
  and others

- **Base Handler Classes**:
  - `ActionHandler`: Base class for implementing action handlers
  - `PollingTriggerHandler`: Base class for implementing polling trigger handlers

- **ExecutionContext**: Provides authenticated HTTP request functionality for integrations

### 2. Define Your Integration Configuration

Create a `config.json` file in your integration directory:

```json
{
    "name": "my-integration",
    "version": "0.1.0",
    "description": "Integration with My Service",
    "entry_point": "my_integration.py",
    "auth": {
        "identifier": "my_auth",
        "type": "Custom",
        "fields": {
            "type":"object",
            "properties": {
                "user_name": {
                    "type": "string",
                    "format": "text",
                    "label": "User name",
                    "help_text": "You'll get this from the API provider."
                },
                "password": {
                    "type": "string",
                    "format": "password",
                    "label": "Password",
                    "help_text": "You'll get this from the API provider."
                }
            },
            "required": [
                "user_name",
                "password"
            ]
        }
    },
    ...
}
```

The content of `auth.fields` has to be valid JSON Schema. Properties like `format`, `label` and `help_text` will in the future be used for rendering a UI when an instance of the integration is being setup.

The example above setups up custom auth with `user_name` and `password`, which would both sent to your integration at runtime.

The only useful value for `auth.type` for integration-defined authentication is currently `Custom`. Platform-defined authentication will introduce its own values. 

### 3. Create Your Integration Handler File and its dependencies

Create a `my_integration.py` file that will contain the main logic for your integration:

```python
from autohive_integrations_sdk import (
    Integration, ExecutionContext, ActionHandler, PollingTriggerHandler
)
from typing import Dict, Any

# Create the integration using the config.json
api_fetch = Integration.load()
```

Currently there are two types of interactions an integration can have:

- `ActionHandler`-based: a one-off call made by your integration
- `PollingTriggerHandler`-based: a call that gets triggered from AutoHive based on a regular schedule

#### ActionHandler-based

Your integration needs to define annotated classes and inherit from the correct handler type. An example for a basic `ActionHandler`-based handler could look like:

```python
@my_integration.action("my_action_handler")
class APIFetchActionHeader(ActionHandler):
    async def execute(self, inputs: Dict[str, Any], context: ExecutionContext):
        url = inputs["url"]
        api_key = context.auth["api_key"]

        # Do the API call here
        response = await context.fetch(url, headers={"Authorization": f"Bearer {api_key}"})
    
        print("Response: ", response)

        return response
```

This integration handler will take a URL and an API key and call the URL with the given API Key sent as a bearer token header. The response will be passed back to AutoHive.

Inside of an `ActionHandler`-based handler you will need to provide an `execute` method that accepts a `Dict` of input variables (matching what's defined in your `config.json`) and an `ExecutionContext` from the SDK. The context will provide network functionality via its `fetch` method and `context.auth` provides information for the purpose of integration-defined auth in AutoHive.

To get the API key passed into your `ExecutionContext`, the `config.json`'s `auth` section would have to be amended by adding:

```json
"api_key": {
    "type": "string",
    "format": "text",
    "label": "API Key",
    "help_text": "You'll get this from the API provider."
}
```

You could at this stage also add `api_key` to the list of required fields.

The handler's `input` `Dict` will be supplied from the AutoHive system. This requires an additional configuration elemement (`actions`) in `config.json`:

```json
{
    "name": "my-integration",
    "version": "0.1.0",
    "description": "Integration with My Service",
    "entry_point": "my_integration.py",
    "auth": {
        ...
    },
    "actions": {
        "my_action_handler": {
            "description": "Call an API.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "The URL of the API to call."
                    }
                },
                "required": [
                    "url"
                ]
            },
            "output_schema": {
                "type": "object",
                "properties": {
                    "data": {
                        "type": "object",
                        "description": "The data returned from the API call."
                    }
                },
                "required": [
                    "data"
                ]
            }
        },
        ... 
    },
    ...
}

```

`input_schema` and `output_schema` have to be valid JSON Schema. In the example above, a required `url` is defined as input and the expected response in `output_schema` is an object named `data`. This object could have further nested structures and actual data coming in or being returned from the integration will be validated against this schema.

#### PollingTriggerHandler-based

Integrations that use `PollingTriggerHandler` require a slightly different approach. Please note that thid approach is still under development and is described here for information and feedback purpose only. Polling triggers are not yet supported on AutoHive's back end systems.


```python
@rss_reader.polling_trigger("new_entries")
class NewEntriesPoller(PollingTriggerHandler):
    async def poll(self, inputs: Dict[str, Any], last_poll_ts: Optional[str], context: ExecutionContext):
        feeds = inputs["feeds"]
        new_entries = []
        ...
    
```

The underlying class has to inherit from `PollingTriggerHandler` and the annotation syntax is slightly different from `ActionHandler`

The example above shows a polling trigger for an RSS feed reader. The `poll` method has to be implemented to fulfill the contract and in addition to `inputs` and `context`, the polling trigger call delivers a `last_poll_ts` argument. This is an epoch timestamp of the time the last time this polling trigger was exectuted.

This information can for example be used within the integration to do additional data filtering and only to return most recent results to AutoHive.

There is no need to modify or update the timestamp, AutoHive tracks when the trigger was executed and stores the most recent value.

The accompanying change to `config.json` adds another section to the configuration: `polling_triggers`

```json
{
    "name": "my-integration",
    "version": "0.1.0",
    "description": "Integration with My Service",
    "entry_point": "my_integration.py",
    "auth": {
        ...
    },
    ...
    "polling_triggers": {
        "new_entries": {
            "description": "Poll for new entries in specified RSS feeds.",
            "polling_interval": "5m",
            "input_schema": {
                "type": "object",
                "properties": {
                    "feeds": {
                        "type": "array",
                        "description": "Array of RSS feed URLs to monitor.",
                        "items": {
                            "type": "string",
                            "description": "A URL of an RSS feed to read."
                        }
                    }
                },
                "required": [
                    "feeds"
                ]
            },
            "output_schema": {
                "type": "object",
                "properties": {
                    "feed_url": {
                        "type": "string",
                        "description": "URL of the RSS feed"
                    },
                    "feed_title": {
                        "type": "string",
                        "description": "Title of the RSS feed"
                    },
                    "title": {
                        "type": "string",
                        "description": "Entry title"
                    },
                    "link": {
                        "type": "string",
                        "description": "Link to entry"
                    },
                    "description": {
                        "type": "string",
                        "description": "The description of the entry"
                    },
                    "published": {
                        "type": "string",
                        "description": "Published date"
                    },
                    "author": {
                        "type": "string",
                        "description": "Author"
                    }
                },
                "required": [
                    "feed_url",
                    "feed_title",
                    "title",
                    "link",
                    "description",
                    "published",
                    "author"
                ]
            }
        }
    }
    ...
}

```

The example above also shows a more complex scenario for an `output_schema` in which an object response type is being defined. 

The expectation is that a polling trigger generally returns a collection of objects at the same time. The collections' objects will need to have a unique `id` field (for instance a UUID or a hashed string) and a `data` fields holding what is defined in `output_schema`.

### 4. Create a Requirements File

Create a Python `requirements.txt` file in your integration's directory to specify any Python dependencies your integration needs. 

Then run `pip install -r requirements.txt --target dependencies` from your integration's directory to install (or update) the additional dependencies from your own code locally to your directory.

## Testing Your Integration

At this stage, the easiest way to test the general functionality of your integration code by running it inside of a local testbed.

The general structure of such a testbed can be seen in `samples/api-fetch/test_api_fetch.py`.

Key concerns are:

1. Ensure the local dependencies are available:

```python
# Add the dependencies directory to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), "dependencies"))
```

2. Import your own integration as a module:

```python
from api_fetch import api_fetch
from integration import ExecutionContext
```

3. Run your integration using an `async` `ExecutionContext`:

```python
# Use the ExecutionContext as an async context manager
async with ExecutionContext(auth=auth) as context:

    # Mock auth
    auth = {
        "user_name": "test_user",
        "password": "test_password",
        "api_key": "test_api_key"
    }

    # Define test configuration
    inputs = {
        "url": "http://localhost:8000/test"
    }

    try:
        result = await api_fetch.execute_action("call_api", inputs, context)
        print("call_api:", result, "\n")
    except Exception as e:
        print(f"Error testing call_api: {e.message}")
    ...
```

The actual api-fetch sample integration demonstrates a call to a customiseable URL in three variations:

- No Auth
- HTTP BASIC Auth
- API Key as Bearer Token

If you spin up a local HTTP server as shown above, you should be able to inspect different headers and bodies being sent from the integration. The `config.json` of the api-fetch sample integration requires the result to a JSON object containing a `data` object. 

We will provide additional samples and updates to this SDK over time.