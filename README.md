# Integrations SDK for Autohive

##  Overview

This is the SDK for building integrations into Autohive's AI agent platform.

### SDK

The SDK code lives in [src/autohive_integrations_sdk](https://github.com/Autohive-AI/integrations-sdk/tree/master/src/autohive_integrations_sdk).

### Documentation

Basic API docs can be found in [docs/apidocs](https://github.com/Autohive-AI/integrations-sdk/tree/master/docs/apidocs).

More verbose documentation lives in [docs/manual](https://github.com/Autohive-AI/integrations-sdk/tree/master/docs/manual), including a [tutorial to build your first integration](docs/manual/building_your_first_integration.md).

### Samples

The [samples directory](https://github.com/Autohive-AI/integrations-sdk/tree/master/samples) contains a very basic "API Fetch" integration as a sample starting point.

## Additional information

[Release Notes](https://github.com/Autohive-AI/integrations-sdk/blob/master/RELEASENOTES.md)

## Error Reporting

The SDK includes integration with Raygun4Py for error reporting and crash tracking. To enable error reporting:

1. Set the `RAYGUN_API_KEY` environment variable with your Raygun API key
2. The SDK will automatically send exception reports to Raygun when errors occur

The setup for error reporting will be done automatically for you by the Autohive application and helps us with monitoring and debugging integration issues in production environments. 

