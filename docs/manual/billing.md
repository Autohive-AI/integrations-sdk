# Billing and Cost Tracking

> This guide covers billing and cost tracking for integrations. For a complete walkthrough of building an integration, see [Building Your First Integration](building_your_first_integration.md).

## Overview

Integrations can report per-action costs back to AutoHive for billing and usage tracking. This is useful for integrations that call paid third-party APIs where each execution has a measurable cost.

## Configuration

To enable billing support, add the `supports_billing` field to your integration's `config.json`:

```json
{
  "name": "my-integration",
  "entry_point": "my_integration.py",
  "description": "My integration with a paid API",
  "supports_billing": true,
  "auth": { ... },
  "actions": { ... }
}
```

### Field Details

- **Field**: `supports_billing`
- **Type**: `boolean`
- **Required**: No (defaults to `false`)
- **Description**: When `true`, the integration's action handlers are expected to return `ActionResult` objects that may include cost information via the `cost_usd` field

## Implementation

### The ActionResult Class

The SDK provides the `ActionResult` dataclass for returning data along with optional billing information:

```python
from autohive_integrations_sdk import ActionResult
```

`ActionResult` accepts two fields:
- **`data`** — the actual result data from the action
- **`cost_usd`** — optional USD cost for billing purposes (defaults to `None`)

### Returning Costs from Action Handlers

When your integration has `supports_billing: true`, your action handlers should return `ActionResult` with the `cost_usd` field to report the cost of each execution:

```python
from autohive_integrations_sdk import Integration, ExecutionContext, ActionHandler, ActionResult
from typing import Dict, Any

integration = Integration.load()

@integration.action("call_api")
class CallApiAction(ActionHandler):
    async def execute(self, inputs: Dict[str, Any], context: ExecutionContext):
        url = inputs["url"]
        credentials = context.auth.get("credentials", {})
        api_key = credentials.get("api_key", "")

        response = await context.fetch(url, headers={"Authorization": f"Bearer {api_key}"})

        return ActionResult(
            data={"result": response},
            cost_usd=0.05
        )
```

### Cost Values

- `cost_usd` is a `float` representing the cost in US dollars
- Set `cost_usd=0.0` for actions that have no cost but still want to participate in billing tracking
- Omit `cost_usd` if billing information is not available for a particular execution

## Example: Paid API Integration

For integrations calling APIs with per-request pricing, calculate and report the actual cost:

```python
@integration.action("generate_content")
class GenerateContentAction(ActionHandler):
    async def execute(self, inputs: Dict[str, Any], context: ExecutionContext):
        prompt = inputs["prompt"]
        credentials = context.auth.get("credentials", {})
        api_key = credentials.get("api_key", "")

        response = await context.fetch(
            "https://api.example.com/generate",
            method="POST",
            headers={"Authorization": f"Bearer {api_key}"},
            json={"prompt": prompt}
        )

        # Calculate cost based on usage returned by the API
        tokens_used = response.get("usage", {}).get("total_tokens", 0)
        cost = tokens_used * 0.00001  # $0.01 per 1000 tokens

        return ActionResult(
            data={"content": response["result"]},
            cost_usd=cost
        )
```
## Best Practices

1. **Always return `ActionResult`** from action handlers — it is the standard return type regardless of whether billing is enabled
2. **Be accurate with costs** - report the actual cost incurred by the third-party API call, not an estimate
3. **Use `0.0` for free operations** - if an action doesn't cost anything, explicitly return `cost_usd=0.0` to signal that billing is working correctly
4. **Calculate dynamically when possible** - if the API returns usage data (e.g., tokens consumed), use it to compute the cost rather than using a fixed value
5. **Handle errors gracefully** - even when an action fails, consider whether a cost was incurred (e.g., an API call was made but post-processing failed)

## Migration Notes

To add billing to an existing integration:

1. Add `"supports_billing": true` to `config.json`
2. Update action handlers to return `ActionResult` with `cost_usd`
3. Import `ActionResult` from the SDK: `from autohive_integrations_sdk import ActionResult`
4. Re-upload the integration
