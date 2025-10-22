# Connected Account Information

## Overview

Integrations can provide connected account information to display which account was used to authorize the integration. This improves transparency and helps users understand which credentials are being used.

When enabled, the platform will:
- Automatically fetch account information when a user authorizes the integration
- Cache the information in the database for fast display
- Show "Connected to **email@example.com** for everyone in **workspace/plan name**" in the UI

## Configuration

To enable connected account support, add the `supports_connected_account` field to your integration's `config.json`:

```json
{
  "name": "github",
  "entry_point": "main.py",
  "description": "GitHub integration for repository management",
  "supports_connected_account": true,
  "auth": {
    "type": "platform",
    "provider": "Github"
  },
  "actions": {
    "create_issue": {
      "display_name": "Create Issue",
      "description": "Creates a new issue in a repository"
    }
  }
}
```

### Field Details

- **Field**: `supports_connected_account`
- **Type**: `boolean`
- **Required**: No (defaults to `false`)
- **Description**: When `true`, the integration must implement the `get_connected_account()` method

## Implementation

### The ConnectedAccount Model

The SDK provides a `ConnectedAccount` dataclass for returning user information:

```python
from autohive_integrations_sdk import ConnectedAccount

@dataclass
class ConnectedAccount:
    """Information about the connected account"""
    email: Optional[str] = None
    username: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    avatar_url: Optional[str] = None
    organization: Optional[str] = None
    user_id: Optional[str] = None
```

### Implementing get_connected_account()

Add the `get_connected_account()` method to your integration class:

```python
from autohive_integrations_sdk import BaseIntegration, ConnectedAccount, ExecutionContext

class MyIntegration(BaseIntegration):
    async def get_connected_account(self, context: ExecutionContext) -> ConnectedAccount:
        """
        Returns information about the connected account.
        
        This method is called once when a user authorizes the integration.
        The returned information is cached in the database.
        
        Args:
            context: ExecutionContext containing auth credentials and metadata
            
        Returns:
            ConnectedAccount with user information
        """
        # Get access token from context
        access_token = context.auth.get('access_token')
        
        # Fetch user info from the API
        headers = {"Authorization": f"Bearer {access_token}"}
        async with self.http_client.get("https://api.example.com/user", headers=headers) as response:
            user_data = await response.json()
        
        # Return ConnectedAccount with available fields
        return ConnectedAccount(
            email=user_data.get("email"),
            username=user_data.get("login"),
            first_name=user_data.get("name", "").split()[0] if user_data.get("name") else None,
            last_name=user_data.get("name", "").split()[-1] if user_data.get("name") and " " in user_data.get("name") else None,
            avatar_url=user_data.get("avatar_url"),
            organization=user_data.get("company"),
            user_id=str(user_data.get("id"))
        )
```

## Example: GitHub Integration

Here's a complete example for a GitHub integration:

```python
from autohive_integrations_sdk import BaseIntegration, ConnectedAccount, ExecutionContext

class GithubIntegration(BaseIntegration):
    async def get_connected_account(self, context: ExecutionContext) -> ConnectedAccount:
        """Fetch GitHub user information"""
        access_token = context.auth.get('access_token')
        
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        async with self.http_client.get("https://api.github.com/user", headers=headers) as response:
            if response.status != 200:
                raise Exception(f"Failed to fetch user info: {response.status}")
            
            user_data = await response.json()
        
        # Parse name into first/last
        name = user_data.get("name", "")
        name_parts = name.split(maxsplit=1) if name else []
        
        return ConnectedAccount(
            email=user_data.get("email"),
            username=user_data.get("login"),
            first_name=name_parts[0] if len(name_parts) > 0 else None,
            last_name=name_parts[1] if len(name_parts) > 1 else None,
            avatar_url=user_data.get("avatar_url"),
            organization=user_data.get("company"),
            user_id=str(user_data.get("id"))
        )
```

## Example: LinkedIn Integration

For OAuth integrations with different API structures:

```python
from autohive_integrations_sdk import BaseIntegration, ConnectedAccount, ExecutionContext

class LinkedInIntegration(BaseIntegration):
    async def get_connected_account(self, context: ExecutionContext) -> ConnectedAccount:
        """Fetch LinkedIn user information"""
        access_token = context.auth.get('access_token')
        
        headers = {"Authorization": f"Bearer {access_token}"}
        
        # LinkedIn API returns profile info
        async with self.http_client.get(
            "https://api.linkedin.com/v2/userinfo",
            headers=headers
        ) as response:
            if response.status != 200:
                raise Exception(f"Failed to fetch user info: {response.status}")
            
            user_data = await response.json()
        
        return ConnectedAccount(
            email=user_data.get("email"),
            first_name=user_data.get("given_name"),
            last_name=user_data.get("family_name"),
            avatar_url=user_data.get("picture"),
            user_id=user_data.get("sub")
        )
```

## Display Priority

The platform displays the connected account information with the following priority:

1. **Email** - If available, email is shown
2. **Username** - If no email, username is shown
3. **First Name** - If neither email nor username, first name is shown

Example displays:
- `Connected to john.doe@company.com for everyone in Engineering workspace`
- `Connected to johndoe for everyone in My Company plan`
- `Connected to John for everyone in Operations workspace`

## Best Practices

1. **Fill as many fields as possible** - The more information you provide, the better the user experience
2. **Handle API errors gracefully** - If the API call fails, raise an exception with a clear message
3. **Don't expose sensitive data** - Only return public profile information
4. **Use the user_id field** - Include a unique identifier when available for future features
5. **Test thoroughly** - Verify your implementation returns correct data for different account types

## When is it Called?

The `get_connected_account()` method is invoked automatically:

1. **After OAuth authorization** - When a user completes the OAuth flow
2. **After custom auth setup** - When custom authentication credentials are saved

The information is cached in the database and not fetched on every page load, ensuring fast UI performance.

## Error Handling

If `get_connected_account()` raises an exception or returns `None`, the system will:
- Log a warning
- Not cache any account information
- Fall back to showing basic connection status without account details

This is best-effort caching - failures won't prevent the integration from working.

## Troubleshooting

### Connected account not showing

1. Verify `supports_connected_account: true` is in config.json
2. Check that `get_connected_account()` is implemented
3. Look for errors in logs during authorization
4. Ensure the API endpoint returns valid data
5. Re-upload the integration after making changes

### API authentication fails

1. Verify the access token is valid in context.auth
2. Check API endpoint URLs and authentication headers
3. Ensure the OAuth scopes include permission to fetch user info
4. Test the API call independently to verify it works

## Migration Notes

Existing integrations without this feature continue working without changes. Setting `supports_connected_account: false` (or omitting the field) means the system won't attempt to fetch account information.
