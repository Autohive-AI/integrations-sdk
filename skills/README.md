# Agent Skills

Agent skills for AI coding assistants (Amp, Claude Code, etc.) that automate common SDK and integration tasks.

## Available Skills

| Skill | Description |
|-------|-------------|
| [`upgrading-sdk-v2/`](upgrading-sdk-v2/) | Upgrades an integration from SDK 1.x to 2.0.0 |

## Setup

Skills must be installed into a location your agent discovers. Two options:

### Option 1: Workspace-level (per-project)

Copy or symlink the skill into your project's `.agents/skills/` directory:

```bash
# From your integrations repo
mkdir -p .agents/skills
cp -r /path/to/integrations-sdk/skills/upgrading-sdk-v2 .agents/skills/

# Or symlink (keeps it up to date with the SDK repo)
ln -s /path/to/integrations-sdk/skills/upgrading-sdk-v2 .agents/skills/upgrading-sdk-v2
```

### Option 2: Global (all projects)

Copy or symlink into your global agent config:

```bash
mkdir -p ~/.config/agents/skills
cp -r /path/to/integrations-sdk/skills/upgrading-sdk-v2 ~/.config/agents/skills/

# Or symlink
ln -s /path/to/integrations-sdk/skills/upgrading-sdk-v2 ~/.config/agents/skills/upgrading-sdk-v2
```

## Usage

Once installed, the skill is automatically available. You can invoke it by:

- Asking your agent to "upgrade this integration to SDK v2"
- Asking to "migrate to SDK 2.0.0"
- Explicitly: "use the upgrading-sdk-v2 skill on the bitly integration"

The agent will load the skill's instructions and follow the step-by-step workflow.
