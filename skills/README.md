# Agent Skills

Agent skills for AI coding assistants (Amp, Claude Code, etc.) that automate common SDK and integration tasks.

## Available Skills

| Skill | Description |
|-------|-------------|
| [`building-integration/`](building-integration/) | Runs the local build and validation pipeline (structure, lint, format, security, tests) |
| [`migrating-private-integration/`](migrating-private-integration/) | Migrates an integration from the private repo to the public integrations repo |
| [`reviewing-integration-prs/`](reviewing-integration-prs/) | Reviews integration PRs for code quality, security, tests, docs, and skill compliance |
| [`upgrading-sdk-v2/`](upgrading-sdk-v2/) | Upgrades an integration from SDK 1.x or 2.0.x to 2.1.0 |
| [`writing-unit-tests/`](writing-unit-tests/) | Writes pytest unit tests for an integration using mock_context + FetchResponse |
| [`writing-integration-tests/`](writing-integration-tests/) | Writes pytest e2e integration tests that call real APIs using SDK ExecutionContext live fixtures |

## SDK and tooling baseline

These skills target released **SDK 2.1.0**. Recommend `autohive-integrations-sdk~=2.1.0` for new integrations and explicit SDK upgrades; this range accepts 2.1.x (`>=2.1.0,<2.2.0`). A private-to-public move preserves the source integration's pin and behavior; upgrade it separately.

Use the [released 2.1.0 source](https://github.com/Autohive-AI/integrations-sdk/tree/2.1.0/src/autohive_integrations_sdk) and [release notes](https://github.com/Autohive-AI/integrations-sdk/blob/2.1.0/RELEASENOTES.md) for SDK contracts, not unreleased behavior on `master`.

Local validation uses the installed Python **HiveUp** CLI (Python 3.13+). Follow the [HiveUp local-build installation instructions](https://github.com/Autohive-AI/autohive-integrations-tooling#install-hiveup-from-a-local-build); HiveUp is **not published to PyPI**. From an integrations repository root:

```bash
hiveup --version
hiveup validate <integration>
hiveup test <integration>
```

`validate` includes unit tests; `test` is the focused unit-test command. Use `hiveup check <check-name> <integration>` for a single check. Legacy scripts and the .NET CLI are compatibility paths, not the default workflow. See [building-integration](building-integration/SKILL.md) for history-aware PR validation.

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
- Asking to "upgrade to SDK 2.1.0"
- Asking to "review this integration PR" or "validate this PR against our skills"
- Explicitly: "use the upgrading-sdk-v2 skill on the bitly integration"

The agent will load the skill's instructions and follow the step-by-step workflow.
