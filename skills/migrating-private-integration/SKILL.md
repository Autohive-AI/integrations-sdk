---
name: migrating-private-integration
description: "Migrates an Autohive integration from the private `Autohive-AI/integrations` repo to the public `Autohive-AI/autohive-integrations` repo. Use when asked to migrate, move, open-source, or publish an integration. Covers a mandatory security/safety/secrets review, structural cleanup, the three coordinated PRs (public add, private remove, SDK skill update if needed), and the obligatory ask in the AH engineering Slack channel for a second opinion before merging."
---

# Migrating a Private Integration to the Public Repo

This skill describes the process for moving an integration from the **private** [`Autohive-AI/integrations`](https://github.com/Autohive-AI/integrations) repo to the **public** [`Autohive-AI/autohive-integrations`](https://github.com/Autohive-AI/autohive-integrations) repo.

> **🚨 Stop and read this first.** Once code is published to a public repo, deleting it does not "unpublish" it — git history, forks, and search-engine caches are forever. **Never** migrate without completing the security/safety/secrets review in Step 1, and **always** ask a second engineer in the AH Slack channel before merging the PRs.

## When to use this skill

Trigger phrases:

- "migrate the X integration to public"
- "move X to the public repo"
- "open-source X"
- "publish X to autohive-integrations"

## When NOT to use this skill

- The integration is being **created from scratch** — it should go straight to the public repo if it's safe; use [building-integration](../building-integration/SKILL.md) and the [starter template](https://github.com/autohive-ai/integrations-sdk/tree/master/samples/template) instead.
- The integration is being **removed** from the private repo without going public — that's a normal `chore: remove X` PR, not a migration.
- The integration touches **internal Autohive infrastructure** (`agno-agent`, `file_echo`, `python-executor`, `testserver`, anything that wraps Dash/internal APIs) — these stay private. If unsure, ask in Slack before doing anything.

## Prerequisites

Before starting, the following repos must exist as siblings:

```
parent-dir/
├── integrations/                      ← private (source)
├── autohive-integrations/              ← public (destination)
├── autohive-integrations-tooling/      ← validation scripts
└── integrations-sdk/                   ← skill + docs
```

Check:

```bash
ls ../integrations/<name>            # the integration to migrate
ls ../autohive-integrations          # the public repo
ls ../autohive-integrations-tooling/scripts/validate_integration.py
```

Activate the public repo's venv (or create one — see [building-integration](../building-integration/SKILL.md) for setup):

```bash
cd ../autohive-integrations
source .venv/bin/activate
```

## Step 1 — Security / safety / secrets review (MANDATORY)

This is the gate. If anything below is found and cannot be cleanly removed, **abort the migration** and discuss in Slack.

### 1a. Static secret scan

```bash
# Hardcoded secrets, tokens, API keys, credentials
grep -rni -E "secret|password|api[_-]?key|token|credential|client[_-]?id|client[_-]?secret|bearer|private[_-]?key" \
  ../integrations/<name>/ \
  --include='*.py' --include='*.json' --include='*.txt' --include='*.md' --include='*.yml' --include='*.yaml' \
  | grep -v __pycache__
```

Expect **zero** real values. Documentation strings like `YOUR_API_KEY`, schema field names like `api_key`, and runtime extraction like `context.auth["credentials"]["access_token"]` are fine. Hardcoded JWT-shaped strings, base64 blobs, or anything that looks like a real key are **not**.

### 1b. Internal hostnames, employee names, customer references

```bash
grep -rni -E "@autohive\.|autohive\.io|autohive-internal|dash\.|qa\.|staging\.|kai|alex|lohit|joel" \
  ../integrations/<name>/ \
  --include='*.py' --include='*.json' --include='*.txt' --include='*.md' \
  | grep -v __pycache__
```

Investigate every match. Real customer URLs, employee emails, or internal hostnames must be removed or replaced with generic examples (`example.com`, `me@example.com`).

### 1c. Trade secrets / proprietary business logic

Read the source file end-to-end and ask:

- Does it contain Autohive's *secret sauce* — e.g., proprietary scoring, internal pricing models, internal API contracts not visible to customers?
- Does it duplicate or reveal internal Autohive platform internals (Dash internals, customer routing logic, billing logic)?
- Is the integration logic itself a competitive moat we don't want to give away?

If yes to any of these, **abort and discuss**. A "wrapper around a public third-party API" is almost never a trade secret. Anything that talks to internal Autohive systems probably is.

### 1d. .env / credential files

```bash
find ../integrations/<name> -name '.env*' -o -name '*credentials*' -o -name '*secrets*' -o -name 'service-account*.json'
```

These should not exist in the source tree. If they do, abort and clean up before re-attempting.

### 1e. Run the GitHub secret scanner on the diff

Use the `mcp__github__run_secret_scanning` tool (or equivalent CLI) on every text file you intend to publish. Don't skip — this catches things grep won't.

### 1f. Icon and binary assets

- Confirm the icon is a clean PNG (no embedded EXIF/metadata leaking employee names).
- `file <name>/icon.png` — should report standard PNG with no comments.

### 1g. Document the review in the PR body

Use a table like the one in the Gmail migration PR (`Autohive-AI/autohive-integrations#322`). The reviewer should be able to see at a glance what was checked.

## Step 2 — Identify and drop legacy artifacts

The private repo accumulates files that don't belong in the public repo. Drop these before copying:

| File / pattern | Why drop it |
|---|---|
| `integration.py` (vendored old SDK) | Public repo uses `autohive-integrations-sdk` from PyPI. |
| `test_<name>_integration.py` (manual harness with `argparse --token`) | Replace with the public pytest pattern. |
| `dependencies/` directory | Build artefact — should never be in source. |
| `__pycache__/`, `.pytest_cache/`, `.ruff_cache/` | Build artefacts. |
| Internal-only documentation (`INTERNAL.md`, `RUNBOOK.md` referencing internal infra) | Keep in private repo or rewrite without internal references. |
| `.env*` files | Should not exist anywhere; if they do, abort Step 1. |

## Step 3 — Copy and adapt files

The public repo follows the standard SDK structure. Copy this minimal set:

```bash
mkdir -p ../autohive-integrations/<name>/tests
cp ../integrations/<name>/config.json    ../autohive-integrations/<name>/
cp ../integrations/<name>/<name>.py      ../autohive-integrations/<name>/
cp ../integrations/<name>/icon.png       ../autohive-integrations/<name>/
cp ../integrations/<name>/requirements.txt ../autohive-integrations/<name>/
touch ../autohive-integrations/<name>/__init__.py
touch ../autohive-integrations/<name>/tests/__init__.py
# Tests — copy if they're real pytest tests; otherwise create the placeholder structure
cp ../integrations/<name>/tests/context.py     ../autohive-integrations/<name>/tests/ 2>/dev/null
cp ../integrations/<name>/tests/test_*.py      ../autohive-integrations/<name>/tests/ 2>/dev/null
```

### Adaptations to make

- **`__init__.py`** → empty file (matches public repo convention).
- **`requirements.txt`** → keep the SDK version pin from the source as-is (the migration is a *move*, not an *upgrade*; bumping the SDK is a separate PR using the [upgrading-sdk-v2](../upgrading-sdk-v2/SKILL.md) skill).
- **`README.md`** → **rewrite** in the public repo style. Model it on a recent public README such as [`google-calendar/README.md`](https://github.com/Autohive-AI/autohive-integrations/blob/master/google-calendar/README.md). Sections:
  - `# <Name> Integration for Autohive`
  - `## Description` (what it does, key features)
  - `## Setup & Authentication` (auth type, scopes, fields)
  - `## Actions` (table or per-action breakdown)
  - `## Requirements` (from `requirements.txt`)
  - `## Usage Examples` (1–3 realistic JSON examples)
  - `## Testing`
- Strip any internal references (Slack channels, Notion links, employee names) from the README before copying.

### Update the repo-level READMEs

- **Public repo `README.md`** — add a new section for the integration, alphabetically near related ones.
- **Private repo `README.md`** — remove the integration's section and add it to a "Migrated to the Public Repo" list at the bottom so contributors know where the new home is.

## Step 4 — Local validation

From the public repo root, with the venv activated:

```bash
python ../autohive-integrations-tooling/scripts/validate_integration.py <name>
python ../autohive-integrations-tooling/scripts/check_code.py <name>
pytest <name>/ -v
```

Required outcome:

- `validate_integration.py` → `0` exit code (warnings about deprecated SDK pin are OK for a pure migration).
- `check_code.py` → `✅ CODE CHECK PASSED`.
- `pytest` → no failures (placeholder tests are fine; new tests are out of scope for a migration).

If anything fails, fix with:

```bash
ruff check --fix --config ../autohive-integrations-tooling/ruff.toml <name>
ruff format --config ../autohive-integrations-tooling/ruff.toml <name>
```

See the [building-integration](../building-integration/SKILL.md) skill for the full validation playbook.

## Step 5 — Coordinate three PRs

Open one GitHub issue and one branch per repo. Cross-reference the PRs in each PR body so reviewers can see the complete picture.

```diagram
╭───────────────────────╮     ╭─────────────────────────╮
│ private: integrations │     │ public: autohive-       │
│ chore/N/remove-<name> │ ──▶ │ integrations            │
│  • delete <name>/     │     │ feat/N/migrate-<name>-  │
│  • update README      │     │ from-private            │
╰───────────────────────╯     │  • add <name>/          │
                              │  • update README        │
                              ╰─────────────────────────╯
                              ╭─────────────────────────╮
                              │ integrations-sdk        │
                              │ (only if process changed│
                              │  → update this skill)   │
                              ╰─────────────────────────╯
```

### PR titles (Conventional Commits)

- Public repo: `feat(<name>): migrate <Name> integration from private repo`
- Private repo: `chore(<name>): remove integration after migration to public repo`
- SDK repo (if updating this skill): `docs(skills): refine migrating-private-integration skill`

### Branch names

- Public: `feat/<issue>/migrate-<name>-from-private`
- Private: `chore/<issue>/remove-<name>-migrated-to-public`
- SDK: `docs/<issue>/migrating-skill-update`

### What each PR body must contain

- A copy of the security/safety/secrets review table from Step 1.
- Links to the companion PRs in the other repos.
- The exact local validation output (validate + check_code).
- `Closes #<issue>` for the matching issue in that repo.

### Merge order

1. **Public PR first.** Publishing has to succeed before the private code is removed.
2. **Private PR second.** Once merged, the private location is gone and the README points to the new home.
3. **SDK PR last** (if any). Skill updates are independent and should land after the migration so they reflect what actually happened.

## Step 6 — Ask in the AH engineering Slack channel

> **You are required to do this. Do not skip.**

Before merging the public PR, post in the AH engineering Slack channel (`#engineering`, `#integrations`, or whichever the team uses for this kind of review):

> 👋 Migrating `<name>` from the private `integrations` repo to the public `autohive-integrations` repo. PR: <link>. Security/safety/secrets review is in the PR body. Could someone take a second look before I merge — particularly anything I might have missed under "internal references" or "trade secrets"? Thanks!

Wait for at least one explicit thumbs-up from another engineer before clicking merge. The review in the PR is mandatory but a second pair of eyes is what catches the things you missed because you wrote the PR.

If the response surfaces a concern, **fix it before merging**, even if it means closing the PR and starting over.

## Step 7 — Post-merge cleanup

After all PRs merge:

- Verify the integration appears in the public repo's `README.md`.
- Verify the private repo no longer lists it (and the "Migrated" section does).
- If any other repos (`autohive-blog`, `autohive-docs`, the platform repo) reference the old private path, open follow-up issues to update them.
- Close the GitHub issues if `Closes #N` didn't auto-close them.

## Common Failures and Fixes

| Failure | Fix |
|---|---|
| Secret scan finds a `# nosec` test token like `"your_access_token_here"` | Fine — these are placeholders, no action needed. |
| `validate_integration.py` warns about deprecated SDK | Acceptable for an as-is migration. Open a follow-up issue to upgrade with [upgrading-sdk-v2](../upgrading-sdk-v2/SKILL.md). |
| `check_code.py` reports config-code sync warnings | These are warnings (⚠️), not failures (❌). Fine to leave for a migration; the integration was already running in production with these. |
| Icon `file` reports embedded EXIF | Strip with `convert icon.png -strip icon.png` (ImageMagick) and re-commit. |
| README mentions internal Slack channel / employee | Rewrite the section before copying. |
| You discover a trade secret mid-migration | Stop. Close the public PR. Discuss in Slack. |

## Reference Migration

The Gmail migration is a complete worked example of this skill in action:

- Public PR: [Autohive-AI/autohive-integrations#323](https://github.com/Autohive-AI/autohive-integrations/pull/323)
- Private PR: [Autohive-AI/integrations#154](https://github.com/Autohive-AI/integrations/pull/154)
- SDK PR (this skill): [Autohive-AI/integrations-sdk#43](https://github.com/Autohive-AI/integrations-sdk/pull/43)
