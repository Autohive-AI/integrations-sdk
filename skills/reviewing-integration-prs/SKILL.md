---
name: reviewing-integration-prs
description: "Reviews Autohive integration pull requests for code quality, security, tests, docs, and compliance with the integration skills. Use when asked to review an integration PR, validate work against skills, or assess integration changes before merge."
---

# Reviewing Integration PRs

Use this skill to perform a structured review of pull requests in `Autohive-AI/autohive-integrations` and related integration migration/upgrade PRs.

The goal is not just a generic code review. Validate the PR against the relevant integration skills, the tooling checks, and the security expectations for public integrations.

## Review Principles

- Review the actual diff and the surrounding integration code; do not rely only on CI status.
- Treat security and secret leakage as blockers.
- Treat failed tooling/validation as blockers unless there is a documented, intentional exception.
- Treat missing root `.env.example` entries as blockers when a PR adds or changes integration tests that read env vars.
- Use the existing skills as sub-skill checklists when their context applies.
- Prefer actionable review comments with file/line references and concrete fixes.
- Separate blockers from should-fix items and minor suggestions.

## Sub-skills to Apply

Apply these existing skills when the PR touches their area:

| Context in PR | Apply this skill/checklist |
|---|---|
| Any integration implementation, config, README, or tests changed | `building-integration` |
| Unit tests added or changed | `writing-unit-tests` |
| Integration tests added or changed | `writing-integration-tests` |
| `requirements.txt` changes SDK 1.x → 2.x, or fetch handling changes | `upgrading-sdk-v2` |
| Private → public migration, copied integration, public publishing | `migrating-private-integration` |

When reviewing, explicitly say which sub-skill contexts applied. Example: “Applied: building-integration, writing-integration-tests.”

## Review Workflow

### 1. Understand the PR scope

Identify:

- Changed integration directories.
- Whether this is a new integration, existing integration change, SDK upgrade, migration, test-only change, or docs-only change.
- Changed files: `config.json`, source `.py`, `requirements.txt`, `README.md`, `tests/`, icons, repo-level `README.md`, root `.env.example`.
- Whether the PR introduces or changes integration tests that need real credentials.

Useful commands when reviewing locally:

```bash
git diff --name-status origin/master...HEAD
python ../autohive-integrations-tooling/scripts/get_changed_dirs.py origin/master
```

### 2. Run or inspect tooling validation

For changed integration directories, verify the same checks CI runs:

```bash
DIRS=$(python ../autohive-integrations-tooling/scripts/get_changed_dirs.py origin/master)
python ../autohive-integrations-tooling/scripts/validate_integration.py $DIRS
python ../autohive-integrations-tooling/scripts/check_code.py --base-ref origin/master $DIRS
python ../autohive-integrations-tooling/scripts/run_tests.py $DIRS
python ../autohive-integrations-tooling/scripts/check_readme.py origin/master $DIRS
python ../autohive-integrations-tooling/scripts/check_version_bump.py origin/master $DIRS
```

If you cannot run these, inspect CI logs or state clearly that validation was not run.

Do not stop at “CI is green.” Still inspect the diff for security, auth, schema, test, and documentation quality.

### 3. General code quality and style

Check for:

- Clear action handler structure and idiomatic SDK usage.
- `config.json` action names matching `@integration.action("...")` decorators.
- Input schema matching code usage and required/optional behavior.
- Output schema matching successful action outputs.
- No broad, swallowed exceptions that hide real failures without returning `ActionError`.
- Good helper boundaries without unnecessary abstractions.
- No dead code, debug prints, temporary files, vendored dependencies, or generated artifacts.
- Ruff-compatible formatting and imports.

Common blockers:

- Source action exists but is missing from `config.json`, or vice versa.
- New integration has config/input drift.
- Required file missing: `config.json`, `requirements.txt`, `README.md`, icon, tests folder.
- SDK dependency missing or unpinned.
- Action output returns fields not described in `output_schema` for success cases.

### 4. Security and public-safety review

Check for:

- No real tokens, API keys, passwords, refresh tokens, JWTs, private keys, service-account JSON, or bearer tokens.
- No committed `.env`, `.env.*`, credential files, secret dumps, local config, or screenshots with secrets.
- No customer data, employee names/emails, internal Autohive hostnames, staging URLs, Slack/Notion/internal links, or private repo references.
- No hardcoded test resource IDs that expose real customer data; prefer env vars for live integration tests.
- No unsafe calls such as `eval`, `exec`, shelling out with user input, insecure temp files, or unbounded file/network operations.
- Auth handling returns user-facing `ActionError` where possible instead of leaking low-level exceptions.
- OAuth scopes are minimal for the implemented actions.

For migrations to public, apply the `migrating-private-integration` security/safety/secrets checklist. Security review should be explicit in the PR body.

### 4.1 Custom auth contract review

For integrations using `auth.type == "custom"`, verify the config, code, and tests match the Autohive runtime contract:

- `auth.fields` describes the same auth object shape the SDK/platform passes to `context.auth` at execution time. Do not assume flat or wrapped credentials without checking the current SDK/platform contract.
- If `auth.fields.required` is present, it matches that runtime auth shape and covers credentials that must be present before handlers run. Non-empty `required` arrays are valid when they match the SDK/platform contract.
- `auth.fields.properties` declares every credential field that action code reads from `context.auth`, including nested credential fields if the runtime contract is wrapped.
- Action code does not read undeclared credential keys from `context.auth`.
- At least one unit test exercises `integration.execute_action(...)` with the expected SDK/platform auth shape, rather than only testing helper functions or using a convenient mock shape.
- Tests cover missing required credentials when the config uses `auth.fields.required`, so credential validation is not accidentally bypassed.
- Live integration tests, if present, are not treated as CI coverage unless the CI logs explicitly show they were run.

Ask explicitly during review: **Does this PR test the same SDK/platform contract that production will use?**

### 5. Tests and `.env.example`

The root `.env.example` check is mandatory for any PR that adds or changes `test_*_integration.py`. Do not rely on CI to catch this; review it manually against the test file.

For unit tests, apply `writing-unit-tests`:

- Tests are named `test_*_unit.py`.
- They use `mock_context`, `make_context`, and `FetchResponse` correctly for SDK 2.x.
- They cover happy paths, request shape, validation/error paths, edge cases, and response shape where applicable.
- Test credential strings use placeholders and `# nosec B105` where needed.

For integration tests, apply `writing-integration-tests`:

- Tests are named `test_*_integration.py` and marked `pytest.mark.integration`.
- Destructive tests are marked `pytest.mark.destructive` and clean up data where possible.
- `live_context` returns `FetchResponse` for SDK 2.x `context.fetch` paths.
- Tests skip cleanly when credentials or required test IDs are missing.
- Every env var read by `env_credentials(...)`, `os.environ.get(...)`, `os.getenv(...)`, `os.environ[...]`, or equivalent helpers is listed as a blank template entry in root `.env.example`.
- Optional test IDs, destructive-test-only variables, and module-level env constants count; either document them in root `.env.example` or remove unused reads.

Use a focused search while reviewing:

```bash
grep -RInE 'env_credentials\(|os\.environ|getenv\(' <integration>/tests/test_*_integration.py
grep -nE 'INTEGRATION_PREFIX|SERVICE_PREFIX' .env.example
```

Missing `.env.example` entries are blockers when the PR adds or changes integration tests that read env vars. If the PR only exposes a pre-existing omission outside the changed tests, call it a should-fix unless it blocks the changed behavior.

### 6. SDK v2 upgrade review

If the PR upgrades an integration to SDK 2.x or changes fetch handling, apply `upgrading-sdk-v2`:

- `requirements.txt` pins `autohive-integrations-sdk~=2.0.0`.
- `context.fetch()` results access `.data` for response body.
- Unit/integration test fetch mocks return `FetchResponse`.
- Error paths return `ActionError(message=...)` instead of success-shaped error data.
- Error-only `error` / `result` fields are removed from success output schemas where applicable.
- `config.json` version bump is appropriate for an existing integration upgrade.
- Integration-test env vars remain documented in root `.env.example` if tests are touched.

### 7. Documentation and metadata

Check:

- Integration `README.md` explains setup/auth, actions, requirements, usage examples, and testing notes.
- Repo-level `README.md` is updated for new integrations.
- `config.json` has clear descriptions, `display_name`, input/output schemas, auth config, and version.
- New or changed integration tests document local run commands in the PR or README when helpful.
- Icons are present and valid; no binary metadata concerns for public migrations.

## Finding Severity

Use these categories:

- **🚫 Blocker** — must fix before merge. Security leaks, broken validation, schema/action mismatch, new integration input drift, missing required files, broken imports/tests, unsafe public migration, or missing root `.env.example` entries for env vars read by newly added/changed integration tests.
- **⚠️ Should-fix** — strongly recommended before merge. Pre-existing `.env.example` omissions not introduced by the PR, incomplete test coverage for changed behavior, unclear docs, overly broad error handling, avoidable warnings.
- **💡 Suggestion** — optional improvements. Naming clarity, small refactors, additional examples, extra edge-case tests.

## Review Output Template

```markdown
## Integration PR review

Applied sub-skills: building-integration, writing-unit-tests, writing-integration-tests

### 🚫 Blockers
- [file:line] Issue and why it blocks merge. Suggested fix.

### ⚠️ Should-fix
- [file:line] Issue and recommended fix.

### 💡 Suggestions
- [file:line] Optional improvement.

### Validation
- Tooling run: `validate_integration.py ...` / `check_code.py ...` / `run_tests.py ...`
- Tests run or inspected:
- Not run:
```

If there are no findings in a category, say “None.” Do not invent issues just to fill the template.

## Final Checklist

Before completing the review, verify:

- [ ] Relevant sub-skills were applied based on PR scope.
- [ ] Security/secrets/public-safety review was performed.
- [ ] Tooling/CI status was checked or local validation was run.
- [ ] Config/code/schema sync was inspected.
- [ ] Unit/integration test changes were reviewed against the appropriate test skill.
- [ ] Root `.env.example` was checked when integration tests reference env vars; missing entries introduced by the PR were treated as blockers.
- [ ] Findings are actionable and severity-labelled.
