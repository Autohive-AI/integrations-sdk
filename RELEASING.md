# Releasing the SDK

## Development and support branches

`master` tracks the next development version. When it has moved to a new
major version, use a support branch to release changes for the previous
major version without including incompatible development changes.

For example, `master` is on `3.0.0.dev0`, while `support/2.1.0` was created
from the `2.0.1` tag for the 2.1.0 release. This preserves the User-Agent
revert in 2.0.1; the 3.x development line retains the User-Agent change.

1. Create `support/<target-version>` from the appropriate published release
   tag, not from `master`. For a later maintenance release, start from the
   latest applicable release tag so earlier fixes are retained.
2. Open feature and fix PRs against that support branch. Keep changes
   compatible with the supported major version and use semantic versioning:
   additive APIs can require a minor release rather than a patch release.
3. Keep tests enabled for both `master` and `support/**` in the workflow's
   push and pull-request filters. Require successful tests before merging.
4. After the support changes are merged and verified, create
   `release/<target-version>` from the reviewed support tip. Build and tag
   the release from that line, not from `master`, using the checklist below.
5. Forward-port applicable fixes, features, tests, and workflow changes to
   `master` through a separate PR. Cherry-pick or reapply the selected changes;
   do not merge the whole support branch into `master`. Retain `master`'s
   development version and intentional behavior differences, update its
   release notes as appropriate, and regenerate API docs from its source.

Keep feature changes separate from release-version commits where practical
to make forward-porting easier. Keep support branches while maintenance is
needed; they do not need to be merged back when a release is finished.
Existing integration dependency pins must be checked separately: for example,
`~=2.0.0` and `~=2.0.1` do not select 2.1.0 automatically.

## Release checklist

* Use semantic versioning

* Create a release branch (`release/<a.b.c>`) from the reviewed source line:
  `master` for its release, or the support branch for a supported-version release.

* Update `pyproject.toml` as required:
    - Version 
    - Development Status
    - Authors
    - Dependencies

* Update `RELEASENOTES.md` with an entry for the new version.

* Run the test suite and ensure all tests pass:
    ```
    python -m pytest tests/ -v --cov=autohive_integrations_sdk --cov-report=term-missing
    ```

* Release to PyPi:
    - `build` is required (`python3 -m pip install --upgrade build`)
    - `twine` is required (`python3 -m pip install --upgrade twine`)

    Build:
    ```
    # Build from sdk main directory, this will create the package in dist/
    python3 -m build
    ```
    Typical output:
    ```
    * Creating venv isolated environment...
    * Installing packages in isolated environment... (hatchling)
    * Getting build dependencies for sdist...
    * Building sdist...
    * Building wheel from sdist
    * Creating venv isolated environment...
    * Installing packages in isolated environment... (hatchling)
    * Getting build dependencies for wheel...
    * Building wheel...
    Successfully built autohive_integrations_sdk-<a.b.c>.tar.gz and autohive_integrations_sdk-<a.b.c>-py3-none-any.whl
    ```
* Regenerate API docs:
    - `pdoc` is required (`python3 -m pip install --upgrade pdoc`)
    ```
    pdoc -o docs/apidocs src/autohive_integrations_sdk
    ```
    - Commit the updated `docs/apidocs/` files — these are tracked in version control.

* Release to PyPi — Upload:
    ```
    # Upload to PyPi, use API token from our secrets management
    python3 -m twine upload dist/autohive_integrations_sdk-<a.b.c>*
    ```
    Typical output:
    ```
    Uploading distributions to https://upload.pypi.org/legacy/
    Enter your API token: 
    Uploading autohive_integrations_sdk-<a.b.c>-py3-none-any.whl
    100% ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 15.3/15.3 kB • 00:00 • 140.2 MB/s
    Uploading autohive_integrations_sdk-<a.b.c>.tar.gz
    100% ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 96.5/96.5 kB • 00:00 • 293.3 MB/s

    View at:
    https://pypi.org/project/autohive-integrations-sdk/<a.b.c>/

    ```
