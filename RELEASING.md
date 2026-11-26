# Releasing the SDK

## Development and support branches

`master` tracks the next development version. When it has moved to a new
major version, use a support branch to release changes for the previous
major version without including incompatible development changes.

For example, `master` is on `3.0.0.dev0`, while `release/2.1.0` was created
from the `2.0.1` tag for the 2.1.0 release. This preserves the User-Agent
revert in 2.0.1; the 3.x development line retains the User-Agent change.

1. Create `release/<target-version>` from the appropriate published release
   tag, not from `master`. For a later maintenance release, start from the
   latest applicable release tag so earlier fixes are retained.
2. Open feature and fix PRs against that release branch. Keep changes
   compatible with the supported major version and use semantic versioning:
   additive APIs can require a minor release rather than a patch release.
3. Keep tests enabled for `master`, `release/**`, and any `support/**` branches in the workflow's
   push and pull-request filters. Require successful tests before merging.
4. After the changes are merged and verified on `release/<target-version>`, build and tag
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

* Create or use the release branch (`release/<a.b.c>`): start from `master`
  for its release, or the appropriate published tag for a supported-version
  release as described above.

* Update `pyproject.toml` as required:
    - Version (also update the exported `__version__` in `src/autohive_integrations_sdk/__init__.py`)
    - Development Status
    - Authors
    - Dependencies

* Update `RELEASENOTES.md` with an entry for the new version.

* In a Python 3.13+ virtual environment on the intended release branch, install test and release tools, then run the tests:
    ```bash
    python -m pip install -e ".[test]" build twine pdoc
    python -m pytest tests/ -v --cov=autohive_integrations_sdk --cov-report=term-missing
    ```

* Regenerate API docs from that branch's source **before the final build or release tag**:
    ```bash
    pdoc -o docs/apidocs src/autohive_integrations_sdk
    ```
    Review and commit the updated `docs/apidocs/` files alongside the version and API changes. These files are tracked. Do not generate support-release docs from development `master` or hand-edit generated HTML to correct source docstrings.

* Check that the manifest version, exported `__version__`, release notes, and intended tag agree. Build from the reviewed release commit with a clean tracked worktree. Existing integration pins and sample compatibility checks are separate from the SDK's own suite; documentation aimed at released 2.1.0 should also pass the [released-sample tests](README.md#testing-the-samples-against-sdk-210).

* Build and check the distributions. The commands below read the version from `pyproject.toml`; use a new, empty version-specific output directory so stale distributions cannot be uploaded accidentally:

    ```bash
    VERSION=$(python -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')
    python -m build --outdir "dist/$VERSION"
    python -m twine check "dist/$VERSION/"*
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
* Install the built wheel in a separate Python 3.13+ virtual environment without an editable SDK checkout. Verify that the installed package metadata and exported `__version__` match the intended release, then rerun the SDK tests with test dependencies installed. This checks the distribution, not just imports from source.

* With release approval, tag the tested commit and upload only the checked distributions. Use the PyPI API token from secrets management:
    ```bash
    python -m twine upload "dist/$VERSION/"*
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

* Verify the published package version and tag commit after upload. Keep the release commit, tag, and built wheel provenance together; do not publish a 2.x maintenance release from the 3.x development line.
