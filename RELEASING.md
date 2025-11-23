# Releasing the SDK

* Use semantic versioning

* Create a release branch (`release/<a.b.c>`)

* Update `pyproject.toml` as required:
    - Version 
    - Development Status
    - Authors
    - Dependencies

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
    Upload:
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