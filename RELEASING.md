# Releasing the SDK

##  Overview

* Create a release branch (`release/<a.b.c>`)
* Update `pyproject.toml` as required:
    - Version 
    - Development Status
    - Authors
    - Dependencies
* Release to PyPi:
    - `build` is required (`python3 -m pip install --upgrade build`)
    - `twine` is required (`python3 -m pip install --upgrade twine`)
    ```
    # Build from sdk main directory, this will create the package in dist/
    python3 -m build

    # Upload to PyPi, use API token from secrets management
    python3 -m twine upload --repository autohive-integrations-sdk dist/*