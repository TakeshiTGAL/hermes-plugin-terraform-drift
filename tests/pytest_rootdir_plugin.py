"""Keep pytest from importing the repo root as a standalone module."""

from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.hookimpl(tryfirst=True)
def pytest_collect_directory(path, parent):
    if Path(path).resolve() == _REPO_ROOT:
        return pytest.Dir.from_parent(parent, path=Path(path))
    return None
