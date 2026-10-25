"""Load the plugin directory as the terraform_drift package."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NAME = "terraform_drift"


def _load():
    if NAME in sys.modules and hasattr(sys.modules[NAME], "tools"):
        return sys.modules[NAME]
    spec = importlib.util.spec_from_file_location(
        NAME,
        ROOT / "__init__.py",
        submodule_search_locations=[str(ROOT)],
    )
    module = importlib.util.module_from_spec(spec)
    module.__package__ = NAME
    sys.modules[NAME] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


_load()
