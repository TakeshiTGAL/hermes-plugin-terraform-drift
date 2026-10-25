"""Tool handlers. They return JSON text and do not choose a destination."""

from __future__ import annotations

import json
from typing import Any, Callable

from .errors import BAD_ARGUMENT, INTERNAL, fail
from .report import compare_directory, digest
from .schemas import ALL_SCHEMAS

_bound: dict[str, Any] = {}


def bind(**kwargs: Any) -> None:
    _bound.clear()
    _bound.update(kwargs)


def reset() -> None:
    _bound.clear()


def _dump(payload: dict) -> str:
    return json.dumps(payload, ensure_ascii=False)


def _directory(args: dict) -> dict | None:
    if "directory" not in args:
        return fail(BAD_ARGUMENT, "directory is required.", "Pass the folder that holds the Terraform files.")
    if not isinstance(args["directory"], str):
        return fail(BAD_ARGUMENT, "directory must be a string.", "Pass the folder path as text.")
    return None


def _drift(args: dict) -> dict:
    rejected = _directory(args)
    if rejected:
        return rejected
    return compare_directory(args["directory"], transport=_bound.get("transport"), clock=_bound.get("clock"))


def _digest(args: dict) -> dict:
    rejected = _directory(args)
    if rejected:
        return rejected
    known = args.get("known")
    cadence = args.get("cadence")
    return digest(
        args["directory"],
        known,
        cadence,
        transport=_bound.get("transport"),
        clock=_bound.get("clock"),
    )


def _wrap(fn: Callable[[dict], dict]) -> Callable:
    def handler(args: dict | None = None, **kwargs: Any) -> str:
        payload = dict(args or {})
        if not payload and kwargs:
            payload = dict(kwargs)
        try:
            return _dump(fn(payload))
        except Exception as exc:  # noqa: BLE001 — typed failure, no traceback
            return _dump(fail(INTERNAL, type(exc).__name__, "Retry the read. No version was saved."))

    return handler


HANDLERS = {
    "terraform_drift": _wrap(_drift),
    "terraform_drift_digest": _wrap(_digest),
}


def names() -> list[str]:
    return [item["name"] for item in ALL_SCHEMAS]
