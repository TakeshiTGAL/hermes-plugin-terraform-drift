"""Failure values. One type per cause. A failure is not a latest version."""

from __future__ import annotations

BAD_ARGUMENT = "bad_argument"
PATH_ESCAPE = "path_escape"
PATH_SYMLINK = "path_symlink"
PATH_MISSING = "path_missing"
PATH_NOT_DIRECTORY = "path_not_directory"
REGISTRY_DOWN = "registry_down"
REGISTRY_TIMEOUT = "registry_timeout"
REGISTRY_AUTH = "registry_auth"
REGISTRY_RATE_LIMIT = "registry_rate_limit"
REGISTRY_HTTP = "registry_http"
REGISTRY_NOT_FOUND = "registry_not_found"
REGISTRY_BODY = "registry_body"
REGISTRY_TRUNCATED = "registry_truncated"
REGISTRY_REDIRECT = "registry_redirect"
DESTINATION_REFUSED = "destination_refused"
INTERNAL = "internal"


def fail(error_type: str, error: str, next_step: str, **extra: object) -> dict:
    body = {
        "ok": False,
        "error_type": error_type,
        "error": error,
        "next_step": next_step,
        "latest": None,
    }
    body.update(extra)
    return body
