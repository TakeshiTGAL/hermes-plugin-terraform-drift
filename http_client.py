"""GET with proxies disabled and redirects refused. Response bodies stay out of errors."""

from __future__ import annotations

import socket
import urllib.error
import urllib.request
from typing import Callable

from .errors import (
    DESTINATION_REFUSED,
    REGISTRY_AUTH,
    REGISTRY_BODY,
    REGISTRY_DOWN,
    REGISTRY_HTTP,
    REGISTRY_NOT_FOUND,
    REGISTRY_RATE_LIMIT,
    REGISTRY_REDIRECT,
    REGISTRY_TIMEOUT,
    REGISTRY_TRUNCATED,
    fail,
)
from .hosts import ALLOWED, reject_reason

TIMEOUT = 8
MAX_BODY = 2_000_000


class RedirectError(Exception):
    def __init__(self, code: int):
        self.code = code
        super().__init__(f"redirect {code}")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise RedirectError(code)


def opener() -> urllib.request.OpenerDirector:
    # An empty proxy map does not read proxy variables from the environment.
    return urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({}))


def _fail_transport(error_type: str, error: str, next_step: str) -> dict:
    return fail(error_type, error, next_step)


def classify_transport(exc: BaseException) -> dict:
    if isinstance(exc, RedirectError):
        return _fail_transport(
            REGISTRY_REDIRECT,
            "The registry returned a redirect. It was not followed.",
            "Retry later. No version was read from the redirect target.",
        )
    if isinstance(exc, urllib.error.HTTPError):
        status = exc.code
        if status == 404:
            return _fail_transport(
                REGISTRY_NOT_FOUND,
                "HTTP 404.",
                "The public registry has no such provider or module. That is not a latest version.",
            )
        if status in (401, 403):
            return _fail_transport(
                REGISTRY_AUTH,
                f"HTTP {status}. This plugin does not send a key.",
                "Retry later. Do not add a key. No version was read.",
            )
        if status == 429:
            return _fail_transport(
                REGISTRY_RATE_LIMIT,
                "HTTP 429.",
                "The public registry is rate limiting. Retry later. No version was saved.",
            )
        return _fail_transport(
            REGISTRY_HTTP,
            f"HTTP {status}.",
            "The public registry returned an HTTP error. Retry later. No version was saved.",
        )
    if isinstance(exc, TimeoutError):
        return _fail_transport(
            REGISTRY_TIMEOUT,
            "The public registry timed out.",
            "Retry later. A timeout is not a latest version.",
        )
    if isinstance(exc, urllib.error.URLError):
        reason = str(getattr(exc, "reason", exc))
        if "Query timed out after" in reason or "timed out" in reason.lower():
            return _fail_transport(
                REGISTRY_TIMEOUT,
                "The public registry timed out.",
                "Retry later. A timeout is not a connection refusal and not a latest version.",
            )
        return _fail_transport(
            REGISTRY_DOWN,
            "The public registry did not connect.",
            "Retry later. No version was read.",
        )
    if isinstance(exc, socket.timeout):
        return _fail_transport(
            REGISTRY_TIMEOUT,
            "The public registry timed out.",
            "Retry later. A timeout is not a latest version.",
        )
    return _fail_transport(
        REGISTRY_DOWN,
        "The public registry did not connect.",
        "Retry later. No version was read.",
    )


def open_request(
    url: str,
    *,
    timeout: float = TIMEOUT,
    opener_factory: Callable[[], urllib.request.OpenerDirector] = opener,
) -> dict:
    """GET one URL. Callers that accept user paths must run reject_reason first."""
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/json, text/plain;q=0.9", "User-Agent": "hermes-terraform-drift"},
        method="GET",
    )
    try:
        with opener_factory().open(req, timeout=timeout) as response:
            raw = response.read(MAX_BODY + 1)
            status = getattr(response, "status", 200)
    except Exception as exc:  # noqa: BLE001 — mapped to a typed failure, traceback dropped
        return classify_transport(exc)
    if status >= 400:
        return classify_transport(urllib.error.HTTPError(url, status, "status", None, None))
    if len(raw) > MAX_BODY:
        return _fail_transport(
            REGISTRY_TRUNCATED,
            "The response was longer than the cap.",
            "Retry later. A truncated body is not a latest version.",
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        return _fail_transport(
            REGISTRY_BODY,
            "The response was not UTF-8.",
            "Retry later. No version was read from a broken body.",
        )
    return {"ok": True, "status": status, "text": text}


def fetch(
    url: str,
    *,
    timeout: float = TIMEOUT,
    allowed: frozenset[str] = ALLOWED,
    schemes: tuple[str, ...] = ("https",),
    opener_factory: Callable[[], urllib.request.OpenerDirector] = opener,
) -> dict:
    if reject_reason(url, allowed=allowed, schemes=schemes) is not None:
        return _fail_transport(
            DESTINATION_REFUSED,
            "That destination is not the public Terraform registry or its changelog host.",
            "No request was sent.",
        )
    return open_request(url, timeout=timeout, opener_factory=opener_factory)
