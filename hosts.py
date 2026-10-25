"""HTTPS allowlist. IP literals and other hosts are refused before a connection."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

ALLOWED = frozenset({"registry.terraform.io", "raw.githubusercontent.com"})
_NAME = r"[A-Za-z0-9](?:[A-Za-z0-9_-]{0,62})"
_TAG = r"v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?"
_PATHS = (
    re.compile(rf"^/v1/providers/{_NAME}/{_NAME}$"),
    re.compile(rf"^/v1/providers/{_NAME}/{_NAME}/versions$"),
    re.compile(rf"^/v1/modules/{_NAME}/{_NAME}/{_NAME}$"),
    re.compile(rf"^/v1/modules/{_NAME}/{_NAME}/{_NAME}/versions$"),
    re.compile(rf"^/{_NAME}/{_NAME}/{_TAG}/CHANGELOG\.md$"),
)


def reject_reason(url: str, *, allowed: frozenset[str] = ALLOWED, schemes: tuple[str, ...] = ("https",)) -> str | None:
    if not isinstance(url, str) or not url or len(url) > 500:
        return "url"
    if any(ord(char) < 32 or ord(char) == 127 for char in url):
        return "url"
    parts = urlsplit(url)
    if parts.scheme not in schemes:
        return "scheme"
    if parts.username or parts.password:
        return "userinfo"
    if parts.query or parts.fragment:
        return "query"
    host = parts.hostname
    if not host or host not in allowed:
        return "host"
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return "ip"
    path = parts.path or ""
    if host == "registry.terraform.io":
        patterns = _PATHS[:4]
    elif host == "raw.githubusercontent.com":
        patterns = _PATHS[4:]
    else:
        patterns = ()
    if not any(pattern.fullmatch(path) for pattern in patterns):
        return "path"
    return None
