"""Semantic versions. 1.10.0 is after 1.9.0. A pre-release is before its release."""

from __future__ import annotations

import re

_SEMVER = re.compile(
    r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)


def parse(text: str) -> tuple | None:
    if not isinstance(text, str):
        return None
    match = _SEMVER.fullmatch(text.strip())
    if match is None:
        return None
    major, minor, patch = (int(match.group(index)) for index in range(1, 4))
    pre_text = match.group(4)
    pre: tuple | None
    if pre_text is None:
        pre = None
    else:
        parts = []
        for item in pre_text.split("."):
            if not item:
                return None
            if item.isdigit():
                parts.append((0, int(item)))
            else:
                parts.append((1, item))
        pre = tuple(parts)
    return (major, minor, patch, pre)


def canonical(text: str) -> str | None:
    """Version without a leading v and without build metadata."""
    parsed = parse(text)
    if parsed is None:
        return None
    major, minor, patch, pre = parsed
    base = f"{major}.{minor}.{patch}"
    if pre is None:
        return base
    rendered = []
    for kind, value in pre:
        rendered.append(str(value))
    return base + "-" + ".".join(rendered)


def sort_key(text: str) -> tuple:
    major, minor, patch, pre = parse(text)  # type: ignore[misc]
    if pre is None:
        return (major, minor, patch, 1, ())
    return (major, minor, patch, 0, pre)


def compare(left: str, right: str) -> int | None:
    if parse(left) is None or parse(right) is None:
        return None
    a, b = sort_key(left), sort_key(right)
    if a < b:
        return -1
    if a > b:
        return 1
    return 0


def highest_stable(versions: list[str]) -> str | None:
    stable = [item for item in versions if parse(item) is not None and parse(item)[3] is None]  # type: ignore[index]
    if not stable:
        return None
    stable.sort(key=sort_key)
    return canonical(stable[-1])
