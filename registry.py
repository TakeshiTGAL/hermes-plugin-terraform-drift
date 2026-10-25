"""Public registry reads. The response's readme and docs are discarded."""

from __future__ import annotations

import json
import re
from typing import Callable

from .http_client import fetch
from .semver import canonical, compare, highest_stable, parse

_HEADING = re.compile(
    r"^#{1,3}\s+\[?v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\]?",
    re.MULTILINE,
)
_HIGHLIGHT = re.compile(r"\b(breaking|security|cve-\d+|vulnerability)\b", re.IGNORECASE)
_SECRET_LINE = re.compile(r"(access_key|secret_key|api[_-]?key|password)\s*=", re.IGNORECASE)
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)


def _https(host: str, path: str) -> str:
    return "https://" + host + path


def _json_object(payload: dict) -> dict | None:
    if not payload.get("ok"):
        return None
    try:
        body = json.loads(payload["text"])
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    if not isinstance(body, dict):
        return None
    return body


def provider_versions(namespace: str, name: str, transport: Callable) -> dict:
    url = _https("registry.terraform.io", f"/v1/providers/{namespace}/{name}/versions")
    payload = transport(url)
    if not payload.get("ok"):
        return payload
    body = _json_object(payload)
    if body is None:
        return {"ok": False, "error_type": "registry_body", "error": "The version list was not a JSON object.",
                "next_step": "Retry later. No latest version was chosen.", "latest": None}
    rows = body.get("versions")
    if not isinstance(rows, list):
        return {"ok": False, "error_type": "registry_body", "error": "The version list was missing.",
                "next_step": "Retry later. No latest version was chosen.", "latest": None}
    versions = []
    for row in rows:
        if isinstance(row, dict) and isinstance(row.get("version"), str):
            versions.append(row["version"])
        elif isinstance(row, str):
            versions.append(row)
    latest = highest_stable(versions)
    if latest is None:
        return {"ok": False, "error_type": "registry_body", "error": "The registry listed no stable version.",
                "next_step": "No pre-release was treated as the latest version.", "latest": None,
                "versions": [canonical(item) for item in versions if canonical(item)]}
    return {"ok": True, "latest": latest, "versions": versions}


def provider_source(namespace: str, name: str, transport: Callable) -> dict:
    url = _https("registry.terraform.io", f"/v1/providers/{namespace}/{name}")
    payload = transport(url)
    if not payload.get("ok"):
        return {"ok": False, "source": None, "status": payload.get("error_type")}
    body = _json_object(payload)
    if body is None:
        return {"ok": False, "source": None, "status": "registry_body"}
    source = body.get("source") if isinstance(body.get("source"), str) else None
    return {"ok": True, "source": source, "status": "ok"}


def module_versions(namespace: str, name: str, provider: str, transport: Callable) -> dict:
    url = _https("registry.terraform.io", f"/v1/modules/{namespace}/{name}/{provider}/versions")
    payload = transport(url)
    if not payload.get("ok"):
        return payload
    body = _json_object(payload)
    if body is None:
        return {"ok": False, "error_type": "registry_body", "error": "The module version list was not a JSON object.",
                "next_step": "Retry later. No latest version was chosen.", "latest": None}
    modules = body.get("modules")
    if not isinstance(modules, list) or not modules or not isinstance(modules[0], dict):
        return {"ok": False, "error_type": "registry_body", "error": "The module version list was missing.",
                "next_step": "Retry later. No latest version was chosen.", "latest": None}
    rows = modules[0].get("versions")
    if not isinstance(rows, list):
        return {"ok": False, "error_type": "registry_body", "error": "The module version list was missing.",
                "next_step": "Retry later. No latest version was chosen.", "latest": None}
    versions = [row["version"] for row in rows if isinstance(row, dict) and isinstance(row.get("version"), str)]
    latest = highest_stable(versions)
    if latest is None:
        return {"ok": False, "error_type": "registry_body", "error": "The registry listed no stable module version.",
                "next_step": "No pre-release was treated as the latest version.", "latest": None}
    return {"ok": True, "latest": latest, "versions": versions}


def module_source(namespace: str, name: str, provider: str, transport: Callable) -> dict:
    url = _https("registry.terraform.io", f"/v1/modules/{namespace}/{name}/{provider}")
    payload = transport(url)
    if not payload.get("ok"):
        return {"ok": False, "source": None, "status": payload.get("error_type")}
    body = _json_object(payload)
    if body is None:
        return {"ok": False, "source": None, "status": "registry_body"}
    source = body.get("source") if isinstance(body.get("source"), str) else None
    # The readme is intentionally dropped.
    return {"ok": True, "source": source, "status": "ok"}


def changelog_urls(source: str | None, version: str) -> list[str]:
    if not isinstance(source, str):
        return []
    prefix = "https://" + "github.com/"
    match = re.fullmatch(re.escape(prefix) + r"([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?", source.strip())
    if match is None:
        return []
    owner, repo = match.group(1), match.group(2)
    if owner.startswith(".") or repo.startswith(".") or ".." in owner or ".." in repo:
        return []
    number = canonical(version)
    if number is None:
        return []
    urls = []
    for tag in (f"v{number}", number):
        url = _https("raw.githubusercontent.com", f"/{owner}/{repo}/{tag}/CHANGELOG.md")
        from .hosts import reject_reason
        if reject_reason(url) is None:
            urls.append(url)
    return urls


def highlights_between(text: str, pin: str, latest: str, *, truncated: bool) -> dict:
    visible = _HTML_COMMENT.sub("", text)
    sections: list[tuple[str, str]] = []
    matches = list(_HEADING.finditer(visible))
    for index, match in enumerate(matches):
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(visible)
        number = canonical(match.group(1))
        if number is None:
            continue
        after_pin = compare(pin, number)
        up_to_latest = compare(number, latest)
        if after_pin is None or up_to_latest is None:
            continue
        if after_pin < 0 and up_to_latest <= 0:
            sections.append((number, visible[start:end]))
    lines: list[str] = []
    for _number, body in sections:
        for raw_line in body.splitlines():
            line = " ".join(raw_line.split())
            if not line or _SECRET_LINE.search(line):
                continue
            if not _HIGHLIGHT.search(line):
                continue
            cleaned = "".join(char for char in line if ord(char) >= 32 and ord(char) != 127)
            if cleaned:
                lines.append(cleaned[:180])
            if len(lines) >= 8:
                break
        if len(lines) >= 8:
            break
    return {
        "highlights": lines,
        "highlights_known": not truncated and len(lines) < 8,
        "changelog_status": "truncated" if truncated else "ok",
    }


def fetch_highlights(source: str | None, pin: str | None, latest: str | None, transport: Callable) -> dict:
    if pin is None or latest is None or compare(pin, latest) is None:
        return {"highlights": [], "highlights_known": False, "changelog_status": "skipped_no_pin"}
    if compare(pin, latest) >= 0:
        return {"highlights": [], "highlights_known": True, "changelog_status": "not_behind"}
    urls = changelog_urls(source, latest)
    if not urls:
        return {"highlights": [], "highlights_known": False, "changelog_status": "unavailable"}
    last = None
    for url in urls:
        payload = transport(url)
        last = payload
        if payload.get("ok"):
            text = payload.get("text") or ""
            truncated = payload.get("error_type") == "registry_truncated"
            return highlights_between(text, pin, latest, truncated=truncated)
        if payload.get("error_type") == "registry_not_found":
            continue
        status = payload.get("error_type") or "registry_down"
        if status == "registry_timeout":
            return {"highlights": [], "highlights_known": False, "changelog_status": "timeout"}
        return {"highlights": [], "highlights_known": False, "changelog_status": status}
    return {"highlights": [], "highlights_known": False, "changelog_status": "unavailable", "detail": (last or {}).get("error_type")}


def default_transport(url: str) -> dict:
    return fetch(url)
