"""Compare pins with the public registry and build the text a person may deliver."""

from __future__ import annotations

import re
import time
from typing import Callable

from .errors import (
    BAD_ARGUMENT,
    PATH_ESCAPE,
    PATH_SYMLINK,
    PATH_MISSING,
    PATH_NOT_DIRECTORY,
    fail,
)
from .registry import (
    default_transport,
    fetch_highlights,
    module_source,
    module_versions,
    provider_source,
    provider_versions,
)
from .scan import collect, exact_version, module_id, provider_id
from .semver import canonical, compare

MAX_COMPONENTS = 30
_SAFE_CONSTRAINT = re.compile(r"^[A-Za-z0-9. <>=~,_-]{1,80}$")
_ID = re.compile(
    r"^registry\.terraform\.io/[A-Za-z0-9](?:[A-Za-z0-9_-]{0,62})"
    r"/[A-Za-z0-9](?:[A-Za-z0-9_-]{0,62})"
    r"(?:/[A-Za-z0-9](?:[A-Za-z0-9_-]{0,62}))?$"
)
_PATH_ERRORS = {
    "bad_argument": (
        BAD_ARGUMENT,
        "The directory is missing or not a plain path.",
        "Pass the directory that holds the .tf files.",
    ),
    "path_escape": (
        PATH_ESCAPE,
        "The directory path contains .. .",
        "Pass a path that stays inside the folder you mean.",
    ),
    "path_symlink": (
        PATH_SYMLINK,
        "The directory path contains a symlink.",
        "Pass the real directory. Nothing was read.",
    ),
    "path_missing": (
        PATH_MISSING,
        "That directory does not exist.",
        "Pass a directory that exists. Nothing was read.",
    ),
    "path_not_directory": (
        PATH_NOT_DIRECTORY,
        "That path is not a directory.",
        "Pass a directory. Nothing was read.",
    ),
}


def _clock_stamp(clock: Callable[[], float]) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(clock()))


def _constraint(text: str | None, literal: bool) -> str | None:
    if not literal or not isinstance(text, str):
        return None
    cleaned = " ".join(text.split())
    if _SAFE_CONSTRAINT.fullmatch(cleaned):
        return cleaned
    return None


def _private_host(value: str | None) -> bool:
    if not isinstance(value, str) or not value or value.startswith("./") or value.startswith("../"):
        return False
    host = value.split("//", 1)[0].split("/")[0]
    return "." in host and host != "registry.terraform.io"


def _remember_private(rows: dict[str, dict], kind_name: str, file_name: str | None) -> None:
    identity = f"private-{kind_name}"
    if file_name:
        identity = f"{identity}-{file_name}"
    if not _ID.fullmatch("registry.terraform.io/local/private") and not re.fullmatch(r"[A-Za-z0-9._/-]{1,220}", identity):
        identity = f"private-{kind_name}"
    row = _blank(kind_name, identity)
    row["relation"] = "private"
    row["registry_status"] = "not_called"
    row["file"] = file_name
    rows[identity] = row


def _blank(kind: str, identity: str) -> dict:
    return {
        "kind": kind,
        "id": identity,
        "pin": None,
        "constraint": None,
        "latest": None,
        "relation": None,
        "registry_status": "not_called",
        "changelog_status": "not_called",
        "highlights": [],
        "highlights_known": False,
        "file": None,
    }


def _merge(collected: dict) -> list[dict]:
    rows: dict[str, dict] = {}
    for item in collected["providers"]:
        if item["kind"] == "provider_requirement":
            identity = provider_id(item.get("source"), bool(item.get("source_literal")))
            if identity is None:
                if _private_host(item.get("source")):
                    _remember_private(rows, "provider", item.get("file"))
                continue
            row = rows.setdefault(identity, _blank("provider", identity))
            row["constraint"] = _constraint(item.get("version"), bool(item.get("version_literal"))) or row["constraint"]
            pin = exact_version(item.get("version"), bool(item.get("version_literal")))
            if pin and row["pin"] is None:
                row["pin"] = pin
                row["pin_from"] = "requirement"
            elif pin and row.get("pin_from") == "requirement" and row["pin"] != pin:
                row["pin_conflict"] = True
            if item.get("file") and row["file"] is None:
                row["file"] = item["file"]
            continue
        if item["kind"] == "lock_provider":
            identity = provider_id(item.get("address"), item.get("address") is not None)
            if identity is None:
                if _private_host(item.get("address")):
                    _remember_private(rows, "provider", item.get("file"))
                continue
            row = rows.setdefault(identity, _blank("provider", identity))
            pin = exact_version(item.get("version"), bool(item.get("version_literal")))
            if pin:
                if row.get("pin_from") == "lock" and row["pin"] not in {None, pin}:
                    row["pin_conflict"] = True
                else:
                    row["pin"] = pin
                    row["pin_from"] = "lock"
            row["constraint"] = row["constraint"] or _constraint(item.get("constraints"), bool(item.get("constraints_literal")))
            if item.get("file") and row["file"] is None:
                row["file"] = item["file"]
    for item in collected["modules"]:
        identity, kind = module_id(item.get("source"), bool(item.get("source_literal")))
        if kind == "registry" and identity:
            row = rows.setdefault(identity, _blank("module", identity))
            pin = exact_version(item.get("version"), bool(item.get("version_literal")))
            if pin:
                if row["pin"] not in {None, pin}:
                    row["pin_conflict"] = True
                else:
                    row["pin"] = pin
            if item.get("file") and row["file"] is None:
                row["file"] = item["file"]
            continue
        key = f"{kind}:{item.get('file')}:{item.get('label') or ''}"
        if not re.fullmatch(r"[A-Za-z0-9._:/-]{1,220}", key):
            key = kind
        row = _blank("module", key)
        row["relation"] = kind
        row["registry_status"] = "not_called"
        if item.get("file"):
            row["file"] = item["file"]
        rows[key] = row
    ordered = sorted(rows.values(), key=lambda row: row["id"])
    return ordered


def _relation(pin: str | None, latest: str | None, conflict: bool) -> str:
    if conflict:
        return "pin_conflict"
    if latest is None:
        return "registry_unknown"
    if pin is None:
        return "pin_unknown"
    compared = compare(pin, latest)
    if compared is None:
        return "pin_unknown"
    if compared < 0:
        return "behind"
    if compared > 0:
        return "ahead"
    return "same"


def _fill(row: dict, transport: Callable) -> None:
    if row["relation"] in {"local", "private", "other"}:
        return
    parts = row["id"].split("/")
    if row["kind"] == "provider" and len(parts) == 3:
        versions = provider_versions(parts[1], parts[2], transport)
        source_info = provider_source(parts[1], parts[2], transport) if versions.get("ok") else {"source": None}
    elif row["kind"] == "module" and len(parts) == 4:
        versions = module_versions(parts[1], parts[2], parts[3], transport)
        source_info = module_source(parts[1], parts[2], parts[3], transport) if versions.get("ok") else {"source": None}
    else:
        row["relation"] = "other"
        return
    if not versions.get("ok"):
        row["registry_status"] = versions.get("error_type") or "registry_down"
        row["latest"] = None
        row["relation"] = "registry_unknown"
        row["registry_error"] = versions.get("error")
        row["registry_next"] = versions.get("next_step")
        return
    row["registry_status"] = "ok"
    row["latest"] = versions["latest"]
    conflict = bool(row.get("pin_conflict"))
    row["relation"] = _relation(row["pin"], row["latest"], conflict)
    notes = fetch_highlights(source_info.get("source"), row["pin"], row["latest"], transport)
    row["changelog_status"] = notes["changelog_status"]
    row["highlights"] = notes["highlights"]
    row["highlights_known"] = notes["highlights_known"]


def _summary(rows: list[dict], complete: bool) -> str:
    if not complete:
        return "The scan did not cover every file or component. The comparison stays unknown."
    registry_rows = [row for row in rows if row["registry_status"] != "not_called"]
    if any(row["registry_status"] != "ok" for row in registry_rows):
        return "A registry read failed. The comparison stays unknown."
    if any(row["relation"] in {"pin_unknown", "pin_conflict"} for row in registry_rows):
        return "An exact pin was missing. The comparison stays unknown."
    if any(row["relation"] == "behind" for row in registry_rows):
        return "At least one exact pin is behind the highest stable registry version."
    if not registry_rows:
        return "No public registry provider or module pin was found."
    return "Every exact public-registry pin matches the highest stable registry version."


def _public(row: dict) -> dict:
    return {
        "kind": row["kind"],
        "id": row["id"],
        "pin": row["pin"],
        "constraint": row["constraint"],
        "latest": row["latest"],
        "relation": row["relation"],
        "registry_status": row["registry_status"],
        "changelog_status": row["changelog_status"],
        "highlights": row["highlights"],
        "highlights_known": row["highlights_known"],
        "file": row["file"],
        "registry_error": row.get("registry_error"),
        "registry_next": row.get("registry_next"),
    }


def compare_directory(directory: str, *, transport: Callable | None = None, clock: Callable[[], float] | None = None) -> dict:
    collected = collect(directory)
    if collected["error"]:
        error_type, error, next_step = _PATH_ERRORS[collected["error"]]
        return fail(error_type, error, next_step)
    transport = transport or default_transport
    clock = clock or time.time
    rows = _merge(collected)
    registry_indexes = [index for index, row in enumerate(rows) if row["relation"] not in {"local", "private", "other"}]
    complete = bool(collected["complete_files"])
    if len(registry_indexes) > MAX_COMPONENTS:
        complete = False
        for index in registry_indexes[MAX_COMPONENTS:]:
            rows[index]["registry_status"] = "not_called"
            rows[index]["relation"] = "not_queried"
    for index in registry_indexes[:MAX_COMPONENTS]:
        _fill(rows[index], transport)
    public = [_public(row) for row in rows]
    registry_rows = [row for row in public if row["registry_status"] == "ok" and row["pin"] and row["relation"] in {"behind", "same", "ahead"}]
    comparable = [row for row in public if row["registry_status"] != "not_called" and row["relation"] != "not_queried"]
    behind_count = None
    if complete and comparable and all(row["registry_status"] == "ok" and row["pin"] and row["relation"] in {"behind", "same", "ahead"} for row in comparable):
        behind_count = sum(1 for row in registry_rows if row["relation"] == "behind")
    return {
        "ok": True,
        "complete_scan": complete,
        "scanned_files": collected["scanned_files"],
        "skipped": collected["skipped"],
        "observed_at": _clock_stamp(clock),
        "behind_count": behind_count,
        "summary": _summary(public, complete),
        "components": public,
    }


def _line(row: dict) -> str:
    pin = row["pin"] or "pin unknown"
    if row["latest"] is None:
        latest = "registry version unknown"
    else:
        latest = row["latest"]
    text = f"{row['kind']} {row['id']} pin {pin} registry {latest} relation {row['relation']}"
    if row["relation"] == "behind" and row["highlights_known"] and not row["highlights"]:
        text += ". No breaking or security line was visible in the fetched changelog sections."
    elif row["relation"] == "behind" and not row["highlights_known"]:
        text += ". Changelog notes are unknown."
    for note in row["highlights"]:
        text += f" | {note}"
    return text


def digest(directory: str, known: dict | None = None, cadence: str | None = None, *, transport: Callable | None = None, clock: Callable[[], float] | None = None) -> dict:
    if cadence is None:
        cadence = "daily"
    if not isinstance(cadence, str) or cadence not in {"daily", "weekly"}:
        return fail(BAD_ARGUMENT, "cadence must be daily or weekly.", "Pass daily or weekly. Nothing was scheduled.")
    if known is not None and not isinstance(known, dict):
        return fail(BAD_ARGUMENT, "known must be a map of registry id to version.", "Omit known, or pass the previous seen map.")
    if isinstance(known, dict) and len(known) > MAX_COMPONENTS:
        return fail(BAD_ARGUMENT, "known has too many ids.", "Pass at most 30 ids from the previous seen map.")
    report = compare_directory(directory, transport=transport, clock=clock)
    if not report.get("ok"):
        return report
    baseline = "missing" if known is None else "present"
    seen = {}
    new_rows = []
    unknown_rows = []
    for row in report["components"]:
        if row["registry_status"] == "ok" and isinstance(row["latest"], str):
            seen[row["id"]] = row["latest"]
        if row["registry_status"] not in {"ok", "not_called"}:
            unknown_rows.append(row)
            continue
        if known is None or row["registry_status"] != "ok" or not row["latest"]:
            continue
        previous = known.get(row["id"]) if isinstance(known, dict) else None
        if not isinstance(previous, str) or canonical(previous) is None:
            if previous is not None:
                unknown_rows.append(row)
            elif compare("0.0.0", row["latest"]) is not None:
                new_rows.append(row)
            continue
        compared = compare(canonical(previous), row["latest"])
        if compared is not None and compared < 0:
            new_rows.append(row)
    only_new = known is not None
    lines = [
        "Terraform registry comparison.",
        "This text is not sent to a destination.",
        f"Cadence label: {cadence}.",
    ]
    if not only_new:
        lines.append("Baseline: missing. These rows are not claimed to be new today.")
        shown = [row for row in report["components"] if row["relation"] in {"behind", "registry_unknown", "pin_unknown", "pin_conflict"} or row["registry_status"] not in {"ok", "not_called"}]
        if report["complete_scan"] and report["behind_count"] == 0 and not shown:
            lines.append("Every exact public-registry pin matches the highest stable registry version.")
        else:
            for row in shown:
                lines.append(_line(row))
            if not shown and not report["complete_scan"]:
                lines.append(report["summary"])
    else:
        lines.append("Baseline: present. Rows below are newer than the seen map, or the registry did not answer.")
        if not new_rows and not unknown_rows and report["complete_scan"]:
            lines.append("No registry version is newer than the seen map.")
        elif not new_rows and not unknown_rows:
            lines.append("The scan was incomplete. Newer versions stay unknown.")
        else:
            for row in new_rows:
                lines.append(_line(row))
            for row in unknown_rows:
                lines.append(_line(row))
            if unknown_rows:
                lines.append("A registry read failed. Newer versions stay unknown.")
    message = "\n".join(lines)
    return {
        "ok": True,
        "only_new": only_new,
        "baseline": baseline,
        "cadence": cadence,
        "observed_at": report["observed_at"],
        "complete_scan": report["complete_scan"],
        "summary": report["summary"],
        "message": message,
        "seen": seen,
        "new_ids": [row["id"] for row in new_rows],
        "unknown_ids": [row["id"] for row in unknown_rows],
        "components": report["components"],
    }
