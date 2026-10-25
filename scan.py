"""Read .tf, .tf.json, and .terraform.lock.hcl inside one directory. Symlinks and .. stay out."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

MAX_FILES = 200
MAX_FILE_BYTES = 1_000_000
SKIP_DIRS = {".git", ".terraform", ".terraform.d"}
_PART = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_-]{0,62})$")
_EXACT = re.compile(r"^(?:=\s*)?v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$")
# macOS aliases. Refusing every ancestor symlink would reject a normal folder under /tmp.
_MACOS_ALIAS = {
    "/tmp": frozenset({"private/tmp", "/private/tmp"}),
    "/var": frozenset({"private/var", "/private/var"}),
}


def _tokenize(text: str) -> tuple[list[tuple], str | None]:
    tokens: list[tuple] = []
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if char in " \t\r\n":
            index += 1
            continue
        if char == "#":
            index = text.find("\n", index)
            if index < 0:
                break
            continue
        if char == "/" and index + 1 < length and text[index + 1] == "/":
            index = text.find("\n", index)
            if index < 0:
                break
            continue
        if char == "/" and index + 1 < length and text[index + 1] == "*":
            end = text.find("*/", index + 2)
            if end < 0:
                return [], "unclosed_comment"
            index = end + 2
            continue
        if text.startswith("<<", index):
            index, error = _skip_heredoc(text, index)
            if error:
                return [], error
            continue
        if char == '"':
            value, literal, index, error = _read_string(text, index)
            if error:
                return [], error
            tokens.append(("str", value, literal))
            continue
        if char in "{}":
            tokens.append((char,))
            index += 1
            continue
        if char == "=":
            tokens.append(("=",))
            index += 1
            continue
        if char.isascii() and (char.isalpha() or char == "_"):
            start = index
            index += 1
            while index < length and text[index].isascii() and (text[index].isalnum() or text[index] == "_"):
                index += 1
            tokens.append(("ident", text[start:index]))
            continue
        index += 1
    return tokens, None


def _read_string(text: str, index: int) -> tuple[str, bool, int, str | None]:
    index += 1
    chars: list[str] = []
    literal = True
    length = len(text)
    while index < length:
        char = text[index]
        if char == "\\":
            if index + 1 >= length:
                return "", False, index, "unclosed_string"
            literal = False
            chars.append(text[index + 1])
            index += 2
            continue
        if char == '"':
            return "".join(chars), literal, index + 1, None
        if char == "$" and index + 1 < length and text[index + 1] in "{%":
            literal = False
        if ord(char) < 32 or ord(char) == 127:
            literal = False
        chars.append(char)
        index += 1
    return "", False, index, "unclosed_string"


def _skip_heredoc(text: str, index: int) -> tuple[int, str | None]:
    index += 2
    if index < len(text) and text[index] == "-":
        index += 1
    start = index
    while index < len(text) and text[index].isascii() and (text[index].isalnum() or text[index] == "_"):
        index += 1
    word = text[start:index]
    if not word:
        return index, "bad_heredoc"
    end = text.find("\n" + word, index)
    if end < 0:
        return index, "unclosed_heredoc"
    line_end = text.find("\n", end + len(word) + 1)
    return len(text) if line_end < 0 else line_end, None


def _skip_brace(tokens: list[tuple], index: int) -> int:
    depth = 1
    while index < len(tokens) and depth:
        kind = tokens[index][0]
        if kind == "{":
            depth += 1
        elif kind == "}":
            depth -= 1
        index += 1
    return index


def _block_fields(tokens: list[tuple], index: int, keys: frozenset[str]) -> tuple[dict, int]:
    found = {key: None for key in keys}
    literal = {key: True for key in keys}
    while index < len(tokens) and tokens[index][0] != "}":
        token = tokens[index]
        if token[0] == "ident" and index + 1 < len(tokens) and tokens[index + 1][0] == "=":
            key = token[1]
            index += 2
            if index < len(tokens) and tokens[index][0] == "{":
                index = _skip_brace(tokens, index + 1)
                continue
            if index < len(tokens) and tokens[index][0] == "str":
                if key in keys:
                    found[key] = tokens[index][1]
                    literal[key] = tokens[index][2]
                index += 1
                continue
            if index < len(tokens):
                index += 1
            continue
        if token[0] == "{":
            index = _skip_brace(tokens, index + 1)
            continue
        index += 1
    if index < len(tokens) and tokens[index][0] == "}":
        index += 1
    found["literal"] = literal
    return found, index


def _balanced(tokens: list[tuple]) -> bool:
    depth = 0
    for token in tokens:
        if token[0] == "{":
            depth += 1
        elif token[0] == "}":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


def parse_tf(text: str) -> tuple[list[dict], str | None]:
    tokens, error = _tokenize(text)
    if error:
        return [], error
    if not _balanced(tokens):
        return [], "unbalanced"
    found: list[dict] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if (
            token[0] == "ident"
            and token[1] == "module"
            and index + 2 < len(tokens)
            and tokens[index + 1][0] == "str"
            and tokens[index + 2][0] == "{"
        ):
            label, label_literal = tokens[index + 1][1], tokens[index + 1][2]
            fields, index = _block_fields(tokens, index + 3, frozenset({"source", "version"}))
            found.append({
                "kind": "module",
                "label": label if label_literal else None,
                "source": fields["source"],
                "source_literal": fields["literal"]["source"],
                "version": fields["version"],
                "version_literal": fields["literal"]["version"],
            })
            continue
        if token[0] == "ident" and token[1] == "required_providers" and index + 1 < len(tokens) and tokens[index + 1][0] == "{":
            index += 2
            while index < len(tokens) and tokens[index][0] != "}":
                if (
                    tokens[index][0] == "ident"
                    and index + 2 < len(tokens)
                    and tokens[index + 1][0] == "="
                    and tokens[index + 2][0] == "{"
                ):
                    local = tokens[index][1]
                    fields, index = _block_fields(tokens, index + 3, frozenset({"source", "version"}))
                    found.append({
                        "kind": "provider_requirement",
                        "label": local,
                        "source": fields["source"],
                        "source_literal": fields["literal"]["source"],
                        "version": fields["version"],
                        "version_literal": fields["literal"]["version"],
                    })
                    continue
                if tokens[index][0] == "{":
                    index = _skip_brace(tokens, index + 1)
                    continue
                index += 1
            if index < len(tokens) and tokens[index][0] == "}":
                index += 1
            continue
        index += 1
    return found, None


def parse_lock(text: str) -> tuple[list[dict], str | None]:
    tokens, error = _tokenize(text)
    if error:
        return [], error
    if not _balanced(tokens):
        return [], "unbalanced"
    found: list[dict] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if (
            token[0] == "ident"
            and token[1] == "provider"
            and index + 2 < len(tokens)
            and tokens[index + 1][0] == "str"
            and tokens[index + 2][0] == "{"
        ):
            address, address_literal = tokens[index + 1][1], tokens[index + 1][2]
            fields, index = _block_fields(tokens, index + 3, frozenset({"version", "constraints"}))
            found.append({
                "kind": "lock_provider",
                "address": address if address_literal else None,
                "version": fields["version"],
                "version_literal": fields["literal"]["version"],
                "constraints": fields["constraints"],
                "constraints_literal": fields["literal"]["constraints"],
            })
            continue
        index += 1
    return found, None


def _json_text(value: object) -> tuple[str | None, bool, str | None]:
    if value is None:
        return None, True, None
    if not isinstance(value, str):
        return None, False, "json"
    literal = "${" not in value and "%{" not in value and not any(ord(char) < 32 or ord(char) == 127 for char in value)
    return value, literal, None


def _json_pair(body: dict, key: str) -> tuple[str | None, bool, str | None]:
    if key not in body:
        return None, True, None
    return _json_text(body[key])


def _labeled_rows(kind: str, value: object) -> tuple[list[dict], str | None]:
    if isinstance(value, dict):
        groups = [value]
    elif isinstance(value, list):
        if not all(isinstance(item, dict) for item in value):
            return [], "json"
        groups = list(value)
    else:
        return [], "json"
    found: list[dict] = []
    for group in groups:
        for label, body in group.items():
            if label == "//":
                continue  # Terraform JSON treats "//" as a comment.
            bodies = body if isinstance(body, list) else [body]
            if not isinstance(label, str):
                return [], "json"
            label_literal = "${" not in label and "%{" not in label
            for one in bodies:
                if not isinstance(one, dict):
                    return [], "json"
                source, source_literal, error = _json_pair(one, "source")
                if error:
                    return [], error
                version, version_literal, error = _json_pair(one, "version")
                if error:
                    return [], error
                found.append({
                    "kind": kind,
                    "label": label if label_literal else None,
                    "source": source,
                    "source_literal": source_literal,
                    "version": version,
                    "version_literal": version_literal,
                })
    return found, None


def _terraform_requirements(value: object) -> tuple[list[dict], str | None]:
    if isinstance(value, dict):
        blocks = [value]
    elif isinstance(value, list):
        if not all(isinstance(item, dict) for item in value):
            return [], "json"
        blocks = list(value)
    else:
        return [], "json"
    found: list[dict] = []
    for block in blocks:
        if "required_providers" not in block:
            continue
        rows, error = _labeled_rows("provider_requirement", block["required_providers"])
        if error:
            return [], error
        found.extend(rows)
    return found, None


_ATTRIBUTES = {"source", "version"}


def _keep_repeats(pairs: list) -> dict:
    """HCL JSON may repeat a block key instead of using an array. Keep every block.

    A repeated block key becomes one list of its blocks (an array value adds each of
    its items). A repeated attribute keeps the last value, as plain JSON does.
    """
    out: dict = {}
    repeated: set = set()
    for key, value in pairs:
        if key not in out or key in _ATTRIBUTES:
            out[key] = value
            continue
        if key not in repeated:
            first = out[key]
            out[key] = list(first) if isinstance(first, list) else [first]
            repeated.add(key)
        out[key].extend(value if isinstance(value, list) else [value])
    return out

def parse_tf_json(text: str) -> tuple[list[dict], str | None]:
    """Take module and required_providers source and version. Other keys stay out."""
    try:
        data = json.loads(text, object_pairs_hook=_keep_repeats)
    except json.JSONDecodeError:
        return [], "json"
    if not isinstance(data, dict):
        return [], "json"
    found: list[dict] = []
    if "terraform" in data:
        rows, error = _terraform_requirements(data["terraform"])
        if error:
            return [], error
        found.extend(rows)
    if "module" in data:
        rows, error = _labeled_rows("module", data["module"])
        if error:
            return [], error
        found.extend(rows)
    return found, None


def exact_version(text: str | None, literal: bool) -> str | None:
    if not literal or not isinstance(text, str):
        return None
    match = _EXACT.fullmatch(text.strip())
    if match is None:
        return None
    body = text.strip()
    if body.startswith("="):
        body = body[1:].strip()
    if body.startswith("v"):
        body = body[1:]
    return body


def provider_id(source: str | None, literal: bool) -> str | None:
    if not literal or not isinstance(source, str):
        return None
    parts = source.strip().split("/")
    if len(parts) == 3 and parts[0] == "registry.terraform.io":
        parts = parts[1:]
    if len(parts) != 2 or not all(_PART.fullmatch(part) for part in parts):
        return None
    return f"registry.terraform.io/{parts[0]}/{parts[1]}"


def module_id(source: str | None, literal: bool) -> tuple[str | None, str]:
    """Return (registry id or None, kind). kind is registry, local, private, or other."""
    if not literal or not isinstance(source, str):
        return None, "other"
    raw = source.strip()
    if raw.startswith("./") or raw.startswith("../") or raw.startswith(".\\"):
        return None, "local"
    raw = raw.split("//", 1)[0]
    parts = raw.split("/")
    if parts and parts[0] not in {"registry.terraform.io"} and "." in parts[0]:
        return None, "private"
    if parts and parts[0] == "registry.terraform.io":
        parts = parts[1:]
    if len(parts) == 3 and all(_PART.fullmatch(part) for part in parts):
        return f"registry.terraform.io/{parts[0]}/{parts[1]}/{parts[2]}", "registry"
    if raw.startswith("git::") or raw.startswith("github.com/") or raw.startswith("https://") or raw.startswith("http://"):
        return None, "other"
    return None, "other"


def _inside(root: Path, path: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return False
    return True


def _safe_relative(root: Path, path: Path) -> str | None:
    try:
        relative = path.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return None
    if not re.fullmatch(r"[A-Za-z0-9._/-]{1,200}", relative):
        return None
    return relative


def _lexical_escape(directory: str) -> bool:
    path = Path(directory)
    if not path.is_absolute():
        path = Path.cwd() / path
    return any(part == ".." for part in path.parts)


def _macos_private_alias(path: Path) -> bool:
    allowed = _MACOS_ALIAS.get(path.as_posix())
    if allowed is None:
        return False
    try:
        target = os.readlink(path)
    except OSError:
        return False
    return target.rstrip("/") in allowed


def _argument_symlink(root: Path) -> bool:
    """True when the leaf or an intermediate component is a symlink.

    /tmp and /var on macOS point at /private. Those two ancestors are not a
    reason to refuse, or a normal folder under /tmp cannot be read. The leaf
    is refused even when it is one of those names.
    """
    current = Path(root.anchor)
    parts = [part for part in root.parts[1:] if part not in {"", "."}]
    if not parts:
        return False
    for index, part in enumerate(parts):
        current = current / part
        try:
            linked = current.is_symlink()
        except OSError:
            return True
        if not linked:
            continue
        if index != len(parts) - 1 and _macos_private_alias(current):
            continue
        return True
    return False


def collect(directory: str) -> dict:
    if not isinstance(directory, str) or not directory or len(directory) > 4096:
        return {"error": "bad_argument"}
    if any(ord(char) < 32 or ord(char) == 127 for char in directory):
        return {"error": "bad_argument"}
    if _lexical_escape(directory):
        return {"error": "path_escape"}
    root = Path(directory)
    if not root.is_absolute():
        root = Path.cwd() / root
    if _argument_symlink(root):
        return {"error": "path_symlink"}
    if not root.exists():
        return {"error": "path_missing"}
    if not root.is_dir():
        return {"error": "path_not_directory"}
    root = root.resolve()
    skipped = {"symlink": 0, "outside": 0, "too_large": 0, "unparsed": 0, "special": 0}
    files: list[Path] = []
    stack = [root]
    complete = True
    while stack:
        current = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            skipped["special"] += 1
            complete = False
            continue
        for entry in entries:
            name = entry.name
            if name != ".terraform.lock.hcl" and (name in SKIP_DIRS or name.startswith(".")):
                continue
            try:
                linked = entry.is_symlink()
            except OSError:
                skipped["special"] += 1
                complete = False
                continue
            if linked:
                skipped["symlink"] += 1
                continue
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
                is_file = entry.is_file(follow_symlinks=False)
            except OSError:
                skipped["special"] += 1
                complete = False
                continue
            if is_dir:
                stack.append(Path(entry.path))
                continue
            if not is_file:
                skipped["special"] += 1
                continue
            is_tf_json = name.endswith(".tf.json")
            is_tf = name.endswith(".tf") and not is_tf_json
            if name != ".terraform.lock.hcl" and not is_tf and not is_tf_json:
                continue
            path = Path(entry.path)
            if not _inside(root, path):
                skipped["outside"] += 1
                complete = False
                continue
            try:
                size = entry.stat(follow_symlinks=False).st_size
            except OSError:
                skipped["special"] += 1
                complete = False
                continue
            if size > MAX_FILE_BYTES:
                skipped["too_large"] += 1
                complete = False
                continue
            files.append(path)
    files.sort(key=lambda item: item.as_posix())
    if len(files) > MAX_FILES:
        files = files[:MAX_FILES]
        complete = False
    providers: list[dict] = []
    modules: list[dict] = []
    for path in files:
        if not _inside(root, path):
            skipped["outside"] += 1
            complete = False
            continue
        relative = _safe_relative(root, path)
        try:
            raw = path.read_bytes()
        except OSError:
            skipped["special"] += 1
            complete = False
            continue
        if b"\x00" in raw:
            skipped["unparsed"] += 1
            complete = False
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeError:
            skipped["unparsed"] += 1
            complete = False
            continue
        if path.name == ".terraform.lock.hcl":
            rows, error = parse_lock(text)
        elif path.name.endswith(".tf.json"):
            rows, error = parse_tf_json(text)
        else:
            rows, error = parse_tf(text)
        if error:
            skipped["unparsed"] += 1
            complete = False
            continue
        for row in rows:
            row["file"] = relative
            if row["kind"] == "module":
                modules.append(row)
            else:
                providers.append(row)
    return {
        "error": None,
        "root": root.as_posix(),
        "complete_files": complete,
        "scanned_files": len(files),
        "skipped": skipped,
        "providers": providers,
        "modules": modules,
    }
