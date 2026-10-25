"""Coverage tests for terraform-drift. The network is fake except the live marker."""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import URLError

import pytest

from terraform_drift import schemas, tools
from terraform_drift.hosts import reject_reason
from terraform_drift.http_client import RedirectError, _NoRedirect, classify_transport, open_request, opener
from terraform_drift.registry import highlights_between
from terraform_drift.semver import compare, highest_stable

ROOT = Path(__file__).resolve().parents[1]
SECRET = "example-access-key-value"
BACKEND = "example-backend-token"
APPROVAL = (
    "Before the call, write the directory path and that the call only reads .tf files, "
    ".tf.json files, and .terraform.lock.hcl plus the public registry, with no terraform init, plan, apply, or state write."
)

TF = """
terraform {
  required_providers {
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
  backend "s3" {
    access_key = "%s"
  }
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.0.0"
  # version = "9.9.9"
}

module "local_net" {
  source = "./modules/local"
}

provider "aws" {
  secret_key = "%s"
}
""" % (SECRET, BACKEND)

LOCK = """
provider "registry.terraform.io/hashicorp/random" {
  version     = "3.6.0"
  constraints = "~> 3.0"
  hashes = ["h1:not-a-secret-hash"]
}
"""

CHANGELOG = """
## 3.6.0

NOTES:

* older

## 3.7.0

BREAKING CHANGES:

* resource/random_pet: this is a breaking change to the separator

## 3.9.1

SECURITY:

* a security fix for the reader
<!-- breaking only inside a comment -->
"""


def _versions(items: list[str]) -> str:
    return json.dumps({"versions": [{"version": item} for item in items]})


def _modules(items: list[str]) -> str:
    return json.dumps({"modules": [{"versions": [{"version": item} for item in items]}]})


class FakeNet:
    def __init__(self, routes: dict[str, str] | None = None, errors: dict | None = None):
        self.routes = routes or {
            "https://registry.terraform.io/v1/providers/hashicorp/random/versions": _versions(
                ["1.9.0", "1.10.0", "3.6.0", "3.9.1", "3.10.0-beta.1"]
            ),
            "https://registry.terraform.io/v1/providers/hashicorp/random": json.dumps(
                {"version": "3.9.1", "source": "https://github.com/hashicorp/terraform-provider-random", "docs": [{"title": "ignore"}]}
            ),
            "https://raw.githubusercontent.com/hashicorp/terraform-provider-random/v3.9.1/CHANGELOG.md": CHANGELOG,
            "https://registry.terraform.io/v1/modules/terraform-aws-modules/vpc/aws/versions": _modules(["5.0.0", "5.1.0", "5.2.0-beta.1"]),
            "https://registry.terraform.io/v1/modules/terraform-aws-modules/vpc/aws": json.dumps(
                {"version": "5.1.0", "source": "https://github.com/terraform-aws-modules/terraform-aws-vpc", "readme": "huge " + SECRET}
            ),
        }
        self.errors = errors or {}
        self.seen: list[str] = []

    def __call__(self, url: str) -> dict:
        self.seen.append(url)
        if url in self.errors:
            return self.errors[url]
        if url not in self.routes:
            return {
                "ok": False,
                "error_type": "registry_not_found",
                "error": "HTTP 404.",
                "next_step": "Missing.",
                "latest": None,
            }
        return {"ok": True, "status": 200, "text": self.routes[url]}


def use(net: FakeNet | None = None) -> FakeNet:
    net = net or FakeNet()
    tools.bind(transport=net, clock=lambda: 1_700_000_000)
    return net


def call(name: str, args: dict) -> dict:
    return json.loads(tools.HANDLERS[name](args))


def tree(tmp_path: Path, tf: str = TF, lock: str = LOCK) -> Path:
    (tmp_path / "versions.tf").write_text(tf, encoding="utf-8")
    (tmp_path / ".terraform.lock.hcl").write_text(lock, encoding="utf-8")
    (tmp_path / "secrets.auto.tfvars").write_text(f'access_key = "{SECRET}"\n', encoding="utf-8")
    (tmp_path / ".env").write_text(f"AWS_SECRET_ACCESS_KEY={SECRET}\n", encoding="utf-8")
    hidden = tmp_path / ".terraform"
    hidden.mkdir()
    (hidden / "terraform.tfstate").write_text(SECRET, encoding="utf-8")
    return tmp_path


def component(result: dict, identity: str) -> dict:
    return next(row for row in result["components"] if row["id"] == identity)


def fingerprint(path: Path) -> list[tuple[str, str]]:
    rows = []
    for item in sorted(path.rglob("*")):
        if item.is_file() and not item.is_symlink():
            rows.append((item.relative_to(path).as_posix(), hashlib.sha256(item.read_bytes()).hexdigest()))
    return rows


@pytest.fixture(autouse=True)
def _reset():
    tools.reset()
    yield
    tools.reset()


def test_semver_1_10_after_1_9():
    assert highest_stable(["1.9.0", "1.10.0", "1.10.0-beta.1"]) == "1.10.0"
    assert "1.10.0" < "1.9.0"
    assert compare("1.9.0", "1.10.0") == -1


def test_semver_edges():
    assert compare("1.2.3-beta", "1.2.3") == -1
    assert compare("1.2.3-beta.2", "1.2.3-beta.11") == -1
    assert highest_stable(["3.7.0-alpha1"]) is None
    assert compare("nope", "1.0.0") is None


def test_drift_reports_pin_and_latest(tmp_path):
    use()
    result = call("terraform_drift", {"directory": str(tree(tmp_path))})
    assert result["ok"] is True and result["complete_scan"] is True
    provider = component(result, "registry.terraform.io/hashicorp/random")
    assert provider["pin"] == "3.6.0" and provider["latest"] == "3.9.1" and provider["relation"] == "behind"
    assert provider["constraint"] == "~> 3.0"
    module = component(result, "registry.terraform.io/terraform-aws-modules/vpc/aws")
    assert module["pin"] == "5.0.0" and module["latest"] == "5.1.0" and module["relation"] == "behind"
    assert any("breaking change" in line for line in provider["highlights"])
    assert any("security fix" in line for line in provider["highlights"])
    assert result["behind_count"] == 2
    assert "9.9.9" not in json.dumps(result)


def test_provider_latest_is_semver(tmp_path):
    net = use()
    net.routes["https://registry.terraform.io/v1/providers/hashicorp/random/versions"] = _versions(["1.9.0", "1.10.0"])
    net.routes["https://registry.terraform.io/v1/providers/hashicorp/random"] = json.dumps(
        {"source": "https://github.com/hashicorp/terraform-provider-random"}
    )
    net.routes["https://raw.githubusercontent.com/hashicorp/terraform-provider-random/v1.10.0/CHANGELOG.md"] = (
        "## 1.10.0\n\nBREAKING CHANGES:\n\n* breaking move\n"
    )
    folder = tmp_path
    (folder / ".terraform.lock.hcl").write_text(
        'provider "registry.terraform.io/hashicorp/random" {\n  version = "1.9.0"\n}\n',
        encoding="utf-8",
    )
    result = call("terraform_drift", {"directory": str(folder)})
    row = component(result, "registry.terraform.io/hashicorp/random")
    assert row["latest"] == "1.10.0" and row["relation"] == "behind"


def test_provider_prerelease_not_latest(tmp_path):
    net = use()
    net.routes["https://registry.terraform.io/v1/providers/hashicorp/random/versions"] = _versions(["3.6.0", "3.10.0-beta.1"])
    folder = tree(tmp_path)
    result = call("terraform_drift", {"directory": str(folder)})
    row = component(result, "registry.terraform.io/hashicorp/random")
    assert row["latest"] == "3.6.0" and row["relation"] == "same"
    assert "3.10.0-beta.1" not in json.dumps(row["latest"])


def test_lock_pin_wins(tmp_path):
    use()
    result = call("terraform_drift", {"directory": str(tree(tmp_path))})
    row = component(result, "registry.terraform.io/hashicorp/random")
    assert row["pin"] == "3.6.0"
    assert row["constraint"] == "~> 3.0"


def test_required_provider_constraint(tmp_path):
    use()
    folder = tmp_path
    (folder / "versions.tf").write_text(
        'terraform { required_providers { random = { source = "hashicorp/random" version = "~> 3.0" } } }\n',
        encoding="utf-8",
    )
    result = call("terraform_drift", {"directory": str(folder)})
    row = component(result, "registry.terraform.io/hashicorp/random")
    assert row["pin"] is None and row["relation"] == "pin_unknown" and row["latest"] == "3.9.1"
    assert result["behind_count"] is None
    assert "nothing is outdated" not in result["summary"]


def test_module_exact_pin(tmp_path):
    use()
    result = call("terraform_drift", {"directory": str(tree(tmp_path))})
    row = component(result, "registry.terraform.io/terraform-aws-modules/vpc/aws")
    assert row["pin"] == "5.0.0" and row["kind"] == "module"


def test_module_edges(tmp_path):
    use()
    folder = tmp_path
    (folder / "mod.tf").write_text(
        'module "ranged" {\n  source = "terraform-aws-modules/vpc/aws"\n  version = "~> 5.0"\n}\n'
        'module "sub" {\n  source = "terraform-aws-modules/vpc/aws//modules/flow-log"\n  version = "= 5.0.0"\n}\n',
        encoding="utf-8",
    )
    result = call("terraform_drift", {"directory": str(folder)})
    row = component(result, "registry.terraform.io/terraform-aws-modules/vpc/aws")
    assert row["pin"] == "5.0.0"
    assert row["relation"] == "behind"


def test_module_outside_source(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.tf").write_text(f'source = "{SECRET}"\n', encoding="utf-8")
    folder = tmp_path / "proj"
    folder.mkdir()
    (folder / "mod.tf").write_text(
        'module "gone" {\n  source = "../outside"\n  version = "1.0.0"\n}\n',
        encoding="utf-8",
    )
    net = use()
    result = call("terraform_drift", {"directory": str(folder)})
    assert SECRET not in json.dumps(result)
    assert net.seen == []
    assert any(row["relation"] == "local" for row in result["components"])


def test_module_registry_down(tmp_path):
    net = use()
    net.errors["https://registry.terraform.io/v1/modules/terraform-aws-modules/vpc/aws/versions"] = {
        "ok": False,
        "error_type": "registry_down",
        "error": "The public registry did not connect.",
        "next_step": "Retry later. No version was read.",
        "latest": None,
    }
    result = call("terraform_drift", {"directory": str(tree(tmp_path))})
    row = component(result, "registry.terraform.io/terraform-aws-modules/vpc/aws")
    assert row["latest"] is None and row["registry_status"] == "registry_down"
    assert "nothing is outdated" not in result["summary"]


def test_registry_failures(tmp_path):
    cases = {
        "registry_timeout": "The public registry timed out.",
        "registry_auth": "HTTP 401. This plugin does not send a key.",
        "registry_rate_limit": "HTTP 429.",
        "registry_http": "HTTP 500.",
        "registry_not_found": "HTTP 404.",
        "registry_body": "The version list was not a JSON object.",
        "registry_redirect": "The registry returned a redirect. It was not followed.",
    }
    folder = tree(tmp_path)
    for error_type, error in cases.items():
        net = FakeNet()
        net.errors["https://registry.terraform.io/v1/providers/hashicorp/random/versions"] = {
            "ok": False,
            "error_type": error_type,
            "error": error,
            "next_step": "Retry later.",
            "latest": None,
        }
        use(net)
        result = call("terraform_drift", {"directory": str(folder)})
        row = component(result, "registry.terraform.io/hashicorp/random")
        assert row["registry_status"] == error_type and row["latest"] is None
        assert row["registry_next"]
        assert error_type != "registry_down" or "did not connect" in (row["registry_error"] or "")


def test_digest_timeout_is_not_latest(tmp_path):
    net = use()
    net.errors["https://registry.terraform.io/v1/providers/hashicorp/random/versions"] = classify_transport(
        URLError("Query timed out after 30 seconds")
    )
    result = call("terraform_drift_digest", {"directory": str(tree(tmp_path)), "known": {}})
    row = component(result, "registry.terraform.io/hashicorp/random")
    assert row["registry_status"] == "registry_timeout" and row["latest"] is None
    assert "did not connect" not in row["registry_error"]
    assert "nothing is new" not in result["message"]
    assert "This text is not sent to a destination." in result["message"]


def test_changelog_highlights(tmp_path):
    use()
    result = call("terraform_drift", {"directory": str(tree(tmp_path))})
    row = component(result, "registry.terraform.io/hashicorp/random")
    assert row["highlights_known"] is True
    assert any("breaking" in line for line in row["highlights"])
    joined = json.dumps(row["highlights"])
    assert "only inside a comment" not in joined


def test_changelog_html_comment():
    text = "## 1.2.0\n\n<!-- breaking change -->\nNOTES:\n\n* quiet\n"
    parsed = highlights_between(text, "1.0.0", "1.2.0", truncated=False)
    assert parsed["highlights"] == [] and parsed["highlights_known"] is True


def test_partial_changelog():
    text = "## 1.2.0\n\nBREAKING CHANGES:\n\n* breaking move\n"
    parsed = highlights_between(text, "1.0.0", "1.2.0", truncated=True)
    assert parsed["highlights_known"] is False and parsed["changelog_status"] == "truncated"


def test_changelog_unavailable(tmp_path):
    net = use()
    net.routes["https://registry.terraform.io/v1/providers/hashicorp/random"] = json.dumps(
        {"source": "https://example.com/not-github/repo"}
    )
    result = call("terraform_drift", {"directory": str(tree(tmp_path))})
    row = component(result, "registry.terraform.io/hashicorp/random")
    assert row["latest"] == "3.9.1"
    assert row["changelog_status"] == "unavailable" and row["highlights_known"] is False
    assert not any(url.startswith("https://example.com") for url in net.seen)


def test_changelog_line_stripped():
    text = "## 1.2.0\n\nSECURITY:\n\n* access_key = \"should-not-show\" breaking\n* a security fix\n"
    parsed = highlights_between(text, "1.0.0", "1.2.0", truncated=False)
    assert all("access_key" not in line for line in parsed["highlights"])
    assert any("security fix" in line for line in parsed["highlights"])


def test_provider_body_cut(tmp_path):
    net = use()
    net.errors["https://registry.terraform.io/v1/providers/hashicorp/random/versions"] = {
        "ok": False,
        "error_type": "registry_truncated",
        "error": "The response was longer than the cap.",
        "next_step": "Retry later. A truncated body is not a latest version.",
        "latest": None,
    }
    result = call("terraform_drift", {"directory": str(tree(tmp_path))})
    row = component(result, "registry.terraform.io/hashicorp/random")
    assert row["latest"] is None and row["registry_status"] == "registry_truncated"


def test_module_readme_dropped(tmp_path):
    use()
    result = call("terraform_drift", {"directory": str(tree(tmp_path))})
    assert "huge" not in json.dumps(result)
    assert SECRET not in json.dumps(result)


def test_secrets_absent(tmp_path):
    use()
    result = call("terraform_drift", {"directory": str(tree(tmp_path))})
    blob = json.dumps(result)
    assert SECRET not in blob and BACKEND not in blob
    assert "h1:not-a-secret-hash" not in blob


def test_lock_hashes_not_returned(tmp_path):
    test_secrets_absent(tmp_path)


def test_dotenv_not_read(tmp_path, monkeypatch):
    opened: list[str] = []
    real_read = Path.read_bytes

    def spy(self: Path):
        opened.append(self.name)
        return real_read(self)

    monkeypatch.setattr(Path, "read_bytes", spy)
    use()
    call("terraform_drift", {"directory": str(tree(tmp_path))})
    assert ".env" not in opened
    assert "secrets.auto.tfvars" not in opened
    assert "terraform.tfstate" not in opened


def test_reads_leave_fingerprint(tmp_path):
    folder = tree(tmp_path)
    before = fingerprint(folder)
    use()
    call("terraform_drift", {"directory": str(folder)})
    call("terraform_drift_digest", {"directory": str(folder), "known": {}, "cadence": "weekly"})
    assert fingerprint(folder) == before


def test_directory_edges(tmp_path):
    assert call("terraform_drift", {"directory": 1})["error_type"] == "bad_argument"
    assert call("terraform_drift", {"directory": ""})["error_type"] == "bad_argument"
    assert call("terraform_drift", {"directory": "bad\npath"})["error_type"] == "bad_argument"
    assert call("terraform_drift", {})["error_type"] == "bad_argument"
    long_path = str(tmp_path) + ("a" * 5000)
    assert call("terraform_drift", {"directory": long_path})["error_type"] == "bad_argument"
    empty = tmp_path / "empty"
    empty.mkdir()
    use()
    result = call("terraform_drift", {"directory": str(empty)})
    assert result["complete_scan"] is True and result["components"] == []
    assert result["behind_count"] is None
    assert "No public registry" in result["summary"]


def test_directory_missing(tmp_path):
    result = call("terraform_drift", {"directory": str(tmp_path / "missing")})
    assert result["error_type"] == "path_missing" and "components" not in result


def test_directory_symlink_file(tmp_path):
    outside = tmp_path / "outside.tf"
    outside.write_text(f'access_key = "{SECRET}"\nmodule "m" {{ source = "hashicorp/x/aws" version = "1.0.0" }}\n', encoding="utf-8")
    folder = tmp_path / "proj"
    folder.mkdir()
    (folder / "leak.tf").symlink_to(outside)
    (folder / "ok.tf").write_text(
        'terraform { required_providers { random = { source = "hashicorp/random" version = "3.6.0" } } }\n',
        encoding="utf-8",
    )
    use()
    result = call("terraform_drift", {"directory": str(folder)})
    assert SECRET not in json.dumps(result)
    assert result["skipped"]["symlink"] >= 1


def test_symlink_dir_not_followed(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "hidden.tf").write_text(
        'terraform { required_providers { other = { source = "hashicorp/null" version = "1.0.0" } } }\n',
        encoding="utf-8",
    )
    folder = tmp_path / "proj"
    folder.mkdir()
    (folder / "linked").symlink_to(outside, target_is_directory=True)
    use()
    result = call("terraform_drift", {"directory": str(folder)})
    assert all("hashicorp/null" not in row["id"] for row in result["components"])
    assert result["skipped"]["symlink"] >= 1


def test_dotdot_refused(tmp_path):
    result = call("terraform_drift", {"directory": str(tmp_path / ".." / "etc")})
    assert result["error_type"] == "path_escape"
    assert "components" not in result


def _null_tf() -> str:
    return (
        'terraform { required_providers { other = { source = "hashicorp/null" version = "9.8.7" } } }\n'
    )


def test_prevent_symlink_last_element(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "hidden.tf").write_text(_null_tf(), encoding="utf-8")
    linked = tmp_path / "linked_root"
    linked.symlink_to(outside, target_is_directory=True)
    use()
    result = call("terraform_drift", {"directory": str(linked)})
    assert "hashicorp/null" not in json.dumps(result)
    assert result["error_type"] == "path_symlink"
    assert "components" not in result


def test_prevent_symlink_intermediate(tmp_path):
    real_parent = tmp_path / "realparent" / "proj"
    real_parent.mkdir(parents=True)
    (real_parent / "main.tf").write_text(_null_tf(), encoding="utf-8")
    jump = tmp_path / "jump"
    jump.symlink_to(tmp_path / "realparent", target_is_directory=True)
    use()
    result = call("terraform_drift", {"directory": str(jump / "proj")})
    assert "hashicorp/null" not in json.dumps(result)
    assert result["error_type"] == "path_symlink"
    assert "components" not in result


def test_prevent_symlink_inside_still_skipped(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "hidden.tf").write_text(_null_tf(), encoding="utf-8")
    folder = tmp_path / "proj"
    folder.mkdir()
    (folder / "ok.tf").write_text(
        'terraform { required_providers { random = { source = "hashicorp/random" version = "3.6.0" } } }\n',
        encoding="utf-8",
    )
    (folder / "leak.tf").symlink_to(outside / "hidden.tf")
    (folder / "linked_dir").symlink_to(outside, target_is_directory=True)
    use()
    result = call("terraform_drift", {"directory": str(folder)})
    assert "hashicorp/null" not in json.dumps(result)
    assert result["skipped"]["symlink"] >= 2
    assert result["complete_scan"] is True
    assert component(result, "registry.terraform.io/hashicorp/random")["pin"] == "3.6.0"


def test_prevent_tmp_normal_folder():
    if not Path("/tmp").is_symlink():
        pytest.skip("macOS /tmp alias is the regression this test locks")
    folder = Path("/tmp") / f"terraform-drift-plain-{os.getpid()}"
    folder.mkdir()
    try:
        (folder / "versions.tf").write_text(
            'terraform { required_providers { random = { source = "hashicorp/random" version = "3.6.0" } } }\n',
            encoding="utf-8",
        )
        use()
        result = call("terraform_drift", {"directory": str(folder)})
        assert str(folder).startswith("/tmp/")
        assert result.get("error_type") is None
        assert result["complete_scan"] is True
        assert component(result, "registry.terraform.io/hashicorp/random")["pin"] == "3.6.0"
    finally:
        for child in folder.iterdir():
            child.unlink()
        folder.rmdir()


def test_prevent_tf_json_only_not_false_empty(tmp_path):
    folder = tmp_path / "json_only"
    folder.mkdir()
    (folder / "versions.tf.json").write_text(
        json.dumps({
            "terraform": {
                "required_providers": {
                    "random": {"source": "hashicorp/random", "version": "3.6.0"},
                }
            },
            "variable": {"db_password": {"default": SECRET}},
        }),
        encoding="utf-8",
    )
    use()
    result = call("terraform_drift", {"directory": str(folder)})
    blob = json.dumps(result)
    assert SECRET not in blob
    assert "No public registry" not in result["summary"]
    row = component(result, "registry.terraform.io/hashicorp/random")
    assert row["pin"] == "3.6.0"


def test_prevent_tf_json_mixed(tmp_path):
    folder = tmp_path / "json_mix"
    folder.mkdir()
    (folder / "versions.tf").write_text(
        'terraform { required_providers { random = { source = "hashicorp/random" version = "3.6.0" } } }\n',
        encoding="utf-8",
    )
    (folder / "extra.tf.json").write_text(
        json.dumps({
            "terraform": {
                "required_providers": {
                    "null": {"source": "hashicorp/null", "version": "3.2.1"},
                }
            }
        }),
        encoding="utf-8",
    )
    use()
    result = call("terraform_drift", {"directory": str(folder)})
    ids = [row["id"] for row in result["components"]]
    assert "registry.terraform.io/hashicorp/null" in ids or result["complete_scan"] is False
    assert "registry.terraform.io/hashicorp/random" in ids
    assert "registry.terraform.io/hashicorp/null" in ids


def test_prevent_tf_only_stays_complete(tmp_path):
    (tmp_path / "versions.tf").write_text(
        'terraform { required_providers { random = { source = "hashicorp/random" version = "3.6.0" } } }\n',
        encoding="utf-8",
    )
    use()
    result = call("terraform_drift", {"directory": str(tmp_path)})
    assert result["complete_scan"] is True
    assert component(result, "registry.terraform.io/hashicorp/random")["pin"] == "3.6.0"


def test_prevent_tf_json_module(tmp_path):
    (tmp_path / "mod.tf.json").write_text(
        json.dumps({
            "module": {
                "vpc": {"source": "terraform-aws-modules/vpc/aws", "version": "5.0.0"},
            }
        }),
        encoding="utf-8",
    )
    use()
    result = call("terraform_drift", {"directory": str(tmp_path)})
    row = component(result, "registry.terraform.io/terraform-aws-modules/vpc/aws")
    assert row["pin"] == "5.0.0"
    assert SECRET not in json.dumps(result)


def test_prevent_tf_json_unreadable_unknown(tmp_path):
    (tmp_path / "versions.tf").write_text(
        'terraform { required_providers { random = { source = "hashicorp/random" version = "3.6.0" } } }\n',
        encoding="utf-8",
    )
    (tmp_path / "broken.tf.json").write_text("{", encoding="utf-8")
    use()
    result = call("terraform_drift", {"directory": str(tmp_path)})
    assert result["complete_scan"] is False
    assert result["behind_count"] is None
    assert "No public registry" not in result["summary"]
    assert "unknown" in result["summary"].lower()


def test_tf_edges(tmp_path):
    assert "Versions.TF".endswith(".tf") is False
    folder = tmp_path
    (folder / "versions.tf").write_text(
        'terraform { required_providers { random = { source = "hashicorp/random" version = "3.6.0" } } }\n',
        encoding="utf-8",
    )
    upper = folder / "Versions.TF"
    if not (upper.exists() and upper.samefile(folder / "versions.tf")):
        upper.write_text(
            'terraform { required_providers { random = { source = "hashicorp/random" version = "9.9.9" } } }\n',
            encoding="utf-8",
        )
    use()
    result = call("terraform_drift", {"directory": str(folder)})
    row = component(result, "registry.terraform.io/hashicorp/random")
    assert row["pin"] == "3.6.0"


def test_tf_unclosed(tmp_path):
    folder = tmp_path
    (folder / "broken.tf").write_text('module "m" { source = "terraform-aws-modules/vpc/aws"\n', encoding="utf-8")
    use()
    result = call("terraform_drift", {"directory": str(folder)})
    assert result["complete_scan"] is False
    assert result["behind_count"] is None
    assert "nothing is outdated" not in result["summary"]


def test_lock_edges(tmp_path):
    folder = tmp_path
    (folder / ".terraform.lock.hcl").write_text(
        'provider "registry.terraform.io/hashicorp/random" {\n  version = "3.6.0"\n}\n'
        'provider "registry.terraform.io/hashicorp/random" {\n  version = "3.5.0"\n}\n',
        encoding="utf-8",
    )
    use()
    result = call("terraform_drift", {"directory": str(folder)})
    row = component(result, "registry.terraform.io/hashicorp/random")
    assert row["relation"] == "pin_conflict"
    assert result["behind_count"] is None


def test_lock_truncated_file(tmp_path):
    folder = tmp_path
    (folder / "big.tf").write_bytes(b"a" * (1_000_001))
    use()
    result = call("terraform_drift", {"directory": str(folder)})
    assert result["complete_scan"] is False and result["skipped"]["too_large"] == 1


def test_drift_edges(tmp_path):
    folder = tmp_path
    (folder / "unicode_name").mkdir()
    # A .tf name that is not ASCII is still inside the folder and is read.
    name = "バージョン.tf"
    (folder / name).write_text(
        'terraform { required_providers { random = { source = "hashicorp/random" version = "3.6.0" } } }\n',
        encoding="utf-8",
    )
    use()
    result = call("terraform_drift", {"directory": str(folder)})
    row = component(result, "registry.terraform.io/hashicorp/random")
    assert row["pin"] == "3.6.0"
    assert SECRET not in json.dumps(result)


def test_digest_only_new(tmp_path):
    use()
    folder = str(tree(tmp_path))
    first = call("terraform_drift_digest", {"directory": folder, "cadence": "daily"})
    assert first["only_new"] is False and first["baseline"] == "missing"
    assert "not claimed to be new today" in first["message"]
    assert "telegram" not in first["message"].lower()
    second = call(
        "terraform_drift_digest",
        {"directory": folder, "known": first["seen"], "cadence": "weekly"},
    )
    assert second["only_new"] is True and second["new_ids"] == []
    assert "No registry version is newer than the seen map." in second["message"]
    moved = dict(first["seen"])
    moved["registry.terraform.io/hashicorp/random"] = "3.8.0"
    third = call("terraform_drift_digest", {"directory": folder, "known": moved})
    assert "registry.terraform.io/hashicorp/random" in third["new_ids"]
    assert "registry.terraform.io/terraform-aws-modules/vpc/aws" not in third["new_ids"]


def test_digest_edges(tmp_path):
    folder = str(tree(tmp_path))
    use()
    assert call("terraform_drift_digest", {"directory": folder, "cadence": "hourly"})["error_type"] == "bad_argument"
    assert call("terraform_drift_digest", {"directory": folder, "known": "3.6.0"})["error_type"] == "bad_argument"
    assert call("terraform_drift_digest", {"directory": folder, "known": []})["error_type"] == "bad_argument"
    result = call("terraform_drift_digest", {"directory": folder, "known": {"not a id": "1.0.0", "registry.terraform.io/hashicorp/random": "nope"}})
    assert "not a id" not in result["message"]
    assert "registry.terraform.io/hashicorp/random" in result["unknown_ids"]


def test_digest_partial_registry(tmp_path):
    net = use()
    net.errors["https://registry.terraform.io/v1/modules/terraform-aws-modules/vpc/aws/versions"] = {
        "ok": False,
        "error_type": "registry_down",
        "error": "The public registry did not connect.",
        "next_step": "Retry later.",
        "latest": None,
    }
    seen = {"registry.terraform.io/hashicorp/random": "3.9.1"}
    result = call("terraform_drift_digest", {"directory": str(tree(tmp_path)), "known": seen})
    assert "registry.terraform.io/terraform-aws-modules/vpc/aws" in result["unknown_ids"]
    assert "nothing is new" not in result["message"]
    assert "registry.terraform.io/hashicorp/random" not in result["new_ids"]


def test_known_edges(tmp_path):
    test_digest_edges(tmp_path)


def test_known_does_not_echo_odd_values(tmp_path):
    use()
    result = call(
        "terraform_drift_digest",
        {"directory": str(tree(tmp_path)), "known": {"https://evil.example/${SECRET}": SECRET}},
    )
    assert SECRET not in json.dumps(result)
    assert "evil.example" not in json.dumps(result)


def test_cadence_rejected(tmp_path):
    assert call("terraform_drift_digest", {"directory": str(tmp_path), "cadence": 1})["error_type"] == "bad_argument"
    assert call("terraform_drift_digest", {"directory": str(tmp_path), "cadence": "Yearly"})["error_type"] == "bad_argument"


def test_private_registry_not_called(tmp_path):
    folder = tmp_path
    (folder / "priv.tf").write_text(
        'terraform { required_providers { aws = { source = "app.terraform.io/example/aws" version = "1.2.3" } } }\n'
        'module "m" { source = "app.terraform.io/example/vpc/aws" version = "1.0.0" }\n',
        encoding="utf-8",
    )
    net = use()
    result = call("terraform_drift", {"directory": str(folder)})
    assert net.seen == []
    assert "app.terraform.io" not in json.dumps(result)
    assert any(row["relation"] == "private" for row in result["components"])


def test_registry_source_not_followed(tmp_path):
    net = use()
    net.routes["https://registry.terraform.io/v1/providers/hashicorp/random"] = json.dumps(
        {"source": "http://169.254.169.254/latest/meta-data"}
    )
    call("terraform_drift", {"directory": str(tree(tmp_path))})
    assert all("169.254.169.254" not in url for url in net.seen)


def test_hosts_allowlist():
    assert reject_reason("https://registry.terraform.io/v1/providers/hashicorp/random/versions") is None
    assert reject_reason("https://registry.terraform.io/v1/providers/hashicorp/random/other") == "path"
    assert reject_reason("http://registry.terraform.io/v1/providers/hashicorp/random") == "scheme"
    assert reject_reason("https://user:s3cret-token@registry.terraform.io/v1/providers/hashicorp/random/versions") == "userinfo"


def test_ip_literals_refused():
    for host in ("169.254.169.254", "0.0.0.0", "192.0.2.1"):
        assert reject_reason(f"https://{host}/") in {"ip", "host", "path"}


def test_userinfo_refused():
    reason = reject_reason("https://user:s3cret-token@registry.terraform.io/v1/providers/hashicorp/random/versions")
    assert reason == "userinfo"


def test_redirect_not_followed():
    handler = _NoRedirect()
    try:
        handler.redirect_request(None, None, 302, "Found", {}, "http://127.0.0.1/secret")
    except RedirectError as exc:
        assert exc.code == 302
    else:
        raise AssertionError("a redirect was accepted")
    hits = {"start": 0, "secret": 0}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path.startswith("/secret"):
                hits["secret"] += 1
            else:
                hits["start"] += 1
            self.send_response(302)
            self.send_header("Location", "/secret")
            self.end_headers()

        def log_message(self, fmt, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        result = open_request(f"http://127.0.0.1:{port}/start", timeout=2)
    finally:
        server.shutdown()
    assert hits["secret"] == 0
    assert result.get("ok") is not True
    if hits["start"]:
        assert result["error_type"] == "registry_redirect"


def test_proxy_ignored(monkeypatch):
    trap_hits = {"n": 0}

    class Trap(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            trap_hits["n"] += 1
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"trap")

        def do_CONNECT(self):  # noqa: N802
            trap_hits["n"] += 1
            self.send_response(200)
            self.end_headers()

        def log_message(self, fmt, *args):
            return

    class Origin(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, fmt, *args):
            return

    origin_hits = {"n": 0}

    class CountingOrigin(Origin):
        def do_GET(self):  # noqa: N802
            origin_hits["n"] += 1
            return super().do_GET()

    trap = ThreadingHTTPServer(("127.0.0.1", 0), Trap)
    origin = ThreadingHTTPServer(("127.0.0.1", 0), CountingOrigin)
    threads = [threading.Thread(target=trap.serve_forever, daemon=True), threading.Thread(target=origin.serve_forever, daemon=True)]
    for thread in threads:
        thread.start()
    names = ["http_proxy", "https_proxy", "ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY", "all_proxy"]
    try:
        proxy = f"http://s3cret-token@127.0.0.1:{trap.server_address[1]}"
        for name in names:
            monkeypatch.setenv(name, proxy)
        monkeypatch.setenv("REQUEST_METHOD", "GET")
        result = open_request(f"http://127.0.0.1:{origin.server_address[1]}/direct", timeout=2)
        built = opener()
    finally:
        trap.shutdown()
        origin.shutdown()
    blob = repr([(type(item).__name__, getattr(item, "proxies", None)) for item in built.handlers])
    assert "s3cret-token" not in blob
    assert "s3cret-token" not in json.dumps(result)
    assert trap_hits["n"] == 0
    if origin_hits["n"]:
        assert result.get("ok") is True and result["text"] == "ok"
    else:
        assert result.get("ok") is not True


def test_proxy_secret_not_in_answer(monkeypatch):
    monkeypatch.setenv("https_proxy", "http://s3cret-token@127.0.0.1:9")
    reason = reject_reason("https://user:s3cret-token@registry.terraform.io/v1/providers/hashicorp/random/versions")
    assert reason == "userinfo"


def test_schemas_readonly():
    for schema in schemas.ALL_SCHEMAS:
        assert schema["annotations"]["readOnlyHint"] is True
        first = schema["description"].split(". ")[0] + "."
        assert len(first) <= 60
        assert len(schema["description"]) <= 1024
    assert len(schemas.SKILL_DESCRIPTION) <= 223
    assert "terraform" in schemas.DRIFT["description"].split(". ")[0].lower()


def test_no_write_tool():
    assert tools.names() == ["terraform_drift", "terraform_drift_digest"]
    source = (ROOT / "tools.py").read_text(encoding="utf-8")
    assert "safe_write" not in source
    assert "terraform init" not in source


def test_checklist_12_no_write_execution(tmp_path):
    """Read-only tools have nothing to run when YOLO or approvals are off."""
    banned = ("subprocess", "os.system", "Popen", "safe_write", "unlink(", "write_text(", "write_bytes(", "mkdir(")
    for path in ROOT.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        for word in banned:
            assert word not in text, (path.name, word)
    for schema in schemas.ALL_SCHEMAS:
        assert schema["annotations"]["readOnlyHint"] is True
    folder = tree(tmp_path)
    before = fingerprint(folder)
    use()
    call("terraform_drift", {"directory": str(folder)})
    call("terraform_drift_digest", {"directory": str(folder), "known": {}, "cadence": "daily"})
    assert fingerprint(folder) == before


def test_approval_text():
    skill = (ROOT / "skills" / "terraform-drift" / "SKILL.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert APPROVAL in skill and APPROVAL in readme
    assert "There is no approval card." in readme
    assert "HashiCorp's terraform-mcp-server is a general registry client." in readme


def test_search_phrases():
    text = " ".join(item["description"] for item in schemas.ALL_SCHEMAS).lower()
    for word in ("terraform", "provider", "module", "version", "lock", "pin", "registry", "changelog", "breaking", "security", "behind", "outdated"):
        assert word in text
    ref = os.environ.get("HERMES_REF")
    if ref:
        catalog_path = Path(ref) / "tools" / "tool_search_catalog.py"
    else:
        catalog_path = Path(__file__).resolve().parents[2] / "hermes-agent-ref" / "tools" / "tool_search_catalog.py"
    if not catalog_path.is_file():
        pytest.skip("tool search catalog is not next to this tree")
    spec = importlib.util.spec_from_file_location("tool_search_catalog_td", catalog_path)
    module = importlib.util.module_from_spec(spec)
    import sys
    sys.modules["tool_search_catalog_td"] = module
    spec.loader.exec_module(module)
    defs = []
    for schema in schemas.ALL_SCHEMAS:
        defs.append({"type": "function", "function": {"name": schema["name"], "description": schema["description"], "parameters": schema["parameters"]}})
    for name, description in (
        ("email_send", "Send an email message to a teammate."),
        ("docker_ps", "List docker containers and their status."),
        ("github_changelog", "Read a github changelog for a pull request."),
        ("security_scan", "Scan a repository for security findings."),
        ("module_import", "Import a python module and show its version."),
        ("provider_status", "Show a cloud provider account status and version."),
    ):
        defs.append({"type": "function", "function": {"name": name, "description": description, "parameters": {"type": "object", "properties": {}}}})
    catalog = []
    for item in defs:
        fn = item["function"]
        catalog.append(module.CatalogEntry(
            name=fn["name"],
            description=fn["description"],
            schema=item,
            source="plugin",
            source_name="terraform-drift" if fn["name"].startswith("terraform_") else "other",
            _tokens=module._tokenize(module._entry_search_text(item, "terraform-drift" if fn["name"].startswith("terraform_") else "")),
        ))
    queries = [
        "outdated terraform provider and module versions",
        "terraform lock file pin behind the public registry",
        "terraform provider changelog breaking security lines",
    ]
    for query in queries:
        found = [entry.name for entry in module.search_catalog(catalog, query, limit=5)]
        assert "terraform_drift" in found[:5], found


def test_digest_does_not_choose_destination(tmp_path):
    use()
    result = call("terraform_drift_digest", {"directory": str(tree(tmp_path))})
    assert "not sent to a destination" in result["message"]
    assert "telegram" not in result["message"].lower()
    assert "smtp" not in result["message"].lower()


def test_register_shape():
    seen = []

    class Ctx:
        def register_tool(self, **kwargs):
            seen.append(kwargs["name"])

        def register_skill(self, name, path, description=""):
            seen.append((name, description))

    from terraform_drift import register
    register(Ctx())
    assert seen[0] == "terraform_drift"
    assert seen[1] == "terraform_drift_digest"
    assert seen[2][0] == "terraform-drift"
    assert len(seen[2][1]) <= 223


def test_skill_and_plugin_agree():
    text = (ROOT / "plugin.yaml").read_text(encoding="utf-8")
    assert 'requires_hermes: ">=0.21.4"' in text
    skill = (ROOT / "skills" / "terraform-drift" / "SKILL.md").read_text(encoding="utf-8")
    front = skill.split("---", 2)[1]
    description = front.split("description:", 1)[1].strip()
    assert description == schemas.SKILL_DESCRIPTION
    tree_ast = ast.parse((ROOT / "tools.py").read_text(encoding="utf-8"))
    assert isinstance(tree_ast, ast.Module)


@pytest.mark.live
def test_live_random_provider(tmp_path):
    folder = tmp_path
    (folder / ".terraform.lock.hcl").write_text(
        'provider "registry.terraform.io/hashicorp/random" {\n  version = "3.6.0"\n}\n',
        encoding="utf-8",
    )
    tools.reset()
    result = call("terraform_drift", {"directory": str(folder)})
    row = component(result, "registry.terraform.io/hashicorp/random")
    assert row["registry_status"] == "ok"
    assert row["pin"] == "3.6.0"
    assert compare(row["pin"], row["latest"]) == -1
    assert row["relation"] == "behind"


def test_repeated_terraform_keys_keep_every_block(tmp_path):
    # HCL JSON may repeat a block key instead of using an array. Both blocks must be read.
    folder = tmp_path / "json_repeat"
    folder.mkdir()
    (folder / "versions.tf.json").write_text(
        '{"terraform": {"required_providers": {"null": {"source": "hashicorp/null", "version": "3.2.1"}}},'
        ' "terraform": {"required_providers": {"random": {"source": "hashicorp/random", "version": "3.6.0"}}}}',
        encoding="utf-8",
    )
    use()
    result = call("terraform_drift", {"directory": str(folder)})
    assert component(result, "registry.terraform.io/hashicorp/null")["pin"] == "3.2.1"
    assert component(result, "registry.terraform.io/hashicorp/random")["pin"] == "3.6.0"


def test_comment_key_inside_required_providers_is_ignored(tmp_path):
    folder = tmp_path / "json_comment"
    folder.mkdir()
    (folder / "versions.tf.json").write_text(
        json.dumps({
            "terraform": {
                "required_providers": {
                    "//": "providers",
                    "random": {"source": "hashicorp/random", "version": "3.6.0"},
                }
            },
            "module": {"//": "modules"},
        }),
        encoding="utf-8",
    )
    use()
    result = call("terraform_drift", {"directory": str(folder)})
    assert result["complete_scan"] is True, result
    assert component(result, "registry.terraform.io/hashicorp/random")["pin"] == "3.6.0"


def test_two_pins_for_one_provider_are_not_all_match(tmp_path):
    folder = tmp_path / "json_two_pins"
    folder.mkdir()
    (folder / "versions.tf.json").write_text(
        '{"terraform": {"required_providers": {"random": {"source": "hashicorp/random", "version": "3.9.1"}}},'
        ' "terraform": {"required_providers": {"random": {"source": "hashicorp/random", "version": "3.5.0"}}}}',
        encoding="utf-8",
    )
    use()
    result = call("terraform_drift", {"directory": str(folder)})
    assert "Every exact public-registry pin matches" not in result["summary"], result
    row = component(result, "registry.terraform.io/hashicorp/random")
    assert row["relation"] == "pin_conflict", row
    assert result["behind_count"] is None


def test_three_blocks_and_mixed_array_forms_are_read(tmp_path):
    folder = tmp_path / "json_three"
    folder.mkdir()
    (folder / "versions.tf.json").write_text(
        '{"terraform": [{"required_providers": {"null": {"source": "hashicorp/null", "version": "3.2.1"}}}],'
        ' "terraform": {"required_providers": {"aws": {"source": "hashicorp/aws", "version": "5.0.0"}}},'
        ' "terraform": {"required_providers": {"random": {"source": "hashicorp/random", "version": "3.6.0", "version": "3.6.0"}}}}',
        encoding="utf-8",
    )
    use()
    result = call("terraform_drift", {"directory": str(folder)})
    assert result.get("parse_error") is None, result
    for name, pin in (("null", "3.2.1"), ("aws", "5.0.0"), ("random", "3.6.0")):
        assert component(result, f"registry.terraform.io/hashicorp/{name}")["pin"] == pin
