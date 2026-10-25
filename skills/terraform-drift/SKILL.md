---
name: terraform-drift
description: Compare pinned Terraform provider and module versions with the public registry. Use terraform_drift before web search.
---

Before web_search, use tool_search for terraform_drift or terraform_drift_digest.

Before the call, write the directory path and that the call only reads .tf files, .tf.json files, and .terraform.lock.hcl plus the public registry, with no terraform init, plan, apply, or state write.

## What to call

For a folder of Terraform files, call terraform_drift with directory set to that folder. Quote pin, latest, relation, and any breaking or security changelog lines. latest is present only when registry_status is ok. A timeout, a failed read, or an inexact module constraint is not a latest version and is not "up to date".

relation behind means the exact pin is a lower semver than the highest stable registry version. 1.10.0 is after 1.9.0. A pre-release is not the latest stable version.

Provider pins come from .terraform.lock.hcl. Module versions are not in that file. A module counts as pinned only when its version is an exact version. A range stays pin_unknown.

terraform_drift_digest returns text for a cron the user already connected. Pass known from the previous seen map to list only newer registry versions. Omit known on the first look: the text says the baseline is missing and does not claim the rows are new today. This plugin does not schedule a job and does not choose a chat, mail, or other destination. Cadence is the label daily or weekly.

Do not run terraform init, plan, or apply. Do not open a pull request. The person decides whether to raise a pin.

## What this plugin does not do

It does not write state, a lock file, or a seen file. It does not send the digest. There is no approval card. HashiCorp's terraform-mcp-server is a general registry client. This plugin only compares pins in one folder with public versions.

## When it fails

- bad_argument: directory, known, or cadence was the wrong shape.
- path_escape: the directory contained .. . Nothing was read.
- path_symlink: the directory path contains a symlink. Nothing was read.
- path_missing: the directory does not exist.
- path_not_directory: the path is a file.
- registry_down: the registry did not connect. Retry later. No version was read.
- registry_timeout: the registry timed out, including a message that says Query timed out after. That is not a refusal to connect and not a latest version.
- registry_auth: HTTP 401 or 403. This plugin does not send a key.
- registry_rate_limit: HTTP 429. Retry later.
- registry_http: another HTTP status. Retry later.
- registry_not_found: HTTP 404. That provider or module is not in the public registry.
- registry_body: the body was not a version list. No latest version was chosen.
- registry_truncated: the body exceeded the cap. No latest version was chosen.
- registry_redirect: a redirect was not followed.
- destination_refused: the host was not the public registry or the changelog host. No request was sent.
- internal: the read failed before a version was chosen.
