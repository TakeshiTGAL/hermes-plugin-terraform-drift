# terraform-drift

Compares pinned Terraform provider and module versions in one folder with the public Terraform Registry, and quotes breaking or security lines from the changelog. HashiCorp's terraform-mcp-server is a general registry client. This plugin only compares the pins in one folder with the public versions.

## Install

Two commands, then the first request.

```
hermes plugins install --no-enable file:///absolute/path/to/hermes-plugin-terraform-drift
hermes plugins enable terraform-drift
```

Then ask: Which Terraform providers and modules in this folder are out of date?

The model should call tool_search with "outdated terraform provider and module versions" and then terraform_drift with directory set to the folder. The result has pin, latest, relation, registry_status, and highlights. latest is set only when registry_status is ok. relation behind means the exact pin is below the highest stable version. 1.10.0 is newer than 1.9.0.

There is no approval card. Before the call, write the directory path and that the call only reads .tf files, .tf.json files, and .terraform.lock.hcl plus the public registry, with no terraform init, plan, apply, or state write.

Example of that message:

```
Directory: /srv/infra
Call: read .tf, .tf.json, and .terraform.lock.hcl, then GET the public registry. No terraform init, plan, apply, or state write.
```

The tools are on for every Hermes surface, including the gateway. Turn one surface off with `hermes tools disable --platform <name> terraform-drift`. Disable the plugin with `hermes plugins disable terraform-drift`.

Requires Hermes >=0.21.4. There are no Python packages to install.

## What the read includes

Provider pins come from `.terraform.lock.hcl`. The constraint in `required_providers` is not the installed pin. Module versions are not in the lock file. A module is pinned only when `version` is an exact version such as `5.0.0` or `= 5.0.0`. A range such as `~> 5.0` stays pin_unknown even if the registry answers.

A `.tf.json` file is read for `module` source and version and for `required_providers` source and version. Other JSON values, including a variable default, are not returned. A `.tf.json` file that cannot be read leaves the comparison unknown.

The registry calls are GET on registry.terraform.io, for example `https://registry.terraform.io/v1/providers/hashicorp/random/versions` and `https://registry.terraform.io/v1/modules/terraform-aws-modules/vpc/aws/versions`. The changelog is GET on raw.githubusercontent.com, for example `https://raw.githubusercontent.com/hashicorp/terraform-provider-random/v3.9.1/CHANGELOG.md`, only when the registry's source field is a github.com repository URL. Redirects are not followed. Other hosts, including 169.254.169.254, 0.0.0.0, and 192.0.2.1, are refused. Proxy environment variables are not used. A `.env` file, `*.tfvars`, and files under `.terraform/` are not read. Backend blocks and provider credentials are not returned.

Nothing is written under `<HERMES_HOME>/plugin-data/terraform-drift`. A symlink inside the folder is not followed. The directory path is refused before reading when its last part, or a part along the way, is a symlink. The macOS names `/tmp` and `/var` are the system aliases for `/private` and still allow a normal folder underneath. A path that contains `..` is refused.

## Morning or weekly text

terraform_drift_digest returns the text. It does not send it and it does not create a cron job. Connect delivery yourself, for example with the channel already configured in Hermes, and schedule daily or weekly with Hermes cron. Pass `known` from the previous `seen` map to hear only registry versions that are newer than that map. Omit `known` the first time: the text says the baseline is missing and does not claim those rows appeared today. `cadence` is the label `daily` or `weekly`. Raising a pin stays a human decision.

Cron, yolo, and approvals off can still run this read, because it only reads the folder and the public registry. There is no cron job to delete.

## When the registry does not answer

registry_down, registry_timeout, registry_auth, registry_rate_limit, registry_http, registry_not_found, registry_body, registry_truncated, and registry_redirect all leave latest null. The summary says the comparison stays unknown. A changelog miss leaves highlights_known false and does not claim there is no breaking change.

## What this plugin does not do

It does not run terraform init, plan, or apply. It does not write state or open a pull request. It does not choose Telegram or any other destination.
