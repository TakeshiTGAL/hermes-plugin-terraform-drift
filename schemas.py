"""Tool schemas. The first sentence of each description stays within 60 characters."""

SKILL_DESCRIPTION = (
    "Compare pinned Terraform provider and module versions with the public registry. "
    "Use terraform_drift before web search."
)

DRIFT = {
    "name": "terraform_drift",
    "description": (
        "Outdated Terraform provider and module versions. "
        "Compare each lock-file pin and each exact module pin with the public registry, "
        "and return visible breaking or security changelog lines. "
        "A timeout is not a latest version. Shows when a pin is behind."
    ),
    "annotations": {"readOnlyHint": True},
    "parameters": {
        "type": "object",
        "properties": {
            "directory": {
                "type": "string",
                "description": "Folder of .tf files, .tf.json files, and one .terraform.lock.hcl. Nothing outside it is read.",
            },
        },
        "required": ["directory"],
        "additionalProperties": False,
    },
}

DIGEST = {
    "name": "terraform_drift_digest",
    "description": (
        "New Terraform provider or module versions. "
        "Compare pins with the registry and return text for versions newer than the seen map. "
        "The text is not delivered. Breaking or security changelog lines stay in that text."
    ),
    "annotations": {"readOnlyHint": True},
    "parameters": {
        "type": "object",
        "properties": {
            "directory": {
                "type": "string",
                "description": "Folder of .tf files, .tf.json files, and one .terraform.lock.hcl. Nothing outside it is read.",
            },
            "known": {
                "type": "object",
                "description": "Map of registry id to the last seen registry version. Omit it when there is no baseline.",
            },
            "cadence": {
                "type": "string",
                "description": "daily or weekly. A label in the text. This plugin does not schedule delivery.",
            },
        },
        "required": ["directory"],
        "additionalProperties": False,
    },
}

ALL_SCHEMAS = [DRIFT, DIGEST]
