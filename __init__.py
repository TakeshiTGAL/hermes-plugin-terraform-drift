"""Pinned Terraform versions compared with the public registry."""

from pathlib import Path

from . import schemas, tools
from .version import __version__  # noqa: F401

_SKILL = Path(__file__).resolve().parent / "skills" / "terraform-drift" / "SKILL.md"


def register(ctx) -> None:
    for schema in schemas.ALL_SCHEMAS:
        ctx.register_tool(
            name=schema["name"],
            toolset="terraform-drift",
            schema=schema,
            handler=tools.HANDLERS[schema["name"]],
            emoji="📌",
        )
    ctx.register_skill("terraform-drift", _SKILL, description=schemas.SKILL_DESCRIPTION)
