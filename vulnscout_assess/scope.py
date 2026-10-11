"""Resolve the CLI project/variant scope to VulnScout variant records."""

from dataclasses import dataclass

DEFAULT_NAME = "default"


class ScopeError(Exception):
    """Raised when the requested project or variant does not exist."""


@dataclass(frozen=True)
class Variant:
    id: str
    name: str


@dataclass(frozen=True)
class Scope:
    project: str
    variants: tuple[Variant, ...]


def resolve_scope(client, project_name: str | None, variant_name: str | None) -> Scope:
    """Apply the --match-condition scope rules and return the in-scope variants."""
    project = project_name or DEFAULT_NAME
    variants = tuple(
        Variant(id=v["id"], name=v["name"])
        for v in client.list_variants_by_project(_find_project_id(client, project))
    )
    if project_name is None and variant_name is None:
        variant_name = DEFAULT_NAME
    if variant_name is not None:
        variants = tuple(v for v in variants if v.name == variant_name)
        if not variants:
            raise ScopeError(f"variant not found: {variant_name}")
    if not variants:
        raise ScopeError(f"project has no variants: {project}")
    return Scope(project=project, variants=variants)


def _find_project_id(client, name: str) -> str:
    for project in client.list_projects():
        if project.get("name") == name:
            return project["id"]
    raise ScopeError(f"project not found: {name}")
