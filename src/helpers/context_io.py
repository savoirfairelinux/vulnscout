# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Shared import/export logic for AI assessment context.

Both the HTTP routes (``src/routes/context.py``) and the CLI commands
(``src/bin/cmd_context.py``) build on these helpers so the export file format
and import semantics stay in one place.
"""

from __future__ import annotations

from copy import deepcopy
import uuid
from datetime import datetime, timezone
from typing import Any, NotRequired, Optional, TypedDict

from ..controllers.context import ProjectContextController, VariantContextController
from ..models.project import Project
from ..models.project_context import ProjectContext
from ..models.variant import Variant
from ..models.variant_context import VariantContext
from .stride_context import export_fields, import_fields
from .shared_context import COLLECTIONS, export_shared, import_shared, validate_document

# Version of the export file format. Bump the major component only on a
# breaking change to the entry shape.
EXPORT_VERSION = "2.0"
SHARED_EXPORT_VERSION = "3.0"


class NamedVariant(TypedDict):
    variant_name: str


class VariantEntry(NamedVariant):
    """One exported variant's context (nested under its project)."""
    variant_description: Optional[str]
    codebase_paths: list[str]
    environment: Optional[str]
    editor_mode: str
    threat_model: Any
    risks: Any
    other_info: Optional[str]
    system: NotRequired[dict]


class ProjectEntry(TypedDict):
    """One exported project with its variants nested underneath."""
    project_name: str
    project_description: Optional[str]
    variants: list[VariantEntry] | list[NamedVariant]
    context: NotRequired[dict]


class ExportDocument(TypedDict):
    """Versioned export envelope grouping variants under their project."""
    version: str
    exported_at: str
    projects: list[ProjectEntry]


def variant_entry(variant: Variant, vc: Optional[VariantContext]) -> VariantEntry:
    """Build one export entry for a variant."""
    fields = export_fields(vc.threat_model if vc else None, vc.risks if vc else None, vc.editor_mode if vc else None)
    entry: VariantEntry = {
        "variant_name": variant.name,
        "variant_description": vc.variant_description if vc else None,
        "codebase_paths": vc.codebase_path.split(";") if vc and vc.codebase_path is not None else [],
        "environment": vc.environment if vc else None,
        "other_info": vc.other_info if vc else None,
        "editor_mode": fields["editor_mode"],
        "threat_model": fields["threat_model"],
        "risks": fields["risks"],
    }
    if "system" in fields:
        entry["system"] = fields["system"]
    return entry


def project_entry(project: Project, pc: Optional[ProjectContext],
                  variants: list[VariantEntry]) -> ProjectEntry:
    """Build one export entry for a project with its variants nested."""
    entry: ProjectEntry = {
        "project_name": project.name,
        "project_description": pc.description if pc else None,
        "variants": variants,
    }
    if pc is not None and pc.shared_context is not None:
        entry["context"] = export_shared(project.id, [variant["variant_name"] for variant in variants])
    return entry


def collect_entries(project_id: Optional[uuid.UUID] = None,
                    variant_id: Optional[uuid.UUID] = None,
                    variant_ids: Optional[set[uuid.UUID]] = None) -> list[ProjectEntry]:
    """Collect export entries grouped by project.

    With no arguments, returns one project entry per project (each with its
    variants nested). With both *project_id* and *variant_id*, returns a
    single-project list containing only that variant. With *variant_ids*, only
    variants whose id is in the set are included (projects with no matching
    variant are dropped); *variant_ids* cannot be combined with the
    single-variant arguments.

    Raises
    ------
    ValueError
        If exactly one of *project_id* / *variant_id* is given, the variant
        does not belong to the project, or *variant_ids* is combined with the
        single-variant arguments.
    LookupError
        If the requested project or variant does not exist.
    """
    if (project_id is None) != (variant_id is None):
        raise ValueError("Both project_id and variant_id are required for a single-variant export")

    if variant_ids is not None and (project_id is not None or variant_id is not None):
        raise ValueError("variant_ids cannot be combined with a single-variant export")

    if project_id is not None and variant_id is not None:
        project = Project.get_by_id(project_id)
        if project is None:
            raise LookupError("Project not found")
        variant = Variant.get_by_id(variant_id)
        if variant is None:
            raise LookupError("Variant not found")
        if variant.project_id != project_id:
            raise ValueError("Variant does not belong to the specified project")
        pc = ProjectContext.get_by_project(project_id)
        vc = VariantContext.get_by_variant(variant_id)
        return [project_entry(project, pc, [variant_entry(variant, vc)])]

    projects: list[ProjectEntry] = []
    for project in Project.get_all():
        pc = ProjectContext.get_by_project(project.id)
        variants: list[VariantEntry] = []
        for variant in Variant.get_by_project(project.id):
            if variant_ids is not None and variant.id not in variant_ids:
                continue
            vc = VariantContext.get_by_variant(variant.id)
            variants.append(variant_entry(variant, vc))
        if not variants:
            continue
        projects.append(project_entry(project, pc, variants))
    return projects


def build_export_document(projects: list[ProjectEntry]) -> ExportDocument:
    """Wrap *projects* in the versioned export envelope."""
    shared = any("context" in project for project in projects)
    if shared:
        projects = deepcopy(projects)
        for entry in projects:
            if "context" not in entry:
                project = Project.get_by_name(entry["project_name"])
                assert project is not None
                entry["context"] = export_shared(project.id, [variant["variant_name"] for variant in entry["variants"]])
            # Shared files have one canonical context, not conflicting flattened copies.
            recipients: list[NamedVariant] = [
                {"variant_name": variant["variant_name"]} for variant in entry["variants"]
            ]
            entry["variants"] = recipients
    return {
        "version": SHARED_EXPORT_VERSION if shared else EXPORT_VERSION,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "projects": projects,
    }


def extract_entries(body) -> list:
    """Normalise an import payload into a flat list of per-variant records.

    Accepts either the versioned envelope (a dict with a ``projects`` list) or
    a bare list of project objects. Each project object carries
    ``project_name`` / ``project_description`` and a ``variants`` list. The
    returned records are flattened so each carries ``project_name``,
    ``project_description`` and the variant fields, matching what
    :func:`import_entries` consumes. Version 1.0 and unversioned files are
    legacy free-text imports; version 2.0 has explicit structured/free modes,
    and version 3.0 keeps canonical project entries with portable variant scopes.

    Raises
    ------
    ValueError
        If *body* is neither a list of projects nor a dict containing a
        ``projects`` list, or if a project's ``variants`` is not a list.
    """
    version = body.get("version", "1.0") if isinstance(body, dict) else "1.0"
    if version not in ("1.0", EXPORT_VERSION, SHARED_EXPORT_VERSION):
        raise ValueError(f"Unsupported context version: {version!r}")
    if isinstance(body, list):
        projects: list = body
    elif isinstance(body, dict):
        raw_projects = body.get("projects")
        if not isinstance(raw_projects, list):
            raise ValueError("Object body must contain a 'projects' array")
        projects = raw_projects
        if version in (EXPORT_VERSION, SHARED_EXPORT_VERSION) and (
            body.keys() - {"version", "exported_at", "projects"}
            or ("exported_at" in body and not isinstance(body["exported_at"], str))
        ):
            raise ValueError("Invalid context envelope")
    else:
        raise ValueError("Body must be a JSON array of projects or an object with a 'projects' array")

    records: list = []
    identities: set[tuple[str, str]] = set()
    for project in projects:
        if not isinstance(project, dict):
            records.append(project)
            continue
        project_name = project.get("project_name")
        project_description = project.get("project_description")
        if version in (EXPORT_VERSION, SHARED_EXPORT_VERSION) and (
            project.keys() - {"project_name", "project_description", "variants", *(
                ("context",) if version == SHARED_EXPORT_VERSION else ()
            )}
            or (project_description is not None and not isinstance(project_description, str))
        ):
            raise ValueError("Invalid project fields")
        variants = project.get("variants")
        if not isinstance(variants, list):
            raise ValueError("Each project must contain a 'variants' array")
        if version == SHARED_EXPORT_VERSION:
            if (not isinstance(project_name, str) or not project_name
                    or any(not isinstance(variant, dict) or set(variant) != {"variant_name"}
                           or not isinstance(variant["variant_name"], str) or not variant["variant_name"]
                           for variant in variants)):
                raise ValueError("Shared projects require a name and variant_name-only variant records")
            names = [variant["variant_name"] for variant in variants]
            if len(set(names)) != len(names) or any((project_name, name) in identities for name in names):
                raise ValueError("Duplicate shared context entry")
            identities.update((project_name, name) for name in names)
            document = deepcopy(project.get("context"))
            if not isinstance(document, dict) or not isinstance(document.get("fields"), dict):
                raise ValueError("Supply a shared context document")
            for rows in [*document["fields"].values(), *(document.get(key) for key in COLLECTIONS)]:
                if not isinstance(rows, list):
                    raise ValueError("Shared records must be arrays")
                for row in rows:
                    if not isinstance(row, dict) or "variant_ids" in row or "variant_names" not in row:
                        raise ValueError("Shared records require variant_names")
                    row["variant_ids"] = row.pop("variant_names")
            validate_document(document, set(names))
            records.append({"project_name": project_name, "description": project_description,
                            "_format_version": version, "_shared": project["context"], "variant_names": names})
            continue
        for variant in variants:
            if not isinstance(variant, dict):
                records.append(variant)
                continue
            name = variant.get("variant_name")
            if version == EXPORT_VERSION and isinstance(project_name, str) and isinstance(name, str):
                identity = (project_name, name)
                if identity in identities:
                    raise ValueError(f"Duplicate context entry: {project_name} / {name}")
                identities.add(identity)
            records.append({
                **variant,
                "project_name": project_name,
                "description": project_description,
                "_format_version": version,
                "_variant": variant,
            })
    return records


def import_entries(entries: list) -> dict:
    """Apply import *entries* and return a classification summary.

    Upserts run with ``commit=False``; the caller is responsible for committing
    (or rolling back) the surrounding transaction so the whole batch is atomic.

    Returns
    -------
    dict
        ``{"imported": [...], "ignored": [...], "failed": [...]}`` where each
        item carries ``project_name`` / ``variant_name`` and, for ignored /
        failed items, a ``reason``.
    """
    def _txt(value):
        return value if isinstance(value, str) else None

    imported: list = []
    ignored: list = []
    failed: list = []

    for entry in entries:
        if not isinstance(entry, dict):
            failed.append({
                "project_name": None,
                "variant_name": None,
                "reason": "Entry is not a JSON object",
            })
            continue

        project_name = _txt(entry.get('project_name'))
        if entry.get("_format_version") == SHARED_EXPORT_VERSION:
            names = entry["variant_names"]
            project = Project.get_by_name(project_name) if project_name else None
            targets = {}
            for name in names:
                variant = Variant.get_by_name_and_project(name, project.id) if project else None
                ident = {"project_name": project_name, "variant_name": name}
                if variant is None:
                    ignored.append({**ident, "reason": "Variant not found" if project else "Project not found"})
                else:
                    targets[name] = str(variant.id)
            if targets:
                assert project is not None
                try:
                    import_shared(project.id, entry["_shared"], targets, entry["description"])
                except ValueError as exc:
                    failed.extend({"project_name": project_name, "variant_name": name, "reason": str(exc)}
                                  for name in targets)
                else:
                    imported.extend({"project_name": project_name, "variant_name": name} for name in targets)
            continue
        variant_name = _txt(entry.get('variant_name'))
        ident = {"project_name": project_name, "variant_name": variant_name}

        if not project_name or not variant_name:
            ignored.append({**ident, "reason": "Missing project_name or variant_name"})
            continue

        project = Project.get_by_name(project_name)
        if project is None:
            ignored.append({**ident, "reason": "Project not found"})
            continue
        variant = Variant.get_by_name_and_project(variant_name, project.id)
        if variant is None:
            ignored.append({**ident, "reason": "Variant not found"})
            continue

        description = _txt(entry.get('description'))
        if entry.get("_format_version") == EXPORT_VERSION:
            try:
                values = import_fields(entry["_variant"])
            except ValueError as exc:
                failed.append({**ident, "reason": str(exc)})
                continue
        else:
            values = {key: _txt(entry.get(key)) for key in (
                "variant_description", "codebase_path", "environment", "threat_model", "risks", "other_info",
            )}
            values["editor_mode"] = "free"
            missing = []
            if not (description and description.strip()):
                missing.append('description')
            if not (values["threat_model"] and values["threat_model"].strip()):
                missing.append('threat_model')
            if missing:
                failed.append({**ident, "reason": f"Missing mandatory field(s): {', '.join(missing)}"})
                continue

        ProjectContextController.upsert(project.id, description=description, commit=False)
        VariantContextController.upsert(
            variant.id,
            **values,
            commit=False,
        )
        imported.append(ident)

    return {"imported": imported, "ignored": ignored, "failed": failed}
