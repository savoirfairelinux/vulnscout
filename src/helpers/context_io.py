# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only
"""Shared import/export logic for AI assessment context.

Both the HTTP routes (``src/routes/context.py``) and the CLI commands
(``src/bin/cmd_context.py``) build on these helpers so the export file format
and import semantics stay in one place.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional, TypedDict

from ..controllers.context import ProjectContextController, VariantContextController
from ..models.project import Project
from ..models.project_context import ProjectContext
from ..models.variant import Variant
from ..models.variant_context import VariantContext

# Version of the export file format. Bump the major component only on a
# breaking change to the entry shape.
EXPORT_VERSION = "1.0"


class VariantEntry(TypedDict):
    """One exported variant's context (nested under its project)."""
    variant_name: str
    variant_description: Optional[str]
    codebase_path: Optional[str]
    environment: Optional[str]
    threat_model: Optional[str]
    risks: Optional[str]
    other_info: Optional[str]


class ProjectEntry(TypedDict):
    """One exported project with its variants nested underneath."""
    project_name: str
    project_description: Optional[str]
    variants: list[VariantEntry]


class ExportDocument(TypedDict):
    """Versioned export envelope grouping variants under their project."""
    version: str
    exported_at: str
    projects: list[ProjectEntry]


def variant_entry(variant: Variant, vc: Optional[VariantContext]) -> VariantEntry:
    """Build one export entry for a variant."""
    return {
        "variant_name": variant.name,
        "variant_description": vc.variant_description if vc else None,
        "codebase_path": vc.codebase_path if vc else None,
        "environment": vc.environment if vc else None,
        "threat_model": vc.threat_model if vc else None,
        "risks": vc.risks if vc else None,
        "other_info": vc.other_info if vc else None,
    }


def project_entry(project: Project, pc: Optional[ProjectContext],
                  variants: list[VariantEntry]) -> ProjectEntry:
    """Build one export entry for a project with its variants nested."""
    return {
        "project_name": project.name,
        "project_description": pc.description if pc else None,
        "variants": variants,
    }


def collect_entries(project_id: Optional[uuid.UUID] = None,
                    variant_id: Optional[uuid.UUID] = None) -> list[ProjectEntry]:
    """Collect export entries grouped by project.

    With no arguments, returns one project entry per project (each with its
    variants nested). With both *project_id* and *variant_id*, returns a
    single-project list containing only that variant.

    Raises
    ------
    ValueError
        If exactly one of *project_id* / *variant_id* is given, or the variant
        does not belong to the project.
    LookupError
        If the requested project or variant does not exist.
    """
    if (project_id is None) != (variant_id is None):
        raise ValueError("Both project_id and variant_id are required for a single-variant export")

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
            vc = VariantContext.get_by_variant(variant.id)
            variants.append(variant_entry(variant, vc))
        if not variants:
            continue
        projects.append(project_entry(project, pc, variants))
    return projects


def build_export_document(projects: list[ProjectEntry]) -> ExportDocument:
    """Wrap *projects* in the versioned export envelope."""
    return {
        "version": EXPORT_VERSION,
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
    :func:`import_entries` consumes. The ``version`` / ``exported_at`` fields
    are ignored (lenient).

    Raises
    ------
    ValueError
        If *body* is neither a list of projects nor a dict containing a
        ``projects`` list, or if a project's ``variants`` is not a list.
    """
    if isinstance(body, list):
        projects = body
    elif isinstance(body, dict):
        projects = body.get("projects")
        if not isinstance(projects, list):
            raise ValueError("Object body must contain a 'projects' array")
    else:
        raise ValueError("Body must be a JSON array of projects or an object with a 'projects' array")

    records: list = []
    for project in projects:
        if not isinstance(project, dict):
            records.append(project)
            continue
        project_name = project.get("project_name")
        project_description = project.get("project_description")
        variants = project.get("variants")
        if not isinstance(variants, list):
            raise ValueError("Each project must contain a 'variants' array")
        for variant in variants:
            if not isinstance(variant, dict):
                records.append(variant)
                continue
            records.append({
                "project_name": project_name,
                "description": project_description,
                **variant,
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
        threat_model = _txt(entry.get('threat_model'))
        missing = []
        if not (description and description.strip()):
            missing.append('description')
        if not (threat_model and threat_model.strip()):
            missing.append('threat_model')
        if missing:
            failed.append({
                **ident,
                "reason": f"Missing mandatory field(s): {', '.join(missing)}",
            })
            continue

        ProjectContextController.upsert(project.id, description=description, commit=False)
        VariantContextController.upsert(
            variant.id,
            variant_description=_txt(entry.get('variant_description')),
            codebase_path=_txt(entry.get('codebase_path')),
            environment=_txt(entry.get('environment')),
            threat_model=threat_model,
            risks=_txt(entry.get('risks')),
            other_info=_txt(entry.get('other_info')),
            commit=False,
        )
        imported.append(ident)

    return {"imported": imported, "ignored": ignored, "failed": failed}
