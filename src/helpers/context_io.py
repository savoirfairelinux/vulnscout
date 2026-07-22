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


class ContextEntry(TypedDict):
    """One exported (project, variant) context record."""
    project_name: str
    variant_name: str
    description: Optional[str]
    variant_description: Optional[str]
    codebase_path: Optional[str]
    environment: Optional[str]
    threat_model: Optional[str]
    risks: Optional[str]
    other_info: Optional[str]


class ExportDocument(TypedDict):
    """Versioned export envelope wrapping a list of context entries."""
    version: str
    exported_at: str
    entries: list[ContextEntry]


def context_entry(project: Project, variant: Variant,
                  pc: Optional[ProjectContext], vc: Optional[VariantContext]) -> ContextEntry:
    """Build one export entry for a (project, variant) pair."""
    return {
        "project_name": project.name,
        "variant_name": variant.name,
        "description": pc.description if pc else None,
        "variant_description": vc.variant_description if vc else None,
        "codebase_path": vc.codebase_path if vc else None,
        "environment": vc.environment if vc else None,
        "threat_model": vc.threat_model if vc else None,
        "risks": vc.risks if vc else None,
        "other_info": vc.other_info if vc else None,
    }


def collect_entries(project_id: Optional[uuid.UUID] = None,
                    variant_id: Optional[uuid.UUID] = None) -> list[ContextEntry]:
    """Collect export entries.

    With no arguments, returns one entry per variant across every project.
    With both *project_id* and *variant_id*, returns a single-entry list for
    that pair.

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
        return [context_entry(project, variant, pc, vc)]

    entries: list[ContextEntry] = []
    for project in Project.get_all():
        pc = ProjectContext.get_by_project(project.id)
        for variant in Variant.get_by_project(project.id):
            vc = VariantContext.get_by_variant(variant.id)
            entries.append(context_entry(project, variant, pc, vc))
    return entries


def build_export_document(entries: list[ContextEntry]) -> ExportDocument:
    """Wrap *entries* in the versioned export envelope."""
    return {
        "version": EXPORT_VERSION,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "entries": entries,
    }


def extract_entries(body) -> list:
    """Normalise an import payload into a list of entries.

    Accepts either the versioned envelope (a dict with an ``entries`` list) or
    a bare list of entries. The ``version`` / ``exported_at`` fields are
    ignored (lenient).

    Raises
    ------
    ValueError
        If *body* is neither a list nor a dict containing an ``entries`` list.
    """
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        entries = body.get("entries")
        if isinstance(entries, list):
            return entries
        raise ValueError("Object body must contain an 'entries' array")
    raise ValueError("Body must be a JSON array of entries or an object with an 'entries' array")


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
