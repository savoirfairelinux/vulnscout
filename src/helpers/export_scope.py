# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Compute the package/variant scope used to restrict an SBOM/VEX export.

An export can be scoped to:

* a single **variant** — only the packages of that variant's latest (active)
  SBOM scan, the vulnerabilities affecting those packages, and the
  assessments belonging to that variant; or
* a whole **project** — the union of the above across every variant in the
  project.

The resulting :class:`ExportScope` is handed to the controllers (see
:class:`~src.controllers.cache.ControllersCache`) so that every view
(SPDX, CycloneDX, OpenVEX) only ever sees the in-scope data.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from collections.abc import Iterable

from .active_scans import (
    active_sbom_scan_ids_for_variant,
    active_sbom_scan_ids_for_project,
    active_package_ids_for_scans,
)
from ..models.variant import Variant
from ..models.scan import Scan
from ..models.sbom_document import SBOMDocument


@dataclass
class ExportScope:
    """Restrict an export to a set of packages and variants.

    Attributes
    ----------
    package_ids:
        DB UUIDs of the packages present in the active SBOM(s) of the scope.
    variant_ids:
        DB UUIDs of the variants in scope (used to filter assessments).
    project_ids:
        DB UUIDs of projects owning the in-scope variants.
    scan_ids:
        DB UUIDs of every scan belonging to the in-scope variants.
    sbom_document_ids:
        DB UUIDs of every SBOM document belonging to the in-scope scans.
    """

    package_ids: set[uuid.UUID] = field(default_factory=set)
    variant_ids: set[uuid.UUID] = field(default_factory=set)
    project_ids: set[uuid.UUID] = field(default_factory=set)
    scan_ids: set[uuid.UUID] = field(default_factory=set)
    sbom_document_ids: set[uuid.UUID] = field(default_factory=set)


def _as_uuid(value: uuid.UUID | str) -> uuid.UUID:
    return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))


def _scope_for_variants(
    selected_ids: set[uuid.UUID],
    active_sbom_scan_ids: list[uuid.UUID],
    project_ids: set[uuid.UUID] | None = None,
) -> ExportScope:
    """Build package and relational context IDs for *selected_ids*."""
    variants = [variant for variant_id in selected_ids
                if (variant := Variant.get_by_id(variant_id)) is not None]
    all_scan_ids = {
        scan.id
        for variant_id in selected_ids
        for scan in Scan.get_by_variant_id(variant_id)
    }
    document_ids = {
        document.id
        for scan_id in all_scan_ids
        for document in SBOMDocument.get_by_scan(scan_id)
    }
    return ExportScope(
        package_ids=active_package_ids_for_scans(active_sbom_scan_ids),
        variant_ids=selected_ids,
        project_ids=(project_ids or set()) | {variant.project_id for variant in variants},
        scan_ids=all_scan_ids,
        sbom_document_ids=document_ids,
    )


def compute_export_scope(
    *,
    project_id: uuid.UUID | str | None = None,
    variant_id: uuid.UUID | str | None = None,
    variant_ids: Iterable[uuid.UUID | str] | None = None,
) -> ExportScope | None:
    """Build an :class:`ExportScope` for selected variants, one variant, or a project.

    ``variant_ids`` takes precedence over ``variant_id`` and ``project_id``.
    Returns ``None`` when no scope is provided (i.e. a global export).
    """
    if variant_ids is not None:
        selected_ids: set[uuid.UUID] = {_as_uuid(value) for value in variant_ids}
        scan_ids: list[uuid.UUID] = [
            scan_id
            for selected_id in selected_ids
            for scan_id in active_sbom_scan_ids_for_variant(selected_id)
        ]
        return _scope_for_variants(selected_ids, scan_ids)
    if variant_id is not None:
        vid = _as_uuid(variant_id)
        scan_ids = active_sbom_scan_ids_for_variant(vid)
        return _scope_for_variants({vid}, scan_ids)
    if project_id is not None:
        pid = _as_uuid(project_id)
        scan_ids = active_sbom_scan_ids_for_project(pid)
        variants = Variant.get_by_project(pid)
        return _scope_for_variants(
            {variant.id for variant in variants},
            scan_ids,
            project_ids={pid},
        )
    return None
