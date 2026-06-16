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

from .active_scans import (
    active_sbom_scan_ids_for_variant,
    active_sbom_scan_ids_for_project,
    active_package_ids_for_scans,
)
from ..models.variant import Variant


@dataclass
class ExportScope:
    """Restrict an export to a set of packages and variants.

    Attributes
    ----------
    package_ids:
        DB UUIDs of the packages present in the active SBOM(s) of the scope.
    variant_ids:
        DB UUIDs of the variants in scope (used to filter assessments).
    """

    package_ids: set[uuid.UUID] = field(default_factory=set)
    variant_ids: set[uuid.UUID] = field(default_factory=set)


def _as_uuid(value) -> uuid.UUID:
    return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))


def compute_export_scope(*, project_id=None, variant_id=None) -> ExportScope | None:
    """Build an :class:`ExportScope` for *variant_id* or *project_id*.

    ``variant_id`` takes precedence over ``project_id``. Returns ``None`` when
    neither is provided (i.e. a global, unscoped export).
    """
    if variant_id is not None:
        vid = _as_uuid(variant_id)
        scan_ids = active_sbom_scan_ids_for_variant(vid)
        return ExportScope(
            package_ids=active_package_ids_for_scans(scan_ids),
            variant_ids={vid},
        )
    if project_id is not None:
        pid = _as_uuid(project_id)
        scan_ids = active_sbom_scan_ids_for_project(pid)
        variants = Variant.get_by_project(pid)
        return ExportScope(
            package_ids=active_package_ids_for_scans(scan_ids),
            variant_ids={v.id for v in variants},
        )
    return None
