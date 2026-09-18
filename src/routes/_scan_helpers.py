# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Shared helpers for scan-related routes and queued scan jobs."""

import uuid as uuid_module

from flask import jsonify, Response
from typing import Optional, Sequence, Set, Tuple, Union

from ..helpers.active_scans import active_sbom_scan_ids_for_variant, active_package_ids_for_scans
from ..helpers.scan_filters import filter_scannable_packages
from ..models.observation import Observation
from ..models.package import Package
from ..models.finding import Finding
from ..models.scan import Scan
from ..extensions import db

ErrorResponse = Tuple[Response, int]


# ---------------------------------------------------------------------------
# UUID parsing
# ---------------------------------------------------------------------------

def parse_uuid_or_400(
    value: str, label: str = "id"
) -> Union[Tuple[uuid_module.UUID, None], Tuple[None, ErrorResponse]]:
    """Parse *value* as a UUID or return a 400 JSON error response.

    Returns ``(uuid, None)`` on success or ``(None, Response)`` on failure.
    """
    try:
        return uuid_module.UUID(value), None
    except (ValueError, AttributeError):
        return None, (jsonify({"error": f"Invalid {label}"}), 400)


# ---------------------------------------------------------------------------
# Resolve active packages for a variant
# ---------------------------------------------------------------------------

def resolve_active_packages(
    variant_uuid: uuid_module.UUID,
    exclude_kernel: bool = True,
) -> Tuple[Sequence[Package], Optional[str]]:
    """Return the active ``Package`` list for *variant_uuid*.

    Looks at the latest **SBOM** scan for the variant, resolves its
    package set and loads the ``Package`` objects.  Tool scans are
    intentionally excluded because they may contain packages from other
    variants (e.g. the Grype export is global).

    Returns ``(packages, error_string_or_None)``.

    When *exclude_kernel* is ``True`` (the default), kernel companion
    packages (``kernel-*``) are dropped: they bloat SPDX 3 SBOMs to
    thousands of entries and all inherit the base kernel CPE, so feeding
    them to the scanners attributes the entire kernel CVE set to each with
    no useful results.  Pass ``exclude_kernel=False`` to scan them anyway.
    """
    latest_ids = active_sbom_scan_ids_for_variant(variant_uuid)

    if not latest_ids:
        return [], "No SBOM scan found for variant"

    all_pkg_ids = active_package_ids_for_scans(latest_ids)

    if not all_pkg_ids:
        return [], "No packages found for variant"

    packages = db.session.execute(
        db.select(Package).where(Package.id.in_(all_pkg_ids))
    ).scalars().all()

    if exclude_kernel:
        return filter_scannable_packages(packages), None
    return packages, None


# ---------------------------------------------------------------------------
# Create observation + initial assessment (de-duplicated)
# ---------------------------------------------------------------------------

def create_observation_and_assessment(
    finding: Finding,
    scan: Scan,
    variant_uuid: uuid_module.UUID,
    origin: str,
    observation_pairs: Set[Tuple[uuid_module.UUID, uuid_module.UUID]],
    assessed_findings: Set[Tuple[uuid_module.UUID, uuid_module.UUID]],
) -> None:
    """Create an Observation and (if needed) an initial Assessment.

    De-duplicates against *observation_pairs* ``{(finding_id, scan_id)}``
    and *assessed_findings* ``{(finding_id, variant_uuid)}``.
    Both sets are mutated in-place.  Does **not** commit.
    """
    from ..models.assessment import Assessment

    pair = (finding.id, scan.id)
    if pair not in observation_pairs:
        observation_pairs.add(pair)
        Observation.create(finding_id=finding.id, scan_id=scan.id, commit=False)

    fv_key = (finding.id, variant_uuid)
    if fv_key not in assessed_findings:
        assessed_findings.add(fv_key)
        has_assess = db.session.execute(
            db.select(Assessment.id).where(
                Assessment.finding_id == finding.id,
                Assessment.variant_id == variant_uuid,
            ).limit(1)
        ).scalar_one_or_none()
        if has_assess is None:
            Assessment.create(
                status="under_investigation",
                simplified_status="Pending Assessment",
                finding_id=finding.id,
                variant_id=variant_uuid,
                origin=origin,
                commit=False,
            )
