# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Shared helpers for scan-related routes.

Extracted from ``scans.py`` to eliminate duplication between the Grype,
NVD and OSV trigger endpoints.
"""

import uuid as uuid_module

from flask import jsonify, Response
from flask.typing import ResponseReturnValue
from typing import Dict, List, Optional, Sequence, Set, Tuple, Union, cast

from ..controllers.variants import VariantController
from ..helpers.active_scans import active_sbom_scan_ids_for_variant, active_package_ids_for_scans
from ..models.observation import Observation
from ..models.package import Package
from ..models.variant import Variant
from ..models.finding import Finding
from ..models.scan import Scan
from ..extensions import db

# Shared progress-tracking structures keyed by stringified variant UUID.
ProgressEntry = Dict[str, object]
ProgressDict = Dict[str, ProgressEntry]
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
# Scan-trigger boilerplate
# ---------------------------------------------------------------------------

def validate_trigger(
    variant_id: str, progress_dict: ProgressDict, scan_label: str
) -> Union[Tuple[None, None, ErrorResponse], Tuple[uuid_module.UUID, Variant, None]]:
    """Common validation for scan trigger endpoints.

    Parses the variant UUID, checks the variant exists, and checks that
    no scan of the same type is already running.

    Returns ``(variant_uuid, variant, error_response)`` — if
    *error_response* is not ``None`` the caller should return it immediately.
    """
    variant_uuid, err = parse_uuid_or_400(variant_id, "variant id")
    if err is not None:
        return None, None, err
    if variant_uuid is None:
        return None, None, (jsonify({"error": "Internal error"}), 500)

    variant = VariantController.get(variant_uuid)
    if variant is None:
        return None, None, (jsonify({"error": "Variant not found"}), 404)

    vid_str = str(variant_uuid)
    if vid_str in progress_dict and progress_dict[vid_str].get("status") == "running":
        return None, None, (
            jsonify({"error": f"A {scan_label} is already in progress for this variant"}),
            409,
        )

    return variant_uuid, variant, None


def scan_status_response(variant_id: str, progress_dict: ProgressDict) -> ResponseReturnValue:
    """Common handler for ``/status`` endpoints."""
    variant_uuid, err = parse_uuid_or_400(variant_id, "variant id")
    if err is not None:
        return err
    vid_str = str(variant_uuid)
    info = progress_dict.get(vid_str)
    if info is None:
        return jsonify({"status": "idle"})
    return jsonify(info)


def init_progress(progress_dict: ProgressDict, vid_str: str, total: int = 0) -> None:
    """Initialise the progress entry for a scan."""
    progress_dict[vid_str] = {
        "status": "running",
        "error": None,
        "progress": "starting",
        "logs": [],
        "total": total,
        "done_count": 0,
    }


def set_error(progress_dict: ProgressDict, vid_str: str, error: str) -> None:
    """Transition a progress entry to error state."""
    old = progress_dict.get(vid_str, {})
    logs = cast(List[str], old.get("logs", []))
    logs.append(f"ERROR: {error}")
    progress_dict[vid_str] = {
        "status": "error",
        "error": error,
        "progress": None,
        "logs": logs,
        "total": old.get("total", 0),
        "done_count": old.get("done_count", 0),
    }


# ---------------------------------------------------------------------------
# Resolve active packages for a variant
# ---------------------------------------------------------------------------

def resolve_active_packages(
    variant_uuid: uuid_module.UUID,
    progress_dict: Optional[ProgressDict] = None,
    vid_str: Optional[str] = None,
) -> Tuple[Sequence[Package], Optional[str]]:
    """Return the active ``Package`` list for *variant_uuid*.

    Looks at the latest **SBOM** scan for the variant, resolves its
    package set and loads the ``Package`` objects.  Tool scans are
    intentionally excluded because they may contain packages from other
    variants (e.g. the Grype export is global).

    Returns ``(packages, error_string_or_None)``.  When *progress_dict*
    and *vid_str* are provided the function sets an error state on failure.
    """
    latest_ids = active_sbom_scan_ids_for_variant(variant_uuid)

    if not latest_ids:
        err = "No SBOM scan found for variant"
        if progress_dict and vid_str:
            set_error(progress_dict, vid_str, err)
        return [], err

    all_pkg_ids = active_package_ids_for_scans(latest_ids)

    if not all_pkg_ids:
        err = "No packages found for variant"
        if progress_dict and vid_str:
            set_error(progress_dict, vid_str, err)
        return [], err

    packages = db.session.execute(
        db.select(Package).where(Package.id.in_(all_pkg_ids))
    ).scalars().all()

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
