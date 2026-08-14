# -*- coding: utf-8 -*-
#
# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""Shared helpers for assessment write endpoints."""

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from ..extensions import db
from ..models import Assessment as DBAssessment, Finding, Package
from ..models.assessment import STATUS_TO_SIMPLIFIED


def resolve_package(pkg_string_id: str) -> "Package | None":
    """Look up an existing Package for 'name@version::supplier'.

    Returns ``None`` when no matching package exists. Writing an assessment must
    never create a package, so callers block the write when this returns
    ``None``. Matching is on name + version + supplier (with the same supplier
    normalization used by :meth:`Package.find_or_create`).
    """
    return Package.get_by_string_id(pkg_string_id)


def find_valid_finding(package_id: UUID, vuln_id: str, variant_id: UUID) -> "Finding | None":
    """Return the finding when it was actually observed for the variant.

    Assessment writes may target active or historical package versions, but
    they must never invent a package/vulnerability/variant relationship that
    was not produced by a scan.
    """
    from ..models.observation import Observation
    from ..models.scan import Scan

    return db.session.execute(
        db.select(Finding)
        .join(Observation, Observation.finding_id == Finding.id)
        .join(Scan, Scan.id == Observation.scan_id)
        .where(
            Finding.package_id == package_id,
            Finding.vulnerability_id == vuln_id.upper(),
            Scan.variant_id == variant_id,
        )
        .distinct()
    ).scalar_one_or_none()


def validate_assessment_findings(
    packages: list[Package], vuln_id: str, variant_id: UUID
) -> "tuple[dict[UUID, Finding], list[str]]":
    findings: dict[UUID, Finding] = {}
    invalid: list[str] = []
    for package in packages:
        finding = find_valid_finding(package.id, vuln_id, variant_id)
        if finding is None:
            invalid.append(package.string_id)
        else:
            findings[package.id] = finding
    return findings, invalid


def create_assessment_record(
    assessment: "DBAssessment",
    finding_id: UUID,
    variant_id: UUID | None,
    timestamp: datetime | None = None,
    origin: str = "custom",
) -> "DBAssessment":
    """Create a single DBAssessment row from a validated DTO.

    Shared between ``add_assessment`` (single) and ``add_assessments_batch``.
    """
    return DBAssessment.create(
        status=assessment.status or "",
        simplified_status=STATUS_TO_SIMPLIFIED.get(assessment.status or "", "Pending Assessment"),
        finding_id=finding_id,
        variant_id=variant_id,
        origin=origin,
        status_notes=assessment.status_notes,
        justification=assessment.justification,
        impact_statement=assessment.impact_statement,
        workaround=getattr(assessment, "workaround", None),
        responses=list(assessment.responses) if assessment.responses else [],
        commit=True,
        timestamp=timestamp,
    )


def payload_to_assessment(data: dict) -> "tuple[DBAssessment | dict[str, str], int]":
    """
    Take an object in input and try to convert it to an Assessment DTO.
    Return either (Assessment, 200) or (error_dict, http_code).
    """
    if "packages" not in data or not isinstance(data["packages"], list) or len(data["packages"]) < 1:
        return {"error": "Invalid request data"}, 400

    assessment = DBAssessment.new_dto(data["vuln_id"], data["packages"])

    if "status" not in data or not isinstance(data["status"], str):
        return {"error": "Invalid request data"}, 400

    if assessment.set_status(data["status"]) is False:
        return {"error": "Invalid status"}, 400

    if "status_notes" in data and isinstance(data["status_notes"], str):
        assessment.set_status_notes(data["status_notes"], False)

    if "justification" in data and isinstance(data["justification"], str):
        if not assessment.set_justification(data["justification"]):
            return {"error": "Invalid justification"}, 400
    elif assessment.is_justification_required():
        return {"error": "Justification required"}, 400

    if "impact_statement" in data and isinstance(data["impact_statement"], str):
        assessment.set_not_affected_reason(data["impact_statement"], False)

    if "workaround" in data and isinstance(data["workaround"], str):
        assessment.set_workaround(data["workaround"])

    if "timestamp" in data and isinstance(data["timestamp"], str):
        try:
            assessment.timestamp = datetime.fromisoformat(data["timestamp"])
        except (ValueError, TypeError):
            pass
    if "responses" in data and isinstance(data["responses"], list):
        for response in data["responses"]:
            assessment.add_response(response)
    return assessment, 200


@dataclass(frozen=True)
class ReconcileRequest:
    """A validated request to bring one assessment group to a desired state."""

    vuln_id: str
    existing_ids: list[UUID]
    packages: list[str]
    variant_ids: list[UUID]
    dto: "DBAssessment"
    update_timestamp: bool
    timestamp: "datetime | None"


def parse_reconcile_payload(
    data: dict[str, Any],
) -> "tuple[ReconcileRequest | None, dict[str, str] | None]":
    """Validate a group-reconcile payload.

    Returns ``(request, None)`` when the payload is well formed, otherwise
    ``(None, error_dict)``. Performs no database access.
    """
    vuln_id = data.get("vuln_id")
    if not isinstance(vuln_id, str) or not vuln_id:
        return None, {"error": "vuln_id is required"}

    packages = data.get("packages")
    if (not isinstance(packages, list) or not packages
            or not all(isinstance(p, str) and p for p in packages)):
        return None, {"error": "packages must be a non-empty list of package ids"}

    raw_variants = data.get("variant_ids")
    if not isinstance(raw_variants, list) or not raw_variants:
        return None, {"error": "variant_ids must be a non-empty list"}
    variant_ids: list[UUID] = []
    for raw in raw_variants:
        try:
            variant_ids.append(UUID(str(raw)))
        except (ValueError, AttributeError, TypeError):
            return None, {"error": f"Invalid variant_id: {raw}"}

    raw_existing = data.get("existing_ids", [])
    if not isinstance(raw_existing, list):
        return None, {"error": "existing_ids must be a list"}
    existing_ids: list[UUID] = []
    for raw in raw_existing:
        try:
            existing_ids.append(UUID(str(raw)))
        except (ValueError, AttributeError, TypeError):
            return None, {"error": f"Invalid assessment id: {raw}"}

    dto, code = payload_to_assessment({**data, "vuln_id": vuln_id, "packages": packages})
    if code != 200 or not isinstance(dto, DBAssessment):
        message = dto.get("error", "Invalid assessment content") if isinstance(dto, dict) else "Invalid content"
        return None, {"error": message}

    update_timestamp = data.get("update_timestamp", True)
    if not isinstance(update_timestamp, bool):
        return None, {"error": "update_timestamp must be a boolean"}

    timestamp: "datetime | None" = None
    raw_ts = data.get("timestamp")
    if isinstance(raw_ts, str) and raw_ts:
        try:
            timestamp = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
        except ValueError:
            return None, {"error": "Invalid timestamp"}

    return ReconcileRequest(
        vuln_id=vuln_id,
        existing_ids=existing_ids,
        packages=packages,
        variant_ids=variant_ids,
        dto=dto,
        update_timestamp=update_timestamp,
        timestamp=timestamp,
    ), None


def load_group_rows(
    existing_ids: list[UUID], vuln_id: str
) -> "tuple[list[DBAssessment], dict[str, str] | None]":
    """Load the group's current rows, rejecting ids that belong to another CVE.

    Without this guard a client could pass arbitrary assessment ids and have
    them deleted by the reconcile below.
    """
    rows: list[DBAssessment] = []
    for assessment_id in existing_ids:
        row = DBAssessment.get_by_id(assessment_id)
        if row is None:
            return [], {"error": f"Assessment not found: {assessment_id}"}
        finding = row.finding
        if finding is None or (finding.vulnerability_id or "").upper() != vuln_id.upper():
            return [], {"error": f"Assessment {assessment_id} does not belong to {vuln_id}"}
        rows.append(row)
    return rows, None
